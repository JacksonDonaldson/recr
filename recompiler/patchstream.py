"""Encode changes to file-backed virtual addresses as a patch stream."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import groupby
from typing import TYPE_CHECKING

from binary.binary import Binary

if TYPE_CHECKING:
    from optimizers.outliner import FunctionRewrite


def select_patch_ranges(
    occupied: Iterable[tuple[int, int]], rewrites: list[FunctionRewrite],
) -> set[tuple[int, int]]:
    """Keep the rewrites needed to make room for the selected fragments."""
    ranges = set(occupied)
    pending = list(ranges)
    retained: set[int] = set()
    while pending:
        start, end = pending.pop()
        for rewrite in rewrites:
            if rewrite.start in retained or max(start, rewrite.live_end) >= min(end, rewrite.original_end):
                continue
            retained.add(rewrite.start)
            new_blocks = set(rewrite.shared_blocks) - ranges
            pending.extend(new_blocks)
            ranges.update(new_blocks)
            ranges.add((rewrite.start, rewrite.live_end))
    return ranges


def _mapped_spans(
    image: Binary, ranges: Iterable[tuple[int, int]],
) -> Iterator[tuple[int, int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            lower, upper = merged[-1]
            merged[-1] = lower, max(upper, end)
        else:
            merged.append((start, end))
    for address, file_offset, size, _ in sorted(image.mapped_segments()):
        for start, end in merged:
            if start >= address + size:
                break
            lower, upper = max(start, address), min(end, address + size)
            if lower < upper:
                yield lower, file_offset + lower - address, upper - lower


def encode_patchstream(
    original: bytes, image: Binary, word_size: int, ranges: Iterable[tuple[int, int]],
) -> bytes:
    modified = image.image_bytes()
    if len(modified) != len(original):
        raise ValueError("cannot encode a patch stream for a change in image size")

    terminator = b"\xff" * word_size
    max_word = int.from_bytes(terminator, "little")
    stream = bytearray()
    for address, file_offset, size in _mapped_spans(image, ranges):
        end = file_offset + size
        before, after = original[file_offset:end], modified[file_offset:end]
        if before == after:
            continue

        offset = 0
        for changed, pairs in groupby(zip(before, after), lambda pair: pair[0] != pair[1]):
            length = sum(1 for _ in pairs)
            if changed:
                start = address + offset
                if start == max_word:
                    raise ValueError(f"cannot encode patch at {start:#x}. This address is the patch stream terminator")
                if length > max_word or start + length - 1 > max_word:
                    raise ValueError(f"cannot encode {length} patch bytes at {start:#x} with {word_size}-byte words")
                stream.extend(start.to_bytes(word_size, "little"))
                stream.extend(length.to_bytes(word_size, "little"))
                stream.extend(after[offset:offset + length])
            offset += length

    stream.extend(terminator)
    return bytes(stream)
