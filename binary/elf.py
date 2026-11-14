"""ELF binary support."""

from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import Path
import shutil
import struct

from elftools.common.exceptions import ELFError as PyElfError
from elftools.elf.elffile import ELFFile

from binary.binary import Binary


class ELFError(ValueError):
    """Raised when a file cannot be parsed as an ELF binary."""


@dataclass(frozen=True)
class _LoadSegment:
    virtual_address: int
    file_offset: int
    file_size: int
    memory_size: int

    def contains(self, address: int) -> bool:
        return self.virtual_address <= address < (
            self.virtual_address + self.memory_size
        )


class ELF(Binary):
    """An ELF binary parsed into its loadable segments."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._data = bytearray(self.path.read_bytes())
        self._segments = self._parse_segments()

    @classmethod
    def open(cls, path: str | Path) -> "ELF":
        return cls(path)

    def _parse_segments(self) -> list[_LoadSegment]:
        try:
            with io.BytesIO(self._data) as stream:
                elf = ELFFile(stream)
                segments: list[_LoadSegment] = []

                for segment in elf.iter_segments():
                    if segment["p_type"] != "PT_LOAD":
                        continue

                    file_offset = int(segment["p_offset"])
                    virtual_address = int(segment["p_vaddr"])
                    file_size = int(segment["p_filesz"])
                    memory_size = int(segment["p_memsz"])

                    if file_size > memory_size:
                        raise ELFError(
                            f"loadable segment at {virtual_address:#x} has "
                            "a file size larger than its memory size"
                        )
                    if file_size and file_offset + file_size > len(self._data):
                        raise ELFError(
                            f"loadable segment at {virtual_address:#x} "
                            "extends past the end of the file"
                        )

                    if memory_size:
                        segments.append(
                            _LoadSegment(
                                virtual_address=virtual_address,
                                file_offset=file_offset,
                                file_size=file_size,
                                memory_size=memory_size,
                            )
                        )
        except ELFError:
            raise
        except (PyElfError, ValueError, IndexError, KeyError, struct.error) as exc:
            raise ELFError(f"failed to parse ELF {self.path}: {exc}") from exc

        if not segments:
            raise ELFError(f"ELF {self.path} has no loadable segments")

        return segments

    def _segment_containing(self, address: int) -> _LoadSegment | None:
        for segment in self._segments:
            if segment.contains(address):
                return segment
        return None

    def mapped_ranges(self) -> list[tuple[int, int]]:
        return [
            (segment.virtual_address, segment.memory_size)
            for segment in sorted(
                self._segments, key=lambda segment: segment.virtual_address
            )
        ]

    def read(self, address: int, length: int) -> bytes:
        if length < 0:
            raise ValueError("read length must be non-negative")
        if length == 0:
            return b""

        result = bytearray()
        current = address
        remaining = length

        while remaining:
            segment = self._segment_containing(current)
            if segment is None:
                raise ValueError(f"virtual address {current:#x} is not mapped")

            offset = current - segment.virtual_address
            chunk_length = min(remaining, segment.memory_size - offset)
            file_length = max(0, min(chunk_length, segment.file_size - offset))

            if file_length:
                start = segment.file_offset + offset
                result.extend(self._data[start : start + file_length])
            if chunk_length > file_length:
                result.extend(b"\0" * (chunk_length - file_length))

            current += chunk_length
            remaining -= chunk_length

        return bytes(result)

    def virtual_to_file(self, address: int) -> int:
        segment = self._segment_containing(address)
        if segment is None:
            raise ValueError(f"virtual address {address:#x} is not mapped")

        offset = address - segment.virtual_address
        if offset >= segment.file_size:
            raise ValueError(f"virtual address {address:#x} is not file-backed")

        return segment.file_offset + offset

    def write(self, address: int, data: bytes) -> None:
        if address < 0:
            raise ValueError("write address must be non-negative")

        if not data:
            return

        segment = self._segment_containing(address)
        if segment is None:
            raise ValueError(f"virtual address {address:#x} is not mapped")

        offset = address - segment.virtual_address
        if offset + len(data) > segment.file_size:
            raise ValueError(
                f"write of {len(data)} bytes at {address:#x} is not "
                "file-backed"
            )

        start = segment.file_offset + offset
        self._data[start : start + len(data)] = data

    def write_to_disk(self, path: str | Path) -> None:
        """Apply metadata fixups and write the in-memory image to ``path``.

        Unwind information, relocations, and symbol sizes are not rewritten
        yet.  The input file's permission bits are copied so the output stays
        executable.
        """
        output = Path(path)
        output.write_bytes(bytes(self._data))
        shutil.copymode(self.path, output)
