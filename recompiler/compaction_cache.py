"""Cache raw-image compaction across edits to the recr extension."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
from typing import TYPE_CHECKING

import cache
from optimizers.outliner import FunctionRewrite

if TYPE_CHECKING:
    from binary.raw import RawBinary
    from recompiler.raw import RawInput


Receipt = dict[str, list[dict[str, int]]]
WarningEvent = str | tuple[int, int, str]
_SOURCE_ROOT = Path(__file__).resolve().parent.parent


def entry_path(raw: RawInput, protected: frozenset[int]) -> Path | None:
    uid = os.getuid()
    directory = cache.CACHE_ROOT.with_name(f"codezip-recr-{uid}")
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        return None

    binary = raw.binary
    digest = sha256(binary.image_bytes())
    metadata = (
        sys.implementation.cache_tag, raw.parsed.isa, sorted(protected), raw.parsed.warnings,
        [(f.name, f.start_address, f.file_offset, f.length) for f in raw.parsed.functions],
        raw.parsed.switch_case_ranges,
        [(r.start_address, r.file_offset, r.length, r.flags) for r in binary.regions],
        sorted(raw.symbols.items()),
    )
    digest.update(json.dumps(metadata).encode())

    # Editable and installed builds both include these sources and decoder tables.
    sources = [_SOURCE_ROOT / name for name in ("codezip.py", "ir.py", "recr.py", "uplifter.py")]
    for package in ("binary", "gpu", "isa", "optimizers", "recompiler"):
        sources.extend(
            path for path in (_SOURCE_ROOT / package).rglob("*")
            if path.suffix in (".py", ".sla", ".cu")
        )
    try:
        for source in sorted(sources):
            digest.update(sha256(source.read_bytes()).digest())
    except OSError:
        return None
    return directory / f"{digest.hexdigest()}.json"


@dataclass
class Compaction:
    receipt: Receipt
    patches: list[tuple[int, str]]
    warnings: list[WarningEvent]
    rewrites: list[FunctionRewrite]

    def apply(self, binary: RawBinary) -> None:
        for address, data in self.patches:
            binary.write(address, bytes.fromhex(data))
        for region in self.receipt["freed"]:
            binary.write(region["address"], b"\xff" * region["length"])


def load(path: Path) -> Compaction | None:
    try:
        checksum, _, data = path.read_bytes().partition(b"\n")
    except OSError:
        return None
    if checksum != sha256(data).hexdigest().encode():
        return None
    entry = json.loads(data)
    return Compaction(
        entry["receipt"],
        [tuple(patch) for patch in entry["patches"]],
        [event if isinstance(event, str) else tuple(event) for event in entry["warnings"]],
        [
            FunctionRewrite(
                item["start"], item["live_end"], item["original_end"],
                tuple((start, end) for start, end in item["shared_blocks"]),
            )
            for item in entry["rewrites"]
        ],
    )


def store(
    path: Path, binary: RawBinary, receipt: Receipt, warnings: list[WarningEvent],
    rewrites: list[FunctionRewrite],
) -> None:
    data = json.dumps({
        "receipt": receipt,
        "patches": [
            (region["address"], binary.read(region["address"], region["length"]).hex())
            for region in receipt.get("modified", [])
        ],
        "warnings": warnings,
        "rewrites": [asdict(rewrite) for rewrite in rewrites],
    }, separators=(",", ":")).encode()
    checksum = sha256(data).hexdigest().encode()
    try:
        cache.replace(path, lambda pending: pending.write_bytes(checksum + b"\n" + data))
    except OSError:
        # An unavailable cache does not prevent writing the recr output.
        pass
