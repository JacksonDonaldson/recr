"""Raw binary support."""

from __future__ import annotations

from pathlib import Path

from binary.binary import Binary


class RawBinary(Binary):
    """A headerless binary image loaded at a fixed base address."""

    @classmethod
    def open(cls, path: str | Path) -> "RawBinary":
        raise NotImplementedError

    def mapped_ranges(self) -> list[tuple[int, int]]:
        raise NotImplementedError

    def read(self, address: int, length: int) -> bytes:
        raise NotImplementedError

    def virtual_to_file(self, address: int) -> int:
        raise NotImplementedError

    def write(self, address: int, data: bytes) -> None:
        raise NotImplementedError

    def write_to_disk(self, path: str | Path) -> None:
        raise NotImplementedError
