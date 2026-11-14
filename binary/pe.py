"""PE binary support."""

from __future__ import annotations

from pathlib import Path

from binary.binary import Binary


class PE(Binary):
    """A Portable Executable binary."""

    @classmethod
    def open(cls, path: str | Path) -> "PE":
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
