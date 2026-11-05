"""Common interface for reading and patching binary files."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class Binary(ABC):
    """A binary file that can be read, patched, and written back out."""

    @classmethod
    @abstractmethod
    def open(cls, path: str | Path) -> "Binary":
        """Open and parse the binary at ``path``."""
        raise NotImplementedError

    @abstractmethod
    def read(self, address: int, length: int) -> bytes:
        """Read ``length`` bytes at virtual ``address``."""
        raise NotImplementedError

    @abstractmethod
    def virtual_to_file(self, address: int) -> int:
        """Map a virtual address to a file offset."""
        raise NotImplementedError

    @abstractmethod
    def write(self, path: str | Path) -> None:
        """Write the current (possibly patched) contents to ``path``."""
        raise NotImplementedError

    @abstractmethod
    def finish(self) -> None:
        """Apply required metadata fixups before the binary is written.

        This includes unwind information, relocations that point into moved
        code, and symbol sizes.
        """
        raise NotImplementedError
