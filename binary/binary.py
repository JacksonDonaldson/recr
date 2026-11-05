"""Common interface for reading and patching binary files."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"


class UnsupportedBinaryFormat(ValueError):
    """Raised when no Binary backend can handle a file."""


def _select_backend(path: Path) -> type["Binary"]:
    with path.open("rb") as stream:
        magic = stream.read(4)

    if magic == ELF_MAGIC:
        from binary.elf import ELF

        return ELF

    if magic.startswith(PE_MAGIC):
        raise UnsupportedBinaryFormat(
            f"{path} is a PE binary; the PE backend is not implemented yet"
        )

    raise UnsupportedBinaryFormat(
        f"{path} is not a supported binary format (expected ELF magic)"
    )


class Binary(ABC):
    """A binary file that can be read, patched, and written back out."""

    def __new__(
        cls, path: str | Path, *args: object, **kwargs: object
    ) -> "Binary":
        if cls is Binary:
            target = _select_backend(Path(path))
            return object.__new__(target)
        return super().__new__(cls)

    @classmethod
    def open(cls, path: str | Path) -> "Binary":
        """Open and parse the binary at ``path``."""
        return cls(path)

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
