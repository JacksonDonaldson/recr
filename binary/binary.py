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
        f"{path} is not a supported binary format. Expected ELF magic, read {magic.hex(' ') or '<empty file>'}. "
        "For a headerless image, use recr with a raw-image YAML manifest"
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
    def mapped_ranges(self) -> list[tuple[int, int]]:
        """Return ``(virtual address, size)`` for each mapped range."""
        raise NotImplementedError

    @abstractmethod
    def mapped_segments(self) -> list[tuple[int, int, int, int]]:
        """Return ``(virtual address, file offset, file size, memory size)``.

        These are the loadable segments behind :meth:`mapped_ranges`, in file
        order.  Bulk scanners use them to map addresses to file bytes.
        """
        raise NotImplementedError

    @abstractmethod
    def image_bytes(self) -> bytes:
        """Return a snapshot of the current in-memory file image."""
        raise NotImplementedError

    def image_revision(self) -> int:
        """Return a counter that changes whenever the image is patched."""
        return 0

    def symbol_address(self, name: str) -> int | None:
        """Return the virtual address of a defined symbol, if available."""
        return None

    @abstractmethod
    def read(self, address: int, length: int) -> bytes:
        """Read ``length`` bytes at virtual ``address``."""
        raise NotImplementedError

    @abstractmethod
    def virtual_to_file(self, address: int) -> int:
        """Map a virtual address to a file offset."""
        raise NotImplementedError

    @abstractmethod
    def write(self, address: int, data: bytes) -> None:
        """Patch ``data`` into the in-memory image at virtual ``address``.

        The input file is never modified.  The write must stay inside one
        loadable, file-backed range.
        """
        raise NotImplementedError

    @abstractmethod
    def write_to_disk(self, path: str | Path) -> None:
        """Apply metadata fixups and write the in-memory image to ``path``.

        This includes unwind information, relocations that point into moved
        code, and symbol sizes.
        """
        raise NotImplementedError
