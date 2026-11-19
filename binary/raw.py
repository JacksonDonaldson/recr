"""File-backed virtual address mappings for headerless binary images."""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import shutil

from binary.binary import Binary


@dataclass(frozen=True)
class Region:
    start_address: int
    file_offset: int
    length: int
    flags: int

    @property
    def end_address(self) -> int:
        return self.start_address + self.length

    @property
    def end_offset(self) -> int:
        return self.file_offset + self.length


class RawBinary(Binary):
    """Map explicit regions of a file while preserving its full byte image."""

    def __init__(
        self, path: str | Path, regions: Sequence[Region], symbols: Mapping[str, int] | None = None,
    ) -> None:
        self.path = Path(path)
        self._data = bytearray(self.path.read_bytes())
        self._revision = 0
        self._symbols = dict(symbols or {})
        self.regions = tuple(sorted(regions, key=lambda region: region.start_address))
        self._starts = tuple(region.start_address for region in self.regions)
        self._file_order = tuple(sorted(self.regions, key=lambda region: region.file_offset))
        if not self.regions:
            raise ValueError(f"raw binary {self.path} requires at least one mapped region with a file_offset")
        for region in self.regions:
            if region.start_address < 0 or region.end_address > 1 << 64:
                raise ValueError(f"raw region [{region.start_address:#x}, {region.end_address:#x}) is outside the 64-bit virtual address space")
            if region.length <= 0 or region.file_offset < 0:
                raise ValueError(f"raw region at {region.start_address:#x} requires a positive length and non-negative file offset. Received {region.length:#x} and {region.file_offset:#x}")
            if region.end_offset > len(self._data):
                raise ValueError(
                    f"raw region at {region.start_address:#x} extends past the end of the file {self.path}. "
                    f"File offsets [{region.file_offset:#x}, {region.end_offset:#x}) exceed the image size {len(self._data):#x}"
                )
        for left, right in zip(self.regions, self.regions[1:]):
            if left.end_address > right.start_address:
                raise ValueError(f"raw regions overlap in virtual address space. Region at {left.start_address:#x} ends at {left.end_address:#x}, past the start {right.start_address:#x} of the next region")
        for left, right in zip(self._file_order, self._file_order[1:]):
            if left.end_offset > right.file_offset:
                raise ValueError(f"raw regions overlap in the file {self.path}. Offsets [{left.file_offset:#x}, {left.end_offset:#x}) and [{right.file_offset:#x}, {right.end_offset:#x}) overlap")

    @classmethod
    def open(
        cls, path: str | Path, regions: Sequence[Region], symbols: Mapping[str, int] | None = None,
    ) -> RawBinary:
        return cls(path, regions, symbols)

    def region_at(self, address: int) -> Region:
        index = bisect_right(self._starts, address) - 1
        if index >= 0 and address < self.regions[index].end_address:
            return self.regions[index]
        raise ValueError(f"virtual address {address:#x} is not mapped in raw image {self.path}")

    def mapped_ranges(self) -> list[tuple[int, int]]:
        return [(r.start_address, r.length) for r in self.regions]

    def mapped_segments(self) -> list[tuple[int, int, int, int]]:
        return [(r.start_address, r.file_offset, r.length, r.length) for r in self._file_order]

    def image_bytes(self) -> bytes:
        return bytes(self._data)

    def image_revision(self) -> int:
        return self._revision

    def symbol_address(self, name: str) -> int | None:
        return self._symbols.get(name)

    def read(self, address: int, length: int) -> bytes:
        if length < 0:
            raise ValueError(f"read length must be non-negative. Received {length} at {address:#x}")
        data = bytearray()
        while length:
            region = self.region_at(address)
            chunk = min(length, region.end_address - address)
            offset = region.file_offset + address - region.start_address
            data.extend(self._data[offset:offset + chunk])
            address += chunk
            length -= chunk
        return bytes(data)

    def virtual_to_file(self, address: int) -> int:
        region = self.region_at(address)
        return region.file_offset + address - region.start_address

    def write(self, address: int, data: bytes) -> None:
        if not data:
            return
        region = self.region_at(address)
        if address + len(data) > region.end_address:
            raise ValueError(f"write at {address:#x} crosses a raw region boundary. Requested {len(data)} bytes, but the region ends at {region.end_address:#x} (exclusive)")
        offset = region.file_offset + address - region.start_address
        self._data[offset:offset + len(data)] = data
        self._revision += 1

    def write_to_disk(self, path: str | Path) -> None:
        output = Path(path)
        output.write_bytes(self._data)
        shutil.copymode(self.path, output)
