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
            raise ValueError("raw binary requires at least one mapped region")
        for region in self.regions:
            if region.start_address < 0 or region.end_address > 1 << 64:
                raise ValueError("raw region is outside the virtual address space")
            if region.length <= 0 or region.file_offset < 0:
                raise ValueError("raw region requires a positive length and non-negative file offset")
            if region.end_offset > len(self._data):
                raise ValueError(f"raw region at {region.start_address:#x} extends past the end of the file")
        for left, right in zip(self.regions, self.regions[1:]):
            if left.end_address > right.start_address:
                raise ValueError("raw regions overlap in virtual address space")
        for left, right in zip(self._file_order, self._file_order[1:]):
            if left.end_offset > right.file_offset:
                raise ValueError("raw regions overlap in the file")

    @classmethod
    def open(
        cls, path: str | Path, regions: Sequence[Region], symbols: Mapping[str, int] | None = None,
    ) -> RawBinary:
        return cls(path, regions, symbols)

    def region_at(self, address: int) -> Region:
        index = bisect_right(self._starts, address) - 1
        if index >= 0 and address < self.regions[index].end_address:
            return self.regions[index]
        raise ValueError(f"virtual address {address:#x} is not mapped")

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
            raise ValueError("read length must be non-negative")
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
            raise ValueError(f"write at {address:#x} crosses a raw region boundary")
        offset = region.file_offset + address - region.start_address
        self._data[offset:offset + len(data)] = data
        self._revision += 1

    def write_to_disk(self, path: str | Path) -> None:
        output = Path(path)
        output.write_bytes(self._data)
        shutil.copymode(self.path, output)
