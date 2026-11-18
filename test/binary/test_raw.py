"""Check virtual-to-file mapping and writes for headerless images."""

from __future__ import annotations

from pathlib import Path

import pytest

from binary.raw import RawBinary, Region


def test_raw_virtual_neighbors_can_be_disjoint_in_the_file(tmp_path: Path) -> None:
    path = tmp_path / "image.bin"
    path.write_bytes(b"headEF-gap-ABCDtail")
    image = RawBinary(path, [Region(0x1004, 4, 2, 5), Region(0x1000, 11, 4, 5)])
    assert image.mapped_ranges() == [(0x1000, 4), (0x1004, 2)]
    assert image.mapped_segments() == [(0x1004, 4, 2, 2), (0x1000, 11, 4, 4)]
    assert image.read(0x1002, 4) == b"CDEF"
    assert image.virtual_to_file(0x1005) == 5
    with pytest.raises(ValueError, match="not mapped"):
        image.read(0x1004, 3)
    with pytest.raises(ValueError, match="crosses a raw region boundary"):
        image.write(0x1003, b"ab")
    assert image.image_revision() == 0
    image.write(0x1004, b"XY")
    assert image.image_revision() == 1
    output = tmp_path / "patched.bin"
    image.write_to_disk(output)
    assert output.read_bytes() == b"headXY-gap-ABCDtail"
    assert path.read_bytes() == b"headEF-gap-ABCDtail"
