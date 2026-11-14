"""Tests for ELF binary support."""

from __future__ import annotations

from pathlib import Path

import pytest

from binary.binary import Binary, UnsupportedBinaryFormat
from binary.elf import ELF, ELFError
from input_parser import parse_re_file

GHIDRA_XML = Path(__file__).parents[1] / "fixtures" / "sample_ghidra.xml"


def test_binary_constructor_routes_elf(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    assert isinstance(binary, ELF)
    assert isinstance(Binary.open(sample_elf), ELF)


def test_read_main_function_from_ghidra_export(sample_elf: Path) -> None:
    result = parse_re_file(str(GHIDRA_XML))
    main = next(function for function in result.functions if function.name == "main")

    assert main.start_address == 0x40182B
    assert main.length == 0x2CC

    binary = Binary(sample_elf)
    file_offset = binary.virtual_to_file(main.start_address)
    main_bytes = binary.read(main.start_address, main.length)
    file_bytes = sample_elf.read_bytes()

    assert file_offset == 0x182B
    assert len(main_bytes) == main.length
    assert main_bytes == file_bytes[file_offset : file_offset + main.length]

    # main starts with endbr64 followed by the standard -O0 frame setup, and
    # ends with leave; ret.
    assert main_bytes[:4] == b"\xf3\x0f\x1e\xfa"
    assert main_bytes[4:8] == b"\x55\x48\x89\xe5"
    assert main_bytes[-2:] == b"\xc9\xc3"


def test_virtual_to_file_maps_load_segments(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    assert binary.virtual_to_file(0x400000) == 0
    assert binary.read(0x400000, 4) == b"\x7fELF"

    assert binary.virtual_to_file(0x401156) == 0x1156
    assert binary.read(0x401156, 4) == b"\xf3\x0f\x1e\xfa"


def test_mapped_ranges_reports_load_segments(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    assert binary.mapped_ranges() == [
        (0x400000, 0x558),
        (0x401000, 0xB39),
        (0x402000, 0x5F4),
        (0x403DF8, 0x230),
    ]



def test_read_zero_fills_bss(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    assert binary.read(0x404020, 8) == b"\0" * 8
    with pytest.raises(ValueError, match="not file-backed"):
        binary.virtual_to_file(0x404020)


def test_unmapped_addresses_are_rejected(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    with pytest.raises(ValueError, match="not mapped"):
        binary.read(0, 4)
    with pytest.raises(ValueError, match="not mapped"):
        binary.virtual_to_file(0)


def test_write_to_disk_round_trip(sample_elf: Path, tmp_path: Path) -> None:
    binary = Binary(sample_elf)
    output = tmp_path / "sample.copy"

    binary.write_to_disk(output)

    assert output.read_bytes() == sample_elf.read_bytes()
    assert output.stat().st_mode == sample_elf.stat().st_mode


def test_write_patches_only_the_in_memory_image(
    sample_elf: Path, tmp_path: Path
) -> None:
    binary = Binary(sample_elf)
    original = sample_elf.read_bytes()
    address = 0x401156
    file_offset = binary.virtual_to_file(address)

    binary.write(address, b"\xcc\xcc")

    assert binary.read(address, 2) == b"\xcc\xcc"
    assert sample_elf.read_bytes() == original

    output = tmp_path / "patched"
    binary.write_to_disk(output)

    assert output.read_bytes() == (
        original[:file_offset] + b"\xcc\xcc" + original[file_offset + 2 :]
    )


def test_write_rejects_unmapped_addresses(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    with pytest.raises(ValueError, match="not mapped"):
        binary.write(0, b"\0")
    with pytest.raises(ValueError, match="non-negative"):
        binary.write(-1, b"\0")


def test_write_rejects_non_file_backed_ranges(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    with pytest.raises(ValueError, match="not file-backed"):
        binary.write(0x404020, b"\0")

    # .text is mapped up to 0x401b39 but the range must stay in one segment.
    with pytest.raises(ValueError, match="not file-backed"):
        binary.write(0x401B38, b"\0\0")


def test_write_of_no_bytes_is_a_noop(sample_elf: Path) -> None:
    binary = Binary(sample_elf)

    binary.write(0, b"")


def test_elf_rejects_malformed_file(tmp_path: Path) -> None:
    path = tmp_path / "truncated.elf"
    path.write_bytes(b"\x7fELF")

    with pytest.raises(ELFError, match="failed to parse ELF"):
        ELF(path)
    with pytest.raises(ELFError, match="failed to parse ELF"):
        Binary(path)


def test_binary_constructor_rejects_unrecognized_format(tmp_path: Path) -> None:
    path = tmp_path / "unknown.bin"
    path.write_bytes(b"\0" * 16)

    with pytest.raises(UnsupportedBinaryFormat, match="not a supported binary"):
        Binary(path)


def test_binary_constructor_rejects_unimplemented_pe(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ" + b"\0" * 14)

    with pytest.raises(UnsupportedBinaryFormat, match="PE backend"):
        Binary(path)
