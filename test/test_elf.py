"""Tests for ELF binary support."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from binary.binary import Binary, UnsupportedBinaryFormat
from binary.elf import ELF, ELFError
from input_parser import parse_re_file

TEST_DIR = Path(__file__).parent
SAMPLE = TEST_DIR / "build" / "sample"
SAMPLE_SOURCE = TEST_DIR / "sample.c"
GHIDRA_XML = TEST_DIR / "fixtures" / "sample_ghidra.xml"


@pytest.fixture(scope="session")
def sample_elf() -> Path:
    """Return the built sample, rebuilding it with make when necessary."""
    if not SAMPLE.is_file() or SAMPLE.stat().st_mtime < SAMPLE_SOURCE.stat().st_mtime:
        try:
            result = subprocess.run(
                ["make", "-C", str(TEST_DIR)],
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            pytest.skip(f"could not run make to build the sample ELF: {exc}")

        if result.returncode != 0:
            pytest.skip(
                "could not build test/build/sample; run 'make -C test'\n"
                f"{result.stdout}{result.stderr}"
            )

    assert SAMPLE.is_file()
    return SAMPLE


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


def test_write_round_trip(sample_elf: Path, tmp_path: Path) -> None:
    binary = Binary(sample_elf)
    output = tmp_path / "sample.copy"

    binary.finish()
    binary.write(output)

    assert output.read_bytes() == sample_elf.read_bytes()


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
