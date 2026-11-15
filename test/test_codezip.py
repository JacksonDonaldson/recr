"""Tests for the command-line pipeline wiring."""

from __future__ import annotations

import logging
from pathlib import Path
import re
import shutil

from binary.binary import Binary
from codezip import _render_receipt, build_arg_parser, main
from ir import Address, FreeSpace

GHIDRA_XML = Path(__file__).parent / "fixtures" / "sample_ghidra.xml"

# Ranges freed by the unreferenced-function pass and the outliner.
FREE_RANGES = (
    (0x4010A0, 0x5),
    (0x401B83, 0x26),
    (0x401BC6, 0x8),
    (0x401BEB, 0x8),
    (0x401C10, 0x8),
)

# Live code rewritten by outlining: the shared block and its three callers.
MODIFIED_RANGES = (
    (0x401B75, 0xE),
    (0x401BA9, 0x1D),
    (0x401BCE, 0x1D),
    (0x401BF3, 0x1D),
)

SHARED_BLOCK = bytes.fromhex("897dfc8b45fc01c083c00389c7c3")


def test_verbose_defaults_to_disabled() -> None:
    parser = build_arg_parser()
    args = parser.parse_args(["sample.bin", "sample.yaml"])

    assert args.verbose is False


def test_verbose_flags_are_accepted() -> None:
    parser = build_arg_parser()

    assert parser.parse_args(["sample.bin", "sample.xml", "-v"]).verbose is True
    assert (
        parser.parse_args(["sample.bin", "sample.xml", "--verbose"]).verbose
        is True
    )


def test_outline_report_defaults_to_disabled() -> None:
    parser = build_arg_parser()

    args = parser.parse_args(["sample.bin", "sample.yaml"])

    assert args.report_outline_matches is False


def test_outline_report_flag_is_accepted() -> None:
    parser = build_arg_parser()

    args = parser.parse_args(
        ["sample.bin", "sample.yaml", "--report-outline-matches"]
    )

    assert args.report_outline_matches is True


def test_receipt_defaults_to_disabled() -> None:
    parser = build_arg_parser()

    assert parser.parse_args(["sample.bin", "sample.yaml"]).receipt is None


def test_receipt_takes_a_path() -> None:
    parser = build_arg_parser()

    args = parser.parse_args(
        ["sample.bin", "sample.xml", "--receipt", "receipt.yaml"]
    )

    assert args.receipt == Path("receipt.yaml")


def test_pipeline_writes_binary_with_free_space_filled(
    caplog, capsys, sample_elf: Path, tmp_path: Path
) -> None:
    caplog.set_level(logging.DEBUG, logger="codezip")
    output = tmp_path / "sample.codezip"

    result = main(
        [str(sample_elf), str(GHIDRA_XML), "--verbose", "-o", str(output)]
    )

    assert result == 0
    assert "function main @ 0x40182b" in capsys.readouterr().out

    assert "uplifted 45/45 function(s)" in caplog.text
    assert "recovering cross-references" in caplog.text
    assert "incoming reference(s)" in caplog.text
    assert "removing unreferenced functions" in caplog.text
    assert "marked 2 function(s) as free space" in caplog.text
    assert (
        "free space 0x401b75 (0x34 bytes): "
        "unreferenced function unreferenced_function"
    ) in caplog.text
    assert re.search(
        r"selected 1 of \d+ outline match\(es\)", caplog.text
    )
    assert "filling 5 free space range(s) with 0xff" in caplog.text
    assert f"writing modified binary to {output}" in caplog.text

    original = sample_elf.read_bytes()
    actual = output.read_bytes()
    assert len(actual) == len(original)

    binary = Binary(sample_elf)
    expected = bytearray(original)
    for address, size in FREE_RANGES:
        offset = binary.virtual_to_file(address)
        expected[offset : offset + size] = b"\xff" * size

    # Everything outside the rewritten live-code ranges must match the
    # original apart from the freed ranges.
    modified_offsets: set[int] = set()
    for address, size in MODIFIED_RANGES:
        offset = binary.virtual_to_file(address)
        modified_offsets.update(range(offset, offset + size))
    for index, expected_byte in enumerate(expected):
        if index not in modified_offsets:
            assert actual[index] == expected_byte

    # The shared block starts with the extracted expression and ends in ret.
    shared_offset = binary.virtual_to_file(MODIFIED_RANGES[0][0])
    assert (
        actual[shared_offset : shared_offset + len(SHARED_BLOCK)]
        == SHARED_BLOCK
    )

    # Each caller keeps its frame and replaces the expression with a call.
    for address, _ in MODIFIED_RANGES[1:]:
        offset = binary.virtual_to_file(address)
        assert actual[offset + 0xC] == 0xE8


def test_outline_report_prints_matches_and_exits(
    capsys, sample_elf: Path, tmp_path: Path
) -> None:
    output = tmp_path / "sample.codezip"

    result = main(
        [
            str(sample_elf),
            str(GHIDRA_XML),
            "-o",
            str(output),
            "--report-outline-matches",
        ]
    )

    assert result == 1
    assert not output.exists()

    stdout = capsys.readouterr().out
    assert "profitable basic-block match(es)" in stdout
    assert "match 1:" in stdout
    assert "shared instructions:" in stdout
    assert "source blocks:" in stdout


def test_receipt_records_freed_and_modified_ranges(
    sample_elf: Path, tmp_path: Path
) -> None:
    output = tmp_path / "sample.codezip"
    receipt = tmp_path / "sample.receipt.yaml"

    result = main(
        [
            str(sample_elf),
            str(GHIDRA_XML),
            "-o",
            str(output),
            "--receipt",
            str(receipt),
        ]
    )

    assert result == 0
    assert receipt.read_text(encoding="utf-8") == (
        "freed:\n"
        "  - address: 0x4010a0\n"
        "    length: 0x5\n"
        "  - address: 0x401b83\n"
        "    length: 0x26\n"
        "  - address: 0x401bc6\n"
        "    length: 0x8\n"
        "  - address: 0x401beb\n"
        "    length: 0x8\n"
        "  - address: 0x401c10\n"
        "    length: 0x8\n"
        "modified:\n"
        "  - address: 0x401b75\n"
        "    length: 0xe\n"
        "  - address: 0x401ba9\n"
        "    length: 0x1d\n"
        "  - address: 0x401bce\n"
        "    length: 0x1d\n"
        "  - address: 0x401bf3\n"
        "    length: 0x1d\n"
    )


def test_receipt_with_no_free_space() -> None:
    assert _render_receipt([]) == "freed: []\n"


def test_receipt_records_modified_ranges() -> None:
    free_space = [FreeSpace(Address.absolute(0x2000), 0x10)]
    modified = [
        FreeSpace(Address.absolute(0x1000), 0x20),
        FreeSpace(Address.absolute(0x3000), 0x8),
    ]

    assert _render_receipt(free_space, modified) == (
        "freed:\n"
        "  - address: 0x2000\n"
        "    length: 0x10\n"
        "modified:\n"
        "  - address: 0x1000\n"
        "    length: 0x20\n"
        "  - address: 0x3000\n"
        "    length: 0x8\n"
    )


def test_receipt_with_only_modified_ranges() -> None:
    modified = [FreeSpace(Address.absolute(0x1000), 0x20)]

    assert _render_receipt([], modified) == (
        "freed: []\n"
        "modified:\n"
        "  - address: 0x1000\n"
        "    length: 0x20\n"
    )


def test_receipt_sorts_ranges_by_address() -> None:
    free_space = [
        FreeSpace(Address.absolute(0x2000), 0x20),
        FreeSpace(Address.absolute(0x1000), 0x10),
    ]

    assert _render_receipt(free_space) == (
        "freed:\n"
        "  - address: 0x1000\n"
        "    length: 0x10\n"
        "  - address: 0x2000\n"
        "    length: 0x20\n"
    )


def test_default_output_is_binary_path_plus_codezip(
    sample_elf: Path, tmp_path: Path
) -> None:
    binary = tmp_path / "sample"
    shutil.copyfile(sample_elf, binary)

    result = main([str(binary), str(GHIDRA_XML)])

    assert result == 0
    assert (tmp_path / "sample.codezip").is_file()


def test_non_verbose_mode_does_not_pretty_print(
    capsys, sample_elf: Path, tmp_path: Path
) -> None:
    result = main(
        [str(sample_elf), str(GHIDRA_XML), "-o", str(tmp_path / "out")]
    )

    assert result == 0
    assert capsys.readouterr().out == ""


def test_missing_export_is_reported_as_an_error(
    caplog, sample_elf: Path, tmp_path: Path
) -> None:
    result = main([str(sample_elf), str(tmp_path / "missing.xml")])

    assert result == 1
    assert "does not exist" in caplog.text
