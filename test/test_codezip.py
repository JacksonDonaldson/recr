"""Tests for the command-line pipeline wiring."""

from __future__ import annotations

import logging
from pathlib import Path
import shutil

from binary.binary import Binary
from codezip import build_arg_parser, main

GHIDRA_XML = Path(__file__).parent / "fixtures" / "sample_ghidra.xml"

# Declared extents of the sample's unreferenced functions, from the fixture.
FREE_RANGES = (
    (0x4010A0, 0x5),
    (0x401AF7, 0x34),
)


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

    assert "uplifted 40/40 function(s)" in caplog.text
    assert "recovering cross-references" in caplog.text
    assert "incoming reference(s)" in caplog.text
    assert "removing unreferenced functions" in caplog.text
    assert "marked 2 function(s) as free space" in caplog.text
    assert (
        "free space 0x401af7 (0x34 bytes): "
        "unreferenced function unreferenced_function"
    ) in caplog.text
    assert "filling 2 free space range(s) with 0xff" in caplog.text
    assert f"writing modified binary to {output}" in caplog.text
    assert "verification is not implemented" in caplog.text

    original = sample_elf.read_bytes()
    expected = bytearray(original)
    binary = Binary(sample_elf)
    for address, size in FREE_RANGES:
        offset = binary.virtual_to_file(address)
        expected[offset : offset + size] = b"\xff" * size

    assert output.read_bytes() == bytes(expected)
    assert len(output.read_bytes()) == len(original)


def test_no_verify_does_not_warn(caplog, sample_elf: Path, tmp_path: Path) -> None:
    caplog.set_level(logging.DEBUG, logger="codezip")

    result = main(
        [
            str(sample_elf),
            str(GHIDRA_XML),
            "--no-verify",
            "-o",
            str(tmp_path / "sample.codezip"),
        ]
    )

    assert result == 0
    assert "verification is not implemented" not in caplog.text


def test_default_output_is_binary_path_plus_codezip(
    sample_elf: Path, tmp_path: Path
) -> None:
    binary = tmp_path / "sample"
    shutil.copyfile(sample_elf, binary)

    result = main([str(binary), str(GHIDRA_XML), "--no-verify"])

    assert result == 0
    assert (tmp_path / "sample.codezip").is_file()


def test_unwritable_output_is_reported(
    caplog, sample_elf: Path, tmp_path: Path
) -> None:
    output = tmp_path / "missing" / "sample.codezip"

    result = main(
        [
            str(sample_elf),
            str(GHIDRA_XML),
            "--no-verify",
            "-o",
            str(output),
        ]
    )

    assert result == 1
    assert "cannot write" in caplog.text


def test_non_verbose_mode_does_not_pretty_print(
    capsys, sample_elf: Path, tmp_path: Path
) -> None:
    result = main(
        [
            str(sample_elf),
            str(GHIDRA_XML),
            "--no-verify",
            "-o",
            str(tmp_path / "sample.codezip"),
        ]
    )

    assert result == 0
    assert capsys.readouterr().out == ""


def test_missing_export_is_reported_as_an_error(
    caplog, sample_elf: Path, tmp_path: Path
) -> None:
    result = main([str(sample_elf), str(tmp_path / "missing.xml")])

    assert result == 1
    assert "does not exist" in caplog.text
