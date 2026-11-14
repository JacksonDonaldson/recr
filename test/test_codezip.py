"""Tests for the command-line pipeline wiring."""

from __future__ import annotations

import logging
from pathlib import Path

from codezip import build_arg_parser, main

GHIDRA_XML = Path(__file__).parent / "fixtures" / "sample_ghidra.xml"


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


def test_pipeline_uplifts_everything_then_exits_with_error(
    caplog, capsys, sample_elf: Path
) -> None:
    caplog.set_level(logging.DEBUG, logger="codezip")

    result = main([str(sample_elf), str(GHIDRA_XML), "--verbose"])

    assert result == 1
    output = capsys.readouterr().out
    assert "function main @ 0x40182b" in output
    assert "function divide_safe @ 0x40119b" in output

    assert "uplifted 39/39 function(s)" in caplog.text
    assert "optimization and verification are not implemented" in caplog.text


def test_non_verbose_mode_does_not_pretty_print(capsys, sample_elf: Path) -> None:
    result = main([str(sample_elf), str(GHIDRA_XML)])

    assert result == 1
    assert capsys.readouterr().out == ""


def test_missing_export_is_reported_as_an_error(
    caplog, sample_elf: Path, tmp_path: Path
) -> None:
    result = main([str(sample_elf), str(tmp_path / "missing.xml")])

    assert result == 1
    assert "does not exist" in caplog.text
