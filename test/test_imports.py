"""Smoke tests for the first-pass project scaffold."""

from __future__ import annotations


def test_core_modules_import() -> None:
    import codezip
    import input_parser
    import ir
    import uplifter


def test_x86_64_isa_is_registered() -> None:
    from isa import X86_64ISA, create_isa

    isa = create_isa("x86_64")
    assert isinstance(isa, X86_64ISA)


def test_cli_parser_builds() -> None:
    from codezip import build_arg_parser

    parser = build_arg_parser()
    args = parser.parse_args(["sample.bin", "sample.yaml"])
    assert args.output is None
    assert args.receipt is None
