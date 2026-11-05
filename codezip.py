#!/usr/bin/env python3
"""Codezip command-line orchestrator.

Drives the parse -> uplift -> optimize -> verify pipeline and writes the
modified binary plus a report.  The pipeline stages themselves are stubs.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codezip",
        description=(
            "Modify a compiled binary to maximize unused space without "
            "changing its behaviour or layout."
        ),
    )
    parser.add_argument("binary", type=Path, help="input binary to optimize")
    parser.add_argument(
        "re_file",
        type=Path,
        help="function export from a reverse-engineering tool (YAML or Ghidra XML)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="where to write the modified binary (default: <binary>.codezip)",
    )
    parser.add_argument(
        "--isa",
        default=None,
        help="override the ISA named by the input export",
    )
    parser.add_argument(
        "--verify",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="run verification after optimization (default: enabled)",
    )
    return parser


def run_pipeline(args: argparse.Namespace) -> int:
    """Execute the full optimization pipeline."""
    raise NotImplementedError


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_pipeline(args)


if __name__ == "__main__":
    raise SystemExit(main())
