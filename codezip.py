#!/usr/bin/env python3
"""Codezip command-line orchestrator.

Drives the parse -> uplift -> optimize -> verify pipeline.  The implemented
stages parse a reverse-engineering export, open the binary, and uplift every
function; the pipeline intentionally stops there until the later stages exist.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from binary.binary import Binary
from input_parser import ParseError, parse_re_file
from uplifter import Uplifter

LOGGER = logging.getLogger("codezip")


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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log pipeline progress and pretty-print every uplifted function",
    )
    return parser


def _configure_logging(verbose: bool) -> None:
    """Route codezip logs to stderr at the requested verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=level,
            format="%(levelname)s: %(message)s",
        )
    LOGGER.setLevel(level)


def run_pipeline(args: argparse.Namespace) -> int:
    """Parse, open, and uplift every function, then report the unimplemented tail.

    The optimizer and verifier are still stubs, so a successful uplift run is
    still a failure from the pipeline's point of view.
    """
    _configure_logging(args.verbose)

    LOGGER.info("loading function export %s", args.re_file)
    try:
        parsed = parse_re_file(str(args.re_file))
    except ParseError as exc:
        LOGGER.error("%s", exc)
        return 1
    except NotImplementedError as exc:
        detail = str(exc) or "parser is not implemented"
        LOGGER.error("cannot parse %s: %s", args.re_file, detail)
        return 1

    for warning in parsed.warnings:
        LOGGER.warning("%s", warning)

    isa_name = args.isa or parsed.isa
    LOGGER.info(
        "parsed %d function(s) using ISA %s", len(parsed.functions), isa_name
    )

    LOGGER.info("opening binary %s", args.binary)
    try:
        binary = Binary(args.binary)
    except (OSError, ValueError) as exc:
        LOGGER.error("cannot open binary %s: %s", args.binary, exc)
        return 1

    try:
        uplifter = Uplifter(isa_name, binary)
    except ValueError as exc:
        LOGGER.error("%s", exc)
        return 1

    failures = 0
    for function in parsed.functions:
        LOGGER.debug(
            "uplifting %s @ %#x (%#x bytes)",
            function.name,
            function.start_address,
            function.length,
        )
        try:
            uplifter.uplift_function(function)
        except (ValueError, NotImplementedError) as exc:
            failures += 1
            LOGGER.error("failed to uplift %s: %s", function.name, exc)
        except Exception as exc:  # noqa: BLE001 - report every function
            failures += 1
            LOGGER.error("failed to uplift %s: %s", function.name, exc)

    uplifted = len(parsed.functions) - failures
    LOGGER.info(
        "uplifted %d/%d function(s)", uplifted, len(parsed.functions)
    )

    if args.verbose:
        for function in parsed.functions:
            if not function.basic_blocks:
                continue
            print()
            function.pretty_print()

    if failures:
        LOGGER.error("failed to uplift %d function(s)", failures)
        return 1

    LOGGER.error(
        "pipeline stops after uplifting all functions: "
        "optimization and verification are not implemented"
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_pipeline(args)


if __name__ == "__main__":
    raise SystemExit(main())
