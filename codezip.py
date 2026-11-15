#!/usr/bin/env python3
"""Codezip command-line orchestrator.

Drives the parse -> uplift -> optimize -> write pipeline.  The implemented
stages parse a reverse-engineering export, open the binary, uplift every
function, recover cross-references, detect unreferenced-function free space,
fill that space with 0xff, write the modified binary, and optionally write a
YAML receipt of the freed ranges.  The outliner currently reports profitable
basic-block matches; it does not generate replacement bytes yet.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from binary.binary import Binary
from input_parser import ParseError, parse_re_file
from ir import FreeSpace
from optimizers import function_remover, outliner
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
        "-r",
        "--receipt",
        type=Path,
        default=None,
        metavar="PATH",
        help="write a YAML receipt of the freed ranges to PATH",
    )
    parser.add_argument(
        "--isa",
        default=None,
        help="override the ISA named by the input export",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log pipeline progress and pretty-print every uplifted function",
    )
    parser.add_argument(
        "--report-outline-matches",
        action="store_true",
        help=(
            "temporary: print every profitable outline match and exit "
            "with status 1 without writing an output binary"
        ),
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


def _render_receipt(free_space: list[FreeSpace]) -> str:
    """Render the freed ranges as a YAML document."""
    if not free_space:
        return "freed: []\n"

    lines = ["freed:"]
    for space in sorted(free_space, key=lambda space: space.start.value):
        lines.append(f"  - address: {space.start.value:#x}")
        lines.append(f"    length: {space.size:#x}")
    return "\n".join(lines) + "\n"


def run_pipeline(args: argparse.Namespace) -> int:
    """Parse, uplift, recover references, match outline candidates, and write.

    The outliner only finds profitable basic-block matches for now; it does not
    generate replacement bytes or regenerate instructions.
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

    LOGGER.info("recovering cross-references")
    try:
        uplifter.build_xrefs()
    except ValueError as exc:
        LOGGER.error("failed to recover cross-references: %s", exc)
        return 1

    xref_count = sum(
        len(function.incoming_references)
        for function in uplifter.function_map.values()
    )
    LOGGER.info("recovered %d incoming reference(s)", xref_count)

    LOGGER.info("removing unreferenced functions")
    free_space = function_remover.run_optimizer(
        binary, uplifter, uplifter.isa
    )
    LOGGER.info("marked %d function(s) as free space", len(free_space))
    for space in free_space:
        LOGGER.debug(
            "free space %#x (%#x bytes): %s",
            space.start.value,
            space.size,
            space.diagnostic,
        )

    LOGGER.info("searching for profitable outline matches")
    try:
        outline_result = outliner.run_optimizer(
            binary, uplifter, uplifter.isa, free_space
        )
    except (ValueError, NotImplementedError) as exc:
        LOGGER.error("outlining failed: %s", exc)
        return 1

    if args.report_outline_matches:
        if outline_result is None:
            print("outlining is not supported by this ISA")
        else:
            print(
                f"{len(outline_result.matches)} profitable basic-block "
                "match(es)"
            )
            for index, match in enumerate(outline_result.matches, start=1):
                print()
                print(f"match {index}:")
                for line in outliner.format_match(match):
                    print(line)
        return 1

    LOGGER.info("filling %d free space range(s) with 0xff", len(free_space))
    for space in free_space:
        binary.write(space.start.value, b"\xff" * space.size)

    output = args.output
    if output is None:
        output = args.binary.with_name(args.binary.name + ".codezip")

    LOGGER.info("writing modified binary to %s", output)
    binary.write_to_disk(output)

    if args.receipt is not None:
        LOGGER.info("writing receipt to %s", args.receipt)
        args.receipt.write_text(_render_receipt(free_space), encoding="utf-8")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_pipeline(args)


if __name__ == "__main__":
    raise SystemExit(main())
