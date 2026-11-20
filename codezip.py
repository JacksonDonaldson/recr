#!/usr/bin/env python3
"""Codezip command-line orchestrator.

Drives the parse -> uplift -> optimize -> write pipeline.  The implemented
stages parse a reverse-engineering export, open the binary, uplift every
function, recover cross-references, remove unreferenced functions, outline
repeated instruction regions, fill the remaining free space with 0xff, write
the modified binary, and optionally write a YAML receipt of the freed and
rewritten ranges.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
import logging
from pathlib import Path

from binary.binary import Binary
from gpu import BackendError
from input_parser import ParseError, parse_re_file
from ir import FreeSpace, Function
from optimizers import function_remover, outliner
from parsers.base import ParseResult
from uplifter import FunctionExtentError, FunctionFallthroughError, Uplifter

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
        help="write a YAML receipt of freed and rewritten ranges to PATH",
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


def _render_receipt(
    free_space: list[FreeSpace],
    modified_ranges: list[FreeSpace] | None = None,
) -> str:
    """Render freed and rewritten ranges as a YAML document."""
    lines: list[str] = []
    if free_space:
        lines.append("freed:")
        for space in sorted(
            free_space, key=lambda item: item.start.value
        ):
            lines.append(f"  - address: {space.start.value:#x}")
            lines.append(f"    length: {space.size:#x}")
    else:
        lines.append("freed: []")

    if modified_ranges:
        lines.append("modified:")
        for space in sorted(
            modified_ranges, key=lambda item: item.start.value
        ):
            lines.append(f"  - address: {space.start.value:#x}")
            lines.append(f"    length: {space.size:#x}")
    return "\n".join(lines) + "\n"


def run_pipeline(
    args: argparse.Namespace, *, protected_entries: frozenset[int] = frozenset(),
    binary: Binary | None = None, parsed: ParseResult | None = None,
    warn: Callable[[str], None] | None = None,
    warn_invalid_extent: Callable[[Function, FunctionExtentError], None] | None = None,
) -> int:
    """Compact and write the image, using caller-supplied input metadata when available."""
    _configure_logging(args.verbose)

    LOGGER.info("loading function export %s", args.re_file)
    if parsed is None:
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
        (warn or LOGGER.warning)(warning)

    isa_name = args.isa or parsed.isa
    LOGGER.info(
        "parsed %d function(s) using ISA %s", len(parsed.functions), isa_name
    )

    LOGGER.info("opening binary %s", args.binary)
    if binary is None:
        try:
            binary = Binary(args.binary)
        except (OSError, ValueError) as exc:
            LOGGER.error("cannot open binary %s: %s", args.binary, exc)
            return 1

    try:
        uplifter = Uplifter(isa_name, binary)
    except (OSError, ValueError) as exc:
        LOGGER.error("cannot initialize ISA %r for %s (export %s). %s", isa_name, args.binary, args.re_file, exc)
        return 1

    failures = 0
    rejected_ranges: list[tuple[int, int]] = []
    fallthrough_targets: set[int] = set()
    for function in parsed.functions:
        LOGGER.debug(
            "uplifting %s @ %#x (%#x bytes)",
            function.name,
            function.start_address,
            function.length,
        )
        try:
            uplifter.uplift_function(function, require_terminator=True)
        except FunctionExtentError as exc:
            if isinstance(exc, FunctionFallthroughError):
                fallthrough_targets.add(exc.target)
            elif warn_invalid_extent is None:
                failures += 1
                LOGGER.error("failed to uplift %s at %#x in %s. %s", function.name, function.start_address, args.binary, exc)
                continue
            if warn_invalid_extent is None:
                LOGGER.warning("%s. Skipping this extent in %s", exc, args.binary)
            else:
                warn_invalid_extent(function, exc)
            rejected_ranges.append((function.start_address, exc.covered_end))
        except (ValueError, NotImplementedError) as exc:
            failures += 1
            LOGGER.error("failed to uplift %s at %#x in %s. %s", function.name, function.start_address, args.binary, exc)
        except Exception as exc:  # noqa: BLE001 - report every function
            failures += 1
            LOGGER.error("failed to uplift %s at %#x in %s. %s: %s", function.name, function.start_address, args.binary, type(exc).__name__, exc)

    uplifted = len(parsed.functions) - failures - len(rejected_ranges)
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
    except (ValueError, BackendError) as exc:
        LOGGER.error("failed to recover cross-references in %s using %s. %s", args.binary, isa_name, exc)
        return 1
    try:
        protected_entries |= uplifter.entries_to_preserve(
            rejected_ranges, fallthrough_targets=fallthrough_targets,
        )
    except (ValueError, BackendError) as exc:
        LOGGER.error("failed to recover references from rejected function extents in %s. %s", args.binary, exc)
        return 1

    xref_count = sum(
        len(function.incoming_references)
        for function in uplifter.function_map.values()
    )
    LOGGER.info("recovered %d incoming reference(s)", xref_count)

    LOGGER.info("removing unreferenced functions")
    free_space = function_remover.run_optimizer(
        binary, uplifter, uplifter.isa, protected_entries=protected_entries,
    )
    LOGGER.info("marked %d function(s) as free space", len(free_space))
    for space in free_space:
        LOGGER.debug(
            "free space %#x (%#x bytes): %s",
            space.start.value,
            space.size,
            space.diagnostic,
        )

    if args.report_outline_matches:
        LOGGER.info("searching for profitable outline matches")
        try:
            outline_result = outliner.extract_instruction_regions(
                binary, uplifter, uplifter.isa, protected_entries=protected_entries, warn=warn,
            )
        except (ValueError, NotImplementedError) as exc:
            LOGGER.error("cannot report outline matches in %s using %s. %s", args.binary, isa_name, exc)
            return 1
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

    LOGGER.info("outlining repeated instruction regions")
    try:
        outline_result = outliner.run_optimizer(
            binary, uplifter, uplifter.isa, free_space, protected_entries=protected_entries, warn=warn,
        )
    except (ValueError, NotImplementedError) as exc:
        LOGGER.error("outlining failed for %s using %s. %s", args.binary, isa_name, exc)
        return 1

    if outline_result is not None:
        LOGGER.info(
            "selected %d of %d outline match(es)",
            len(outline_result.selected_matches),
            len(outline_result.matches),
        )

    LOGGER.info("filling %d free space range(s) with 0xff", len(free_space))
    for space in free_space:
        try:
            binary.write(space.start.value, b"\xff" * space.size)
        except ValueError as exc:
            LOGGER.error("cannot fill %d freed bytes at %#x in %s. %s", space.size, space.start.value, args.binary, exc)
            return 1

    output = args.output
    if output is None:
        output = args.binary.with_name(args.binary.name + ".codezip")

    LOGGER.info("writing modified binary to %s", output)
    try:
        binary.write_to_disk(output)
    except OSError as exc:
        LOGGER.error("cannot write modified binary to %s. %s", output, exc)
        return 1

    if args.receipt is not None:
        modified_ranges = (
            outline_result.modified_ranges
            if outline_result is not None
            else []
        )
        LOGGER.info("writing receipt to %s", args.receipt)
        try:
            args.receipt.write_text(_render_receipt(free_space, modified_ranges), encoding="utf-8")
        except OSError as exc:
            LOGGER.error("modified binary written to %s, but cannot write receipt to %s. %s", output, args.receipt, exc)
            return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return run_pipeline(args)


if __name__ == "__main__":
    raise SystemExit(main())
