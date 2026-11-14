"""Uplift and pretty-print every function in the sample ELF.

Run directly from the project root:

    python test/uplift_sample.py

The script builds ``test/build/sample`` from ``test/sample.c`` when it is
missing or stale, loads the committed Ghidra XML export, uplifts every parsed
function, and prints the resulting IR.  It exits nonzero if any function
cannot be uplifted.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from binary.binary import Binary
from input_parser import parse_re_file
from parsers.base import ParseResult
from uplifter import Uplifter

TEST_DIR = Path(__file__).resolve().parent
SAMPLE_SOURCE = TEST_DIR / "sample.c"
SAMPLE_ELF = TEST_DIR / "build" / "sample"
GHIDRA_XML = TEST_DIR / "fixtures" / "sample_ghidra.xml"


def _ensure_sample_built() -> None:
    """Build the sample ELF when it is missing or older than its source."""
    if not GHIDRA_XML.is_file():
        raise RuntimeError(f"missing Ghidra XML fixture: {GHIDRA_XML}")

    if (
        SAMPLE_ELF.is_file()
        and SAMPLE_ELF.stat().st_mtime >= SAMPLE_SOURCE.stat().st_mtime
    ):
        return

    try:
        result = subprocess.run(
            ["make", "-C", str(TEST_DIR)],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(
            f"could not run make to build {SAMPLE_ELF}: {exc}"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"could not build {SAMPLE_ELF}\n{result.stdout}{result.stderr}"
        )
    if not SAMPLE_ELF.is_file():
        raise RuntimeError(f"make did not produce {SAMPLE_ELF}")


def load_sample() -> tuple[ParseResult, Binary]:
    """Build and load the sample ELF and its Ghidra XML export."""
    _ensure_sample_built()
    parsed = parse_re_file(str(GHIDRA_XML))
    return parsed, Binary(SAMPLE_ELF)


def uplift_sample() -> tuple[ParseResult, Binary, Uplifter]:
    """Uplift every parsed sample function, rejecting the first failure."""
    parsed, binary = load_sample()
    uplifter = Uplifter(parsed.isa, binary)
    for function in parsed.functions:
        uplifter.uplift_function(function)
    return parsed, binary, uplifter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-pretty",
        action="store_true",
        help="uplift and summarize without printing the IR",
    )
    args = parser.parse_args(argv)

    parsed, binary = load_sample()
    uplifter = Uplifter(parsed.isa, binary)
    failures: list[tuple[str, Exception]] = []

    for function in parsed.functions:
        try:
            uplifter.uplift_function(function)
        except ValueError as exc:
            failures.append((function.name, exc))
        except Exception as exc:  # noqa: BLE001 - the harness reports all errors
            failures.append((function.name, exc))

    for warning in parsed.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    uplifted = len(parsed.functions) - len(failures)
    print(
        f"uplifted {uplifted}/{len(parsed.functions)} functions "
        f"using {parsed.isa} from {SAMPLE_ELF}"
    )

    for name, exc in failures:
        print(f"failed {name}: {exc}", file=sys.stderr)

    if not args.no_pretty:
        for function in parsed.functions:
            if not function.basic_blocks:
                continue
            print()
            function.pretty_print()

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
