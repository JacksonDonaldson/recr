#!/usr/bin/env python3
"""Mutation sensitivity check for the pcre2 end-to-end fixture.

``run_e2e.py`` checks that pcre2's suite still passes after codezip rewrites
its test binaries.  Passing once proves little on its own: a suite that never
executes the rewritten code would also pass.  This script flips random bytes in
the codezipped binaries and runs the matching pcre2 test script.  A suite that
is actually sensitive to the bytes it executes fails on most mutations.

Run it after ``make -C test e2e`` (the artifacts are reused):

    test/e2e/mutation_check.py

By default it mutates executable bytes only, because debug sections, symbol
tables, and read-only data are not executed and would dilute the measurement.
Use ``--region mapped`` or ``--region file`` to include more of the image.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import random
import resource
import signal
import subprocess
import sys

from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parent))

import grep_corpus  # noqa: E402
from run_e2e import BINARIES, X86_LAYOUT  # noqa: E402

SOURCE_DIR = X86_LAYOUT.source
RESULT_DIR = X86_LAYOUT.results
LOG_DIR = X86_LAYOUT.logs / "mutation"
MUTANT_DIR = X86_LAYOUT.root / "mutants"
RESULT_PATH = RESULT_DIR / "mutation.json"

SCRIPTS = {
    "pcre2test": "RunTest",
    "pcre2grep": "RunGrepTest",
}
# The last line each script prints after it has actually run its tests.
PASS_MARKERS = {
    "pcre2test": "All tests passed.",
    "pcre2grep": "Testing miscellaneous pcre2grep arguments",
}
REGIONS = ("code", "mapped", "file")


@dataclass(frozen=True)
class _Range:
    """A run of file bytes, optionally with the address they map to."""

    start: int
    end: int
    virtual_address: int | None

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class _Mutation:
    file_offset: int
    virtual_address: int | None
    original: int
    mutated: int


@dataclass(frozen=True)
class _Trial:
    binary: str
    region: str
    mutations: tuple[_Mutation, ...]
    outcome: str
    returncode: int | None
    message: str


def _fail(message: str) -> None:
    sys.stdout.flush()
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def _load_ranges(path: Path, region: str) -> list[_Range]:
    if region == "file":
        return [_Range(0, path.stat().st_size, None)]

    ranges: list[_Range] = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue

            executable = bool(int(segment["p_flags"]) & 0x1)
            if region == "code" and not executable:
                continue

            size = int(segment["p_filesz"])
            if size == 0:
                continue

            start = int(segment["p_offset"])
            ranges.append(
                _Range(
                    start=start,
                    end=start + size,
                    virtual_address=int(segment["p_vaddr"]),
                )
            )

    if not ranges:
        _fail(f"{path} has no file-backed bytes for region {region!r}")
    return ranges


def _pick_offset(
    rng: random.Random, ranges: list[_Range]
) -> tuple[int, int | None]:
    total = sum(item.size for item in ranges)
    index = rng.randrange(total)
    for item in ranges:
        if index < item.size:
            offset = item.start + index
            address = (
                None
                if item.virtual_address is None
                else item.virtual_address + index
            )
            return offset, address
        index -= item.size
    raise AssertionError("unreachable")


def _mutate(
    data: bytearray,
    ranges: list[_Range],
    rng: random.Random,
    flips: int,
) -> tuple[_Mutation, ...]:
    size = sum(item.size for item in ranges)
    if flips > size:
        _fail(f"cannot flip {flips} distinct bytes in {size} bytes")

    chosen: set[int] = set()
    mutations: list[_Mutation] = []
    while len(mutations) < flips:
        offset, address = _pick_offset(rng, ranges)
        if offset in chosen:
            continue
        chosen.add(offset)
        original = data[offset]
        mutated = original ^ rng.randrange(1, 256)
        data[offset] = mutated
        mutations.append(
            _Mutation(
                file_offset=offset,
                virtual_address=address,
                original=original,
                mutated=mutated,
            )
        )
    return tuple(mutations)


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _run_script(
    binary: str,
    executable: Path,
    *,
    timeout: float,
) -> tuple[int | None, str, bool]:
    """Run the pcre2 test script against ``executable``.

    Returns ``(returncode, output, timed_out)``.  ``returncode`` is ``None``
    when the trial timed out and the process group was killed.
    """
    env = os.environ.copy()
    env["srcdir"] = str(SOURCE_DIR)
    env["builddir"] = str(SOURCE_DIR)
    env[binary] = str(executable)

    process = subprocess.Popen(
        [str(SOURCE_DIR / SCRIPTS[binary])],
        cwd=SOURCE_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        start_new_session=True,
        preexec_fn=_disable_core_dumps,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
        return process.returncode, output, False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        return None, output, True


def _summary_line(output: str) -> str:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("**") or "Segmentation fault" in stripped:
            return stripped[:200]
    lines = output.strip().splitlines()
    return lines[-1][:200] if lines else ""


def _log_path(binary: str, region: str, index: int) -> Path:
    return LOG_DIR / f"{binary}-{region}-{index:03d}.log"


def _write_log(
    path: Path, mutations: tuple[_Mutation, ...], output: str
) -> None:
    header = ", ".join(
        f"offset {item.file_offset:#x}"
        + (
            ""
            if item.virtual_address is None
            else f" (address {item.virtual_address:#x})"
        )
        + f": {item.original:#04x} -> {item.mutated:#04x}"
        for item in mutations
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{header}\n\n{output}", encoding="utf-8")


def _run_trial(
    binary: str,
    region: str,
    index: int,
    original: bytes,
    ranges: list[_Range],
    rng: random.Random,
    flips: int,
    timeout: float,
    corpus: grep_corpus.Corpus | None = None,
    corpus_expected: dict[str, grep_corpus.RunResult] | None = None,
) -> _Trial:
    data = bytearray(original)
    mutations = _mutate(data, ranges, rng, flips)

    MUTANT_DIR.mkdir(parents=True, exist_ok=True)
    mutant = MUTANT_DIR / f"{binary}-{region}-{index:03d}"
    mutant.write_bytes(data)
    mutant.chmod(0o755)

    corpus_problem: str | None = None
    try:
        returncode, output, timed_out = _run_script(
            binary, mutant, timeout=timeout
        )
        if (
            not timed_out
            and returncode == 0
            and corpus is not None
            and corpus_expected is not None
        ):
            corpus_problem = grep_corpus.compare(
                mutant, corpus, corpus_expected, timeout=timeout
            )
            if corpus_problem is not None:
                output += f"\n\ncorpus: {corpus_problem}\n"
    finally:
        mutant.unlink(missing_ok=True)

    if timed_out:
        outcome = "timeout"
    elif returncode < 0:
        outcome = "signal"
    elif returncode > 0:
        outcome = "failure"
    elif corpus_problem is not None:
        outcome = "corpus"
    else:
        marker = PASS_MARKERS[binary]
        if marker not in output:
            _write_log(_log_path(binary, region, index), mutations, output)
            _fail(
                f"{binary} {region} trial {index} exited 0 without running "
                f"the suite; see {_log_path(binary, region, index)}"
            )
        outcome = "pass"

    trial = _Trial(
        binary=binary,
        region=region,
        mutations=mutations,
        outcome=outcome,
        returncode=returncode,
        message=(
            ""
            if outcome == "pass"
            else (corpus_problem or _summary_line(output))
        ),
    )
    if outcome != "pass":
        _write_log(_log_path(binary, region, index), mutations, output)
    return trial


def _check_baseline(
    binary: str,
    timeout: float,
    corpus: grep_corpus.Corpus | None = None,
) -> dict[str, grep_corpus.RunResult] | None:
    executable = RESULT_DIR / f"{binary}.codezip"
    if not executable.is_file():
        _fail(
            f"{executable} is missing; run `make -C test e2e` first"
        )

    returncode, output, timed_out = _run_script(
        binary, executable, timeout=timeout
    )
    log_path = LOG_DIR / f"baseline-{binary}.log"
    _write_log(log_path, (), output)

    if timed_out or returncode != 0:
        _fail(
            f"unmutated {executable.name} did not pass {SCRIPTS[binary]}; "
            f"see {log_path}"
        )
    if PASS_MARKERS[binary] not in output:
        _fail(
            f"{SCRIPTS[binary]} exited 0 without running its tests; "
            f"see {log_path}"
        )

    expected = None
    if corpus is not None:
        try:
            expected = grep_corpus.capture(
                executable, corpus, timeout=timeout
            )
        except (grep_corpus.CorpusError, subprocess.TimeoutExpired) as error:
            _fail(f"unmutated {executable.name}: {error}")
        print(f"baseline {binary} corpus: pass")
    print(f"baseline {binary}: pass")
    return expected


def _trial_record(trial: _Trial) -> dict:
    record = asdict(trial)
    record["mutations"] = [asdict(item) for item in trial.mutations]
    return record


def _print_result(
    binary: str,
    region: str,
    trials: list[_Trial],
    minimum: float,
) -> bool:
    detected = sum(trial.outcome != "pass" for trial in trials)
    total = len(trials)
    rate = detected / total
    outcomes: dict[str, int] = {}
    for trial in trials:
        outcomes[trial.outcome] = outcomes.get(trial.outcome, 0) + 1
    detail = ", ".join(
        f"{name}={count}" for name, count in sorted(outcomes.items())
    )
    status = "ok" if rate >= minimum else "LOW"
    print(
        f"  {binary:9} {region:6} {detected:3}/{total:<3} "
        f"detected = {rate:6.1%}  [{detail}] {status}"
    )
    return rate >= minimum


def _parse_regions(values: list[str]) -> list[str]:
    regions: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part not in REGIONS:
                _fail(
                    f"unknown region {part!r}; choose from {', '.join(REGIONS)}"
                )
            if part not in regions:
                regions.append(part)
    return regions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Flip random bytes in the codezipped pcre2 binaries and measure "
            "how often pcre2's test suite notices."
        )
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=20,
        help="trials per binary and region (default: 20)",
    )
    parser.add_argument(
        "--flips",
        type=int,
        default=1,
        help="distinct bytes to flip per trial (default: 1)",
    )
    parser.add_argument(
        "--region",
        action="append",
        default=None,
        metavar="REGION",
        help=(
            "code, mapped, or file; repeat or use commas "
            "(default: code)"
        ),
    )
    parser.add_argument(
        "--binary",
        action="append",
        default=None,
        choices=BINARIES,
        help="binary to mutate; repeat (default: both)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="random seed; the chosen seed is recorded (default: random)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="seconds before a trial is killed (default: 60)",
    )
    parser.add_argument(
        "--min-failure-rate",
        type=float,
        default=0.4,
        help=(
            "exit nonzero if a binary/region detection rate is lower "
            "(default: 0.4)"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print each trial outcome",
    )
    args = parser.parse_args(argv)
    _disable_core_dumps()

    if args.trials <= 0:
        _fail("--trials must be positive")
    if args.flips <= 0:
        _fail("--flips must be positive")
    if not 0.0 <= args.min_failure_rate <= 1.0:
        _fail("--min-failure-rate must be between 0 and 1")
    if args.timeout <= 0:
        _fail("--timeout must be positive")

    regions = _parse_regions(args.region or ["code"])
    binaries = list(dict.fromkeys(args.binary or BINARIES))
    seed = (
        args.seed
        if args.seed is not None
        else random.SystemRandom().randrange(1 << 63)
    )

    print("Mutation sensitivity check")
    print(f"  artifacts: {RESULT_DIR}")
    print(f"  seed: {seed}")
    print(
        f"  {args.trials} trial(s) per binary and region, "
        f"{args.flips} byte flip(s) each"
    )

    corpus = None
    if "pcre2grep" in binaries:
        executable = RESULT_DIR / "pcre2grep.codezip"
        if not executable.is_file():
            _fail(f"{executable} is missing; run `make -C test e2e` first")
        print("preparing the pcre2grep library corpus")
        try:
            corpus = grep_corpus.build(
                SOURCE_DIR, X86_LAYOUT.root / "grep-corpus", executable
            )
        except (grep_corpus.CorpusError, subprocess.TimeoutExpired) as error:
            _fail(f"pcre2grep corpus: {error}")
        print(f"  corpus: {corpus.root}")

    corpus_expected: dict[str, grep_corpus.RunResult] | None = None
    for binary in binaries:
        expected = _check_baseline(
            binary, args.timeout, corpus if binary == "pcre2grep" else None
        )
        if binary == "pcre2grep":
            corpus_expected = expected

    records: list[dict] = []
    results: dict[str, dict[str, dict]] = {}
    rng = random.Random(seed)
    all_ok = True
    for binary in binaries:
        source = RESULT_DIR / f"{binary}.codezip"
        original = source.read_bytes()
        results[binary] = {}
        for region in regions:
            ranges = _load_ranges(source, region)
            trials: list[_Trial] = []
            for index in range(args.trials):
                trial = _run_trial(
                    binary,
                    region,
                    index,
                    original,
                    ranges,
                    rng,
                    args.flips,
                    args.timeout,
                    corpus if binary == "pcre2grep" else None,
                    corpus_expected if binary == "pcre2grep" else None,
                )
                trials.append(trial)
                if args.verbose:
                    print(
                        f"  trial {binary} {region} {index}: "
                        f"{trial.outcome}"
                    )
                records.append(_trial_record(trial))

            detected = sum(trial.outcome != "pass" for trial in trials)
            outcomes: dict[str, int] = {}
            for trial in trials:
                outcomes[trial.outcome] = outcomes.get(trial.outcome, 0) + 1
            results[binary][region] = {
                "detected": detected,
                "trials": len(trials),
                "rate": detected / len(trials),
                "outcomes": outcomes,
            }
            all_ok &= _print_result(
                binary, region, trials, args.min_failure_rate
            )

    summary = {
        "seed": seed,
        "trials": args.trials,
        "flips": args.flips,
        "regions": regions,
        "binaries": binaries,
        "minimum_failure_rate": args.min_failure_rate,
        "results": results,
        "trial_records": records,
    }
    if corpus is not None:
        summary["corpus"] = {
            "root": str(corpus.root),
            "patterns": {
                mode: sum(
                    1
                    for line in path.read_bytes().split(b"\n")
                    if line
                )
                for mode, path in corpus.patterns.items()
            },
        }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"  summary: {RESULT_PATH}")

    if not all_ok:
        _fail(
            "at least one detection rate is below the requested minimum "
            f"of {args.min_failure_rate:.1%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
