#!/usr/bin/env python3
"""End-to-end codezip check against a pinned pcre2 build.

Build pcre2 with full debug information and no optimization, export its
functions with Ghidra, run its test suite, rewrite the test executables with
codezip, and require the suite to pass again.  The run is opt-in because it
needs network access on the first invocation and takes several minutes.

Run it with ``make -C test e2e``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TEST_DIR.parent

sys.path.insert(0, str(PROJECT_ROOT))

from binary.binary import Binary  # noqa: E402
import grep_corpus  # noqa: E402

BUILD_ROOT = TEST_DIR / "build" / "e2e"
SOURCE_DIR = BUILD_ROOT / "pcre2"
LOG_DIR = BUILD_ROOT / "logs"
RESULT_DIR = BUILD_ROOT / "results"
GHIDRA_PROJECT_DIR = BUILD_ROOT / "ghidra"
GHIDRA_SCRIPT_DIR = TEST_DIR / "ghidra_scripts"
GHIDRA_EXPORT_SCRIPT = GHIDRA_SCRIPT_DIR / "ExportGhidraXml.java"
BASELINE_DIR = BUILD_ROOT / "baseline"
BASELINE_MANIFEST = BASELINE_DIR / "manifest.json"
EXPORT_MANIFEST = RESULT_DIR / "ghidra-exports.json"

PCRE2_REPO = "https://github.com/PCRE2Project/pcre2.git"
PCRE2_TAG = "pcre2-10.49"
PCRE2_COMMIT = "6f9d7c1373262c541324a16a358785b33ef116cf"

CONFIGURE_FLAGS = ("--disable-shared", "--disable-jit")
CFLAGS = (
    "-O0",
    "-g3",
    "-fno-pie",
    "-fno-inline",
    "-fno-omit-frame-pointer",
    "-falign-functions=1",
)
LDFLAGS = ("-no-pie",)
BINARIES = ("pcre2test", "pcre2grep")

_RECEIPT_ITEM = re.compile(
    r"^\s*-\s*address:\s*(0x[0-9a-fA-F]+)\s*$"
)
_RECEIPT_LENGTH = re.compile(r"^\s*length:\s*(0x[0-9a-fA-F]+)\s*$")


def _run(
    command: list[str],
    *,
    cwd: Path,
    log_name: str,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``command``, tee its output to a log, and fail on a nonzero status."""
    log_path = LOG_DIR / log_name
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = " ".join(shlex.quote(part) for part in command)
    print(f"$ {rendered}")
    print(f"  log: {log_path}")

    with log_path.open("wb") as log:
        log.write(f"$ {rendered}\n\n".encode())
        log.flush()
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
        )

    if result.returncode != 0:
        _fail(
            f"{log_name} failed with exit status {result.returncode}",
            log_path,
        )
    return result


def _fail(message: str, log_path: Path | None = None) -> None:
    """Report ``message`` (and the tail of ``log_path``) and exit."""
    print(f"FAIL: {message}", file=sys.stderr)
    if log_path is not None and log_path.is_file():
        lines = log_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        print(f"Last lines of {log_path}:", file=sys.stderr)
        for line in lines[-25:]:
            print(f"  {line}", file=sys.stderr)
    raise SystemExit(1)


def _check_tools() -> None:
    for tool in ("git", "make", "cc", "autoconf", "automake", "libtoolize"):
        if shutil.which(tool) is None:
            _fail(f"required tool {tool!r} is not on PATH")

    headless = _ghidra_headless()
    if not headless.is_file():
        _fail(
            "Ghidra headless launcher not found at "
            f"{headless}; set GHIDRA_HOME to the Ghidra installation"
        )


def _ghidra_headless() -> Path:
    home = Path(
        os.environ.get("GHIDRA_HOME", "~/opt/ghidra")
    ).expanduser()
    return home / "support" / "analyzeHeadless"


def _prepare_dirs() -> None:
    for directory in (BUILD_ROOT, LOG_DIR, RESULT_DIR, GHIDRA_PROJECT_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path) -> dict:
    """Return the JSON object at ``path``, or an empty dict if unreadable."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _build_identity() -> dict[str, object]:
    """Return the inputs that determine the contents of the pcre2 binaries."""
    return {
        "commit": PCRE2_COMMIT,
        "configure_flags": list(CONFIGURE_FLAGS),
        "cflags": list(CFLAGS),
        "ldflags": list(LDFLAGS),
    }


def _cached_binaries_usable() -> bool:
    """Return whether the saved binaries may replace a fresh build."""
    if not (SOURCE_DIR / "Makefile").is_file():
        return False

    manifest = _read_json(BASELINE_MANIFEST)
    if manifest.get("build") != _build_identity():
        return False

    hashes = manifest.get("binaries")
    if not isinstance(hashes, dict):
        return False
    for name in BINARIES:
        saved = BASELINE_DIR / name
        if not saved.is_file() or hashes.get(name) != _sha256(saved):
            return False
    return True


def _restore_cached_binaries() -> None:
    for name in BINARIES:
        shutil.copy2(BASELINE_DIR / name, SOURCE_DIR / name)


def _save_cached_binaries() -> None:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for name in BINARIES:
        shutil.copy2(SOURCE_DIR / name, BASELINE_DIR / name)
        hashes[name] = _sha256(SOURCE_DIR / name)
    _write_json(
        BASELINE_MANIFEST,
        {"build": _build_identity(), "binaries": hashes},
    )


def _git_head() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=SOURCE_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _checkout() -> None:
    if SOURCE_DIR.exists():
        try:
            current = _git_head()
        except (OSError, subprocess.CalledProcessError):
            current = ""
        if current != PCRE2_COMMIT:
            print(
                f"cached pcre2 checkout is {current or 'invalid'}; "
                f"replacing it with {PCRE2_COMMIT}"
            )
            shutil.rmtree(SOURCE_DIR)

    if not SOURCE_DIR.exists():
        print(f"cloning pcre2 {PCRE2_TAG} (network required)")
        _run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                PCRE2_TAG,
                PCRE2_REPO,
                str(SOURCE_DIR),
            ],
            cwd=BUILD_ROOT,
            log_name="git-clone.log",
        )

    current = _git_head()
    if current != PCRE2_COMMIT:
        _fail(
            f"pcre2 checkout is {current}, expected {PCRE2_COMMIT}"
        )


def _build() -> None:
    if _cached_binaries_usable():
        print(f"reusing cached pcre2 binaries from {BASELINE_DIR}")
        _restore_cached_binaries()
        return

    if not (SOURCE_DIR / "configure").is_file():
        _run(
            ["./autogen.sh"],
            cwd=SOURCE_DIR,
            log_name="autogen.log",
        )

    _run(
        [
            "./configure",
            *CONFIGURE_FLAGS,
            f"CFLAGS={' '.join(CFLAGS)}",
            f"LDFLAGS={' '.join(LDFLAGS)}",
        ],
        cwd=SOURCE_DIR,
        log_name="configure.log",
    )
    _run(["make", "clean"], cwd=SOURCE_DIR, log_name="make-clean.log")
    _run(
        ["make", f"-j{os.cpu_count() or 1}"],
        cwd=SOURCE_DIR,
        log_name="make.log",
    )

    for name in BINARIES:
        if not (SOURCE_DIR / name).is_file():
            _fail(f"pcre2 build did not produce {name}")

    _save_cached_binaries()


def _assert_suite_passed(log_path: Path, label: str) -> None:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "Testsuite summary for PCRE2" not in text:
        _fail(f"{label}: pcre2 test suite did not run", log_path)

    for key in ("FAIL", "ERROR", "XPASS"):
        match = re.search(
            rf"^#\s+{key}:\s+(\d+)\s*$", text, re.MULTILINE
        )
        if match is None or int(match.group(1)) != 0:
            _fail(f"{label}: pcre2 reported {key} > 0", log_path)

    match = re.search(r"^#\s+PASS:\s+(\d+)\s*$", text, re.MULTILINE)
    if match is None or int(match.group(1)) == 0:
        _fail(f"{label}: pcre2 reported no passing tests", log_path)


def _run_check(log_name: str) -> None:
    _run(["make", "check"], cwd=SOURCE_DIR, log_name=log_name)
    _assert_suite_passed(LOG_DIR / log_name, log_name)


def _clear_ghidra_project(project_name: str) -> None:
    for suffix in (".rep", ".gpr"):
        path = GHIDRA_PROJECT_DIR / f"{project_name}{suffix}"
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def _ghidra_export(name: str) -> Path:
    binary = SOURCE_DIR / name
    output = RESULT_DIR / f"{name}.xml"
    binary_digest = _sha256(binary)
    script_digest = _sha256(GHIDRA_EXPORT_SCRIPT)
    exports = _read_json(EXPORT_MANIFEST)
    record = exports.get(name)
    if (
        output.is_file()
        and isinstance(record, dict)
        and record.get("binary_sha256") == binary_digest
        and record.get("script_sha256") == script_digest
    ):
        print(f"reusing Ghidra export {output}")
        return output

    project_name = f"codezip_e2e_{name}"
    _clear_ghidra_project(project_name)

    print(f"exporting {name} functions with Ghidra")
    _run(
        [
            str(_ghidra_headless()),
            str(GHIDRA_PROJECT_DIR),
            project_name,
            "-import",
            str(binary),
            "-scriptPath",
            str(GHIDRA_SCRIPT_DIR),
            "-postScript",
            "ExportGhidraXml.java",
            str(output),
            "-analysisTimeoutPerFile",
            "900",
            "-deleteProject",
        ],
        cwd=BUILD_ROOT,
        log_name=f"ghidra-{name}.log",
    )

    if not output.is_file():
        _fail(f"Ghidra did not write {output}")

    exports[name] = {
        "binary_sha256": binary_digest,
        "script_sha256": script_digest,
    }
    _write_json(EXPORT_MANIFEST, exports)
    return output


def _read_receipt(
    path: Path,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or not lines[0].startswith("freed:"):
        _fail(f"{path} is not a codezip receipt")

    sections: dict[str, list[tuple[int, int]]] = {
        "freed": [],
        "modified": [],
    }
    section: str | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("freed:"):
            section = "freed"
            index += 1
            continue
        if line.startswith("modified:"):
            section = "modified"
            index += 1
            continue

        address_match = _RECEIPT_ITEM.match(line)
        if address_match is None:
            index += 1
            continue
        if section is None:
            _fail(f"{path} has a range outside a receipt section")
        if index + 1 >= len(lines):
            _fail(f"{path} has an address without a length")
        length_match = _RECEIPT_LENGTH.match(lines[index + 1])
        if length_match is None:
            _fail(f"{path} has an address without a length")

        sections[section].append(
            (
                int(address_match.group(1), 16),
                int(length_match.group(1), 16),
            )
        )
        index += 2

    return sections["freed"], sections["modified"]


def _verify_codezipped(
    binary: Path, output: Path, receipt: Path
) -> tuple[int, int]:
    """Check output changes are confined to the receipt ranges."""
    freed, modified_ranges = _read_receipt(receipt)
    original = binary.read_bytes()
    modified = output.read_bytes()
    if len(modified) != len(original):
        _fail(f"{output} changed the file size")

    image = Binary(binary)
    expected = bytearray(original)
    rewritten = bytearray(len(expected))
    freed_marks = bytearray(len(expected))
    total = 0

    def check_range(address: int, length: int) -> int:
        if length <= 0:
            _fail(f"{receipt} contains an empty range")
        try:
            offset = image.virtual_to_file(address)
        except ValueError as exc:
            _fail(f"{receipt}: {exc}")
        if offset + length > len(expected):
            _fail(f"{receipt} range at {address:#x} is out of bounds")
        return offset

    previous_end = 0
    for address, length in freed:
        if address < previous_end:
            _fail(f"{receipt} contains overlapping freed ranges")
        previous_end = address + length
        offset = check_range(address, length)
        expected[offset : offset + length] = b"\xff" * length
        freed_marks[offset : offset + length] = b"\x01" * length
        total += length

    previous_end = 0
    for address, length in modified_ranges:
        if address < previous_end:
            _fail(f"{receipt} contains overlapping modified ranges")
        previous_end = address + length
        offset = check_range(address, length)
        if any(rewritten[offset : offset + length]):
            _fail(f"{receipt} contains overlapping modified ranges")
        if any(freed_marks[offset : offset + length]):
            _fail(f"{receipt} modified range overlaps a freed range")
        rewritten[offset : offset + length] = b"\x01" * length

    for index, (original_byte, output_byte) in enumerate(
        zip(expected, modified)
    ):
        if rewritten[index]:
            continue
        if original_byte != output_byte:
            _fail(
                f"{output} changes bytes outside the ranges in {receipt}"
            )

    return total, len(freed)


def _codezip_all() -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for name in BINARIES:
        binary = SOURCE_DIR / name
        export = RESULT_DIR / f"{name}.xml"
        output = RESULT_DIR / f"{name}.codezip"
        receipt = RESULT_DIR / f"{name}.receipt.yaml"

        print(f"codezipping {name} (this can take a while)")
        _run(
            [
                sys.executable,
                str(PROJECT_ROOT / "codezip.py"),
                str(binary),
                str(export),
                "-o",
                str(output),
                "--receipt",
                str(receipt),
            ],
            cwd=PROJECT_ROOT,
            log_name=f"codezip-{name}.log",
        )

        freed_bytes, freed_ranges = _verify_codezipped(
            binary, output, receipt
        )
        stats[name] = {
            "freed_bytes": freed_bytes,
            "freed_ranges": freed_ranges,
            "mapped_bytes": sum(
                size for _, size in Binary(binary).mapped_ranges()
            ),
        }
    return stats


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _grep_corpus_baseline() -> tuple[
    grep_corpus.Corpus, dict[str, grep_corpus.RunResult]
]:
    print("building the pcre2grep library corpus")
    try:
        corpus = grep_corpus.build(
            SOURCE_DIR, BUILD_ROOT / "grep-corpus", SOURCE_DIR / "pcre2grep"
        )
        expected = grep_corpus.capture(SOURCE_DIR / "pcre2grep", corpus)
    except (grep_corpus.CorpusError, subprocess.TimeoutExpired) as error:
        _fail(f"pcre2grep corpus baseline failed: {error}")
    counts = {
        mode: sum(1 for line in path.read_bytes().split(b"\n") if line)
        for mode, path in corpus.patterns.items()
    }
    print("  " + ", ".join(f"{mode}={count}"
                           for mode, count in counts.items()))
    return corpus, expected


def _post_codezip_check(
    corpus: grep_corpus.Corpus | None = None,
    expected: dict[str, grep_corpus.RunResult] | None = None,
) -> None:
    backup_dir = RESULT_DIR / "originals"
    backup_dir.mkdir(parents=True, exist_ok=True)

    for name in BINARIES:
        shutil.copy2(SOURCE_DIR / name, backup_dir / name)

    installed: dict[str, str] = {}
    try:
        for name in BINARIES:
            shutil.copyfile(
                RESULT_DIR / f"{name}.codezip", SOURCE_DIR / name
            )
            installed[name] = _sha256(SOURCE_DIR / name)

        _run_check("check-post-codezip.log")

        for name in BINARIES:
            if _sha256(SOURCE_DIR / name) != installed[name]:
                _fail(
                    f"make rebuilt {name}; the codezipped binary was not "
                    "the one under test"
                )

        if corpus is not None and expected is not None:
            problem = grep_corpus.compare(
                SOURCE_DIR / "pcre2grep", corpus, expected
            )
            if problem is not None:
                _fail(f"pcre2grep library corpus: {problem}")
    finally:
        for name in BINARIES:
            shutil.copy2(backup_dir / name, SOURCE_DIR / name)


def _write_summary(
    stats: dict[str, dict[str, int]],
    corpus: grep_corpus.Corpus | None = None,
) -> None:
    total = sum(entry["freed_bytes"] for entry in stats.values())
    if total <= 0:
        _fail("codezip freed no bytes; the fixture no longer exercises removal")

    summary = {
        "project": "pcre2",
        "tag": PCRE2_TAG,
        "commit": PCRE2_COMMIT,
        "configure_flags": list(CONFIGURE_FLAGS),
        "cflags": list(CFLAGS),
        "ldflags": list(LDFLAGS),
        "binaries": stats,
        "total_freed_bytes": total,
        "baseline_check": "pass",
        "post_codezip_check": "pass",
    }
    if corpus is not None:
        summary["grep_corpus"] = {
            "root": str(corpus.root),
            "patterns": {
                mode: sum(1 for line in path.read_bytes().split(b"\n")
                          if line)
                for mode, path in corpus.patterns.items()
            },
        }
    path = RESULT_DIR / "summary.json"
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print()
    print("End-to-end codezip result")
    for name, entry in stats.items():
        print(
            f"  {name}: {entry['freed_bytes']} freed byte(s) in "
            f"{entry['freed_ranges']} range(s) "
            f"({entry['mapped_bytes']} mapped bytes)"
        )
    print(f"  total freed: {total} byte(s)")
    print(f"  summary: {path}")


def main() -> int:
    print(
        "Building pinned pcre2, running its suite before and after codezip. "
        "Expect about 4 minutes."
    )
    _check_tools()
    _prepare_dirs()
    _checkout()
    _build()
    _run_check("check-baseline.log")
    corpus, corpus_expected = _grep_corpus_baseline()

    for name in BINARIES:
        _ghidra_export(name)

    stats = _codezip_all()
    _post_codezip_check(corpus, corpus_expected)
    _write_summary(stats, corpus)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
