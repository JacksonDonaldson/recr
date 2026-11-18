#!/usr/bin/env python3
"""End-to-end codezip check against a pinned pcre2 build.

Build pcre2 with full debug information and no optimization, export its
functions with Ghidra, run its test suite, rewrite the test executables with
codezip, and require the suite to pass again.  The run is opt-in because it
needs network access on the first invocation and takes several minutes.

The native target is x86-64. ``--arch riscv64`` cross-compiles the same
fixture and runs both the original and rewritten executables under QEMU.

Run it with ``make -C test e2e`` or ``make -C test e2e-riscv``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = TEST_DIR.parent

sys.path.insert(0, str(PROJECT_ROOT))

from binary.binary import Binary  # noqa: E402
import grep_corpus  # noqa: E402
from input_parser import ParseError, parse_re_file  # noqa: E402

BUILD_ROOT = TEST_DIR / "build" / "e2e"
GHIDRA_SCRIPT_DIR = TEST_DIR / "ghidra_scripts"
GHIDRA_EXPORT_SCRIPT = GHIDRA_SCRIPT_DIR / "ExportGhidraXml.java"

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
PROGRAMS = BINARIES + ("pcre2posix_test",)

_RECEIPT_ITEM = re.compile(r"^\s*-\s*address:\s*(0x[0-9a-fA-F]+)\s*$")
_RECEIPT_LENGTH = re.compile(r"^\s*length:\s*(0x[0-9a-fA-F]+)\s*$")


@dataclass(frozen=True)
class Target:
    """How to build and run the pcre2 fixture for one architecture."""

    name: str
    configure_host: str | None
    compiler: str
    runner: str | None
    sysroot: Path | None
    native: bool

    @property
    def is_native(self) -> bool:
        return self.native

    def real_name(self, program: str) -> str:
        """Return the on-disk name of the actual target executable."""
        return program if self.is_native else f"{program}.{self.name}"


@dataclass(frozen=True)
class Layout:
    """Per-architecture build, cache, and result directories."""

    root: Path
    source: Path
    logs: Path
    results: Path
    ghidra: Path
    baseline: Path

    @property
    def baseline_manifest(self) -> Path:
        return self.baseline / "manifest.json"

    @property
    def export_manifest(self) -> Path:
        return self.results / "ghidra-exports.json"


def _layout(arch: str) -> Layout:
    root = BUILD_ROOT / arch
    return Layout(
        root=root,
        source=root / "pcre2",
        logs=root / "logs",
        results=root / "results",
        ghidra=root / "ghidra",
        baseline=root / "baseline",
    )


X86_64 = "x86_64"
RISCV64 = "riscv64"
ARCHES = (X86_64, RISCV64)
X86_LAYOUT = _layout(X86_64)

# Compatibility aliases for mutation_check.py, which mutates the native build.
SOURCE_DIR = X86_LAYOUT.source
RESULT_DIR = X86_LAYOUT.results


def _target(arch: str) -> Target:
    if arch == X86_64:
        return Target(
            name=X86_64,
            configure_host=None,
            compiler=os.environ.get("CC", "cc"),
            runner=None,
            sysroot=None,
            native=True,
        )

    if arch == RISCV64:
        qemu = os.environ.get("RISCV64_QEMU")
        if not qemu:
            for candidate in ("qemu-riscv64-static", "qemu-riscv64"):
                found = shutil.which(candidate)
                if found is not None:
                    qemu = found
                    break
        sysroot = Path(
            os.environ.get("RISCV64_SYSROOT", "/usr/riscv64-linux-gnu")
        ).expanduser()
        return Target(
            name=RISCV64,
            configure_host="riscv64-linux-gnu",
            compiler=os.environ.get(
                "RISCV64_CC", "riscv64-linux-gnu-gcc"
            ),
            runner=qemu,
            sysroot=sysroot,
            native=False,
        )

    raise ValueError(f"unsupported architecture {arch!r}")


def _run(
    command: list[str],
    *,
    cwd: Path,
    log_name: str,
    logs: Path,
) -> subprocess.CompletedProcess[bytes]:
    """Run ``command``, tee its output to a log, and fail on a nonzero status."""
    log_path = logs / log_name
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


def _check_executable(command: str) -> str | None:
    """Return a diagnostic if ``command`` cannot be executed."""
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return f"{command!r} is not a valid command: {exc}"
    if not parts:
        return "empty command"
    executable = parts[0]
    if os.path.sep in executable:
        if not Path(executable).is_file():
            return f"{executable} does not exist"
        if not os.access(executable, os.X_OK):
            return f"{executable} is not executable"
        return None
    if shutil.which(executable) is None:
        return f"{executable!r} is not on PATH"
    return None


def _check_tools(target: Target) -> None:
    for tool in ("git", "make", "autoconf", "automake", "libtoolize"):
        if shutil.which(tool) is None:
            _fail(f"required tool {tool!r} is not on PATH")

    compiler_problem = _check_executable(target.compiler)
    if compiler_problem is not None:
        _fail(
            f"{target.name} C compiler unavailable: {compiler_problem}"
        )

    if not target.is_native:
        if target.runner is None:
            _fail(
                f"{target.name} emulator not found; install "
                "qemu-user-static or set RISCV64_QEMU"
            )
        runner_problem = _check_executable(target.runner)
        if runner_problem is not None:
            _fail(
                f"{target.name} emulator unavailable: {runner_problem}; "
                "install qemu-user-static or set RISCV64_QEMU"
            )
        assert target.sysroot is not None
        loader = target.sysroot / "lib" / "ld-linux-riscv64-lp64d.so.1"
        if not loader.is_file():
            _fail(
                f"{target.name} sysroot {target.sysroot} is missing {loader}; "
                "install gcc-riscv64-linux-gnu or set RISCV64_SYSROOT"
            )

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


def _prepare_dirs(layout: Layout) -> None:
    for directory in (
        layout.root,
        layout.logs,
        layout.results,
        layout.ghidra,
    ):
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


def _build_identity(target: Target) -> dict[str, object]:
    """Return the inputs that determine the contents of the pcre2 binaries."""
    return {
        "arch": target.name,
        "configure_host": target.configure_host,
        "compiler": target.compiler,
        "runner": target.runner,
        "sysroot": str(target.sysroot) if target.sysroot else None,
        "commit": PCRE2_COMMIT,
        "configure_flags": list(CONFIGURE_FLAGS),
        "cflags": list(CFLAGS),
        "ldflags": list(LDFLAGS),
    }


def _real_binary(layout: Layout, target: Target, name: str) -> Path:
    return layout.source / target.real_name(name)


def _cached_binaries_usable(layout: Layout, target: Target) -> bool:
    """Return whether the saved binaries may replace a fresh build."""
    if not (layout.source / "Makefile").is_file():
        return False

    manifest = _read_json(layout.baseline_manifest)
    if manifest.get("build") != _build_identity(target):
        return False

    hashes = manifest.get("binaries")
    if not isinstance(hashes, dict):
        return False
    for name in PROGRAMS:
        real = _real_binary(layout, target, name)
        saved = layout.baseline / real.name
        if (
            not real.is_file()
            or not saved.is_file()
            or hashes.get(name) != _sha256(real)
            or hashes.get(name) != _sha256(saved)
        ):
            return False
    return True


def _restore_cached_binaries(layout: Layout, target: Target) -> None:
    for name in PROGRAMS:
        real = _real_binary(layout, target, name)
        shutil.copy2(layout.baseline / real.name, real)


def _save_cached_binaries(layout: Layout, target: Target) -> None:
    layout.baseline.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, str] = {}
    for name in PROGRAMS:
        real = _real_binary(layout, target, name)
        shutil.copy2(real, layout.baseline / real.name)
        hashes[name] = _sha256(real)
    _write_json(
        layout.baseline_manifest,
        {"build": _build_identity(target), "binaries": hashes},
    )


def _is_wrapper(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(2) == b"#!"
    except OSError:
        return False


def _install_wrappers(layout: Layout, target: Target) -> None:
    """Move target executables aside and put qemu launchers in their place."""
    if target.is_native:
        return

    assert target.runner is not None and target.sysroot is not None
    for name in PROGRAMS:
        program = layout.source / name
        real = _real_binary(layout, target, name)
        if program.is_file() and not _is_wrapper(program):
            program.replace(real)
        if not real.is_file():
            _fail(f"pcre2 build did not produce {real.name}")

        launcher = shlex.join(
            [target.runner, "-L", str(target.sysroot), str(real)]
        )
        program.write_text(
            f"#!/bin/sh\nexec {launcher} \"$@\"\n",
            encoding="utf-8",
        )
        program.chmod(0o755)


def _git_head(layout: Layout) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=layout.source,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _checkout(layout: Layout) -> None:
    if layout.source.exists():
        try:
            current = _git_head(layout)
        except (OSError, subprocess.CalledProcessError):
            current = ""
        if current != PCRE2_COMMIT:
            print(
                f"cached pcre2 checkout is {current or 'invalid'}; "
                f"replacing it with {PCRE2_COMMIT}"
            )
            shutil.rmtree(layout.source)

    if not layout.source.exists():
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
                str(layout.source),
            ],
            cwd=layout.root,
            log_name="git-clone.log",
            logs=layout.logs,
        )

    current = _git_head(layout)
    if current != PCRE2_COMMIT:
        _fail(
            f"pcre2 checkout is {current}, expected {PCRE2_COMMIT}"
        )


def _build(layout: Layout, target: Target) -> None:
    if _cached_binaries_usable(layout, target):
        print(f"reusing cached pcre2 binaries from {layout.baseline}")
        _restore_cached_binaries(layout, target)
        _install_wrappers(layout, target)
        return

    if not (layout.source / "configure").is_file():
        _run(
            ["./autogen.sh"],
            cwd=layout.source,
            log_name="autogen.log",
            logs=layout.logs,
        )

    configure = [
        "./configure",
        *CONFIGURE_FLAGS,
        f"CC={target.compiler}",
        f"CFLAGS={' '.join(CFLAGS)}",
        f"LDFLAGS={' '.join(LDFLAGS)}",
    ]
    if target.configure_host is not None:
        configure.append(f"--host={target.configure_host}")

    _run(
        configure,
        cwd=layout.source,
        log_name="configure.log",
        logs=layout.logs,
    )
    _run(
        ["make", "clean"],
        cwd=layout.source,
        log_name="make-clean.log",
        logs=layout.logs,
    )
    _run(
        ["make", f"-j{os.cpu_count() or 1}"],
        cwd=layout.source,
        log_name="make.log",
        logs=layout.logs,
    )

    for name in PROGRAMS:
        if not (layout.source / name).is_file():
            _fail(f"pcre2 build did not produce {name}")

    _install_wrappers(layout, target)
    _save_cached_binaries(layout, target)


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


def _run_check(layout: Layout, log_name: str) -> None:
    _run(
        ["make", "check"],
        cwd=layout.source,
        log_name=log_name,
        logs=layout.logs,
    )
    _assert_suite_passed(layout.logs / log_name, log_name)


def _clear_ghidra_project(layout: Layout, project_name: str) -> None:
    for suffix in (".rep", ".gpr"):
        path = layout.ghidra / f"{project_name}{suffix}"
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def _ghidra_export(
    layout: Layout, target: Target, name: str
) -> Path:
    binary = _real_binary(layout, target, name)
    output = layout.results / f"{name}.xml"
    binary_digest = _sha256(binary)
    script_digest = _sha256(GHIDRA_EXPORT_SCRIPT)
    exports = _read_json(layout.export_manifest)
    record = exports.get(name)
    if (
        output.is_file()
        and isinstance(record, dict)
        and record.get("binary_sha256") == binary_digest
        and record.get("script_sha256") == script_digest
    ):
        print(f"reusing Ghidra export {output}")
        return output

    project_name = f"codezip_e2e_{target.name}_{name}"
    _clear_ghidra_project(layout, project_name)

    print(f"exporting {name} functions with Ghidra")
    _run(
        [
            str(_ghidra_headless()),
            str(layout.ghidra),
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
        cwd=layout.root,
        log_name=f"ghidra-{name}.log",
        logs=layout.logs,
    )

    if not output.is_file():
        _fail(f"Ghidra did not write {output}")

    exports[name] = {
        "binary_sha256": binary_digest,
        "script_sha256": script_digest,
    }
    _write_json(layout.export_manifest, exports)
    return output


def _parse_export(path: Path, target: Target) -> int:
    """Parse ``path`` with the production parser and return its function count."""
    try:
        result = parse_re_file(str(path))
    except ParseError as exc:
        _fail(f"cannot parse Ghidra export {path}: {exc}")
    if result.isa != target.name:
        _fail(
            f"Ghidra export {path} was parsed as ISA {result.isa!r}, "
            f"expected {target.name!r}"
        )
    return len(result.functions)


def _ghidra_language(path: Path) -> str:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        _fail(f"cannot read Ghidra export {path}: {exc}")
    processor = root.find("PROCESSOR")
    if processor is None:
        _fail(f"Ghidra export {path} has no PROCESSOR element")
    return processor.get("LANGUAGE_PROVIDER") or processor.get("NAME") or ""


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
) -> tuple[int, int, int]:
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

    return total, len(freed), len(modified_ranges)


def _codezip_all(layout: Layout, target: Target) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = {}
    for name in BINARIES:
        binary = _real_binary(layout, target, name)
        export = layout.results / f"{name}.xml"
        output = layout.results / f"{name}.codezip"
        receipt = layout.results / f"{name}.receipt.yaml"

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
            logs=layout.logs,
        )

        freed_bytes, freed_ranges, modified_ranges = _verify_codezipped(
            binary, output, receipt
        )
        if target.name == RISCV64 and not modified_ranges:
            _fail(f"{name}: no RISC-V outlines were written")
        stats[name] = {
            "freed_bytes": freed_bytes,
            "freed_ranges": freed_ranges,
            "modified_ranges": modified_ranges,
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


def _grep_corpus_baseline(
    layout: Layout, target: Target,
) -> tuple[grep_corpus.Corpus, dict[str, grep_corpus.RunResult]]:
    print("building the pcre2grep library corpus")
    try:
        corpus = grep_corpus.build(
            layout.source,
            layout.root / "grep-corpus",
            layout.source / "pcre2grep",
            reference_image=None if target.is_native else _real_binary(layout, target, "pcre2grep"),
        )
        expected = grep_corpus.capture(layout.source / "pcre2grep", corpus)
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
    layout: Layout,
    target: Target,
    corpus: grep_corpus.Corpus | None = None,
    expected: dict[str, grep_corpus.RunResult] | None = None,
) -> None:
    backup_dir = layout.results / "originals"
    backup_dir.mkdir(parents=True, exist_ok=True)

    for name in BINARIES:
        real = _real_binary(layout, target, name)
        shutil.copy2(real, backup_dir / real.name)

    installed: dict[str, str] = {}
    try:
        for name in BINARIES:
            real = _real_binary(layout, target, name)
            shutil.copyfile(
                layout.results / f"{name}.codezip", real
            )
            installed[name] = _sha256(real)

        _run_check(layout, "check-post-codezip.log")

        for name in BINARIES:
            real = _real_binary(layout, target, name)
            if _sha256(real) != installed[name]:
                _fail(
                    f"make rebuilt {name}; the codezipped binary was not "
                    "the one under test"
                )

        if corpus is not None and expected is not None:
            problem = grep_corpus.compare(
                layout.source / "pcre2grep", corpus, expected
            )
            if problem is not None:
                _fail(f"pcre2grep library corpus: {problem}")
    finally:
        for name in BINARIES:
            real = _real_binary(layout, target, name)
            shutil.copy2(backup_dir / real.name, real)


def _write_summary(
    layout: Layout,
    target: Target,
    stats: dict[str, dict[str, int]] | None,
    *,
    languages: dict[str, str] | None = None,
    functions: dict[str, int] | None = None,
    corpus: grep_corpus.Corpus | None = None,
) -> None:
    summary: dict[str, object] = {
        "project": "pcre2",
        "arch": target.name,
        "tag": PCRE2_TAG,
        "commit": PCRE2_COMMIT,
        "configure_flags": list(CONFIGURE_FLAGS),
        "cflags": list(CFLAGS),
        "ldflags": list(LDFLAGS),
        "baseline_check": "pass",
    }
    if languages is not None:
        summary["ghidra_languages"] = languages
    if functions is not None:
        summary["parsed_functions"] = functions
    if stats is None:
        summary["codezip"] = "skipped: baseline-only run"
    else:
        total = sum(entry["freed_bytes"] for entry in stats.values())
        if total <= 0:
            _fail(
                "codezip freed no bytes; the fixture no longer exercises "
                "removal"
            )
        summary["binaries"] = stats
        summary["total_freed_bytes"] = total
        summary["post_codezip_check"] = "pass"
        if corpus is not None:
            summary["grep_corpus"] = {
                "root": str(corpus.root),
                "patterns": {
                    mode: sum(
                        1 for line in path.read_bytes().split(b"\n") if line
                    )
                    for mode, path in corpus.patterns.items()
                },
            }
    path = layout.results / "summary.json"
    _write_json(path, summary)

    print()
    if stats is None:
        print("End-to-end baseline result")
        print(f"  {target.name}: unmodified pcre2 suite passed")
        print("  codezip: skipped (baseline-only run)")
    else:
        print("End-to-end codezip result")
        for name, entry in stats.items():
            print(
                f"  {name}: {entry['freed_bytes']} freed byte(s) in "
                f"{entry['freed_ranges']} range(s) "
                f"({entry['mapped_bytes']} mapped bytes)"
            )
        total = sum(entry["freed_bytes"] for entry in stats.values())
        print(f"  total freed: {total} byte(s)")
    print(f"  summary: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the codezip end-to-end pcre2 check."
    )
    parser.add_argument(
        "--arch",
        choices=ARCHES,
        default=X86_64,
        help="target architecture (default: x86_64)",
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help=(
            "build, run the unmodified suite, and export with Ghidra, but "
            "skip codezip and the post-rewrite check"
        ),
    )
    args = parser.parse_args(argv)

    target = _target(args.arch)
    layout = _layout(target.name)
    print("Running the pinned pcre2 end-to-end check; expect several minutes.")
    if args.baseline_only:
        print(
            f"{target.name}: baseline-only run; codezip will not be invoked."
        )
    _check_tools(target)
    _prepare_dirs(layout)
    _checkout(layout)
    _build(layout, target)
    _run_check(layout, "check-baseline.log")

    corpus: grep_corpus.Corpus | None = None
    corpus_expected: dict[str, grep_corpus.RunResult] | None = None
    if not args.baseline_only:
        corpus, corpus_expected = _grep_corpus_baseline(layout, target)

    languages: dict[str, str] = {}
    functions: dict[str, int] = {}
    for name in BINARIES:
        export = _ghidra_export(layout, target, name)
        languages[name] = _ghidra_language(export)
        functions[name] = _parse_export(export, target)
        print(
            f"  {name}: {languages[name]} "
            f"({functions[name]} functions)"
        )
        if target.name == RISCV64 and not languages[name].upper().startswith(
            "RISCV"
        ):
            _fail(
                f"Ghidra exported {name} as {languages[name]!r}, "
                "not a RISC-V language"
            )

    if args.baseline_only:
        _write_summary(
            layout, target, None,
            languages=languages, functions=functions,
        )
        return 0

    stats = _codezip_all(layout, target)
    _post_codezip_check(layout, target, corpus, corpus_expected)
    _write_summary(
        layout, target, stats,
        languages=languages, functions=functions, corpus=corpus,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
