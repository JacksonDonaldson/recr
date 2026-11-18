"""Exercise pcre2grep's linked pcre2 library with pcre2's own test corpus.

``RunGrepTest`` concentrates on pcre2grep's file and option handling, so only a
small part of the statically linked library runs.  This module extracts the
patterns and subject lines from pcre2's ``testdata`` directory, filters out
patterns that this ``pcre2grep`` build cannot run, and executes the resulting
corpus in plain and UTF modes.  ``run_e2e`` compares the corpus output before
and after codezip, and ``mutation_check`` uses it as an additional oracle.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

MODES = ("plain", "utf")
CORPUS_VERSION = "5"
CURATED_CASES = Path(__file__).with_name("survivor_cases.json")
MAX_PATTERN = 8000
MATCH_LIMIT = 1_000_000
DEPTH_LIMIT = 100_000
FILTER_TIMEOUT = 5.0
SLOW_PATTERN = 0.5
RUN_TIMEOUT = 120.0

# pcre2test accepts these one-letter modifiers.  Only i, m, s, and x are
# pattern options; the rest keep a token from being mistaken for a long name.
_LETTER_MODIFIERS = frozenset("imsxBIgr")
_LONG_MODIFIERS = {
    "caseless": "i",
    "dotall": "s",
    "multiline": "m",
    "extended": "x",
}
_PREFIX_MODIFIERS = {
    "alt_bsux": "(*ALT_BSUX)",
    "dupnames": "(?J)",
    "no_auto_capture": "(?n)",
    "no_auto_possess": "(*NO_AUTO_POSSESS)",
    "no_start_optimize": "(*NO_START_OPT)",
    "ucp": "(*UCP)",
    "ungreedy": "(?U)",
}
_SKIP_MODIFIERS = frozenset(
    {"alt_extended_class", "literal", "null_pattern"}
)
_SUBJECT_EXTRA = (
    "The quick brown fox jumps over the lazy dog 0123456789",
    "PACK MY BOX WITH FIVE DOZEN LIQUOR JUGS",
    "abc ABC aaa AAZ xxx --- +++ ((())) [[[]]] {{}} \\\\ /// ?!.,;:'\"",
    "\tleading and trailing whitespace\t",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
)
_UTF_SUBJECT_EXTRA = (
    "café naïve Ελληνικά Русский 日本語 中文",
    "Ångström ÅNGSTRÖM straße STRASSE",
    "e\u0301 combining marks a\u0308o\u0308u\u0308",
    "\U0001f600 \U0001f642 \U0001f1eb\U0001f1f7 \u05e9\u05dc\u05d5\u05dd "
    "\u0645\u0631\u062d\u0628\u0627",
    "\u00a0\u2003\u2009\u2028\u2029\u200b\u200c\u200d",
    "\u2163 \u2164 \u2173 \u2460 \u24b6 \u24d0",
)
_HIGH_BYTES = bytes(range(0x80, 0x100))


@dataclass(frozen=True)
class Pattern:
    """A candidate pattern and the pcre2grep mode it belongs to."""

    mode: str
    text: bytes
    source: str


@dataclass(frozen=True)
class RunResult:
    """Captured output from one corpus mode."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class Corpus:
    """A cached pattern and subject corpus."""

    root: Path
    patterns: dict[str, Path]
    subjects: dict[str, Path]
    negative: tuple[tuple[str, Path, Path, tuple[str, ...]], ...] = ()
    defaults: tuple[tuple[str, Path, Path, tuple[str, ...]], ...] = ()
    specials: tuple[tuple[str, Path, Path, tuple[str, ...]], ...] = ()


class CorpusError(RuntimeError):
    """Raised when the reference binary cannot run the corpus."""


def _digest(parts: list[bytes]) -> str:
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "little"))
        hasher.update(part)
    return hasher.hexdigest()


def _testdata_files(source_dir: Path) -> list[Path]:
    files = sorted((source_dir / "testdata").glob("testinput*"))
    return [
        path
        for path in files
        if path.name != "testinputheap" and not path.name.endswith("~")
    ]


def _curated_cases() -> list[dict]:
    """Return verified regression cases for rare pcre2 code paths."""
    if not CURATED_CASES.is_file():
        return []
    payload = json.loads(CURATED_CASES.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        raise CorpusError(f"{CURATED_CASES} has no cases list")
    return cases


def _modifier_tokens(modifiers: str) -> list[str]:
    return [token for token in modifiers.split(",") if token]


def _inline_options(modifiers: str) -> tuple[str, str] | None:
    """Return ``(mode, prefix)`` for a pcre2test modifier string."""
    tokens = _modifier_tokens(modifiers)
    if any(token in _SKIP_MODIFIERS for token in tokens):
        return None

    mode = "utf" if "utf" in tokens and "never_utf" not in tokens else "plain"
    letters: set[str] = set()
    for token in tokens:
        if token in _LONG_MODIFIERS:
            letters.add(_LONG_MODIFIERS[token])
        elif token and all(char in _LETTER_MODIFIERS for char in token):
            letters.update(char for char in token if char in "imsx")

    prefix = ""
    if letters:
        prefix += "(?" + "".join(c for c in "imsx" if c in letters) + ")"
    for token in tokens:
        prefix += _PREFIX_MODIFIERS.get(token, "")
    return mode, prefix


def extract(data: bytes, source: str) -> list[Pattern]:
    """Extract patterns from a pcre2test input file."""
    patterns: list[Pattern] = []
    for raw in data.split(b"\n"):
        line = raw.rstrip(b"\r")
        if not line.startswith(b"/"):
            continue
        end = line.rfind(b"/")
        if end <= 0:
            continue

        body = line[1:end]
        if not body or b"\0" in body:
            continue
        modifiers = line[end + 1 :].decode("latin1").strip()
        options = _inline_options(modifiers)
        if options is None:
            continue
        mode, prefix = options

        # A pattern file trims trailing white space, so normalize here to
        # make per-pattern validation and the batched run agree.
        body = body.rstrip(b" \t")
        if not body:
            continue
        text = prefix.encode("ascii") + body
        if len(text) > MAX_PATTERN:
            continue
        patterns.append(Pattern(mode=mode, text=text, source=source))
    return patterns


def _subjects(data: bytes, *, utf: bool) -> list[bytes]:
    lines: list[bytes] = []
    for raw in data.split(b"\n"):
        line = raw.rstrip(b"\r")
        stripped = line.strip()
        if not stripped or stripped.startswith((b"#", b"/", b"\\")):
            continue
        if b"\0" in line:
            continue
        try:
            line.decode("utf-8")
        except UnicodeDecodeError:
            if utf:
                continue
        lines.append(line)
    return lines


def _write_subjects(path: Path, lines: list[bytes]) -> None:
    path.write_bytes(b"\n".join(lines) + b"\n")


def _build_subjects(
    source_dir: Path, root: Path, cases: list[dict]
) -> dict[str, Path]:
    plain: list[bytes] = []
    utf: list[bytes] = []
    seen_plain: set[bytes] = set()
    seen_utf: set[bytes] = set()

    for path in _testdata_files(source_dir):
        data = path.read_bytes()
        for line in _subjects(data, utf=False):
            if line not in seen_plain:
                seen_plain.add(line)
                plain.append(line)
        for line in _subjects(data, utf=True):
            if line not in seen_utf:
                seen_utf.add(line)
                utf.append(line)

    for line in _SUBJECT_EXTRA:
        encoded = line.encode("utf-8")
        if encoded not in seen_plain:
            seen_plain.add(encoded)
            plain.append(encoded)
        if encoded not in seen_utf:
            seen_utf.add(encoded)
            utf.append(encoded)
    for line in _UTF_SUBJECT_EXTRA:
        encoded = line.encode("utf-8")
        if encoded not in seen_utf:
            seen_utf.add(encoded)
            utf.append(encoded)
    if _HIGH_BYTES not in seen_plain:
        plain.append(_HIGH_BYTES)
        seen_plain.add(_HIGH_BYTES)

    for case in cases:
        if case.get("kind", "positive") != "positive":
            continue
        mode = case.get("mode")
        if mode not in MODES:
            raise CorpusError(f"curated case has invalid mode {mode!r}")
        target = plain if mode == "plain" else utf
        seen = seen_plain if mode == "plain" else seen_utf
        for subject in case.get("subjects", []):
            encoded = str(subject).encode("utf-8")
            if encoded not in seen:
                seen.add(encoded)
                target.append(encoded)

    subjects = {
        "plain": root / "subjects-plain.txt",
        "utf": root / "subjects-utf.txt",
    }
    _write_subjects(subjects["plain"], plain)
    _write_subjects(subjects["utf"], utf)
    return subjects


def _write_case_files(
    cases: list[dict], root: Path, kind: str, prefix: str
) -> tuple[tuple[str, Path, Path, tuple[str, ...]], ...]:
    """Write one pattern/subject pair per special case."""
    paths: list[tuple[str, Path, Path, tuple[str, ...]]] = []
    for case in cases:
        if case.get("kind") != kind:
            continue
        mode = case.get("mode")
        patterns = case.get("patterns", [])
        subjects = case.get("subjects", [])
        subjects_hex = case.get("subjects_hex", [])
        args = case.get("args", [])
        if mode not in MODES:
            raise CorpusError(f"{kind} case has invalid mode {mode!r}")
        if len(patterns) != 1:
            raise CorpusError(f"a {kind} case needs exactly one pattern")
        if not isinstance(args, list) or not all(
            isinstance(arg, str) for arg in args
        ):
            raise CorpusError(f"{kind} case has invalid args {args!r}")
        index = len(paths)
        pattern = root / f"{prefix}-{index}.pat"
        subject = root / f"{prefix}-{index}.subj"
        pattern.write_bytes(str(patterns[0]).encode("utf-8") + b"\n")
        if subjects_hex:
            subject.write_bytes(bytes.fromhex(str(subjects_hex[0])))
        else:
            subject.write_bytes(
                (str(subjects[0]) if subjects else "").encode("utf-8")
                + b"\n"
            )
        paths.append((mode, pattern, subject, tuple(args)))
    return tuple(paths)


def _run_case_files(
    executable: Path,
    cases: tuple[tuple[str, Path, Path, tuple[str, ...]], ...],
    *,
    timeout: float,
    output: bool,
    validate: bool,
    require_error: bool,
) -> RunResult:
    """Run special cases and frame each result for comparison."""
    chunks: list[bytes] = []
    for index, (mode, pattern, subject, args) in enumerate(cases):
        try:
            result = _run_patterns(
                executable, pattern, subject, mode, timeout=timeout,
                output=output, extra_args=args,
            )
        except subprocess.TimeoutExpired:
            return RunResult(-999, b"", b"special corpus timed out")
        if validate:
            if require_error and result.returncode != 2:
                raise CorpusError(
                    f"error case {index} returned {result.returncode}, "
                    "expected 2"
                )
            if not require_error and result.returncode not in (0, 1):
                raise CorpusError(
                    f"special case {index} returned {result.returncode}"
                )
        chunks.append(
            f"case {index} rc={result.returncode}\n".encode()
            + result.stdout
            + b"\0"
            + result.stderr
            + b"\0"
        )
    return RunResult(0, b"".join(chunks), b"")


def _run_patterns(
    executable: Path,
    pattern_file: Path,
    subject_file: Path,
    mode: str,
    *,
    timeout: float,
    output: bool = True,
    extra_args: tuple[str, ...] = (),
) -> RunResult:
    command = [
        str(executable.resolve()),
        *(["-o"] if output else []),
        *extra_args,
        "--allow-lookaround-bsk",
        f"--match-limit={MATCH_LIMIT}",
        f"--depth-limit={DEPTH_LIMIT}",
    ]
    if mode == "utf":
        command.append("-u")
    command.extend(
        ["-f", str(pattern_file.resolve()), str(subject_file.resolve())]
    )
    result = subprocess.run(
        command,
        cwd=pattern_file.resolve().parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return RunResult(result.returncode, result.stdout, result.stderr)


_SCRATCH_FILES = threading.local()


def _pattern_ok(
    executable: Path,
    text: bytes,
    subject_file: Path,
    mode: str,
    scratch: Path,
) -> bool:
    name = getattr(_SCRATCH_FILES, "file", None)
    if name is None:
        name = scratch / f"one-{threading.get_ident()}.txt"
        _SCRATCH_FILES.file = name
    name.write_bytes(text + b"\n")
    started = time.perf_counter()
    try:
        result = _run_patterns(
            executable, name, subject_file, mode, timeout=FILTER_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return False
    elapsed = time.perf_counter() - started
    return (
        result.returncode in (0, 1)
        and not result.stderr
        and elapsed <= SLOW_PATTERN
    )


def _filter_patterns(
    executable: Path,
    candidates: list[Pattern],
    subjects: dict[str, Path],
    scratch: Path,
) -> dict[str, list[bytes]]:
    keep: dict[str, list[bytes]] = {mode: [] for mode in MODES}
    workers = min(16, os.cpu_count() or 1)
    for mode in MODES:
        selected = [item for item in candidates if item.mode == mode]
        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = executor.map(
                lambda item: _pattern_ok(
                    executable, item.text, subjects[mode], mode, scratch
                ),
                selected,
            )
            for item, ok in zip(selected, results):
                if ok:
                    keep[mode].append(item.text)
    return keep


def _manifest_path(root: Path) -> Path:
    return root / "manifest.json"


def build(
    source_dir: Path,
    cache_root: Path,
    reference: Path,
    *,
    reference_image: Path | None = None,
) -> Corpus:
    """Return a cached corpus, creating it if necessary.

    ``reference`` must be an executable pcre2grep; it decides which patterns
    compile and run cleanly.  Its hash is part of the cache key, so switching
    between the original and codezipped binary does not reuse a stale filter.
    """
    source_dir = source_dir.resolve()
    cache_root = cache_root.resolve()
    reference = reference.resolve()
    files = _testdata_files(source_dir)
    if not files:
        raise CorpusError(f"no testinput files under {source_dir / 'testdata'}")

    cases = _curated_cases()
    curated_bytes = json.dumps(
        cases, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    testdata = [(path.name.encode(), path.read_bytes()) for path in files]
    reference_bytes = reference.read_bytes()
    image_bytes = [reference_image.read_bytes()] if reference_image is not None else []
    limits = {
        "match_limit": MATCH_LIMIT,
        "depth_limit": DEPTH_LIMIT,
        "filter_timeout": FILTER_TIMEOUT,
        "slow_pattern": SLOW_PATTERN,
    }
    key = _digest(
        [CORPUS_VERSION.encode()]
        + [part for _, part in testdata]
        + [reference_bytes, *image_bytes, curated_bytes]
        + [json.dumps(limits, sort_keys=True).encode()]
    )
    root = cache_root / key[:16]
    manifest = _manifest_path(root)
    if manifest.is_file():
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        if (
            payload.get("version") == CORPUS_VERSION
            and payload.get("testdata") == _digest([p for _, p in testdata])
            and payload.get("reference") == hashlib.sha256(
                reference_bytes
            ).hexdigest()
            and payload.get("limits") == limits
            and payload.get("curated") == _digest([curated_bytes])
        ):
            patterns = {
                mode: root / f"patterns-{mode}.txt" for mode in MODES
            }
            subjects = {
                mode: root / f"subjects-{mode}.txt" for mode in MODES
            }
            paths = [*patterns.values(), *subjects.values()]
            if all(path.is_file() for path in paths):
                negative = _write_case_files(cases, root, "error", "negative")
                defaults = _write_case_files(
                    cases, root, "default", "default"
                )
                specials = _write_case_files(
                    cases, root, "special", "special"
                )
                return Corpus(
                    root, patterns, subjects, negative, defaults, specials
                )

    root.mkdir(parents=True, exist_ok=True)
    negative = _write_case_files(cases, root, "error", "negative")
    defaults = _write_case_files(cases, root, "default", "default")
    specials = _write_case_files(cases, root, "special", "special")
    subjects = _build_subjects(source_dir, root, cases)

    candidates: list[Pattern] = []
    seen: set[tuple[str, bytes]] = set()
    for name, data in testdata:
        for item in extract(data, name.decode()):
            marker = (item.mode, item.text)
            if marker in seen:
                continue
            seen.add(marker)
            candidates.append(item)
    for case in cases:
        if case.get("kind", "positive") != "positive":
            continue
        mode = case.get("mode")
        if mode not in MODES:
            raise CorpusError(f"curated case has invalid mode {mode!r}")
        for text in case.get("patterns", []):
            body = str(text).encode("utf-8").rstrip(b" \t")
            if not body or b"\0" in body or b"\n" in body:
                raise CorpusError(f"curated case has an unusable pattern {text!r}")
            if len(body) > MAX_PATTERN:
                raise CorpusError(f"curated case pattern is too long: {text!r}")
            marker = (mode, body)
            if marker not in seen:
                seen.add(marker)
                candidates.append(
                    Pattern(mode, body, f"curated:{case.get('id', '?')}")
                )

    scratch = root / "scratch"
    scratch.mkdir(exist_ok=True)
    try:
        keep = _filter_patterns(reference, candidates, subjects, scratch)
    finally:
        for path in scratch.glob("*.txt"):
            path.unlink(missing_ok=True)
        scratch.rmdir()

    patterns: dict[str, Path] = {}
    for mode in MODES:
        path = root / f"patterns-{mode}.txt"
        path.write_bytes(b"\n".join(keep[mode]) + b"\n")
        patterns[mode] = path

    manifest.write_text(
        json.dumps(
            {
                "version": CORPUS_VERSION,
                "testdata": _digest([p for _, p in testdata]),
                "reference": hashlib.sha256(reference_bytes).hexdigest(),
                "limits": limits,
                "curated": _digest([curated_bytes]),
                "counts": {mode: len(keep[mode]) for mode in MODES},
                "negative": len(negative),
                "defaults": len(defaults),
                "specials": len(specials),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return Corpus(root, patterns, subjects, negative, defaults, specials)


def capture(
    executable: Path, corpus: Corpus, *, timeout: float = RUN_TIMEOUT
) -> dict[str, RunResult]:
    """Run every mode against ``executable`` and return its output."""
    results: dict[str, RunResult] = {}
    for mode in MODES:
        results[mode] = _run_patterns(
            executable,
            corpus.patterns[mode],
            corpus.subjects[mode],
            mode,
            timeout=timeout,
        )
        if results[mode].returncode not in (0, 1):
            detail = results[mode].stderr.decode(
                "latin1", errors="replace"
            ).strip()
            raise CorpusError(
                f"{executable} returned {results[mode].returncode} while "
                f"running the {mode} corpus"
                + (f": {detail[:400]}" if detail else "")
            )
    if corpus.negative:
        results["negative"] = _run_case_files(
            executable, corpus.negative, timeout=timeout,
            output=True, validate=True, require_error=True,
        )
    if corpus.defaults:
        results["default"] = _run_case_files(
            executable, corpus.defaults, timeout=timeout,
            output=False, validate=True, require_error=False,
        )
    if corpus.specials:
        results["special"] = _run_case_files(
            executable, corpus.specials, timeout=timeout,
            output=True, validate=True, require_error=False,
        )
    return results


def compare(
    executable: Path,
    corpus: Corpus,
    expected: dict[str, RunResult],
    *,
    timeout: float = RUN_TIMEOUT,
) -> str | None:
    """Return a description of the first difference, or ``None``."""
    modes = list(MODES)
    if "negative" in expected:
        modes.append("negative")
    if "default" in expected:
        modes.append("default")
    if "special" in expected:
        modes.append("special")
    for mode in modes:
        try:
            if mode in MODES:
                result = _run_patterns(
                    executable,
                    corpus.patterns[mode],
                    corpus.subjects[mode],
                    mode,
                    timeout=timeout,
                )
                if result.returncode not in (0, 1):
                    return f"{mode} corpus exited {result.returncode}"
            elif mode == "negative":
                result = _run_case_files(
                    executable, corpus.negative, timeout=timeout,
                    output=True, validate=False, require_error=True,
                )
            elif mode == "default":
                result = _run_case_files(
                    executable, corpus.defaults, timeout=timeout,
                    output=False, validate=False, require_error=False,
                )
            else:
                result = _run_case_files(
                    executable, corpus.specials, timeout=timeout,
                    output=True, validate=False, require_error=False,
                )
        except subprocess.TimeoutExpired:
            return f"{mode} corpus timed out"
        reference = expected[mode]
        if result.returncode != reference.returncode:
            return (
                f"{mode} corpus exit status {result.returncode} != "
                f"{reference.returncode}"
            )
        if result.stdout != reference.stdout:
            return f"{mode} corpus stdout changed"
        if result.stderr != reference.stderr:
            return f"{mode} corpus stderr changed"
    return None
