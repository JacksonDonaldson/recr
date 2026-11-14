"""Tests for the pcre2grep library-corpus builder."""

from __future__ import annotations

import pytest

from grep_corpus import (
    CorpusError,
    _curated_cases,
    _subjects,
    _write_case_files,
    extract,
)


def _texts(data: bytes) -> list[tuple[str, bytes]]:
    return [(item.mode, item.text) for item in extract(data, "testinput")]


def test_extract_applies_pattern_modifiers() -> None:
    data = (
        b"/a.b/\n"
        b"/x/i\n"
        b"/y/imsx\n"
        b"/z/utf\n"
        b"/w/ucp\n"
        b"/v/never_utf,utf\n"
        b"/u/caseless\n"
        b"/t/gmx\n"
    )

    assert _texts(data) == [
        ("plain", b"a.b"),
        ("plain", b"(?i)x"),
        ("plain", b"(?imsx)y"),
        ("utf", b"z"),
        ("plain", b"(*UCP)w"),
        ("plain", b"v"),
        ("plain", b"(?i)u"),
        ("plain", b"(?mx)t"),
    ]


def test_extract_handles_escaped_delimiter_and_trailing_space() -> None:
    assert _texts(b"/a\\//\n/abc /\n") == [
        ("plain", b"a\\/"),
        ("plain", b"abc"),
    ]


def test_extract_skips_unsupported_or_unusable_patterns() -> None:
    data = (
        b"/literal/literal\n"
        b"/null/null_pattern\n"
        b"/eclass/alt_extended_class\n"
        b"/nul/a\0b/\n"
        b"/"
        + b"a" * 8001
        + b"/\n"
    )

    assert _texts(data) == []


def test_extract_ignores_unknown_modifier_words() -> None:
    # "mark" and "replace" contain pattern-option letters but are not flags.
    assert _texts(b"/x/mark\n/y/replace\n") == [
        ("plain", b"x"),
        ("plain", b"y"),
    ]


def test_subjects_drop_directives_and_invalid_utf() -> None:
    data = (
        b"# comment\n"
        b"/pattern/\n"
        b"\\= Expect no match\n"
        b"    \\= Also a directive\n"
        b"\n"
        b"subject one\n"
        b"\xff\xfe\n"
    )

    assert _subjects(data, utf=False) == [
        b"subject one",
        b"\xff\xfe",
    ]
    assert _subjects(data, utf=True) == [b"subject one"]


def test_write_case_files_supports_hex_and_args(tmp_path) -> None:
    cases = [
        {
            "kind": "special",
            "mode": "utf",
            "patterns": ["a"],
            "subjects_hex": ["61ff0a"],
            "args": ["-P"],
        }
    ]

    (entry,) = _write_case_files(cases, tmp_path, "special", "special")

    mode, pattern, subject, args = entry
    assert mode == "utf"
    assert pattern.read_bytes() == b"a\n"
    assert subject.read_bytes() == b"a\xff\n"
    assert args == ("-P",)
    assert pattern.name == "special-0.pat"
    assert subject.name == "special-0.subj"


def test_write_case_files_rejects_bad_cases(tmp_path) -> None:
    with pytest.raises(CorpusError):
        _write_case_files(
            [{"kind": "special", "mode": "bogus", "patterns": ["a"]}],
            tmp_path,
            "special",
            "special",
        )
    with pytest.raises(CorpusError):
        _write_case_files(
            [{"kind": "special", "mode": "plain", "patterns": ["a", "b"]}],
            tmp_path,
            "special",
            "special",
        )


def test_curated_cases_are_well_formed() -> None:
    for case in _curated_cases():
        assert case["mode"] in ("plain", "utf")
        assert case["patterns"]
        assert case.get("subjects") or case.get("subjects_hex")
        kind = case.get("kind", "positive")
        assert kind in ("positive", "error", "default", "special")
        if kind != "positive":
            assert len(case["patterns"]) == 1
            assert len(case.get("subjects", [])) == 1 or len(
                case.get("subjects_hex", [])
            ) == 1
        assert all(isinstance(arg, str) for arg in case.get("args", []))
        for value in case.get("subjects_hex", []):
            bytes.fromhex(value)
        for pattern in case["patterns"]:
            encoded = pattern.encode("utf-8")
            assert encoded
            assert b"\0" not in encoded
            assert b"\n" not in encoded
            assert len(encoded) <= 8000
