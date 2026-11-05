"""Parser tests.

These document the intended behaviour of the first-pass scaffolds and will be
enabled once the parsers are implemented.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from input_parser import parse_re_file

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = pytest.mark.skip(reason="parser implementations are pending")


def test_sample_yaml_parses() -> None:
    result = parse_re_file(str(FIXTURES / "sample.yaml"))
    assert result.isa == "x86_64"
    assert {function.name for function in result.functions} == {
        "_start",
        "main",
        "helper",
    }


def test_sample_ghidra_xml_parses() -> None:
    result = parse_re_file(str(FIXTURES / "sample_ghidra.xml"))
    assert result.isa == "x86_64"
    assert {function.name for function in result.functions} == {
        "_start",
        "main",
        "helper",
    }
