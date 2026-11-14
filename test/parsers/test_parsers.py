"""Parser tests for the supported reverse-engineering exports."""

from __future__ import annotations

from pathlib import Path

import pytest

from input_parser import ParseError, parse_re_file
from parsers import ghidra_xml

FIXTURES = Path(__file__).parents[1] / "fixtures"

EXPECTED_USER_FUNCTIONS = {
    "add",
    "subtract",
    "multiply",
    "divide_safe",
    "modulo_safe",
    "min_int",
    "max_int",
    "clamp",
    "abs_int",
    "sign",
    "square",
    "cube",
    "sum_to",
    "factorial",
    "gcd",
    "lcm",
    "is_even",
    "is_odd",
    "popcount",
    "reverse_bits",
    "rotate_left",
    "rotate_right",
    "checksum",
    "count_bytes",
    "find_byte",
    "reverse_array",
    "sum_array",
    "max_array",
    "bubble_sort",
    "binary_search",
    "main",
    "switch_dispatch",
    "unreferenced_function",
}


@pytest.mark.skip(reason="YAML parser is not implemented yet")
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
    names = {function.name for function in result.functions}
    assert EXPECTED_USER_FUNCTIONS <= names

    # Ghidra's artificial EXTERNAL block is not part of the binary image.
    assert not any(
        0x405000 <= function.start_address < 0x405020
        for function in result.functions
    )
    assert len(result.functions) == 41


def test_ghidra_function_metadata() -> None:
    result = parse_re_file(str(FIXTURES / "sample_ghidra.xml"))
    functions = {function.name: function for function in result.functions}

    add = functions["add"]
    assert add.start_address == 0x401156
    assert add.length == 0x18
    assert add.file_offset == ghidra_xml.UNKNOWN_FILE_OFFSET

    main = functions["main"]
    assert main.start_address == 0x40182B
    assert main.length == 0x2E6

    binary_search = functions["binary_search"]
    assert binary_search.start_address == 0x401790
    assert binary_search.length == 0x9B

    switch_dispatch = functions["switch_dispatch"]
    assert switch_dispatch.start_address == 0x401B11
    assert switch_dispatch.length == 0x57

    unreferenced = functions["unreferenced_function"]
    assert unreferenced.start_address == 0x401B68
    assert unreferenced.length == 0x34

    # This is a real PLT stub in .plt.sec, not part of the artificial external
    # block, so it must be retained despite its Ghidra-assigned name.
    printf_thunk = functions["<EXTERNAL>::printf"]
    assert printf_thunk.start_address == 0x401060
    assert printf_thunk.length == 0xA

    # The Ghidra XML export has no original file offsets; every function uses
    # the documented sentinel instead.
    assert all(
        function.file_offset == ghidra_xml.UNKNOWN_FILE_OFFSET
        for function in result.functions
    )


def test_ghidra_parser_reports_skipped_entries() -> None:
    result = parse_re_file(str(FIXTURES / "sample_ghidra.xml"))
    warnings = "\n".join(result.warnings)

    assert "skipping function" in warnings
    assert "artificial memory block" in warnings
    assert "deregister_tm_clones" in warnings
    assert "non-contiguous address ranges are not supported" in warnings


def test_ghidra_is_supported() -> None:
    assert ghidra_xml.is_supported(str(FIXTURES / "sample_ghidra.xml"))
    assert not ghidra_xml.is_supported(str(FIXTURES / "sample.yaml"))


def test_parse_re_file_rejects_non_ghidra_xml(tmp_path: Path) -> None:
    path = tmp_path / "not_ghidra.xml"
    path.write_text("<root />", encoding="utf-8")

    with pytest.raises(ParseError, match="not a Ghidra XML export"):
        parse_re_file(str(path))


def test_parse_re_file_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="does not exist"):
        parse_re_file(str(tmp_path / "missing.xml"))
