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
    "mix_a",
    "mix_b",
    "mix_c",
    "mix_total",
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
    assert len(result.functions) == 45


def test_ghidra_function_metadata() -> None:
    result = parse_re_file(str(FIXTURES / "sample_ghidra.xml"))
    functions = {function.name: function for function in result.functions}

    add = functions["add"]
    assert add.start_address == 0x401156
    assert add.length == 0x18
    assert add.file_offset == ghidra_xml.UNKNOWN_FILE_OFFSET

    main = functions["main"]
    assert main.start_address == 0x40182B
    assert main.length == 0x2F3

    binary_search = functions["binary_search"]
    assert binary_search.start_address == 0x401790
    assert binary_search.length == 0x9B

    switch_dispatch = functions["switch_dispatch"]
    assert switch_dispatch.start_address == 0x401B1E
    assert switch_dispatch.length == 0x57

    unreferenced = functions["unreferenced_function"]
    assert unreferenced.start_address == 0x401B75
    assert unreferenced.length == 0x34

    mix_a = functions["mix_a"]
    assert mix_a.start_address == 0x401BA9
    assert mix_a.length == 0x25

    mix_b = functions["mix_b"]
    assert mix_b.start_address == 0x401BCE
    assert mix_b.length == 0x25

    mix_c = functions["mix_c"]
    assert mix_c.start_address == 0x401BF3
    assert mix_c.length == 0x25

    mix_total = functions["mix_total"]
    assert mix_total.start_address == 0x401C18
    assert mix_total.length == 0x3A

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


def _processor_export(tmp_path: Path, provider: str, name: str) -> Path:
    path = tmp_path / "processor.xml"
    path.write_text(
        "<?xml version=\"1.0\"?>\n"
        "<PROGRAM NAME=\"processor\">\n"
        f"  <PROCESSOR NAME=\"{name}\" LANGUAGE_PROVIDER=\"{provider}\" "
        "ENDIAN=\"little\" />\n"
        "  <FUNCTIONS />\n"
        "</PROGRAM>\n",
        encoding="utf-8",
    )
    return path


def test_ghidra_detects_riscv64(tmp_path: Path) -> None:
    path = _processor_export(
        tmp_path, "RISCV:LE:64:default:gcc", "RISCV"
    )

    result = parse_re_file(str(path))

    assert result.isa == "riscv64"
    assert result.functions == []


def test_ghidra_detects_riscv32(tmp_path: Path) -> None:
    path = _processor_export(
        tmp_path, "RISCV:LE:32:default:gcc", "RISCV"
    )

    assert parse_re_file(str(path)).isa == "riscv32"


def test_ghidra_accepts_address_space_qualified_addresses(
    tmp_path: Path,
) -> None:
    # Ghidra 12.2 exports RISC-V addresses as ``ram:offset``.
    path = tmp_path / "riscv.xml"
    path.write_text(
        "<?xml version=\"1.0\"?>\n"
        "<PROGRAM NAME=\"riscv\">\n"
        "  <PROCESSOR NAME=\"RISCV\" "
        "LANGUAGE_PROVIDER=\"RISCV:LE:64:default:gcc\" ENDIAN=\"little\" />\n"
        "  <MEMORY_MAP>\n"
        "    <MEMORY_SECTION NAME=\".text\" START_ADDR=\"ram:00001000\" "
        "LENGTH=\"0x20\" PERMISSIONS=\"rx\" />\n"
        "  </MEMORY_MAP>\n"
        "  <FUNCTIONS>\n"
        "    <FUNCTION ENTRY_POINT=\"ram:00001000\" NAME=\"main\">\n"
        "      <ADDRESS_RANGE START=\"ram:00001000\" "
        "END=\"ram:0000100b\" />\n"
        "    </FUNCTION>\n"
        "  </FUNCTIONS>\n"
        "</PROGRAM>\n",
        encoding="utf-8",
    )

    result = parse_re_file(str(path))

    assert result.isa == "riscv64"
    assert result.warnings == []
    assert len(result.functions) == 1
    assert result.functions[0].name == "main"
    assert result.functions[0].start_address == 0x1000
    assert result.functions[0].length == 0xC
