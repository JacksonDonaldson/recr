"""Parser tests for the supported reverse-engineering exports."""

from __future__ import annotations

from pathlib import Path

import pytest

from input_parser import ParseError, parse_re_file
from parsers import ghidra_xml, yaml

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


def test_sample_yaml_parses() -> None:
    path = str(FIXTURES / "sample.yaml")
    assert yaml.is_supported(path)
    result = parse_re_file(path)
    assert result.isa == "x86_64"
    assert [(f.name, f.start_address, f.file_offset, f.length) for f in result.functions] == [
        ("_start", 0x401000, 0x1000, 0x20),
        ("main", 0x401020, 0x1020, 0x40),
        ("helper", 0x401060, 0x1060, 0x10),
    ]
    assert result.warnings == []


def test_equivalent_yaml_and_ghidra_exports_parse_identically() -> None:
    yaml_export = parse_re_file(str(FIXTURES / "sample_ghidra.yaml"))
    xml_export = parse_re_file(str(FIXTURES / "sample_ghidra.xml"))
    assert yaml_export.isa == xml_export.isa
    assert yaml_export.functions == xml_export.functions


def test_yaml_accepts_yml_extension_and_empty_function_mapping(tmp_path: Path) -> None:
    path = tmp_path / "empty.YML"
    path.write_text("isa: riscv64\nfunctions: {}\n", encoding="utf-8")
    assert yaml.is_supported(str(path))
    assert parse_re_file(str(path)).functions == []


@pytest.mark.parametrize(
    "text,reason",
    [
        ("functions: [", "invalid YAML export"),
        ("!!map []", "expected a mapping node"),
        ("!!python/object/apply:builtins.str [hello]", "could not determine a constructor"),
        ("[]", "document must be a mapping"),
        ("isa: true\nfunctions: {}", "'isa' must be a nonempty string"),
        ("functions: {}", "'isa' must be a nonempty string"),
        ("isa: x86_64\nfunctions: []", "'functions' must be a mapping"),
        ("isa: x86_64\nfunctions: {42: {}}", "function names must be nonempty strings"),
        ("isa: x86_64\nfunctions: {main: []}", "function 'main' must be a mapping"),
        ("isa: x86_64\nfunctions: {main: {}, main: {}}", "duplicate mapping key 'main'"),
    ],
)
def test_invalid_yaml_exports_are_rejected(tmp_path: Path, text: str, reason: str) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(text, encoding="utf-8")
    assert not yaml.is_supported(str(path))
    with pytest.raises(ParseError, match=reason):
        parse_re_file(str(path))


@pytest.mark.parametrize(
    "record,field",
    [
        ("start_address: -1, file_offset: 0, length: 1", "start_address"),
        ("start_address: 0x10000000000000000, file_offset: 0, length: 1", "start_address"),
        ("start_address: 1, file_offset: 0, length: 0", "length"),
        ("start_address: 1, file_offset: 0, length: true", "length"),
        ("start_address: 1, file_offset: 0, length: '0x1'", "length"),
        ("start_address: 1, file_offset: -2, length: 1", "file_offset"),
        ("start_address: 1, length: 1", "file_offset"),
    ],
)
def test_invalid_yaml_function_numbers_are_rejected(tmp_path: Path, record: str, field: str) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(f"isa: x86_64\nfunctions:\n  main: {{{record}}}\n", encoding="utf-8")
    with pytest.raises(ParseError, match=f"function 'main' field '{field}'"):
        parse_re_file(str(path))


def test_yaml_rejects_a_function_extending_past_address_space(tmp_path: Path) -> None:
    path = tmp_path / "overflow.yaml"
    path.write_text(
        "isa: riscv64\nfunctions:\n"
        "  example: {start_address: 0xffffffffffffffff, file_offset: -1, length: 2}\n",
        encoding="utf-8",
    )
    with pytest.raises(ParseError, match="extends past the 64-bit address space"):
        parse_re_file(str(path))


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
    assert main.length == 0x30C

    binary_search = functions["binary_search"]
    assert binary_search.start_address == 0x401790
    assert binary_search.length == 0x9B

    switch_dispatch = functions["switch_dispatch"]
    assert switch_dispatch.start_address == 0x401B37
    assert switch_dispatch.length == 0x57

    unreferenced = functions["unreferenced_function"]
    assert unreferenced.start_address == 0x401B8E
    assert unreferenced.length == 0x34

    mix_a = functions["mix_a"]
    assert mix_a.start_address == 0x401BC2
    assert mix_a.length == 0x25

    mix_b = functions["mix_b"]
    assert mix_b.start_address == 0x401BE7
    assert mix_b.length == 0x25

    mix_c = functions["mix_c"]
    assert mix_c.start_address == 0x401C0C
    assert mix_c.length == 0x25

    mix_total = functions["mix_total"]
    assert mix_total.start_address == 0x401C31
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


@pytest.mark.parametrize("name", [
    "main_app::switchD_ram:b01b81e0::caseD_0",
    "main_app::caseD_0",
    "caseD_0",
    "switchD_unk_type_65::c00101c4a::default",
])
def test_ghidra_preserves_all_ranges_of_a_switch_case(tmp_path: Path, name: str) -> None:
    path = tmp_path / "switch.xml"
    path.write_text(f"""<PROGRAM>
      <PROCESSOR LANGUAGE_PROVIDER="RISCV:LE:64:default:gcc" />
      <FUNCTIONS>
        <FUNCTION NAME="{name}" ENTRY_POINT="ram:b01b7fd2">
          <ADDRESS_RANGE START="ram:b01b7fd0" END="ram:b01b7fdd" />
          <ADDRESS_RANGE START="ram:b01b8072" END="ram:b01b8083" />
        </FUNCTION>
        <FUNCTION NAME="main_app::default" ENTRY_POINT="ram:b01b90f0">
          <ADDRESS_RANGE START="ram:b01b90f0" END="ram:b01b90f1" />
        </FUNCTION>
      </FUNCTIONS>
    </PROGRAM>""")

    result = parse_re_file(str(path))

    assert [(f.name, f.start_address, f.length) for f in result.functions] == [("main_app::default", 0xB01B90F0, 2)]
    assert result.warnings == []
    assert result.switch_case_ranges == [(0xB01B7FD0, 0xB01B7FDE), (0xB01B8072, 0xB01B8084)]


def test_ghidra_rejects_a_switch_case_without_extent_metadata(tmp_path: Path) -> None:
    path = tmp_path / "switch.xml"
    path.write_text("""<PROGRAM>
      <PROCESSOR LANGUAGE_PROVIDER="RISCV:LE:64:default:gcc" />
      <FUNCTIONS>
        <FUNCTION NAME="switchD_ram:b01b81e0::caseD_0" ENTRY_POINT="ram:b01b7fd2" />
      </FUNCTIONS>
    </PROGRAM>""")

    with pytest.raises(ParseError, match=r"cannot preserve Ghidra switch case .*no ADDRESS_RANGE"):
        parse_re_file(str(path))


def test_ghidra_is_supported() -> None:
    assert ghidra_xml.is_supported(str(FIXTURES / "sample_ghidra.xml"))
    assert not ghidra_xml.is_supported(str(FIXTURES / "sample.yaml"))


def test_parse_re_file_rejects_non_ghidra_xml(tmp_path: Path) -> None:
    path = tmp_path / "not_ghidra.xml"
    path.write_text("<root />", encoding="utf-8")

    with pytest.raises(ParseError, match="not a Ghidra XML export"):
        parse_re_file(str(path))


def test_parse_re_file_reports_the_location_of_malformed_ghidra_xml(tmp_path: Path) -> None:
    path = tmp_path / "malformed.xml"
    path.write_text("<PROGRAM>\n  <FUNCTIONS>\n</PROGRAM>\n", encoding="utf-8")

    with pytest.raises(ParseError, match="mismatched tag.*line 3, column") as exc:
        parse_re_file(str(path))
    assert str(path) in str(exc.value)


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


@pytest.mark.parametrize("language", ["RISCV:BE:64:default:gcc", "RISCV:LE:32:AndeStar_v5:gcc"])
def test_ghidra_rejects_unsupported_riscv_language(tmp_path: Path, language: str) -> None:
    path = _processor_export(tmp_path, language, "RISCV")
    with pytest.raises(ParseError, match="unsupported Ghidra processor"):
        parse_re_file(str(path))


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
