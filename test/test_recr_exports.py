"""Check the metadata passed from Ghidra exports to recr."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from parsers import ghidra_xml
from recompiler.exports import read_ghidra_exports
from recompiler.target import X86_64, Target


@pytest.mark.parametrize(("destinations", "expected"), [
    pytest.param(None, set(), id="no-markup"),
    pytest.param((), set(), id="empty-markup"),
    pytest.param(("ram:80001000",), {0x80001000}, id="single-reference"),
    pytest.param(("80001000", "ram:80001004", "ram:80001000"), {0x80001000, 0x80001004}, id="duplicates"),
    pytest.param(("ram:80001000", None), {0x80001000}, id="missing-destination"),
])
def test_ghidra_references_preserve_target(
    tmp_path: Path, destinations: tuple[str | None, ...] | None, expected: set[int],
) -> None:
    root = ET.Element("PROGRAM")
    if destinations is not None:
        markup = ET.SubElement(root, "MARKUP")
        for index, destination in enumerate(destinations):
            reference = ET.SubElement(markup, "MEMORY_REFERENCE", ADDRESS=f"ram:{0x80000000 + 4 * index:x}")
            if destination is not None:
                reference.set("TO_ADDRESS", destination)
    xml = tmp_path / "firmware.xml"
    ET.ElementTree(root).write(xml)

    target = Target("riscv64", "EM_RISCV", 64, flags=5, march="rv64gc")
    exports = read_ghidra_exports(xml, [], [], target)

    assert exports.references == expected
    assert exports.target is target


def test_ghidra_namespaced_function_keeps_its_name_and_typed_definition(tmp_path: Path) -> None:
    xml = tmp_path / "program.xml"
    xml.write_text(
        """<PROGRAM>
          <PROCESSOR LANGUAGE_PROVIDER="x86:LE:64:default:gcc" />
          <DATATYPES>
            <FUNCTION_DEF NAME="AppVprintf">
              <RETURN_TYPE DATATYPE="void" />
            </FUNCTION_DEF>
            <FUNCTION_DEF NAME="main_app::AppVprintf">
              <RETURN_TYPE DATATYPE="int" />
              <PARAMETER DATATYPE="char *" />
            </FUNCTION_DEF>
          </DATATYPES>
          <FUNCTIONS>
            <FUNCTION NAME="main_app::AppVprintf" ENTRY_POINT="1000">
              <ADDRESS_RANGE START="1000" END="100f" />
            </FUNCTION>
          </FUNCTIONS>
        </PROGRAM>""",
        encoding="utf-8",
    )
    functions = ghidra_xml.parse(str(xml)).functions
    function, = functions
    exports = read_ghidra_exports(xml, functions, [], X86_64)

    assert function.name == "main_app::AppVprintf"
    assert exports.functions == {"AppVprintf": [function]}
    assert exports.address("AppVprintf") == 0x1000
    assert exports.declarations == {"AppVprintf": "extern int AppVprintf(char *);"}
