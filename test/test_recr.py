"""Exercise recompilation, trampolines, and fragmented ELF placement."""

from __future__ import annotations

from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile
import pytest
import yaml

from binary.binary import Binary
from ir import Address
from isa.x86_64 import X86_64ISA
from recr import main
from recompiler.compiler import rewrite_hooks
from recompiler.exports import Exports, Segment
from recompiler.placement import Object, Section, Space, _Image, place


TEST = Path(__file__).resolve().parent
FIXTURES = TEST / "fixtures"
GHIDRA_XML = FIXTURES / "sample_ghidra.xml"


@pytest.fixture(scope="module")
def input_image(tmp_path_factory):
    path = tmp_path_factory.mktemp("recr")
    binary = path / "sample"
    export = path / "sample.xml"
    subprocess.run([
        "gcc", "-m64", "-O0", "-g3", "-fno-omit-frame-pointer", "-fno-inline",
        "-fno-pie", "-no-pie", "-Wl,--section-start=.recr_space=0x500000,-z,ibtplt",
        str(TEST / "sample.c"), str(FIXTURES / "recr_space.S"), "-o", str(binary),
    ], check=True, capture_output=True)
    root = ET.parse(GHIDRA_XML)
    with binary.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        for symbol in symbols.iter_symbols():
            if not symbol.name.startswith(("recr_spare_", "recr_scale")):
                continue
            start = symbol["st_value"]
            function = ET.SubElement(
                root.find("FUNCTIONS"), "FUNCTION", NAME=symbol.name, ENTRY_POINT=f"{start:x}",
            )
            ET.SubElement(function, "ADDRESS_RANGE", START=f"{start:x}", END=f"{start + symbol['st_size'] - 1:x}")
            if symbol.name == "recr_scale":
                ET.SubElement(function, "RETURN_TYPE", DATATYPE="double")
                ET.SubElement(function, "TYPEINFO_CMT").text = "double recr_scale(double value)"
    root.write(export, encoding="utf-8")
    return binary, export


def test_hook_uses_original_functions_and_shadows_exports(input_image, tmp_path):
    binary, export = input_image
    output = tmp_path / "hooked"
    receipt = tmp_path / "receipt.yaml"
    assert main([str(binary), str(export), str(FIXTURES / "sample.rec"), "-o", str(output), "-r", str(receipt)]) == 0
    assert output.stat().st_size == binary.stat().st_size
    original = subprocess.run([binary], check=True, text=True, capture_output=True)
    rewritten = subprocess.run([output], check=True, text=True, capture_output=True)
    assert "min_int just got called" not in original.stdout
    assert rewritten.stdout.splitlines() == [
        "min_int just got called",
        "original min_int=3 add=6 subtract=1",
        "typed result=2.5",
        "in hook: global_string=alobal string other_global_string=cook global string",
        "total=9835 factorial=720 first=1 last=9",
        "global_string=alobal string other_global_string=other global string",
    ]
    before, after = Binary(binary), Binary(output)
    target = before.symbol_address("min_int")
    assert after.read(target, 4) == before.read(target, 4) == bytes.fromhex("f30f1efa")
    assert after.read(target + 4, 1) == b"\xe9"
    assert any(item["address"] == target + 4 for item in yaml.safe_load(receipt.read_text())["modified"])


def test_fragmented_hook_executes_calls_and_jumps_with_a_static_library(input_image, tmp_path):
    binary, export = input_image
    source = tmp_path / "library.c"
    obj, archive = tmp_path / "library.o", tmp_path / "libexample.a"
    source.write_text("int extra(int n) { return n + 7; }\n")
    subprocess.run(["gcc", "-Os", "-fno-pic", "-c", source, "-o", obj], check=True)
    subprocess.run(["ar", "rcs", archive, obj], check=True)
    rec = tmp_path / "split.rec"
    rec.write_text("""
        extern int extra(int);
        int @min_int(int a, int b) {
            if (b) __asm__ volatile(".rept 280\\n nop\\n .endr");
            return extra(min_int(a + DELTA, b));
        }
    """)
    output = tmp_path / "split"
    receipt = tmp_path / "receipt.yaml"
    assert main([
        str(binary), str(export), str(rec), "-o", str(output), "-r", str(receipt),
        "--", "-DDELTA=1", f"-L{tmp_path}", "-lexample",
    ]) == 0
    result = subprocess.run([output], check=True, text=True, capture_output=True)
    assert "total=9844 " in result.stdout
    ranges = yaml.safe_load(receipt.read_text())["modified"]
    large_fragments = [
        item for item in ranges if item["address"] >= 0x500000 and item["length"] > 100
    ]
    assert len(large_fragments) >= 2


def test_recr_rejects_missing_hook(sample_elf, tmp_path, capsys):
    rec = tmp_path / "missing.rec"
    rec.write_text("int @no_such_function(void) { return 0; }")
    output = tmp_path / "output"
    assert main([str(sample_elf), str(GHIDRA_XML), str(rec), "-o", str(output)]) == 1
    assert "must match exactly one original function, found 0" in capsys.readouterr().err
    assert not output.exists()


def test_recr_rejects_ambiguous_hook(sample_elf, tmp_path, capsys):
    root = ET.parse(GHIDRA_XML)
    nodes = root.find("FUNCTIONS")
    nodes.append(nodes.find("FUNCTION[@NAME='min_int']"))
    export, rec = tmp_path / "duplicate.xml", tmp_path / "duplicate.rec"
    root.write(export)
    rec.write_text("int @min_int(int a, int b) { return a + b; }")
    assert main([str(sample_elf), str(export), str(rec), "-o", str(tmp_path / "output")]) == 1
    assert "must match exactly one original function, found 2" in capsys.readouterr().err


def test_placement_failure_preserves_an_existing_output(sample_elf, tmp_path, capsys):
    rec, output = tmp_path / "too_large.rec", tmp_path / "output"
    rec.write_text('int @min_int(int a, int b) { __asm__ volatile(".rept 500\\n nop\\n .endr"); return a + b; }')
    output.write_bytes(b"previous output")
    assert main([str(sample_elf), str(GHIDRA_XML), str(rec), "-o", str(output)]) == 1
    assert "insufficient cleared executable space" in capsys.readouterr().err
    assert output.read_bytes() == b"previous output"


def test_writable_data_requires_a_writable_receipt_range(sample_elf, tmp_path, capsys):
    rec = tmp_path / "writable.rec"
    rec.write_text("volatile int state = 3; int @min_int(int a, int b) { return state++; }")
    output = tmp_path / "output"
    assert main([str(sample_elf), str(GHIDRA_XML), str(rec), "-o", str(output)]) == 1
    assert "insufficient cleared space for .data" in capsys.readouterr().err
    assert not output.exists()


def test_split_section_promotes_a_short_branch_to_a_distant_fragment():
    code = bytes.fromhex("31c0 7402 90 c3 b807000000 c3")
    # The original section fits in one slot before promotion, so both slots
    # are just smaller than the section. A final fragment has no stitch jump.
    code += b"\x90\x90\xc3"
    section = Section(".text.example", code, 6, 1)
    segments = [Segment(address, 12, 12, 5) for address in (0x10000, 0x20000)]
    exports = Exports({}, {}, {}, segments, [], set())
    isa = X86_64ISA()
    fragments = place(Object({1: section}, {}), Space([(s.start, s.size) for s in segments], exports), {}, isa)
    assert len(fragments) == 2
    first = fragments[0]
    branch = isa.disassemble(_Image(bytes(first.data)), 2)
    assert branch.length == 6
    assert branch.flows_to[0] == Address.absolute(fragments[1].address - first.address)


def test_hook_syntax_preserves_comments_and_literals():
    source = '/* @comment */ char s[] = "@literal";\n// @line\nint @target(void) {}\n'
    rewritten, names = rewrite_hooks(source)
    assert rewritten == source.replace("@target", "__recr_hook_target")
    assert names == ("target",)
