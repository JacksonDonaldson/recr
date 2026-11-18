"""Build a static firmware fixture and run raw-image hooks at their mapped VAs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
import subprocess
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile
import pytest
import yaml

from recr import main
from test.test_recr_riscv import RISCV64_CC, _qemu_command


FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOOK = FIXTURES / "recr_raw.rec"


@dataclass
class Firmware:
    wrapper: Path
    binary: Path
    manifest: Path
    layout: dict
    sections: list[tuple[int, int, int]]
    isa: str
    compiler: list[str]

    def run(self, image: Path, executable: Path) -> int:
        wrapper = bytearray(self.wrapper.read_bytes())
        data = image.read_bytes()
        for binary_offset, elf_offset, length in self.sections:
            wrapper[elf_offset:elf_offset + length] = data[binary_offset:binary_offset + length]
        executable.write_bytes(wrapper)
        executable.chmod(0o755)
        command = _qemu_command(executable, 64) if self.isa == "riscv64" else [executable]
        return subprocess.run(command).returncode


@pytest.fixture(params=["x86_64", "riscv64"])
def firmware(request: pytest.FixtureRequest, tmp_path: Path) -> Firmware:
    isa = request.param
    compiler = RISCV64_CC if isa == "riscv64" else ["gcc"]
    arch = (
        ["-march=rv64ic", "-mabi=lp64", "-Wl,--no-relax"] if isa == "riscv64" else ["-m64"]
    )
    wrapper = tmp_path / "runner.elf"
    subprocess.run([
        *compiler, *arch, "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
        "-Wl,-Ttext=0x400000,--section-start=.spare=0x410000,-Tdata=0x420000",
        FIXTURES / "recr_raw.S", "-o", wrapper,
    ], check=True, capture_output=True)
    binary = tmp_path / "firmware.bin"
    metadata = tmp_path / "config"
    metadata.mkdir()
    manifest = metadata / "firmware.yaml"
    layout = {"binary": "../firmware.bin", "isa": isa, "regions": [], "functions": {}}
    if isa == "riscv64":
        layout["riscv"] = {"march": "rv64ic", "abi": "lp64"}
    data = bytearray(b"firmware header\xff\x00")
    sections = []
    with wrapper.open("rb") as stream:
        elf = ELFFile(stream)
        # File order differs from virtual order. Bytes between mappings are opaque.
        for name, permissions in ((".data", "rw"), (".spare", "rwx"), (".text", None)):
            section = elf.get_section_by_name(name)
            offset = len(data)
            region = dict(start_address=section["sh_addr"], file_offset=offset, length=section["sh_size"])
            if permissions:
                region["permissions"] = permissions
            layout["regions"].append(region)
            sections.append((offset, section["sh_offset"], section["sh_size"]))
            data.extend(section.data())
            data.extend(b"\xfa unmapped \x17")
        symtab = elf.get_section_by_name(".symtab")
        for name in ("_start", "transform", "dispatched", "spare"):
            symbol, = symtab.get_symbol_by_name(name)
            layout["functions"][name] = dict(start_address=symbol["st_value"], length=symbol["st_size"])
        counter, = symtab.get_symbol_by_name("counter")
        layout["symbols"] = {"counter": {"address": counter["st_value"], "declaration": "extern int counter;"}}
    layout["functions"]["transform"]["declaration"] = "extern int transform(int value);"
    layout["entry_points"] = [layout["functions"]["_start"]["start_address"]]
    binary.write_bytes(data)
    manifest.write_text(yaml.safe_dump(layout), encoding="utf-8")
    return Firmware(wrapper, binary, manifest, layout, sections, isa, compiler)


def test_built_static_raw_fixture_runs(firmware: Firmware, tmp_path: Path) -> None:
    assert firmware.run(firmware.binary, tmp_path / "original") == 14


@pytest.mark.parametrize("with_ghidra_export", [False, True], ids=["yaml-functions", "ghidra-functions"])
def test_recr_hooks_static_raw_image(firmware: Firmware, tmp_path: Path, with_ghidra_export: bool) -> None:
    receipt = tmp_path / "receipt.yaml"
    before = firmware.binary.read_bytes()
    export_args = []
    if with_ghidra_export:
        export = tmp_path / "firmware.xml"
        _write_ghidra_export(firmware, export)
        export_args.append(str(export))
        manifest = {key: value for key, value in firmware.layout.items() if key not in {"isa", "functions", "symbols"}}
        firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    assert main([
        str(firmware.manifest), *export_args, str(HOOK), "--cc", shlex.join(firmware.compiler), "-r", str(receipt),
    ]) == 0
    output = firmware.binary.with_suffix(".bin.recr")
    assert firmware.run(output, tmp_path / "hooked") == 24
    assert firmware.binary.read_bytes() == before
    after = output.read_bytes()
    assert len(after) == len(before)
    patched = yaml.safe_load(receipt.read_text(encoding="utf-8"))
    described = set()
    for item in patched["freed"] + patched["modified"]:
        start, length = item["address"], item["length"]
        region, = [
            r for r in firmware.layout["regions"]
            if r["start_address"] <= start and start + length <= r["start_address"] + r["length"]
        ]
        offset = start - region["start_address"] + region["file_offset"]
        described.update(range(offset, offset + length))
    assert {i for i, (old, new) in enumerate(zip(before, after)) if old != new} <= described
    entries = {name: record["start_address"] for name, record in firmware.layout["functions"].items()}
    modified = {item["address"] for item in patched["modified"]}
    assert {entries["transform"], entries["spare"]} <= modified
    assert {entries["_start"], entries["dispatched"]}.isdisjoint(modified)


def _write_ghidra_export(firmware: Firmware, output: Path) -> None:
    root = ET.Element("PROGRAM")
    language = "RISCV:LE:64:default:gcc" if firmware.isa == "riscv64" else "x86:LE:64:default:gcc"
    ET.SubElement(root, "PROCESSOR", LANGUAGE_PROVIDER=language)
    functions = ET.SubElement(root, "FUNCTIONS")
    for name, record in firmware.layout["functions"].items():
        start, length = record["start_address"], record["length"]
        function = ET.SubElement(functions, "FUNCTION", NAME=name, ENTRY_POINT=f"{start:x}")
        ET.SubElement(function, "ADDRESS_RANGE", START=f"{start:x}", END=f"{start + length - 1:x}")
        if name == "transform":
            ET.SubElement(function, "RETURN_TYPE", DATATYPE="int")
            ET.SubElement(function, "TYPEINFO_CMT").text = "int transform(int value)"
    counter = f"{firmware.layout['symbols']['counter']['address']:x}"
    ET.SubElement(ET.SubElement(root, "DATA"), "DEFINED_DATA", ADDRESS=counter, DATATYPE="int")
    ET.SubElement(ET.SubElement(root, "SYMBOL_TABLE"), "SYMBOL", NAME="counter", ADDRESS=counter)
    ET.ElementTree(root).write(output)


@pytest.mark.parametrize(("regions", "reason"), [
    ([], "nonempty list"),
    ([{"start_address": 0x1000, "file_offset": 1, "length": 8}], "past the end of the file"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": True}], "region 1 length"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": 4},
      {"start_address": 0x1002, "file_offset": 4, "length": 4}], "overlap in virtual address space"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": 4},
      {"start_address": 0x3000, "file_offset": 2, "length": 4}], "overlap in the file"),
])
def test_recr_rejects_invalid_raw_mappings(tmp_path: Path, capsys, regions: list[dict], reason: str) -> None:
    binary, manifest, output = (tmp_path / name for name in ("image.bin", "image.yml", "output"))
    binary.write_bytes(b"12345678")
    document = {"binary": binary.name, "isa": "x86_64", "regions": regions}
    manifest.write_text(yaml.safe_dump(document), encoding="utf-8")
    output.write_bytes(b"previous output")
    assert main([str(manifest), str(HOOK), "-o", str(output)]) == 1
    assert reason in capsys.readouterr().err
    assert output.read_bytes() == b"previous output"


@pytest.mark.parametrize(("metadata", "reason"), [
    ({"functions": {"transform": {"start_address": 0x1000, "length": 2, "file_offset": 1}}},
     "file_offset disagrees"),
    ({"functions": {"transform": {"start_address": 0x1001, "length": 9}}},
     "must fit in one executable region"),
    ({"entry_points": [0x3000]}, "outside mapped executable memory"),
    ({"isa": "riscv32", "riscv": {"march": "rv32i", "abi": "lp64"}}, "riscv.abi"),
])
def test_recr_rejects_invalid_raw_metadata(tmp_path: Path, capsys, metadata: dict, reason: str) -> None:
    binary, manifest = tmp_path / "image.bin", tmp_path / "image.yaml"
    binary.write_bytes(b"12345678")
    document = {
        "binary": binary.name, "isa": "x86_64",
        "regions": [{"start_address": 0x1000, "file_offset": 0, "length": 8}],
        **metadata,
    }
    manifest.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert main([str(manifest), str(HOOK)]) == 1
    assert reason in capsys.readouterr().err
    assert not binary.with_suffix(".bin.recr").exists()
