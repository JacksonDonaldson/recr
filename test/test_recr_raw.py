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

import cache
import codezip
from recr import main
from recompiler.placement import Space
from recompiler.raw import read_raw_input
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
        for name in ("_start", "transform", "transform_thunk", "dispatched", "spare"):
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


@pytest.mark.parametrize("firmware", ["riscv64"], indirect=True)
def test_recr_places_riscv_hook_and_trampoline_in_reach(firmware: Firmware, tmp_path: Path) -> None:
    far = 0x900000
    data = bytes.fromhex("13000000") * 7 + bytes.fromhex("67800000")
    offset = firmware.binary.stat().st_size
    with firmware.binary.open("ab") as image:
        image.write(data)
    firmware.layout["regions"].append(dict(start_address=far, file_offset=offset, length=len(data), permissions="rx"))
    firmware.layout["functions"]["far_spare"] = dict(start_address=far, length=len(data))
    firmware.manifest.write_text(yaml.safe_dump(firmware.layout), encoding="utf-8")

    output = tmp_path / "hooked.bin"
    receipt = tmp_path / "receipt.yaml"
    assert main([
        str(firmware.manifest), str(HOOK), "--cc", shlex.join(firmware.compiler), "-o", str(output), "-r", str(receipt),
    ]) == 0
    assert firmware.run(output, tmp_path / "hooked") == 24
    assert output.read_bytes()[offset:] == b"\xff" * len(data)
    assert any(item["address"] == far for item in yaml.safe_load(receipt.read_text())["freed"])


@pytest.mark.parametrize("failure", ["unreachable", "overrun", "decode"])
def test_recr_classifies_uplift_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    monkeypatch.setattr(cache, "CACHE_ROOT", tmp_path / "cache")
    image = tmp_path / "original.bin"
    manifest = tmp_path / "original.yaml"
    hook = tmp_path / "change.re.c"
    output = tmp_path / "result.bin"
    receipt = tmp_path / "receipt.yaml"
    base = 0x400000
    bad, neighbor = 0x40, 0x60
    data = bytearray(b"\xcc" * 0x200)
    data[:6] = bytes.fromhex("b8 07 00 00 00 c3")
    data[0x100:0x180] = b"\x90" * 0x7f + b"\xc3"
    if failure == "unreachable":
        data[bad:bad + 4] = bytes.fromhex("eb 02 90 90")
        # The only reachable branch into neighbor targets its second instruction.
        disp = neighbor + 1 - (bad + 9)
        data[bad + 4:bad + 9] = b"\xe9" + disp.to_bytes(4, "little", signed=True)
        data[neighbor:neighbor + 4] = bytes.fromhex("90 90 90 c3")
        length = 9
        reason = "2 decoded instruction(s) are unreachable"
    elif failure == "overrun":
        neighbor = bad + 2
        data[bad:neighbor + 4] = bytes.fromhex("b8 90 90 90 90 c3")
        length = 2
        reason = "extends past the function end"
    else:
        bad, length = len(data) - 1, 1
        data[bad] = 0x0f
        data[neighbor:neighbor + 4] = bytes.fromhex("90 90 90 c3")
        reason = "failed to decode instruction"
    image.write_bytes(data)
    manifest.write_text(yaml.safe_dump({
        "binary": image.name,
        "isa": "x86_64",
        "regions": [dict(start_address=base, file_offset=0, length=len(data), permissions="rx")],
        "functions": {
            "transform": dict(start_address=base, length=6, declaration="int transform(void);"),
            "bad": dict(start_address=base + bad, length=length),
            "neighbor": dict(start_address=base + neighbor, length=4),
            "spare": dict(start_address=base + 0x100, length=0x80),
        },
    }))
    hook.write_text("int @transform(void) { return 17; }\n")
    args = [str(manifest), str(hook), "-o", str(output), "-r", str(receipt), "--cc", "gcc"]
    assert main(args) == (1 if failure == "decode" else 0)
    stderr = capsys.readouterr().err
    if failure == "decode":
        assert reason in caplog.text
        assert "failed to uplift bad" in caplog.text
        assert f"[{base + bad:#x}, {base + bad + length:#x}) using x86_64" in caplog.text
        assert "Available bytes are 0f" in caplog.text
        assert not output.exists()
        assert not receipt.exists()
        return

    assert reason in stderr
    assert "recr: warning: cannot uplift function bad:" in stderr
    assert "[-Winvalid-function-extent]" in stderr
    rewritten = output.read_bytes()
    assert rewritten[bad:bad + length] == data[bad:bad + length]
    assert rewritten[neighbor:neighbor + 4] == data[neighbor:neighbor + 4]
    assert rewritten[:6] != data[:6]
    previous_receipt = receipt.read_bytes()

    def unexpected_compaction(*args, **kwargs):
        pytest.fail("expected to reuse compaction and replay its extent warnings")

    monkeypatch.setattr(codezip, "run_pipeline", unexpected_compaction)
    assert main([*args, "-Werror"]) == 1
    assert "recr: error: cannot uplift function bad:" in capsys.readouterr().err
    assert output.read_bytes() == rewritten
    assert receipt.read_bytes() == previous_receipt

    assert main([*args, "-Werror", "-Wno-invalid-function-extent"]) == 0
    assert reason not in capsys.readouterr().err
    assert output.read_bytes() == rewritten
    assert receipt.read_bytes() == previous_receipt


def test_recr_reuses_raw_compaction_across_hook_edits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cache, "CACHE_ROOT", tmp_path / "cache")
    image, manifest, hook = (tmp_path / name for name in ("image.bin", "image.yaml", "hook.re.c"))
    output, receipt = tmp_path / "output", tmp_path / "receipt.yaml"
    base = 0x400000
    data = bytearray(b"\xcc" * 0x210)
    data[:6] = bytes.fromhex("b8 07 00 00 00 c3")
    data[0x100:0x180] = b"\x90" * 0x7f + b"\xc3"
    functions = {
        "transform": dict(start_address=base, length=6, declaration="int transform(void);"),
        "spare": dict(start_address=base + 0x100, length=0x80),
    }
    sequence = bytes.fromhex("8b07 0306 0fafc0 8902 c3")
    for index in range(3):
        start = 0x20 + 0x20 * index
        data[start:start + len(sequence)] = sequence
        functions[f"retained_{index}"] = dict(start_address=base + start, length=len(sequence))
        # The image contains pointers to the retained functions.
        data[0x200 + 4 * index:0x204 + 4 * index] = (base + start).to_bytes(4, "little")
    image.write_bytes(data)
    layout = {
        "binary": image.name, "isa": "x86_64", "functions": functions,
        "regions": [dict(start_address=base, file_offset=0, length=len(data), permissions="rx")],
    }
    manifest.write_text(yaml.safe_dump(layout))
    hook.write_text("int @transform(void) { return 17; }\n")
    args = [str(manifest), str(hook), "--cc", "gcc", "-o", str(output), "-r", str(receipt)]
    run_pipeline = codezip.run_pipeline
    compactions = 0

    def count_compaction(*args, **kwargs):
        nonlocal compactions
        compactions += 1
        return run_pipeline(*args, **kwargs)

    monkeypatch.setattr(codezip, "run_pipeline", count_compaction)
    assert main(args) == 0
    assert compactions == 1
    initial_output, initial_receipt = output.read_bytes(), receipt.read_bytes()
    assert initial_output[0x20] == 0xe8  # An outlined call in the cached patch set.
    assert main(args) == 0
    assert compactions == 1
    assert output.read_bytes() == initial_output
    assert receipt.read_bytes() == initial_receipt

    hook.write_text("int @transform(void) { return 18; }\n")
    assert main(args) == 0
    assert compactions == 1
    edited_output = output.read_bytes()
    assert edited_output != initial_output
    assert receipt.read_bytes() == initial_receipt

    entry, = tmp_path.glob("codezip-recr-*/*.json")
    entry.write_bytes(b"incomplete")
    assert main(args) == 0
    assert compactions == 2
    assert output.read_bytes() == edited_output

    layout["entry_points"] = [functions["retained_0"]["start_address"]]
    manifest.write_text(yaml.safe_dump(layout))
    assert main(args) == 0
    assert compactions == 3
    assert output.read_bytes()[0x20:0x20 + len(sequence)] == sequence

    data[-1] = 0x42
    image.write_bytes(data)
    assert main(args) == 0
    assert compactions == 4
    assert output.read_bytes()[-1] == 0x42


def test_recr_checks_fixed_riscv_hi20_before_compaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cache, "CACHE_ROOT", tmp_path / "cache")
    image, manifest, hook = (tmp_path / name for name in ("image.bin", "image.yaml", "hook.re.c"))
    output, receipt = tmp_path / "output", tmp_path / "receipt.yaml"
    base = 0x400000
    data = bytes.fromhex("1b 05 15 00 67 80 00 00") + bytes(8)
    data += bytes.fromhex("13 00 00 00") * 63 + bytes.fromhex("67 80 00 00")
    image.write_bytes(data)
    layout = {
        "binary": image.name, "isa": "riscv64", "riscv": {"march": "rv64i", "abi": "lp64"},
        "functions": {
            "transform": dict(start_address=base, length=8, declaration="int transform(int value);"),
            "spare": dict(start_address=base + 16, length=256),
        },
        "regions": [
            dict(start_address=base, file_offset=0, length=len(data), permissions="rx"),
            dict(start_address=0x7ffff7fc, length=8, permissions="rw"),
        ],
        "symbols": {"counter": dict(address=0x7ffff7fc, declaration="extern volatile int counter;")},
    }
    manifest.write_text(yaml.safe_dump(layout))
    hook.write_text("int @transform(int value) { return value + counter; }\n")
    args = [str(manifest), str(hook), "--cc", shlex.join(RISCV64_CC), "-o", str(output), "-r", str(receipt)]
    assert main(args) == 0
    original_output, original_receipt = output.read_bytes(), receipt.read_bytes()
    layout["symbols"]["counter"]["address"] += 4
    manifest.write_text(yaml.safe_dump(layout))

    def unexpected_compaction(*args, **kwargs):
        pytest.fail("an unencodable fixed relocation should fail before compaction")

    with monkeypatch.context() as patch:
        patch.setattr(codezip, "run_pipeline", unexpected_compaction)
        assert main([*args, "--verbose"]) == 1
    diagnostic = capsys.readouterr().err
    assert "R_RISCV_HI20 at .text.__recr_hook_transform+" in diagnostic
    assert "symbol 'counter' resolves to 0x7ffff800" in diagnostic
    assert "Rounded LUI immediate +0x80000000 does not fit" in diagnostic
    assert "[-0x80000000, +0x7ffff000]" in diagnostic
    assert "-- -mcmodel=medany" in diagnostic
    assert output.read_bytes() == original_output
    assert receipt.read_bytes() == original_receipt
    assert main([*args, "--", "-mcmodel=medany"]) == 0

    layout["regions"][1]["start_address"] = 0xb0200c44
    layout["symbols"]["counter"]["address"] = 0xb0200c44
    manifest.write_text(yaml.safe_dump(layout))
    medany_output, medany_receipt = output.read_bytes(), receipt.read_bytes()
    assert main([*args, "--", "-mcmodel=medany"]) == 1
    diagnostic = capsys.readouterr().err
    assert "R_RISCV_PCREL_HI20 at .text.__recr_hook_transform+" in diagnostic
    assert "for symbol 'counter' failed. cannot reach 0xb0200c44 from 0x" in diagnostic
    assert "Rounded AUIPC displacement" in diagnostic
    assert output.read_bytes() == medany_output
    assert receipt.read_bytes() == medany_receipt


@pytest.mark.parametrize("with_ghidra_export", [False, True], ids=["yaml-functions", "ghidra-functions"])
@pytest.mark.parametrize(("warning_flags", "warns"), [
    ([], True),
    (["-Wall", "-Werror=unused-variable"], True),
    (["-Wall", "-Werror", "-Wno-function-outside-executable-range", "-Wno-skip-short-functions"], False),
    (["-Wno-skip-short-functions", "-Wno-function-outside-executable-range", "-Werror", "-Wall"], False),
], ids=["default", "all", "suppress-after", "suppress-before"])
def test_recr_hooks_static_raw_image(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str], with_ghidra_export: bool,
    warning_flags: list[str], warns: bool,
) -> None:
    receipt = tmp_path / "receipt.yaml"
    before = firmware.binary.read_bytes()
    text = firmware.layout["regions"][-1]
    ignored = {
        "unmapped": {"start_address": 0x500000, "length": 4, "declaration": "invalid declaration"},
        "in_data": {"start_address": firmware.layout["regions"][0]["start_address"], "length": 4},
        "crosses_text_end": {"start_address": text["start_address"] + 2, "length": text["length"]},
    }
    short_length = 1 if firmware.isa == "riscv64" else 0
    # Ghidra represents extents as inclusive address ranges.
    has_short_record = short_length > 0 or not with_ghidra_export
    if has_short_record:
        firmware.layout["functions"]["short"] = {"start_address": text["start_address"] + 4, "length": short_length}
    firmware.layout["functions"].update(ignored)
    export_args = []
    if with_ghidra_export:
        export = tmp_path / "firmware.xml"
        _write_ghidra_export(firmware, export, transform_name="main_app::transform")
        export_args.append(str(export))
        manifest = {key: value for key, value in firmware.layout.items() if key not in {"isa", "functions", "symbols"}}
    else:
        manifest = firmware.layout
    firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    assert main([
        str(firmware.manifest), *export_args, str(HOOK), "--cc", shlex.join(firmware.compiler), "-r", str(receipt),
        *warning_flags,
    ]) == 0
    stderr = capsys.readouterr().err
    assert stderr.count("[-Wfunction-outside-executable-range]") == (len(ignored) if warns else 0)
    assert ("[-Wskip-short-functions]" in stderr) == (warns and has_short_record)
    for name in ignored:
        assert (f"warning: skipping raw function {name!r}" in stderr) == warns
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


def _write_ghidra_export(firmware: Firmware, output: Path, *, transform_name: str = "transform") -> None:
    root = ET.Element("PROGRAM")
    language = "RISCV:LE:64:default:gcc" if firmware.isa == "riscv64" else "x86:LE:64:default:gcc"
    ET.SubElement(root, "PROCESSOR", LANGUAGE_PROVIDER=language)
    functions = ET.SubElement(root, "FUNCTIONS")
    for name, record in firmware.layout["functions"].items():
        start, length = record["start_address"], record["length"]
        export_name = transform_name if name == "transform" else name
        function = ET.SubElement(functions, "FUNCTION", NAME=export_name, ENTRY_POINT=f"{start:x}")
        ET.SubElement(function, "ADDRESS_RANGE", START=f"{start:x}", END=f"{start + length - 1:x}")
        if name == "transform":
            ET.SubElement(function, "RETURN_TYPE", DATATYPE="int")
            ET.SubElement(function, "TYPEINFO_CMT").text = f"int {export_name}(int value)"
    counter_address = firmware.layout["symbols"]["counter"]["address"]
    counter = f"{counter_address:x}"
    ET.SubElement(ET.SubElement(root, "DATA"), "DEFINED_DATA", ADDRESS=counter, DATATYPE="int")
    ET.SubElement(ET.SubElement(root, "SYMBOL_TABLE"), "SYMBOL", NAME="counter", ADDRESS=counter)
    markup = ET.SubElement(root, "MARKUP")
    entry = firmware.layout["functions"]["_start"]["start_address"]
    transform = firmware.layout["functions"]["transform"]["start_address"]
    thunk = firmware.layout["functions"]["transform_thunk"]["start_address"]
    dispatched = firmware.layout["functions"]["dispatched"]["start_address"]
    ET.SubElement(markup, "MEMORY_REFERENCE", ADDRESS=f"ram:{entry:x}", TO_ADDRESS=f"ram:{thunk:x}")
    ET.SubElement(markup, "MEMORY_REFERENCE", ADDRESS=f"ram:{thunk:x}", TO_ADDRESS=f"ram:{transform:x}")
    # The dispatch pointer follows the four-byte counter in the assembly fixture.
    ET.SubElement(markup, "MEMORY_REFERENCE", ADDRESS=f"ram:{counter_address + 4:x}", TO_ADDRESS=f"ram:{dispatched:x}")
    ET.ElementTree(root).write(output)


def test_recr_imports_strings_and_runtime_only_data(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    with firmware.wrapper.open("rb") as stream:
        elf = ELFFile(stream)
        bss = elf.get_section_by_name(".bss")
        assert bss["sh_type"] == "SHT_NOBITS"
        runtime_start = bss["sh_addr"]
        symtab = elf.get_section_by_name(".symtab")
        message, = symtab.get_symbol_by_name("notify_format")
        counter, = symtab.get_symbol_by_name("runtime_counter")
        assert counter["st_value"] == runtime_start
        runtime_size = counter["st_size"]
        message_address = message["st_value"]
    runtime_end = runtime_start + runtime_size
    export = tmp_path / "firmware.xml"
    _write_ghidra_export(firmware, export)
    xml = ET.parse(export)
    for name, address, datatype in (
        ("notify_format", message_address, "string"),
        ("runtime_counter", runtime_start, "int"),
        ("past_runtime_region", runtime_end, "int"),
    ):
        ET.SubElement(xml.find("DATA"), "DEFINED_DATA", ADDRESS=f"ram:{address:x}", DATATYPE=datatype, SIZE="0x4")
        ET.SubElement(xml.find("SYMBOL_TABLE"), "SYMBOL", NAME=name, ADDRESS=f"ram:{address:x}")
    phantom = ET.SubElement(xml.find("FUNCTIONS"), "FUNCTION", NAME="runtime_function", ENTRY_POINT=f"{runtime_start:x}")
    ET.SubElement(phantom, "ADDRESS_RANGE", START=f"{runtime_start:x}", END=f"{runtime_end - 1:x}")
    xml.write(export)
    manifest = {key: value for key, value in firmware.layout.items() if key not in {"functions", "symbols"}}
    # Even an executable region cannot provide code or free space without backing bytes.
    manifest["regions"] = [
        *manifest["regions"], {"start_address": runtime_start, "length": runtime_size, "permissions": "rwx"},
    ]
    firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    raw = read_raw_input(firmware.manifest, export, warn=lambda message, option: None)
    assert raw.exports.address("runtime_counter") == runtime_start
    assert raw.exports.declarations["runtime_counter"] == "extern int runtime_counter;"
    assert "past_runtime_region" not in raw.exports.addresses
    assert (runtime_start, runtime_size) not in raw.binary.mapped_ranges()
    assert not Space([(runtime_start, runtime_size)], raw.exports).ranges
    original = firmware.binary.read_bytes()
    with pytest.raises(ValueError, match="not mapped"):
        raw.binary.write(runtime_start, b"\xff" * runtime_size)
    assert raw.binary.image_bytes() == original

    hook = tmp_path / "hook.re.c"
    hook.write_text('''int @transform(int value) {
        return transform(value) + runtime_counter + (notify_format[0] == 'Z' ? 40 : 0);
    }
    ''', encoding="utf-8")
    output, receipt = tmp_path / "output", tmp_path / "receipt.yaml"
    assert main([
        str(firmware.manifest), str(export), str(hook), "--cc", shlex.join(firmware.compiler),
        "-o", str(output), "-r", str(receipt),
    ]) == 0
    assert "skipping raw function 'runtime_function'" in capsys.readouterr().err
    assert firmware.run(output, tmp_path / "hooked") == 65
    assert firmware.binary.read_bytes() == original
    assert len(output.read_bytes()) == len(original)
    ranges = yaml.safe_load(receipt.read_text(encoding="utf-8"))
    for item in ranges["freed"] + ranges["modified"]:
        start = item["address"]
        assert start >= runtime_end or start + item["length"] <= runtime_start


@pytest.mark.parametrize(("flags", "level", "typed"), [
    pytest.param([], "warning", True, id="default"),
    pytest.param([], "warning", False, id="untyped"),
    pytest.param(["-Werror"], "error", True, id="fatal"),
    pytest.param(["-Wall", "-Werror", "-Wno-ignoring-thunk-function"], None, True, id="suppressed"),
])
def test_recr_hooks_the_longer_duplicate(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str], flags: list[str], level: str | None,
    typed: bool,
) -> None:
    export = tmp_path / "firmware.xml"
    qualified = "main_app::transform"
    _write_ghidra_export(firmware, export, transform_name=qualified)
    xml = ET.parse(export)
    datatypes = ET.Element("DATATYPES")
    xml.getroot().insert(1, datatypes)
    shared_definition = ET.SubElement(datatypes, "FUNCTION_DEF", NAME=qualified)
    ET.SubElement(shared_definition, "RETURN_TYPE", DATATYPE="void")
    short_node = xml.find("./FUNCTIONS/FUNCTION[@NAME='transform_thunk']")
    short_node.set("NAME", qualified)
    ET.SubElement(short_node, "RETURN_TYPE", DATATYPE="void")
    ET.SubElement(short_node, "TYPEINFO_CMT").text = f"void {qualified}(void)"
    if not typed:
        implementation = xml.find(f"./FUNCTIONS/FUNCTION[@NAME='{qualified}']")
        implementation.remove(implementation.find("RETURN_TYPE"))
        implementation.remove(implementation.find("TYPEINFO_CMT"))
    xml.write(export)
    manifest = {key: value for key, value in firmware.layout.items() if key not in {"functions", "symbols"}}
    firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    longer = firmware.layout["functions"]["transform"]
    shorter = firmware.layout["functions"]["transform_thunk"]
    assert shorter["length"] < 8 <= longer["length"]
    output, receipt = tmp_path / "output", tmp_path / "receipt.yaml"
    output.write_bytes(b"previous output")
    receipt.write_bytes(b"previous receipt")

    result = main([
        str(firmware.manifest), str(export), str(HOOK), "--cc", shlex.join(firmware.compiler),
        "-o", str(output), "-r", str(receipt), *flags,
    ])
    stderr = capsys.readouterr().err
    if level is not None:
        assert f"recr: {level}: ignoring presumed thunk {qualified!r} at {shorter['start_address']:#x}" in stderr
        assert f"Choosing {qualified!r} at {longer['start_address']:#x}" in stderr
        assert "[-Wignoring-thunk-function]" in stderr
    else:
        assert "[-Wignoring-thunk-function]" not in stderr
    if not typed:
        assert f"Ghidra XML export has no usable prototype for {qualified!r} at {longer['start_address']:#x}" in stderr
        assert "Commit all return/parameter details" in stderr
    if level == "error" or not typed:
        assert result == 1
        assert output.read_bytes() == b"previous output"
        assert receipt.read_bytes() == b"previous receipt"
        return

    assert result == 0
    assert firmware.run(output, tmp_path / "hooked") == 24
    text = firmware.layout["regions"][-1]
    offset = text["file_offset"] + shorter["start_address"] - text["start_address"]
    end = offset + shorter["length"]
    assert output.read_bytes()[offset:end] == firmware.binary.read_bytes()[offset:end]
    modified = yaml.safe_load(receipt.read_text(encoding="utf-8"))["modified"]
    assert any(region["address"] == longer["start_address"] for region in modified)


@pytest.mark.parametrize(("declaration", "diagnostic"), [
    pytest.param(None, "raw manifest has no declaration for hook 'transform'", id="missing"),
    pytest.param("extern int transform();", "function declaration isn't a prototype", id="no-prototype"),
])
def test_recr_requires_a_manifest_hook_prototype(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    declaration: str | None, diagnostic: str,
) -> None:
    transform = firmware.layout["functions"]["transform"]
    if declaration is None:
        del transform["declaration"]
    else:
        transform["declaration"] = declaration
    firmware.manifest.write_text(yaml.safe_dump(firmware.layout), encoding="utf-8")
    output, receipt = tmp_path / "output", tmp_path / "receipt"
    output.write_bytes(b"previous output")
    receipt.write_bytes(b"previous receipt")

    assert main([
        str(firmware.manifest), str(HOOK), "--cc", shlex.join(firmware.compiler),
        "-o", str(output), "-r", str(receipt),
    ]) == 1

    assert diagnostic in capsys.readouterr().err
    assert output.read_bytes() == b"previous output"
    assert receipt.read_bytes() == b"previous receipt"


@pytest.mark.parametrize("malformed", [False, True], ids=["inside-entry-window", "malformed-address"])
def test_recr_rejects_unsafe_ghidra_reference(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str], malformed: bool,
) -> None:
    export = tmp_path / "firmware.xml"
    _write_ghidra_export(firmware, export)
    xml = ET.parse(export)
    entry = firmware.layout["functions"]["_start"]["start_address"]
    transform = firmware.layout["functions"]["transform"]["start_address"]
    destination = "ram:not-hex" if malformed else f"ram:{transform + 2:x}"
    ET.SubElement(xml.getroot().find("MARKUP"), "MEMORY_REFERENCE", ADDRESS=f"ram:{entry:x}", TO_ADDRESS=destination)
    xml.write(export)
    manifest = {key: value for key, value in firmware.layout.items() if key not in {"functions", "symbols"}}
    firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    output, receipt = tmp_path / "output", tmp_path / "receipt.yaml"
    output.write_bytes(b"previous output")
    receipt.write_bytes(b"previous receipt")

    assert main([
        str(firmware.manifest), str(export), str(HOOK), "--cc", shlex.join(firmware.compiler),
        "-o", str(output), "-r", str(receipt),
    ]) == 1
    diagnostic = capsys.readouterr().err
    if malformed:
        assert f"invalid TO_ADDRESS {destination!r} for the MEMORY_REFERENCE at 'ram:{entry:x}'" in diagnostic
        assert str(export) in diagnostic
    else:
        assert "hook 'transform' has a reference into its entry window" in diagnostic
        assert f"at {transform + 2:#x}" in diagnostic
    assert output.read_bytes() == b"previous output"
    assert receipt.read_bytes() == b"previous receipt"


@pytest.mark.parametrize(("regions", "reason"), [
    ([], "nonempty list"),
    ([{"start_address": 0x1000, "file_offset": 1, "length": 8}], "past the end of the file"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": True}], "region 1 length"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": 4},
      {"start_address": 0x1002, "file_offset": 4, "length": 4}], "overlap in virtual address space"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": 4},
      {"start_address": 0x1003, "length": 4, "permissions": "rw"}], "overlap in virtual address space"),
    ([{"start_address": 0x1000, "file_offset": 0, "length": 4},
      {"start_address": 0x3000, "file_offset": 2, "length": 4}], "overlap in the file"),
])
def test_recr_rejects_invalid_raw_mappings(tmp_path: Path, capsys, regions: list[dict], reason: str) -> None:
    binary, manifest, output, receipt = (tmp_path / name for name in ("image.bin", "image.yml", "output", "receipt"))
    binary.write_bytes(b"12345678")
    document = {"binary": binary.name, "isa": "x86_64", "regions": regions}
    manifest.write_text(yaml.safe_dump(document), encoding="utf-8")
    output.write_bytes(b"previous output")
    receipt.write_bytes(b"previous receipt")
    assert main([str(manifest), str(HOOK), "-o", str(output), "-r", str(receipt)]) == 1
    diagnostic = capsys.readouterr().err
    assert reason in diagnostic
    assert str(manifest) in diagnostic
    assert output.read_bytes() == b"previous output"
    assert receipt.read_bytes() == b"previous receipt"


@pytest.mark.parametrize(("metadata", "reason"), [
    ({"functions": {"transform": {"start_address": 0x1000, "length": 2, "file_offset": 1}}},
     "file_offset disagrees"),
    ({"functions": {"first": {"start_address": 0x1000, "length": 4},
                    "second": {"start_address": 0x1002, "length": 4}}},
     "overlaps another function"),
    ({"entry_points": [0x3000]}, "outside mapped executable memory"),
    ({"isa": "riscv32", "riscv": {"march": "rv32i", "abi": "lp64"}}, "riscv.abi"),
    ({"isa": "riscv32", "riscv": {"march": "rv32i", "abi": "ilp32"},
      "functions": {"misaligned": {"start_address": 0x1000, "length": 5}}}, "misaligned for the target ISA"),
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


@pytest.mark.parametrize(("metadata", "suppression", "diagnostic"), [
    ({"functions": {"outside": {"start_address": 0x1002, "length": 8}}},
     "-Wno-skip-short-functions", "error: skipping raw function 'outside'"),
    ({"isa": "riscv32", "riscv": {"march": "rv32i", "abi": "ilp32"},
      "functions": {"short": {"start_address": 0x1002, "length": 3}}},
     "-Wno-function-outside-executable-range",
     "error: skipping raw function 'short' at 0x1002: length 3 is below the target alignment of 4 bytes"),
], ids=["outside-executable-range", "short-function"])
def test_recr_treats_raw_function_warning_as_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], metadata: dict, suppression: str, diagnostic: str,
) -> None:
    binary, manifest, output, receipt = (tmp_path / name for name in ("image.bin", "image.yaml", "output", "receipt"))
    binary.write_bytes(b"12345678")
    manifest.write_text(yaml.safe_dump({
        "binary": binary.name, "isa": "x86_64",
        "regions": [{"start_address": 0x1000, "file_offset": 0, "length": 8}],
        **metadata,
    }), encoding="utf-8")
    output.write_bytes(b"previous output")
    assert main([str(manifest), str(HOOK), "-Werror", suppression, "-o", str(output), "-r", str(receipt)]) == 1
    assert diagnostic in capsys.readouterr().err
    assert output.read_bytes() == b"previous output"
    assert not receipt.exists()


def test_raw_input_retains_function_at_alignment(tmp_path: Path) -> None:
    binary, manifest = tmp_path / "image.bin", tmp_path / "image.yaml"
    binary.write_bytes(bytes.fromhex("67800000"))
    manifest.write_text(yaml.safe_dump({
        "binary": binary.name, "isa": "riscv32", "riscv": {"march": "rv32i", "abi": "ilp32"},
        "regions": [{"start_address": 0x1000, "file_offset": 0, "length": 4}],
        "functions": {"exact": {"start_address": 0x1000, "length": 4}},
    }), encoding="utf-8")
    function, = read_raw_input(manifest).parsed.functions
    assert (function.name, function.length, function.file_offset) == ("exact", 4, 0)


def test_recr_treats_ghidra_warning_as_error(
    firmware: Firmware, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    export = tmp_path / "firmware.xml"
    _write_ghidra_export(firmware, export)
    xml = ET.parse(export)
    ET.SubElement(xml.getroot().find("FUNCTIONS"), "FUNCTION", NAME="missing_range", ENTRY_POINT="500000")
    xml.write(export)
    manifest = {key: value for key, value in firmware.layout.items() if key not in {"functions", "symbols"}}
    firmware.manifest.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    assert main([
        str(firmware.manifest), str(export), str(HOOK), "--cc", shlex.join(firmware.compiler),
        "-Wno-function-outside-executable-range", "-Werror",
    ]) == 1
    assert "error: skipping function missing_range: no ADDRESS_RANGE" in capsys.readouterr().err
    assert not firmware.binary.with_suffix(".bin.recr").exists()
