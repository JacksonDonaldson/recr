"""Cross-build and exercise RISC-V sample executables under QEMU."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile
import pytest
import yaml

from binary.binary import Binary
from recr import main


TEST = Path(__file__).resolve().parent
FIXTURES = TEST / "fixtures"
RISCV64_CC = shlex.split(os.environ.get("RISCV64_CC", "riscv64-linux-gnu-gcc"))
RISCV64_SYSROOT = os.environ.get("RISCV64_SYSROOT", "/usr/riscv64-linux-gnu")
RISCV64_XML = FIXTURES / "sample_riscv64_ghidra.xml"


def _qemu_command(binary: Path, bits: int) -> list[str | Path]:
    variable = f"RISCV{bits}_QEMU"
    qemu = os.environ.get(variable) or shutil.which(f"qemu-riscv{bits}-static")
    qemu = qemu or f"qemu-riscv{bits}"
    sysroot = ["-L", RISCV64_SYSROOT] if bits == 64 else []
    return [*shlex.split(qemu), *sysroot, binary]


def _run_riscv(binary: Path) -> str:
    result = subprocess.run(_qemu_command(binary, 64), check=True, text=True, capture_output=True)
    return result.stdout


def _build_sample(binary: Path, *extra: str) -> None:
    subprocess.run([
        *RISCV64_CC, "-O0", "-g3", "-fno-omit-frame-pointer", "-fno-inline",
        "-fno-pie", "-no-pie", str(TEST / "sample.c"), *extra, "-o", binary,
    ], check=True, capture_output=True)


@pytest.fixture(scope="module")
def riscv64_sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    binary = tmp_path_factory.mktemp("sample-rv64") / "sample"
    _build_sample(binary)
    return binary


def test_sample_c_runs_on_riscv64(riscv64_sample: Path) -> None:
    assert _run_riscv(riscv64_sample).splitlines() == [
        "total=9836 factorial=720 first=1 last=9",
        "global_string=global string other_global_string=other global string",
    ]


@pytest.fixture(scope="module")
def riscv64_hook_image(tmp_path_factory: pytest.TempPathFactory) -> Path:
    binary = tmp_path_factory.mktemp("recr-rv64") / "sample"
    _build_sample(
        binary, str(FIXTURES / "recr_space_riscv64.S"), str(FIXTURES / "recr_scale.c"),
        "-Wl,--section-start=.recr_space=0x80000",
    )
    return binary


def test_recr_hooks_the_riscv64_sample(riscv64_hook_image: Path, tmp_path: Path) -> None:
    output = tmp_path / "hooked"
    assert main([
        str(riscv64_hook_image), str(RISCV64_XML), str(FIXTURES / "sample.rec"),
        "-o", str(output), "--cc", shlex.join(RISCV64_CC),
    ]) == 0
    assert output.stat().st_size == riscv64_hook_image.stat().st_size
    assert _run_riscv(output).splitlines() == [
        "min_int just got called",
        "original min_int=3 add=6 subtract=1",
        "typed result=2.5",
        "in hook: global_string=alobal string other_global_string=cook global string",
        "total=9835 factorial=720 first=1 last=9",
        "global_string=alobal string other_global_string=other global string",
    ]
    original, rewritten = Binary(riscv64_hook_image), Binary(output)
    entry = original.symbol_address("min_int")
    assert entry is not None
    assert rewritten.read(entry, 1) == b"\x6f"  # jal zero, hook


def test_recr_splits_riscv64_code_and_relinks_pcrel_pairs(
    riscv64_hook_image: Path, tmp_path: Path,
) -> None:
    library = tmp_path / "library.c"
    library.write_text("int bonus(int arg) { return arg + 5; }\n")
    obj = tmp_path / "library.o"
    archive = tmp_path / "libbonus.a"
    subprocess.run([*RISCV64_CC, "-Os", "-mno-relax", "-c", library, "-o", obj], check=True)
    subprocess.run(["ar", "rcs", archive, obj], check=True)
    source = tmp_path / "split.rec"
    source.write_text(r'''
        extern int bonus(int);
        int @min_int(int a, int b) {
            if (b) __asm__ volatile(".rept 280\n nop\n .endr");
            global_string[0] = 'b';
            return min_int(bonus(a), b);
        }
    ''')
    output = tmp_path / "split"
    receipt = tmp_path / "receipt.yaml"
    assert main([
        str(riscv64_hook_image), str(RISCV64_XML), str(source), "-o", str(output),
        "-r", str(receipt), "--cc", shlex.join(RISCV64_CC), "--", "-mcmodel=medany",
        str(archive),
    ]) == 0
    assert _run_riscv(output).splitlines() == [
        "total=9841 factorial=720 first=1 last=9",
        "global_string=blobal string other_global_string=other global string",
    ]
    modified = yaml.safe_load(receipt.read_text())["modified"]
    assert sum(region["address"] >= 0x80000 and region["length"] >= 100 for region in modified) >= 2


def test_recr_hooks_a_riscv32_elf_without_compressed_instructions(tmp_path: Path) -> None:
    assembly = tmp_path / "bare.S"
    assembly.write_text("""
        .text
        .option norvc
        .global _start, transform, spare
    _start:
        addi a0,zero,7
        jal ra,transform
        addi a7,zero,93
        ecall
        .size _start, .-_start
    transform:
        addi a0,a0,1
        addi a0,a0,2
        jalr zero,0(ra)
        .size transform, .-transform
    spare:
        .fill 31,4,0x00000013
        jalr zero,0(ra)
        .size spare, .-spare
    """)
    binary = tmp_path / "bare"
    subprocess.run([
        *RISCV64_CC, "-march=rv32i", "-mabi=ilp32", "-nostdlib", "-static", "-no-pie",
        "-Wl,--no-relax", assembly, "-o", binary,
    ], check=True)
    root = ET.Element("PROGRAM")
    ET.SubElement(root, "PROCESSOR", LANGUAGE_PROVIDER="RISCV:LE:32:default:gcc")
    functions = ET.SubElement(root, "FUNCTIONS")
    with binary.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        for name in ("_start", "transform", "spare"):
            symbol, = symbols.get_symbol_by_name(name)
            start = symbol["st_value"]
            function = ET.SubElement(functions, "FUNCTION", NAME=name, ENTRY_POINT=f"{start:x}")
            ET.SubElement(function, "ADDRESS_RANGE", START=f"{start:x}", END=f"{start + symbol['st_size'] - 1:x}")
            if name == "transform":
                ET.SubElement(function, "RETURN_TYPE", DATATYPE="int")
                ET.SubElement(function, "TYPEINFO_CMT").text = "int transform(int arg)"
    export = tmp_path / "bare.xml"
    ET.ElementTree(root).write(export)
    source = tmp_path / "hook.rec"
    source.write_text("int @transform(int arg) { return transform(arg) + 5; }\n")
    output = tmp_path / "hooked"
    assert main([
        str(binary), str(export), str(source), "-o", str(output),
        "--cc", shlex.join(RISCV64_CC),
    ]) == 0
    assert subprocess.run(_qemu_command(binary, 32)).returncode == 10
    assert subprocess.run(_qemu_command(output, 32)).returncode == 15
