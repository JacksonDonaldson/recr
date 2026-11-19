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


def test_recr_hooks_a_riscv64_variadic_method(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "app.c"
    source.write_text("""
        #include <stdarg.h>
        struct main_app { int base; };
        __attribute__((noipa))
        int AppVprintf(struct main_app *self, char *format, ...) {
            va_list args;
            va_start(args, format);
            int total = self->base + *format;
            for (int i = 1; i <= 8; i++)
                total += i * va_arg(args, int);
            va_end(args);
            return total;
        }
        void _start(void) {
            struct main_app app = {3};
            char format[] = {7, 0};
            register long result asm("a0") = AppVprintf(&app, format, 1, 2, 3, 4, 5, 6, 7, 8);
            register long syscall asm("a7") = 93;
            asm volatile("ecall" : : "r"(result), "r"(syscall) : "memory");
            __builtin_unreachable();
        }
    """, encoding="utf-8")
    binary = tmp_path / "app"
    subprocess.run([
        *RISCV64_CC, "-march=rv64gc", "-mabi=lp64d", "-Os", "-fno-pie", "-no-pie",
        "-fno-stack-protector", "-ffreestanding", "-nostdlib", "-static",
        "-Wl,--no-relax,--section-start=.recr_space=0x80000", source,
        FIXTURES / "recr_space_riscv64.S", "-o", binary,
    ], check=True, capture_output=True)
    root = ET.Element("PROGRAM")
    ET.SubElement(root, "PROCESSOR", LANGUAGE_PROVIDER="RISCV:LE:64:default:gcc")
    ET.SubElement(ET.SubElement(root, "DATATYPES"), "STRUCTURE", NAME="main_app", NAMESPACE="/", SIZE="0x4")
    functions = ET.SubElement(root, "FUNCTIONS")
    with binary.open("rb") as stream:
        symbols = ELFFile(stream).get_section_by_name(".symtab")
        for symbol in symbols.iter_symbols():
            name = symbol.name
            if name not in ("_start", "AppVprintf") and not name.startswith("recr_spare_"):
                continue
            start = symbol["st_value"]
            qualified = "main_app::AppVprintf" if name == "AppVprintf" else name
            function = ET.SubElement(functions, "FUNCTION", NAME=qualified, ENTRY_POINT=f"ram:{start:x}")
            if name == "AppVprintf":
                ET.SubElement(function, "RETURN_TYPE", DATATYPE="int")
            ET.SubElement(function, "ADDRESS_RANGE", START=f"ram:{start:x}", END=f"ram:{start + symbol['st_size'] - 1:x}")
            if name == "AppVprintf":
                ET.SubElement(function, "TYPEINFO_CMT").text = "int __thiscall AppVprintf(char * format, ...)"
                receiver = ET.SubElement(function, "REGISTER_VAR", NAME="this", REGISTER="a1",
                                         DATATYPE="main_app *", DATATYPE_NAMESPACE="/")
                ET.SubElement(function, "REGISTER_VAR", NAME="format", REGISTER="a1", DATATYPE="char *")
    export, hook = tmp_path / "app.xml", tmp_path / "hook.re.c"
    hook.write_text("""
        #include <stdarg.h>
        int @AppVprintf(struct main_app *self, char *format, ...) {
            va_list args;
            va_start(args, format);
            int values[8];
            for (int i = 0; i < 8; i++)
                values[i] = va_arg(args, int);
            va_end(args);
            return AppVprintf(self, format, values[0], values[1], values[2], values[3],
                              values[4], values[5], values[6], values[7]) + 5;
        }
    """, encoding="utf-8")
    output, receipt = tmp_path / "hooked", tmp_path / "receipt"
    output.write_bytes(b"previous binary")
    receipt.write_bytes(b"previous receipt")
    command = [str(binary), str(export), str(hook), "-o", str(output), "-r", str(receipt),
               "--cc", shlex.join(RISCV64_CC)]

    ET.ElementTree(root).write(export)
    assert main(command) == 1
    assert "no usable prototype for 'main_app::AppVprintf'" in capsys.readouterr().err
    assert output.read_bytes() == b"previous binary"
    assert receipt.read_bytes() == b"previous receipt"

    receiver.set("REGISTER", "a0")
    ET.ElementTree(root).write(export)
    assert main(command) == 0
    assert subprocess.run(_qemu_command(binary, 64)).returncode == 214
    assert subprocess.run(_qemu_command(output, 64)).returncode == 219


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
