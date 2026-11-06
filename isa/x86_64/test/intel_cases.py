"""Generate NASM-backed expected encodings for the Intel 64-bit form corpus."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import subprocess
import tempfile

OLD_ORIGIN = 0
NEW_ORIGIN = 0x20

_SIZE = {
    8: "byte",
    16: "word",
    32: "dword",
    64: "qword",
    80: "tword",
    128: "oword",
    256: "yword",
    512: "zword",
}

_BASE = {
    "r/m8": "al",
    "r/m16": "ax",
    "r/m32": "eax",
    "r/m64": "rax",
    "r/m": "rax",
    "r8": "al",
    "r16": "ax",
    "r32": "eax",
    "r64": "rax",
    "r32a": "eax",
    "r32b": "ecx",
    "r64a": "rax",
    "r64b": "rcx",
    "reg": "eax",
    "reg/m8": "al",
    "reg/m16": "ax",
    "reg/m32": "eax",
    "reg/m64": "rax",
    "r32/m16": "eax",
    "r64/m16": "rax",
    "r64/m32": "eax",
    "rm8": "al",
    "rm16": "ax",
    "rm32": "eax",
    "rm64": "rax",
    "m8": "byte [rbx]",
    "m16": "word [rbx]",
    "m32": "dword [rbx]",
    "m64": "qword [rbx]",
    "m128": "oword [rbx]",
    "m256": "yword [rbx]",
    "m512": "zword [rbx]",
    "m": "[rbx]",
    "mem": "[rbx]",
    "imm8": "1",
    "imm16": "1",
    "imm32": "1",
    "imm64": "1",
    "imm8/16/32": "1",
    "imm8/16/32/64": "1",
    "iw": "1",
    "id": "1",
    "ib": "1",
    "1": "1",
    "3": "3",
    "0": "0",
    "rel8": "0x40",
    "rel16": "0x1000",
    "rel32": "0x401000",
    "xmm": "xmm1",
    "ymm": "ymm1",
    "zmm": "zmm1",
    "mm": "mm1",
    "k": "k1",
    "tmm": "tmm1",
    "st(i)": "st1",
    "ST(i)": "st1",
    "st": "st0",
    "ST": "st0",
    "ST(0)": "st0",
    "Sreg": "ds",
    "sreg": "ds",
    "CR": "cr0",
    "DR": "dr0",
    "bnd": "bnd1",
    "CR0-CR7": "cr0",
    "CR8": "cr8",
    "DR0-DR7": "dr0",
    "moffs8": "byte [0x404020]",
    "moffs16": "word [0x404020]",
    "moffs32": "dword [0x404020]",
    "moffs64": "qword [0x404020]",
    "Moffs": "qword [0x404020]",
    "AL/AX/EAX/RAX": "rax",
    "RDX/EDX": "rdx",
    "XMM0": "xmm0",
    "<XMM0>": "xmm0",
    "CL": "cl",
    "AL": "al",
    "AX": "ax",
    "EAX": "eax",
    "RAX": "rax",
    "DX": "dx",
    "FS": "fs",
    "GS": "gs",
    "SS": "ss",
    "DS": "ds",
    "ES": "es",
    "vm32x": "[rbx+xmm2*4]",
    "vm32y": "[rbx+ymm2*4]",
    "vm32z": "[rbx+zmm2*4]",
    "vm64x": "[rbx+xmm2*8]",
    "vm64y": "[rbx+ymm2*8]",
    "vm64z": "[rbx+zmm2*8]",
}

_STRING_OPS = {
    "CMPS": {"m8": "CMPSB", "m16": "CMPSW", "m32": "CMPSD", "m64": "CMPSQ"},
    "MOVS": {"m8": "MOVSB", "m16": "MOVSW", "m32": "MOVSD", "m64": "MOVSQ"},
    "LODS": {"m8": "LODSB", "m16": "LODSW", "m32": "LODSD", "m64": "LODSQ"},
    "STOS": {"m8": "STOSB", "m16": "STOSW", "m32": "STOSD", "m64": "STOSQ"},
    "SCAS": {"m8": "SCASB", "m16": "SCASW", "m32": "SCASD", "m64": "SCASQ"},
    "INS": {"m8": "INSB", "m16": "INSW", "m32": "INSD"},
    "OUTS": {"m8": "OUTSB", "m16": "OUTSW", "m32": "OUTSD"},
}


def _operand(text: str) -> str | None:
    value = text.strip()
    if value.startswith("["):
        return value
    if value in _BASE:
        return _BASE[value]

    value = re.sub(r"\{[^}]*\}", "", value).strip()
    value = re.sub(r"\s*\([^)]*\)", "", value).strip()
    if value in _BASE:
        return _BASE[value]

    if "/" in value:
        value = value.split("/", 1)[0].strip()

    if re.match(r"^m\d+/\d+byte$", value):
        return "[rbx]"

    value = value.replace(" ", "")
    if value in _BASE:
        return _BASE[value]
    if re.match(r"^(xmm|ymm|zmm|mm|k|bnd|tmm)\d+$", value.lower()):
        return value.lower()
    if re.match(
        r"^(r(ax|bx|cx|dx|si|di|sp|bp)|e(ax|bx|cx|dx|si|di|sp|bp)|"
        r"[abcd][lh]|[sd]il|[sb]pl|r(8|9|1[0-5])(d|w|b)?)$",
        value.lower(),
    ):
        return value.lower()

    match = re.match(r"^m(\d+)(fp|int|bcd|dec|real)?$", value)
    if match:
        size = _SIZE.get(int(match.group(1)))
        return f"{size} [rbx]" if size else "[rbx]"
    if value.startswith("m"):
        return "[rbx]"
    if value.lower() in (
        "al",
        "ax",
        "eax",
        "rax",
        "cl",
        "dx",
        "rdx",
        "1",
        "3",
        "0",
        "st0",
        "st1",
        "st2",
        "st3",
        "st4",
        "st5",
        "st6",
        "st7",
    ):
        return value.lower()
    if value.startswith("imm"):
        return "1"
    if value.startswith("rel"):
        return "0x401000"
    if re.match(r"^\d+$", value):
        return value
    return None


def convert_form(form: str) -> str | None:
    """Convert one Intel-syntax form into an assemblable NASM line."""
    parts = form.split(None, 1)
    mnemonic = parts[0].upper()
    rest = parts[1] if len(parts) > 1 else ""

    if mnemonic == "LOCK":
        return "LOCK ADD byte [rbx], 1"
    if mnemonic == "XACQUIRE":
        return "XACQUIRE LOCK ADD byte [rbx], 1"
    if mnemonic == "XRELEASE":
        return "XRELEASE LOCK ADD byte [rbx], 1"
    if mnemonic == "UD0":
        return "UD0 eax, [rbx]"
    if not rest:
        return mnemonic

    operands: list[str] = []
    current = ""
    depth = 0
    for char in rest:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            operands.append(current)
            current = ""
        else:
            current += char
    operands.append(current)
    stripped = [operand.strip() for operand in operands]

    if mnemonic in _STRING_OPS:
        sizes = [op for op in stripped if re.match(r"^m(8|16|32|64)$", op)]
        if sizes and sizes[0] in _STRING_OPS[mnemonic]:
            return _STRING_OPS[mnemonic][sizes[0]]
    if mnemonic == "XLAT":
        return "XLATB"
    if mnemonic in ("PEXTRB", "VPEXTRB") and stripped:
        stripped[0] = "eax"
    if mnemonic in ("PEXTRW", "VPEXTRW") and stripped:
        stripped[0] = "eax"
    if mnemonic in (
        "CLFLUSH",
        "CLFLUSHOPT",
        "CLWB",
        "PREFETCHW",
        "INVLPG",
        "BNDMK",
        "BNDMOV",
        "FLDENV",
        "FRSTOR",
        "FSAVE",
        "FNSAVE",
        "FSTENV",
        "FNSTENV",
    ):
        if stripped and (
            stripped[-1].startswith("m") or stripped[-1].startswith("mem")
        ):
            stripped[-1] = "[rbx]"

    converted = []
    for operand in stripped:
        value = _operand(operand)
        if value is None:
            return None
        converted.append(value)
    return mnemonic + " " + ", ".join(converted)


def assemble(line: str, origin: int) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "case.s"
        output = Path(directory) / "case.bin"
        source.write_text(f"bits 64\norg {origin:#x}\n{line}\n", encoding="utf-8")
        result = subprocess.run(
            ["nasm", "-f", "bin", str(source), "-o", str(output)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"NASM failed for {line!r}: {result.stderr}")
        return output.read_bytes()


def _generate_case(form: str) -> dict[str, str]:
    assembly = convert_form(form)
    if assembly is None:
        raise RuntimeError(f"could not convert {form!r}")
    old = assemble(assembly, OLD_ORIGIN)
    new = assemble(assembly, NEW_ORIGIN)
    return {
        "form": form,
        "assembly": assembly,
        "old": old.hex(),
        "new": new.hex(),
    }


def generate(forms_path: Path, output_path: Path, jobs: int = 8) -> None:
    forms = [
        line.strip()
        for line in forms_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        cases = list(executor.map(_generate_case, forms))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "source": forms_path.name,
                "old_origin": OLD_ORIGIN,
                "new_origin": NEW_ORIGIN,
                "cases": cases,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("forms", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    generate(args.forms, args.output, args.jobs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
