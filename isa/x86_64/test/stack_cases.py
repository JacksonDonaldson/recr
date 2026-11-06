"""Generate NASM-backed expected encodings for stack-relative instruction forms."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from intel_cases import assemble, convert_form  # noqa: E402
from ir import InstructionType, StateSpaceKind  # noqa: E402
from isa.sleigher import X86Sleigher  # noqa: E402

# ``[rbx`` is the generator's placeholder for a memory operand.  Each variant
# rewrites the opening of that operand and leaves any existing index (for
# example the vector index of a VSIB gather) intact.  Only RSP-relative
# operands change: the outlining call pushes a return address and leaves RBP
# untouched.
VARIANTS = (
    ("rsp_disp8", "[rsp+0x10", "[rsp+0x18"),
    # Use an odd displacement so NASM cannot use EVEX disp8*N compression.
    ("rsp_disp32", "[rsp+0x111", "[rsp+0x119"),
    # A 32-bit address size adds a legacy 0x67 prefix before EVEX.
    ("esp_disp8", "[esp+0x40", "[esp+0x48"),
    ("esp_disp32", "[esp+0x111", "[esp+0x119"),
    ("rbp_disp8", "[rbp+0x10", "[rbp+0x10"),
    ("sib_disp8", "[rsp+rax*4+0x10", "[rsp+rax*4+0x18"),
    ("rbp_zero", "[rbp", "[rbp"),
    ("sib_zero", "[rbp+rax*4", "[rbp+rax*4"),
    ("rsp_zero", "[rsp", "[rsp+8"),
    ("sib_rsp_zero", "[rsp+rax*4", "[rsp+rax*4+8"),
)

# VSIB forms already have an index register, so adding a GPR index would be
# invalid.  The remaining variants exercise the same ModRM/SIB paths.
VSIB_EXCLUDED_VARIANTS = frozenset({"sib_disp8", "sib_zero", "sib_rsp_zero"})

# Instructions that change the stack pointer or control flow cannot be
# outlined even when their explicit memory operand can be biased.  The SLEIGH
# decoder classifies some traps and control transfers as ARITHMETIC, so list
# them explicitly rather than relying on InstructionType alone.
NON_OUTLINABLE_MNEMONICS = {
    "CALL",
    "ENTER",
    "GETSEC",
    "HLT",
    "INT",
    "INT1",
    "INT3",
    "INTO",
    "IRET",
    "JMP",
    "LEAVE",
    "POP",
    "PUSH",
    "RET",
    "RSM",
    "SKINIT",
    "STGI",
    "CLGI",
    "SYSCALL",
    "SYSENTER",
    "SYSEXIT",
    "SYSRET",
    "UD0",
    "UD1",
    "UD2",
    "UIRET",
    "VMCALL",
    "VMLAUNCH",
    "VMMCALL",
    "VMRESUME",
    "VMRUN",
    "VMXOFF",
    "XABORT",
    "XBEGIN",
}

_LEGACY_PREFIXES = {
    0x26,
    0x2E,
    0x36,
    0x3E,
    0x64,
    0x65,
    0x66,
    0x67,
    0xF0,
    0xF2,
    0xF3,
}

_SLEIGHER: X86Sleigher | None = None


def _sleigher() -> X86Sleigher:
    global _SLEIGHER
    if _SLEIGHER is None:
        _SLEIGHER = X86Sleigher()
    return _SLEIGHER


def _is_address_operand(operand, resolved) -> bool:
    name = operand.operand.name.lower()
    if name.startswith(("addr", "vaddr", "bndmk_addr")):
        return True
    return any(
        kind == "text" and value == "["
        for kind, value in resolved.constructor.print_pieces
    )


def _address_offsets(resolved) -> list[int]:
    offsets: list[int] = []
    for operand in resolved.operands:
        child = operand.resolved
        if child is None:
            continue
        if _is_address_operand(operand, child):
            offsets.append(operand.offset)
        offsets.extend(_address_offsets(child))
    return offsets


def _uses_rsp_as_value(data: bytes) -> bool:
    sleigher = _sleigher()
    resolved = sleigher.spec.resolve(data, sleigher.context)
    if resolved is None:
        return False

    def walk(constructor, in_address: bool) -> bool:
        for operand in constructor.operands:
            child = operand.resolved
            is_address = (
                child is not None and _is_address_operand(operand, child)
            )
            if child is not None:
                if walk(child, in_address or is_address):
                    return True
                continue
            if in_address:
                continue
            location = sleigher.spec._location_for_operand(
                operand, data, constructor.context
            )
            if location is None:
                continue
            state = sleigher.spec._state_space(
                (location.space_index, location.offset, location.size)
            )
            if (
                state is not None
                and state.kind is StateSpaceKind.REGISTER
                and state.name == "RSP"
            ):
                return True
        return False

    return walk(resolved, False)


def _displacement_size(data: bytes, offset: int) -> int | None:
    if offset >= len(data):
        return None
    modrm = data[offset]
    mod = modrm >> 6
    rm = modrm & 7
    if mod == 3:
        return None
    position = offset + 1
    if rm == 4:
        if position >= len(data):
            return None
        sib = data[position]
        position += 1
        base = sib & 7
        if mod == 0 and base == 5:
            return 4
    elif rm == 5 and mod == 0:
        return 4
    if mod == 0:
        return None
    return 1 if mod == 1 else 4


def _starts_with_evex(data: bytes) -> bool:
    for byte in data:
        if byte in _LEGACY_PREFIXES:
            continue
        return byte == 0x62
    return False


def _is_evex_disp8(data: bytes) -> bool:
    if not _starts_with_evex(data):
        return False
    sleigher = _sleigher()
    resolved = sleigher.spec.resolve(data, sleigher.context)
    if resolved is None:
        return False
    return any(
        _displacement_size(data, offset) == 1
        for offset in _address_offsets(resolved)
    )


def _non_outlinable_mnemonic(assembly: str) -> bool:
    mnemonic = assembly.split(None, 1)[0].upper()
    return (
        mnemonic in NON_OUTLINABLE_MNEMONICS
        or mnemonic.startswith("J")
        or mnemonic.startswith("LOOP")
    )


def _expected_outlinable(original: bytes, assembly: str) -> bool:
    if _non_outlinable_mnemonic(assembly):
        return False

    instruction = _sleigher().parse(original, 0)
    if instruction is None:
        return False
    if instruction.type in {
        InstructionType.CALL,
        InstructionType.CALL_INDIRECT,
        InstructionType.BRANCH,
        InstructionType.RET,
        InstructionType.OUTLINE_RESULT_CALL,
    }:
        return False
    if any(
        state.kind is StateSpaceKind.REGISTER and state.name == "RSP"
        for state in instruction.modifies
    ):
        return False
    return not _uses_rsp_as_value(original)


def _generate_case(
    form: str, assembly: str, variant: str, base: str, biased: str
) -> dict[str, object]:
    old_line = assembly.replace("[rbx", base)
    new_line = assembly.replace("[rbx", biased)
    original = assemble(old_line, 0)
    expected = assemble(new_line, 0)

    # NASM emits x87 wait forms as a standalone FWAIT (0x9b) followed by the
    # real instruction.  The stack-relative operand belongs to the latter.
    instruction_offset = (
        1
        if len(original) > 1
        and original[:1] == b"\x9b"
        and expected[:1] == b"\x9b"
        else 0
    )
    original_instruction = original[instruction_offset:]
    expected_instruction = expected[instruction_offset:]

    def case(
        *, adjustable: bool, outlinable: bool, reason: str
    ) -> dict[str, object]:
        return {
            "form": form,
            "variant": variant,
            "assembly": old_line,
            "original": original.hex(),
            "adjusted": expected.hex(),
            "instruction_offset": instruction_offset,
            "adjustable": adjustable,
            "outlinable": outlinable,
            "reason": reason,
        }

    if original_instruction == expected_instruction:
        # The variant does not bias this operand (RBP is callee-saved), so
        # EVEX disp8 compression cannot affect the result.
        if _uses_rsp_as_value(original_instruction):
            return case(
                adjustable=False, outlinable=False, reason="rsp_value_use"
            )
        outlinable = _expected_outlinable(original_instruction, assembly)
        return case(
            adjustable=True,
            outlinable=outlinable,
            reason="" if outlinable else "not_outlinable",
        )

    if len(original_instruction) != len(expected_instruction):
        return case(
            adjustable=False, outlinable=False, reason="length_changes"
        )

    if _is_evex_disp8(original_instruction):
        return case(
            adjustable=False, outlinable=False, reason="evex_compressed"
        )

    if _uses_rsp_as_value(original_instruction):
        return case(
            adjustable=False, outlinable=False, reason="rsp_value_use"
        )

    outlinable = _expected_outlinable(original_instruction, assembly)
    return case(
        adjustable=True,
        outlinable=outlinable,
        reason="" if outlinable else "not_outlinable",
    )


def _variants_for(assembly: str) -> tuple[tuple[str, str, str], ...]:
    """Return the variants that can be applied to one memory form."""
    if "[rbx+" not in assembly:
        return VARIANTS
    return tuple(
        variant for variant in VARIANTS if variant[0] not in VSIB_EXCLUDED_VARIANTS
    )


def generate(forms_path: Path, output_path: Path, jobs: int = 8) -> None:
    forms = [
        line.strip()
        for line in forms_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    memory_forms: list[tuple[str, str]] = []
    for form in forms:
        assembly = convert_form(form)
        if assembly is not None and "[rbx" in assembly:
            memory_forms.append((form, assembly))

    tasks = [
        (form, assembly, variant, base, biased)
        for form, assembly in memory_forms
        for variant, base, biased in _variants_for(assembly)
    ]
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        cases = list(executor.map(lambda task: _generate_case(*task), tasks))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {
                "source": forms_path.name,
                "memory_forms": len(memory_forms),
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
