"""Data-driven coverage for a broad set of x86-64 opcodes."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from ir import InstructionType, StateSpaceKind
from isa.sleigher import X86Sleigher

NEW_BASE = 0x500000

FLAGS = (StateSpaceKind.FLAG, "flags")
RAM = (StateSpaceKind.MEMORY, "ram")


def reg(name: str) -> tuple[StateSpaceKind, str]:
    return StateSpaceKind.REGISTER, name


# name, encoded length, instruction type, modified states, source states
CASES: list[
    tuple[str, int, InstructionType, set[tuple[StateSpaceKind, str]], set[tuple[StateSpaceKind, str]]]
] = [
    ('add eax, 0x20', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX")}),
    ('add rax, rbx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('sub ecx, edx', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RCX")}, {reg("RCX"), reg("RDX")}),
    ('imul eax, ebx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {FLAGS, reg("RAX"), reg("RBX")}),
    ('inc eax', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX")}),
    ('dec rcx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RCX")}, {reg("RCX")}),
    ('neg rdx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RDX")}, {reg("RDX")}),
    ('not rsi', 3, InstructionType.ARITHMETIC, {reg("RSI")}, {reg("RSI")}),
    ('xor eax, eax', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX")}),
    ('and eax, ebx', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('or eax, ebx', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('shl eax, 1', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {FLAGS, reg("RAX")}),
    ('shr ebx, cl', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RBX")}, {FLAGS, reg("RBX"), reg("RCX")}),
    ('sar rdx, 2', 4, InstructionType.ARITHMETIC, {FLAGS, reg("RDX")}, {FLAGS, reg("RDX")}),
    ('rol eax, 3', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {FLAGS, reg("RAX")}),
    ('ror rbx, 4', 4, InstructionType.ARITHMETIC, {FLAGS, reg("RBX")}, {FLAGS, reg("RBX")}),
    ('mul ecx', 2, InstructionType.ARITHMETIC, {FLAGS, reg("RAX"), reg("RDX")}, {FLAGS, reg("RAX"), reg("RCX"), reg("RDX")}),
    ('div ecx', 2, InstructionType.ARITHMETIC, {reg("RAX"), reg("RDX")}, {reg("RAX"), reg("RCX"), reg("RDX")}),
    ('idiv ecx', 2, InstructionType.ARITHMETIC, {reg("RAX"), reg("RDX")}, {reg("RAX"), reg("RCX"), reg("RDX")}),
    ('cmp eax, ebx', 2, InstructionType.ARITHMETIC, {FLAGS}, {reg("RAX"), reg("RBX")}),
    ('test eax, eax', 2, InstructionType.ARITHMETIC, {FLAGS}, {reg("RAX")}),
    ('mov eax, ebx', 2, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('mov rax, 0x1122334455667788', 10, InstructionType.ARITHMETIC, {reg("RAX")}, set()),
    ('movzx eax, bh', 3, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('movsx rax, byte [rdi]', 4, InstructionType.ARITHMETIC, {reg("RAX")}, {RAM, reg("RDI")}),
    ('movsxd rax, ecx', 3, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RCX")}),
    ('lea rax, [rdi+8]', 4, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RDI")}),
    ('push rbp', 1, InstructionType.ARITHMETIC, {RAM, reg("RSP")}, {reg("RBP"), reg("RSP")}),
    ('pop rbp', 1, InstructionType.ARITHMETIC, {reg("RBP"), reg("RSP")}, {RAM, reg("RSP")}),
    ('leave', 1, InstructionType.ARITHMETIC, {reg("RBP"), reg("RSP")}, {RAM, reg("RBP"), reg("RSP")}),
    ('mov rsp, rbp', 3, InstructionType.ARITHMETIC, {reg("RSP")}, {reg("RBP")}),
    ('add rsp, 8', 4, InstructionType.ARITHMETIC, {FLAGS, reg("RSP")}, {reg("RSP")}),
    ('ret', 1, InstructionType.RET, {reg("RIP"), reg("RSP")}, {RAM, reg("RIP"), reg("RSP")}),
    ('call 0x401000', 5, InstructionType.CALL, {RAM, reg("RSP")}, {reg("RSP")}),
    ('jmp 0x401000', 5, InstructionType.BRANCH, set(), set()),
    ('je 0x401000', 6, InstructionType.BRANCH, set(), {FLAGS}),
    ('nop', 1, InstructionType.NOP, set(), set()),
    ('bswap eax', 2, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RAX")}),
    ('popcnt eax, ebx', 4, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('lzcnt eax, ebx', 4, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ('clc', 1, InstructionType.ARITHMETIC, {FLAGS}, set()),
    ('stc', 1, InstructionType.ARITHMETIC, {FLAGS}, set()),
    ('cld', 1, InstructionType.ARITHMETIC, {FLAGS}, set()),
    ('std', 1, InstructionType.ARITHMETIC, {FLAGS}, set()),
    ('cmc', 1, InstructionType.ARITHMETIC, {FLAGS}, {FLAGS}),
    ('lahf', 1, InstructionType.ARITHMETIC, {reg("RAX")}, {FLAGS}),
    ('sahf', 1, InstructionType.ARITHMETIC, {FLAGS}, {reg("RAX")}),
    ('cdq', 1, InstructionType.ARITHMETIC, {reg("RDX")}, {reg("RAX"), reg("RDX")}),
    ('cqo', 2, InstructionType.ARITHMETIC, {reg("RDX")}, {reg("RAX")}),
    ('cwde', 1, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RAX")}),
    ('cdqe', 2, InstructionType.ARITHMETIC, {reg("RAX")}, {reg("RAX")}),
    ('xchg eax, ebx', 1, InstructionType.ARITHMETIC, {reg("RAX"), reg("RBX")}, {reg("RAX"), reg("RBX")}),
    ('bt eax, ebx', 3, InstructionType.ARITHMETIC, {FLAGS}, {reg("RAX"), reg("RBX")}),
    ('mov [rbx], eax', 2, InstructionType.ARITHMETIC, {RAM}, {reg("RAX"), reg("RBX")}),
    ('mov r9, rdx', 3, InstructionType.ARITHMETIC, {reg("R9")}, {reg("RDX")}),
    ('bsf eax, ebx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {FLAGS, reg("RAX"), reg("RBX")}),
    ('bsr eax, ebx', 3, InstructionType.ARITHMETIC, {FLAGS, reg("RAX")}, {FLAGS, reg("RAX"), reg("RBX")}),
    ('int3', 1, InstructionType.ARITHMETIC, set(), set()),
]

_OFFSETS: list[int] = []
_offset = 0
for _case in CASES:
    _OFFSETS.append(_offset)
    _offset += _case[1]


def _assemble_at(name: str, origin: int, tmp_path: Path) -> bytes:
    source = tmp_path / "instruction.s"
    output = tmp_path / "instruction.bin"
    source.write_text(f"bits 64\norg {origin:#x}\n{name}\n", encoding="utf-8")

    result = subprocess.run(
        ["nasm", "-f", "bin", str(source), "-o", str(output)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"NASM failed for {name!r}: {result.stderr}")

    return output.read_bytes()


@pytest.mark.parametrize(
    "offset,case",
    list(zip(_OFFSETS, CASES)),
    ids=[case[0] for case in CASES],
)
def test_opcode(
    offset: int,
    case: tuple[
        str,
        int,
        InstructionType,
        set[tuple[StateSpaceKind, str]],
        set[tuple[StateSpaceKind, str]],
    ],
    opcodes_binary: Path,
    sleigher: X86Sleigher,
) -> None:
    name, length, instruction_type, expected_modifies, expected_sources = case
    data = opcodes_binary.read_bytes()
    instruction = sleigher.parse(data[offset:], address=offset)

    assert instruction is not None, name
    assert instruction.length == length, name
    assert instruction.original_data == data[offset : offset + length], name
    assert instruction.type is instruction_type, name
    assert {
        (state.kind, state.name) for state in instruction.modifies
    } == expected_modifies, name
    assert {
        (state.kind, state.name) for state in instruction.depends_on
    } == expected_sources, name


@pytest.mark.parametrize(
    "offset,case",
    list(zip(_OFFSETS, CASES)),
    ids=[case[0] for case in CASES],
)
def test_reassemble_matches_nasm_at_new_base(
    offset: int,
    case: tuple[
        str,
        int,
        InstructionType,
        set[tuple[StateSpaceKind, str]],
        set[tuple[StateSpaceKind, str]],
    ],
    opcodes_binary: Path,
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    name, length, instruction_type, expected_modifies, _ = case
    data = opcodes_binary.read_bytes()
    instruction = sleigher.parse(data[offset:], address=offset)
    assert instruction is not None, name

    new_address = NEW_BASE + offset
    relocated = sleigher.reassemble(instruction, new_address)

    assert relocated is not None, name
    assert relocated.address == new_address, name
    assert relocated.length == length, name
    assert relocated.modifies == instruction.modifies, name

    expected = _assemble_at(name, new_address, tmp_path)
    assert len(expected) == length, name
    assert relocated.original_data == expected, name

    if instruction_type in (InstructionType.BRANCH, InstructionType.CALL):
        assert relocated.original_data != instruction.original_data, name


def test_opcode_fixture_size(opcodes_binary: Path) -> None:
    assert opcodes_binary.stat().st_size == sum(case[1] for case in CASES)
