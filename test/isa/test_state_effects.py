"""Hand-authored state-effect coverage for instruction categories."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from ir import StateSpaceKind
from isa.sleigher import X86Sleigher


FLAGS = (StateSpaceKind.FLAG, "flags")
RAM = (StateSpaceKind.MEMORY, "ram")


def reg(name: str) -> tuple[StateSpaceKind, str]:
    return StateSpaceKind.REGISTER, name


def st_range(*indices: int) -> set[tuple[StateSpaceKind, str]]:
    return {reg(f"ST{index}") for index in indices}


# name, modified states, source states
CASES: list[
    tuple[
        str,
        set[tuple[StateSpaceKind, str]],
        set[tuple[StateSpaceKind, str]],
    ]
] = [
    # Partial GPR writes canonicalize to the 64-bit parent.
    ("mov al, 1", {reg("RAX")}, set()),
    ("mov ah, 1", {reg("RAX")}, set()),
    ("mov ax, 1", {reg("RAX")}, set()),
    ("add al, bl", {FLAGS, reg("RAX")}, {reg("RAX"), reg("RBX")}),
    ("inc ah", {FLAGS, reg("RAX")}, {reg("RAX")}),
    ("movzx eax, bh", {reg("RAX")}, {reg("RAX"), reg("RBX")}),
    # Vector registers canonicalize to their ZMM parent.
    ("addsd xmm0, xmm1", {reg("ZMM0")}, {reg("ZMM0"), reg("ZMM1")}),
    ("mulss xmm2, xmm3", {reg("ZMM2")}, {reg("ZMM2"), reg("ZMM3")}),
    ("movdqa xmm0, xmm1", {reg("ZMM0")}, {reg("ZMM1")}),
    ("vaddsd xmm0, xmm1, xmm2", {reg("ZMM0")}, {reg("ZMM1"), reg("ZMM2")}),
    (
        "vaddps ymm0, ymm1, ymm2",
        {reg("ZMM0")},
        {reg("ZMM0"), reg("ZMM1"), reg("ZMM2")},
    ),
    ("pxor mm0, mm1", {reg("MM0")}, {reg("MM0"), reg("MM1")}),
    # x87 state.
    ("fld st0", st_range(0, 1, 2, 3, 4, 5, 6, 7), st_range(0, 1, 2, 3, 4, 5, 6)),
    (
        "fadd st0, st1",
        {reg("FPUInstructionPointer"), reg("ST0")},
        {reg("ST0"), reg("ST1")},
    ),
    (
        "fstp st0",
        {reg("FPUInstructionPointer"), *st_range(0, 1, 2, 3, 4, 5, 6)},
        st_range(0, 1, 2, 3, 4, 5, 6, 7),
    ),
    # Memory addressing and segment state.
    (
        "mov rax, [rbx+rcx*4+8]",
        {reg("RAX")},
        {RAM, reg("RBX"), reg("RCX")},
    ),
    (
        "mov [rbx+rcx*4+8], rax",
        {RAM},
        {reg("RAX"), reg("RBX"), reg("RCX")},
    ),
    (
        "mov rax, fs:[0x10]",
        {reg("RAX")},
        {RAM, reg("FS"), reg("FS_OFFSET")},
    ),
    # Flags and conditional operations.
    ("pushfq", {FLAGS, RAM, reg("RSP")}, {FLAGS, reg("RSP")}),
    ("popfq", {FLAGS, reg("RSP")}, {FLAGS, RAM, reg("RSP")}),
    (
        "cmovz eax, ebx",
        {reg("RAX")},
        {FLAGS, RAM, reg("RAX"), reg("RBX")},
    ),
    ("setz al", {reg("RAX")}, {FLAGS}),
    # Mask registers, fences, and upper-lane zeroing.
    ("kmovw k1, eax", {reg("K1")}, {reg("RAX")}),
    ("mfence", set(), set()),
    ("vzeroupper", {reg(f"ZMM{index}") for index in range(16)}, set()),
    (
        "movsx rax, byte [rdi]",
        {reg("RAX")},
        {RAM, reg("RDI")},
    ),
]


def _assemble(instruction: str, tmp_path: Path) -> bytes:
    source = tmp_path / "state.s"
    output = tmp_path / "state.bin"
    source.write_text(f"bits 64\norg 0\n{instruction}\n", encoding="utf-8")

    result = subprocess.run(
        ["nasm", "-f", "bin", str(source), "-o", str(output)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"NASM failed for {instruction!r}: {result.stderr}")

    return output.read_bytes()


@pytest.mark.parametrize(
    "instruction,expected_modifies,expected_sources",
    CASES,
    ids=[case[0] for case in CASES],
)
def test_state_effects(
    instruction: str,
    expected_modifies: set[tuple[StateSpaceKind, str]],
    expected_sources: set[tuple[StateSpaceKind, str]],
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))

    assert decoded is not None, instruction
    assert {
        (state.kind, state.name) for state in decoded.modifies
    } == expected_modifies, instruction
    assert {
        (state.kind, state.name) for state in decoded.depends_on
    } == expected_sources, instruction
