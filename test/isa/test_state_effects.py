"""Hand-authored state-effect coverage for instruction categories."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from ir import Address, StateSpaceKind
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
        {FLAGS, reg("RAX"), reg("RBX")},
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


CALLEE_SAVED = {"RBX", "RBP", "R12", "R13", "R14", "R15"}
CALL_ARGUMENTS = {
    "RAX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "RSP",
    *(f"ZMM{index}" for index in range(8)),
}


def _state_keys(states) -> set[tuple[StateSpaceKind, str]]:
    return {(state.kind, state.name) for state in states}


def _non_callee_saved_states(
    sleigher: X86Sleigher,
) -> set[tuple[StateSpaceKind, str]]:
    return {
        (state.kind, state.name)
        for state in sleigher.spec.all_state_spaces()
        if not (
            state.kind is StateSpaceKind.REGISTER
            and state.name in CALLEE_SAVED
        )
    }


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
    assert decoded.flows_from == [], instruction
    assert decoded.flows_to == [Address.absolute(decoded.length)], instruction


ADDRESS_SENSITIVE_ENCODINGS = [
    ("rip-relative load", "8b0510000000"),
    ("rip-relative store", "890510000000"),
    ("direct call", "e810000000"),
    ("push rbp", "55"),
    ("rsp-relative load", "8b442408"),
    ("sse rip-relative load", "f30f100540000000"),
    ("ret", "c3"),
]


@pytest.mark.parametrize(
    "name,encoded",
    ADDRESS_SENSITIVE_ENCODINGS,
    ids=[case[0] for case in ADDRESS_SENSITIVE_ENCODINGS],
)
def test_state_effects_are_address_independent(
    name: str, encoded: str, sleigher: X86Sleigher
) -> None:
    data = bytes.fromhex(encoded)

    low = sleigher.parse(data, address=0x1000)
    high = sleigher.parse(data, address=0x7FFF00000000)

    assert low is not None and high is not None, name
    assert low.length == high.length, name
    assert low.type is high.type, name
    assert low.modifies == high.modifies, name
    assert low.depends_on == high.depends_on, name


def test_repeated_decode_returns_independent_state_lists(
    sleigher: X86Sleigher,
) -> None:
    data = bytes.fromhex("488b442408")

    first = sleigher.parse(data, address=0x1000)
    second = sleigher.parse(data, address=0x2000)

    assert first is not None and second is not None
    assert first.modifies == second.modifies
    assert first.depends_on == second.depends_on

    first.modifies.append(first.depends_on[0])
    first.depends_on.clear()
    assert first.modifies != second.modifies
    assert second.depends_on != []


@pytest.mark.parametrize(
    "instruction",
    ["call 0x1234", "call rax", "ret", "jmp rax"],
)
def test_unknown_transfer_clobbers_non_callee_saved_state(
    instruction: str,
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))
    assert decoded is not None, instruction

    expected = _non_callee_saved_states(sleigher)
    assert _state_keys(decoded.modifies) == expected, instruction
    assert {
        (state.kind, state.name) for state in decoded.modifies
    } & {(StateSpaceKind.REGISTER, name) for name in CALLEE_SAVED} == set()
    assert (StateSpaceKind.REGISTER, "RSP") in expected
    assert (StateSpaceKind.REGISTER, "RIP") in expected
    assert FLAGS in expected
    assert RAM in expected


@pytest.mark.parametrize(
    "instruction", ["int 0x80", "int3", "hlt", "ud2"]
)
def test_trap_clobbers_and_depends_on_all_state(
    instruction: str,
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))
    assert decoded is not None, instruction

    expected = {
        (state.kind, state.name)
        for state in sleigher.spec.all_state_spaces()
    }
    assert _state_keys(decoded.modifies) == expected, instruction
    assert _state_keys(decoded.depends_on) == expected, instruction


def test_direct_branch_does_not_clobber_state(
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble("jmp 0x1234", tmp_path))
    assert decoded is not None

    assert decoded.modifies == []
    assert decoded.depends_on == []


@pytest.mark.parametrize("instruction", ["call 0x1234", "call rax"])
def test_call_depends_on_potential_arguments(
    instruction: str,
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))
    assert decoded is not None, instruction

    expected = {
        (StateSpaceKind.REGISTER, name) for name in CALL_ARGUMENTS
    } | {RAM}
    assert _state_keys(decoded.depends_on) == expected, instruction


def test_return_keeps_precise_dependencies(
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble("ret", tmp_path))
    assert decoded is not None

    assert _state_keys(decoded.depends_on) == {
        RAM,
        (StateSpaceKind.REGISTER, "RIP"),
        (StateSpaceKind.REGISTER, "RSP"),
    }
