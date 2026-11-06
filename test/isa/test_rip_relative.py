"""RIP-relative decoding and relocation tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from ir import StateSpaceKind
from isa.sleigher import X86Sleigher


FLAGS = (StateSpaceKind.FLAG, "flags")
RAM = (StateSpaceKind.MEMORY, "ram")


def reg(name: str) -> tuple[StateSpaceKind, str]:
    return StateSpaceKind.REGISTER, name


@dataclass(frozen=True)
class RipCase:
    name: str
    original: bytes
    original_address: int
    relocated_address: int
    relocated: bytes
    modifies: frozenset[tuple[StateSpaceKind, str]]
    depends_on: frozenset[tuple[StateSpaceKind, str]]


CASES = [
    RipCase(
        "mov eax, [rip+0x10]",
        bytes.fromhex("8b0510000000"),
        0x1000,
        0x2000,
        bytes.fromhex("8b0510f0ffff"),
        frozenset({reg("RAX")}),
        frozenset({RAM, reg("RAX")}),
    ),
    RipCase(
        "lea rax, [rip+0x20]",
        bytes.fromhex("488d0520000000"),
        0x1000,
        0x3000,
        bytes.fromhex("488d0520e0ffff"),
        frozenset({reg("RAX")}),
        frozenset(),
    ),
    RipCase(
        "cmp byte [rip+0x30], 0",
        bytes.fromhex("803d3000000000"),
        0x1000,
        0x4000,
        bytes.fromhex("803d30d0ffff00"),
        frozenset({FLAGS}),
        frozenset({RAM}),
    ),
    RipCase(
        "movss xmm0, [rip+0x40]",
        bytes.fromhex("f30f100540000000"),
        0x1000,
        0x5000,
        bytes.fromhex("f30f100540c0ffff"),
        frozenset({reg("ZMM0")}),
        frozenset({RAM}),
    ),
    RipCase(
        "call qword [rip+0x50]",
        bytes.fromhex("ff1550000000"),
        0x1000,
        0x6000,
        bytes.fromhex("ff1550b0ffff"),
        frozenset({RAM, reg("RSP")}),
        frozenset({RAM, reg("RSP")}),
    ),
    RipCase(
        "jmp qword [rip+0x60]",
        bytes.fromhex("ff2560000000"),
        0x1000,
        0x7000,
        bytes.fromhex("ff2560a0ffff"),
        frozenset(),
        frozenset({RAM}),
    ),
    RipCase(
        "add dword [rip+0x70], eax",
        bytes.fromhex("010570000000"),
        0x1000,
        0x8000,
        bytes.fromhex("01057090ffff"),
        frozenset({FLAGS, RAM}),
        frozenset({RAM, reg("RAX")}),
    ),
    RipCase(
        "mov qword [rip+0x80], rax",
        bytes.fromhex("48890580000000"),
        0x1000,
        0x9000,
        bytes.fromhex("4889058080ffff"),
        frozenset({RAM}),
        frozenset({reg("RAX")}),
    ),
    RipCase(
        "mov rax, [rip-0x10]",
        bytes.fromhex("488b05f0ffffff"),
        0x1000,
        0xA000,
        bytes.fromhex("488b05f06fffff"),
        frozenset({reg("RAX")}),
        frozenset({RAM}),
    ),
]


def _target(
    sleigher: X86Sleigher,
    data: bytes,
    address: int,
) -> int:
    resolved = sleigher.spec.resolve(data, sleigher.context)
    assert resolved is not None
    relative = sleigher.spec.relative_target(resolved, data, address)
    assert relative is not None
    return relative[0]


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_rip_relative_reassemble_preserves_target(
    case: RipCase, sleigher: X86Sleigher
) -> None:
    instruction = sleigher.parse(case.original, address=case.original_address)
    assert instruction is not None

    assert {
        (state.kind, state.name) for state in instruction.modifies
    } == case.modifies
    assert {
        (state.kind, state.name) for state in instruction.depends_on
    } == case.depends_on

    relocated = sleigher.reassemble(instruction, case.relocated_address)
    assert relocated is not None
    assert relocated.address == case.relocated_address
    assert relocated.length == len(case.original)
    assert relocated.original_data == case.relocated

    old_target = _target(
        sleigher, case.original, case.original_address
    )
    new_target = _target(
        sleigher, relocated.original_data, case.relocated_address
    )
    assert new_target == old_target


def test_rip_relative_reassemble_at_low_address(
    sleigher: X86Sleigher,
) -> None:
    instruction = sleigher.parse(
        bytes.fromhex("8b0510000000"), address=0x1000
    )
    assert instruction is not None

    relocated = sleigher.reassemble(instruction, 0)
    assert relocated is not None
    assert relocated.original_data == bytes.fromhex("8b0510100000")


@pytest.mark.parametrize("new_address", [0x80002000, 0x100000000])
def test_rip_relative_reassemble_rejects_out_of_range(
    new_address: int, sleigher: X86Sleigher
) -> None:
    instruction = sleigher.parse(
        bytes.fromhex("8b0510000000"), address=0x1000
    )
    assert instruction is not None

    assert sleigher.reassemble(instruction, new_address) is None
