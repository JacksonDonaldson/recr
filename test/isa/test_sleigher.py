"""Tests for the direct SLA-backed instruction decoder."""

from __future__ import annotations

from pathlib import Path

from ir import InstructionType, StateSpaceKind
from isa.sleigher import X86Sleigher


def test_parse_add_modifies_rax(
    isa_test_binary: Path, sleigher: X86Sleigher
) -> None:
    instruction = sleigher.parse(isa_test_binary.read_bytes())

    assert instruction is not None
    assert instruction.original_data == b"\x83\xc0\x20"
    assert instruction.length == 3
    assert instruction.type is InstructionType.ARITHMETIC

    registers = [
        state
        for state in instruction.modifies
        if state.kind is StateSpaceKind.REGISTER
    ]
    assert any(state.name == "RAX" and state.size == 8 for state in registers)
    assert any(state.kind is StateSpaceKind.FLAG for state in instruction.modifies)

    assert any(
        state.kind is StateSpaceKind.REGISTER and state.name == "RAX"
        for state in instruction.depends_on
    )


def test_reassemble_position_independent_instruction(
    isa_test_binary: Path, sleigher: X86Sleigher
) -> None:
    instruction = sleigher.parse(isa_test_binary.read_bytes())
    assert instruction is not None

    moved = sleigher.reassemble(instruction, 0x401000)

    assert moved is not None
    assert moved.address == 0x401000
    assert moved.original_data == instruction.original_data
    assert moved.length == instruction.length
    assert moved.modifies == instruction.modifies


def test_incomplete_input_returns_none(sleigher: X86Sleigher) -> None:
    assert sleigher.parse(b"") is None
    assert sleigher.parse(b"\x83") is None
