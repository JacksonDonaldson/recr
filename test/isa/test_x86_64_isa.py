"""ISA-level decoding behaviour that is independent of the SLEIGH parser."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ir import Address, Instruction, InstructionType
from isa.x86_64 import X86_64ISA


class _BoundedBinary:
    """Binary stand-in that rejects reads crossing the mapped region."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self.data):
            raise ValueError(f"virtual address {address:#x} is not mapped")
        return self.data[address : address + length]


def test_disassemble_clamps_read_to_mapped_memory(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction_bytes = bytes.fromhex("488b442408")
    data = b"\x90" * 13 + instruction_bytes

    instruction = x86_64_isa.disassemble(_BoundedBinary(data), 13)

    assert instruction.original_data == instruction_bytes
    assert instruction.length == len(instruction_bytes)
    assert instruction.flows_from == []
    assert instruction.flows_to == [Address.absolute(13 + len(instruction_bytes))]


def test_disassemble_rejects_unmapped_address(
    x86_64_isa: X86_64ISA,
) -> None:
    with pytest.raises(ValueError, match="cannot read instruction bytes"):
        x86_64_isa.disassemble(_BoundedBinary(b"\x90"), 1)


def test_decode_flows_clamps_read_to_mapped_memory(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction_bytes = bytes.fromhex("488b442408")
    data = b"\x90" * 13 + instruction_bytes

    flow = x86_64_isa.decode_flows(_BoundedBinary(data), 13)

    assert flow.address == 13
    assert flow.length == len(instruction_bytes)
    assert flow.type is InstructionType.ARITHMETIC
    assert flow.flows_to == (Address.absolute(13 + len(instruction_bytes)),)


def test_decode_flows_rejects_unmapped_address(
    x86_64_isa: X86_64ISA,
) -> None:
    with pytest.raises(ValueError, match="cannot read instruction bytes"):
        x86_64_isa.decode_flows(_BoundedBinary(b"\x90"), 1)


@pytest.mark.parametrize(
    "data",
    [b"\x48", b"\x66", b"\x0f", b"\x62", bytes.fromhex("83c0")],
    ids=[
        "lone-rex",
        "lone-operand-size",
        "lone-opcode-0f",
        "lone-evex",
        "truncated-add",
    ],
)
def test_decode_flows_rejects_undecodable_bytes(
    data: bytes, x86_64_isa: X86_64ISA
) -> None:
    with pytest.raises(ValueError, match="cannot decode instruction"):
        x86_64_isa.decode_flows(_BoundedBinary(data), 0)


def _decode(x86_64_isa: X86_64ISA, data: bytes) -> Instruction:
    return x86_64_isa.disassemble(_BoundedBinary(data), 0)


def test_relocate_instruction_preserves_rip_relative_target(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _decode(x86_64_isa, bytes.fromhex("8b0510000000"))

    relocated = x86_64_isa.relocate_instruction(instruction, 0x1000)

    assert relocated.address == 0x1000
    assert relocated.length == instruction.length
    assert relocated.original_data == bytes.fromhex("8b0510f0ffff")
    assert relocated.flows_from == []
    assert relocated.flows_to == [
        Address.absolute(0x1000 + relocated.length)
    ]


def test_relocate_instruction_rejects_out_of_range_address(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _decode(x86_64_isa, bytes.fromhex("8b0510000000"))

    with pytest.raises(ValueError, match="cannot relocate"):
        x86_64_isa.relocate_instruction(instruction, 0x100000000)


def test_can_encode_and_required_length(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _decode(x86_64_isa, bytes.fromhex("8b0510000000"))

    assert x86_64_isa.can_encode(instruction, 0) is True
    assert x86_64_isa.can_encode(instruction, 0x1000) is True
    assert x86_64_isa.can_encode(instruction, 0x100000000) is False
    assert x86_64_isa.required_length(instruction, 0) == 6
    assert x86_64_isa.required_length(instruction, 0x1000) == 6

    with pytest.raises(ValueError, match="cannot encode"):
        x86_64_isa.required_length(instruction, 0x100000000)


def test_position_independent_instruction_encodes_anywhere(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _decode(x86_64_isa, b"\x90")

    assert x86_64_isa.can_encode(instruction, 0x100000000) is True
    assert x86_64_isa.required_length(instruction, 0x100000000) == 1


def test_try_interpret_as_pointer_reads_both_widths(
    x86_64_isa: X86_64ISA,
) -> None:
    binary = _BoundedBinary(
        b"\x56\x11\x40\x00\x00\x00\x00\x00" + b"\xff" * 8
    )

    assert x86_64_isa.try_interpret_as_pointer(binary, 0) == {
        Address.absolute(0x401156)
    }
    assert x86_64_isa.try_interpret_as_pointer(binary, 8) == {
        Address.absolute(0xFFFFFFFFFFFFFFFF),
        Address.absolute(0xFFFFFFFF),
    }


def test_try_interpret_as_pointer_falls_back_to_32_bits(
    x86_64_isa: X86_64ISA,
) -> None:
    binary = _BoundedBinary(b"\0" * 4 + b"\x56\x11\x40\x00")

    assert x86_64_isa.try_interpret_as_pointer(binary, 4) == {
        Address.absolute(0x401156)
    }


def test_try_interpret_as_pointer_rejects_unmapped_offsets(
    x86_64_isa: X86_64ISA,
) -> None:
    binary = _BoundedBinary(b"\0" * 8)

    assert x86_64_isa.try_interpret_as_pointer(binary, -1) == set()
    assert x86_64_isa.try_interpret_as_pointer(binary, 5) == set()
    assert x86_64_isa.try_interpret_as_pointer(binary, 8) == set()


def test_is_outlinable_accepts_empty_flows(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[],
        flows_to=[],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_accepts_fallthrough_without_flows_from(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[],
        flows_to=[Address.absolute(0x1001)],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_accepts_single_fallthrough_flow(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[Address.absolute(0x1000)],
        flows_to=[Address.absolute(0x1001)],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_rejects_non_fallthrough_flow(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[Address.absolute(0x1000)],
        flows_to=[Address.absolute(0x1002)],
    )

    assert x86_64_isa.is_outlinable(instruction) is False


def test_is_outlinable_rejects_unpaired_flow(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[Address.absolute(0x1000)],
    )

    assert x86_64_isa.is_outlinable(instruction) is False


def test_is_outlinable_accepts_multi_byte_fallthrough(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, bytes.fromhex("83c020")),
        address=0x1000,
        flows_from=[Address.absolute(0x1000)],
        flows_to=[Address.absolute(0x1003)],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_accepts_predecessor_address_in_flows_from(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[Address.absolute(0x0FFF)],
        flows_to=[Address.absolute(0x1001)],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_accepts_multiple_predecessors(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        address=0x1000,
        flows_from=[
            Address.absolute(0x0FFE),
            Address.absolute(0x0FFF),
        ],
        flows_to=[Address.absolute(0x1001)],
    )

    assert x86_64_isa.is_outlinable(instruction) is True


def test_is_outlinable_rejects_endbr64(x86_64_isa: X86_64ISA) -> None:
    instruction = replace(
        _decode(x86_64_isa, bytes.fromhex("f30f1efa")),
        address=0x1000,
        flows_from=[Address.absolute(0x0FFF)],
        flows_to=[Address.absolute(0x1004)],
    )

    assert x86_64_isa.is_outlinable(instruction) is False


def test_outline_call_and_return_lengths(x86_64_isa: X86_64ISA) -> None:
    assert x86_64_isa.call_instruction_length() == 5
    assert x86_64_isa.ret_instruction_length() == 1


def test_is_outlinable_rejects_outline_result_call(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = replace(
        _decode(x86_64_isa, b"\x90"),
        type=InstructionType.OUTLINE_RESULT_CALL,
    )

    assert x86_64_isa.is_outlinable(instruction) is False


def test_is_outlinable_rejects_undecodable_instruction(
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = Instruction(
        original_data=b"\xd6",
        type=InstructionType.ARITHMETIC,
        length=1,
    )

    assert x86_64_isa.is_outlinable(instruction) is False
    with pytest.raises(ValueError):
        x86_64_isa.add_extra_stack_space(instruction, 8)
