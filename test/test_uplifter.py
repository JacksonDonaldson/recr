"""Tests for function uplifting and Function.pretty_print."""

from __future__ import annotations

import pytest

from ir import (
    Address,
    AddressKind,
    Function,
    Instruction,
    InstructionType,
    Reference,
)
from test.uplift_sample import uplift_sample
from uplifter import Uplifter


@pytest.fixture(scope="session")
def uplifted_sample():
    """Return the parsed sample, its binary, and a fully uplifted function map."""
    return uplift_sample()


def _function(parsed, name: str) -> Function:
    return next(function for function in parsed.functions if function.name == name)


def _instructions(function: Function) -> list[Instruction]:
    return [
        instruction
        for block in function.basic_blocks
        for instruction in block.instructions
    ]


def test_every_sample_function_is_uplifted(uplifted_sample) -> None:
    parsed, _, uplifter = uplifted_sample

    assert len(parsed.functions) == 39
    assert len(uplifter.function_map) == len(parsed.functions)

    for function in parsed.functions:
        entry = Address.absolute(function.start_address)
        assert uplifter.function_map[entry] is function
        assert function.basic_blocks
        assert function.basic_blocks[0].start_location == entry


def test_basic_blocks_cover_the_function_extent(uplifted_sample) -> None:
    parsed, binary, _ = uplifted_sample

    for function in parsed.functions:
        instructions = _instructions(function)
        end = function.start_address + function.length

        assert instructions
        assert instructions[0].address == function.start_address
        assert sum(instruction.length for instruction in instructions) == (
            function.length
        )

        for instruction in instructions:
            assert instruction.address + instruction.length <= end
            assert instruction.original_data == binary.read(
                instruction.address, instruction.length
            )

        for previous, current in zip(instructions, instructions[1:]):
            assert current.address == previous.address + previous.length

        for block in function.basic_blocks:
            assert block.instructions
            assert block.containing_function is function
            assert block.start_location == Address.absolute(
                block.instructions[0].address
            )
            for previous, current in zip(
                block.instructions, block.instructions[1:]
            ):
                assert current.address == previous.address + previous.length


def test_flow_edges_and_outgoing_references_are_reciprocal(
    uplifted_sample,
) -> None:
    parsed, _, _ = uplifted_sample

    for function in parsed.functions:
        instructions = _instructions(function)
        by_address = {
            instruction.address: instruction for instruction in instructions
        }
        start = function.start_address
        end = start + function.length
        expected_outgoing: set[Reference] = set()

        for instruction in instructions:
            source = Address.absolute(instruction.address)
            for target in instruction.flows_to:
                if target.kind is AddressKind.ABSOLUTE and (
                    start <= target.value < end
                ):
                    assert target.value in by_address
                    assert source in by_address[target.value].flows_from
                else:
                    expected_outgoing.add(Reference(source, target))

        for instruction in instructions:
            for source in instruction.flows_from:
                assert source.kind is AddressKind.ABSOLUTE
                assert source.value in by_address
                assert Address.absolute(instruction.address) in by_address[
                    source.value
                ].flows_to

        assert len(function.outgoing_references) == len(
            set(function.outgoing_references)
        )
        assert set(function.outgoing_references) == expected_outgoing

        for reference in function.outgoing_references:
            assert reference.from_.kind is AddressKind.ABSOLUTE
            assert reference.from_.value in by_address


def test_branches_split_basic_blocks(uplifted_sample) -> None:
    parsed, _, _ = uplifted_sample
    function = _function(parsed, "divide_safe")

    assert [block.start_location for block in function.basic_blocks] == [
        Address.absolute(0x40119B),
        Address.absolute(0x4011AF),
        Address.absolute(0x4011B6),
        Address.absolute(0x4011BD),
    ]
    assert [
        block.instructions[-1].address for block in function.basic_blocks
    ] == [0x4011AD, 0x4011B4, 0x4011BA, 0x4011BE]

    branch = next(
        instruction
        for instruction in _instructions(function)
        if instruction.address == 0x4011AD
    )
    assert branch.type is InstructionType.BRANCH
    assert branch.flows_to == [
        Address.absolute(0x4011B6),
        Address.absolute(0x4011AF),
    ]

    join = next(
        instruction
        for instruction in _instructions(function)
        if instruction.address == 0x4011BD
    )
    assert join.flows_from == [
        Address.absolute(0x4011B4),
        Address.absolute(0x4011BA),
    ]


def test_calls_do_not_end_a_basic_block(uplifted_sample) -> None:
    parsed, _, _ = uplifted_sample
    function = _function(parsed, "main")
    containing_block = {
        instruction.address: block
        for block in function.basic_blocks
        for instruction in block.instructions
    }

    call = next(
        instruction
        for instruction in _instructions(function)
        if instruction.address == 0x40189E
    )
    assert call.type is InstructionType.CALL
    assert containing_block[0x40189E] is containing_block[0x4018A3]


def test_outgoing_references_cover_calls_branches_and_fallthrough(
    uplifted_sample,
) -> None:
    parsed, _, _ = uplifted_sample

    start = _function(parsed, "_start")
    assert (
        Reference(
            Address.absolute(0x40108F), Address.unknown_nonlocal()
        )
        in start.outgoing_references
    )
    assert (
        Reference(Address.absolute(0x401095), Address.absolute(0x401096))
        in start.outgoing_references
    )

    printf = _function(parsed, "<EXTERNAL>::printf")
    assert (
        Reference(Address.absolute(0x401064), Address.unknown_local())
        in printf.outgoing_references
    )

    main = _function(parsed, "main")
    assert (
        Reference(Address.absolute(0x40189E), Address.absolute(0x401156))
        in main.outgoing_references
    )


def test_uplift_rejects_a_zero_length_function(uplifted_sample) -> None:
    _, _, uplifter = uplifted_sample
    function = Function(
        name="empty",
        file_offset=-1,
        start_address=0x401156,
        length=0,
    )

    with pytest.raises(ValueError, match="has no bytes"):
        uplifter.uplift_function(function)
    assert function.basic_blocks == []


def test_uplift_rejects_instruction_past_function_end(
    uplifted_sample,
) -> None:
    _, _, uplifter = uplifted_sample
    function = Function(
        name="truncated",
        file_offset=-1,
        start_address=0x401156,
        length=1,
    )

    with pytest.raises(ValueError, match="extends past the function end"):
        uplifter.uplift_function(function)
    assert function.basic_blocks == []


def test_uplift_rejects_unreachable_instructions(uplifted_sample) -> None:
    _, _, uplifter = uplifted_sample
    function = Function(
        name="fragment",
        file_offset=-1,
        start_address=0x4011B4,
        length=0x9,
    )

    with pytest.raises(ValueError, match="unreachable from entry"):
        uplifter.uplift_function(function)
    assert function.basic_blocks == []


def test_uplift_rejects_flow_into_the_middle_of_an_instruction(
    monkeypatch, uplifted_sample
) -> None:
    _, binary, _ = uplifted_sample
    instructions = {
        0x1000: Instruction(
            original_data=b"\xeb\x00",
            type=InstructionType.BRANCH,
            length=2,
            address=0x1000,
            flows_to=[Address.absolute(0x1001)],
        ),
        0x1002: Instruction(
            original_data=b"\x90\x90",
            type=InstructionType.NOP,
            length=2,
            address=0x1002,
            flows_to=[Address.absolute(0x1004)],
        ),
    }

    class FakeISA:
        def disassemble(self, binary, address):
            return instructions[address]

    monkeypatch.setattr("uplifter.create_isa", lambda name: FakeISA())
    uplifter = Uplifter("x86_64", binary)
    function = Function(
        name="misaligned",
        file_offset=-1,
        start_address=0x1000,
        length=4,
    )

    with pytest.raises(ValueError, match="not an instruction boundary"):
        uplifter.uplift_function(function)
    assert Address.absolute(0x1000) not in uplifter.function_map


def test_pretty_print_writes_blocks_and_flow_details(
    capsys, uplifted_sample
) -> None:
    parsed, _, _ = uplifted_sample
    function = _function(parsed, "divide_safe")

    assert function.pretty_print() is None
    output = capsys.readouterr().out

    assert (
        "function divide_safe @ 0x40119b "
        "(0x24 bytes, 4 blocks, 14 instructions)"
    ) in output
    assert "  block 0 @ 0x40119b (7 instructions, 0x14 bytes)" in output
    assert "0x4011ad  7507" in output
    assert "branch" in output
    assert "to=[0x4011b6, 0x4011af]" in output
    assert "from=[0x4011b4, 0x4011ba]" in output


def test_pretty_print_renders_unknown_flow_kinds(
    capsys, uplifted_sample
) -> None:
    parsed, _, _ = uplifted_sample

    _function(parsed, "<EXTERNAL>::printf").pretty_print()
    assert "to=[UNK_LOCAL]" in capsys.readouterr().out

    _function(parsed, "_start").pretty_print()
    assert "to=[UNK_NONLOCAL, 0x401095]" in capsys.readouterr().out


def test_pretty_print_summarizes_large_state_lists(
    capsys, uplifted_sample
) -> None:
    parsed, _, _ = uplifted_sample

    _function(parsed, "_init").pretty_print()
    output = capsys.readouterr().out

    assert "mod=152 states (RSP, ram, RAX, RCX" in output
    assert "mod=152 states (RIP, RSP, RAX, RCX" in output
    assert "+144)" in output
    assert "TR_Attributes" not in output
