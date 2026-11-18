"""Tests for the outlining optimizer."""

from __future__ import annotations

import logging
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile
import pytest

from ir import (
    Address,
    BasicBlock,
    FreeSpace,
    Function,
    Instruction,
    InstructionType,
    StateSpace,
    StateSpaceKind,
)
from optimizers import function_remover, outliner
from test.uplift_sample import uplift_sample
from uplifter import Uplifter

RAX = StateSpace(StateSpaceKind.REGISTER, "RAX", 8)
R10 = StateSpace(StateSpaceKind.REGISTER, "R10", 8)
R11 = StateSpace(StateSpaceKind.REGISTER, "R11", 8)
R12 = StateSpace(StateSpaceKind.REGISTER, "R12", 8)


class _MemoryBinary:
    """A small writable address space for decoded synthetic functions."""

    def __init__(self, size: int = 0x4000) -> None:
        self.data = bytearray(size)

    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self.data):
            raise ValueError(f"unmapped read at {address:#x}")
        return bytes(self.data[address : address + length])

    def write(self, address: int, data: bytes) -> None:
        if address < 0 or address + len(data) > len(self.data):
            raise ValueError(f"unmapped write at {address:#x}")
        self.data[address : address + len(data)] = data


def _decode_function(
    isa,
    binary: _MemoryBinary,
    name: str,
    start: int,
    code: bytes,
) -> Function:
    binary.write(start, code)
    function = Function(
        name=name,
        file_offset=-1,
        start_address=start,
        length=len(code),
    )
    instructions: list[Instruction] = []
    address = start
    while address < start + len(code):
        instruction = isa.disassemble(binary, address)
        instructions.append(instruction)
        address += instruction.length
    block = BasicBlock(
        start_location=Address.absolute(start),
        containing_function=function,
        instructions=instructions,
    )
    function.basic_blocks = [block]
    return function


def _make_synthetic(
    isa, *, with_free_space: bool = True
) -> tuple[_MemoryBinary, list[Function], SimpleNamespace, list[FreeSpace]]:
    binary = _MemoryBinary()
    sequence = bytes.fromhex("8b07" "0306" "0fafc0" "8902")
    code = sequence + b"\xc3"
    functions = [
        _decode_function(isa, binary, f"f{index}", start, code)
        for index, start in enumerate((0x1000, 0x1100, 0x1200))
    ]
    uplifter = SimpleNamespace(
        function_map={
            Address.absolute(function.start_address): function
            for function in functions
        }
    )
    free_space = (
        [FreeSpace(Address.absolute(0x3000), 0x100, "test free space")]
        if with_free_space
        else []
    )
    return binary, functions, uplifter, free_space


@pytest.fixture(scope="module")
def synthetic_case(x86_64_isa):
    binary, functions, uplifter, free_space = _make_synthetic(x86_64_isa)
    result = outliner.run_optimizer(
        binary, uplifter, x86_64_isa, free_space
    )
    assert result is not None
    return x86_64_isa, binary, functions, uplifter, free_space, result


def _load_red_zone_functions(
    isa, object_path, base: int = 0x1000
) -> tuple[_MemoryBinary, dict[str, Function]]:
    """Load the NASM fixture's functions from its ELF symbol table."""
    with object_path.open("rb") as stream:
        elf = ELFFile(stream)
        data = elf.get_section_by_name(".text").data()
        symbols = {
            symbol.name: symbol["st_value"]
            for symbol in elf.get_section_by_name(".symtab").iter_symbols()
            if symbol.name and symbol["st_info"]["type"] != "STT_FILE"
        }

    binary = _MemoryBinary(size=0x10000)
    binary.write(base, data)

    functions: dict[str, Function] = {}
    for name, end in symbols.items():
        if not name.endswith("_end"):
            continue
        function_name = name[: -len("_end")]
        start = symbols.get(function_name)
        if start is None or start >= end:
            continue
        functions[function_name] = _decode_function(
            isa,
            binary,
            function_name,
            base + start,
            data[start:end],
        )
    return binary, functions


@pytest.fixture(scope="module")
def red_zone_case(x86_64_isa, red_zone_object):
    binary, functions = _load_red_zone_functions(x86_64_isa, red_zone_object)
    uplifter = SimpleNamespace(
        function_map={
            Address.absolute(function.start_address): function
            for function in functions.values()
        }
    )
    free_space = [
        FreeSpace(Address.absolute(0x3000), 0x1000, "test free space")
    ]
    result = outliner.run_optimizer(
        binary, uplifter, x86_64_isa, free_space
    )
    assert result is not None
    return x86_64_isa, binary, functions, uplifter, free_space, result


def _selected_function_names(result) -> set[str]:
    return {
        block.containing_function.name
        for match in result.selected_matches
        for block in match.blocks
    }


def test_red_zone_outliner_keeps_only_dead_slot_sites(red_zone_case) -> None:
    _, _, _, _, _, result = red_zone_case
    selected = _selected_function_names(result)

    assert selected == {
        "leaf_ok_a",
        "leaf_ok_b",
        "leaf_deep_a",
        "leaf_deep_b",
        "leaf_over_a",
        "leaf_over_b",
        "leaf_call_a",
        "leaf_call_b",
        "mixed_safe_a",
        "mixed_safe_b",
    }
    assert {"leaf_read_a", "leaf_read_b"}.isdisjoint(selected)
    assert {"leaf_winread_a", "leaf_winread_b"}.isdisjoint(selected)
    assert {"leaf_alias_a", "leaf_alias_b"}.isdisjoint(selected)
    assert "mixed_unsafe" not in selected


def test_red_zone_outliner_drops_only_the_unsafe_mixed_site(
    red_zone_case,
) -> None:
    _, _, _, _, _, result = red_zone_case
    mixed = [
        match
        for match in result.selected_matches
        if any(
            block.containing_function.name.startswith("mixed_")
            for block in match.blocks
        )
    ]

    assert len(mixed) == 1
    assert mixed[0].block_count == 2
    assert {
        block.containing_function.name for block in mixed[0].blocks
    } == {"mixed_safe_a", "mixed_safe_b"}


def test_red_zone_outliner_leaves_unsafe_sites_unchanged(
    red_zone_case,
) -> None:
    _, _, functions, _, _, _ = red_zone_case

    for name in (
        "leaf_read_a",
        "leaf_read_b",
        "leaf_winread_a",
        "leaf_winread_b",
        "leaf_alias_a",
        "leaf_alias_b",
        "mixed_unsafe",
    ):
        function = functions[name]
        assert not any(
            block.used_for_outlining for block in function.basic_blocks
        )
        assert not any(
            instruction.type is InstructionType.OUTLINE_RESULT_CALL
            for block in function.basic_blocks
            for instruction in block.instructions
        )


@pytest.fixture(scope="module")
def sample_matches():
    """Return matches from the real sample without modifying it."""
    parsed, binary, uplifter = uplift_sample()
    uplifter.build_xrefs()
    function_remover.run_optimizer(binary, uplifter, uplifter.isa)
    result = outliner.extract_instruction_regions(
        binary, uplifter, uplifter.isa
    )
    assert result is not None
    return parsed, uplifter, result


def _instruction(
    *,
    modifies: tuple[StateSpace, ...] = (),
    depends_on: tuple[StateSpace, ...] = (),
    instruction_type: InstructionType = InstructionType.ARITHMETIC,
    flows_to: tuple[Address, ...] = (),
    address: int = 0x1000,
    length: int = 1,
) -> Instruction:
    return Instruction(
        original_data=b"\x90" * length,
        type=instruction_type,
        length=length,
        address=address,
        modifies=list(modifies),
        depends_on=list(depends_on),
        flows_to=list(flows_to),
    )


def test_generates_shared_block_and_calls(synthetic_case) -> None:
    isa, binary, functions, _, free_space, result = synthetic_case

    assert len(result.selected_matches) == 1
    match = result.selected_matches[0]
    assert match.block_count == 3
    assert {block.containing_function.name for block in match.blocks} == {
        "f0",
        "f1",
        "f2",
    }

    target = next(
        block
        for block in result.extracted_instructions
        if block.start_location.value == 0x3000
    )
    assert b"".join(
        instruction.original_data for instruction in target.instructions
    ) == bytes.fromhex("8b0703060fafc08902c3")

    for function in functions:
        instructions = function.basic_blocks[0].instructions
        assert [instruction.type for instruction in instructions] == [
            InstructionType.OUTLINE_RESULT_CALL,
            InstructionType.RET,
        ]
        call = instructions[0]
        assert call.address == function.start_address
        assert call.length == isa.call_instruction_length()
        assert call.flows_to[0] == Address.absolute(0x3000)
        assert call.flows_to[1] == Address.absolute(
            call.address + call.length
        )
        assert function.basic_blocks[0].used_for_outlining is True

    assert binary.data[0x1000:0x1006] == bytes.fromhex("e8fb1f0000c3")
    assert binary.data[0x1100:0x1106] == bytes.fromhex("e8fb1e0000c3")
    assert binary.data[0x1200:0x1206] == bytes.fromhex("e8fb1d0000c3")

    assert {
        (space.start.value, space.size) for space in free_space
    } == {
        (0x1006, 0x4),
        (0x1106, 0x4),
        (0x1206, 0x4),
        (0x300A, 0xF6),
    }
    assert result.free_space is free_space
    assert {
        (space.start.value, space.size)
        for space in result.modified_ranges
    } == {
        (0x1000, 0x6),
        (0x1100, 0x6),
        (0x1200, 0x6),
        (0x3000, 0xA),
    }


def test_extract_does_not_write_until_relink(x86_64_isa) -> None:
    binary, functions, uplifter, free_space = _make_synthetic(x86_64_isa)
    before = bytes(binary.data)

    result = outliner.extract_instruction_regions(
        binary, uplifter, x86_64_isa
    )

    assert result is not None
    assert result.matches
    assert result.selected_matches
    assert result.extracted_instructions
    assert result.basic_blocks_to_regenerate
    assert bytes(binary.data) == before
    assert {
        (space.start.value, space.size) for space in result.free_space
    } == {(0x1006, 4), (0x1106, 4), (0x1206, 4)}

    result = outliner.relink_in_instructions(
        binary, uplifter, x86_64_isa, result, free_space
    )

    assert result.selected_matches
    assert bytes(binary.data) != before
    assert {
        (space.start.value, space.size) for space in result.free_space
    } == {
        (0x1006, 4),
        (0x1106, 4),
        (0x1206, 4),
        (0x300A, 0xF6),
    }
    # ``relink_in_instructions`` returns the updated free space; the caller's
    # list is only replaced by ``run_optimizer``.
    assert free_space == [
        FreeSpace(Address.absolute(0x3000), 0x100, "test free space")
    ]


def test_no_free_space_leaves_functions_unchanged(x86_64_isa) -> None:
    binary, functions, uplifter, free_space = _make_synthetic(
        x86_64_isa, with_free_space=False
    )

    result = outliner.run_optimizer(
        binary, uplifter, x86_64_isa, free_space
    )

    assert result is not None
    assert result.selected_matches == []
    assert free_space == []
    for function in functions:
        instructions = function.basic_blocks[0].instructions
        assert [instruction.type for instruction in instructions] == [
            InstructionType.ARITHMETIC,
            InstructionType.ARITHMETIC,
            InstructionType.ARITHMETIC,
            InstructionType.ARITHMETIC,
            InstructionType.RET,
        ]


def test_short_branch_out_of_range_drops_plan(caplog) -> None:
    # The shared window shrinks by four bytes.  The short jump at 0x1009
    # targets 0x1089, so its displacement grows from 0x7e to 0x82 and no
    # longer fits a rel8.  The plan must be dropped and the function left
    # untouched.
    code = bytes.fromhex("8b07" "0306" "0fafc0" "85c0" "eb7e")
    binary = _MemoryBinary()
    starts = (0x1000, 0x1100, 0x1200)
    for start in starts:
        binary.write(start, code)

    uplifter = Uplifter("x86_64", binary)
    for index, start in enumerate(starts):
        uplifter.uplift_function(
            Function(
                name=f"f{index}",
                file_offset=-1,
                start_address=start,
                length=len(code),
            )
        )

    before = {
        start: bytes(binary.data[start : start + len(code)])
        for start in starts
    }
    free_space = [
        FreeSpace(Address.absolute(0x3000), 0x100, "test free space")
    ]

    caplog.set_level(logging.DEBUG, logger="optimizers.outliner")
    result = outliner.run_optimizer(
        binary, uplifter, uplifter.isa, free_space
    )

    assert result is not None
    assert result.matches
    assert result.selected_matches == []
    assert result.extracted_instructions == []
    assert result.modified_ranges == []
    assert free_space == [
        FreeSpace(Address.absolute(0x3000), 0x100, "test free space")
    ]
    assert "cannot relocate" in caplog.text
    for start in starts:
        assert bytes(binary.data[start : start + len(code)]) == before[start]


def test_sample_red_zone_candidates_are_not_selected(sample_matches) -> None:
    _, uplifter, result = sample_matches
    isa = uplifter.isa

    # Red-zone functions now produce candidate matches, but every sample
    # candidate touches a live slot, so none of them survives selection.
    assert any(
        isa.uses_red_zone(block.containing_function)
        for match in result.matches
        for block in match.blocks
    )
    assert all(
        not isa.uses_red_zone(block.containing_function)
        for match in result.selected_matches
        for block in match.blocks
    )


def test_sample_eligible_functions_include_red_zone(sample_matches) -> None:
    _, uplifter, _ = sample_matches
    isa = uplifter.isa
    names = {
        function.name
        for function in outliner._eligible_functions(uplifter, isa)
    }

    assert "main" in names
    assert "gcd" in names
    assert "mix_a" in names
    assert "mix_b" in names
    assert "mix_c" in names
    assert "add" in names
    assert "is_even" in names


def test_sample_outliner_selects_the_shared_mix_expression(
    sample_matches,
) -> None:
    _, _, result = sample_matches

    assert len(result.selected_matches) == 1
    match = result.selected_matches[0]
    assert {block.containing_function.name for block in match.blocks} == {
        "mix_a",
        "mix_b",
        "mix_c",
    }
    assert match.common_length == 0xD
    assert {
        (space.start.value, space.size) for space in result.free_space
    } == {
        (0x401BDF, 0x8),
        (0x401C04, 0x8),
        (0x401C29, 0x8),
    }


def test_find_basic_block_matches_is_limited_per_block(
    sample_matches,
) -> None:
    _, uplifter, _ = sample_matches
    isa = uplifter.isa
    functions = outliner._eligible_functions(uplifter, isa)
    index = outliner._build_instruction_index(functions, isa)

    for function in functions:
        for block in function.basic_blocks:
            matches = outliner.find_basic_block_matches(block, index, isa)
            assert len(matches) <= outliner._MAX_MATCHES_PER_BLOCK


def test_unsupported_isa_returns_none() -> None:
    class UnsupportedISA:
        supports_outlining = False
        name = "unsupported"

    uplifter = SimpleNamespace(function_map={})

    assert (
        outliner.extract_instruction_regions(
            None, uplifter, UnsupportedISA()
        )
        is None
    )


def test_format_match_lists_shared_instructions_and_blocks(
    sample_matches,
) -> None:
    _, _, result = sample_matches
    match = result.matches[0]

    lines = outliner.format_match(match)
    text = "\n".join(lines)

    assert "shared instructions:" in text
    assert "source blocks:" in text
    for instruction in match.common_instructions:
        assert instruction.original_data.hex() in text
    for block in match.blocks:
        assert f"{block.start_location.value:#x}" in text


def test_can_swap_instruction_rejects_dependencies() -> None:
    first = _instruction(modifies=(RAX,), depends_on=(RAX,))
    reader = _instruction(depends_on=(RAX,))
    writer = _instruction(modifies=(RAX,))
    independent = _instruction(modifies=(R10,), depends_on=(R10,))

    assert outliner.can_swap_instruction([first], reader) is False
    assert outliner.can_swap_instruction([first], writer) is False
    assert outliner.can_swap_instruction([independent], reader) is True


def test_can_swap_instruction_rejects_control_transfer() -> None:
    independent = _instruction(modifies=(R10,))
    branch = _instruction(
        instruction_type=InstructionType.BRANCH,
        flows_to=(Address.absolute(0x2000),),
    )
    call = _instruction(instruction_type=InstructionType.CALL)

    assert outliner.can_swap_instruction([independent], branch) is False
    assert outliner.can_swap_instruction([branch], independent) is False
    assert outliner.can_swap_instruction([independent], call) is True


def test_convert_reorders_instructions_and_returns_window() -> None:
    before = _instruction(modifies=(R10,))
    first = _instruction(modifies=(R10,))
    middle = _instruction(modifies=(R11,))
    second = _instruction(modifies=(R12,))
    block = BasicBlock(
        start_location=Address.absolute(0x1000),
        instructions=[before, first, middle, second],
    )

    converted = (
        outliner.convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
            block, [first, second], [first, second]
        )
    )

    assert converted is not None
    reordered, start = converted
    assert start == 1
    assert reordered.instructions == [before, first, second, middle]
    assert block.instructions == [before, first, middle, second]


def test_convert_fails_when_dependencies_block_reordering() -> None:
    first = _instruction(modifies=(RAX,))
    blocker = _instruction(modifies=(RAX,), depends_on=(RAX,))
    second = _instruction(modifies=(RAX,))
    block = BasicBlock(
        start_location=Address.absolute(0x1000),
        instructions=[first, blocker, second],
    )

    assert (
        outliner.convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
            block, [first, second], [first, second]
        )
        is None
    )


def test_find_indices_uses_instruction_identity() -> None:
    first = _instruction()
    second = _instruction()
    third = _instruction()
    block = BasicBlock(
        start_location=Address.absolute(0x1000),
        instructions=[first, second, third],
    )

    assert outliner.find_indices(block, [first, third]) == [0, 2]


def test_function_can_shrink_requires_a_non_fallthrough_terminator() -> None:
    ret = _instruction(
        instruction_type=InstructionType.RET,
        address=0x1000,
    )
    jump = _instruction(
        instruction_type=InstructionType.BRANCH,
        flows_to=(Address.absolute(0x2000),),
        address=0x1000,
        length=2,
    )
    conditional = _instruction(
        instruction_type=InstructionType.BRANCH,
        flows_to=(
            Address.absolute(0x2000),
            Address.absolute(0x1002),
        ),
        address=0x1000,
        length=2,
    )
    call = _instruction(
        instruction_type=InstructionType.CALL,
        address=0x1000,
    )

    def function_with(last: Instruction) -> Function:
        function = Function(
            name="f",
            file_offset=-1,
            start_address=0x1000,
            length=0x10,
        )
        function.basic_blocks = [
            BasicBlock(
                start_location=Address.absolute(0x1000),
                containing_function=function,
                instructions=[last],
            )
        ]
        return function

    assert outliner._function_can_shrink(function_with(ret)) is True
    assert outliner._function_can_shrink(function_with(jump)) is True
    assert outliner._function_can_shrink(function_with(conditional)) is False
    assert outliner._function_can_shrink(function_with(call)) is False


def test_uses_red_zone_tracks_rbp_relative_locals(x86_64_isa) -> None:
    binary = _MemoryBinary()

    no_frame = _decode_function(
        x86_64_isa,
        binary,
        "no_frame",
        0x1000,
        bytes.fromhex("55" "4889e5" "897dfc" "c3"),
    )
    frame = _decode_function(
        x86_64_isa,
        binary,
        "frame",
        0x1100,
        bytes.fromhex("55" "4889e5" "4883ec10" "897dfc" "c3"),
    )
    too_deep = _decode_function(
        x86_64_isa,
        binary,
        "too_deep",
        0x1200,
        bytes.fromhex("55" "4889e5" "4883ec10" "8b45e8" "c3"),
    )
    negative_rsp = _decode_function(
        x86_64_isa,
        binary,
        "negative_rsp",
        0x1300,
        bytes.fromhex("55" "4889e5" "4883ec10" "8b4424f8" "c3"),
    )
    positive_rsp = _decode_function(
        x86_64_isa,
        binary,
        "positive_rsp",
        0x1400,
        bytes.fromhex("55" "4889e5" "4883ec10" "8b442408" "c3"),
    )
    lea_rsp = _decode_function(
        x86_64_isa,
        binary,
        "lea_rsp",
        0x1500,
        bytes.fromhex("55" "4889e5" "488d4424f8" "c3"),
    )

    assert x86_64_isa.uses_red_zone(no_frame) is True
    assert x86_64_isa.uses_red_zone(frame) is False
    assert x86_64_isa.uses_red_zone(too_deep) is True
    assert x86_64_isa.uses_red_zone(negative_rsp) is True
    assert x86_64_isa.uses_red_zone(positive_rsp) is False
    assert x86_64_isa.uses_red_zone(lea_rsp) is False
