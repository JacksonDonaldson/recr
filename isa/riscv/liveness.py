"""Backward liveness for the RISC-V outliner's alternate link register."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable

from ir import AddressKind, Function, Instruction, InstructionType

_LINK = 5
_CALLS = frozenset({
    InstructionType.CALL, InstructionType.CALL_INDIRECT,
    InstructionType.OUTLINE_RESULT_CALL,
})


def link_live_before(
    instruction: Instruction, live_after: bool, definite_write: Callable[[Instruction], bool],
) -> bool:
    """Transfer liveness through one instruction, including source operands."""
    if any(state.name == "t0" for state in instruction.depends_on):
        return True
    if instruction.type is InstructionType.OUTLINE_RESULT_CALL:
        return False
    if instruction.type in _CALLS:
        # A normal call's ABI clobber is only a possible write. The callee
        # could inspect t0, including a hand-written routine or PLT code.
        # JAL/JALR with rd=x5 write it before control reaches the callee.
        word = int.from_bytes(instruction.original_data, "little")
        return not (
            instruction.length == 4
            and word & 0x7F in (0x67, 0x6F)
            and (word >> 7) & 31 == _LINK
        )
    return live_after and not definite_write(instruction)


def live_block_exits(
    function: Function, definite_write: Callable[[Instruction], bool],
) -> set[int]:
    """Return the block addresses with a live link value at exit."""
    instructions = {
        instr.address: instr
        for block in function.basic_blocks
        for instr in block.instructions
    }
    predecessors: dict[int, list[int]] = defaultdict(list)
    successors: dict[int, list[int]] = defaultdict(list)
    open_exits: set[int] = set()
    for address, instruction in instructions.items():
        for target in instruction.flows_to:
            if target.kind is AddressKind.ABSOLUTE and target.value in instructions:
                successors[address].append(target.value)
                predecessors[target.value].append(address)
            elif instruction.type not in _CALLS:
                open_exits.add(address)
        # A normal ABI return leaves no live caller-saved registers. An
        # unclassified terminal instruction has no such guarantee.
        if not instruction.flows_to and instruction.type is not InstructionType.RET:
            open_exits.add(address)

    live_at_entry = {
        address for address, instruction in instructions.items()
        if link_live_before(instruction, address in open_exits, definite_write)
    }
    work = deque(live_at_entry)
    while work:
        address = work.popleft()
        for predecessor in predecessors[address]:
            if predecessor in live_at_entry:
                continue
            if link_live_before(instructions[predecessor], True, definite_write):
                live_at_entry.add(predecessor)
                work.append(predecessor)

    live_exits = set()
    for block in function.basic_blocks:
        last = block.instructions[-1].address
        if last in open_exits or any(target in live_at_entry for target in successors[last]):
            live_exits.add(block.start_location.value)
    return live_exits
