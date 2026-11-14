"""Lift recovered functions into instructions, basic blocks, and a CFG."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from ir import (
    Address,
    AddressKind,
    BasicBlock,
    Function,
    Instruction,
    InstructionType,
    Reference,
)
from isa import ISA, create_isa

if TYPE_CHECKING:
    from binary.binary import Binary


_BLOCK_ENDING_TYPES = frozenset(
    {
        InstructionType.BRANCH,
        InstructionType.RET,
    }
)


class Uplifter:
    """Turn function locations from an input description into IR."""

    def __init__(self, isa: str, binary: "Binary") -> None:
        self.isa: ISA = create_isa(isa)
        self.binary = binary
        self.function_map: dict[Address, Function] = {}

    def uplift_function(self, function: Function) -> None:
        """Disassemble ``function``, recover its flow graph, and index it.

        The whole declared extent is decoded first.  Control flow is then
        recovered by walking ``flows_to`` from the entry point.  A function is
        rejected if an instruction does not decode, an instruction crosses the
        declared end, a flow target lands in the middle of an instruction, or
        decoded bytes are unreachable from the entry.
        """
        if function.length <= 0:
            raise ValueError(
                f"cannot uplift function {function.name}: "
                "the function has no bytes"
            )

        start = function.start_address
        end = start + function.length
        instructions = self._decode_linear(function, start, end)
        basic_blocks, outgoing_references = self._recover_flow(
            function, instructions, start, end
        )

        function.basic_blocks = basic_blocks
        function.outgoing_references = outgoing_references
        self.function_map[Address.absolute(start)] = function

    def build_xrefs(self) -> None:
        """Recover cross-references across the full binary.

        This runs after every function has been uplifted.  It scans mapped
        memory rather than trusting the input function list, which may be
        incomplete: both pointer-sized values and successfully decoded
        instructions are checked for references to known function entries.

        Only control flow is decoded here, not state effects, because the
        scan visits every byte of mapped memory.
        """
        if not self.function_map:
            return

        for start, size in sorted(self.binary.mapped_ranges()):
            for address in range(start, start + size):
                self._record_pointer_reference(address)
                self._record_flow_references(address)

    def _record_pointer_reference(self, address: int) -> None:
        pointers = self.isa.try_interpret_as_pointer(self.binary, address)
        for pointer in pointers:
            if pointer.kind is not AddressKind.ABSOLUTE:
                continue

            function = self.function_map.get(pointer)
            if function is None:
                continue

            _append_unique(
                function.incoming_references,
                Reference(Address.absolute(address), pointer),
            )

    def _record_flow_references(self, address: int) -> None:
        try:
            flow = self.isa.decode_flows(self.binary, address)
        except ValueError:
            return

        source = Address.absolute(address)
        fallthrough = flow.address + flow.length
        for target in flow.flows_to:
            if target.kind is not AddressKind.ABSOLUTE:
                continue

            # A straight-line instruction's only flow is its fallthrough.  For
            # calls and conditional branches the fallthrough is likewise not a
            # real cross-reference; only branch targets are.  Counting padding
            # between functions as an incoming reference would keep otherwise
            # unreferenced functions alive.
            if (
                flow.type is not InstructionType.BRANCH
                and target.value == fallthrough
            ):
                continue

            function = self.function_map.get(target)
            if function is None:
                continue

            _append_unique(
                function.incoming_references, Reference(source, target)
            )

    def _decode_linear(
        self, function: Function, start: int, end: int
    ) -> dict[int, Instruction]:
        """Decode every instruction in ``[start, end)`` into an address map."""
        instructions: dict[int, Instruction] = {}
        address = start

        while address < end:
            try:
                instruction = self.isa.disassemble(self.binary, address)
            except ValueError as exc:
                raise ValueError(
                    f"cannot uplift function {function.name}: "
                    f"failed to decode instruction at {address:#x}"
                ) from exc

            if instruction.address != address:
                raise ValueError(
                    f"cannot uplift function {function.name}: decoder returned "
                    f"address {instruction.address:#x} for instruction at "
                    f"{address:#x}"
                )
            if instruction.length <= 0:
                raise ValueError(
                    f"cannot uplift function {function.name}: instruction at "
                    f"{address:#x} has non-positive length"
                )
            if address + instruction.length > end:
                raise ValueError(
                    f"cannot uplift function {function.name}: instruction at "
                    f"{address:#x} extends past the function end {end:#x}"
                )

            instructions[address] = instruction
            address += instruction.length

        return instructions

    def _recover_flow(
        self,
        function: Function,
        instructions: dict[int, Instruction],
        start: int,
        end: int,
    ) -> tuple[list[BasicBlock], list[Reference]]:
        """Recover predecessors, outgoing references, and basic blocks."""
        outgoing_references: list[Reference] = []
        leaders = {start}
        visited: set[int] = set()
        pending = deque([start])

        while pending:
            address = pending.popleft()
            if address in visited:
                continue

            instruction = instructions[address]
            visited.add(address)
            source = Address.absolute(address)

            for target in instruction.flows_to:
                if target.kind is not AddressKind.ABSOLUTE:
                    _append_unique(
                        outgoing_references, Reference(source, target)
                    )
                    continue

                target_address = target.value
                if not start <= target_address < end:
                    _append_unique(
                        outgoing_references, Reference(source, target)
                    )
                    continue

                if target_address not in instructions:
                    raise ValueError(
                        f"cannot uplift function {function.name}: instruction "
                        f"at {address:#x} flows to {target_address:#x}, which "
                        "is not an instruction boundary"
                    )

                # Sequential fallthrough does not start a new block.  A
                # branch's fallthrough is handled by splitting after the
                # branch itself.
                if target_address != instruction.address + instruction.length:
                    leaders.add(target_address)

                target_instruction = instructions[target_address]
                if source not in target_instruction.flows_from:
                    target_instruction.flows_from.append(source)
                if target_address not in visited:
                    pending.append(target_address)

        unreachable = sorted(set(instructions) - visited)
        if unreachable:
            raise ValueError(
                f"cannot uplift function {function.name}: "
                f"{len(unreachable)} decoded instruction(s) are unreachable "
                f"from entry {start:#x} (first at {unreachable[0]:#x})"
            )

        return (
            self._build_basic_blocks(function, instructions, leaders),
            outgoing_references,
        )

    @staticmethod
    def _build_basic_blocks(
        function: Function,
        instructions: dict[int, Instruction],
        leaders: set[int],
    ) -> list[BasicBlock]:
        """Group instructions into maximal straight-line basic blocks."""
        basic_blocks: list[BasicBlock] = []
        current_block: BasicBlock | None = None
        previous: Instruction | None = None

        for address in sorted(instructions):
            instruction = instructions[address]
            starts_new_block = current_block is None
            if not starts_new_block:
                assert previous is not None
                starts_new_block = (
                    address in leaders
                    or previous.type in _BLOCK_ENDING_TYPES
                    or address != previous.address + previous.length
                )

            if starts_new_block:
                current_block = BasicBlock(
                    start_location=Address.absolute(address),
                    containing_function=function,
                )
                basic_blocks.append(current_block)

            current_block.instructions.append(instruction)
            previous = instruction

        return basic_blocks


def _append_unique(references: list[Reference], reference: Reference) -> None:
    """Append ``reference`` unless an equal reference is already present."""
    if reference not in references:
        references.append(reference)
