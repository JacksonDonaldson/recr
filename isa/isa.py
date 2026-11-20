"""ISA encoding contract shared by the uplifter, optimizers, and ISAs.

The normative description lives in ``ir.md``.  This class is the interface each
concrete ISA implements; see :mod:`isa.x86_64` for the first implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, AbstractSet, ClassVar, Iterator

from ir import Address, AddressKind, Instruction, InstructionType, JumpRange

if TYPE_CHECKING:
    from binary.binary import Binary
    from ir import BasicBlock, Function


@dataclass(frozen=True)
class DecodedFlow:
    """Control-flow facts about one decoded instruction.

    :meth:`ISA.decode_flows` returns these instead of an
    :class:`~ir.Instruction` because state effects dominate decode time and a
    whole-image scan only needs the control flow.
    """

    address: int
    length: int
    type: InstructionType
    flows_to: tuple[Address, ...]

    def references(self, targets: AbstractSet[int]) -> Iterator[tuple[int, int]]:
        fallthrough = self.address + self.length
        for target in self.flows_to:
            if target.kind is not AddressKind.ABSOLUTE or target.value not in targets:
                continue
            if self.type is InstructionType.BRANCH or target.value != fallthrough:
                yield self.address, target.value


class ISA(ABC):
    """Interface for an instruction-set architecture."""

    name: ClassVar[str] = ""
    supports_outlining: ClassVar[bool] = False
    pointer_size: ClassVar[int] = 0

    @abstractmethod
    def disassemble(self, binary: "Binary", address: int) -> Instruction:
        """Decode one instruction at ``address`` and fill in its dependencies."""
        raise NotImplementedError

    @abstractmethod
    def decode_flows(self, binary: "Binary", address: int) -> DecodedFlow:
        """Decode one instruction's control flow at ``address``.

        Return the same address, length, type, and flow targets as
        :meth:`disassemble` without computing state effects.  Raise
        :class:`ValueError` if no instruction decodes at ``address``.
        """
        raise NotImplementedError

    def fallthrough_target(self, instruction: Instruction) -> int | None:
        """Return the implicit next address of a decoded instruction, if any."""
        target = instruction.address + instruction.length
        return target if Address.absolute(target) in instruction.flows_to else None

    def decode_range(
        self, binary: "Binary", start: int, end: int
    ) -> Iterator[DecodedFlow | None]:
        """Decode one instruction at every address in ``[start, end)``.

        Yields ``None`` where no instruction decodes.  The default
        implementation decodes one address at a time; an ISA may override this
        to batch the work, for example on a GPU.  The yielded flows are
        identical to calling :meth:`decode_flows` at each address.
        """
        for address in range(start, end):
            try:
                yield self.decode_flows(binary, address)
            except ValueError:
                yield None

    def decode_control_flow_range(
        self, binary: "Binary", start: int, end: int
    ) -> Iterator[DecodedFlow]:
        """Yield the flows in ``[start, end)`` that can produce a reference.

        Straight-line instructions are skipped because their only flow is the
        fallthrough, which is never a cross-reference.  This is a filter over
        :meth:`decode_range`, so an override must not yield anything the
        default would have dropped.
        """
        for flow in self.decode_range(binary, start, end):
            if flow is None:
                continue
            if flow.type in (
                InstructionType.ARITHMETIC,
                InstructionType.NOP,
            ):
                continue
            yield flow

    def iter_pointer_references(
        self,
        binary: "Binary",
        start: int,
        end: int,
        targets: AbstractSet[int],
    ) -> Iterator[tuple[int, int]]:
        """Yield ``(address, target)`` for pointer readings of ``targets``.

        ``targets`` holds the addresses that are worth reporting.  The default
        implementation reads every address; an ISA may override this to scan a
        whole range at once.
        """
        for address in range(start, end):
            for pointer in self.try_interpret_as_pointer(binary, address):
                if (
                    pointer.kind is AddressKind.ABSOLUTE
                    and pointer.value in targets
                ):
                    yield address, pointer.value

    def iter_control_flow_references(
        self, binary: Binary, start: int, end: int, targets: AbstractSet[int],
    ) -> Iterator[tuple[int, int]]:
        """Yield cross-references to targets from decoded control flow."""
        for flow in self.decode_control_flow_range(binary, start, end):
            yield from flow.references(targets)

    def outline_call_target_bounds(self, first: int, last: int) -> tuple[int, int] | None:
        """Return inclusive bounds for a destination reachable from both call sites."""
        return None

    def jump_displacement_range(self) -> JumpRange:
        """Return non-wrapping bounds for the recompiler's fixed-width direct jump."""
        raise NotImplementedError(f"fixed-width direct jump placement is unavailable for {self.name}")

    def iter_address_references(
        self, binary: "Binary", start: int, end: int, targets: AbstractSet[int],
    ) -> Iterator[tuple[int, int]]:
        """Yield references formed by architecture-specific instruction sequences."""
        return iter(())

    def is_outlinable(self, instruction: Instruction) -> bool:
        """Return whether ``instruction`` may be moved into an outlined block."""
        return False

    def can_reorder_across(self, instruction: Instruction) -> bool:
        """Return whether dependency analysis may move code across this instruction."""
        return True

    def add_extra_stack_space(
        self, instruction: Instruction, pointer_size: int
    ) -> Instruction:
        """Return ``instruction`` with stack-relative operands biased.

        Outlined instructions run with ``pointer_size`` more bytes on the
        stack, so every stack-relative memory operand is shifted by that
        amount.  Raise :class:`ValueError` if the instruction cannot be
        re-encoded in place without changing its length or semantics.
        """
        raise ValueError(f"outlining is disabled for {self.name}")

    def make_call_instruction(self) -> Instruction:
        """Return a direct-call placeholder for an outline source site.

        The returned instruction is not yet targeted; the outliner patches it
        with :meth:`set_instruction_target` after placing the shared block.
        """
        raise ValueError(f"outlining is disabled for {self.name}")

    def make_return_instruction(self) -> Instruction:
        """Return a return instruction for the end of a shared block."""
        raise ValueError(f"outlining is disabled for {self.name}")

    def uses_red_zone(self, function: "Function") -> bool:
        """Return whether ``function`` accesses memory below the stack pointer."""
        return False

    def can_outline_region(
        self,
        function: "Function",
        block: "BasicBlock",
        instructions: list[Instruction],
        window_start: int,
        window_length: int,
    ) -> bool:
        """Return whether the call and return preserve state at the window.

        ``instructions`` is the block's instruction order after outlining
        reorders it, and the window is ``instructions[window_start:...]``.
        The default implementation allows every region; an ISA with a red zone
        overrides this to prove that the call's pushed return address does not
        overwrite a live stack value.
        """
        return True

    @abstractmethod
    def relocate_instruction(
        self, instruction: Instruction, new_base_address: int
    ) -> Instruction:
        """Re-encode ``instruction`` for ``new_base_address`` without growing it."""
        raise NotImplementedError

    @abstractmethod
    def set_instruction_target(
        self, instruction: Instruction, new_target_address: Address
    ) -> Instruction:
        """Re-encode a branch or call to target ``new_target_address``."""
        raise NotImplementedError

    @abstractmethod
    def can_encode(self, instruction: Instruction, address: int) -> bool:
        """Return whether ``instruction`` can be encoded at ``address``."""
        raise NotImplementedError

    @abstractmethod
    def required_length(self, instruction: Instruction, address: int) -> int:
        """Return the encoded length of ``instruction`` at ``address``."""
        raise NotImplementedError

    @abstractmethod
    def try_interpret_as_pointer(
        self, binary: "Binary", offset: int
    ) -> set[Address]:
        """Interpret bytes at ``offset`` as 64-bit and 32-bit addresses."""
        raise NotImplementedError

    def call_instruction_length(self) -> int:
        """Return the length of the call emitted at an outline source site."""
        raise ValueError(f"outlining is disabled for {self.name}")

    def ret_instruction_length(self) -> int:
        """Return the length of the return emitted at an outline target site."""
        raise ValueError(f"outlining is disabled for {self.name}")
