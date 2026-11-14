"""ISA encoding contract shared by the uplifter, optimizers, and ISAs.

The normative description lives in ``ir.md``.  This class is the interface each
concrete ISA implements; see :mod:`isa.x86_64` for the first implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, AbstractSet, ClassVar, Iterator

from ir import Address, AddressKind, Instruction, InstructionType

if TYPE_CHECKING:
    from binary.binary import Binary


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


class ISA(ABC):
    """Interface for an instruction-set architecture."""

    name: ClassVar[str] = ""
    supports_outlining: ClassVar[bool] = False

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

    @abstractmethod
    def is_outlinable(self, instruction: Instruction) -> bool:
        """Return whether ``instruction`` may be moved into an outlined block."""
        raise NotImplementedError

    @abstractmethod
    def add_extra_stack_space(
        self, instruction: Instruction, pointer_size: int
    ) -> Instruction:
        """Return ``instruction`` with stack-relative operands biased.

        Outlined instructions run with ``pointer_size`` more bytes on the
        stack, so every stack-relative memory operand is shifted by that
        amount.  Raise :class:`ValueError` if the instruction cannot be
        re-encoded in place without changing its length or semantics.
        """
        raise NotImplementedError

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

    @abstractmethod
    def call_instruction_length(self) -> int:
        """Return the length of the call emitted at an outline source site."""
        raise NotImplementedError

    @abstractmethod
    def ret_instruction_length(self) -> int:
        """Return the length of the return emitted at an outline target site."""
        raise NotImplementedError
