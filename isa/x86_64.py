"""x86-64 ISA backend.

This will be implemented with Capstone.  Every method is currently a stub.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ir import Address, Instruction
from isa.isa import ISA

if TYPE_CHECKING:
    from binary.binary import Binary


class X86_64ISA(ISA):
    """x86-64 instruction decoding and relinking."""

    name = "x86_64"
    supports_outlining = True

    def __init__(self) -> None:
        # TODO: initialize the Capstone handle and configure detail mode.
        pass

    def disassemble(self, binary: "Binary", address: int) -> Instruction:
        raise NotImplementedError

    def relocate_instruction(
        self, instruction: Instruction, new_base_address: int
    ) -> Instruction:
        raise NotImplementedError

    def set_instruction_target(
        self, instruction: Instruction, new_target_address: Address
    ) -> Instruction:
        raise NotImplementedError

    def can_encode(self, instruction: Instruction, address: int) -> bool:
        raise NotImplementedError

    def required_length(self, instruction: Instruction, address: int) -> int:
        raise NotImplementedError

    def try_interpret_as_pointer(
        self, binary: "Binary", offset: int
    ) -> Optional[Address]:
        raise NotImplementedError

    def call_instruction_length(self) -> int:
        raise NotImplementedError

    def ret_instruction_length(self) -> int:
        raise NotImplementedError
