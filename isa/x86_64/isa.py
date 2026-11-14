"""x86-64 ISA backend.

Disassembly and IR are driven by Ghidra's x86-64 SLEIGH specification.  The
backend also knows how to bias explicit stack-relative memory operands, which
the outliner needs when it moves instructions into a block that runs with a
different stack pointer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Iterator

from ir import (
    Address,
    AddressKind,
    Instruction,
    InstructionType,
    StateSpaceKind,
)
from isa.isa import DecodedFlow, ISA
from isa.sleigher import X86Sleigher
from isa.sleigher.sla import ResolvedConstructor, ResolvedOperand

if TYPE_CHECKING:
    from binary.binary import Binary


class _NotAdjustable(ValueError):
    """Raised when a stack-relative operand cannot be biased in place."""


@dataclass(frozen=True)
class _StackDisplacement:
    """An encoded displacement field that must be shifted."""

    offset: int
    size: int
    value: int


class X86_64ISA(ISA):
    """x86-64 instruction decoding and relinking."""

    name = "x86_64"
    supports_outlining = True
    pointer_size = 8

    # x86 instructions are at most 15 bytes.
    _MAX_INSTRUCTION_LENGTH = 15

    _NON_OUTLINABLE_TYPES = frozenset(
        {
            InstructionType.CALL,
            InstructionType.CALL_INDIRECT,
            InstructionType.BRANCH,
            InstructionType.RET,
            InstructionType.OUTLINE_RESULT_CALL,
        }
    )

    # The SLEIGH decoder classifies these traps and control transfers as
    # ARITHMETIC because it trusts the printed mnemonic.  They are not
    # straight-line instructions: they trap, halt, or transfer control through
    # a table that is not part of the instruction stream.
    _NON_OUTLINABLE_MNEMONICS = frozenset(
        {
            "GETSEC",
            "HLT",
            "INT",
            "INT1",
            "INT3",
            "INTO",
            "RSM",
            "SKINIT",
            "STGI",
            "CLGI",
            "SYSCALL",
            "SYSENTER",
            "SYSEXIT",
            "SYSRET",
            "UD0",
            "UD1",
            "UD2",
            "UIRET",
            "VMCALL",
            "VMLAUNCH",
            "VMMCALL",
            "VMRESUME",
            "VMRUN",
            "VMXOFF",
            "XABORT",
            "XBEGIN",
        }
    )

    _LEGACY_PREFIXES = frozenset(
        {
            0x26,
            0x2E,
            0x36,
            0x3E,
            0x64,
            0x65,
            0x66,
            0x67,
            0xF0,
            0xF2,
            0xF3,
        }
    )

    def __init__(self) -> None:
        self._sleigher = X86Sleigher()

    def disassemble(self, binary: "Binary", address: int) -> Instruction:
        data = self._read_instruction_bytes(binary, address)
        instruction = self._sleigher.parse(data, address)
        if instruction is None:
            raise ValueError(f"cannot decode instruction at {address:#x}")
        return instruction

    def decode_flows(self, binary: "Binary", address: int) -> DecodedFlow:
        data = self._read_instruction_bytes(binary, address)
        flow = self._sleigher.parse_flow(data, address)
        if flow is None:
            raise ValueError(f"cannot decode instruction at {address:#x}")
        return flow

    def is_outlinable(self, instruction: Instruction) -> bool:
        if instruction.type in self._NON_OUTLINABLE_TYPES:
            return False
        if not self._is_fallthrough(instruction):
            return False
        if self._modifies_rsp(instruction):
            return False

        try:
            resolved = self._resolve(instruction)
            mnemonic = self._sleigher.spec.mnemonic(resolved).upper()
            if mnemonic in self._NON_OUTLINABLE_MNEMONICS:
                return False
            if self._uses_rsp_as_value(resolved, instruction.original_data):
                return False
            self._stack_displacements(
                resolved, instruction.original_data, self.pointer_size
            )
        except _NotAdjustable:
            return False
        return True

    def add_extra_stack_space(
        self, instruction: Instruction, pointer_size: int
    ) -> Instruction:
        if pointer_size < 0:
            raise ValueError("pointer size must be non-negative")
        if pointer_size == 0:
            return self._copy_instruction(instruction)

        resolved = self._resolve(instruction)
        if self._uses_rsp_as_value(resolved, instruction.original_data):
            raise _NotAdjustable(
                "instruction uses RSP as a value, not only as an address base"
            )

        displacements = self._stack_displacements(
            resolved, instruction.original_data, pointer_size
        )
        if not displacements:
            return self._copy_instruction(instruction)

        data = bytearray(instruction.original_data)
        for displacement in displacements:
            try:
                encoded = displacement.value.to_bytes(
                    displacement.size, "little", signed=True
                )
            except OverflowError as exc:
                raise _NotAdjustable(
                    "stack displacement does not fit in its encoding"
                ) from exc
            data[
                displacement.offset : displacement.offset + displacement.size
            ] = encoded

        adjusted = bytes(data)
        self._verify_adjustment(instruction, adjusted)
        return self._copy_instruction(instruction, original_data=adjusted)

    def relocate_instruction(
        self, instruction: Instruction, new_base_address: int
    ) -> Instruction:
        relocated = self._sleigher.reassemble(instruction, new_base_address)
        if relocated is None:
            raise ValueError(
                f"cannot relocate instruction to {new_base_address:#x}"
            )
        return relocated

    def set_instruction_target(
        self, instruction: Instruction, new_target_address: Address
    ) -> Instruction:
        raise NotImplementedError

    def can_encode(self, instruction: Instruction, address: int) -> bool:
        return self._sleigher.reassemble(instruction, address) is not None

    def required_length(self, instruction: Instruction, address: int) -> int:
        relocated = self._sleigher.reassemble(instruction, address)
        if relocated is None:
            raise ValueError(f"cannot encode instruction at {address:#x}")
        return relocated.length

    def try_interpret_as_pointer(
        self, binary: "Binary", offset: int
    ) -> set[Address]:
        """Return 64-bit and 32-bit little-endian readings at ``offset``.

        Each width is read independently so a 32-bit value near the end of a
        mapped range is still recovered when a full pointer-sized read would
        cross into unmapped memory.  Unreadable widths contribute nothing.
        """
        pointers: set[Address] = set()
        if offset < 0:
            return pointers

        for size in (self.pointer_size, 4):
            try:
                data = binary.read(offset, size)
            except ValueError:
                continue
            if len(data) != size:
                continue
            pointers.add(
                Address.absolute(int.from_bytes(data, "little", signed=False))
            )
        return pointers

    def call_instruction_length(self) -> int:
        raise NotImplementedError

    def ret_instruction_length(self) -> int:
        raise NotImplementedError

    @classmethod
    def _read_instruction_bytes(
        cls, binary: "Binary", address: int
    ) -> bytes:
        """Read up to one instruction without crossing mapped memory.

        ``Binary.read`` rejects a request that crosses into unmapped virtual
        memory.  Shrink the request until it fits so an instruction at the end
        of a mapped segment can still be decoded.
        """
        last_error: ValueError | None = None
        for length in range(cls._MAX_INSTRUCTION_LENGTH, 0, -1):
            try:
                data = binary.read(address, length)
            except ValueError as exc:
                last_error = exc
                continue
            if len(data) >= length:
                return data
        raise ValueError(
            f"cannot read instruction bytes at {address:#x}"
        ) from last_error

    def _resolve(self, instruction: Instruction) -> ResolvedConstructor:
        resolved = self._sleigher.spec.resolve(
            instruction.original_data, self._sleigher.context
        )
        if resolved is None:
            raise _NotAdjustable("instruction cannot be resolved")
        return resolved

    @staticmethod
    def _copy_instruction(
        instruction: Instruction, *, original_data: bytes | None = None
    ) -> Instruction:
        return replace(
            instruction,
            original_data=(
                instruction.original_data
                if original_data is None
                else original_data
            ),
            modifies=list(instruction.modifies),
            depends_on=list(instruction.depends_on),
            flows_from=list(instruction.flows_from),
            flows_to=list(instruction.flows_to),
        )

    @staticmethod
    def _is_fallthrough(instruction: Instruction) -> bool:
        if not instruction.flows_from and not instruction.flows_to:
            return True
        if len(instruction.flows_to) != 1:
            return False

        target = instruction.flows_to[0]
        if target.kind is not AddressKind.ABSOLUTE:
            return False

        if instruction.flows_from:
            if len(instruction.flows_from) != 1:
                return False
            source = instruction.flows_from[0]
            if source.kind is not AddressKind.ABSOLUTE:
                return False
            return target.value == source.value + instruction.length

        # flows_from is filled in by the code-flow recovery pass, so accept a
        # single fallthrough edge before that pass has run.
        return target.value == instruction.address + instruction.length

    @staticmethod
    def _modifies_rsp(instruction: Instruction) -> bool:
        return any(
            state.kind is StateSpaceKind.REGISTER and state.name == "RSP"
            for state in instruction.modifies
        )

    def _verify_adjustment(
        self, instruction: Instruction, adjusted: bytes
    ) -> None:
        decoded = self._sleigher.parse(adjusted, instruction.address)
        if decoded is None or decoded.length != instruction.length:
            raise _NotAdjustable(
                "adjusted instruction does not decode to the same length"
            )
        if decoded.type is not instruction.type:
            raise _NotAdjustable(
                "adjusted instruction changes its instruction type"
            )

    def _stack_displacements(
        self,
        resolved: ResolvedConstructor,
        data: bytes,
        pointer_size: int,
    ) -> list[_StackDisplacement]:
        displacements: list[_StackDisplacement] = []
        for operand in self._address_operands(resolved):
            base = self._base_register(operand, data)
            # Only RSP changes when the outliner replaces the source region
            # with a call.  RBP is callee-saved and must keep its displacement.
            if base != "RSP":
                continue

            field = self._modrm_displacement(data, operand.offset)
            if field is None:
                raise _NotAdjustable(
                    "stack-relative operand has no displacement field"
                )
            size, offset = field
            if size == 1 and self._starts_with_evex(data):
                # EVEX disp8 is compressed by the instruction's tuple size.
                # The pinned SLEIGH specification does not expose that size
                # reliably for every form, so reject rather than risk
                # encoding the wrong effective address.
                raise _NotAdjustable(
                    "EVEX compressed displacement is not supported"
                )

            if offset + size > len(data):
                raise _NotAdjustable("displacement extends past instruction")

            current = int.from_bytes(
                data[offset : offset + size], "little", signed=True
            )
            value = current + pointer_size
            if size == 1 and not -0x80 <= value <= 0x7F:
                raise _NotAdjustable(
                    "stack displacement no longer fits in disp8"
                )
            if size == 4 and not -0x80000000 <= value <= 0x7FFFFFFF:
                raise _NotAdjustable(
                    "stack displacement no longer fits in disp32"
                )
            displacements.append(_StackDisplacement(offset, size, value))
        return displacements

    def _address_operands(
        self, resolved: ResolvedConstructor
    ) -> Iterator[ResolvedOperand]:
        for operand in resolved.operands:
            child = operand.resolved
            if child is None:
                continue
            if self._is_address_operand(operand, child):
                yield operand
            yield from self._address_operands(child)

    @staticmethod
    def _is_address_operand(
        operand: ResolvedOperand, resolved: ResolvedConstructor
    ) -> bool:
        name = operand.operand.name.lower()
        if name.startswith(("addr", "vaddr", "bndmk_addr")):
            return True
        return any(
            kind == "text" and value == "["
            for kind, value in resolved.constructor.print_pieces
        )

    def _base_register(
        self, operand: ResolvedOperand, data: bytes
    ) -> str | None:
        if operand.resolved is None:
            return None
        for child in operand.resolved.operands:
            name = child.operand.name.lower()
            if not name.startswith(("base", "rmr")):
                continue
            location = self._sleigher.spec._location_for_operand(
                child, data, operand.resolved.context
            )
            if location is None:
                continue
            state = self._sleigher.spec._state_space(
                (location.space_index, location.offset, location.size)
            )
            if (
                state is not None
                and state.kind is StateSpaceKind.REGISTER
            ):
                return state.name
        return None

    @classmethod
    def _starts_with_evex(cls, data: bytes) -> bool:
        """Return whether the instruction begins with an EVEX prefix.

        EVEX may follow legacy prefixes such as 0x67 or 0x64, so the check
        must skip them before looking for 0x62.
        """
        for byte in data:
            if byte in cls._LEGACY_PREFIXES:
                continue
            return byte == 0x62
        return False

    @staticmethod
    def _modrm_displacement(
        data: bytes, offset: int
    ) -> tuple[int, int] | None:
        """Return ``(size, offset)`` for the ModRM displacement field."""
        if offset >= len(data):
            raise _NotAdjustable("address operand is outside the instruction")

        modrm = data[offset]
        mod = modrm >> 6
        rm = modrm & 7
        if mod == 3:
            return None

        position = offset + 1
        if rm == 4:
            if position >= len(data):
                raise _NotAdjustable("missing SIB byte")
            sib = data[position]
            position += 1
            base = sib & 7
            if mod == 0 and base == 5:
                return 4, position
        elif rm == 5 and mod == 0:
            return 4, position

        if mod == 0:
            return None
        if mod == 1:
            return 1, position
        return 4, position

    def _uses_rsp_as_value(
        self, resolved: ResolvedConstructor, data: bytes
    ) -> bool:
        def walk(
            constructor: ResolvedConstructor, in_address: bool
        ) -> bool:
            for operand in constructor.operands:
                child = operand.resolved
                is_address = (
                    child is not None
                    and self._is_address_operand(operand, child)
                )
                if child is not None:
                    if walk(child, in_address or is_address):
                        return True
                    continue
                if in_address:
                    continue
                location = self._sleigher.spec._location_for_operand(
                    operand, data, constructor.context
                )
                if location is None:
                    continue
                state = self._sleigher.spec._state_space(
                    (location.space_index, location.offset, location.size)
                )
                if (
                    state is not None
                    and state.kind is StateSpaceKind.REGISTER
                    and state.name == "RSP"
                ):
                    return True
            return False

        return walk(resolved, False)
