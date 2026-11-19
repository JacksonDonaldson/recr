"""Little-endian RV32 and RV64 decoding and fixed-width re-encoding."""

from __future__ import annotations

from collections.abc import Iterator, Set
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from struct import Struct
from typing import TYPE_CHECKING

from isa.isa import DecodedFlow, ISA
from isa.riscv.encoding import JUMP, UPPER, relative_immediate, sign_extend
from isa.riscv.liveness import link_live_before, live_block_exits
from isa.riscv.references import scan
from isa.riscv.sleigher import RISCVSlaSpec
from isa.sleigher.sla import ResolvedConstructor
from ir import Address, AddressKind, BasicBlock, Function, Instruction, InstructionType, StateSpace, StateSpaceKind

if TYPE_CHECKING:
    from binary.binary import Binary


_WORD = Struct("<I")
_DOUBLEWORD = Struct("<Q")


@lru_cache(maxsize=2)
def _load_spec(filename: str) -> RISCVSlaSpec:
    return RISCVSlaSpec(Path(__file__).with_name("ghidra") / filename)


class _RISCVISA(ISA):
    supports_outlining = True
    _sla_filename: str
    _mxl: int

    def __init__(self) -> None:
        self.spec = _load_spec(self._sla_filename)
        self.context = self.spec.build_context({"MXL": self._mxl})
        self.xlen = self.pointer_size * 8
        self.address_mask = (1 << self.xlen) - 1
        self._link = StateSpace(StateSpaceKind.REGISTER, "t0", self.pointer_size)
        self._outline_liveness: dict[
            int, tuple[tuple[list[Instruction], ...], set[int] | None]
        ] = {}

    def _check_address(self, address: int) -> None:
        if not 0 <= address <= self.address_mask or address % 2:
            raise ValueError(f"invalid RV{self.xlen} instruction address {address:#x}")

    def _read_instruction(self, binary: Binary, address: int) -> bytes:
        self._check_address(address)
        first = binary.read(address, 2)
        if len(first) != 2:
            raise ValueError(f"truncated instruction at {address:#x}")
        if first[0] & 3 != 3:
            return first
        if first[0] & 0x1F == 0x1F:
            raise ValueError(f"unsupported instruction length at {address:#x}")
        self._check_address(address + 2)
        return first + binary.read(address + 2, 2)

    def _resolve(self, data: bytes, address: int) -> ResolvedConstructor:
        if len(data) >= 2:
            length = 4 if data[0] & 3 == 3 else 2
            if len(data) == length and data[0] & 0x1F != 0x1F:
                resolved = self.spec.resolve(data, self.context)
                if resolved is not None and resolved.length == length:
                    if length == 2:
                        word = int.from_bytes(data, "little")
                        rd = (word >> 7) & 31
                        funct3 = word >> 13
                        if rd == 0 and (
                            word == 0x8002
                            or (word & 3 == 1 and funct3 == 1 and self.xlen == 64)
                            or (word & 3 == 2 and funct3 in ((2, 3) if self.xlen == 64 else (2,)))
                        ):
                            raise ValueError(f"reserved RISC-V instruction at {address:#x}: {data.hex()}")
                    return resolved
        raise ValueError(f"invalid RISC-V instruction at {address:#x}: {data.hex()}")

    def disassemble(self, binary: Binary, address: int) -> Instruction:
        data = self._read_instruction(binary, address)
        return self.spec.make_instruction(data, address, self._resolve(data, address), self.context)

    def decode_flows(self, binary: Binary, address: int) -> DecodedFlow:
        data = self._read_instruction(binary, address)
        return self.spec.decode_flow(data, address, self._resolve(data, address))

    def decode_range(
        self, binary: Binary, start: int, end: int,
    ) -> Iterator[DecodedFlow | None]:
        if start >= end:
            return
        data = self._read_scan_range(binary, start, end)
        if data is None or start < 0 or end - 1 > self.address_mask:
            yield from super().decode_range(binary, start, end)
            return

        # Leave the final parcel to the scalar decoder, which can read across
        # the end of the requested interval if the next bytes are mapped.
        bulk_end = max(start, end - 3)
        for address in range(start, bulk_end):
            if address & 1:
                yield None
                continue
            offset = address - start
            first = data[offset]
            if first & 0x1F == 0x1F:
                yield None
                continue
            length = 4 if first & 3 == 3 else 2
            raw = data[offset:offset + length]
            try:
                yield self.spec.decode_flow(raw, address, self._resolve(raw, address))
            except ValueError:
                yield None

        yield from super().decode_range(binary, bulk_end, end)

    @staticmethod
    def _read_scan_range(binary: Binary, start: int, end: int) -> bytes | None:
        try:
            data = binary.read(start, end - start)
        except ValueError:
            return None
        return data if len(data) == end - start else None

    def _ordinary_instruction(self, instruction: Instruction) -> bool:
        """Recognize scalar forms whose GPR destinations are definite writes."""
        if instruction.type is not InstructionType.ARITHMETIC:
            return False
        if instruction.length == 2:
            resolved = self._resolve(instruction.original_data, instruction.address)
            return self.spec.mnemonic(resolved).lower() in {
                "c.add", "c.addi", "c.addi16sp", "c.addi4spn", "c.addiw", "c.addw",
                "c.and", "c.andi", "c.li", "c.lui", "c.mv", "c.or", "c.slli", "c.srai",
                "c.srli", "c.sub", "c.subw", "c.xor", "c.lw", "c.lwsp", "c.ld",
                "c.ldsp", "c.sw", "c.swsp", "c.sd", "c.sdsp", "c.fld", "c.fldsp",
                "c.flw", "c.flwsp", "c.fsd", "c.fsdsp", "c.fsw", "c.fswsp",
            }
        opcode = instruction.original_data[0] & 0x7F
        if opcode in (0x07, 0x27):
            return (instruction.original_data[1] >> 4) & 7 in (2, 3)
        return opcode in (0x03, 0x13, 0x1B, 0x23, 0x33, 0x37, 0x3B)

    def _definitely_writes_link(self, instruction: Instruction) -> bool:
        return self._link in instruction.modifies and (
            instruction.type is InstructionType.PC_RELATIVE
            or self._ordinary_instruction(instruction)
        )

    def is_outlinable(self, instruction: Instruction) -> bool:
        return (
            self._ordinary_instruction(instruction)
            and self._link not in instruction.modifies
            and self._link not in instruction.depends_on
            and instruction.flows_to == [Address.absolute(instruction.address + instruction.length)]
        )

    def can_reorder_across(self, instruction: Instruction) -> bool:
        return instruction.type is InstructionType.NOP or self._ordinary_instruction(instruction)

    def can_outline_region(
        self, function: Function, block: BasicBlock, instructions: list[Instruction],
        window_start: int, window_length: int,
    ) -> bool:
        window_end = window_start + window_length
        if any(not self.is_outlinable(item) for item in instructions[window_start:window_end]):
            return False
        lists = tuple(item.instructions for item in function.basic_blocks)
        cached = self._outline_liveness.get(id(function))
        if cached is None or len(cached[0]) != len(lists) or any(
            old is not new for old, new in zip(cached[0], lists)
        ):
            # An inserted jump can break the forward-progress guarantees of
            # a constrained LR/SC loop, even though it leaves RAM unchanged.
            has_reservation = any(
                item.length == 4 and item.original_data[0] & 0x7F == 0x2F
                and item.original_data[3] >> 3 in (2, 3)
                for items in lists for item in items
            )
            exits = None if has_reservation else live_block_exits(
                function, self._definitely_writes_link,
            )
            self._outline_liveness[id(function)] = lists, exits
        else:
            exits = cached[1]
        if exits is None:
            return False
        live = block.start_location.value in exits
        for item in reversed(instructions[window_end:]):
            live = link_live_before(item, live, self._definitely_writes_link)
        return not live

    def add_extra_stack_space(self, instruction: Instruction, pointer_size: int) -> Instruction:
        # JAL sets t0 without pushing a return address.
        return instruction

    def make_call_instruction(self) -> Instruction:
        return Instruction(b"\xef\x02\x00\x00", InstructionType.OUTLINE_RESULT_CALL, 4, modifies=[self._link])

    def make_return_instruction(self) -> Instruction:
        return Instruction(b"\x67\x80\x02\x00", InstructionType.RET, 4, depends_on=[self._link])

    def call_instruction_length(self) -> int:
        return 4

    def ret_instruction_length(self) -> int:
        return 4

    def _encode(self, instruction: Instruction, address: int, target: int | None) -> Instruction:
        self._check_address(address)
        data = instruction.original_data
        original = self._resolve(data, instruction.address)
        if original.length != instruction.length:
            raise ValueError("invalid RISC-V instruction length")
        word = int.from_bytes(data, "little")
        immediate = relative_immediate(word, original.length, self.xlen)
        if target is not None and (immediate is None or immediate is UPPER):
            raise ValueError("instruction has no direct branch or call target")
        if address != instruction.address:
            if original.constructor.template is None:
                raise ValueError("cannot relocate an instruction with opaque semantics")
            if immediate is JUMP or (original.length == 4 and word & 0x7F == 0x67):
                rd = (word >> 7) & 31
                if rd not in (0, 1, 5):
                    raise ValueError("cannot relocate an explicit non-ABI link value")
            if immediate is None and self.spec.mnemonic(original).lower() in {
                "ecall", "ebreak", "c.ebreak", "unimp", "dret", "mret", "sret", "uret",
            }:
                raise ValueError("cannot relocate a trap or exception transfer")
        if immediate is not None:
            if target is None:
                target = (instruction.address + immediate.decode(word)) & self.address_mask
            displacement = sign_extend((target - address) & self.address_mask, self.xlen)
            patched = immediate.encode(word, displacement)
            data = patched.to_bytes(original.length, "little")

        resolved = self._resolve(data, address)
        flow = self.spec.decode_flow(data, address, resolved)
        expected_type = (
            InstructionType.CALL if instruction.type is InstructionType.OUTLINE_RESULT_CALL
            else instruction.type
        )
        if flow.type is not expected_type:
            raise ValueError("re-encoding changed the instruction type")
        return replace(instruction, address=address, original_data=data, flows_to=list(flow.flows_to))

    def relocate_instruction(self, instruction: Instruction, new_base_address: int) -> Instruction:
        return self._encode(instruction, new_base_address, None)

    def set_instruction_target(self, instruction: Instruction, new_target_address: Address) -> Instruction:
        if new_target_address.kind is not AddressKind.ABSOLUTE:
            raise ValueError("instruction target must be an absolute address")
        self._check_address(new_target_address.value)
        return self._encode(instruction, instruction.address, new_target_address.value)

    def can_encode(self, instruction: Instruction, address: int) -> bool:
        try:
            self._encode(instruction, address, None)
        except ValueError:
            return False
        return True

    def required_length(self, instruction: Instruction, address: int) -> int:
        return self._encode(instruction, address, None).length

    def try_interpret_as_pointer(self, binary: Binary, offset: int) -> set[Address]:
        pointers = set()
        for width in {4, self.pointer_size}:
            try:
                data = binary.read(offset, width)
            except ValueError:
                continue
            if len(data) == width:
                pointers.add(Address.absolute(int.from_bytes(data, "little")))
        return pointers

    def iter_pointer_references(
        self, binary: Binary, start: int, end: int, targets: Set[int],
    ) -> Iterator[tuple[int, int]]:
        if not targets or start >= end:
            return
        data = self._read_scan_range(binary, start, end)
        if data is None:
            yield from super().iter_pointer_references(binary, start, end, targets)
            return

        # A 64-bit reading below 2**32 duplicates its low 32-bit reading.
        wide_targets = (
            {target for target in targets if target >= 1 << 32}
            if self.pointer_size == 8 else set()
        )
        width = _DOUBLEWORD.size if wide_targets else _WORD.size
        limit = max(0, len(data) - width + 1)
        for offset in range(limit):
            word, = _WORD.unpack_from(data, offset)
            if word in targets:
                yield start + offset, word
            if wide_targets:
                doubleword, = _DOUBLEWORD.unpack_from(data, offset)
                if doubleword in wide_targets:
                    yield start + offset, doubleword

        yield from super().iter_pointer_references(binary, start + limit, end, targets)

    def iter_address_references(
        self, binary: Binary, start: int, end: int, targets: Set[int],
    ) -> Iterator[tuple[int, int]]:
        return scan(binary, start, end, targets, self.xlen, binary.symbol_address("__global_pointer$"))


class RISCV32ISA(_RISCVISA):
    name = "riscv32"
    pointer_size = 4
    _sla_filename = "riscv.ilp32d.sla"
    _mxl = 1


class RISCV64ISA(_RISCVISA):
    name = "riscv64"
    pointer_size = 8
    _sla_filename = "riscv.lp64d.sla"
    _mxl = 2
