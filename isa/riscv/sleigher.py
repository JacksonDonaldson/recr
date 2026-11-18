"""RISC-V register, effect, and control-flow policy for the SLEIGH decoder."""

from __future__ import annotations

from functools import cached_property

from isa.isa import DecodedFlow
from isa.riscv.encoding import BRANCH, COMPRESSED_BRANCH, COMPRESSED_JUMP, JUMP, UPPER, relative_immediate, sign_extend
from isa.sleigher.sla import (
    OP_BRANCH, OP_BRANCHIND, OP_CALL, OP_CALLIND, OP_CBRANCH, OP_RETURN,
    ConstTpl, ResolvedConstructor, SlaError, SlaSpec, VarnodeInfo,
)
from ir import Address, InstructionType, StateSpace, StateSpaceKind


_LINK_REGISTERS = (1, 5)
_RAM = StateSpace(StateSpaceKind.MEMORY, "ram", 1)
_CSR = StateSpace(StateSpaceKind.MEMORY, "csreg", 1)
_TRAPS = frozenset({"ebreak", "c.ebreak", "ecall", "unimp"})
_EXCEPTION_RETURNS = frozenset({"dret", "mret", "sret", "uret"})
_CSR_ALIASES = frozenset({
    "fflags", "frm", "fcsr", "uepc", "sepc", "mepc", "dcsr", "dpc",
    "dscratch0", "dscratch1",
})
_GPRS = (
    "zero ra sp gp tp t0 t1 t2 s0 s1 a0 a1 a2 a3 a4 a5 a6 a7 "
    "s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 t3 t4 t5 t6"
).split()


class RISCVSlaSpec(SlaSpec):
    """Use assembler ABI register names and distinguish RAM from the CSR bank."""

    @staticmethod
    def _register_parent(name: str) -> None:
        return None
    _callee_saved_registers = frozenset({"sp", "gp", "tp", *(f"s{i}" for i in range(12))})
    _call_argument_registers = frozenset(
        {"sp", "gp", "tp", *(f"a{i}" for i in range(8)), *(f"fa{i}" for i in range(8))}
    )
    _opaque_transfer_mnemonics = frozenset()

    def _register_state(self, varnode: VarnodeInfo) -> StateSpace | None:
        if varnode.name in {"zero", "CONTEXT", "pc"}:
            return None
        if varnode.name in _CSR_ALIASES:
            return _CSR
        return StateSpace(StateSpaceKind.REGISTER, varnode.name, varnode.size)

    def _implicit_state_spaces(self) -> tuple[StateSpace, ...]:
        return _RAM, _CSR

    def _memory_state_for_access(self, space_id: ConstTpl) -> StateSpace:
        if space_id.kind != "spaceid" or space_id.value not in self.spaces:
            raise SlaError("invalid RISC-V P-code memory address space")
        if self.spaces[space_id.value].name == "csreg":
            return _CSR
        return _RAM

    def _state_space(self, location: tuple[int, int, int]) -> StateSpace | None:
        if self.spaces[location[0]].name == "csreg":
            return _CSR
        return super()._state_space(location)

    @cached_property
    def xlen(self) -> int:
        return 8 * self.spaces[self._space_index(self.default_space)].size

    def decode_flow(
        self, data: bytes, address: int, resolved: ResolvedConstructor
    ) -> DecodedFlow:
        length = resolved.length
        word = int.from_bytes(data[:length], "little")
        mnemonic = self.mnemonic(resolved).lower()
        mask = (1 << self.xlen) - 1
        next_address = Address.absolute((address + length) & mask)
        instruction_type = InstructionType.ARITHMETIC
        flows = [next_address]
        immediate = relative_immediate(word, length, self.xlen)
        if immediate is UPPER:
            instruction_type = InstructionType.PC_RELATIVE
        elif immediate is not None:
            target = Address.absolute((address + immediate.decode(word)) & mask)
            rd = (word >> 7) & 31
            is_call = (immediate is JUMP and rd in _LINK_REGISTERS) or (
                immediate is COMPRESSED_JUMP and word >> 13 == 1
            )
            if is_call:
                instruction_type = InstructionType.CALL
                flows = [target, next_address]
            else:
                instruction_type = InstructionType.BRANCH
                flows = [target]
                if immediate in (BRANCH, COMPRESSED_BRANCH):
                    flows.append(next_address)
        elif length == 4 and word & 0x7F == 0x67:
            rd, rs1 = (word >> 7) & 31, (word >> 15) & 31
            displacement = sign_extend(word >> 20, 12)
            if rd == 0 and rs1 in _LINK_REGISTERS and displacement == 0:
                instruction_type, flows = InstructionType.RET, []
            elif rd in _LINK_REGISTERS:
                instruction_type = InstructionType.CALL_INDIRECT
                target = Address.unknown_nonlocal() if rs1 else Address.absolute(displacement & mask & ~1)
                flows = [target, next_address]
            else:
                instruction_type = InstructionType.BRANCH
                flows = [Address.unknown_local() if rs1 else Address.absolute(displacement & mask & ~1)]
        elif mnemonic == "c.jalr":
            instruction_type = InstructionType.CALL_INDIRECT
            flows = [Address.unknown_nonlocal(), next_address]
        elif mnemonic == "c.jr":
            if (word >> 7) & 31 == 5:
                instruction_type, flows = InstructionType.RET, []
            else:
                instruction_type, flows = InstructionType.BRANCH, [Address.unknown_local()]
        elif mnemonic == "ret" or mnemonic in _EXCEPTION_RETURNS:
            instruction_type, flows = InstructionType.RET, []
        elif mnemonic == "unimp":
            instruction_type, flows = InstructionType.BRANCH, [Address.unknown_nonlocal()]
        elif mnemonic in _TRAPS:
            # The trap handler may resume execution at the next instruction.
            instruction_type = InstructionType.CALL_INDIRECT
            flows = [Address.unknown_nonlocal(), next_address]
        elif mnemonic in {"nop", "c.nop"} or word == 0x13:
            instruction_type = InstructionType.NOP
        else:
            # P-code can jump to labels inside its expansion or to the
            # instruction's own fallthrough, as for integer division.
            opcodes = {
                op.opcode for op, _ in self._semantic_ops(resolved)
                if op.opcode not in (OP_BRANCH, OP_CBRANCH)
                or op.inputs[0].offset.kind not in ("relative", "next")
            }
            if OP_RETURN in opcodes:
                instruction_type, flows = InstructionType.RET, []
            elif opcodes.intersection((OP_CALL, OP_CALLIND)):
                instruction_type = InstructionType.CALL_INDIRECT
                flows = [Address.unknown_nonlocal(), next_address]
            elif opcodes.intersection((OP_BRANCH, OP_BRANCHIND, OP_CBRANCH)):
                instruction_type = InstructionType.BRANCH
                flows = [Address.unknown_local()]
                if OP_CBRANCH in opcodes:
                    flows.append(next_address)
        return DecodedFlow(address, length, instruction_type, tuple(dict.fromkeys(flows)))

    def _compute_state_effects(
        self, data: bytes, flow: DecodedFlow, resolved: ResolvedConstructor, address: int
    ) -> tuple[tuple[StateSpace, ...], tuple[StateSpace, ...]]:
        mnemonic = self.mnemonic(resolved).lower()
        if resolved.constructor.template is None or mnemonic in _TRAPS | _EXCEPTION_RETURNS | {"wfi"}:
            states = self.all_state_spaces()
            return states, states

        writes, reads = super()._compute_state_effects(data, flow, resolved, address)
        word = int.from_bytes(data[:flow.length], "little")
        opcode = word & 0x7F
        funct3 = (word >> 12) & 7
        if mnemonic in ("fclass.s", "fclass.d") and (rd := (word >> 7) & 31):
            # The pinned P-code only reads rs1 and omits the write to rd.
            state = StateSpace(StateSpaceKind.REGISTER, _GPRS[rd], self.xlen // 8)
            writes = tuple(dict.fromkeys((*writes, state)))
        if flow.length == 4 and opcode == 0x73 and funct3 in (1, 2, 3, 5, 6, 7):
            rd, source = (word >> 7) & 31, (word >> 15) & 31
            if funct3 in (1, 5) or source:
                writes = tuple(dict.fromkeys((*writes, _CSR)))
            if funct3 not in (1, 5) or rd:
                reads = tuple(dict.fromkeys((*reads, _CSR)))
        # Floating-point computational operations can accrue exception
        # flags and use the dynamic rounding mode in the CSR bank.
        if flow.length == 4 and (
            opcode in (0x43, 0x47, 0x4B, 0x4F)
            or (opcode == 0x53 and word >> 27 not in (4, 5, 28, 30))
        ):
            writes = tuple(dict.fromkeys((*writes, _CSR)))
            reads = tuple(dict.fromkeys((*reads, _CSR)))
        if flow.type is InstructionType.RET:
            # The alternate link register also appears in SLEIGH as a jump.
            link = "t0" if (word >> (7 if flow.length == 2 else 15)) & 31 == 5 else "ra"
            reads = tuple(dict.fromkeys((*reads, StateSpace(StateSpaceKind.REGISTER, link, self.xlen // 8))))
        return writes, reads
