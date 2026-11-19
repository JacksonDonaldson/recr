"""x86-64 ISA backend.

Disassembly and IR are driven by Ghidra's x86-64 SLEIGH specification.  The
backend also knows how to bias explicit stack-relative memory operands, which
the outliner needs when it moves instructions into a block that runs with a
different stack pointer.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, AbstractSet, Iterator

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
    from ir import BasicBlock, Function
    # ``gpu`` is imported lazily inside the range methods: it pulls in the
    # SLEIGH parser, which imports this package.
    import gpu


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

    # A block reached with more distinct stack states than this is too
    # ambiguous to prove anything about.
    _MAX_STACK_STATES = 8

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
    #
    # ENDBR is kept at function entry points: moving it into a shared block
    # would leave indirect branch targets without the mark required by CET.
    _NON_OUTLINABLE_MNEMONICS = frozenset(
        {
            "ENDBR32",
            "ENDBR64",
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
        self._gpu_tables: gpu.GpuTables | None = None
        self._gpu_device: gpu.Device | None = None
        self._gpu_binary: object | None = None
        self._gpu_revision = -1
        # The outliner asks about the same function many times.  Functions are
        # not mutated during the planning pass, so the red-zone verdict and
        # block-entry states are stable for the life of the object.
        self._outline_red_zone: dict[int, bool] = {}
        self._outline_states: dict[
            int, dict[int, set[tuple[int, int | None]]] | None
        ] = {}

    def disassemble(self, binary: "Binary", address: int) -> Instruction:
        data = self._read_instruction_bytes(binary, address)
        instruction = self._sleigher.parse(data, address)
        if instruction is None:
            raise ValueError(f"cannot decode instruction at {address:#x} as x86-64. Available bytes are {data.hex(' ') or '<none>'}")
        return instruction

    def decode_flows(self, binary: "Binary", address: int) -> DecodedFlow:
        data = self._read_instruction_bytes(binary, address)
        flow = self._sleigher.parse_flow(data, address)
        if flow is None:
            raise ValueError(f"cannot decode instruction at {address:#x} as x86-64. Available bytes are {data.hex(' ') or '<none>'}")
        return flow

    # ------------------------------------------------------------ range scans

    # Addresses are handed to the device in batches so the scratch buffers stay
    # small on very large images.
    _RANGE_CHUNK = 1 << 20

    def tables(self) -> gpu.GpuTables:
        """Return the flattened decode tables for this specification."""
        import gpu

        if self._gpu_tables is None:
            self._gpu_tables = gpu.build_tables(self._sleigher.spec)
        return self._gpu_tables

    def device(self, binary: "Binary") -> gpu.Device | None:
        """Return a CUDA device holding ``binary``, or ``None``.

        The device caches the image, so it is rebuilt whenever the binary is
        patched.  Anything that cannot be uploaded falls back to the CPU.
        """
        import gpu

        if not hasattr(binary, "mapped_segments") or not gpu.available():
            return None
        revision = binary.image_revision()
        if self._gpu_binary is binary and self._gpu_revision == revision:
            return self._gpu_device

        self._gpu_device = None
        self._gpu_binary = None
        try:
            segments = [
                gpu.Segment(*values) for values in binary.mapped_segments()
            ]
            device = gpu.Device(
                self.tables().blob, binary.image_bytes(), segments
            )
        except (gpu.BackendError, ValueError):
            return None

        self._gpu_device = device
        self._gpu_binary = binary
        self._gpu_revision = revision
        return device

    def _gpu_chunks(
        self, device: gpu.Device, start: int, end: int
    ) -> Iterator[tuple]:
        tables = self.tables()
        context = self._sleigher.context
        position = start
        while position < end:
            count = min(self._RANGE_CHUNK, end - position)
            avail = device.check_addresses(position, count)
            batch = device.decode_range(
                position, count, avail, tables.root, context
            )
            yield (position,) + batch
            position += count

    @staticmethod
    def _flow_from(
        position: int, index: int, types, lengths, targets, kinds
    ) -> DecodedFlow:
        """Build one flow from the kernel's per-address columns."""
        import gpu

        length = lengths[index * 2] | (lengths[index * 2 + 1] << 8)
        values: list[Address] = []
        for slot in (0, 1):
            kind = kinds[index * 2 + slot]
            if kind == gpu.KIND_NONE:
                continue
            if kind == gpu.KIND_ABSOLUTE:
                values.append(Address.absolute(targets[index * 2 + slot]))
            elif kind == gpu.KIND_UNK_LOCAL:
                values.append(Address.unknown_local())
            else:
                values.append(Address.unknown_nonlocal())
        return DecodedFlow(
            address=position + index,
            length=length,
            type=gpu.tables.TYPE_FROM_CODE[types[index]],
            flows_to=tuple(values),
        )

    def decode_range(
        self, binary: "Binary", start: int, end: int
    ) -> Iterator[DecodedFlow | None]:
        import gpu

        device = self.device(binary)
        if device is None:
            yield from super().decode_range(binary, start, end)
            return

        tables = self.tables()
        for position, status, types, lengths, targets, kinds in (
            self._gpu_chunks(device, start, end)
        ):
            for index, state in enumerate(status):
                address = position + index
                if state == gpu.STATUS_DEFER:
                    yield self._defer(binary, address)
                    continue
                if state == gpu.STATUS_UNDECODED:
                    yield None
                    continue
                yield self._flow_from(
                    position, index, types, lengths, targets, kinds
                )

    def _defer(self, binary: "Binary", address: int) -> DecodedFlow | None:
        data = self._read_instruction_bytes(binary, address)
        return self._sleigher.parse_flow(data, address)

    def decode_control_flow_range(
        self, binary: "Binary", start: int, end: int
    ) -> Iterator[DecodedFlow]:
        import gpu

        device = self.device(binary)
        if device is None:
            yield from super().decode_control_flow_range(binary, start, end)
            return

        for position, status, types, lengths, targets, kinds in (
            self._gpu_chunks(device, start, end)
        ):
            index = status.find(gpu.STATUS_FLOW)
            while index != -1:
                yield self._flow_from(
                    position, index, types, lengths, targets, kinds
                )
                index = status.find(gpu.STATUS_FLOW, index + 1)

            index = status.find(gpu.STATUS_DEFER)
            while index != -1:
                flow = self._defer(binary, position + index)
                if flow is not None and flow.type not in (
                    InstructionType.ARITHMETIC,
                    InstructionType.NOP,
                ):
                    yield flow
                index = status.find(gpu.STATUS_DEFER, index + 1)

    def iter_pointer_references(
        self,
        binary: "Binary",
        start: int,
        end: int,
        targets: AbstractSet[int],
    ) -> Iterator[tuple[int, int]]:
        device = self.device(binary)
        if not targets:
            return
        if device is None:
            yield from super().iter_pointer_references(
                binary, start, end, targets
            )
            return

        entries = sorted(targets)
        position = start
        while position < end:
            count = min(self._RANGE_CHUNK, end - position)
            for address, target in sorted(
                device.scan_pointers(position, count, entries)
            ):
                yield address, target
            position += count

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

    def make_call_instruction(self) -> Instruction:
        """Return a zero-displacement ``call rel32`` placeholder."""
        decoded = self._sleigher.parse(bytes.fromhex("e800000000"), 0)
        if decoded is None:
            raise ValueError("cannot decode the outline call template")
        return replace(
            decoded,
            type=InstructionType.OUTLINE_RESULT_CALL,
            address=0,
            outline_target=None,
            flows_from=[],
            flows_to=[],
        )

    def make_return_instruction(self) -> Instruction:
        """Return a one-byte ``ret``."""
        decoded = self._sleigher.parse(b"\xc3", 0)
        if decoded is None:
            raise ValueError("cannot decode the outline return template")
        return replace(
            decoded,
            address=0,
            outline_target=None,
            flows_from=[],
            flows_to=[],
        )

    def uses_red_zone(self, function: "Function") -> bool:
        """Return whether a function accesses memory below the stack pointer.

        RSP and RBP are tracked as offsets from the RSP at function entry.
        A frame-pointer function that never subtracts from RSP keeps its locals
        in the red zone even though they are addressed through RBP, so checking
        only explicit RSP operands is not enough.
        """
        blocks = function.basic_blocks
        if not blocks:
            return False

        by_start = {block.start_location.value: block for block in blocks}
        entry = blocks[0].start_location.value
        pending: deque[tuple[int, int, int | None]] = deque(
            [(entry, 0, None)]
        )
        seen: dict[int, set[tuple[int, int | None]]] = {}
        visited: set[int] = set()

        while pending:
            start, rsp_delta, rbp_delta = pending.popleft()
            block = by_start.get(start)
            if block is None:
                continue
            state = (rsp_delta, rbp_delta)
            states = seen.setdefault(start, set())
            if state in states:
                continue
            if len(states) >= self._MAX_STACK_STATES:
                return True
            states.add(state)
            visited.add(start)

            current_rsp = rsp_delta
            current_rbp = rbp_delta
            for instruction in block.instructions:
                if self._accesses_below_rsp(
                    instruction, current_rsp, current_rbp
                ):
                    return True
                effect = self._stack_effect(
                    instruction, current_rsp, current_rbp
                )
                if effect is None:
                    return True
                current_rsp, current_rbp = effect

            last = block.instructions[-1]
            for target in last.flows_to:
                if target.kind is not AddressKind.ABSOLUTE:
                    return True
                if target.value in by_start:
                    pending.append(
                        (target.value, current_rsp, current_rbp)
                    )

        return len(visited) != len(blocks)

    def can_outline_region(
        self,
        function: "Function",
        block: "BasicBlock",
        instructions: list[Instruction],
        window_start: int,
        window_length: int,
    ) -> bool:
        """Return whether the outline call cannot clobber a live stack value.

        The call pushes its return address at ``[rsp - pointer_size, rsp)``.
        The function must not read that slot after the call, and the moved
        window itself must neither read nor write it.  The search follows every
        control-flow path until a covering write, a call at the same stack
        depth, or a return makes the slot dead.
        """
        key = id(function)
        red_zone = self._outline_red_zone.get(key)
        if red_zone is None:
            red_zone = self.uses_red_zone(function)
            self._outline_red_zone[key] = red_zone
        if not red_zone:
            return True
        if not function.basic_blocks:
            return False

        if key not in self._outline_states:
            self._outline_states[key] = self._block_entry_states(function)
        states = self._outline_states[key]
        if states is None:
            return False
        entry_states = states.get(block.start_location.value)
        if not entry_states:
            return False
        return all(
            self._outline_site_is_safe(
                function,
                block,
                instructions,
                window_start,
                window_length,
                rsp_delta,
                rbp_delta,
            )
            for rsp_delta, rbp_delta in entry_states
        )

    def _block_entry_states(
        self, function: "Function"
    ) -> dict[int, set[tuple[int, int | None]]] | None:
        """Return the possible stack states at each block entry.

        States are relative to the stack pointer at function entry.  ``None``
        means a stack update could not be modeled, a flow is unresolved, or a
        block has too many distinct states to analyze.
        """
        blocks = function.basic_blocks
        if not blocks or not all(block.instructions for block in blocks):
            return None

        by_start = {block.start_location.value: block for block in blocks}
        entry = blocks[0].start_location.value
        pending: deque[tuple[int, int, int | None]] = deque(
            [(entry, 0, None)]
        )
        states: dict[int, set[tuple[int, int | None]]] = {}

        while pending:
            start, rsp_delta, rbp_delta = pending.popleft()
            block = by_start.get(start)
            if block is None:
                return None

            state = (rsp_delta, rbp_delta)
            seen = states.setdefault(start, set())
            if state in seen:
                continue
            if len(seen) >= self._MAX_STACK_STATES:
                return None
            seen.add(state)

            current_rsp = rsp_delta
            current_rbp = rbp_delta
            for instruction in block.instructions:
                effect = self._stack_effect(
                    instruction, current_rsp, current_rbp
                )
                if effect is None:
                    return None
                current_rsp, current_rbp = effect

            last = block.instructions[-1]
            for target in last.flows_to:
                if last.type in (
                    InstructionType.CALL,
                    InstructionType.CALL_INDIRECT,
                    InstructionType.OUTLINE_RESULT_CALL,
                ):
                    # A call continues at its fallthrough, not at its target.
                    if (
                        target.kind is AddressKind.ABSOLUTE
                        and target.value == last.address + last.length
                        and target.value in by_start
                    ):
                        pending.append(
                            (target.value, current_rsp, current_rbp)
                        )
                    continue
                if target.kind is not AddressKind.ABSOLUTE:
                    return None
                if target.value in by_start:
                    pending.append(
                        (target.value, current_rsp, current_rbp)
                    )

        return states

    def _outline_site_is_safe(
        self,
        function: "Function",
        block: "BasicBlock",
        instructions: list[Instruction],
        window_start: int,
        window_length: int,
        rsp_delta: int,
        rbp_delta: int | None,
    ) -> bool:
        current_rsp = rsp_delta
        current_rbp = rbp_delta
        for instruction in instructions[:window_start]:
            effect = self._stack_effect(
                instruction, current_rsp, current_rbp
            )
            if effect is None:
                return False
            current_rsp, current_rbp = effect

        site_rsp = current_rsp
        if site_rsp % self.pointer_size:
            # Sites whose stack pointers differ by a partial pointer could
            # have partially overlapping return-address slots.
            return False
        region_start = site_rsp - self.pointer_size
        region_end = site_rsp

        for instruction in instructions[
            window_start : window_start + window_length
        ]:
            if self._creates_stack_alias(instruction):
                return False
            accesses = self._stack_memory_accesses(instruction)
            if accesses is None:
                return False
            for base, displacement, width in accesses:
                start, end = self._access_range(
                    base,
                    displacement,
                    width,
                    current_rsp,
                    current_rbp,
                )
                if start is None:
                    return False
                if self._overlaps(
                    start, end, region_start, region_end
                ):
                    return False
            effect = self._stack_effect(
                instruction, current_rsp, current_rbp
            )
            if effect is None:
                return False
            current_rsp, current_rbp = effect

        # The call restores RSP.  The window cannot modify RSP, but its RBP
        # changes persist after the shared block returns.
        return self._region_stays_clear(
            function,
            block,
            instructions,
            window_start,
            window_length,
            site_rsp,
            current_rbp,
            region_start,
            region_end,
        )

    def _region_stays_clear(
        self,
        function: "Function",
        start_block: "BasicBlock",
        start_instructions: list[Instruction],
        window_start: int,
        window_length: int,
        site_rsp: int,
        rbp_delta: int | None,
        region_start: int,
        region_end: int,
    ) -> bool:
        by_start = {
            block.start_location.value: block
            for block in function.basic_blocks
        }
        pending: deque[
            tuple[list[Instruction], int, int, int | None, bool]
        ] = deque(
            [
                (
                    start_instructions,
                    window_start + window_length,
                    site_rsp,
                    rbp_delta,
                    True,
                )
            ]
        )
        visited: set[tuple[int, int, int, int | None]] = set()

        while pending:
            instructions, index, rsp_delta, rbp_delta, is_start = (
                pending.popleft()
            )
            while index < len(instructions):
                if is_start and index == window_start:
                    # A branch back to the outline call.  It overwrites the
                    # slot only when it pushes at the same stack depth.
                    if rsp_delta == site_rsp:
                        break
                    return False

                key = (id(instructions), index, rsp_delta, rbp_delta)
                if key in visited:
                    break
                visited.add(key)

                instruction = instructions[index]
                if self._creates_stack_alias(instruction):
                    return False
                accesses = self._stack_memory_accesses(instruction)
                if accesses is None:
                    return False
                reads = self._reads_memory(instruction)
                writes = self._writes_memory(instruction)
                terminated = False
                for base, displacement, width in accesses:
                    start, end = self._access_range(
                        base,
                        displacement,
                        width,
                        rsp_delta,
                        rbp_delta,
                    )
                    if start is None:
                        return False
                    if not self._overlaps(
                        start, end, region_start, region_end
                    ):
                        continue
                    if reads or not writes:
                        return False
                    if start <= region_start and end >= region_end:
                        # The slot is overwritten before any read, so the
                        # outline call's value is dead.
                        terminated = True
                        break
                if terminated:
                    break

                if instruction.type is InstructionType.RET:
                    if self._overlaps(
                        rsp_delta,
                        rsp_delta + self.pointer_size,
                        region_start,
                        region_end,
                    ):
                        return False
                    if self._mnemonic(instruction) not in ("RET", "RETN"):
                        return False
                    break

                if instruction.type in (
                    InstructionType.CALL,
                    InstructionType.CALL_INDIRECT,
                ):
                    if rsp_delta == site_rsp:
                        break
                    return False

                effect = self._stack_effect(
                    instruction, rsp_delta, rbp_delta
                )
                if effect is None:
                    return False
                if effect != (rsp_delta, rbp_delta):
                    mnemonic = self._mnemonic(instruction)
                    if mnemonic == "PUSH" and rsp_delta == site_rsp:
                        break
                    if (
                        mnemonic is not None
                        and mnemonic.startswith("POP")
                        and self._overlaps(
                            rsp_delta,
                            rsp_delta + self.pointer_size,
                            region_start,
                            region_end,
                        )
                    ):
                        return False
                    if mnemonic == "LEAVE" and (
                        rbp_delta is None
                        or self._overlaps(
                            rbp_delta,
                            rbp_delta + self.pointer_size,
                            region_start,
                            region_end,
                        )
                    ):
                        return False
                rsp_delta, rbp_delta = effect

                if instruction.type is InstructionType.BRANCH:
                    if not self._enqueue_successors(
                        pending,
                        instruction,
                        rsp_delta,
                        rbp_delta,
                        start_block,
                        start_instructions,
                        by_start,
                    ):
                        return False
                    break

                index += 1
                if index == len(instructions):
                    if not self._enqueue_successors(
                        pending,
                        instruction,
                        rsp_delta,
                        rbp_delta,
                        start_block,
                        start_instructions,
                        by_start,
                    ):
                        return False
                    break

        return True

    def _enqueue_successors(
        self,
        pending: deque[
            tuple[list[Instruction], int, int, int | None, bool]
        ],
        instruction: Instruction,
        rsp_delta: int,
        rbp_delta: int | None,
        start_block: "BasicBlock",
        start_instructions: list[Instruction],
        by_start: dict[int, "BasicBlock"],
    ) -> bool:
        if not instruction.flows_to:
            return False
        for target in instruction.flows_to:
            if target.kind is not AddressKind.ABSOLUTE:
                return False
            if target.value == start_block.start_location.value:
                pending.append(
                    (
                        start_instructions,
                        0,
                        rsp_delta,
                        rbp_delta,
                        True,
                    )
                )
                continue
            block = by_start.get(target.value)
            if block is None:
                return False
            pending.append(
                (block.instructions, 0, rsp_delta, rbp_delta, False)
            )
        return True

    def _stack_memory_accesses(
        self, instruction: Instruction
    ) -> list[tuple[str, int, int]] | None:
        """Return the stack-relative memory ranges an instruction touches.

        Each entry is ``(base, displacement, width)``.  ``None`` means a
        stack-relative operand exists but its width or address could not be
        determined.
        """
        if not self._reads_memory(instruction) and not self._writes_memory(
            instruction
        ):
            return []
        try:
            resolved = self._resolve(instruction)
        except _NotAdjustable:
            return None

        data = instruction.original_data
        accesses: list[tuple[str, int, int]] = []
        unknown = False

        def walk(
            operand: ResolvedOperand,
            context: int,
            width: int | None,
        ) -> None:
            nonlocal unknown
            try:
                location = self._sleigher.spec._location_for_operand(
                    operand, data, context
                )
            except _NotAdjustable:
                location = None
            if location is not None:
                state = self._sleigher.spec._state_space(
                    (location.space_index, location.offset, location.size)
                )
                if (
                    state is not None
                    and state.kind is StateSpaceKind.MEMORY
                ):
                    width = location.size

            if operand.resolved is not None and self._is_address_operand(
                operand, operand.resolved
            ):
                try:
                    base = self._base_register(operand, data)
                    displacement = self._address_displacement(
                        operand, data
                    )
                except _NotAdjustable:
                    unknown = True
                    return
                if base in ("RSP", "RBP"):
                    if width is None:
                        unknown = True
                        return
                    accesses.append((base, displacement, width))

            if operand.resolved is not None:
                for child in operand.resolved.operands:
                    walk(child, operand.resolved.context, width)

        for operand in resolved.operands:
            walk(operand, resolved.context, None)

        if unknown:
            return None
        return accesses

    @staticmethod
    def _reads_memory(instruction: Instruction) -> bool:
        return any(
            state.kind is StateSpaceKind.MEMORY
            for state in instruction.depends_on
        )

    @staticmethod
    def _writes_memory(instruction: Instruction) -> bool:
        return any(
            state.kind is StateSpaceKind.MEMORY
            for state in instruction.modifies
        )

    def _mnemonic(self, instruction: Instruction) -> str | None:
        try:
            resolved = self._resolve(instruction)
        except _NotAdjustable:
            return None
        return self._sleigher.spec.mnemonic(resolved).upper()

    def _creates_stack_alias(self, instruction: Instruction) -> bool:
        """Return whether a value derived from RSP or RBP escapes to a register.

        The scan tracks only RSP and RBP.  A register holding an RSP- or
        RBP-relative address could hide a later read of the return-address
        slot, so such an instruction rejects the site.
        """
        if not any(
            state.kind is StateSpaceKind.REGISTER
            for state in instruction.modifies
        ):
            return False
        try:
            resolved = self._resolve(instruction)
        except _NotAdjustable:
            return True

        data = instruction.original_data
        if self._sleigher.spec.mnemonic(resolved).upper() == "LEA":
            try:
                for operand in self._address_operands(resolved):
                    if self._base_register(operand, data) in ("RSP", "RBP"):
                        return True
            except _NotAdjustable:
                return True

        modified = {
            state.name
            for state in instruction.modifies
            if state.kind is StateSpaceKind.REGISTER
        }
        if not modified - {"RSP", "RBP"}:
            return False
        return any(
            self._uses_register_as_value(resolved, data, name)
            for name in ("RSP", "RBP")
        )

    def _access_range(
        self,
        base: str,
        displacement: int,
        width: int,
        rsp_delta: int,
        rbp_delta: int | None,
    ) -> tuple[int | None, int | None]:
        origin = rsp_delta if base == "RSP" else rbp_delta
        if origin is None:
            return None, None
        start = origin + displacement
        return start, start + width

    @staticmethod
    def _overlaps(
        start: int,
        end: int,
        region_start: int,
        region_end: int,
    ) -> bool:
        return start < region_end and region_start < end

    def relocate_instruction(
        self, instruction: Instruction, new_base_address: int
    ) -> Instruction:
        relocated = self._sleigher.reassemble(instruction, new_base_address)
        if relocated is None:
            raise ValueError(
                f"cannot relocate instruction {instruction.original_data.hex(' ')} "
                f"from {instruction.address:#x} to {new_base_address:#x} with its existing encoding"
            )
        return relocated

    def set_instruction_target(
        self, instruction: Instruction, new_target_address: Address
    ) -> Instruction:
        if new_target_address.kind is not AddressKind.ABSOLUTE:
            raise ValueError(
                f"instruction target must be an absolute address. Received {new_target_address.kind.name} "
                f"for instruction at {instruction.address:#x}"
            )
        if instruction.type not in (
            InstructionType.BRANCH,
            InstructionType.CALL,
            InstructionType.OUTLINE_RESULT_CALL,
        ):
            raise ValueError(
                f"instruction type {instruction.type.name} at {instruction.address:#x} has no direct target"
            )

        data = bytearray(instruction.original_data)
        resolved = self._sleigher.spec.resolve(bytes(data), self._sleigher.context)
        if resolved is None:
            raise ValueError(f"instruction {data.hex(' ')} at {instruction.address:#x} cannot be resolved for retargeting")
        relative = self._sleigher.spec.relative_target(
            resolved, bytes(data), instruction.address
        )
        if relative is None:
            raise ValueError(f"instruction {data.hex(' ')} at {instruction.address:#x} has no relative target field")
        _, offset, size = relative

        displacement = new_target_address.value - (
            instruction.address + instruction.length
        )
        try:
            encoded = displacement.to_bytes(size, "little", signed=True)
        except OverflowError as exc:
            raise ValueError(
                f"target {new_target_address.value:#x} does not fit the signed {size * 8}-bit "
                f"displacement from instruction {instruction.address:#x} (requires {displacement:+#x})"
            ) from exc
        data[offset : offset + size] = encoded

        patched = bytes(data)
        decoded = self._sleigher.parse(patched, instruction.address)
        if decoded is None or decoded.length != instruction.length:
            raise ValueError(
                f"patched instruction {patched.hex(' ')} at {instruction.address:#x} does not decode in place "
                f"with the original length of {instruction.length} bytes"
            )
        if (
            not decoded.flows_to
            or decoded.flows_to[0].kind is not AddressKind.ABSOLUTE
            or decoded.flows_to[0].value != new_target_address.value
        ):
            raise ValueError(
                f"patched instruction {patched.hex(' ')} at {instruction.address:#x} "
                f"does not reach the requested target {new_target_address.value:#x}"
            )

        if instruction.type is InstructionType.OUTLINE_RESULT_CALL:
            flows_to = [
                new_target_address,
                Address.absolute(instruction.address + instruction.length),
            ]
        else:
            flows_to = list(decoded.flows_to)

        return replace(
            instruction,
            original_data=patched,
            flows_to=flows_to,
        )

    def can_encode(self, instruction: Instruction, address: int) -> bool:
        return self._sleigher.reassemble(instruction, address) is not None

    def required_length(self, instruction: Instruction, address: int) -> int:
        relocated = self._sleigher.reassemble(instruction, address)
        if relocated is None:
            raise ValueError(
                f"cannot encode instruction {instruction.original_data.hex(' ')} "
                f"from {instruction.address:#x} at {address:#x} with its existing encoding"
            )
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

        try:
            data = binary.read(offset, self.pointer_size)
        except ValueError:
            data = None
        if data is not None and len(data) == self.pointer_size:
            pointers.add(
                Address.absolute(int.from_bytes(data, "little", signed=False))
            )
            # The 32-bit reading is the low half of the same bytes.
            pointers.add(
                Address.absolute(
                    int.from_bytes(data[:4], "little", signed=False)
                )
            )
            return pointers

        # A pointer-sized read that crosses unmapped memory is unreadable, but
        # the 32-bit value may still fit.
        try:
            data = binary.read(offset, 4)
        except ValueError:
            return pointers
        if len(data) == 4:
            pointers.add(
                Address.absolute(int.from_bytes(data, "little", signed=False))
            )
        return pointers

    def call_instruction_length(self) -> int:
        """Return the length of a ``call rel32`` used at an outline site."""
        return 5

    def ret_instruction_length(self) -> int:
        """Return the length of a one-byte ``ret`` used at a target site."""
        return 1

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
        if not instruction.flows_to:
            # Before code-flow recovery both lists are empty.  Once recovery
            # has run, an instruction with incoming edges but no outgoing edge
            # is not a straight-line instruction.
            return not instruction.flows_from
        if len(instruction.flows_to) != 1:
            return False

        target = instruction.flows_to[0]
        if target.kind is not AddressKind.ABSOLUTE:
            return False

        # flows_from holds predecessor addresses, not the instruction's own
        # address, so the fallthrough is always relative to this instruction.
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

    def _accesses_below_rsp(
        self,
        instruction: Instruction,
        rsp_delta: int,
        rbp_delta: int | None,
    ) -> bool:
        """Return whether ``instruction`` reads or writes below RSP."""
        if not any(
            state.kind is StateSpaceKind.MEMORY
            for state in (*instruction.modifies, *instruction.depends_on)
        ):
            # LEA computes an address but does not access memory.  Its
            # displacement is biased by the outliner like any other RSP-based
            # address, but it cannot clobber the red zone itself.
            return False

        try:
            resolved = self._resolve(instruction)
        except _NotAdjustable:
            return True

        try:
            for operand in self._address_operands(resolved):
                base = self._base_register(
                    operand, instruction.original_data
                )
                if base not in ("RSP", "RBP"):
                    continue
                displacement = self._address_displacement(
                    operand, instruction.original_data
                )
                if base == "RSP":
                    if rsp_delta + displacement < rsp_delta:
                        return True
                else:
                    if rbp_delta is None:
                        return True
                    if rbp_delta + displacement < rsp_delta:
                        return True
        except _NotAdjustable:
            return True
        return False

    def _address_displacement(
        self, operand: ResolvedOperand, data: bytes
    ) -> int:
        """Return the ModRM displacement of an address operand."""
        field = self._modrm_displacement(data, operand.offset)
        if field is None:
            return 0
        size, offset = field
        if offset + size > len(data):
            raise _NotAdjustable("displacement extends past instruction")
        return int.from_bytes(data[offset : offset + size], "little", signed=True)

    def _stack_effect(
        self,
        instruction: Instruction,
        rsp_delta: int,
        rbp_delta: int | None,
    ) -> tuple[int, int | None] | None:
        """Return the stack state after ``instruction``.

        ``None`` means the instruction changes the stack pointer in a way this
        analyzer does not model.
        """
        modifies_rsp = self._modifies_register(instruction, "RSP")
        modifies_rbp = self._modifies_register(instruction, "RBP")
        if not modifies_rsp and not modifies_rbp:
            return rsp_delta, rbp_delta

        if instruction.type in (
            InstructionType.CALL,
            InstructionType.CALL_INDIRECT,
            InstructionType.OUTLINE_RESULT_CALL,
            InstructionType.RET,
        ):
            # Calls restore RSP when they return; returns end the block.
            return rsp_delta, rbp_delta

        try:
            resolved = self._resolve(instruction)
        except _NotAdjustable:
            return None
        mnemonic = self._sleigher.spec.mnemonic(resolved).upper()
        data = instruction.original_data
        info = self._opcode_info(data)
        if info is None:
            return None
        rex_w, rex_b, rex_r, has_66, opcode_index, opcode = info

        if mnemonic == "PUSH":
            if has_66:
                return None
            return rsp_delta - self.pointer_size, rbp_delta
        if mnemonic.startswith("POP"):
            if has_66:
                return None
            if opcode == 0x5C and not rex_b:
                # pop rsp takes its new value from memory.
                return None
            new_rbp = rbp_delta
            if opcode == 0x5D and not rex_b:
                new_rbp = None
            return rsp_delta + self.pointer_size, new_rbp
        if mnemonic == "LEAVE":
            if rbp_delta is None:
                return None
            return rbp_delta + self.pointer_size, None
        if mnemonic == "ENTER":
            return None

        if opcode in (0x89, 0x8B) and rex_w and not has_66:
            if opcode_index + 1 >= len(data):
                return None
            modrm = data[opcode_index + 1]
            if modrm >> 6 != 3:
                return None
            if opcode == 0x8B:
                destination = (modrm >> 3) & 7
                source = modrm & 7
                if rex_r:
                    destination += 8
                if rex_b:
                    source += 8
            else:
                destination = modrm & 7
                source = (modrm >> 3) & 7
                if rex_b:
                    destination += 8
                if rex_r:
                    source += 8
            if destination == 5 and source == 4:
                # mov rbp, rsp
                return rsp_delta, rsp_delta
            if destination == 4 and source == 5:
                # mov rsp, rbp
                if rbp_delta is None:
                    return None
                return rbp_delta, rbp_delta
            if destination == 4:
                return None
            if destination == 5:
                return rsp_delta, None

        if mnemonic in ("SUB", "ADD") and opcode in (0x83, 0x81):
            if not rex_w or has_66 or rex_b or rex_r:
                return None
            modrm_index = opcode_index + 1
            if modrm_index >= len(data):
                return None
            modrm = data[modrm_index]
            if modrm >> 6 != 3 or (modrm & 7) != 4:
                return None
            operation = (modrm >> 3) & 7
            if mnemonic == "SUB" and operation != 5:
                return None
            if mnemonic == "ADD" and operation != 0:
                return None
            immediate_index = modrm_index + 1
            immediate_size = 1 if opcode == 0x83 else 4
            if immediate_index + immediate_size > len(data):
                return None
            amount = int.from_bytes(
                data[immediate_index : immediate_index + immediate_size],
                "little",
                signed=True,
            )
            if mnemonic == "SUB":
                return rsp_delta - amount, rbp_delta
            return rsp_delta + amount, rbp_delta

        if modifies_rsp:
            return None
        return rsp_delta, None

    @staticmethod
    def _modifies_register(
        instruction: Instruction, name: str
    ) -> bool:
        return any(
            state.kind is StateSpaceKind.REGISTER and state.name == name
            for state in instruction.modifies
        )

    def _opcode_info(
        self, data: bytes
    ) -> tuple[bool, bool, bool, bool, int, int] | None:
        """Return REX and opcode facts for an x86 instruction."""
        index = 0
        has_66 = False
        rex = 0
        while index < len(data):
            byte = data[index]
            if byte in self._LEGACY_PREFIXES:
                if byte == 0x66:
                    has_66 = True
                index += 1
                continue
            if 0x40 <= byte <= 0x4F:
                rex = byte
                index += 1
                continue
            break
        if index >= len(data):
            return None
        return (
            bool(rex & 0x08),
            bool(rex & 0x01),
            bool(rex & 0x04),
            has_66,
            index,
            data[index],
        )

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
        return self._uses_register_as_value(resolved, data, "RSP")

    def _uses_register_as_value(
        self,
        resolved: ResolvedConstructor,
        data: bytes,
        name: str,
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
                    and state.name == name
                ):
                    return True
            return False

        return walk(resolved, False)
