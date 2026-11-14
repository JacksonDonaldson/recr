"""Flatten a decoded SLEIGH specification into the GPU table layout.

The kernel in :mod:`gpu.kernels` reimplements the same resolution algorithm as
:class:`isa.sleigher.sla.SlaSpec`, but as a table interpreter so that one
thread can resolve one address.  This module produces those tables.

The blob is a single little-endian ``uint32`` array.  The header holds the
element offset of every section; the C side reads the same layout.  Both
descriptions must be kept in step.
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass

from ir import InstructionType
from isa.sleigher.sla import (
    OP_BRANCH,
    OP_BRANCHIND,
    OP_BUILD,
    OP_CALLIND,
    OP_CBRANCH,
    Constructor,
    DecisionNode,
    Pattern,
    PatternBlock,
    SlaError,
    SlaSpec,
    _expr_contains,
    _expr_operand_index,
)


MAGIC = 0x5A504447

# Header element indices.  Keep in sync with ``gpu/kernels.cu``.
H_MAGIC = 0
H_NODES = 1
H_PAIRS = 2
H_PCHILD = 3
H_NCHILD = 4
H_PATTERNS = 5
H_BLOCKS = 6
H_WORDS = 7
H_CTORS = 8
H_OPERANDS = 9
H_CTX = 10
H_INSTRS = 11
H_SUBTABLES = 12
H_BUILD = 13
H_ROOT = 14
H_LEN = 15

# Expression opcodes.  Keep in sync with ``gpu/kernels.cu``.
E_CONST = 0
E_TOKEN = 1
E_CONTEXT = 2
E_ZERO = 3
E_OPERAND = 4
E_NEG = 5
E_NOT = 6
E_ADD = 7
E_SUB = 8
E_MUL = 9
E_LSHIFT = 10
E_RSHIFT = 11
E_AND = 12
E_OR = 13
E_XOR = 14
E_DIV = 15

# Instruction classes, ordered so that zero means "no printed mnemonic".
TYPE_NONE = 0
TYPE_CALL = 1
TYPE_RET = 2
TYPE_BRANCH = 3
TYPE_NOP = 4
TYPE_ARITHMETIC = 5

_TYPE_CODES = {
    InstructionType.CALL: TYPE_CALL,
    InstructionType.RET: TYPE_RET,
    InstructionType.BRANCH: TYPE_BRANCH,
    InstructionType.NOP: TYPE_NOP,
    InstructionType.ARITHMETIC: TYPE_ARITHMETIC,
}

TYPE_FROM_CODE = {value: key for key, value in _TYPE_CODES.items()}

# Control-transfer P-code opcodes that decide how a flow target is formed.
OPCODE_BRANCH = 1 << 0
OPCODE_CBRANCH = 1 << 1
OPCODE_BRANCHIND = 1 << 2
OPCODE_CALLIND = 1 << 3

_OPCODE_BITS = {
    OP_BRANCH: OPCODE_BRANCH,
    OP_CBRANCH: OPCODE_CBRANCH,
    OP_BRANCHIND: OPCODE_BRANCHIND,
    OP_CALLIND: OPCODE_CALLIND,
}

INSTR_STRIDE = 9
MAX_OPERANDS = 16
_MAX_OPERAND_OFFSET = 30000


def _mask(value: int) -> int:
    return value & 0xFFFFFFFF


def _static_text(constructor: Constructor) -> str:
    return "".join(
        value for kind, value in constructor.print_pieces if kind == "text"
    ).strip()


def constructor_type(constructor: Constructor) -> InstructionType | None:
    """Return the instruction type implied by the printed mnemonic.

    ``None`` means the mnemonic is not carried by this constructor itself, so
    the type depends on which subtable constructor the bytes select.  The
    kernel propagates the first printed mnemonic of the resolved tree, which is
    exactly what :meth:`SlaSpec.mnemonic` returns.
    """
    text = _static_text(constructor)
    if not text:
        return None
    mnemonic = text.split(" ", 1)[0].upper()
    if mnemonic.startswith("CALL"):
        return InstructionType.CALL
    if mnemonic.startswith("RET") or mnemonic.startswith("IRET"):
        return InstructionType.RET
    if mnemonic.startswith("J") or mnemonic.startswith("LOOP"):
        return InstructionType.BRANCH
    if mnemonic == "NOP":
        return InstructionType.NOP
    return InstructionType.ARITHMETIC


@dataclass(frozen=True)
class GpuTables:
    """The flattened specification, ready to upload."""

    blob: array
    root: int
    constructors: tuple[Constructor, ...]
    type_codes: tuple[int, ...]

    @property
    def element_count(self) -> int:
        return len(self.blob)


class _Builder:
    def __init__(self, spec: SlaSpec) -> None:
        self.spec = spec
        self.nodes = array("I")
        self.pairs = array("I")
        self.pattern_children = array("I")
        self.node_children = array("I")
        self.patterns = array("I")
        self.blocks = array("I")
        self.words = array("I")
        self.ctors = array("I")
        self.operands = array("I")
        self.context_ops = array("I")
        self.instructions = array("I")
        self.subtables = array("I")
        self.build_operands = array("I")

        self._block_index: dict[tuple[object, ...], int] = {}
        self._expr_index: dict[tuple[object, ...], int] = {}
        self._operand_index: dict[int, int] = {}
        self._subtable_index: dict[int, int] = {}
        self.constructors: list[Constructor] = []
        self.type_codes: list[int] = []

    # ------------------------------------------------------------- sections

    def _add_block(self, block: PatternBlock) -> int:
        key = (
            block.offset,
            block.nonzerosize,
            tuple(block.masks),
            tuple(block.values),
        )
        existing = self._block_index.get(key)
        if existing is not None:
            return existing
        word_base = len(self.words) // 2
        for mask, value in zip(block.masks, block.values):
            self.words.append(_mask(mask))
            self.words.append(_mask(value))
        index = len(self.blocks) // 4
        self.blocks.extend(
            (
                _mask(block.offset),
                _mask(word_base),
                _mask(len(block.masks)),
                _mask(block.nonzerosize),
            )
        )
        self._block_index[key] = index
        return index

    def _add_pattern(self, pattern: Pattern) -> int:
        kind = {"instruction": 0, "context": 1, "combine": 2, "or": 3}.get(
            pattern.kind
        )
        if kind is None:
            raise SlaError(f"unknown pattern kind {pattern.kind}")
        if pattern.kind in ("instruction", "context"):
            if pattern.block is None:
                raise SlaError("pattern block is missing")
            block = self._add_block(pattern.block)
            index = len(self.patterns) // 4
            self.patterns.extend((kind, _mask(block), 0, 0))
            return index

        children = [self._add_pattern(child) for child in pattern.children]
        child_base = len(self.pattern_children)
        self.pattern_children.extend(_mask(child) for child in children)
        index = len(self.patterns) // 4
        self.patterns.extend(
            (kind, 0, _mask(child_base), _mask(len(children)))
        )
        return index

    def _add_decision(self, node: DecisionNode) -> int:
        children = [self._add_decision(child) for child in node.children]
        child_base = len(self.node_children)
        self.node_children.extend(_mask(child) for child in children)

        pair_base = len(self.pairs) // 2
        for pattern, constructor_id in node.pairs:
            self.pairs.append(_mask(self._add_pattern(pattern)))
            self.pairs.append(_mask(constructor_id))

        index = len(self.nodes) // 7
        self.nodes.extend(
            (
                _mask(node.startbit),
                _mask(node.bitsize),
                _mask(1 if node.context else 0),
                _mask(child_base),
                _mask(len(children)),
                _mask(pair_base),
                _mask(len(node.pairs)),
            )
        )
        return index

    # --------------------------------------------------------- expressions

    def _add_expr(self, expr: tuple[object, ...]) -> int:
        existing = self._expr_index.get(expr)
        if existing is not None:
            return existing

        program: list[tuple[int, ...]] = []

        def emit(node: tuple[object, ...]) -> None:
            kind = node[0]
            if kind == "const":
                value = int(node[1])
                program.append((E_CONST, _mask(value), _mask(value >> 32)))
                return
            if kind == "token":
                program.append(
                    (
                        E_TOKEN,
                        int(node[1]),
                        int(node[2]),
                        int(node[3]),
                        int(node[4]),
                        int(node[5]),
                        int(node[6]),
                        int(node[7]),
                    )
                )
                return
            if kind == "context":
                program.append(
                    (E_CONTEXT, int(node[1]), int(node[2]), int(node[3]))
                )
                return
            if kind in ("start", "next", "next2"):
                program.append((E_ZERO,))
                return
            if kind == "operand":
                program.append((E_OPERAND, int(node[1])))
                return
            if kind == "unary":
                emit(node[2])
                program.append((E_NEG if node[1] == "minus" else E_NOT,))
                return
            if kind == "binary":
                operator = {
                    "plus": E_ADD,
                    "minus": E_SUB,
                    "mult": E_MUL,
                    "lshift": E_LSHIFT,
                    "rshift": E_RSHIFT,
                    "and": E_AND,
                    "or": E_OR,
                    "xor": E_XOR,
                    "div": E_DIV,
                }.get(str(node[1]))
                if operator is None:
                    raise SlaError(f"unknown binary expression {node[1]}")
                emit(node[2])
                emit(node[3])
                program.append((operator,))
                return
            raise SlaError(f"unknown pattern expression {kind}")

        emit(expr)

        start = len(self.instructions)
        self.instructions.append(_mask(len(program)))
        for instruction in program:
            for position in range(INSTR_STRIDE):
                value = (
                    instruction[position] if position < len(instruction) else 0
                )
                self.instructions.append(_mask(value))
        self._expr_index[expr] = start
        return start

    # -------------------------------------------------------------- operands

    def _build_operands(self) -> None:
        for symbol_id, operand in self.spec.operands.items():
            self._operand_index[symbol_id] = len(self.operands) // 6
            definition = -1
            if operand.definition is not None:
                definition = self._add_expr(operand.definition)
            next_info = -1
            if operand.definition is not None and _expr_contains(
                operand.definition, "next"
            ):
                index = _expr_operand_index(operand.definition)
                if index is not None:
                    next_info = (index << 1) | 1
            self.operands.extend(
                (
                    _mask(operand.offset_base),
                    _mask(operand.relative_offset),
                    _mask(operand.minimum_length),
                    _mask(-1),
                    _mask(definition),
                    _mask(next_info),
                )
            )

    def _patch_subsyms(self) -> None:
        for symbol_id, operand in self.spec.operands.items():
            slot = self._operand_index[symbol_id]
            subsym = operand.subsym_id
            resolved = -1
            if subsym is not None and subsym in self._subtable_index:
                resolved = self._subtable_index[subsym]
            self.operands[slot * 6 + 3] = _mask(resolved)

    def _build_subtables(self) -> int:
        for index, symbol_id in enumerate(self.spec.subtables):
            self._subtable_index[symbol_id] = index
        self._patch_subsyms()

        root = -1
        for symbol_id, subtable in self.spec.subtables.items():
            index = self._subtable_index[symbol_id]
            node_base = (
                self._add_decision(subtable.decision)
                if subtable.decision is not None
                else -1
            )
            constructor_base = len(self.constructors)
            for constructor in subtable.constructors:
                self._add_constructor(constructor)
            self.subtables.extend(
                (
                    _mask(node_base),
                    _mask(constructor_base),
                    _mask(len(subtable.constructors)),
                )
            )
            if self.spec.root_subtable is subtable:
                root = index
        return root

    def _add_constructor(self, constructor: Constructor) -> None:
        if len(constructor.operands) > MAX_OPERANDS:
            raise SlaError(
                f"constructor has {len(constructor.operands)} operands; "
                f"the GPU layout holds {MAX_OPERANDS}"
            )
        operand_base = len(self.operands) // 6
        for symbol_id in constructor.operands:
            slot = self._operand_slot(symbol_id)
            entry = tuple(self.operands[slot * 6 : slot * 6 + 6])
            relative = entry[1]
            if relative >= 0x80000000:
                relative -= 0x100000000
            if relative < 0 or relative > _MAX_OPERAND_OFFSET:
                raise SlaError("operand offset does not fit the GPU layout")
            # ``offset_base`` already indexes the constructor's own operand
            # list, which is exactly what the kernel expects.
            self.operands.extend(entry)

        context_base = len(self.context_ops) // 4
        for op in constructor.context_ops:
            self.context_ops.extend(
                (
                    _mask(op.word),
                    _mask(op.shift),
                    _mask(op.mask),
                    _mask(self._add_expr(op.expression)),
                )
            )

        opcode_mask = 0
        build_ids: list[int] = []
        template = constructor.template
        if template is not None:
            for op in template.ops:
                if op.opcode == OP_BUILD and op.output is None:
                    if op.inputs:
                        build_ids.append(int(op.inputs[0].offset.value))
                    continue
                opcode_mask |= _OPCODE_BITS.get(op.opcode, 0)
        build_base = len(self.build_operands)
        self.build_operands.extend(_mask(value) for value in build_ids)

        instruction_type = constructor_type(constructor)
        type_code = _TYPE_CODES.get(instruction_type, TYPE_NONE)

        self.constructors.append(constructor)
        self.type_codes.append(type_code)
        self.ctors.extend(
            (
                _mask(constructor.minimum_length),
                _mask(operand_base),
                _mask(len(constructor.operands)),
                _mask(context_base),
                _mask(len(constructor.context_ops)),
                _mask(type_code),
                _mask(opcode_mask),
                _mask(build_base),
                _mask(len(build_ids)),
            )
        )

    def _operand_slot(self, symbol_id: int) -> int:
        index = self._operand_index.get(symbol_id)
        if index is None:
            raise SlaError(f"operand {symbol_id} is not defined")
        return index

    # ----------------------------------------------------------------- build

    def build(self) -> GpuTables:
        self._build_operands()
        root = self._build_subtables()
        if root < 0:
            raise SlaError("specification has no root subtable")

        sections = (
            self.nodes,
            self.pairs,
            self.pattern_children,
            self.node_children,
            self.patterns,
            self.blocks,
            self.words,
            self.ctors,
            self.operands,
            self.context_ops,
            self.instructions,
            self.subtables,
            self.build_operands,
        )
        header = array("I", [0] * H_LEN)
        header[H_MAGIC] = MAGIC
        offset = H_LEN
        for position, section in enumerate(sections, start=1):
            header[position] = offset
            offset += len(section)
        header[H_ROOT] = root

        blob = array("I", header)
        for section in sections:
            blob.extend(section)
        return GpuTables(
            blob=blob,
            root=root,
            constructors=tuple(self.constructors),
            type_codes=tuple(self.type_codes),
        )


def build_tables(spec: SlaSpec) -> GpuTables:
    """Flatten ``spec`` into the GPU table blob."""
    return _Builder(spec).build()
