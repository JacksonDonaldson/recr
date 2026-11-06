"""Reader for Ghidra's packed ``.sla`` SLEIGH specification format.

The compiled specification contains the address spaces, symbol table,
constructor patterns, decision trees, and P-code templates needed to decode
instructions.  This module intentionally mirrors the subset of the Ghidra
runtime model that codezip needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import zlib
from typing import Any

from ir import Instruction, InstructionType, StateSpace, StateSpaceKind


class SlaError(ValueError):
    """Raised when a ``.sla`` file cannot be decoded or interpreted."""


# Attribute ids from Ghidra's slaformat.hh.
A_VAL = 2
A_ID = 3
A_SPACE = 4
A_S = 5
A_OFF = 6
A_CODE = 7
A_MASK = 8
A_INDEX = 9
A_NONZERO = 10
A_PIECE = 11
A_NAME = 12
A_SCOPE = 13
A_STARTBIT = 14
A_SIZE = 15
A_TABLE = 16
A_CT = 17
A_MINLEN = 18
A_BASE = 19
A_NUMBER = 20
A_CONTEXT = 21
A_PARENT = 22
A_SUBSYM = 23
A_LINE = 24
A_SOURCE = 25
A_LENGTH = 26
A_FIRST = 27
A_PLUS = 28
A_SHIFT = 29
A_ENDBIT = 30
A_SIGNBIT = 31
A_ENDBYTE = 32
A_STARTBYTE = 33
A_BIGENDIAN = 35
A_DEFAULTSPACE = 41
A_DELAY = 42
A_WORDSIZE = 43
A_PHYSICAL = 44
A_SCOPESIZE = 45
A_SYMBOLSIZE = 46
A_VARNODE = 47
A_LOW = 48
A_HIGH = 49
A_FLOW = 50
A_I = 52
A_NUMCT = 53
A_SECTION = 54

# Element ids from Ghidra's slaformat.hh.
E_CONST_REAL = 1
E_VARNODE_TPL = 2
E_CONST_SPACEID = 3
E_CONST_HANDLE = 4
E_OP_TPL = 5
E_MASK_WORD = 6
E_PAT_BLOCK = 7
E_PRINT = 8
E_PAIR = 9
E_CONTEXT_PAT = 10
E_NULL = 11
E_OPERAND_EXP = 12
E_OPERAND_SYM = 13
E_OPERAND_SYM_HEAD = 14
E_OPER = 15
E_DECISION = 16
E_OPPRINT = 17
E_INSTRUCT_PAT = 18
E_COMBINE_PAT = 19
E_CONSTRUCTOR = 20
E_CONSTRUCT_TPL = 21
E_SCOPE = 22
E_VARNODE_SYM = 23
E_VARNODE_SYM_HEAD = 24
E_USEROP = 25
E_USEROP_HEAD = 26
E_TOKENFIELD = 27
E_VAR = 28
E_CONTEXTFIELD = 29
E_HANDLE_TPL = 30
E_CONST_RELATIVE = 31
E_CONTEXT_OP = 32
E_SLEIGH = 33
E_SPACES = 34
E_SOURCEFILES = 35
E_SOURCEFILE = 36
E_SPACE = 37
E_SYMBOL_TABLE = 38
E_VALUE_SYM = 39
E_VALUE_SYM_HEAD = 40
E_CONTEXT_SYM = 41
E_CONTEXT_SYM_HEAD = 42
E_END_SYM = 43
E_END_SYM_HEAD = 44
E_SPACE_OTHER = 45
E_SPACE_UNIQUE = 46
E_AND_EXP = 47
E_DIV_EXP = 48
E_LSHIFT_EXP = 49
E_MINUS_EXP = 50
E_MULT_EXP = 51
E_NOT_EXP = 52
E_OR_EXP = 53
E_PLUS_EXP = 54
E_RSHIFT_EXP = 55
E_SUB_EXP = 56
E_XOR_EXP = 57
E_INTB = 58
E_END_EXP = 59
E_NEXT2_EXP = 60
E_START_EXP = 61
E_EPSILON_SYM = 62
E_EPSILON_SYM_HEAD = 63
E_NAME_SYM = 64
E_NAME_SYM_HEAD = 65
E_NAMETAB = 66
E_NEXT2_SYM = 67
E_NEXT2_SYM_HEAD = 68
E_START_SYM = 69
E_START_SYM_HEAD = 70
E_SUBTABLE_SYM = 71
E_SUBTABLE_SYM_HEAD = 72
E_VALUEMAP_SYM = 73
E_VALUEMAP_SYM_HEAD = 74
E_VALUETAB = 75
E_VARLIST_SYM = 76
E_VARLIST_SYM_HEAD = 77
E_OR_PAT = 78
E_COMMIT = 79
E_CONST_START = 80
E_CONST_NEXT = 81
E_CONST_NEXT2 = 82
E_CONST_CURSPACE = 83
E_CONST_CURSPACE_SIZE = 84
E_CONST_FLOWREF = 85
E_CONST_FLOWREF_SIZE = 86
E_CONST_FLOWDEST = 87
E_CONST_FLOWDEST_SIZE = 88

HEADER_ELEMENTS = {
    E_USEROP_HEAD,
    E_EPSILON_SYM_HEAD,
    E_VALUE_SYM_HEAD,
    E_VALUEMAP_SYM_HEAD,
    E_NAME_SYM_HEAD,
    E_VARNODE_SYM_HEAD,
    E_CONTEXT_SYM_HEAD,
    E_VARLIST_SYM_HEAD,
    E_OPERAND_SYM_HEAD,
    E_START_SYM_HEAD,
    E_END_SYM_HEAD,
    E_NEXT2_SYM_HEAD,
    E_SUBTABLE_SYM_HEAD,
}

# P-code opcodes used for state-space effects.
OP_LOAD = 2
OP_STORE = 3
OP_BRANCH = 4
OP_CBRANCH = 5
OP_BRANCHIND = 6
OP_CALL = 7
OP_CALLIND = 8
OP_RETURN = 10
OP_BUILD = 60

FLAG_REGISTERS = {
    "CF",
    "F1",
    "PF",
    "F3",
    "AF",
    "F5",
    "ZF",
    "SF",
    "TF",
    "IF",
    "DF",
    "OF",
    "IOPL",
    "NT",
    "F15",
    "RF",
    "VM",
    "AC",
    "VIF",
    "VIP",
    "ID",
    "flags",
    "eflags",
    "rflags",
}

# Legacy names and their 64-bit parent registers.
_GPR_PARENTS = {
    "AL": "RAX",
    "AH": "RAX",
    "AX": "RAX",
    "EAX": "RAX",
    "RAX": "RAX",
    "BL": "RBX",
    "BH": "RBX",
    "BX": "RBX",
    "EBX": "RBX",
    "RBX": "RBX",
    "CL": "RCX",
    "CH": "RCX",
    "CX": "RCX",
    "ECX": "RCX",
    "RCX": "RCX",
    "DL": "RDX",
    "DH": "RDX",
    "DX": "RDX",
    "EDX": "RDX",
    "RDX": "RDX",
    "SIL": "RSI",
    "SI": "RSI",
    "ESI": "RSI",
    "RSI": "RSI",
    "DIL": "RDI",
    "DI": "RDI",
    "EDI": "RDI",
    "RDI": "RDI",
    "SPL": "RSP",
    "SP": "RSP",
    "ESP": "RSP",
    "RSP": "RSP",
    "BPL": "RBP",
    "BP": "RBP",
    "EBP": "RBP",
    "RBP": "RBP",
    "IP": "RIP",
    "EIP": "RIP",
    "RIP": "RIP",
}

_EXTENDED_GPR = re.compile(r"^R([89]|1[0-5])(?:B|W|D)?$")
_VECTOR_REGISTER = re.compile(r"^(?:XMM|YMM|ZMM)(\d+)(?:_[A-Za-z]+)?$")
_MM_REGISTER = re.compile(r"^MM(\d+)(?:_[A-Za-z]+)?$")
_X87_REGISTER = re.compile(r"^ST(\d+)h?$")


def _canonical_register_parent(name: str) -> str | None:
    """Return the root architectural register for a SLEIGH register name."""
    parent = _GPR_PARENTS.get(name)
    if parent is not None:
        return parent

    match = _EXTENDED_GPR.match(name)
    if match is not None:
        return f"R{match.group(1)}"

    match = _VECTOR_REGISTER.match(name)
    if match is not None:
        return f"ZMM{match.group(1)}"

    match = _MM_REGISTER.match(name)
    if match is not None:
        return f"MM{match.group(1)}"

    match = _X87_REGISTER.match(name)
    if match is not None:
        return f"ST{match.group(1)}"

    return None


MAX_INSTRUCTION_BYTES = 16
UINTM_MASK = 0xFFFFFFFF


@dataclass
class SlaElement:
    """One decoded element in the packed specification stream."""

    id: int
    attributes: dict[int, Any] = field(default_factory=dict)
    children: list["SlaElement"] = field(default_factory=list)


class _PackedReader:
    """Decode Ghidra's packed element/attribute encoding."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def _byte(self) -> int:
        if self.position >= len(self.data):
            raise SlaError("unexpected end of packed SLEIGH data")
        value = self.data[self.position]
        self.position += 1
        return value

    def _peek(self) -> int:
        if self.position >= len(self.data):
            raise SlaError("unexpected end of packed SLEIGH data")
        return self.data[self.position]

    def _integer(self, length: int) -> int:
        value = 0
        for _ in range(length):
            value = (value << 7) | (self._byte() & 0x7F)
        return value

    def _attribute(self) -> tuple[int, Any]:
        header = self._byte()
        if header & 0xC0 != 0xC0:
            raise SlaError("expected packed attribute")
        attribute_id = header & 0x1F
        if header & 0x20:
            attribute_id = (attribute_id << 7) | (self._byte() & 0x7F)

        type_byte = self._byte()
        type_code = type_byte >> 4
        length_code = type_byte & 0x0F

        if type_code == 1:
            value: Any = length_code != 0
        elif type_code == 2:
            value = self._integer(length_code)
        elif type_code == 3:
            value = -self._integer(length_code)
        elif type_code == 4:
            value = self._integer(length_code)
        elif type_code == 5:
            value = ("space", self._integer(length_code))
        elif type_code == 6:
            value = ("special_space", length_code)
        elif type_code == 7:
            length = self._integer(length_code)
            start = self.position
            self.position += length
            value = self.data[start : self.position].decode("utf-8")
        else:
            raise SlaError(f"unknown packed attribute type {type_code}")

        return attribute_id, value

    def element(self) -> SlaElement:
        header = self._byte()
        if header & 0xC0 != 0x40:
            raise SlaError("expected packed element start")
        element_id = header & 0x1F
        if header & 0x20:
            element_id = (element_id << 7) | (self._byte() & 0x7F)

        attributes: dict[int, Any] = {}
        while self._peek() & 0xC0 == 0xC0:
            attribute_id, value = self._attribute()
            attributes[attribute_id] = value

        children: list[SlaElement] = []
        while self._peek() & 0xC0 == 0x40:
            children.append(self.element())

        end_header = self._byte()
        if end_header & 0xC0 != 0x80:
            raise SlaError("expected packed element end")
        end_id = end_header & 0x1F
        if end_header & 0x20:
            end_id = (end_id << 7) | (self._byte() & 0x7F)
        if end_id != element_id:
            raise SlaError(
                f"packed element close mismatch: {element_id} != {end_id}"
            )

        return SlaElement(element_id, attributes, children)


def decode_sla(path: str | Path) -> SlaElement:
    """Decode a Ghidra ``.sla`` file into an element tree."""
    data = Path(path).read_bytes()
    if data[:4] != b"sla\x04":
        raise SlaError(f"{path} is not a version 4 SLA file")
    try:
        unpacked = zlib.decompress(data[4:])
    except zlib.error as exc:
        raise SlaError(f"failed to decompress {path}: {exc}") from exc

    root = _PackedReader(unpacked).element()
    if root.id != E_SLEIGH:
        raise SlaError(f"{path} does not contain a <sleigh> root element")
    return root


@dataclass(frozen=True)
class AddressSpaceInfo:
    index: int
    name: str
    size: int
    word_size: int
    big_endian: bool
    kind: str


@dataclass(frozen=True)
class SymbolInfo:
    id: int
    name: str
    scope: int
    kind: int
    content: SlaElement | None = None


@dataclass(frozen=True)
class VarnodeInfo:
    symbol_id: int
    name: str
    space_index: int
    offset: int
    size: int


@dataclass(frozen=True)
class OperandInfo:
    symbol_id: int
    name: str
    subsym_id: int | None
    relative_offset: int
    offset_base: int
    minimum_length: int
    index: int
    definition: tuple[Any, ...] | None = None


@dataclass(frozen=True)
class VarListInfo:
    symbol_id: int
    name: str
    pattern: Any
    varnodes: tuple[int | None, ...]


@dataclass(frozen=True)
class ContextInfo:
    symbol_id: int
    name: str
    startbit: int
    endbit: int


@dataclass(frozen=True)
class ConstTpl:
    kind: str
    value: int = 0
    select: int = 0
    plus: int = 0


@dataclass(frozen=True)
class VarnodeTpl:
    space: ConstTpl
    offset: ConstTpl
    size: ConstTpl


@dataclass(frozen=True)
class OpTpl:
    opcode: int
    output: VarnodeTpl | None
    inputs: tuple[VarnodeTpl, ...]


@dataclass(frozen=True)
class HandleTpl:
    space: ConstTpl
    size: ConstTpl
    ptrspace: ConstTpl
    ptroffset: ConstTpl
    ptrsize: ConstTpl
    temp_space: ConstTpl
    temp_offset: ConstTpl


@dataclass(frozen=True)
class ConstructTpl:
    result: HandleTpl | None
    ops: tuple[OpTpl, ...]


@dataclass(frozen=True)
class ContextOp:
    word: int
    shift: int
    mask: int
    expression: tuple[Any, ...]


@dataclass
class Constructor:
    index: int
    parent_id: int
    minimum_length: int
    operands: list[int]
    print_pieces: list[tuple[str, Any]]
    context_ops: list[ContextOp]
    template: ConstructTpl | None
    raw: SlaElement


@dataclass
class PatternBlock:
    offset: int = 0
    nonzerosize: int = 0
    masks: list[int] = field(default_factory=list)
    values: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.normalize()

    def normalize(self) -> None:
        if self.nonzerosize <= 0:
            self.offset = 0
            self.masks.clear()
            self.values.clear()
            return

        start = 0
        while start < len(self.masks) and self.masks[start] == 0:
            start += 1
        if start:
            self.masks = self.masks[start:]
            self.values = self.values[start:]
            self.offset += start * 4

        if self.masks:
            suboff = 0
            tmp = self.masks[0]
            while tmp != 0:
                suboff += 1
                tmp >>= 8
            suboff = 4 - suboff
            if suboff:
                self.offset += suboff
                for i in range(len(self.masks) - 1):
                    self.masks[i] = (
                        (self.masks[i] << (suboff * 8))
                        | (self.masks[i + 1] >> ((4 - suboff) * 8))
                    ) & UINTM_MASK
                    self.values[i] = (
                        (self.values[i] << (suboff * 8))
                        | (self.values[i + 1] >> ((4 - suboff) * 8))
                    ) & UINTM_MASK
                self.masks[-1] = (self.masks[-1] << (suboff * 8)) & UINTM_MASK
                self.values[-1] = (self.values[-1] << (suboff * 8)) & UINTM_MASK

            end = len(self.masks)
            while end > 0 and self.masks[end - 1] == 0:
                end -= 1
            self.masks = self.masks[:end]
            self.values = self.values[:end]

        if not self.masks:
            self.offset = 0
            self.nonzerosize = 0
            return

        self.nonzerosize = len(self.masks) * 4
        tmp = self.masks[-1]
        while (tmp & 0xFF) == 0:
            self.nonzerosize -= 1
            tmp >>= 8

    def match_instruction(self, data: bytes, base_offset: int) -> bool:
        if self.nonzerosize <= 0:
            return self.nonzerosize == 0
        offset = base_offset + self.offset
        for mask, value in zip(self.masks, self.values):
            if (_instruction_bytes(data, offset, 4) & mask) != value:
                return False
            offset += 4
        return True

    def match_context(self, context: int) -> bool:
        if self.nonzerosize <= 0:
            return self.nonzerosize == 0
        offset = self.offset
        for mask, value in zip(self.masks, self.values):
            if (_context_bytes(context, offset, 4) & mask) != value:
                return False
            offset += 4
        return True


@dataclass
class Pattern:
    kind: str
    block: PatternBlock | None = None
    children: list["Pattern"] = field(default_factory=list)

    def match(self, data: bytes, context: int, base_offset: int) -> bool:
        if self.kind == "instruction":
            assert self.block is not None
            return self.block.match_instruction(data, base_offset)
        if self.kind == "context":
            assert self.block is not None
            return self.block.match_context(context)
        if self.kind == "combine":
            return all(
                child.match(data, context, base_offset) for child in self.children
            )
        if self.kind == "or":
            return any(
                child.match(data, context, base_offset) for child in self.children
            )
        raise SlaError(f"unknown pattern kind {self.kind}")


@dataclass
class DecisionNode:
    startbit: int
    bitsize: int
    context: bool
    pairs: list[tuple[Pattern, int]] = field(default_factory=list)
    children: list["DecisionNode"] = field(default_factory=list)

    def resolve(
        self, data: bytes, context: int, base_offset: int
    ) -> int | None:
        if self.bitsize == 0:
            for pattern, constructor_id in self.pairs:
                if pattern.match(data, context, base_offset):
                    return constructor_id
            return None

        if self.context:
            value = _context_bits(context, self.startbit, self.bitsize)
        else:
            value = _instruction_bits(
                data, base_offset * 8 + self.startbit, self.bitsize
            )
        if value >= len(self.children):
            return None
        return self.children[value].resolve(data, context, base_offset)


@dataclass
class Subtable:
    symbol_id: int
    name: str
    constructors: list[Constructor] = field(default_factory=list)
    decision: DecisionNode | None = None


@dataclass
class ResolvedConstructor:
    constructor: Constructor
    offset: int
    length: int
    context: int = 0
    operands: list["ResolvedOperand"] = field(default_factory=list)


@dataclass
class ResolvedOperand:
    operand: OperandInfo
    offset: int
    length: int
    resolved: ResolvedConstructor | None = None


def _instruction_bytes(data: bytes, offset: int, count: int) -> int:
    chunk = data[offset : offset + count]
    if len(chunk) < count:
        chunk = chunk.ljust(count, b"\0")
    return int.from_bytes(chunk, "big")


def _instruction_bits(data: bytes, startbit: int, size: int) -> int:
    byte_offset = startbit // 8
    bit_offset = startbit % 8
    byte_count = (bit_offset + size - 1) // 8 + 1
    value = _instruction_bytes(data, byte_offset, byte_count)
    value <<= 8 * (4 - byte_count) + bit_offset
    value >>= 8 * 4 - size
    return value & ((1 << size) - 1)


def _context_words(context: int) -> tuple[int, int]:
    return ((context >> 32) & UINTM_MASK, context & UINTM_MASK)


def _context_bytes(context: int, byte_start: int, count: int) -> int:
    words = _context_words(context)
    int_start = byte_start // 4
    if int_start >= len(words):
        return 0
    value = words[int_start]
    byte_offset = byte_start % 4
    unused_bytes = 4 - count
    value = (value << (byte_offset * 8)) & UINTM_MASK
    value >>= unused_bytes * 8
    remaining = count - 4 + byte_offset
    if remaining > 0 and int_start + 1 < len(words):
        second = words[int_start + 1]
        unused_bytes = 4 - remaining
        second >>= unused_bytes * 8
        value |= second
    return value


def _context_bits(context: int, startbit: int, size: int) -> int:
    return (context >> (64 - startbit - size)) & ((1 << size) - 1)


def _byte_swap(value: int, size: int) -> int:
    result = 0
    for _ in range(size):
        result = (result << 8) | (value & 0xFF)
        value >>= 8
    return result


def _eval_expr(
    expr: tuple[Any, ...],
    data: bytes,
    base_offset: int,
    context: int,
    operand_resolver=None,
) -> int | None:
    kind = expr[0]
    if kind == "const":
        return int(expr[1])
    if kind == "token":
        _, bigendian, signbit, startbit, endbit, bytestart, byteend, shift = expr
        size = byteend - bytestart + 1
        value = 0
        remaining = size
        position = base_offset + bytestart
        while remaining >= 4:
            value = (value << 32) | _instruction_bytes(data, position, 4)
            position += 4
            remaining -= 4
        if remaining > 0:
            value = (value << (8 * remaining)) | _instruction_bytes(
                data, position, remaining
            )
        if not bigendian:
            value = _byte_swap(value, size)
        value >>= shift
        bits = endbit - startbit + 1
        value &= (1 << bits) - 1
        if signbit and value & (1 << (bits - 1)):
            value -= 1 << bits
        return value
    if kind == "context":
        _, signbit, startbit, endbit = expr
        size = endbit - startbit + 1
        value = _context_bits(context, startbit, size)
        if signbit and value & (1 << (size - 1)):
            value -= 1 << size
        return value
    if kind in ("start", "next", "next2"):
        return 0
    if kind == "operand":
        if operand_resolver is None:
            return None
        return operand_resolver(int(expr[1]))
    if kind == "unary":
        _, operator, operand = expr
        value = _eval_expr(
            operand, data, base_offset, context, operand_resolver
        )
        if value is None:
            return None
        if operator == "minus":
            return -value
        if operator == "not":
            return ~value
        raise SlaError(f"unknown unary expression {operator}")
    if kind == "binary":
        _, operator, left, right = expr
        lhs = _eval_expr(left, data, base_offset, context, operand_resolver)
        rhs = _eval_expr(right, data, base_offset, context, operand_resolver)
        if lhs is None or rhs is None:
            return None
        if operator == "plus":
            return lhs + rhs
        if operator == "minus":
            return lhs - rhs
        if operator == "mult":
            return lhs * rhs
        if operator == "lshift":
            return lhs << rhs
        if operator == "rshift":
            return lhs >> rhs
        if operator == "and":
            return lhs & rhs
        if operator == "or":
            return lhs | rhs
        if operator == "xor":
            return lhs ^ rhs
        if operator == "div":
            return lhs // rhs
        raise SlaError(f"unknown binary expression {operator}")
    raise SlaError(f"unknown pattern expression {kind}")


def _expr_contains(expr: tuple[Any, ...], kind: str) -> bool:
    if expr[0] == kind:
        return True
    return any(
        _expr_contains(part, kind)
        for part in expr[1:]
        if isinstance(part, tuple)
    )


def _expr_operand_index(expr: tuple[Any, ...]) -> int | None:
    if expr[0] == "operand":
        return int(expr[1])
    for part in expr[1:]:
        if isinstance(part, tuple):
            result = _expr_operand_index(part)
            if result is not None:
                return result
    return None


def _parse_expr(element: SlaElement) -> tuple[Any, ...]:
    if element.id == E_TOKENFIELD:
        a = element.attributes
        return (
            "token",
            a[A_BIGENDIAN],
            a[A_SIGNBIT],
            a[A_STARTBIT],
            a[A_ENDBIT],
            a[A_STARTBYTE],
            a[A_ENDBYTE],
            a[A_SHIFT],
        )
    if element.id == E_CONTEXTFIELD:
        a = element.attributes
        return ("context", a[A_SIGNBIT], a[A_STARTBIT], a[A_ENDBIT])
    if element.id == E_INTB:
        return ("const", element.attributes[A_VAL])
    if element.id == E_START_EXP:
        return ("start",)
    if element.id == E_END_EXP:
        return ("next",)
    if element.id == E_NEXT2_EXP:
        return ("next2",)
    if element.id == E_OPERAND_EXP:
        a = element.attributes
        return ("operand", a[A_INDEX], a[A_TABLE], a[A_CT])
    if element.id in (E_MINUS_EXP, E_NOT_EXP):
        return (
            "unary",
            "minus" if element.id == E_MINUS_EXP else "not",
            _parse_expr(element.children[0]),
        )
    operators = {
        E_PLUS_EXP: "plus",
        E_SUB_EXP: "minus",
        E_MULT_EXP: "mult",
        E_LSHIFT_EXP: "lshift",
        E_RSHIFT_EXP: "rshift",
        E_AND_EXP: "and",
        E_OR_EXP: "or",
        E_XOR_EXP: "xor",
        E_DIV_EXP: "div",
    }
    if element.id in operators:
        return (
            "binary",
            operators[element.id],
            _parse_expr(element.children[0]),
            _parse_expr(element.children[1]),
        )
    raise SlaError(f"unsupported pattern expression element {element.id}")


def _parse_pattern_block(element: SlaElement) -> PatternBlock:
    a = element.attributes
    masks: list[int] = []
    values: list[int] = []
    for child in element.children:
        if child.id == E_MASK_WORD:
            masks.append(int(child.attributes[A_MASK]))
            values.append(int(child.attributes[A_VAL]))
    return PatternBlock(int(a[A_OFF]), int(a[A_NONZERO]), masks, values)


def _parse_pattern(element: SlaElement) -> Pattern:
    if element.id == E_INSTRUCT_PAT:
        return Pattern("instruction", _parse_pattern_block(element.children[0]))
    if element.id == E_CONTEXT_PAT:
        return Pattern("context", _parse_pattern_block(element.children[0]))
    if element.id == E_COMBINE_PAT:
        return Pattern("combine", children=[_parse_pattern(c) for c in element.children])
    if element.id == E_OR_PAT:
        return Pattern("or", children=[_parse_pattern(c) for c in element.children])
    raise SlaError(f"unsupported pattern element {element.id}")


def _parse_decision(element: SlaElement) -> DecisionNode:
    a = element.attributes
    node = DecisionNode(
        startbit=int(a[A_STARTBIT]),
        bitsize=int(a[A_SIZE]),
        context=bool(a[A_CONTEXT]),
    )
    for child in element.children:
        if child.id == E_PAIR:
            pattern_element = next(
                c
                for c in child.children
                if c.id in (E_INSTRUCT_PAT, E_CONTEXT_PAT, E_COMBINE_PAT, E_OR_PAT)
            )
            node.pairs.append((_parse_pattern(pattern_element), int(child.attributes[A_ID])))
        elif child.id == E_DECISION:
            node.children.append(_parse_decision(child))
    return node


def _parse_const(element: SlaElement) -> ConstTpl:
    a = element.attributes
    if element.id == E_CONST_REAL:
        return ConstTpl("real", int(a[A_VAL]))
    if element.id == E_CONST_HANDLE:
        return ConstTpl(
            "handle",
            int(a[A_VAL]),
            int(a[A_S]),
            int(a.get(A_PLUS, 0)),
        )
    if element.id == E_CONST_SPACEID:
        space = a[A_SPACE]
        if not isinstance(space, tuple) or space[0] != "space":
            raise SlaError("CONST_SPACEID is missing its address space")
        return ConstTpl("spaceid", int(space[1]))
    if element.id == E_CONST_START:
        return ConstTpl("start")
    if element.id == E_CONST_NEXT:
        return ConstTpl("next")
    if element.id == E_CONST_NEXT2:
        return ConstTpl("next2")
    if element.id == E_CONST_CURSPACE:
        return ConstTpl("curspace")
    if element.id == E_CONST_CURSPACE_SIZE:
        return ConstTpl("curspace_size")
    if element.id == E_CONST_RELATIVE:
        return ConstTpl("relative", int(a[A_VAL]))
    if element.id == E_CONST_FLOWREF:
        return ConstTpl("flowref")
    if element.id == E_CONST_FLOWREF_SIZE:
        return ConstTpl("flowref_size")
    if element.id == E_CONST_FLOWDEST:
        return ConstTpl("flowdest")
    if element.id == E_CONST_FLOWDEST_SIZE:
        return ConstTpl("flowdest_size")
    raise SlaError(f"unsupported constant element {element.id}")


def _parse_varnode_tpl(element: SlaElement) -> VarnodeTpl:
    if element.id != E_VARNODE_TPL or len(element.children) != 3:
        raise SlaError("invalid VARNODE_TPL")
    return VarnodeTpl(
        _parse_const(element.children[0]),
        _parse_const(element.children[1]),
        _parse_const(element.children[2]),
    )


def _parse_op_tpl(element: SlaElement) -> OpTpl:
    children = iter(element.children)
    first = next(children)
    output = None if first.id == E_NULL else _parse_varnode_tpl(first)
    inputs = tuple(_parse_varnode_tpl(child) for child in children)
    return OpTpl(int(element.attributes[A_CODE]), output, inputs)


def _parse_handle_tpl(element: SlaElement) -> HandleTpl:
    if element.id != E_HANDLE_TPL or len(element.children) != 7:
        raise SlaError("invalid HANDLE_TPL")
    return HandleTpl(*(_parse_const(child) for child in element.children))


def _parse_construct_tpl(element: SlaElement) -> ConstructTpl | None:
    if A_SECTION in element.attributes:
        return None
    result = None
    ops: list[OpTpl] = []
    for child in element.children:
        if child.id == E_HANDLE_TPL:
            result = _parse_handle_tpl(child)
        elif child.id == E_OP_TPL:
            ops.append(_parse_op_tpl(child))
    return ConstructTpl(result, tuple(ops))


class SlaSpec:
    """A decoded SLEIGH specification with instruction-resolution helpers."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.root = decode_sla(self.path)
        self.spaces: dict[int, AddressSpaceInfo] = {}
        self.symbols: dict[int, SymbolInfo] = {}
        self.varnodes: dict[int, VarnodeInfo] = {}
        self.operands: dict[int, OperandInfo] = {}
        self.varlists: dict[int, VarListInfo] = {}
        self.contexts: dict[int, ContextInfo] = {}
        self.subtables: dict[int, Subtable] = {}
        self._varnodes_by_location: dict[tuple[int, int, int], VarnodeInfo] = {}
        self._varnodes_by_name: dict[str, VarnodeInfo] = {}
        self._canonical_registers: dict[int, VarnodeInfo] = {}
        self.default_space = "ram"
        self.root_subtable: Subtable | None = None
        self._parse()

    @classmethod
    def from_path(cls, path: str | Path) -> "SlaSpec":
        return cls(path)

    def _parse(self) -> None:
        self.spaces[0] = AddressSpaceInfo(0, "const", 8, 1, False, "const")
        symbol_table: SlaElement | None = None
        for child in self.root.children:
            if child.id == E_SPACES:
                self._parse_spaces(child)
            elif child.id == E_SYMBOL_TABLE:
                symbol_table = child

        if symbol_table is None:
            raise SlaError("SLA specification has no symbol table")
        self._parse_symbols(symbol_table)
        self._build_register_canonicalization()
        self._parse_subtables()

        self.root_subtable = next(
            (sub for sub in self.subtables.values() if sub.name == "instruction"),
            None,
        )
        if self.root_subtable is None:
            raise SlaError("SLA specification has no 'instruction' subtable")

    def _parse_spaces(self, element: SlaElement) -> None:
        self.default_space = str(element.attributes.get(A_DEFAULTSPACE, "ram"))
        for child in element.children:
            a = child.attributes
            index = int(a[A_INDEX])
            kind = {
                E_SPACE: "ram",
                E_SPACE_UNIQUE: "unique",
                E_SPACE_OTHER: "other",
            }[child.id]
            self.spaces[index] = AddressSpaceInfo(
                index=index,
                name=str(a[A_NAME]),
                size=int(a[A_SIZE]),
                word_size=int(a.get(A_WORDSIZE, 1)),
                big_endian=bool(a.get(A_BIGENDIAN, False)),
                kind=kind,
            )

    def _parse_symbols(self, symbol_table: SlaElement) -> None:
        for child in symbol_table.children:
            if child.id not in HEADER_ELEMENTS:
                continue
            symbol_id = int(child.attributes[A_ID])
            self.symbols[symbol_id] = SymbolInfo(
                id=symbol_id,
                name=str(child.attributes[A_NAME]),
                scope=int(child.attributes[A_SCOPE]),
                kind=child.id,
            )

        contents: dict[int, SlaElement] = {}
        for child in symbol_table.children:
            if child.id == E_SCOPE or child.id in HEADER_ELEMENTS:
                continue
            symbol_id = child.attributes.get(A_ID)
            if symbol_id is not None:
                contents[int(symbol_id)] = child

        for symbol_id, content in contents.items():
            symbol = self.symbols.get(symbol_id)
            if symbol is not None:
                self.symbols[symbol_id] = SymbolInfo(
                    symbol.id, symbol.name, symbol.scope, symbol.kind, content
                )

        for symbol_id, content in contents.items():
            symbol = self.symbols[symbol_id]
            if content.id == E_VARNODE_SYM:
                a = content.attributes
                space = a[A_SPACE]
                if not isinstance(space, tuple) or space[0] != "space":
                    raise SlaError(f"register {symbol.name} has no address space")
                varnode = VarnodeInfo(
                    symbol_id=symbol_id,
                    name=symbol.name,
                    space_index=int(space[1]),
                    offset=int(a[A_OFF]),
                    size=int(a[A_SIZE]),
                )
                self.varnodes[symbol_id] = varnode
                self._varnodes_by_location[
                    (varnode.space_index, varnode.offset, varnode.size)
                ] = varnode
                self._varnodes_by_name.setdefault(varnode.name, varnode)
            elif content.id == E_OPERAND_SYM:
                a = content.attributes
                self.operands[symbol_id] = OperandInfo(
                    symbol_id=symbol_id,
                    name=symbol.name,
                    subsym_id=(
                        int(a[A_SUBSYM]) if A_SUBSYM in a else None
                    ),
                    relative_offset=int(a[A_OFF]),
                    offset_base=int(a[A_BASE]),
                    minimum_length=int(a[A_MINLEN]),
                    index=int(a[A_INDEX]),
                    definition=(
                        _parse_expr(content.children[1])
                        if len(content.children) > 1
                        else None
                    ),
                )
            elif content.id == E_VARLIST_SYM:
                pattern = _parse_expr(content.children[0])
                varnodes: list[int | None] = []
                for child in content.children[1:]:
                    if child.id == E_VAR:
                        varnodes.append(int(child.attributes[A_ID]))
                    else:
                        varnodes.append(None)
                self.varlists[symbol_id] = VarListInfo(
                    symbol_id, symbol.name, pattern, tuple(varnodes)
                )
            elif content.id == E_CONTEXT_SYM:
                field = next(
                    child
                    for child in content.children
                    if child.id == E_CONTEXTFIELD
                )
                self.contexts[symbol_id] = ContextInfo(
                    symbol_id,
                    symbol.name,
                    int(field.attributes[A_STARTBIT]),
                    int(field.attributes[A_ENDBIT]),
                )

    def _build_register_canonicalization(self) -> None:
        for varnode in self.varnodes.values():
            parent_name = _canonical_register_parent(varnode.name)
            parent = self._varnodes_by_name.get(parent_name) if parent_name else None
            self._canonical_registers[varnode.symbol_id] = parent or varnode

    def _parse_subtables(self) -> None:
        for symbol_id, symbol in self.symbols.items():
            content = symbol.content
            if symbol.kind != E_SUBTABLE_SYM_HEAD or content is None:
                continue

            subtable = Subtable(symbol_id, symbol.name)
            for index, child in enumerate(
                (c for c in content.children if c.id == E_CONSTRUCTOR)
            ):
                subtable.constructors.append(
                    self._parse_constructor(index, symbol_id, child)
                )
            decision = next(
                (c for c in content.children if c.id == E_DECISION), None
            )
            if decision is not None:
                subtable.decision = _parse_decision(decision)
            self.subtables[symbol_id] = subtable

    def _parse_constructor(
        self, index: int, parent_id: int, element: SlaElement
    ) -> Constructor:
        a = element.attributes
        operands = [
            int(child.attributes[A_ID])
            for child in element.children
            if child.id == E_OPER
        ]
        pieces: list[tuple[str, Any]] = []
        context_ops: list[ContextOp] = []
        template = None
        for child in element.children:
            if child.id == E_PRINT:
                pieces.append(("text", str(child.attributes[A_PIECE])))
            elif child.id == E_OPPRINT:
                pieces.append(("operand", int(child.attributes[A_ID])))
            elif child.id == E_CONTEXT_OP:
                ca = child.attributes
                context_ops.append(
                    ContextOp(
                        word=int(ca[A_I]),
                        shift=int(ca[A_SHIFT]),
                        mask=int(ca[A_MASK]),
                        expression=_parse_expr(child.children[0]),
                    )
                )
            elif child.id == E_CONSTRUCT_TPL:
                parsed = _parse_construct_tpl(child)
                if parsed is not None:
                    template = parsed
        return Constructor(
            index=index,
            parent_id=parent_id,
            minimum_length=int(a[A_LENGTH]),
            operands=operands,
            print_pieces=pieces,
            context_ops=context_ops,
            template=template,
            raw=element,
        )

    def build_context(self, defaults: dict[str, int]) -> int:
        """Build a 64-bit SLEIGH context value from named defaults."""
        context = 0
        for name, value in defaults.items():
            info = next(
                (c for c in self.contexts.values() if c.name == name), None
            )
            if info is None:
                raise SlaError(f"unknown context variable {name!r}")
            bits = info.endbit - info.startbit + 1
            mask = ((1 << bits) - 1) << (64 - (info.startbit + bits))
            context = (context & ~mask) | (
                (int(value) << (64 - (info.startbit + bits))) & mask
            )
        return context

    def resolve(
        self, data: bytes, context: int, base_offset: int = 0
    ) -> ResolvedConstructor | None:
        if self.root_subtable is None:
            return None
        return self._resolve_subtable(
            self.root_subtable, data, context, base_offset, 0
        )

    def _resolve_subtable(
        self,
        subtable: Subtable,
        data: bytes,
        context: int,
        base_offset: int,
        depth: int,
    ) -> ResolvedConstructor | None:
        if subtable.decision is None or depth > 64:
            return None
        constructor_id = subtable.decision.resolve(data, context, base_offset)
        if constructor_id is None or constructor_id >= len(subtable.constructors):
            return None
        return self._resolve_constructor(
            subtable.constructors[constructor_id],
            data,
            context,
            base_offset,
            depth,
        )

    def _operand_ref_value(
        self,
        index: int,
        operands: list[ResolvedOperand],
        data: bytes,
        context: int,
        seen: set[int] | None = None,
    ) -> int | None:
        if seen is None:
            seen = set()
        if index < 0 or index >= len(operands) or index in seen:
            return None
        seen.add(index)
        operand = operands[index]
        definition = operand.operand.definition
        if definition is None:
            return None
        return _eval_expr(
            definition,
            data,
            operand.offset,
            context,
            lambda nested: self._operand_ref_value(
                nested, operands, data, context, seen
            ),
        )

    def _apply_context_ops(
        self,
        context_ops: list[ContextOp],
        operands: list[ResolvedOperand],
        data: bytes,
        base_offset: int,
        context: int,
    ) -> int:
        for op in context_ops:
            value = _eval_expr(
                op.expression,
                data,
                base_offset,
                context,
                lambda index: self._operand_ref_value(
                    index, operands, data, context
                ),
            )
            if value is None:
                continue
            word_shift = 32 * (1 - op.word)
            mask = op.mask & UINTM_MASK
            context &= ~(mask << word_shift)
            context |= (((value << op.shift) & mask) << word_shift)
        return context

    def _resolve_constructor(
        self,
        constructor: Constructor,
        data: bytes,
        context: int,
        base_offset: int,
        depth: int,
    ) -> ResolvedConstructor | None:
        resolved = ResolvedConstructor(constructor, base_offset, 0)
        for operand_id in constructor.operands:
            operand = self.operands[operand_id]
            if operand.offset_base < 0:
                offset = base_offset + operand.relative_offset
            else:
                base = resolved.operands[operand.offset_base]
                offset = base.offset + base.length
            resolved.operands.append(
                ResolvedOperand(operand, offset, operand.minimum_length)
            )

        context = self._apply_context_ops(
            constructor.context_ops,
            resolved.operands,
            data,
            base_offset,
            context,
        )
        resolved.context = context

        for index, child in enumerate(resolved.operands):
            operand = child.operand
            if operand.offset_base >= 0:
                base = resolved.operands[operand.offset_base]
                child.offset = base.offset + base.length
            subtable = (
                self.subtables.get(operand.subsym_id)
                if operand.subsym_id is not None
                else None
            )
            if subtable is not None:
                nested = self._resolve_subtable(
                    subtable, data, context, child.offset, depth + 1
                )
                if nested is None:
                    return None
                child.resolved = nested
                child.length = nested.length

        length = constructor.minimum_length + base_offset
        for child in resolved.operands:
            length = max(length, child.offset + child.length)
        resolved.length = length - base_offset
        return resolved

    def _handle_tpl_location(
        self,
        handle: HandleTpl,
        owner: ResolvedConstructor,
        data: bytes,
        context: int,
        address: int,
    ) -> VarnodeInfo | None:
        context = owner.context
        space = self._const_value(
            handle.space, owner, data, context, address
        )
        offset = self._const_value(
            handle.ptroffset, owner, data, context, address
        )
        size = self._const_value(
            handle.size, owner, data, context, address
        )
        if space is None or offset is None or size is None:
            return None
        return VarnodeInfo(-1, "", space, offset, size)

    def _location_for_operand(
        self,
        operand: ResolvedOperand,
        data: bytes,
        context: int,
        address: int = 0,
    ) -> VarnodeInfo | None:
        symbol_id = operand.operand.subsym_id
        direct = self.varnodes.get(symbol_id)
        if direct is not None:
            return direct

        varlist = self.varlists.get(symbol_id)
        if varlist is not None:
            index = _eval_expr(
                varlist.pattern, data, operand.offset, context
            )
            if index is None or index < 0 or index >= len(varlist.varnodes):
                return None
            varnode_id = varlist.varnodes[index]
            if varnode_id is None:
                return None
            return self.varnodes.get(varnode_id)

        if operand.resolved is not None:
            owner = operand.resolved
            template = owner.constructor.template
            if template is not None and template.result is not None:
                result = self._handle_tpl_location(
                    template.result, owner, data, owner.context, address
                )
                if result is not None:
                    return result
            for child in owner.operands:
                result = self._location_for_operand(
                    child, data, owner.context, address
                )
                if result is not None:
                    return result
        return None

    def _handle_varnode(
        self,
        handle_index: int,
        resolved: ResolvedConstructor,
        data: bytes,
        context: int,
        address: int,
    ) -> VarnodeInfo | None:
        if handle_index < 0 or handle_index >= len(resolved.operands):
            return None
        return self._location_for_operand(
            resolved.operands[handle_index], data, resolved.context, address
        )

    @staticmethod
    def _first_handle_index(tpl: VarnodeTpl) -> int | None:
        for const in (tpl.space, tpl.offset, tpl.size):
            if const.kind == "handle":
                return const.value
        return None

    def _register_states_for_operand(
        self,
        operand: ResolvedOperand,
        data: bytes,
        context: int,
    ) -> list[StateSpace]:
        states: list[StateSpace] = []
        symbol_id = operand.operand.subsym_id
        direct = self.varnodes.get(symbol_id)
        if direct is not None:
            state = self._state_space(
                (direct.space_index, direct.offset, direct.size)
            )
            if state is not None and state.kind is not StateSpaceKind.MEMORY:
                states.append(state)

        varlist = self.varlists.get(symbol_id)
        if varlist is not None:
            index = _eval_expr(varlist.pattern, data, operand.offset, context)
            if index is not None and 0 <= index < len(varlist.varnodes):
                varnode_id = varlist.varnodes[index]
                if varnode_id is not None:
                    varnode = self.varnodes.get(varnode_id)
                    if varnode is not None:
                        state = self._state_space(
                            (varnode.space_index, varnode.offset, varnode.size)
                        )
                        if (
                            state is not None
                            and state.kind is not StateSpaceKind.MEMORY
                        ):
                            states.append(state)

        if operand.resolved is not None:
            nested_context = operand.resolved.context
            for child in operand.resolved.operands:
                for state in self._register_states_for_operand(
                    child, data, nested_context
                ):
                    if state not in states:
                        states.append(state)
        return states

    def _const_value(
        self,
        const: ConstTpl,
        resolved: ResolvedConstructor,
        data: bytes,
        context: int,
        address: int,
    ) -> int | None:
        if const.kind == "real":
            return const.value
        if const.kind == "handle":
            varnode = self._handle_varnode(
                const.value, resolved, data, context, address
            )
            if varnode is None:
                return None
            if const.select == 0:
                return varnode.space_index
            if const.select == 1:
                return varnode.offset + const.plus
            if const.select == 2:
                return varnode.size
            if const.select == 3:
                return varnode.offset + const.plus
            return None
        if const.kind == "spaceid":
            return const.value
        if const.kind == "start":
            return address
        if const.kind == "next":
            return address + resolved.length
        if const.kind == "next2":
            return address + resolved.length
        if const.kind == "curspace":
            return self._space_index(self.default_space)
        if const.kind == "curspace_size":
            return self.spaces[self._space_index(self.default_space)].size
        return None

    def _resolve_varnode_tpl(
        self,
        tpl: VarnodeTpl,
        resolved: ResolvedConstructor,
        data: bytes,
        context: int,
        address: int,
    ) -> tuple[int, int, int] | None:
        space = self._const_value(
            tpl.space, resolved, data, context, address
        )
        offset = self._const_value(
            tpl.offset, resolved, data, context, address
        )
        size = self._const_value(
            tpl.size, resolved, data, context, address
        )
        if space is None or offset is None or size is None:
            return None
        return space, offset, size

    def _space_index(self, name: str) -> int:
        for space in self.spaces.values():
            if space.name == name:
                return space.index
        raise SlaError(f"unknown address space {name!r}")

    def _semantic_ops(
        self, resolved: ResolvedConstructor, depth: int = 0
    ):
        """Yield real P-code ops, expanding SLEIGH BUILD directives."""
        if depth > 64:
            return
        template = resolved.constructor.template
        if template is None:
            return
        for op in template.ops:
            if op.opcode == OP_BUILD and op.output is None:
                if not op.inputs:
                    continue
                index = op.inputs[0].offset.value
                if 0 <= index < len(resolved.operands):
                    child = resolved.operands[index].resolved
                    if child is not None:
                        yield from self._semantic_ops(child, depth + 1)
                continue
            yield op, resolved

    def instruction_type(self, resolved: ResolvedConstructor) -> InstructionType:
        mnemonic = self.mnemonic(resolved).upper()
        if mnemonic.startswith("CALL"):
            return InstructionType.CALL
        if mnemonic.startswith("RET") or mnemonic.startswith("IRET"):
            return InstructionType.RET
        if mnemonic.startswith("J") or mnemonic.startswith("LOOP"):
            return InstructionType.BRANCH
        if mnemonic == "NOP":
            return InstructionType.NOP

        if mnemonic:
            # Many non-control instructions contain internal CBRANCH p-code
            # (for example BSF/BSR).  Trust the printed mnemonic over the
            # presence of internal control flow.
            return InstructionType.ARITHMETIC

        ops = list(self._semantic_ops(resolved))
        opcodes = {op.opcode for op, _ in ops}
        if OP_CALL in opcodes or OP_CALLIND in opcodes:
            return InstructionType.CALL
        if OP_BRANCH in opcodes or OP_CBRANCH in opcodes or OP_BRANCHIND in opcodes:
            return InstructionType.BRANCH
        if OP_RETURN in opcodes:
            return InstructionType.RET
        return InstructionType.ARITHMETIC

    def mnemonic(self, resolved: ResolvedConstructor) -> str:
        text = "".join(
            value
            for kind, value in resolved.constructor.print_pieces
            if kind == "text"
        ).strip()
        if text:
            return text.split(" ", 1)[0]
        for child in resolved.operands:
            if child.resolved is not None:
                mnemonic = self.mnemonic(child.resolved)
                if mnemonic:
                    return mnemonic
        return ""

    def _find_relative_displacement(
        self, resolved: ResolvedConstructor
    ) -> tuple[int, int] | None:
        for operand in resolved.operands:
            definition = operand.operand.definition
            if definition is not None and _expr_contains(definition, "next"):
                index = _expr_operand_index(definition)
                if index is not None and index < len(resolved.operands):
                    displacement = resolved.operands[index]
                    return displacement.offset, displacement.length
            if operand.resolved is not None:
                found = self._find_relative_displacement(operand.resolved)
                if found is not None:
                    return found
        return None

    def relative_target(
        self,
        resolved: ResolvedConstructor,
        data: bytes,
        address: int,
    ) -> tuple[int, int, int] | None:
        """Return (target, displacement offset, displacement size)."""
        found = self._find_relative_displacement(resolved)
        if found is None:
            return None
        offset, size = found
        if size <= 0 or offset + size > len(data):
            return None
        displacement = int.from_bytes(
            data[offset : offset + size], "little", signed=True
        )
        return address + resolved.length + displacement, offset, size

    def make_instruction(
        self,
        data: bytes,
        address: int,
        resolved: ResolvedConstructor,
        context: int,
    ) -> Instruction:
        modifies: list[StateSpace] = []
        depends_on: list[StateSpace] = []

        for op, owner in self._semantic_ops(resolved):
            owner_context = owner.context
            if op.output is not None:
                location = self._resolve_varnode_tpl(
                    op.output, owner, data, owner_context, address
                )
                if location is not None:
                    state = self._state_space(location)
                    if state is not None and state not in modifies:
                        modifies.append(state)
                    if state is not None and state.kind is StateSpaceKind.MEMORY:
                        handle_index = self._first_handle_index(op.output)
                        if (
                            handle_index is not None
                            and handle_index < len(owner.operands)
                        ):
                            for source in self._register_states_for_operand(
                                owner.operands[handle_index],
                                data,
                                owner_context,
                            ):
                                if source not in depends_on:
                                    depends_on.append(source)
            elif op.opcode == OP_STORE:
                state = StateSpace(StateSpaceKind.MEMORY, self.default_space, 1)
                if state not in modifies:
                    modifies.append(state)

            if op.opcode == OP_LOAD:
                state = StateSpace(StateSpaceKind.MEMORY, self.default_space, 1)
                if state not in depends_on:
                    depends_on.append(state)

            for input_tpl in op.inputs:
                location = self._resolve_varnode_tpl(
                    input_tpl, owner, data, owner_context, address
                )
                if location is not None:
                    state = self._state_space(location)
                    if state is not None and state not in depends_on:
                        depends_on.append(state)

                handle_index = self._first_handle_index(input_tpl)
                if (
                    handle_index is not None
                    and handle_index < len(owner.operands)
                ):
                    for state in self._register_states_for_operand(
                        owner.operands[handle_index], data, owner_context
                    ):
                        if state not in depends_on:
                            depends_on.append(state)

        length = resolved.length
        return Instruction(
            original_data=data[:length],
            type=self.instruction_type(resolved),
            length=length,
            address=address,
            modifies=modifies,
            depends_on=depends_on,
        )

    def _state_space(
        self, location: tuple[int, int, int]
    ) -> StateSpace | None:
        space_index, offset, size = location
        space = self.spaces.get(space_index)
        if space is None:
            return None
        if space.name == "register":
            varnode = self._varnodes_by_location.get(location)
            if varnode is None:
                containing = [
                    candidate
                    for (s, o, _), candidate in self._varnodes_by_location.items()
                    if s == space_index
                    and o <= offset < o + candidate.size
                    and offset + size <= o + candidate.size
                ]
                varnode = (
                    min(containing, key=lambda candidate: candidate.size)
                    if containing
                    else None
                )
            if varnode is None:
                return None
            canonical = self._canonical_registers.get(varnode.symbol_id, varnode)
            if canonical.name in FLAG_REGISTERS:
                return StateSpace(StateSpaceKind.FLAG, "flags", 1)
            return StateSpace(
                StateSpaceKind.REGISTER, canonical.name, canonical.size
            )
        if space.kind == "ram" or space.kind == "other":
            return StateSpace(StateSpaceKind.MEMORY, space.name, size)
        return None
