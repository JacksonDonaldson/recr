"""Recover constants from RISC-V address materialization sequences."""

from __future__ import annotations

from collections.abc import Iterator, Set
from itertools import product
from typing import TYPE_CHECKING

from isa.riscv.encoding import UPPER, sign_extend

if TYPE_CHECKING:
    from binary.binary import Binary


def _operation(word: int, length: int, xlen: int) -> tuple[str, int, int, int, int] | None:
    """Return (operation, destination, first register, second register, immediate)."""
    rd = (word >> 7) & 31
    if length == 4:
        opcode, funct3 = word & 0x7F, (word >> 12) & 7
        rs1, rs2 = (word >> 15) & 31, (word >> 20) & 31
        low = sign_extend(word >> 20, 12)
        if opcode in (0x17, 0x37):
            return ("pc" if opcode == 0x17 else "add", rd, 0, 0, UPPER.decode(word))
        if opcode in (0x13, 0x1B):
            word_result = opcode == 0x1B
            if funct3 == 0:
                return ("addw" if word_result else "add", rd, rs1, 0, low)
            if funct3 == 1 and word >> (25 if word_result or xlen == 32 else 26) == 0:
                return ("shiftw" if word_result else "shift", rd, rs1, 0, (word >> 20) & (31 if word_result else xlen - 1))
            if funct3 in (4, 6, 7) and not word_result:
                return ({4: "xor", 6: "or", 7: "and"}[funct3], rd, rs1, 0, low)
            return ("kill", rd, 0, 0, 0)
        if opcode in (0x33, 0x3B):
            funct7 = word >> 25
            if funct3 == 0 and funct7 in (0, 0x20):
                name = "sub" if funct7 else "add"
                return (name + ("w" if opcode == 0x3B else ""), rd, rs1, rs2, 0)
            return ("kill", rd, 0, 0, 0)
        if opcode == 0x67 and funct3 == 0:
            return ("jump", rd, rs1, 0, low)
        if opcode == 0x6F:
            return ("call" if rd in (1, 5) else "stop", rd, 0, 0, 0)
        if opcode == 0x03 and funct3 != 7:
            return ("load", rd, rs1, 0, (word >> 20) | (funct3 << 12))
        if opcode in (0x23, 0x27):
            store_offset = sign_extend((word >> 25) << 5 | rd, 12)
            return ("address", 0, rs1, 0, store_offset)
        if opcode in (0x07, 0x2F, 0x73):
            return ("kill" if opcode != 0x07 else "address", rd if opcode != 0x07 else 0, rs1, 0, low)
        return None

    quadrant, funct3 = word & 3, word >> 13
    low = sign_extend(((word >> 12) & 1) << 5 | (word >> 2) & 31, 6)
    if quadrant == 1:
        if funct3 == 0:
            return ("add", rd, rd, 0, low)
        if funct3 == 1:
            return ("addw", rd, rd, 0, low) if xlen == 64 else ("call", 1, 0, 0, 0)
        if funct3 == 2:
            return ("add", rd, 0, 0, low)
        if funct3 == 3 and rd != 2:
            return ("add", rd, 0, 0, low << 12)
        if funct3 == 4:
            rs1, rs2 = 8 + ((word >> 7) & 7), 8 + ((word >> 2) & 7)
            selector = (word >> 10) & 3
            if selector == 2:
                return ("and", rs1, rs1, 0, low)
            if selector == 3 and (word >> 5) & 3 == 0:
                return ("subw" if word & 0x1000 else "sub", rs1, rs1, rs2, 0)
            if selector == 3 and (word >> 5) & 3 == 1 and word & 0x1000:
                return ("addw", rs1, rs1, rs2, 0)
            return ("kill", rs1, 0, 0, 0)
        if funct3 == 5:
            return ("stop", 0, 0, 0, 0)
    if quadrant == 2:
        if funct3 == 0:
            return ("shift", rd, rd, 0, low & (xlen - 1))
        if funct3 == 4:
            rs2 = (word >> 2) & 31
            if rs2:
                return ("add", rd, rd if word & 0x1000 else 0, rs2, 0)
            if rd:
                return ("jump", int(bool(word & 0x1000)), rd, 0, 0)
        if funct3 == 2 or (funct3 == 3 and xlen == 64):
            return ("kill", rd, 0, 0, 0)
    if quadrant == 0:
        rs1, compact_rd = 8 + ((word >> 7) & 7), 8 + ((word >> 2) & 7)
        if funct3 in (2, 6):
            offset = ((word >> 7) & 0x38) | ((word >> 4) & 4) | ((word << 1) & 0x40)
            return ("load", compact_rd, rs1, 0, offset | (2 << 12)) if funct3 == 2 else ("address", 0, rs1, 0, offset)
        if funct3 in (1, 3, 5, 7):
            if funct3 in (3, 7) and xlen == 32:
                offset = ((word >> 7) & 0x38) | ((word >> 4) & 4) | ((word << 1) & 0x40)
            else:
                offset = ((word >> 7) & 0x38) | ((word << 1) & 0xC0)
            if funct3 == 3 and xlen == 64:
                return ("load", compact_rd, rs1, 0, offset | (3 << 12))
            return ("address", 0, rs1, 0, offset)
        if funct3 == 0:
            return ("kill", compact_rd, 0, 0, 0)
    return None


def _values(
    binary: Binary, operation: str, left: frozenset[int], right: frozenset[int],
    immediate: int, address: int, length: int, mask: int,
) -> tuple[frozenset[int], frozenset[int]]:
    references: set[int] = set()
    values: set[int] = set()
    if operation == "pc":
        values.add((address + immediate) & mask)
    elif operation in ("call", "stop"):
        values.add((address + length) & mask)
    elif operation == "jump":
        references.update((base + immediate) & mask & ~1 for base in left)
        values.add((address + length) & mask)
    elif operation == "address":
        references.update((base + immediate) & mask for base in left)
    elif operation == "load":
        kind = immediate >> 12
        width = 1 << (kind & 3)
        for base in left:
            target = (base + sign_extend(immediate & 0xFFF, 12)) & mask
            references.add(target)
            try:
                data = binary.read(target, width)
            except ValueError:
                continue
            if len(data) == width:
                values.add(int.from_bytes(data, "little", signed=kind < 4) & mask)
    elif operation != "kill":
        name = operation.removesuffix("w")
        for lhs, rhs in product(left, right):
            if name == "add":
                result = lhs + rhs + immediate
            elif name == "sub":
                result = lhs - rhs
            elif name == "shift":
                result = lhs << immediate
            elif name == "or":
                result = lhs | immediate
            elif name == "xor":
                result = lhs ^ immediate
            else:
                result = lhs & immediate
            if operation.endswith("w"):
                result = sign_extend(result & 0xFFFFFFFF, 32)
            values.add(result & mask)
    return frozenset(values), frozenset(references)


_ZERO = frozenset({0})
_EMPTY: frozenset[int] = frozenset()
_MAX_ALTERNATIVES = 128
_PRESERVED = frozenset({2, 3, 4, 8, 9, *range(18, 28)})


def _global_pointer_values(
    data: memoryview, start: int, mask: int, symbol: int | None,
) -> frozenset[int]:
    if symbol is not None:
        return frozenset({symbol})
    values = set()
    for offset in range(start & 1, len(data) - 7, 2):
        if data[offset] not in (0x97, 0xB7):
            continue
        upper = int.from_bytes(data[offset:offset + 4], "little")
        lower = int.from_bytes(data[offset + 4:offset + 8], "little")
        if upper & 0xFFF in (0x197, 0x1B7) and lower & 0xFFFFF == 0x18193:
            base = start + offset if upper & 0x7F == 0x17 else 0
            values.add((base + UPPER.decode(upper) + sign_extend(lower >> 20, 12)) & mask)
    return frozenset(values)


def scan(
    binary: Binary, start: int, end: int, targets: Set[int], xlen: int,
    gp: int | None,
) -> Iterator[tuple[int, int]]:
    """Scan both possible instruction starts in each four-byte interval.

    A site is a possible entry even when the bytes before it are data or the
    upper parcel of another instruction. Values propagate through either
    parcel length. Merging those streams intentionally permits false xrefs.
    """
    data = memoryview(binary.read(start, end - start))
    mask = (1 << xlen) - 1
    pending: dict[int, dict[int, frozenset[int]]] = {}
    gp_values = _global_pointer_values(data, start, mask, gp)
    for offset in range(start & 1, min(end - start, len(data)) - 1, 2):
        address = start + offset
        values = pending.pop(offset, {})
        first = data[offset]
        length = 4 if first & 3 == 3 else 2
        if first & 0x1F == 0x1F or offset + length > len(data):
            continue
        word = int.from_bytes(data[offset:offset + length], "little")
        if not word:
            continue
        operation = _operation(word, length, xlen)
        if operation is not None:
            name, rd, rs1, rs2, immediate = operation
            left = _ZERO if rs1 == 0 else values.get(rs1, _EMPTY)
            if rs1 == 3:
                left |= gp_values
            right = _ZERO if rs2 == 0 else values.get(rs2, _EMPTY)
            if rs2 == 3:
                right |= gp_values
            result, references = _values(binary, name, left, right, immediate, address, length, mask)
            for target in (references | (result if rd else _EMPTY)) & targets:
                yield address, target
            if name == "stop" or (name == "jump" and rd not in (1, 5)):
                continue
            if name in ("call", "jump"):
                values = {reg: val for reg, val in values.items() if reg in _PRESERVED}
            if rd:
                if result:
                    values[rd] = result
                else:
                    values.pop(rd, None)
        next_offset = offset + length
        if next_offset not in pending:
            pending[next_offset] = values
            continue
        merged = pending[next_offset]
        for register, candidates in values.items():
            combined = merged.get(register, _EMPTY) | candidates
            if len(combined) > _MAX_ALTERNATIVES:
                # Ambiguous bytes may feed indefinitely many constants into
                # a register. Keep all possible functions live in that case.
                for target in targets:
                    yield address, target
                return
            merged[register] = combined
