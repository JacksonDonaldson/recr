"""RISC-V instruction parcels and split PC-relative immediates."""

from __future__ import annotations

from dataclasses import dataclass


def sign_extend(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


@dataclass(frozen=True)
class RelativeImmediate:
    width: int
    alignment: int
    # Each field is (immediate bit, instruction bit, width).
    fields: tuple[tuple[int, int, int], ...]

    def decode(self, word: int) -> int:
        value = 0
        for immediate_bit, instruction_bit, width in self.fields:
            value |= ((word >> instruction_bit) & ((1 << width) - 1)) << immediate_bit
        return sign_extend(value, self.width)

    def encode(self, word: int, displacement: int) -> int:
        limit = 1 << (self.width - 1)
        if displacement % self.alignment or not -limit <= displacement < limit:
            raise ValueError(f"RISC-V displacement {displacement:+#x} does not fit")
        for immediate_bit, instruction_bit, width in self.fields:
            mask = (1 << width) - 1
            word &= ~(mask << instruction_bit)
            word |= ((displacement >> immediate_bit) & mask) << instruction_bit
        return word


BRANCH = RelativeImmediate(13, 2, ((1, 8, 4), (5, 25, 6), (11, 7, 1), (12, 31, 1)))
JUMP = RelativeImmediate(21, 2, ((1, 21, 10), (11, 20, 1), (12, 12, 8), (20, 31, 1)))
UPPER = RelativeImmediate(32, 4096, ((12, 12, 20),))
COMPRESSED_BRANCH = RelativeImmediate(
    9, 2, ((1, 3, 2), (3, 10, 2), (5, 2, 1), (6, 5, 2), (8, 12, 1))
)
COMPRESSED_JUMP = RelativeImmediate(
    12, 2, ((1, 3, 3), (4, 11, 1), (5, 2, 1), (6, 7, 1), (7, 6, 1),
            (8, 9, 2), (10, 8, 1), (11, 12, 1))
)
_WORD_IMMEDIATES = {0x63: BRANCH, 0x6F: JUMP, 0x17: UPPER}


def relative_immediate(word: int, length: int, xlen: int) -> RelativeImmediate | None:
    if length == 2:
        if word & 3 == 1:
            funct3 = word >> 13
            if funct3 in (6, 7):
                return COMPRESSED_BRANCH
            if funct3 == 5 or (funct3 == 1 and xlen == 32):
                return COMPRESSED_JUMP
        return None
    return _WORD_IMMEDIATES.get(word & 0x7F)
