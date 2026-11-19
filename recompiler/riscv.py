"""RISC-V ELF fixups for placed extension sections."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from elftools.elf.relocation import RelocationSection

from isa.riscv.encoding import (
    BRANCH, COMPRESSED_BRANCH, COMPRESSED_JUMP, JUMP, UPPER,
    relative_immediate, sign_extend,
)

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile
    from recompiler.placement import Object, Relocation, Section, Symbol


ABS32, ABS64 = 1, 2
BRANCH_RELOC, JAL, CALL, CALL_PLT = 16, 17, 18, 19
PCREL_HI20, PCREL_LO12_I, PCREL_LO12_S = 23, 24, 25
HI20, LO12_I, LO12_S = 26, 27, 28
ALIGN, RVC_BRANCH, RVC_JUMP, RELAX, PCREL32 = 43, 44, 45, 51, 57

CALL_PAIRS = frozenset((CALL, CALL_PLT))
BRANCH_RELOCS = frozenset((BRANCH_RELOC, JAL, RVC_BRANCH, RVC_JUMP))
_IMMEDIATES = {
    BRANCH_RELOC: BRANCH, JAL: JUMP, RVC_BRANCH: COMPRESSED_BRANCH, RVC_JUMP: COMPRESSED_JUMP,
}
_RELOCATION_NAMES = {
    ABS32: "32", ABS64: "64", BRANCH_RELOC: "BRANCH", JAL: "JAL", CALL: "CALL", CALL_PLT: "CALL_PLT",
    PCREL_HI20: "PCREL_HI20", PCREL_LO12_I: "PCREL_LO12_I", PCREL_LO12_S: "PCREL_LO12_S",
    HI20: "HI20", LO12_I: "LO12_I", LO12_S: "LO12_S", ALIGN: "ALIGN",
    RVC_BRANCH: "RVC_BRANCH", RVC_JUMP: "RVC_JUMP", RELAX: "RELAX", PCREL32: "32_PCREL",
}


def relocation_name(kind: int) -> str:
    if 33 <= kind <= 40:
        operation = "ADD" if kind <= 36 else "SUB"
        return f"R_RISCV_{operation}{8 << ((kind - 33) % 4)}"
    name = _RELOCATION_NAMES.get(kind)
    return f"R_RISCV_{name}" if name is not None else f"RISC-V relocation type {kind}"


def plt_addresses(elf: ELFFile) -> dict[str, set[int]]:
    """Match executable PLT stubs to their ELF jump slots."""
    plt = elf.get_section_by_name(".plt")
    relocations = elf.get_section_by_name(".rela.plt")
    if plt is None or not isinstance(relocations, RelocationSection):
        return {}
    symbols = elf.get_section(relocations["sh_link"])
    slots = {
        item["r_offset"]: symbols.get_symbol(item["r_info_sym"]).name
        for item in relocations.iter_relocations() if item["r_info_type"] == 5
    }
    entries: dict[str, set[int]] = {}
    code = plt.data()
    load = 0x000E2E03 if elf.elfclass == 32 else 0x000E3E03  # lw/ld t3, offset(t3)
    for offset in range(0, len(code) - 11, 4):
        high = int.from_bytes(code[offset:offset + 4], "little")
        low = int.from_bytes(code[offset + 4:offset + 8], "little")
        jump = int.from_bytes(code[offset + 8:offset + 12], "little")
        if high & 0xFFF != 0xE17 or low & 0xFFFFF != load or jump != 0x000E0367:
            continue
        address = plt["sh_addr"] + offset
        slot = address + UPPER.decode(high) + sign_extend(low >> 20, 12)
        if slot in slots:
            entries.setdefault(slots[slot], set()).add(address)
    return entries


def promote(raw: bytes, xlen: int) -> tuple[bytes, int]:
    """Return an expandable branch and the byte offset of its long jump."""
    word = int.from_bytes(raw, "little")
    immediate = relative_immediate(word, len(raw), xlen)
    if immediate is COMPRESSED_JUMP:
        rd = 1 if word >> 13 == 1 else 0  # RV32 C.JAL.
        return (0x6F | rd << 7).to_bytes(4, "little"), 0
    if immediate is COMPRESSED_BRANCH:
        rs1 = 8 + ((word >> 7) & 7)
        inverse_funct3 = 1 if word >> 13 == 6 else 0  # C.BEQZ or C.BNEZ.
        inverse = 0x63 | inverse_funct3 << 12 | rs1 << 15
    elif immediate is BRANCH:
        inverse = word ^ (1 << 12)
    else:
        return raw, 0
    return BRANCH.encode(inverse, 8).to_bytes(4, "little") + b"\x6f\0\0\0", 4


def _upper(value: int, xlen: int) -> tuple[int, int]:
    if xlen == 32:
        value = sign_extend(value & 0xFFFFFFFF, 32)
    rounded = (value + 0x800) & ~0xFFF
    high = sign_extend(rounded & 0xFFFFFFFF, 32) if xlen == 32 else rounded
    return high, value - rounded


def _encode_upper(word: int, value: int, xlen: int, *, absolute: bool = False) -> tuple[int, int]:
    high, low = _upper(value, xlen)
    label = "Rounded LUI immediate" if absolute else "Rounded AUIPC displacement"
    return UPPER.encode(word, high, label=label), low


def validate_fixed_hi20(object_: Object, imports: dict[str, int], xlen: int) -> None:
    """Reject absolute upper immediates whose targets are fixed before placement."""
    for section in object_.sections.values():
        for relocation in section.relocations:
            if relocation.kind != HI20:
                continue
            symbol = relocation.symbol
            if symbol.section == "SHN_ABS":
                address = symbol.offset
            elif symbol.section == "SHN_UNDEF" and symbol.name in imports:
                address = imports[symbol.name]
            else:
                continue
            try:
                _encode_upper(0, address + relocation.addend, xlen, absolute=True)
            except ValueError as exc:
                hint = ""
                if symbol.section == "SHN_UNDEF" and xlen == 64:
                    hint = (
                        "\n  Try passing -- -mcmodel=medany to recr to generate PC-relative references. "
                        "The symbol must still be within reach of the placed code."
                    )
                site = relocation.describe(section, relocation_name(relocation.kind))
                raise ValueError(
                    f"{site} resolves to {address + relocation.addend:#x} "
                    f"and cannot encode an absolute RV{xlen} address.\n  {exc}.{hint}"
                ) from exc


def _patch_low(section: Section, address: int, value: int, store: bool) -> None:
    word = section.read_word(address, 4)
    low = value & 0xFFF
    if store:
        word = (word & ~0xFE000F80) | ((low >> 5) << 25) | ((low & 31) << 7)
    else:
        word = (word & 0xFFFFF) | low << 20
    section.write_word(address, word, 4)


def apply(
    object_: Object, section: Section, relocation: Relocation,
    resolve: Callable[[Symbol, int], int], xlen: int,
) -> None:
    kind = relocation.kind
    offset = relocation.offset
    place = section.address(offset)
    if kind == ALIGN:
        # Preserve existing padding only where it meets the requested alignment.
        padding = relocation.addend
        alignment = 1 << padding.bit_length()
        following = section.address(offset + padding)
        if following % alignment:
            raise ValueError(
                f"RISC-V alignment requires relaxation. Address {following:#x} after "
                f"{padding} padding bytes is not aligned to {alignment} bytes"
            )
        return
    if kind in (PCREL_LO12_I, PCREL_LO12_S):
        anchor = relocation.symbol
        offset = anchor.offset + relocation.addend
        anchor_section = object_.sections.get(anchor.section)
        high = next((
            candidate for candidate in anchor_section.relocations
            if candidate.offset == offset and candidate.kind == PCREL_HI20
        ), None) if anchor_section is not None else None
        if high is None:
            anchor_name = anchor_section.name if anchor_section is not None else f"section {anchor.section}"
            raise ValueError(f"RISC-V PCREL_LO12 is missing its R_RISCV_PCREL_HI20 anchor at {anchor_name}+{offset:#x}")
        value = resolve(high.symbol, high.addend) - anchor_section.address(offset)
        _patch_low(section, place, value, kind == PCREL_LO12_S)
        return

    value = resolve(relocation.symbol, relocation.addend)
    if kind in (ABS32, ABS64, PCREL32):
        if kind == PCREL32:
            value = sign_extend((value - place) & 0xFFFFFFFF, 32) if xlen == 32 else value - place
        section.write_word(place, value, 8 if kind == ABS64 else 4, signed=kind == PCREL32)
    elif kind in BRANCH_RELOCS:
        if offset in section.promoted_branches:
            place += section.promoted_branches[offset]
            kind = JAL
        width = 2 if kind in (RVC_BRANCH, RVC_JUMP) else 4
        word = section.read_word(place, width)
        try:
            patched = _IMMEDIATES[kind].encode(word, value - place)
        except ValueError as exc:
            raise ValueError(f"cannot reach {value:#x} from {place:#x} with {relocation_name(kind)}. {exc}") from exc
        section.write_word(place, patched, width)
    elif kind in CALL_PAIRS or kind in (HI20, PCREL_HI20):
        word = section.read_word(place, 4)
        try:
            patched, low = _encode_upper(word, value if kind == HI20 else value - place, xlen, absolute=kind == HI20)
        except ValueError as exc:
            if kind == HI20:
                detail = f"cannot encode absolute address {value:#x}"
            else:
                detail = f"cannot reach {value:#x} from {place:#x} with an AUIPC-based reference"
            raise ValueError(f"{detail}. {exc}") from exc
        section.write_word(place, patched, 4)
        if kind in CALL_PAIRS:
            if section.address(offset + 4) != place + 4:
                raise ValueError(f"split AUIPC/JALR pair at {place:#x}. Both instructions must stay adjacent")
            _patch_low(section, place + 4, low, False)
    elif kind in (LO12_I, LO12_S):
        _patch_low(section, place, value, kind == LO12_S)
    elif 33 <= kind <= 40:  # ADD8 through ADD64, SUB8 through SUB64.
        width = 1 << ((kind - 33) % 4)
        original = section.read_word(place, width)
        result = original + value if kind <= 36 else original - value
        section.write_word(place, result & ((1 << (width * 8)) - 1), width)
    else:
        raise ValueError(f"unsupported RISC-V relocation {kind} in {section.name}")
