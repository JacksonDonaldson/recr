"""Place an x86-64 ELF extension into file-backed codezip receipt ranges."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from ir import Address, Instruction, InstructionType
from isa.x86_64 import X86_64ISA
from recompiler.exports import Exports


@dataclass(frozen=True)
class Symbol:
    name: str
    section: int | str
    offset: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    kind: int
    symbol: Symbol
    addend: int


@dataclass
class Section:
    name: str
    data: bytes
    flags: int
    alignment: int
    relocations: list[Relocation] = field(default_factory=list)
    fragments: list[Fragment] = field(default_factory=list)
    instruction_addresses: dict[int, int] = field(default_factory=dict)
    pc_bias: dict[int, int] = field(default_factory=dict)

    @property
    def permissions(self) -> int:
        return 4 | (2 if self.flags & 1 else 0) | (1 if self.flags & 4 else 0)

    def address(self, offset: int) -> int:
        if not self.instruction_addresses:
            return self.fragments[0].address + offset
        if offset in self.instruction_addresses:
            return self.instruction_addresses[offset]
        if offset == len(self.data):
            fragment = self.fragments[-1]
            return fragment.address + len(fragment.data)
        raise ValueError(f"reference into a non-instruction boundary in split section {self.name}+{offset:#x}")


@dataclass
class Fragment:
    address: int
    data: bytearray


@dataclass
class Object:
    sections: dict[int, Section]
    symbols: dict[str, Symbol]

    @classmethod
    def read(cls, path: Path) -> Object:
        sections = {}
        symbols = {}
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header.e_type != "ET_REL" or elf.header.e_machine != "EM_X86_64":
                raise ValueError("GCC must produce a relocatable x86-64 ELF object")
            for index, section in enumerate(elf.iter_sections()):
                flags = section["sh_flags"]
                if not flags & 2 or not section["sh_size"]:
                    continue
                if section.name in (".eh_frame", ".note.gnu.property"):
                    continue
                if flags & 0x400 or section["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
                    raise ValueError(f"unsupported loadable extension section {section.name!r}")
                sections[index] = Section(
                    section.name, section.data(), flags, section["sh_addralign"] or 1,
                )
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                raise ValueError("the extension object has no symbol table")
            for entry in symtab.iter_symbols():
                if entry.name and entry["st_shndx"] in sections:
                    symbols[entry.name] = _symbol(entry)
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection) or section["sh_info"] not in sections:
                    continue
                if not section.is_RELA():
                    raise ValueError("x86-64 extension relocations require explicit addends")
                target = sections[section["sh_info"]]
                for entry in section.iter_relocations():
                    kind = entry["r_info_type"]
                    if kind:
                        target.relocations.append(Relocation(
                            entry["r_offset"], kind,
                            _symbol(symtab.get_symbol(entry["r_info_sym"])), entry["r_addend"],
                        ))
        return cls(sections, symbols)

    def imports(self) -> set[str]:
        return {
            r.symbol.name for section in self.sections.values() for r in section.relocations
            if r.symbol.section == "SHN_UNDEF"
        }


def _symbol(entry) -> Symbol:
    return Symbol(entry.name, entry["st_shndx"], entry["st_value"])


@dataclass(frozen=True)
class Range:
    start: int
    end: int
    flags: int


class Space:
    def __init__(self, freed: list[tuple[int, int]], exports: Exports):
        self.ranges = []
        for start, size in freed:
            for segment in exports.segments:
                lower = max(start, segment.start)
                upper = min(start + size, segment.start + segment.size)
                if lower >= upper:
                    continue
                cuts = {lower, upper}
                for a, b in exports.relro:
                    if lower < a < upper:
                        cuts.add(a)
                    if lower < b < upper:
                        cuts.add(b)
                limits = sorted(cuts)
                for a, b in zip(limits, limits[1:]):
                    flags = segment.flags
                    if any(a < end and b > begin for begin, end in exports.relro):
                        flags &= ~2
                    self.ranges.append(Range(a, b, flags))

    @staticmethod
    def aligned(address: int, align: int) -> int:
        return (address + align - 1) // align * align

    def take(self, index: int, start: int, size: int) -> int:
        region = self.ranges.pop(index)
        end = start + size
        if region.start < start:
            self.ranges.append(Range(region.start, start, region.flags))
        if end < region.end:
            self.ranges.append(Range(end, region.end, region.flags))
        return start

    def allocate(self, size: int, align: int, flags: int) -> int | None:
        candidates = []
        for index, region in enumerate(self.ranges):
            start = self.aligned(region.start, align)
            if region.flags & flags == flags and start + size <= region.end:
                # Preserve writable space for data when placing code or constants.
                excess_permissions = (region.flags & ~flags).bit_count()
                candidates.append((excess_permissions, region.end - region.start, start, index))
        if candidates:
            _, _, start, index = min(candidates)
            return self.take(index, start, size)
        return None


def jump(source: int, target: int) -> bytes:
    try:
        return b"\xe9" + (target - source - 5).to_bytes(4, "little", signed=True)
    except OverflowError as exc:
        raise ValueError(f"jump from {source:#x} to {target:#x} is out of range") from exc


@dataclass(frozen=True)
class _Instruction:
    original: Instruction
    data: bytes
    falls_through: bool
    branch: int | None
    relative_data: bool

    @property
    def offset(self) -> int:
        return self.original.address


class _Image:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self.data):
            raise ValueError("read outside compiled section")
        return self.data[address:address + length]


def _instructions(section: Section, isa: X86_64ISA) -> list[_Instruction]:
    image = _Image(section.data)
    items = []
    offset = 0
    relocated_offsets = {relocation.offset for relocation in section.relocations}
    while offset < len(section.data):
        original = isa.disassemble(image, offset)
        raw = original.original_data
        following = offset + original.length
        branch = None
        relative_data = False
        resolved = isa._sleigher.spec.resolve(raw, isa._sleigher.context)
        relative = isa._sleigher.spec.relative_target(resolved, raw, offset)
        for location in range(offset, following):
            if location in relocated_offsets:
                section.pc_bias[location] = following - location
        if relative is not None and offset + relative[1] not in relocated_offsets:
            if original.type in (InstructionType.BRANCH, InstructionType.CALL):
                branch = relative[0]
                if raw[0] == 0xEB and original.length == 2:
                    raw = b"\xe9\0\0\0\0"
                elif 0x70 <= raw[0] <= 0x7F and original.length == 2:
                    raw = bytes((0x0F, raw[0] + 0x10)) + bytes(4)
            else:
                relative_data = True
        falls_through = original.type is not InstructionType.RET and (
            original.type is not InstructionType.BRANCH
            or any(flow.value == following for flow in original.flows_to)
        )
        items.append(_Instruction(original, raw, falls_through, branch, relative_data))
        offset = following
    return items


def _split(section: Section, space: Space, isa: X86_64ISA) -> None:
    items = _instructions(section, isa)
    remaining = items
    groups = []
    while remaining:
        align = section.alignment if not groups else 1
        candidates = []
        for index, region in enumerate(space.ranges):
            if region.flags & 5 != 5:
                continue
            start = space.aligned(region.start, align)
            candidates.append((region.end - start, start, index))
        for available, start, index in sorted(candidates, reverse=True):
            count = 0
            payload = 0
            for i, item in enumerate(remaining, 1):
                payload += len(item.data)
                glue = 5 if i < len(remaining) and item.falls_through else 0
                if payload + glue <= available:
                    count, total = i, payload + glue
                if payload > available:
                    break
            if count:
                break
        else:
            raise ValueError(f"insufficient cleared executable space for {section.name}")

        space.take(index, start, total)
        fragment = Fragment(start, bytearray(total))
        section.fragments.append(fragment)
        members, remaining = remaining[:count], remaining[count:]
        groups.append((fragment, members))
        position = start
        for item in members:
            section.instruction_addresses[item.offset] = position
            position += len(item.data)

    for index, (fragment, members) in enumerate(groups):
        cursor = 0
        for item in members:
            address = fragment.address + cursor
            raw = item.data
            if item.branch is not None:
                target = section.address(item.branch)
                template = isa.disassemble(_Image(raw), 0)
                instruction = isa.set_instruction_target(
                    Instruction(raw, template.type, len(raw), address), Address.absolute(target),
                )
                if not isa.can_encode(instruction, address):
                    raise ValueError(f"cannot encode split branch in {section.name}")
                raw = instruction.original_data
            elif item.relative_data:
                raise ValueError(f"cannot split {section.name} with an unrelocated PC-relative operand")
            elif not isa.can_encode(item.original, address):
                raise ValueError(f"cannot encode split instruction in {section.name}+{item.offset:#x}")
            fragment.data[cursor:cursor + len(raw)] = raw
            cursor += len(raw)
        if cursor < len(fragment.data):
            fragment.data[cursor:] = jump(fragment.address + cursor, groups[index + 1][0].address)


def place(object_: Object, space: Space, imports: dict[str, int], isa: X86_64ISA) -> list[Fragment]:
    sections = sorted(
        object_.sections.values(),
        key=lambda section: (not bool(section.flags & 1), bool(section.flags & 4), -len(section.data)),
    )
    split = []
    for section in sections:
        address = space.allocate(len(section.data), section.alignment, section.permissions)
        if address is not None:
            section.fragments.append(Fragment(address, bytearray(section.data)))
        elif section.flags & 4:
            split.append(section)
        else:
            raise ValueError(f"insufficient cleared space for {section.name} ({len(section.data)} bytes)")
    for section in split:
        _split(section, space, isa)
    for section in sections:
        for relocation in section.relocations:
            _apply(object_, section, relocation, imports, isa)
    return [fragment for section in sections for fragment in section.fragments]


def _apply(
    object_: Object, section: Section, relocation: Relocation,
    imports: dict[str, int], isa: X86_64ISA,
) -> None:
    # R_X86_64_64, PC32, PLT32, 32, 32S, and PC64.
    formats = {1: (8, False, False), 2: (4, True, True), 4: (4, True, True),
               10: (4, False, False), 11: (4, True, False), 24: (8, True, True)}
    if relocation.kind not in formats:
        raise ValueError(f"unsupported x86-64 relocation {relocation.kind} in {section.name}")
    width, signed, relative = formats[relocation.kind]
    offset = relocation.offset
    if section.instruction_addresses:
        starts = [start for start in section.instruction_addresses if start <= offset]
        if not starts:
            raise ValueError(f"relocation outside instructions in {section.name}")
        start = max(starts)
        address = section.address(start) + offset - start
    else:
        address = section.address(offset)

    symbol = relocation.symbol
    addend = relocation.addend
    if symbol.section == "SHN_UNDEF":
        value = imports[symbol.name] + addend
    elif symbol.section == "SHN_ABS":
        value = symbol.offset + addend
    elif symbol.section in object_.sections:
        destination = object_.sections[symbol.section]
        if destination.instruction_addresses and relative:
            if not section.pc_bias and section.flags & 4:
                _instructions(section, isa)
            bias = section.pc_bias.get(offset, 0)
        else:
            bias = 0
        value = destination.address(symbol.offset + addend + bias) - bias
    else:
        raise ValueError(f"relocation references an unsupported section for {symbol.name!r}")

    if relative:
        value -= address
    try:
        encoded = value.to_bytes(width, "little", signed=signed)
    except OverflowError as exc:
        raise ValueError(f"relocation overflows for {symbol.name or section.name!r}") from exc
    for fragment in section.fragments:
        start = address - fragment.address
        if 0 <= start and start + width <= len(fragment.data):
            fragment.data[start:start + width] = encoded
            return
    raise ValueError(f"relocation outside placed bytes in {section.name}")
