"""Place an ELF extension into file-backed codezip receipt ranges."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.relocation import RelocationSection

from ir import Address, Instruction, InstructionType
from isa.isa import ISA
from isa.riscv.encoding import UPPER, relative_immediate
from isa.x86_64 import X86_64ISA
from recompiler import riscv
from recompiler.exports import Exports
from recompiler.target import X86_64, Target


_X86_RELOCATION_NAMES = {value: name for name, value in ENUM_RELOC_TYPE_x64.items()}


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

    def describe(self, section: Section, kind: str) -> str:
        symbol = self.symbol
        name = f"symbol {symbol.name!r}" if symbol.name else f"section {symbol.section} at offset {symbol.offset:#x}"
        addend = f" (addend {self.addend:+#x})" if self.addend else ""
        return f"{kind} at {section.name}+{self.offset:#x} for {name}{addend}"


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
    promoted_branches: dict[int, int] = field(default_factory=dict)

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

    def _location(self, address: int, width: int) -> tuple[bytearray, int]:
        for fragment in self.fragments:
            offset = address - fragment.address
            if 0 <= offset and offset + width <= len(fragment.data):
                return fragment.data, offset
        raise ValueError(f"{width}-byte relocation at {address:#x} extends outside the placed bytes of {self.name}")

    def read_word(self, address: int, width: int) -> int:
        data, offset = self._location(address, width)
        return int.from_bytes(data[offset:offset + width], "little")

    def write_word(self, address: int, value: int, width: int, *, signed: bool = False) -> None:
        data, offset = self._location(address, width)
        try:
            encoded = value.to_bytes(width, "little", signed=signed)
        except OverflowError as exc:
            field = "signed" if signed else "unsigned"
            raise ValueError(f"value {value:#x} at {address:#x} does not fit a {field} {width * 8}-bit field") from exc
        data[offset:offset + width] = encoded


@dataclass
class Fragment:
    address: int
    data: bytearray


@dataclass
class Object:
    sections: dict[int, Section]
    symbols: dict[str, Symbol]

    @classmethod
    def read(cls, path: Path, target: Target = X86_64) -> Object:
        sections = {}
        symbols = {}
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if not target.accepts_object(elf):
                endian = "little-endian" if elf.little_endian else "big-endian"
                raise ValueError(
                    f"GCC must produce a relocatable ELF object matching the {target.isa} ABI (flags {target.flags:#x}). "
                    f"Produced ELF{elf.elfclass} {endian} {elf.header.e_machine} {elf.header.e_type} "
                    f"with flags {elf.header.e_flags:#x}. Check --cc and the compiler flags after --"
                )
            for index, section in enumerate(elf.iter_sections()):
                flags = section["sh_flags"]
                if not flags & 2 or not section["sh_size"]:
                    continue
                if section.name in (".eh_frame", ".note.gnu.property"):
                    continue
                if flags & 0x400 or section["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS"):
                    raise ValueError(
                        f"unsupported loadable extension section {section.name!r} "
                        f"with type {section['sh_type']} and flags {flags:#x}"
                    )
                sections[index] = Section(
                    section.name, section.data(), flags, section["sh_addralign"] or 1,
                )
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                raise ValueError("the extension object has no .symtab symbol table. Check for strip options in the compiler command")
            for entry in symtab.iter_symbols():
                if entry.name and entry["st_shndx"] in sections:
                    symbols[entry.name] = _symbol(entry)
            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection) or section["sh_info"] not in sections:
                    continue
                if not section.is_RELA():
                    raise ValueError(f"extension relocations require explicit addends. Section {section.name!r} uses REL")
                destination = sections[section["sh_info"]]
                for entry in section.iter_relocations():
                    kind = entry["r_info_type"]
                    if kind and not (target.machine == "EM_RISCV" and kind == riscv.RELAX):
                        destination.relocations.append(Relocation(
                            entry["r_offset"], kind,
                            _symbol(symtab.get_symbol(entry["r_info_sym"])), entry["r_addend"],
                        ))
        return cls(sections, symbols)

    def imports(self) -> set[str]:
        return {
            r.symbol.name for section in self.sections.values() for r in section.relocations
            if r.symbol.section == "SHN_UNDEF" and r.symbol.name
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

    def describe_capacity(self, align: int, flags: int) -> str:
        permissions = "".join(letter for bit, letter in ((4, "r"), (2, "w"), (1, "x")) if flags & bit)
        available = [
            region.end - self.aligned(region.start, align)
            for region in self.ranges if region.flags & flags == flags
        ]
        usable = [size for size in available if size > 0]
        return (
            f"needs {permissions} permissions and {align}-byte alignment. "
            f"{sum(usable)} usable bytes across {len(usable)} cleared ranges, "
            f"with {max(usable, default=0)} bytes in the largest"
        )


@dataclass(frozen=True)
class _Instruction:
    original: Instruction
    data: bytes
    falls_through: bool
    branch: int | None
    relative_data: bool
    branch_offset: int = 0
    elf_relocated: bool = False

    @property
    def offset(self) -> int:
        return self.original.address


class _Image:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self.data):
            raise ValueError(f"read of {length} bytes at section offset {address:#x} falls outside the {len(self.data)} compiled bytes")
        return self.data[address:address + length]


def _instructions(section: Section, isa: ISA, target: Target = X86_64) -> list[_Instruction]:
    image = _Image(section.data)
    items = []
    offset = 0
    relocations = {relocation.offset: relocation.kind for relocation in section.relocations}
    while offset < len(section.data):
        try:
            original = isa.disassemble(image, offset)
        except ValueError as exc:
            raise ValueError(f"cannot decode compiled instruction at {section.name}+{offset:#x}. {exc}") from exc
        raw = original.original_data
        following = offset + original.length
        branch = None
        relative_data = False
        branch_offset = 0
        elf_relocated = False
        if target.machine == "EM_RISCV":
            kind = relocations.get(offset)
            word = int.from_bytes(raw, "little")
            immediate = relative_immediate(word, len(raw), target.bits)
            elf_relocated = immediate is UPPER and kind is not None
            if immediate is UPPER:
                relative_data = not elf_relocated
            elif immediate is not None:
                if kind not in riscv.BRANCH_RELOCS:
                    branch = offset + immediate.decode(word)
                else:
                    elf_relocated = True
                raw, branch_offset = riscv.promote(raw, target.bits)
                if kind in riscv.BRANCH_RELOCS and len(raw) != original.length:
                    section.promoted_branches[offset] = branch_offset
        else:
            assert isinstance(isa, X86_64ISA)
            resolved = isa._sleigher.spec.resolve(raw, isa._sleigher.context)
            relative = isa._sleigher.spec.relative_target(resolved, raw, offset)
            for location in range(offset, following):
                if location in relocations:
                    section.pc_bias[location] = following - location
            if relative is not None and offset + relative[1] not in relocations:
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
        items.append(_Instruction(
            original, raw, falls_through, branch, relative_data, branch_offset, elf_relocated,
        ))
        offset = following
    return items


def _split(section: Section, space: Space, isa: ISA, target: Target) -> None:
    items = _instructions(section, isa, target)
    remaining = items
    groups = []
    pair_interiors = {
        relocation.offset + 4 for relocation in section.relocations
        if target.machine == "EM_RISCV" and relocation.kind in riscv.CALL_PAIRS
    }
    while remaining:
        align = max(section.alignment, target.alignment) if not groups else target.alignment
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
                if payload > available:
                    break
                if i < len(remaining) and remaining[i].offset in pair_interiors:
                    continue
                glue = target.jump_size if i < len(remaining) and item.falls_through else 0
                if payload + glue <= available:
                    count, total = i, payload + glue
            if count:
                break
        else:
            raise ValueError(
                f"insufficient cleared executable space for {section.name}+{remaining[0].offset:#x}. "
                f"The next fragment starts with a {len(remaining[0].data)}-byte instruction and "
                f"{space.describe_capacity(align, 5)}"
            )

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
                destination = section.address(item.branch)
                tail = raw[item.branch_offset:]
                template = isa.disassemble(_Image(tail), 0)
                branch_address = address + item.branch_offset
                try:
                    instruction = isa.set_instruction_target(
                        Instruction(tail, template.type, len(tail), branch_address), Address.absolute(destination),
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"cannot encode split branch at {section.name}+{item.offset:#x} "
                        f"from {branch_address:#x} to {destination:#x}. {exc}"
                    ) from exc
                if not isa.can_encode(instruction, branch_address):
                    raise ValueError(f"cannot encode split branch at {section.name}+{item.offset:#x} from {branch_address:#x} to {destination:#x}")
                raw = raw[:item.branch_offset] + instruction.original_data
            elif item.relative_data:
                raise ValueError(f"cannot split {section.name} with an unrelocated PC-relative operand at offset {item.offset:#x}")
            # ELF fixups validate the final displacements for unlinked operands.
            elif not item.elf_relocated and not isa.can_encode(item.original, address):
                raise ValueError(f"cannot encode split instruction {item.original.original_data.hex(' ')} in {section.name}+{item.offset:#x} at {address:#x}")
            fragment.data[cursor:cursor + len(raw)] = raw
            cursor += len(raw)
        if cursor < len(fragment.data):
            try:
                fragment.data[cursor:] = target.jump(fragment.address + cursor, groups[index + 1][0].address)
            except ValueError as exc:
                raise ValueError(f"cannot join split fragments of {section.name}. {exc}") from exc


def place(
    object_: Object, space: Space, imports: dict[str, int], isa: ISA, target: Target = X86_64,
) -> list[Fragment]:
    sections = sorted(
        object_.sections.values(),
        key=lambda section: (not bool(section.flags & 1), bool(section.flags & 4), -len(section.data)),
    )
    split = []
    for section in sections:
        alignment = max(section.alignment, target.alignment) if section.flags & 4 else section.alignment
        address = space.allocate(len(section.data), alignment, section.permissions)
        if address is not None:
            section.fragments.append(Fragment(address, bytearray(section.data)))
        elif section.flags & 4:
            split.append(section)
        else:
            raise ValueError(
                f"insufficient cleared space for {section.name} ({len(section.data)} contiguous bytes). "
                f"The section {space.describe_capacity(alignment, section.permissions)}"
            )
    for section in split:
        _split(section, space, isa, target)

    def resolve(symbol: Symbol, addend: int) -> int:
        return _symbol_address(object_, symbol, addend, imports)

    for section in sections:
        for relocation in section.relocations:
            try:
                if target.machine == "EM_RISCV":
                    riscv.apply(object_, section, relocation, resolve, target.bits)
                else:
                    _apply_x86(object_, section, relocation, imports, isa)
            except ValueError as exc:
                kind = (
                    riscv.relocation_name(relocation.kind) if target.machine == "EM_RISCV"
                    else _X86_RELOCATION_NAMES.get(relocation.kind, f"x86-64 relocation type {relocation.kind}")
                )
                raise ValueError(f"{relocation.describe(section, kind)} failed. {exc}") from exc
    return [fragment for section in sections for fragment in section.fragments]


def _symbol_address(object_: Object, symbol: Symbol, addend: int, imports: dict[str, int]) -> int:
    if symbol.section == "SHN_UNDEF":
        if symbol.name not in imports:
            raise ValueError(f"undefined relocation symbol {symbol.name!r}")
        return imports[symbol.name] + addend
    if symbol.section == "SHN_ABS":
        return symbol.offset + addend
    if symbol.section in object_.sections:
        return object_.sections[symbol.section].address(symbol.offset + addend)
    raise ValueError(f"relocation references an unsupported section for {symbol.name!r}")


def _apply_x86(
    object_: Object, section: Section, relocation: Relocation,
    imports: dict[str, int], isa: ISA,
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
    destination = object_.sections.get(symbol.section)
    if destination is not None and destination.instruction_addresses and relative:
        if not section.pc_bias and section.flags & 4:
            _instructions(section, isa)
        bias = section.pc_bias.get(offset, 0)
    else:
        bias = 0
    value = _symbol_address(object_, symbol, addend + bias, imports) - bias

    if relative:
        value -= address
    section.write_word(address, value, width, signed=signed)
