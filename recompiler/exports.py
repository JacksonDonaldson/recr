"""Read typed C symbols from Ghidra and classify available storage for recr."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from elftools.elf.elffile import ELFFile

from ir import Function
from parsers.ghidra_xml import _parse_hex
from recompiler.riscv import plt_addresses
from recompiler.target import X86_64, Target, executable_target


IDENTIFIER = re.compile(r"[A-Za-z_]\w*", re.ASCII)
_SCALAR = re.compile(
    r"(?:(?:const|volatile)\s+)*(?:void|_Bool|char|short|int|long|float|double|"
    r"unsigned|signed|u?int(?:8|16|32|64)_t|size_t|ssize_t|u?intptr_t)"
    r"(?:\s+(?:char|short|int|long|double))*"
    r"(?:\s*\*\s*(?:const\s*)?)*"
)
_TYPE_NAMES = {
    "bool": "_Bool", "byte": "unsigned char", "sbyte": "signed char",
    "uchar": "unsigned char", "ushort": "unsigned short", "uint": "unsigned int",
    "ulong": "unsigned long", "longlong": "long long",
    "ulonglong": "unsigned long long", "word": "uint16_t", "dword": "uint32_t",
    "qword": "uint64_t",
}


@dataclass(frozen=True)
class Segment:
    start: int
    size: int
    memory_size: int
    flags: int


@dataclass
class Exports:
    functions: dict[str, list[Function]]
    addresses: dict[str, set[int]]
    declarations: dict[str, str]
    segments: list[Segment]
    relro: list[tuple[int, int]]
    references: set[int]
    target: Target = X86_64

    def address(self, name: str) -> int:
        values = self.addresses.get(name, set())
        if len(values) != 1:
            detail = "ambiguous" if values else "undefined"
            raise ValueError(f"{detail} exported symbol {name!r}")
        return next(iter(values))


def _type(text: str, typedefs: dict[str, str]) -> str | None:
    tokens = re.findall(r"[A-Za-z_]\w*|\*|[^\s]", text)
    words = []
    for word in tokens:
        seen = set()
        while word in typedefs and word not in seen:
            seen.add(word)
            word = typedefs[word]
        words.append(_TYPE_NAMES.get(word, word))
    value = " ".join(words)
    return value if _SCALAR.fullmatch(value) else None


def _signature(
    name: str, function: ET.Element, definition: ET.Element | None,
    typedefs: dict[str, str],
) -> str | None:
    metadata = definition if definition is not None else function
    result = metadata.find("RETURN_TYPE")
    if result is None:
        return None
    returned = _type(result.get("DATATYPE", ""), typedefs)
    if returned is None:
        return None
    text = function.findtext("TYPEINFO_CMT", "")
    arguments = []
    if definition is not None:
        for parameter in definition.findall("PARAMETER"):
            argument = _type(parameter.get("DATATYPE", ""), typedefs)
            if argument is None:
                return None
            arguments.append(argument)
    else:
        match = re.search(r"\b" + re.escape(name) + r"\s*\((.*)\)\s*$", text)
        if match is None:
            return None
        for parameter in match[1].split(","):
            parameter = parameter.strip()
            if not parameter or parameter in ("void", "..."):
                continue
            argument = _type(parameter, typedefs)
            if argument is None:
                argument = _type(re.sub(r"[A-Za-z_]\w*$", "", parameter).strip(), typedefs)
            if argument is None:
                return None
            arguments.append(argument)
    if re.search(r"\.\.\.\s*\)\s*$", text):
        arguments.append("...")
    if name == "printf" and arguments == ["char *", "..."]:
        arguments[0] = "const char *"
    return f"extern {returned} {name}({', '.join(arguments) or 'void'});"


def read_exports(binary: Path, xml: Path, functions: list[Function]) -> Exports:
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        target = executable_target(elf)
        imports = plt_addresses(elf) if target.machine == "EM_RISCV" else {}
        segments = []
        relro = []
        for segment in elf.iter_segments():
            start = segment["p_vaddr"]
            if segment["p_type"] == "PT_LOAD":
                segments.append(Segment(start, segment["p_filesz"], segment["p_memsz"], segment["p_flags"]))
            if segment["p_type"] == "PT_GNU_RELRO":
                relro.append((start, start + segment["p_memsz"]))
    return read_ghidra_exports(xml, functions, segments, target, imports=imports, relro=relro)


def read_ghidra_exports(
    xml: Path, functions: list[Function], segments: list[Segment], target: Target,
    *, imports: dict[str, set[int]] | None = None, relro: list[tuple[int, int]] | None = None,
) -> Exports:
    imports = imports or {}
    root = ET.parse(xml).getroot()
    typedefs = {e.get("NAME", ""): e.get("DATATYPE", "") for e in root.findall("DATATYPES/TYPE_DEF")}
    definitions = {}
    for definition in root.findall("DATATYPES/FUNCTION_DEF"):
        name = definition.get("NAME", "")
        if name not in definitions or definition.get("NAMESPACE", "").startswith("/DWARF/"):
            definitions[name] = definition
    function_nodes = {
        _parse_hex(node.attrib["ENTRY_POINT"]): node
        for node in root.findall("FUNCTIONS/FUNCTION") if node.get("ENTRY_POINT")
    }
    by_name: dict[str, list[Function]] = defaultdict(list)
    addresses: dict[str, set[int]] = defaultdict(set)
    prototypes: dict[str, set[str]] = defaultdict(set)
    for function in functions:
        name = function.name.removeprefix("<EXTERNAL>::")
        if not IDENTIFIER.fullmatch(name):
            continue
        by_name[name].append(function)
        addresses[name].add(function.start_address)
        declaration = _signature(name, function_nodes[function.start_address], definitions.get(name), typedefs)
        if declaration:
            prototypes[name].add(declaration)

    for node in root.findall("FUNCTIONS/FUNCTION"):
        qualified = node.get("NAME", "")
        if not qualified.startswith("<EXTERNAL>::"):
            continue
        name = qualified.removeprefix("<EXTERNAL>::")
        if not IDENTIFIER.fullmatch(name) or name not in imports:
            continue
        addresses[name].update(imports[name])
        declaration = _signature(name, node, definitions.get(name), typedefs)
        if declaration:
            prototypes[name].add(declaration)

    data_types = {
        node.get("ADDRESS"): node.get("DATATYPE", "")
        for node in root.findall("DATA/DEFINED_DATA")
    }
    for node in root.findall("SYMBOL_TABLE/SYMBOL"):
        name = node.get("NAME", "")
        raw_address = node.get("ADDRESS", "")
        if not IDENTIFIER.fullmatch(name) or raw_address.startswith("EXTERNAL:"):
            continue
        try:
            address = _parse_hex(raw_address)
        except ValueError:
            continue
        if not any(s.start <= address < s.start + s.memory_size for s in segments):
            continue
        addresses[name].add(address)
        datatype = data_types.get(raw_address)
        if not datatype:
            continue
        array = re.fullmatch(r"(.+?)\s*((?:\[\d+\])+)", datatype)
        datatype = _type(array[1] if array else datatype, typedefs)
        if datatype:
            suffix = array[2] if array else ""
            prototypes[name].add(f"extern {datatype} {name}{suffix};")
    declarations = {
        name: next(iter(values)) for name, values in prototypes.items()
        if len(values) == 1 and len(addresses[name]) == 1
    }
    reference_addresses = set()
    for node in root.findall("MARKUP/MEMORY_REFERENCE"):
        target = node.get("TO_ADDRESS")
        if target:
            reference_addresses.add(_parse_hex(target))
    return Exports(by_name, addresses, declarations, segments, relro or [], reference_addresses, target)
