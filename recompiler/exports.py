"""Read typed C symbols from Ghidra and classify available storage for recr."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
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
    function_declarations: dict[tuple[str, int], str] = field(default_factory=dict)

    def address(self, name: str, *, ignored_entry: int | None = None) -> int:
        values = self.addresses.get(name, set())
        if ignored_entry is not None:
            values = values - {ignored_entry}
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


def _riscv_receiver(
    function: ET.Element, target: Target, structures: dict[str, set[str]],
) -> str | None:
    receivers = function.findall("REGISTER_VAR[@NAME='this']")
    if target.machine != "EM_RISCV" or len(receivers) != 1 or receivers[0].get("REGISTER") != "a0":
        return None
    receiver = receivers[0]
    pointer = re.fullmatch(r"([A-Za-z_]\w*)\s*\*", receiver.get("DATATYPE", ""))
    if pointer is None or structures.get(pointer[1]) != {receiver.get("DATATYPE_NAMESPACE", "/")}:
        return None
    return pointer[1]


def _signature(
    name: str, function: ET.Element, definition: ET.Element | None,
    typedefs: dict[str, str], *, for_hook: bool = False, receiver: str | None = None,
) -> str | None:
    text = function.findtext("TYPEINFO_CMT", "")
    match = re.search(rf"\b(?:[A-Za-z_]\w*::)*{re.escape(name)}\s*\((.*)\)\s*$", text)
    if "__thiscall" in text.partition("(")[0].split() and receiver is None:
        return None
    if for_hook:
        if match is None:
            return None
        # RETURN_TYPE describes storage after ABI lowering. The comment holds the formal signature.
        result_type = re.sub(r"\s+__(?:stdcall|cdecl|thiscall)\s*$", "", text[:match.start()])
    else:
        metadata = definition if definition is not None else function
        result = metadata.find("RETURN_TYPE")
        if result is None:
            return None
        result_type = result.get("DATATYPE", "")
    returned = _type(result_type, typedefs)
    if returned is None:
        return None
    arguments = []
    if definition is not None:
        for parameter in definition.findall("PARAMETER"):
            argument = _type(parameter.get("DATATYPE", ""), typedefs)
            if argument is None:
                return None
            arguments.append(argument)
    else:
        if match is None:
            return None
        parameters = [parameter.strip() for parameter in match[1].split(",")]
        if for_hook and (
            "" in parameters or ("void" in parameters and parameters != ["void"])
            or "..." in parameters[:-1] or (parameters == ["..."] and receiver is None)
        ):
            return None
        for parameter in parameters:
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
    if not for_hook and name == "printf" and arguments == ["char *", "..."]:
        arguments[0] = "const char *"
    if receiver is not None:
        # Ghidra omits the automatic receiver from TYPEINFO_CMT.
        arguments.insert(0, f"struct {receiver} *")
        return f"struct {receiver};\nextern {returned} {name}({', '.join(arguments)});"
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
    structures: dict[str, set[str]] = defaultdict(set)
    for structure in root.findall("DATATYPES/STRUCTURE"):
        structures[structure.get("NAME", "")].add(structure.get("NAMESPACE", "/"))
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
    function_declarations: dict[tuple[str, int], str] = {}
    for function in functions:
        name = function.name.rpartition("::")[2]
        if not IDENTIFIER.fullmatch(name):
            continue
        by_name[name].append(function)
        addresses[name].add(function.start_address)
        node = function_nodes[function.start_address]
        thiscall = "__thiscall" in node.findtext("TYPEINFO_CMT", "").partition("(")[0].split()
        receiver = _riscv_receiver(node, target, structures) if thiscall else None
        # Named datatypes can be shared by multiple entries and omit variadic details.
        hook_declaration = _signature(name, node, None, typedefs, for_hook=True, receiver=receiver)
        if hook_declaration:
            function_declarations[name, function.start_address] = hook_declaration
        definition = definitions.get(function.name, definitions.get(name))
        declaration = hook_declaration if thiscall else _signature(name, node, definition, typedefs)
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
        if datatype == "string":
            prototypes[name].add(f"extern char {name}[];")
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
        to_address = node.get("TO_ADDRESS")
        if to_address:
            reference_addresses.add(_parse_hex(to_address))
    return Exports(
        by_name, addresses, declarations, segments, relro or [], reference_addresses, target,
        function_declarations=function_declarations,
    )
