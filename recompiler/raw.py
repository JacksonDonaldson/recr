"""Read a raw firmware manifest and build the metadata needed by recr."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Callable
from dataclasses import dataclass
import logging
from pathlib import Path

from binary.raw import RawBinary, Region
from input_parser import parse_re_file
from ir import Function
from parsers.base import UNKNOWN_FILE_OFFSET, ParseResult
from parsers.yaml import load_document, parse_functions
from recompiler.exports import IDENTIFIER, Exports, Segment, read_ghidra_exports
from recompiler.target import raw_target


FUNCTION_OUTSIDE_EXECUTABLE_RANGE = "function-outside-executable-range"
SKIP_SHORT_FUNCTIONS = "skip-short-functions"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RawInput:
    binary: RawBinary
    parsed: ParseResult
    exports: Exports
    protected_entries: frozenset[int]


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer greater than or equal to {minimum}")
    return value


def _regions(records: object, address_limit: int) -> tuple[list[Region], list[Segment]]:
    if not isinstance(records, list) or not records:
        raise ValueError("'regions' must be a nonempty list of mappings")
    file_regions = []
    segments = []
    for index, record in enumerate(records, 1):
        label = f"region {index}"
        if not isinstance(record, dict):
            raise ValueError(f"{label} must be a mapping")
        start = _integer(record.get("start_address"), f"{label} start_address")
        length = _integer(record.get("length"), f"{label} length", 1)
        if start + length > address_limit:
            raise ValueError(f"{label} extends past the target address space")
        permissions = record.get("permissions", "rx")
        if permissions not in ("r", "rw", "rx", "rwx"):
            raise ValueError(f"{label} permissions must be r, rw, rx, or rwx")
        flags = 4 | (2 if "w" in permissions else 0) | (1 if "x" in permissions else 0)
        file_size = 0
        if "file_offset" in record:
            offset = _integer(record["file_offset"], f"{label} file_offset")
            file_regions.append(Region(start, offset, length, flags))
            file_size = length
        segments.append(Segment(start, file_size, length, flags))

    virtual_order = sorted(segments, key=lambda segment: segment.start)
    for left, right in zip(virtual_order, virtual_order[1:]):
        if left.start + left.memory_size > right.start:
            raise ValueError(f"raw regions overlap in virtual address space at {right.start:#x}")
    return file_regions, segments


def _symbols(records: object, address_limit: int) -> dict[str, int]:
    if not isinstance(records, dict):
        raise ValueError("'symbols' must be a mapping")
    symbols = {}
    for name, record in records.items():
        if not isinstance(name, str) or not name:
            raise ValueError("symbol names must be nonempty strings")
        if not isinstance(record, dict):
            raise ValueError(f"symbol {name!r} must be a mapping")
        address = _integer(record.get("address"), f"symbol {name!r} address")
        if address >= address_limit:
            raise ValueError(f"symbol {name!r} is outside the target address space")
        symbols[name] = address
    return symbols


def _declarations(records: dict) -> dict[str, str]:
    declarations = {}
    for name, record in records.items():
        if "declaration" not in record:
            continue
        declaration = record["declaration"]
        if not IDENTIFIER.fullmatch(name) or not isinstance(declaration, str) or not declaration.strip().endswith(";"):
            raise ValueError(f"declaration for {name!r} must be a C declaration ending in ';'")
        declarations[name] = declaration
    return declarations


def _entry_points(binary: RawBinary, records: object) -> set[int]:
    if not isinstance(records, list):
        raise ValueError("'entry_points' must be a list of executable virtual addresses")
    entries = set()
    for value in records:
        address = _integer(value, "entry point")
        try:
            region = binary.region_at(address)
        except ValueError:
            region = None
        if region is None or not region.flags & 1:
            raise ValueError(f"entry point {address:#x} is outside mapped executable memory")
        entries.add(address)
    return entries


def _log_warning(message: str, option: str) -> None:
    LOGGER.warning("%s [-W%s]", message, option)


def _check_functions(
    binary: RawBinary, functions: list[Function], alignment: int, warn: Callable[[str, str], None],
) -> list[Function]:
    accepted = []
    for function in functions:
        start = function.start_address
        if function.length < alignment:
            warn(
                f"skipping raw function {function.name!r} at {start:#x}: "
                f"length {function.length} is below the target alignment of {alignment} bytes",
                SKIP_SHORT_FUNCTIONS,
            )
            continue
        end = start + function.length
        try:
            region = binary.region_at(start)
        except ValueError:
            region = None
        if region is None or end > region.end_address or not region.flags & 1:
            warn(
                f"skipping raw function {function.name!r} at {start:#x}: must fit in one executable region",
                FUNCTION_OUTSIDE_EXECUTABLE_RANGE,
            )
            continue
        if start % alignment or function.length % alignment:
            raise ValueError(
                f"raw function {function.name!r} is misaligned for the target ISA. "
                f"Is at {start:#x}, length {function.length:#x}, but must be aligned to {alignment:#x}"
            )
        offset = binary.virtual_to_file(start)
        if function.file_offset not in (UNKNOWN_FILE_OFFSET, offset):
            raise ValueError(f"raw function {function.name!r} file_offset disagrees with the region map")
        function.file_offset = offset
        accepted.append(function)

    end = 0
    for function in sorted(accepted, key=lambda item: item.start_address):
        if function.start_address < end:
            raise ValueError(f"raw function {function.name!r} overlaps another function")
        end = function.start_address + function.length
    return accepted


def read_raw_input(
    manifest: Path, xml: Path | None = None, *, warn: Callable[[str, str], None] = _log_warning,
) -> RawInput:
    document = {"functions": {}, **load_document(manifest)}
    path = document.get("binary")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("'binary' must name the raw image file")
    if xml is None:
        parsed = parse_functions(document, mapped_offsets=True, allow_empty=True)
    else:
        if document["functions"] != {}:
            raise ValueError("supply function records in either the manifest or the Ghidra XML export")
        parsed = parse_re_file(str(xml))
        if "isa" in document and document["isa"] != parsed.isa:
            raise ValueError(f"the manifest ISA disagrees with the {parsed.isa} Ghidra export")
    target = raw_target(parsed.isa, document.get("riscv"))
    address_limit = 1 << target.bits
    file_regions, segments = _regions(document.get("regions"), address_limit)
    symbol_records = document.get("symbols", {})
    symbols = _symbols(symbol_records, address_limit)
    binary = RawBinary(manifest.parent / path, file_regions, symbols)
    parsed.functions = _check_functions(binary, parsed.functions, target.alignment, warn)
    entries = _entry_points(binary, document.get("entry_points", []))
    declared_references = entries | set(symbols.values())
    points = sorted(declared_references)
    protected = set()
    if xml is None:
        functions = {f.name: [f] for f in parsed.functions}
        addresses = {f.name: {f.start_address} for f in parsed.functions}
        declarations = _declarations({name: document["functions"][name] for name in functions})
        function_declarations = {
            (f.name, f.start_address): declarations[f.name] for f in parsed.functions if f.name in declarations
        }
        exports = Exports(
            functions, addresses, declarations, segments, [], set(), target,
            function_declarations=function_declarations,
        )
    else:
        exports = read_ghidra_exports(xml, parsed.functions, segments, target)
    for name, address in symbols.items():
        if name in exports.functions:
            raise ValueError(f"raw name {name!r} is declared as both a function and a symbol")
        exports.addresses[name] = {address}
    exports.declarations.update(_declarations(symbol_records))
    exports.references.update(declared_references)
    for function in parsed.functions:
        start = function.start_address
        index = bisect_left(points, start)
        if index < len(points) and points[index] < start + function.length:
            protected.add(start)
    return RawInput(binary, parsed, exports, frozenset(protected))
