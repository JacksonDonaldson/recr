"""Parse function metadata from Ghidra XML program exports."""

from __future__ import annotations

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from ir import Function
from parsers.base import UNKNOWN_FILE_OFFSET, ParseError, ParseResult


_SWITCH_CASE_NAME = re.compile(
    r"(?:^|::)(?:caseD_[0-9a-fA-F]+|switchD_(?:[^:]+:{1,2})?[0-9a-fA-F]+::default)\Z"
)


def is_switch_case(name: str) -> bool:
    """Recognize generated case labels and defaults in a switch namespace."""
    return _SWITCH_CASE_NAME.search(name) is not None


def is_supported(filename: str) -> bool:
    """Return whether ``filename`` is a Ghidra XML program export."""
    if Path(filename).suffix.lower() != ".xml":
        return False

    try:
        root = ET.parse(filename).getroot()
    except (ET.ParseError, OSError):
        return False

    return root.tag == "PROGRAM"


def parse(filename: str) -> ParseResult:
    """Parse a Ghidra XML function export."""
    try:
        root = ET.parse(filename).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ParseError(f"failed to parse Ghidra XML {filename}: {exc}") from exc

    if root.tag != "PROGRAM":
        raise ParseError(
            f"{filename} is not a Ghidra XML export "
            f"(expected <PROGRAM>, found <{root.tag}>)"
        )

    warnings: list[str] = []
    functions: list[Function] = []
    switch_case_ranges: list[tuple[int, int]] = []
    artificial_ranges = _find_artificial_ranges(root)

    for element in root.findall("./FUNCTIONS/FUNCTION"):
        name = element.get("NAME", "")
        if is_switch_case(name):
            try:
                ranges = _address_ranges(element)
                entry = _parse_hex(element.get("ENTRY_POINT", ""))
                if not any(start <= entry <= end for start, end in ranges):
                    raise ValueError("ENTRY_POINT is outside the declared ADDRESS_RANGE elements")
            except ValueError as exc:
                raise ParseError(f"cannot preserve Ghidra switch case {name!r} in {filename}. {exc}") from exc
            switch_case_ranges.extend((start, end + 1) for start, end in ranges)
            continue
        function = _parse_function(element, warnings, artificial_ranges)
        if function is not None:
            functions.append(function)

    try:
        isa = _detect_isa(root)
    except ParseError as exc:
        raise ParseError(f"cannot identify the ISA in Ghidra XML {filename}. {exc}") from exc
    return ParseResult(isa=isa, functions=functions, warnings=warnings, switch_case_ranges=switch_case_ranges)


def _detect_isa(root: ET.Element) -> str:
    processor = root.find("PROCESSOR")
    if processor is None:
        raise ParseError("Ghidra XML is missing the PROCESSOR element")

    language = processor.get("LANGUAGE_PROVIDER", "")
    parts = [part.strip().upper() for part in language.split(":") if part.strip()]
    if parts and parts[0] == "X86":
        if "64" in parts:
            return "x86_64"
        if "32" in parts:
            return "x86"

    name = (processor.get("NAME") or "").lower()
    address_model = (processor.get("ADDRESS_MODEL") or "").lower()
    if name in ("x86", "x86_64", "x86-64"):
        return "x86_64" if ("64" in name or "64" in address_model) else "x86"

    if parts and parts[0] == "RISCV":
        if len(parts) >= 4 and parts[1] == "LE" and parts[3] == "DEFAULT":
            if parts[2] in ("32", "64"):
                return f"riscv{parts[2]}"
        raise ParseError(f"unsupported Ghidra processor: {language!r}")
    if name == "riscv":
        if (processor.get("ENDIAN") or "little").lower() != "little":
            raise ParseError(f"unsupported Ghidra processor endianness: {processor.get('ENDIAN')!r}")
        if "64" in address_model:
            return "riscv64"
        if "32" in address_model:
            return "riscv32"

    display_name = language or name or "<unknown>"
    raise ParseError(f"unsupported Ghidra processor: {display_name!r}")


def _find_artificial_ranges(root: ET.Element) -> list[tuple[int, int]]:
    """Return address ranges Ghidra created only to hold external symbols."""
    ranges: list[tuple[int, int]] = []

    for section in root.findall("./MEMORY_MAP/MEMORY_SECTION"):
        if (section.get("ARTIFICIAL") or "").lower() != "y":
            continue

        start_value = section.get("START_ADDR")
        length_value = section.get("LENGTH")
        if not start_value or not length_value:
            continue

        try:
            start = _parse_hex(start_value)
            length = _parse_hex(length_value)
        except ValueError:
            continue

        ranges.append((start, start + length))

    return ranges


def _parse_function(
    element: ET.Element,
    warnings: list[str],
    artificial_ranges: list[tuple[int, int]],
) -> Function | None:
    name = element.get("NAME") or ""
    entry_point = element.get("ENTRY_POINT")

    if not entry_point:
        warnings.append(f"skipping function {name or '<unnamed>'}: missing ENTRY_POINT")
        return None

    try:
        start_address = _parse_hex(entry_point)
    except ValueError:
        warnings.append(
            f"skipping function {name or '<unnamed>'}: "
            f"invalid ENTRY_POINT {entry_point!r}"
        )
        return None

    if not name:
        name = f"sub_{start_address:x}"

    if any(start <= start_address < end for start, end in artificial_ranges):
        warnings.append(
            f"skipping function {name}: address is in an artificial memory block"
        )
        return None

    # Older or stripped exports may not mark the external block as artificial.
    if not artificial_ranges and name.startswith("<EXTERNAL>::"):
        warnings.append(f"skipping external function {name}")
        return None

    try:
        ranges = _address_ranges(element)
    except ValueError as exc:
        warnings.append(f"skipping function {name}: {exc}")
        return None

    if len(ranges) > 1:
        warnings.append(
            f"skipping function {name}: {len(ranges)} non-contiguous "
            "address ranges are not supported"
        )
        return None

    range_start, range_end = ranges[0]
    if range_start != start_address:
        warnings.append(
            f"function {name}: ADDRESS_RANGE starts at {range_start:#x} but "
            f"ENTRY_POINT is {start_address:#x}; using ENTRY_POINT"
        )

    if range_end < start_address:
        warnings.append(f"skipping function {name}: address range precedes entry point")
        return None

    return Function(
        name=name,
        file_offset=UNKNOWN_FILE_OFFSET,
        start_address=start_address,
        length=range_end - start_address + 1,
    )


def _address_ranges(element: ET.Element) -> list[tuple[int, int]]:
    """Read the inclusive bounds of each declared body range."""
    ranges: list[tuple[int, int]] = []
    for address_range in element.findall("ADDRESS_RANGE"):
        start_value = address_range.get("START")
        end_value = address_range.get("END")
        if not start_value or not end_value:
            raise ValueError("incomplete ADDRESS_RANGE")
        try:
            start = _parse_hex(start_value)
            end = _parse_hex(end_value)
        except ValueError as exc:
            raise ValueError("invalid ADDRESS_RANGE") from exc
        if end < start:
            raise ValueError("ADDRESS_RANGE ends before it starts")
        ranges.append((start, end))
    if not ranges:
        raise ValueError("no ADDRESS_RANGE")
    return ranges


def _parse_hex(value: str) -> int:
    """Parse a Ghidra numeric value.

    Values are hexadecimal with or without ``0x``.  Some exports qualify an
    address with its address space, for example ``ram:00011220``; the offset is
    the virtual address in the binary image.
    """
    text = value.strip()
    if not text:
        raise ValueError("empty address")

    space, separator, offset = text.rpartition(":")
    if separator:
        if not space or not offset:
            raise ValueError(f"invalid address {value!r}")
        text = offset

    return int(text, 16)
