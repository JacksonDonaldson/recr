"""YAML input parser.

Expected schema::

    isa: x86_64
    functions:
      function_name:
        start_address: 0x401000
        file_offset: 0x1000
        length: 0x20

Additional top-level keys are ignored. Use -1 for an unknown file offset.
"""

from __future__ import annotations

from collections.abc import Hashable
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, Node

from ir import Function
from parsers.base import UNKNOWN_FILE_OFFSET, ParseError, ParseResult

EXTENSIONS = (".yaml", ".yml")
_ADDRESS_LIMIT = 1 << 64


class _UniqueKeyLoader(yaml.SafeLoader):
    """Reject duplicate keys before they can overwrite a function or field."""

    def construct_mapping(self, node: Node, deep: bool = False) -> dict:
        if not isinstance(node, MappingNode):
            return super().construct_mapping(node, deep=deep)
        keys: set[Hashable] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            if key_node.tag == "tag:yaml.org,2002:value":
                key = self.construct_scalar(key_node)
            else:
                key = self.construct_object(key_node, deep=deep)
            if isinstance(key, Hashable):
                if key in keys:
                    raise ConstructorError(
                        None, None, f"duplicate mapping key {key!r}", key_node.start_mark
                    )
                keys.add(key)
        return super().construct_mapping(node, deep=deep)


def is_supported(filename: str) -> bool:
    """Return whether ``filename`` is a valid YAML function export."""
    if Path(filename).suffix.lower() not in EXTENSIONS:
        return False
    try:
        parse(filename)
    except ParseError:
        return False
    return True


def load_document(filename: str | Path) -> dict:
    """Read a YAML mapping with unique keys."""
    try:
        document = yaml.load(Path(filename).read_bytes(), Loader=_UniqueKeyLoader)
        if not isinstance(document, dict):
            raise ValueError("the document must be a mapping")
        return document
    except (OSError, RecursionError, ValueError, yaml.YAMLError) as exc:
        raise ParseError(f"invalid YAML export {filename}: {exc}") from exc


def parse(filename: str) -> ParseResult:
    """Parse a YAML function export."""
    try:
        return parse_functions(load_document(filename))
    except ValueError as exc:
        raise ParseError(f"invalid YAML export {filename}: {exc}") from exc


def parse_functions(document: dict, *, mapped_offsets: bool = False) -> ParseResult:
    """Parse function records, optionally deriving missing offsets from a memory map."""
    isa = document.get("isa")
    if not isinstance(isa, str) or not isa.strip():
        raise ValueError("'isa' must be a nonempty string")
    records = document.get("functions")
    if not isinstance(records, dict):
        raise ValueError("'functions' must be a mapping")

    functions: list[Function] = []
    for name, record in records.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("function names must be nonempty strings")
        if not isinstance(record, dict):
            raise ValueError(f"function {name!r} must be a mapping")
        start = _read_integer(record, "start_address", name, 0)
        offset = UNKNOWN_FILE_OFFSET
        if not mapped_offsets or "file_offset" in record:
            offset = _read_integer(record, "file_offset", name, UNKNOWN_FILE_OFFSET)
        length = _read_integer(record, "length", name, 1)
        if start + length > _ADDRESS_LIMIT:
            raise ValueError(f"function {name!r} extends past the 64-bit address space")
        functions.append(
            Function(name=name, start_address=start, file_offset=offset, length=length)
        )

    return ParseResult(isa=isa.strip(), functions=functions)


def _read_integer(record: dict, field: str, function: str, minimum: int) -> int:
    value = record.get(field)
    if type(value) is not int or not minimum <= value < _ADDRESS_LIMIT:
        raise ValueError(
            f"function {function!r} field {field!r} must be an integer "
            f"between {minimum} and {_ADDRESS_LIMIT - 1:#x}"
        )
    return value
