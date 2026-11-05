"""Select and run an input parser for a reverse-engineering tool export."""

from __future__ import annotations

from parsers import ghidra_xml, yaml
from parsers.base import ParseResult

# Order matters: the first parser whose ``is_supported`` returns true wins.
PARSER_LIST = (yaml, ghidra_xml)

__all__ = ["PARSER_LIST", "ParseResult", "parse_re_file"]


def parse_re_file(filename: str) -> ParseResult:
    """Parse ``filename`` by extension, confirming by content sniffing."""
    raise NotImplementedError
