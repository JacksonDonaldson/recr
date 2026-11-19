"""Select and run an input parser for a reverse-engineering tool export."""

from __future__ import annotations

from pathlib import Path

from parsers import ghidra_xml, yaml
from parsers.base import ParseError, ParseResult

# The first successful content probe wins for formats that use probing.
PARSER_LIST = (yaml, ghidra_xml)

__all__ = ["PARSER_LIST", "ParseError", "ParseResult", "parse_re_file"]


def parse_re_file(filename: str) -> ParseResult:
    """Parse ``filename`` by extension, confirming by content sniffing."""
    path = Path(filename)
    if not path.is_file():
        if path.is_dir():
            raise ParseError(f"input export {filename} is a directory. Supply an export file")
        raise ParseError(f"input export does not exist: {filename}")

    suffix = path.suffix.lower()
    # Dispatch known extensions directly to retain their parse diagnostics.
    if suffix in yaml.EXTENSIONS:
        return yaml.parse(filename)
    if suffix == ".xml":
        return ghidra_xml.parse(filename)

    for parser in PARSER_LIST:
        if parser.is_supported(filename):
            return parser.parse(filename)

    raise ParseError(
        f"no parser supports input export {filename} "
        f"(extension {suffix or '<none>'}). Use a Ghidra .xml export or a .yaml/.yml function export"
    )
