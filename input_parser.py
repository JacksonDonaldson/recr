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
        raise ParseError(f"input export does not exist: {filename}")

    suffix = path.suffix.lower()
    # Dispatch YAML directly so malformed exports retain their schema diagnostics.
    if suffix in yaml.EXTENSIONS:
        return yaml.parse(filename)

    for parser in PARSER_LIST:
        if parser.is_supported(filename):
            return parser.parse(filename)

    if suffix == ".xml":
        raise ParseError(
            f"{filename} has an .xml extension but is not a Ghidra XML export"
        )
    raise ParseError(
        f"no parser supports input export {filename} "
        f"(extension {suffix or '<none>'})"
    )
