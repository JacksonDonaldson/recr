"""Types shared by all reverse-engineering input parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ir import Function

UNKNOWN_FILE_OFFSET = -1


class ParseError(Exception):
    """Raised when an input file is not a valid supported export."""


@dataclass
class ParseResult:
    """Function-level information recovered from an RE-tool export."""

    isa: str
    functions: list[Function] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    switch_case_ranges: list[tuple[int, int]] = field(default_factory=list)  # Half-open byte ranges.
