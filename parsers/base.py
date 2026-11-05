"""Types shared by all reverse-engineering input parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ir import Function


@dataclass
class ParseResult:
    """Function-level information recovered from an RE-tool export."""

    isa: str
    functions: list[Function] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
