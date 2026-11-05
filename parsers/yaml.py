"""YAML input parser.

Expected schema::

    isa: x86_64
    functions:
      function_name:
        start_address: 0x401000
        file_offset: 0x1000
        length: 0x20

Additional top-level keys are ignored.
"""

from __future__ import annotations

from parsers.base import ParseResult


def is_supported(filename: str) -> bool:
    """Return whether ``filename`` looks like a YAML function export."""
    raise NotImplementedError


def parse(filename: str) -> ParseResult:
    """Parse a YAML function export."""
    raise NotImplementedError
