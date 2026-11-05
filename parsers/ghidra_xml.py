"""Ghidra XML input parser.

Ghidra exports virtual addresses; the active :class:`binary.binary.Binary`
implementation is responsible for mapping them to file offsets.  The function
information is read from the ``FUNCTIONS`` section of the program document.
See ``test/fixtures/sample_ghidra.xml`` for the expected shape.
"""

from __future__ import annotations

from parsers.base import ParseResult


def is_supported(filename: str) -> bool:
    """Return whether ``filename`` looks like a Ghidra XML export."""
    raise NotImplementedError


def parse(filename: str) -> ParseResult:
    """Parse a Ghidra XML function export."""
    raise NotImplementedError
