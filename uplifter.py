"""Lift recovered functions into instructions, basic blocks, and a CFG."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ir import Address, Function
from isa import ISA, create_isa

if TYPE_CHECKING:
    from binary.binary import Binary


class Uplifter:
    """Turn function locations from an input description into IR."""

    def __init__(self, isa: str, binary: "Binary") -> None:
        self.isa: ISA = create_isa(isa)
        self.binary = binary
        self.function_map: dict[Address, Function] = {}

    def uplift_function(self, function: Function) -> None:
        """Disassemble ``function``, recover its flow graph, and index it."""
        raise NotImplementedError

    def build_xrefs(self) -> None:
        """Recover cross-references across the full binary.

        This runs after every function has been uplifted.  It scans the whole
        binary rather than trusting the input function list, which may be
        incomplete.
        """
        raise NotImplementedError
