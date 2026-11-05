"""Remove functions that have no incoming references."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ir import FreeSpace

if TYPE_CHECKING:
    from binary.binary import Binary
    from isa.isa import ISA
    from uplifter import Uplifter


def run_optimizer(
    binary: "Binary", uplifter: "Uplifter", isa: "ISA"
) -> list[FreeSpace]:
    """Drop unreferenced functions and return the space they occupied."""
    raise NotImplementedError
