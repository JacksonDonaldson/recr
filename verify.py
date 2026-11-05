"""Verify that an optimized binary still behaves like the original.

Any function that fails a check will eventually be reverted to its original
bytes.  All checks are currently stubs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binary.binary import Binary
    from isa.isa import ISA
    from uplifter import Uplifter


def run(
    original: "Binary",
    modified: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
) -> bool:
    """Run every verification stage and return whether all checks passed."""
    raise NotImplementedError


def check_round_trip(original: "Binary", isa: "ISA") -> list[str]:
    """Disassemble and re-emit every original instruction; require byte identity."""
    raise NotImplementedError


def check_static(
    original: "Binary",
    modified: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
) -> list[str]:
    """Check freed bytes are unreferenced and modified CFGs are isomorphic."""
    raise NotImplementedError


def check_per_function(
    original: "Binary",
    modified: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
) -> list[str]:
    """Emulate original and modified functions with the same state and compare."""
    raise NotImplementedError


def check_end_to_end(original: "Binary", modified: "Binary") -> list[str]:
    """Run a large C project's test suite against both binaries."""
    raise NotImplementedError
