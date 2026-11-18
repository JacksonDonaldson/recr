"""Drop functions that no other code references.

The pass only identifies free space for now.  A later stage may overwrite that
space or reuse it for outlined code; this pass does not modify the binary.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, AbstractSet

from ir import Address, FreeSpace

if TYPE_CHECKING:
    from binary.binary import Binary
    from isa.isa import ISA
    from uplifter import Uplifter


def run_optimizer(
    binary: "Binary", uplifter: "Uplifter", isa: "ISA", *,
    protected_entries: AbstractSet[int] = frozenset(),
) -> list[FreeSpace]:
    """Drop unreferenced functions and return the space they occupied.

    A function is unreferenced when its ``incoming_references`` list is empty.
    Such a function is removed from the uplifter's live function map, and its
    complete declared extent is reported as one :class:`FreeSpace` block.
    Detection is based only on the recovered cross-references, so callers must
    run :meth:`Uplifter.build_xrefs` first.
    """
    free_space: list[FreeSpace] = []

    for entry, function in sorted(
        uplifter.function_map.items(), key=lambda item: item[0].value
    ):
        if function.incoming_references or entry.value in protected_entries:
            continue

        del uplifter.function_map[entry]
        free_space.append(
            FreeSpace(
                start=Address.absolute(function.start_address),
                size=function.length,
                diagnostic=f"unreferenced function {function.name}",
            )
        )

    return free_space
