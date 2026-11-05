"""Aggressive function outlining.

This pass finds repeated instruction regions, extracts them into a shared
target block, and replaces each source site with a call.  It must run after the
function remover.  Unwind information is intentionally out of scope for now.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ir import BasicBlock, FreeSpace, Instruction

if TYPE_CHECKING:
    from binary.binary import Binary
    from isa.isa import ISA
    from uplifter import Uplifter


@dataclass
class ExtractionResult:
    """Data returned by :func:`extract_instruction_regions`."""

    free_space: list[FreeSpace] = field(default_factory=list)
    extracted_instructions: list[BasicBlock] = field(default_factory=list)
    extracted_basic_blocks: list[BasicBlock] = field(default_factory=list)
    basic_blocks_to_regenerate: list[tuple[BasicBlock, BasicBlock]] = field(
        default_factory=list
    )


def run_optimizer(
    binary: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
    free_space: list[FreeSpace],
) -> None:
    """Orchestrate function outlining."""
    raise NotImplementedError


def extract_instruction_regions(
    binary: "Binary", uplifter: "Uplifter", isa: "ISA"
) -> ExtractionResult | None:
    """Find profitable repeated regions and plan their extraction."""
    raise NotImplementedError


def relink_in_instructions(
    extracted_instructions: list[BasicBlock],
    extracted_basic_blocks: list[BasicBlock],
    free_space: list[FreeSpace],
) -> None:
    """Place extracted blocks in free space and relink their source sites."""
    raise NotImplementedError


def find_basic_block_matches(
    block: BasicBlock,
) -> list[tuple[set[BasicBlock], set[Instruction]]]:
    """Return the most profitable sets of blocks that could share instructions."""
    raise NotImplementedError


def try_generate_replacement_bytes(
    basic_blocks: set[BasicBlock], common_instructions: set[Instruction]
) -> tuple[list[BasicBlock], BasicBlock] | None:
    """Try to reorder each block so the common instructions are contiguous."""
    raise NotImplementedError


def find_indices(
    basic_block: BasicBlock, instructions_to_find: set[Instruction]
) -> list[int]:
    """Return the indices of ``instructions_to_find`` in ``basic_block``."""
    raise NotImplementedError


def convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
    basic_block: BasicBlock,
    instructions_to_move: list[Instruction],
    target_instruction_order: list[Instruction],
) -> tuple[BasicBlock, int] | None:
    """Reorder instructions while minimizing non-target instructions between them."""
    raise NotImplementedError


def can_swap_instruction(
    group_to_move: list[Instruction], to_swap_with: Instruction
) -> bool:
    """Return whether two instruction groups can be reordered safely."""
    raise NotImplementedError
