"""Aggressive function outlining.

This pass finds repeated instruction regions, extracts them into a shared
target block, and replaces each source site with a call.  It must run after the
function remover.  Unwind information is intentionally out of scope for now.

The current implementation builds the position-invariant instruction index and
finds profitable basic-block matches.  Replacement bytes, function regeneration,
and relinking are not implemented yet.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ir import BasicBlock, FreeSpace, Instruction

if TYPE_CHECKING:
    from binary.binary import Binary
    from isa.isa import ISA
    from uplifter import Uplifter

LOGGER = logging.getLogger(__name__)

# Every matched instruction is re-linked to this fixed address before its bytes
# become a match key.  A relative operand therefore compares by its absolute
# target instead of by the address it happened to be decoded at.
_CANONICAL_ADDRESS = 0
_MAX_MATCHES_PER_BLOCK = 10


@dataclass(frozen=True)
class BasicBlockMatch:
    """A set of blocks that can share a common instruction sequence."""

    blocks: tuple[BasicBlock, ...]
    common_instructions: tuple[Instruction, ...]
    encodings: frozenset[bytes]
    common_length: int
    estimated_savings: int

    @property
    def block_count(self) -> int:
        """Return how many source sites this match would replace."""
        return len(self.blocks)


@dataclass
class ExtractionResult:
    """Data returned by :func:`extract_instruction_regions`."""

    free_space: list[FreeSpace] = field(default_factory=list)
    extracted_instructions: list[BasicBlock] = field(default_factory=list)
    extracted_basic_blocks: list[BasicBlock] = field(default_factory=list)
    basic_blocks_to_regenerate: list[tuple[BasicBlock, BasicBlock]] = field(
        default_factory=list
    )
    matches: list[BasicBlockMatch] = field(default_factory=list)


@dataclass
class _InstructionIndex:
    """Position-invariant encodings mapped to the blocks containing them."""

    blocks: dict[bytes, dict[int, BasicBlock]] = field(default_factory=dict)
    lengths: dict[bytes, int] = field(default_factory=dict)


def run_optimizer(
    binary: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
    free_space: list[FreeSpace],
) -> ExtractionResult | None:
    """Orchestrate function outlining.

    Only extraction and matching are implemented so far.  The result carries
    the profitable basic-block matches; it is returned without modifying the
    binary.
    """
    result = extract_instruction_regions(binary, uplifter, isa)
    if result is None:
        return None

    LOGGER.info(
        "outliner found %d profitable basic-block match(es)", len(result.matches)
    )

    # TODO(outliner): try to generate replacement bytes for each match, mark
    # the source blocks as used, regenerate the affected functions, and relink
    # the extracted blocks into ``free_space``.
    return result


def extract_instruction_regions(
    binary: "Binary", uplifter: "Uplifter", isa: "ISA"
) -> ExtractionResult | None:
    """Find profitable repeated regions and plan their extraction."""
    if not isa.supports_outlining:
        LOGGER.warning(
            "ISA %s does not support function outlining",
            isa.name or "<unknown>",
        )
        return None

    index = _build_instruction_index(uplifter, isa)
    result = ExtractionResult()
    seen: set[tuple[frozenset[int], frozenset[bytes]]] = set()

    for function in sorted(
        uplifter.function_map.values(), key=lambda item: item.start_address
    ):
        if function.has_unk_local_reference():
            continue

        # TODO(outliner): skip functions that use the red zone.  This does not
        # affect matching, but it must be implemented before referenced blocks
        # are actually relocated.  Function.uses_red_zone() is still a stub.
        for block in function.basic_blocks:
            if block.used_for_outlining:
                continue

            for match in find_basic_block_matches(block, index, isa):
                signature = (
                    frozenset(id(match_block) for match_block in match.blocks),
                    match.encodings,
                )
                if signature in seen:
                    continue
                seen.add(signature)
                result.matches.append(match)

    result.matches.sort(key=_match_sort_key)
    return result


def find_basic_block_matches(
    block: BasicBlock,
    instruction_index: _InstructionIndex,
    isa: "ISA",
) -> list[BasicBlockMatch]:
    """Return the most profitable sets of blocks that could share instructions.

    Instructions are compared by their position-invariant encoding.  A match
    groups blocks whose set of instructions in common with ``block`` is
    identical, and is kept only when the estimated saving is positive.
    """
    call_length = isa.call_instruction_length()
    ret_length = isa.ret_instruction_length()

    outlinable: list[tuple[bytes, Instruction]] = []
    seen_encodings: set[bytes] = set()
    for instruction in block.instructions:
        if not isa.is_outlinable(instruction):
            continue
        encoding = _canonical_encoding(isa, instruction)
        if encoding is None or encoding in seen_encodings:
            continue
        seen_encodings.add(encoding)
        outlinable.append((encoding, instruction))

    candidates: dict[int, tuple[BasicBlock, set[bytes]]] = {}
    for encoding, _ in outlinable:
        for block_id, other in instruction_index.blocks.get(
            encoding, {}
        ).items():
            if block_id == id(block):
                continue
            if block_id not in candidates:
                candidates[block_id] = (other, set())
            candidates[block_id][1].add(encoding)

    groups: dict[frozenset[bytes], dict[int, BasicBlock]] = {}
    for block_id, (other, encodings) in candidates.items():
        groups.setdefault(frozenset(encodings), {})[block_id] = other

    matches: list[BasicBlockMatch] = []
    for encodings, group_blocks in groups.items():
        blocks_by_id = dict(group_blocks)
        blocks_by_id[id(block)] = block
        blocks = tuple(
            sorted(blocks_by_id.values(), key=_block_sort_key)
        )

        common_length = sum(
            instruction_index.lengths[encoding]
            for encoding in encodings
        )
        if common_length < call_length:
            continue

        # Every source site loses the shared bytes and gains a call.  The
        # shared block itself is stored once in free space and ends in a
        # return, so that cost is subtracted as well.
        target_length = common_length + ret_length
        estimated_savings = (
            (common_length - call_length) * len(blocks) - target_length
        )
        if estimated_savings <= 0:
            continue

        common_instructions = tuple(
            instruction
            for encoding, instruction in outlinable
            if encoding in encodings
        )
        matches.append(
            BasicBlockMatch(
                blocks=blocks,
                common_instructions=common_instructions,
                encodings=encodings,
                common_length=common_length,
                estimated_savings=estimated_savings,
            )
        )

    matches.sort(key=_match_sort_key)
    return matches[:_MAX_MATCHES_PER_BLOCK]


def format_match(match: BasicBlockMatch) -> list[str]:
    """Render ``match`` as human-readable output lines."""
    lines = [
        (
            f"{match.block_count} source block(s), "
            f"{len(match.common_instructions)} shared instruction(s), "
            f"{match.common_length:#x} shared bytes, "
            f"estimated {match.estimated_savings:#x} bytes saved"
        ),
        "  shared instructions:",
    ]
    for instruction in match.common_instructions:
        lines.append(
            f"    {instruction.original_data.hex():<30} "
            f"{instruction.length} bytes"
        )

    lines.append("  source blocks:")
    for block in match.blocks:
        function = block.containing_function
        name = function.name if function is not None else "<unknown>"
        lines.append(f"    {block.start_location.value:#x} {name}")
    return lines


def relink_in_instructions(
    extracted_instructions: list[BasicBlock],
    extracted_basic_blocks: list[BasicBlock],
    free_space: list[FreeSpace],
) -> None:
    """Place extracted blocks in free space and relink their source sites."""
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


def _build_instruction_index(
    uplifter: "Uplifter", isa: "ISA"
) -> _InstructionIndex:
    """Index every outlinable instruction by its position-invariant encoding."""
    index = _InstructionIndex()
    for function in sorted(
        uplifter.function_map.values(), key=lambda item: item.start_address
    ):
        if function.has_unk_local_reference():
            continue
        for block in function.basic_blocks:
            for instruction in block.instructions:
                if not isa.is_outlinable(instruction):
                    continue
                encoding = _canonical_encoding(isa, instruction)
                if encoding is None:
                    continue
                index.blocks.setdefault(encoding, {})[id(block)] = block
                index.lengths.setdefault(encoding, instruction.length)
    return index


def _canonical_encoding(
    isa: "ISA", instruction: Instruction
) -> bytes | None:
    """Return position-invariant bytes for ``instruction``, or ``None``."""
    try:
        relocated = isa.relocate_instruction(
            instruction, _CANONICAL_ADDRESS
        )
    except ValueError:
        return None
    return relocated.original_data


def _block_sort_key(block: BasicBlock) -> tuple[int, str]:
    function = block.containing_function
    name = function.name if function is not None else ""
    return block.start_location.value, name


def _match_sort_key(
    match: BasicBlockMatch,
) -> tuple[int, int, int, int]:
    return (
        -match.estimated_savings,
        -match.block_count,
        -match.common_length,
        match.blocks[0].start_location.value,
    )
