"""Aggressive function outlining.

This pass finds repeated instruction regions, extracts them into a shared
target block, and replaces each source site with a call.  It must run after the
function remover.  Unwind information is intentionally out of scope for now.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import TYPE_CHECKING

from ir import (
    Address,
    AddressKind,
    BasicBlock,
    FreeSpace,
    Function,
    Instruction,
    InstructionType,
    Reference,
    StateSpace,
)

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
_OUTLINE_WINDOW_CACHE_SIZE = 65536


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
    selected_matches: list[BasicBlockMatch] = field(default_factory=list)
    modified_ranges: list[FreeSpace] = field(default_factory=list)
    # The selected replacement plans and their regenerated function layouts.
    # ``extract_instruction_regions`` returns these so that
    # ``relink_in_instructions`` can place the extracted blocks without
    # repeating the matching and regeneration work.
    plans: list["_ReplacementPlan"] = field(
        default_factory=list, repr=False
    )
    layouts: dict[int, "_FunctionLayout"] = field(
        default_factory=dict, repr=False
    )


@dataclass
class _InstructionIndex:
    """Index blocks by their complete sets of position-invariant encodings."""

    blocks: list[BasicBlock] = field(default_factory=list)
    positions: dict[int, int] = field(default_factory=dict)
    instructions: list[dict[bytes, Instruction]] = field(default_factory=list)
    postings: dict[bytes, set[int]] = field(default_factory=dict)
    lengths: dict[bytes, int] = field(default_factory=dict)
    signatures: list[frozenset[bytes]] = field(default_factory=list)
    signature_blocks: list[list[int]] = field(default_factory=list)
    block_signatures: list[int] = field(default_factory=list)


@dataclass(eq=False)
class _BlockReplacement:
    """A source block with its shared instructions replaced by a call."""

    original: BasicBlock
    instructions: list[Instruction]
    call: Instruction
    window_start: int
    removed_addresses: tuple[int, ...]
    replaced_first_address: int


@dataclass(frozen=True)
class _OutlineWindow:
    instructions: list[Instruction]
    start: int
    selected: list[Instruction]


@dataclass(eq=False)
class _ReplacementPlan:
    """One possible extraction for a :class:`BasicBlockMatch`."""

    match: BasicBlockMatch
    replacements: list[_BlockReplacement]
    extracted: BasicBlock
    extracted_instructions: list[Instruction]

    @property
    def extracted_length(self) -> int:
        return sum(instruction.length for instruction in self.extracted_instructions)


@dataclass(eq=False)
class _BlockLayout:
    """A source block after regeneration."""

    block: BasicBlock
    instructions: list[Instruction]
    start_address: int


@dataclass(eq=False)
class _FunctionLayout:
    """A function after all selected replacements were applied."""

    function: Function
    blocks: list[_BlockLayout]
    new_end: int
    old_to_new: dict[int, Instruction]


@dataclass(frozen=True)
class _CachedLayout:
    replacements: tuple[_BlockReplacement, ...]
    layout: _FunctionLayout


@dataclass(eq=False)
class _Placement:
    """A shared target block placed in free space."""

    plan: _ReplacementPlan
    block: BasicBlock
    patches: list[tuple[_BlockLayout, int, Instruction]]
    free_space: list[FreeSpace]


def run_optimizer(
    binary: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
    free_space: list[FreeSpace],
    *, protected_entries: frozenset[int] = frozenset(),
    warn: Callable[[str], None] | None = None,
) -> ExtractionResult | None:
    """Extract repeated regions and relink them into free space."""
    result = extract_instruction_regions(binary, uplifter, isa, protected_entries=protected_entries, warn=warn)
    if result is None:
        return None

    if (
        not result.extracted_instructions
        or not result.basic_blocks_to_regenerate
    ):
        return result

    result = relink_in_instructions(
        binary, uplifter, isa, result, free_space
    )
    if not result.selected_matches:
        LOGGER.info("outliner could not place any shared block")
        return result

    free_space[:] = result.free_space
    result.free_space = free_space
    LOGGER.info(
        "outliner selected %d of %d match(es)",
        len(result.selected_matches),
        len(result.matches),
    )
    return result


def extract_instruction_regions(
    binary: "Binary", uplifter: "Uplifter", isa: "ISA", *,
    protected_entries: frozenset[int] = frozenset(),
    warn: Callable[[str], None] | None = None,
) -> ExtractionResult | None:
    """Find profitable matches and regenerate the functions they touch."""
    if not isa.supports_outlining:
        (warn or LOGGER.warning)(f"ISA {isa.name or '<unknown>'} does not support function outlining")
        return None

    cache: dict[int, bytes | None] = {}
    functions = [
        function for function in _eligible_functions(uplifter, isa)
        if function.start_address not in protected_entries
    ]
    index = _build_instruction_index(functions, isa, cache)
    result = ExtractionResult()
    seen: set[tuple[frozenset[int], frozenset[bytes]]] = set()

    for function in functions:
        for block in function.basic_blocks:
            if block.used_for_outlining:
                continue

            for match in find_basic_block_matches(block, index, isa, cache):
                signature = (
                    frozenset(id(match_block) for match_block in match.blocks),
                    match.encodings,
                )
                if signature in seen:
                    continue
                seen.add(signature)
                result.matches.append(match)

    result.matches.sort(key=_match_sort_key)
    if not result.matches:
        LOGGER.info("outliner found no profitable basic-block matches")
        return result

    selected = _select_plans(result.matches, isa, index)
    if not selected:
        LOGGER.info("outliner could not build a replacement plan")
        return result

    selected, layouts = _layout_selected(selected, isa)
    if not selected or layouts is None:
        return result

    result.plans = selected
    result.layouts = layouts
    result.selected_matches = [plan.match for plan in selected]
    result.free_space = _collect_free_space(layouts)
    result.extracted_instructions = [plan.extracted for plan in selected]
    result.extracted_basic_blocks = [
        replacement.original
        for plan in selected
        for replacement in plan.replacements
    ]
    result.basic_blocks_to_regenerate = _basic_blocks_to_regenerate(
        layouts, selected
    )
    return result


def _layout_selected(
    selected: list[_ReplacementPlan], isa: "ISA",
    cache: dict[int, _CachedLayout] | None = None,
) -> tuple[list[_ReplacementPlan], dict[int, _FunctionLayout] | None]:
    """Regenerate functions until every remaining plan can be applied."""
    if cache is None:
        cache = {}
    while selected:
        layouts, failed_function = _layout_functions(selected, isa, cache)
        if layouts is not None:
            return selected, layouts
        selected = _drop_failed_function(selected, failed_function)
    return [], None


def _drop_failed_function(
    selected: list[_ReplacementPlan], failed_function: Function | None
) -> list[_ReplacementPlan]:
    if failed_function is None:
        dropped = selected.pop()
        LOGGER.debug(
            "dropping outline match at %#x: regeneration failed",
            dropped.match.blocks[0].start_location.value,
        )
        return selected
    before = len(selected)
    remaining = [
        plan
        for plan in selected
        if not any(
            replacement.original.containing_function is failed_function
            for replacement in plan.replacements
        )
    ]
    if len(remaining) == before:
        remaining.pop()
    LOGGER.debug(
        "dropping outline matches in %s: regeneration failed",
        failed_function.name,
    )
    return remaining


def _basic_blocks_to_regenerate(
    layouts: dict[int, _FunctionLayout],
    plans: list[_ReplacementPlan],
) -> list[tuple[BasicBlock, BasicBlock]]:
    modified_ids = _modified_block_ids(plans)
    return [
        (layout_block.block, _clone_block(layout_block))
        for layout in layouts.values()
        for layout_block in layout.blocks
        if id(layout_block.block) in modified_ids
    ]


def relink_in_instructions(
    binary: "Binary",
    uplifter: "Uplifter",
    isa: "ISA",
    result: ExtractionResult,
    free_space: list[FreeSpace],
) -> ExtractionResult:
    """Place extracted blocks in free space and rewrite live code."""
    selected = result.plans
    layouts = result.layouts
    layout_cache: dict[int, _CachedLayout] = {}

    while selected:
        ranges = list(free_space) + _collect_free_space(layouts)
        placements, failed = _place_targets(
            selected, layouts, ranges, isa
        )
        if failed is None:
            _apply_placements(placements)
            _finalize_layouts(layouts)
            _finalize_extracted_blocks(placements)
            _write_layouts(binary, layouts, placements)
            _update_incoming_references(uplifter, layouts)
            _commit_layouts(layouts, selected)

            result.plans = selected
            result.selected_matches = [plan.match for plan in selected]
            result.extracted_instructions = [
                placement.block for placement in placements
            ]
            result.extracted_basic_blocks = [
                replacement.original
                for plan in selected
                for replacement in plan.replacements
            ]
            result.modified_ranges = _modified_ranges(layouts, placements)
            result.basic_blocks_to_regenerate = _basic_blocks_to_regenerate(
                layouts, selected
            )
            if placements:
                ranges = placements[-1].free_space
            result.free_space = ranges
            return result

        selected = [plan for plan in selected if plan is not failed]
        LOGGER.debug(
            "dropping outline match at %#x. Could not place its %d-byte shared block and return within reach of all %d call sites",
            failed.match.blocks[0].start_location.value,
            failed.extracted_length + isa.ret_instruction_length(),
            failed.match.block_count,
        )
        if not selected:
            break
        selected, layouts = _layout_selected(selected, isa, layout_cache)
        if layouts is None:
            break
        result.plans = selected
        result.layouts = layouts

    result.plans = []
    result.layouts = {}
    result.selected_matches = []
    result.extracted_instructions = []
    result.extracted_basic_blocks = []
    result.modified_ranges = []
    result.basic_blocks_to_regenerate = []
    result.free_space = list(free_space)
    return result


def find_basic_block_matches(
    block: BasicBlock,
    instruction_index: _InstructionIndex,
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> list[BasicBlockMatch]:
    """Return the most profitable sets of blocks that could share instructions.

    Instructions are compared by their position-invariant encoding.  A match
    groups blocks whose set of instructions in common with ``block`` is
    identical, and is kept only when the estimated saving is positive.
    """
    call_length = isa.call_instruction_length()
    ret_length = isa.ret_instruction_length()

    position = instruction_index.positions.get(id(block))
    outlinable = (
        _first_by_encoding(block, isa, cache)
        if position is None
        else instruction_index.instructions[position]
    )
    postings = instruction_index.postings
    lengths = instruction_index.lengths
    encodings_with_postings = [encoding for encoding in outlinable if encoding in postings]
    remaining = sum(lengths[encoding] for encoding in encodings_with_postings)
    candidates: set[int] = set()
    # Any profitable group must share more bytes than the call costs. Once
    # the unvisited encodings fit in that budget, they cannot introduce a
    # profitable candidate. Visit rare encodings first to keep the union small.
    for encoding in sorted(encodings_with_postings, key=lambda key: len(postings[key])):
        if remaining <= call_length:
            break
        candidates.update(postings[encoding])
        remaining -= lengths[encoding]

    anchor_encodings = (
        frozenset(outlinable) if position is None
        else instruction_index.signatures[instruction_index.block_signatures[position]]
    )
    groups: dict[frozenset[bytes], list[int]] = {}
    for signature in candidates:
        common = anchor_encodings & instruction_index.signatures[signature]
        groups.setdefault(common, []).append(signature)

    encoding_order = {encoding: offset for offset, encoding in enumerate(outlinable)}
    matches: list[tuple[BasicBlockMatch, int, int]] = []
    for encodings, signatures in groups.items():
        common_length = sum(lengths[encoding] for encoding in encodings)
        if common_length <= call_length:
            continue
        block_groups = [instruction_index.signature_blocks[signature] for signature in signatures]
        # The anchor is already part of its own full intersection.
        includes_anchor = position is not None and encodings == anchor_encodings
        sites = sum(map(len, block_groups)) + (0 if includes_anchor else 1)
        estimated_savings = _outline_savings(common_length, sites, call_length, ret_length)
        if sites < 2 or estimated_savings <= 0:
            continue
        positions = [other for group in block_groups for other in group if other != position]

        # The former visitation order was the first common encoding in the
        # anchor followed by the block's index position. Keep it for ties.
        sources = [instruction_index.blocks[other] for other in sorted(positions)]
        sources.append(block)
        common_instructions = tuple(
            instruction
            for encoding, instruction in outlinable.items()
            if encoding in encodings
        )
        match = BasicBlockMatch(
            blocks=tuple(sorted(sources, key=_block_sort_key)),
            common_instructions=common_instructions,
            encodings=encodings,
            common_length=common_length,
            estimated_savings=estimated_savings,
        )
        first_encoding = min(encoding_order[encoding] for encoding in encodings)
        matches.append((match, first_encoding, min(positions)))

    matches.sort(key=lambda item: (_match_sort_key(item[0]), item[1], item[2]))
    return [match for match, _, _ in matches[:_MAX_MATCHES_PER_BLOCK]]


def _outline_savings(length: int, sites: int, call_length: int, ret_length: int) -> int:
    return (length - call_length) * sites - (length + ret_length)


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


def try_generate_replacement_bytes(
    match: BasicBlockMatch,
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
    *,
    index: _InstructionIndex | None = None,
    find_window: Callable[[BasicBlock, tuple[bytes, ...]], _OutlineWindow | None] | None = None,
) -> _ReplacementPlan | None:
    """Try each viable instruction order while preserving template priority."""
    call_length = isa.call_instruction_length()
    ret_length = isa.ret_instruction_length()
    per_site_savings = match.common_length - call_length
    if not match.encodings or per_site_savings <= 0:
        return None
    minimum_sites = (match.common_length + ret_length) // per_site_savings + 1
    by_order: dict[tuple[bytes, ...], list[BasicBlock]] = {}
    by_block: dict[int, tuple[bytes, ...]] = {}
    encodings_by_block: dict[int, dict[bytes, Instruction]] = {}
    for block in match.blocks:
        encodings = (
            _first_by_encoding(block, isa, cache)
            if index is None
            else index.instructions[index.positions[id(block)]]
        )
        order = tuple(encoding for encoding in encodings if encoding in match.encodings)
        if len(order) == len(match.encodings):
            by_order.setdefault(order, []).append(block)
            by_block[id(block)] = order
            encodings_by_block[id(block)] = encodings

    # Reordering can move intervening instructions but never swaps two
    # selected instructions. Each block can therefore participate in only
    # one order, regardless of which site supplies the shared body.
    prepared: dict[tuple[bytes, ...], dict[int, _OutlineWindow]] = {}
    for template in match.blocks:
        template_id = id(template)
        order = by_block.get(template_id)
        if order is None:
            continue
        if order not in prepared:
            sites: dict[int, _OutlineWindow] = {}
            if len(by_order[order]) >= minimum_sites:
                for block in by_order[order]:
                    if find_window is None:
                        encodings = encodings_by_block[id(block)]
                        window = _outline_window(block, [encodings[key] for key in order], isa)
                    else:
                        window = find_window(block, order)
                    if window is not None:
                        sites[id(block)] = window
            if len(sites) < minimum_sites:
                sites.clear()
            prepared[order] = sites

        sites = prepared[order]
        window = sites.get(template_id)
        if window is None:
            continue
        adjusted = _adjust_shared_instructions(window.selected, isa)
        if adjusted is None:
            continue

        shared = _placeholder_block()
        replacements = [_make_replacement(template, window, shared, isa)]
        replacements.extend(
            _make_replacement(block, sites[id(block)], shared, isa)
            for block in by_order[order] if block is not template and id(block) in sites
        )
        filtered_match = replace(
            match,
            blocks=tuple(replacement.original for replacement in replacements),
            estimated_savings=_outline_savings(
                match.common_length, len(replacements), call_length, ret_length,
            ),
        )
        return _ReplacementPlan(filtered_match, replacements, shared, adjusted)
    return None


def find_indices(
    basic_block: BasicBlock,
    instructions_to_find: list[Instruction] | tuple[Instruction, ...],
) -> list[int]:
    """Return the indices of the given instruction objects in ``basic_block``."""
    return [
        index
        for index, instruction in enumerate(basic_block.instructions)
        if any(instruction is target for target in instructions_to_find)
    ]


def convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
    basic_block: BasicBlock,
    instructions_to_move: list[Instruction],
    target_instruction_order: list[Instruction],
    isa: "ISA | None" = None,
) -> tuple[BasicBlock, int] | None:
    """Move the selected subsequence together without crossing dependencies."""
    target_ids = [id(instruction) for instruction in target_instruction_order]
    targets = set(target_ids)
    if not target_ids or len(targets) != len(target_ids):
        return None
    if {id(instruction) for instruction in instructions_to_move} != targets:
        return None

    items = basic_block.instructions
    indices = [index for index, item in enumerate(items) if id(item) in targets]
    if [id(items[index]) for index in indices] != target_ids:
        return None
    reordered = _reorder_window(items, indices, target_instruction_order, isa)
    if reordered is None:
        return None
    if reordered is items:
        reordered = items.copy()
    return _clone_block_with_instructions(basic_block, reordered), indices[0]


def _reorder_window(
    items: list[Instruction], indices: list[int], selected: list[Instruction], isa: ISA | None,
) -> list[Instruction] | None:
    first, last = indices[0], indices[-1]
    if last - first + 1 == len(selected):
        return items
    targets = set(indices)
    gaps: list[Instruction] = []
    gap_writes: set[StateSpace] = set()
    gap_reads: set[StateSpace] = set()
    # Every gap stays after the selected subsequence, so a later selected
    # instruction must be able to cross every gap seen up to that point.
    for index in range(first + 1, last + 1):
        instruction = items[index]
        if index in targets:
            if gaps and (
                not _can_reorder(instruction, isa)
                or not gap_writes.isdisjoint(instruction.depends_on)
                or not gap_writes.isdisjoint(instruction.modifies)
                or not gap_reads.isdisjoint(instruction.modifies)
            ):
                return None
        else:
            if not _can_reorder(instruction, isa):
                return None
            gaps.append(instruction)
            gap_writes.update(instruction.modifies)
            gap_reads.update(instruction.depends_on)

    return items[:first] + selected + gaps + items[last + 1:]


def _can_reorder(instruction: Instruction, isa: "ISA | None") -> bool:
    return not _is_non_fallthrough(instruction) and (
        isa is None or isa.can_reorder_across(instruction)
    )


def can_swap_instruction(
    group_to_move: list[Instruction], to_swap_with: Instruction,
    isa: "ISA | None" = None,
) -> bool:
    """Return whether two instruction groups can be reordered safely."""
    if not _can_reorder(to_swap_with, isa) or any(
        not _can_reorder(instruction, isa) for instruction in group_to_move
    ):
        return False

    group_modifies = _state_set(group_to_move, modifies=True)
    group_depends = _state_set(group_to_move, modifies=False)
    other_modifies = set(to_swap_with.modifies)
    other_depends = set(to_swap_with.depends_on)

    if group_modifies & other_depends:
        return False
    if other_modifies & group_depends:
        return False
    if group_modifies & other_modifies:
        return False
    return True


def _select_plans(
    matches: list[BasicBlockMatch],
    isa: "ISA",
    index: _InstructionIndex,
) -> list[_ReplacementPlan]:
    """Choose non-overlapping matches and build their replacement plans."""
    @lru_cache(maxsize=4096)
    def instruction_positions(position: int) -> dict[int, int]:
        return {id(item): offset for offset, item in enumerate(index.blocks[position].instructions)}

    @lru_cache(maxsize=_OUTLINE_WINDOW_CACHE_SIZE)
    def cached_window(position: int, order: tuple[bytes, ...]) -> _OutlineWindow | None:
        encodings = index.instructions[position]
        return _outline_window(
            index.blocks[position], [encodings[key] for key in order], isa,
            positions=instruction_positions(position),
        )

    def find_window(block: BasicBlock, order: tuple[bytes, ...]) -> _OutlineWindow | None:
        return cached_window(index.positions[id(block)], order)

    selected: list[_ReplacementPlan] = []
    deferred: list[_ReplacementPlan] = []
    used: set[int] = set()
    for match in matches:
        if any(id(block) in used for block in match.blocks):
            continue
        plan = try_generate_replacement_bytes(match, isa, index=index, find_window=find_window)
        if plan is None:
            continue
        if len(plan.match.blocks) < len(match.blocks):
            # Some source sites could not participate.  Let full matches
            # claim their blocks first, then select the remainder.
            deferred.append(plan)
            continue
        selected.append(plan)
        used.update(id(block) for block in plan.match.blocks)

    deferred.sort(key=lambda plan: plan.match.estimated_savings, reverse=True)
    for plan in deferred:
        if any(id(block) in used for block in plan.match.blocks):
            continue
        selected.append(plan)
        used.update(id(block) for block in plan.match.blocks)
    return selected


def _outline_window(
    block: BasicBlock, selected: list[Instruction], isa: "ISA",
    *, positions: dict[int, int] | None = None,
) -> _OutlineWindow | None:
    function = block.containing_function
    if function is None:
        return None
    if positions is None:
        converted = convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
            block, selected, selected, isa,
        )
        if converted is None:
            return None
        reordered, start = converted
        instructions = reordered.instructions
    else:
        # The indexed order is the order in which these instructions already
        # appear in the block. Only the intervening instructions can move.
        indices = [positions[id(item)] for item in selected]
        start = indices[0]
        instructions = _reorder_window(block.instructions, indices, selected, isa)
        if instructions is None:
            return None
    if not isa.can_outline_region(function, block, instructions, start, len(selected)):
        return None
    return _OutlineWindow(instructions, start, selected)


def _make_replacement(
    block: BasicBlock, window: _OutlineWindow, shared: BasicBlock, isa: "ISA",
) -> _BlockReplacement:
    start, selected = window.start, window.selected
    call = isa.make_call_instruction()
    call.outline_target = shared
    instructions = (
        window.instructions[:start]
        + [call]
        + window.instructions[start + len(selected):]
    )
    return _BlockReplacement(
        original=block,
        instructions=instructions,
        call=call,
        window_start=start,
        removed_addresses=tuple(instruction.address for instruction in selected),
        replaced_first_address=selected[0].address,
    )


def _adjust_shared_instructions(
    instructions: list[Instruction], isa: "ISA",
) -> list[Instruction] | None:
    adjusted: list[Instruction] = []
    for instruction in instructions:
        try:
            moved = isa.add_extra_stack_space(instruction, isa.pointer_size)
        except ValueError:
            return None
        if moved.length != instruction.length:
            return None
        adjusted.append(moved)
    return adjusted


def _layout_functions(
    plans: list[_ReplacementPlan], isa: "ISA", cache: dict[int, _CachedLayout],
) -> tuple[dict[int, _FunctionLayout] | None, Function | None]:
    functions: dict[int, tuple[Function, dict[int, _BlockReplacement]]] = {}
    for plan in plans:
        for replacement in plan.replacements:
            function = replacement.original.containing_function
            if function is None:
                return None, None
            function_id = id(function)
            if function_id not in functions:
                functions[function_id] = function, {}
            functions[function_id][1][id(replacement.original)] = replacement

    for function_id in cache.keys() - functions.keys():
        del cache[function_id]

    layouts: dict[int, _FunctionLayout] = {}
    for function_id, (function, replacements) in functions.items():
        # Dropping a plan affects only the functions containing its sites.
        signature = tuple(replacements.values())
        cached = cache.get(function_id)
        if cached is not None and cached.replacements == signature:
            layouts[function_id] = cached.layout
            continue
        layout = _layout_function(function, replacements, isa)
        if layout is None:
            LOGGER.debug(
                "outliner cannot regenerate function %s", function.name
            )
            return None, function
        cache[function_id] = _CachedLayout(signature, layout)
        layouts[function_id] = layout
    return layouts, None


def _layout_function(
    function: Function,
    replacements: dict[int, _BlockReplacement],
    isa: "ISA",
) -> _FunctionLayout | None:
    layouts: list[_BlockLayout] = []
    old_to_new: dict[int, Instruction] = {}
    positions: dict[int, tuple[_BlockLayout, int]] = {}
    pairs: list[tuple[Instruction, Instruction]] = []
    removed: set[int] = set()
    address = function.start_address

    for block in function.basic_blocks:
        replacement = replacements.get(id(block))
        items = (
            replacement.instructions
            if replacement is not None
            else block.instructions
        )
        start = address
        instructions: list[Instruction] = []
        for instruction in items:
            if instruction.type is InstructionType.OUTLINE_RESULT_CALL:
                new_instruction = replace(
                    instruction,
                    address=address,
                    flows_from=[],
                    flows_to=[],
                )
                if (
                    replacement is not None
                    and instruction is replacement.call
                ):
                    old_to_new[replacement.replaced_first_address] = (
                        new_instruction
                    )
            else:
                try:
                    new_instruction = _relocate(isa, instruction, address)
                except ValueError:
                    LOGGER.debug(
                        "outliner cannot relocate %s at %#x to %#x",
                        instruction.original_data.hex(),
                        instruction.address,
                        address,
                    )
                    return None
                if new_instruction.length != instruction.length:
                    LOGGER.debug(
                        "outliner relocation changes length for %s at %#x",
                        instruction.original_data.hex(),
                        instruction.address,
                    )
                    return None
                old_to_new[instruction.address] = new_instruction
                pairs.append((instruction, new_instruction))
            instructions.append(new_instruction)
            address += new_instruction.length

        block_layout = _BlockLayout(
            block=block, instructions=instructions, start_address=start
        )
        layouts.append(block_layout)
        for index, instruction in enumerate(instructions):
            positions[id(instruction)] = (block_layout, index)

        if replacement is not None:
            removed.update(replacement.removed_addresses)

    for old_instruction, new_instruction in pairs:
        if old_instruction.type not in (
            InstructionType.BRANCH,
            InstructionType.CALL,
        ):
            continue
        if not old_instruction.flows_to:
            continue
        target = old_instruction.flows_to[0]
        if target.kind is not AddressKind.ABSOLUTE:
            continue

        new_target = old_to_new.get(target.value)
        if new_target is None:
            if target.value in removed:
                # A branch into the middle of an outlined window cannot be
                # preserved by replacing the window with one call.
                LOGGER.debug(
                    "outliner branch at %#x targets removed %#x",
                    old_instruction.address,
                    target.value,
                )
                return None
            continue

        try:
            patched = isa.set_instruction_target(
                new_instruction, Address.absolute(new_target.address)
            )
        except ValueError:
            LOGGER.debug(
                "outliner cannot retarget %s at %#x from %#x to %#x",
                old_instruction.original_data.hex(),
                old_instruction.address,
                target.value,
                new_target.address,
            )
            return None
        block_layout, index = positions[id(new_instruction)]
        block_layout.instructions[index] = patched

    new_end = address
    if new_end > function.start_address + function.length:
        LOGGER.debug(
            "outliner grows function %s from %#x to %#x bytes",
            function.name,
            function.length,
            new_end - function.start_address,
        )
        return None
    return _FunctionLayout(
        function=function,
        blocks=layouts,
        new_end=new_end,
        old_to_new=old_to_new,
    )


def _modified_ranges(
    layouts: dict[int, _FunctionLayout],
    placements: list[_Placement],
) -> list[FreeSpace]:
    """Return the live code ranges rewritten by outlining."""
    ranges: list[FreeSpace] = []
    for layout in layouts.values():
        size = layout.new_end - layout.function.start_address
        if size > 0:
            ranges.append(
                FreeSpace(
                    Address.absolute(layout.function.start_address),
                    size,
                    f"outlined function {layout.function.name}",
                )
            )
    for placement in placements:
        size = sum(
            instruction.length
            for instruction in placement.block.instructions
        )
        if size > 0:
            ranges.append(
                FreeSpace(
                    placement.block.start_location,
                    size,
                    "outlined shared block",
                )
            )
    ranges.sort(key=lambda item: item.start.value)
    return ranges


def _collect_free_space(
    layouts: dict[int, _FunctionLayout],
) -> list[FreeSpace]:
    """Return the tails freed by regenerating the laid-out functions."""
    ranges: list[FreeSpace] = []
    for layout in layouts.values():
        old_end = layout.function.start_address + layout.function.length
        if layout.new_end < old_end:
            ranges.append(
                FreeSpace(
                    start=Address.absolute(layout.new_end),
                    size=old_end - layout.new_end,
                    diagnostic=(
                        f"outlined function {layout.function.name}"
                    ),
                )
            )
    return ranges


def _place_targets(
    plans: list[_ReplacementPlan],
    layouts: dict[int, _FunctionLayout],
    free_space: list[FreeSpace],
    isa: "ISA",
) -> tuple[list[_Placement], _ReplacementPlan | None]:
    call_sites = _call_sites(layouts)
    placements: list[_Placement] = []
    ranges = list(free_space)

    for plan in sorted(
        plans, key=lambda item: item.extracted_length, reverse=True
    ):
        placement = _try_place(
            plan, call_sites.get(id(plan.extracted), []), ranges, isa
        )
        if placement is None:
            return placements, plan
        placements.append(placement)
        ranges = placement.free_space

    return placements, None


def _try_place(
    plan: _ReplacementPlan,
    call_sites: list[tuple[_BlockLayout, int, Instruction]],
    free_space: list[FreeSpace],
    isa: "ISA",
) -> _Placement | None:
    if not call_sites:
        return None

    # A candidate must be reachable from both endpoints before the encoder
    # checks all of the sites and relocates the shared body.
    first = min(call_sites, key=lambda site: site[2].address)
    last = max(call_sites, key=lambda site: site[2].address)
    bounds = isa.outline_call_target_bounds(first[2].address, last[2].address)
    if bounds is not None and bounds[0] > bounds[1]:
        return None
    checks = [first]
    if last is not first:
        checks.append(last)
    checks.extend(site for site in call_sites if site is not first and site is not last)

    needed = plan.extracted_length + isa.ret_instruction_length()
    candidates: list[tuple[int, int, int]] = []
    for index, free in enumerate(free_space):
        if free.size < needed:
            continue
        start = free.start.value
        end_start = start + free.size - needed
        if bounds is None or bounds[0] <= start <= bounds[1]:
            candidates.append((free.size, start, index))
        if end_start != start and (bounds is None or bounds[0] <= end_start <= bounds[1]):
            candidates.append((free.size, end_start, index))
    candidates.sort(key=lambda item: (item[0], item[1]))

    for _, address, index in candidates:
        destination = Address.absolute(address)
        patches: list[tuple[_BlockLayout, int, Instruction]] = []
        try:
            for block_layout, position, call in checks:
                patched = isa.set_instruction_target(call, destination)
                patches.append((block_layout, position, patched))
        except ValueError:
            continue

        relocated: list[Instruction] = []
        current = address
        failed = False
        for instruction in plan.extracted_instructions:
            try:
                new_instruction = _relocate(isa, instruction, current)
            except ValueError:
                failed = True
                break
            if new_instruction.length != instruction.length:
                failed = True
                break
            relocated.append(new_instruction)
            current += new_instruction.length
        if failed:
            continue

        return_instruction = isa.make_return_instruction()
        return_instruction.address = current
        relocated.append(return_instruction)
        current += return_instruction.length
        if current - address != needed:
            continue

        target = BasicBlock(
            start_location=Address.absolute(address),
            containing_function=None,
            instructions=relocated,
        )
        patches = [
            (block_layout, position, replace(patched, outline_target=target))
            for block_layout, position, patched in patches
        ]
        return _Placement(
            plan=plan,
            block=target,
            patches=patches,
            free_space=_reserve_range(free_space, index, address, needed),
        )
    return None


def _reserve_range(
    free_space: list[FreeSpace], index: int, address: int, size: int
) -> list[FreeSpace]:
    ranges = list(free_space)
    free = ranges.pop(index)
    start = free.start.value
    end = start + free.size
    if address > start:
        ranges.append(
            FreeSpace(
                Address.absolute(start), address - start, free.diagnostic
            )
        )
    if address + size < end:
        ranges.append(
            FreeSpace(
                Address.absolute(address + size),
                end - (address + size),
                free.diagnostic,
            )
        )
    return ranges


def _call_sites(
    layouts: dict[int, _FunctionLayout],
) -> dict[int, list[tuple[_BlockLayout, int, Instruction]]]:
    sites: dict[int, list[tuple[_BlockLayout, int, Instruction]]] = {}
    for layout in layouts.values():
        for block_layout in layout.blocks:
            for index, instruction in enumerate(block_layout.instructions):
                if instruction.type is not InstructionType.OUTLINE_RESULT_CALL:
                    continue
                if instruction.outline_target is None:
                    continue
                sites.setdefault(id(instruction.outline_target), []).append(
                    (block_layout, index, instruction)
                )
    return sites


def _apply_placements(placements: list[_Placement]) -> None:
    for placement in placements:
        for block_layout, index, patched in placement.patches:
            block_layout.instructions[index] = patched


def _finalize_layouts(layouts: dict[int, _FunctionLayout]) -> None:
    for layout in layouts.values():
        instructions = [
            instruction
            for block_layout in layout.blocks
            for instruction in block_layout.instructions
        ]
        by_address = {
            instruction.address: instruction for instruction in instructions
        }
        for instruction in instructions:
            instruction.flows_from = []

        outgoing: list[Reference] = []
        for instruction in instructions:
            source = Address.absolute(instruction.address)
            for target in instruction.flows_to:
                if (
                    target.kind is AddressKind.ABSOLUTE
                    and target.value in by_address
                ):
                    target_instruction = by_address[target.value]
                    if source not in target_instruction.flows_from:
                        target_instruction.flows_from.append(source)
                else:
                    reference = Reference(source, target)
                    if reference not in outgoing:
                        outgoing.append(reference)
        layout.function.outgoing_references = outgoing


def _finalize_extracted_blocks(
    placements: list[_Placement],
) -> None:
    for placement in placements:
        block = placement.block
        by_address = {
            instruction.address: instruction for instruction in block.instructions
        }
        for instruction in block.instructions:
            instruction.flows_from = []
        for instruction in block.instructions:
            source = Address.absolute(instruction.address)
            for target in instruction.flows_to:
                if (
                    target.kind is AddressKind.ABSOLUTE
                    and target.value in by_address
                ):
                    target_instruction = by_address[target.value]
                    if source not in target_instruction.flows_from:
                        target_instruction.flows_from.append(source)

        if not block.instructions:
            continue
        first = block.instructions[0]
        for _, _, call in placement.patches:
            source = Address.absolute(call.address)
            if source not in first.flows_from:
                first.flows_from.append(source)


def _write_layouts(
    binary: "Binary",
    layouts: dict[int, _FunctionLayout],
    placements: list[_Placement],
) -> None:
    for layout in layouts.values():
        for block_layout in layout.blocks:
            data = b"".join(
                instruction.original_data
                for instruction in block_layout.instructions
            )
            binary.write(block_layout.start_address, data)

    for placement in placements:
        data = b"".join(
            instruction.original_data
            for instruction in placement.block.instructions
        )
        binary.write(placement.block.start_location.value, data)


def _update_incoming_references(
    uplifter: "Uplifter", layouts: dict[int, _FunctionLayout]
) -> None:
    old_to_new_address: dict[int, int] = {}
    for layout in layouts.values():
        for old_address, new_instruction in layout.old_to_new.items():
            old_to_new_address[old_address] = new_instruction.address

    if not old_to_new_address:
        return

    for function in uplifter.function_map.values():
        updated: list[Reference] = []
        for reference in function.incoming_references:
            if (
                reference.from_.kind is AddressKind.ABSOLUTE
                and reference.from_.value in old_to_new_address
            ):
                updated.append(
                    Reference(
                        Address.absolute(
                            old_to_new_address[reference.from_.value]
                        ),
                        reference.to,
                    )
                )
            else:
                updated.append(reference)
        function.incoming_references = updated


def _commit_layouts(
    layouts: dict[int, _FunctionLayout],
    plans: list[_ReplacementPlan],
) -> None:
    for layout in layouts.values():
        for block_layout in layout.blocks:
            block_layout.block.instructions = block_layout.instructions
            block_layout.block.start_location = Address.absolute(
                block_layout.start_address
            )
    for plan in plans:
        for replacement in plan.replacements:
            replacement.original.used_for_outlining = True


def _clone_block(block_layout: _BlockLayout) -> BasicBlock:
    return BasicBlock(
        start_location=Address.absolute(block_layout.start_address),
        containing_function=block_layout.block.containing_function,
        instructions=list(block_layout.instructions),
        used_for_outlining=True,
    )


def _modified_block_ids(plans: list[_ReplacementPlan]) -> set[int]:
    return {
        id(replacement.original)
        for plan in plans
        for replacement in plan.replacements
    }


def _build_instruction_index(
    functions: list[Function],
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> _InstructionIndex:
    """Index every outlinable instruction by its position-invariant encoding."""
    index = _InstructionIndex()
    signature_ids: dict[frozenset[bytes], int] = {}
    for function in functions:
        for block in function.basic_blocks:
            position = len(index.blocks)
            index.positions[id(block)] = position
            index.blocks.append(block)
            instructions = _first_by_encoding(block, isa, cache)
            index.instructions.append(instructions)
            signature = frozenset(instructions)
            signature_id = signature_ids.get(signature)
            if signature_id is None:
                signature_id = len(index.signatures)
                signature_ids[signature] = signature_id
                index.signatures.append(signature)
                index.signature_blocks.append([])
                for encoding, instruction in instructions.items():
                    index.postings.setdefault(encoding, set()).add(signature_id)
                    index.lengths.setdefault(encoding, instruction.length)
            index.block_signatures.append(signature_id)
            index.signature_blocks[signature_id].append(position)
    return index


def _first_by_encoding(
    block: BasicBlock, isa: "ISA", cache: dict[int, bytes | None] | None,
) -> dict[bytes, Instruction]:
    encodings: dict[bytes, Instruction] = {}
    for instruction in block.instructions:
        encoding = _outlinable_encoding(isa, instruction, cache)
        if encoding is not None:
            encodings.setdefault(encoding, instruction)
    return encodings


def _eligible_functions(
    uplifter: "Uplifter", isa: "ISA"
) -> list[Function]:
    functions: list[Function] = []
    for function in sorted(
        uplifter.function_map.values(), key=lambda item: item.start_address
    ):
        if function.has_unk_local_reference():
            continue
        if not _function_can_shrink(function):
            continue
        functions.append(function)
    return functions


def _function_can_shrink(function: Function) -> bool:
    """Return whether removing bytes cannot change an implicit fallthrough."""
    if not function.basic_blocks:
        return False
    last_block = function.basic_blocks[-1]
    if not last_block.instructions:
        return False
    last = last_block.instructions[-1]
    if last.type is InstructionType.RET:
        return True
    if last.type is InstructionType.BRANCH:
        for target in last.flows_to:
            if target.kind is not AddressKind.ABSOLUTE:
                return False
            if target.value == last.address + last.length:
                return False
        return True
    return False


def _outlinable_encoding(
    isa: "ISA",
    instruction: Instruction,
    cache: dict[int, bytes | None] | None,
) -> bytes | None:
    """Return the position-invariant encoding if it can be outlined.

    The same instruction object is visited by the index, the match finder, and
    every replacement plan, so the cache keeps the expensive SLEIGH resolution
    to one call per instruction.
    """
    if cache is not None and id(instruction) in cache:
        return cache[id(instruction)]

    encoding = None
    if isa.is_outlinable(instruction):
        encoding = _canonical_encoding(isa, instruction)
    if cache is not None:
        cache[id(instruction)] = encoding
    return encoding


def _canonical_encoding(isa: "ISA", instruction: Instruction) -> bytes | None:
    """Return position-invariant bytes for ``instruction``, or ``None``."""
    try:
        relocated = _relocate(isa, instruction, _CANONICAL_ADDRESS)
    except ValueError:
        return None
    return relocated.original_data


def _relocate(isa: "ISA", instruction: Instruction, address: int) -> Instruction:
    if not isa.can_encode(instruction, address):
        raise ValueError(f"cannot encode instruction at {address:#x}")
    return isa.relocate_instruction(instruction, address)


def _placeholder_block() -> BasicBlock:
    return BasicBlock(start_location=Address.absolute(0))


def _clone_block_with_instructions(
    block: BasicBlock, instructions: list[Instruction]
) -> BasicBlock:
    return BasicBlock(
        start_location=block.start_location,
        containing_function=block.containing_function,
        instructions=instructions,
        used_for_outlining=block.used_for_outlining,
    )


def _is_non_fallthrough(instruction: Instruction) -> bool:
    return instruction.type in (
        InstructionType.BRANCH,
        InstructionType.RET,
    )


def _state_set(
    instructions: list[Instruction], *, modifies: bool
) -> set[StateSpace]:
    states: set[StateSpace] = set()
    for instruction in instructions:
        states.update(
            instruction.modifies if modifies else instruction.depends_on
        )
    return states


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
