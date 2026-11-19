"""Aggressive function outlining.

This pass finds repeated instruction regions, extracts them into a shared
target block, and replaces each source site with a call.  It must run after the
function remover.  Unwind information is intentionally out of scope for now.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field, replace
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
    """Position-invariant encodings mapped to the blocks containing them."""

    blocks: dict[bytes, dict[int, BasicBlock]] = field(default_factory=dict)
    lengths: dict[bytes, int] = field(default_factory=dict)


@dataclass(eq=False)
class _BlockReplacement:
    """A source block with its shared instructions replaced by a call."""

    original: BasicBlock
    instructions: list[Instruction]
    call: Instruction
    window_start: int
    removed_addresses: tuple[int, ...]
    replaced_first_address: int


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

    selected = _select_plans(result.matches, isa, cache)
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
    selected: list[_ReplacementPlan], isa: "ISA"
) -> tuple[list[_ReplacementPlan], dict[int, _FunctionLayout] | None]:
    """Regenerate functions until every remaining plan can be applied."""
    while selected:
        layouts, failed_function = _layout_functions(selected, isa)
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
            "dropping outline match at %#x: no room for shared block",
            failed.match.blocks[0].start_location.value,
        )
        if not selected:
            break
        selected, layouts = _layout_selected(selected, isa)
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

    outlinable: list[tuple[bytes, Instruction]] = []
    seen_encodings: set[bytes] = set()
    for instruction in block.instructions:
        encoding = _outlinable_encoding(isa, instruction, cache)
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
        blocks = tuple(sorted(blocks_by_id.values(), key=_block_sort_key))

        common_length = sum(
            instruction_index.lengths[encoding] for encoding in encodings
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


def try_generate_replacement_bytes(
    match: BasicBlockMatch,
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> _ReplacementPlan | None:
    """Try to reorder each block so the common instructions are contiguous."""
    for template in match.blocks:
        plan = _plan_for_template(match, template, isa, cache)
        if plan is not None:
            return plan
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
    """Reorder instructions while keeping the target instructions adjacent.

    Each target instruction after the first is moved toward the position
    immediately after its predecessor.  Non-target instructions are moved with
    the target as a group when they cannot be swapped individually, and are
    then moved to the far side of the target chain.
    """
    target_ids = [id(instruction) for instruction in target_instruction_order]
    if not target_ids or len(set(target_ids)) != len(target_ids):
        return None
    if {id(instruction) for instruction in instructions_to_move} != set(
        target_ids
    ):
        return None

    items = list(basic_block.instructions)
    target_id_set = set(target_ids)
    if any(_index_of(items, target_id) < 0 for target_id in target_ids):
        return None

    for position in range(1, len(target_ids)):
        previous_id = target_ids[position - 1]
        moved_id = target_ids[position]
        previous_index = _index_of(items, previous_id)
        moved_index = _index_of(items, moved_id)
        if previous_index < 0 or moved_index < 0:
            return None

        target_location = previous_index + 1
        if moved_index == target_location:
            continue

        group = [items[moved_index]]
        group_start = moved_index
        group_end = moved_index
        iterations = 0

        if moved_index > target_location:
            while group_start != target_location:
                iterations += 1
                if iterations > len(items) or group_start == 0:
                    return None
                neighbor = items[group_start - 1]
                if id(neighbor) in target_id_set:
                    return None
                if can_swap_instruction(group, neighbor, isa):
                    items[group_start - 1 : group_end + 1] = (
                        group + [neighbor]
                    )
                    group_start -= 1
                    group_end -= 1
                else:
                    group.insert(0, neighbor)
                    group_start -= 1

            # The target is at the end of the group; move the non-target
            # instructions to the far side so the target chain is adjacent.
            for index in range(len(group) - 1, 0, -1):
                if not can_swap_instruction(
                    [group[index]], group[index - 1], isa
                ):
                    return None
                group[index - 1], group[index] = (
                    group[index],
                    group[index - 1],
                )
            items[group_start : group_end + 1] = group
        else:
            while group_start != target_location:
                iterations += 1
                if iterations > len(items) or group_end + 1 >= len(items):
                    return None
                neighbor = items[group_end + 1]
                if id(neighbor) in target_id_set:
                    return None
                if can_swap_instruction(group, neighbor, isa):
                    items[group_start : group_end + 2] = [neighbor] + group
                    group_start += 1
                    group_end += 1
                else:
                    group.append(neighbor)
                    group_end += 1

    indices = [_index_of(items, target_id) for target_id in target_ids]
    if any(index < 0 for index in indices):
        return None
    if indices != list(range(indices[0], indices[0] + len(target_ids))):
        return None
    return _clone_block_with_instructions(basic_block, items), indices[0]


def can_swap_instruction(
    group_to_move: list[Instruction], to_swap_with: Instruction,
    isa: "ISA | None" = None,
) -> bool:
    """Return whether two instruction groups can be reordered safely."""
    if _is_non_fallthrough(to_swap_with):
        return False
    if any(_is_non_fallthrough(instruction) for instruction in group_to_move):
        return False
    if isa is not None and not all(
        isa.can_reorder_across(instruction)
        for instruction in (*group_to_move, to_swap_with)
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
    cache: dict[int, bytes | None] | None = None,
) -> list[_ReplacementPlan]:
    """Choose non-overlapping matches and build their replacement plans."""
    selected: list[_ReplacementPlan] = []
    deferred: list[_ReplacementPlan] = []
    used: set[int] = set()
    for match in matches:
        if any(id(block) in used for block in match.blocks):
            continue
        plan = try_generate_replacement_bytes(match, isa, cache)
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


def _plan_for_template(
    match: BasicBlockMatch,
    template: BasicBlock,
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> _ReplacementPlan | None:
    encoded_template = _encoded_instructions(template, isa, cache)
    target_order: list[bytes] = []
    seen: set[bytes] = set()
    for instruction, encoding in encoded_template:
        if encoding is None or encoding not in match.encodings:
            continue
        if encoding in seen:
            continue
        seen.add(encoding)
        target_order.append(encoding)
    if len(target_order) != len(match.encodings):
        return None

    replacements: list[_BlockReplacement] = []
    template_selection: list[Instruction] | None = None

    # Check the template first so an unusable shared block fails quickly, and
    # drop other sites that cannot participate instead of discarding the whole
    # match.  Plans with dropped sites are deferred by the selector so they do
    # not pre-empt a full match.
    ordered_blocks = (template,) + tuple(
        block for block in match.blocks if block is not template
    )
    for block in ordered_blocks:
        selected = _select_instructions(
            block.instructions, isa, target_order, cache
        )
        if selected is None:
            if block is template:
                return None
            continue
        if block is template:
            template_selection = selected

        source_indices = find_indices(block, selected)
        instructions_to_move = [
            block.instructions[index] for index in source_indices
        ]
        converted = convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance(
            block, instructions_to_move, selected, isa
        )
        if converted is None:
            if block is template:
                return None
            continue
        reordered, window_start = converted
        window_end = window_start + len(selected)
        window = reordered.instructions[window_start:window_end]
        if any(
            actual is not expected
            for actual, expected in zip(window, selected)
        ):
            if block is template:
                return None
            continue

        function = block.containing_function
        if function is None:
            if block is template:
                return None
            continue
        if not isa.can_outline_region(
            function,
            block,
            reordered.instructions,
            window_start,
            len(selected),
        ):
            if block is template:
                # The template supplies the shared block, so its own window
                # must be safe.  Try another block as the template.
                return None
            continue

        call = isa.make_call_instruction()
        call.outline_target = _placeholder_block()
        instructions = (
            reordered.instructions[:window_start]
            + [call]
            + reordered.instructions[window_end:]
        )
        replacements.append(
            _BlockReplacement(
                original=block,
                instructions=instructions,
                call=call,
                window_start=window_start,
                removed_addresses=tuple(
                    instruction.address for instruction in selected
                ),
                replaced_first_address=selected[0].address,
            )
        )

    if template_selection is None:
        return None

    safe_blocks = tuple(
        replacement.original for replacement in replacements
    )
    if len(safe_blocks) < 2:
        return None
    estimated_savings = (
        (match.common_length - isa.call_instruction_length())
        * len(safe_blocks)
        - (match.common_length + isa.ret_instruction_length())
    )
    if estimated_savings <= 0:
        return None
    filtered_match = replace(
        match, blocks=safe_blocks, estimated_savings=estimated_savings
    )

    adjusted: list[Instruction] = []
    for instruction in template_selection:
        try:
            adjusted_instruction = isa.add_extra_stack_space(
                instruction, isa.pointer_size
            )
        except ValueError:
            return None
        if adjusted_instruction.length != instruction.length:
            return None
        adjusted.append(adjusted_instruction)

    extracted = _placeholder_block()
    for replacement in replacements:
        replacement.call.outline_target = extracted

    return _ReplacementPlan(
        match=filtered_match,
        replacements=replacements,
        extracted=extracted,
        extracted_instructions=adjusted,
    )


def _select_instructions(
    instructions: list[Instruction],
    isa: "ISA",
    target_order: list[bytes],
    cache: dict[int, bytes | None] | None = None,
) -> list[Instruction] | None:
    """Return the first instruction for each encoding in ``target_order``."""
    by_encoding: dict[bytes, Instruction] = {}
    for instruction in instructions:
        encoding = _outlinable_encoding(isa, instruction, cache)
        if encoding is None or encoding in by_encoding:
            continue
        by_encoding[encoding] = instruction

    selected: list[Instruction] = []
    for encoding in target_order:
        instruction = by_encoding.get(encoding)
        if instruction is None:
            return None
        selected.append(instruction)
    return selected


def _layout_functions(
    plans: list[_ReplacementPlan], isa: "ISA"
) -> tuple[dict[int, _FunctionLayout] | None, Function | None]:
    replacements: dict[int, _BlockReplacement] = {}
    functions: dict[int, Function] = {}
    for plan in plans:
        for replacement in plan.replacements:
            replacements[id(replacement.original)] = replacement
            function = replacement.original.containing_function
            if function is None:
                return None, None
            functions[id(function)] = function

    layouts: dict[int, _FunctionLayout] = {}
    for function_id, function in functions.items():
        layout = _layout_function(function, replacements, isa)
        if layout is None:
            LOGGER.debug(
                "outliner cannot regenerate function %s", function.name
            )
            return None, function
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

    needed = plan.extracted_length + isa.ret_instruction_length()
    candidates: list[tuple[int, int, int]] = []
    for index, free in enumerate(free_space):
        if free.size < needed:
            continue
        start = free.start.value
        candidates.append((free.size, start, index))
        end_start = start + free.size - needed
        if end_start != start:
            candidates.append((free.size, end_start, index))
    candidates.sort(key=lambda item: (item[0], item[1]))

    for _, address, index in candidates:
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

        patches: list[tuple[_BlockLayout, int, Instruction]] = []
        for block_layout, position, call in call_sites:
            try:
                patched = isa.set_instruction_target(
                    call, Address.absolute(address)
                )
            except ValueError:
                failed = True
                break
            patches.append((block_layout, position, patched))
        if failed:
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
    for function in functions:
        for block in function.basic_blocks:
            for instruction in block.instructions:
                encoding = _outlinable_encoding(isa, instruction, cache)
                if encoding is None:
                    continue
                index.blocks.setdefault(encoding, {})[id(block)] = block
                index.lengths.setdefault(encoding, instruction.length)
    return index


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


def _encoded_instructions(
    block: BasicBlock,
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> list[tuple[Instruction, bytes | None]]:
    return _encoded_instructions_from_list(block.instructions, isa, cache)


def _encoded_instructions_from_list(
    instructions: list[Instruction],
    isa: "ISA",
    cache: dict[int, bytes | None] | None = None,
) -> list[tuple[Instruction, bytes | None]]:
    encoded: list[tuple[Instruction, bytes | None]] = []
    for instruction in instructions:
        encoded.append(
            (instruction, _outlinable_encoding(isa, instruction, cache))
        )
    return encoded


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


def _index_of(items: list[Instruction], instruction_id: int) -> int:
    for index, instruction in enumerate(items):
        if id(instruction) == instruction_id:
            return index
    return -1


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
