"""Tests for the outlining basic-block match finder."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from optimizers import function_remover, outliner
from test.uplift_sample import uplift_sample


@pytest.fixture(scope="module")
def match_sample():
    """Return the sample after xref recovery and outline matching."""
    parsed, binary, uplifter = uplift_sample()
    uplifter.build_xrefs()
    free_space = function_remover.run_optimizer(binary, uplifter, uplifter.isa)
    result = outliner.run_optimizer(binary, uplifter, uplifter.isa, free_space)
    assert result is not None
    return parsed, uplifter, result


def test_finds_profitable_matches(match_sample) -> None:
    _, uplifter, result = match_sample
    isa = uplifter.isa

    assert result.matches

    for match in result.matches:
        assert match.block_count >= 2
        assert match.common_length >= isa.call_instruction_length()
        assert match.estimated_savings > 0
        assert match.estimated_savings == (
            (match.common_length - isa.call_instruction_length())
            * match.block_count
            - match.common_length
            - isa.ret_instruction_length()
        )
        assert len({id(block) for block in match.blocks}) == match.block_count
        assert len(match.common_instructions) == len(match.encodings)
        assert all(
            isa.is_outlinable(instruction)
            for instruction in match.common_instructions
        )


def test_matches_are_sorted_by_estimated_savings(match_sample) -> None:
    _, _, result = match_sample

    savings = [match.estimated_savings for match in result.matches]

    assert savings == sorted(savings, reverse=True)


def test_finds_is_even_is_odd_match(match_sample) -> None:
    _, _, result = match_sample
    encodings = frozenset(
        bytes.fromhex(value)
        for value in (
            "897dfc",
            "8b45fc",
            "83e001",
            "85c0",
            "0fb6c0",
        )
    )

    match = next(
        match
        for match in result.matches
        if match.encodings == encodings
        and {
            block.containing_function.name for block in match.blocks
        }
        == {"is_even", "is_odd"}
    )

    assert match.common_length == 0xE
    assert match.block_count == 2
    assert match.estimated_savings == 3


def test_matches_can_span_functions(match_sample) -> None:
    _, _, result = match_sample

    assert any(
        len(
            {
                block.containing_function.name
                for block in match.blocks
            }
        )
        > 1
        for match in result.matches
    )


def test_find_basic_block_matches_is_limited_per_block(match_sample) -> None:
    _, uplifter, _ = match_sample
    isa = uplifter.isa
    index = outliner._build_instruction_index(uplifter, isa)

    for function in uplifter.function_map.values():
        if function.has_unk_local_reference():
            continue
        for block in function.basic_blocks:
            matches = outliner.find_basic_block_matches(block, index, isa)
            assert len(matches) <= outliner._MAX_MATCHES_PER_BLOCK


def test_unsupported_isa_returns_none() -> None:
    class UnsupportedISA:
        supports_outlining = False
        name = "unsupported"

    uplifter = SimpleNamespace(function_map={})

    assert (
        outliner.extract_instruction_regions(
            None, uplifter, UnsupportedISA()
        )
        is None
    )


def test_format_match_lists_shared_instructions_and_blocks(
    match_sample,
) -> None:
    _, _, result = match_sample
    match = result.matches[0]

    lines = outliner.format_match(match)
    text = "\n".join(lines)

    assert "shared instructions:" in text
    assert "source blocks:" in text
    for instruction in match.common_instructions:
        assert instruction.original_data.hex() in text
    for block in match.blocks:
        assert f"{block.start_location.value:#x}" in text
