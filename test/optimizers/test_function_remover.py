"""Tests for the unreferenced-function optimizer."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ir import Address, FreeSpace, Function, Reference
from optimizers import function_remover
from test.uplift_sample import uplift_sample


@pytest.fixture(scope="module")
def optimized_sample():
    """Return the sample after xref recovery and function removal."""
    parsed, binary, uplifter = uplift_sample()
    uplifter.build_xrefs()
    free_space = function_remover.run_optimizer(binary, uplifter, uplifter.isa)
    return parsed, uplifter, free_space


def _function(parsed, name: str) -> Function:
    return next(
        function for function in parsed.functions if function.name == name
    )


def test_unreferenced_function_is_marked_as_free_space(
    optimized_sample,
) -> None:
    parsed, uplifter, free_space = optimized_sample
    unused = _function(parsed, "unreferenced_function")

    assert unused.start_address == 0x401AF7
    assert unused.length == 0x34
    assert unused.incoming_references == []

    entry = Address.absolute(unused.start_address)
    assert entry not in uplifter.function_map

    block = next(space for space in free_space if space.start == entry)
    assert block.size == unused.length
    assert block.diagnostic == "unreferenced function unreferenced_function"
    assert block.start.value + block.size == (
        unused.start_address + unused.length
    )


def test_referenced_functions_remain_live(optimized_sample) -> None:
    parsed, uplifter, _ = optimized_sample

    for name in ("add", "divide_safe", "<EXTERNAL>::printf"):
        function = _function(parsed, name)
        assert function.incoming_references
        entry = Address.absolute(function.start_address)
        assert uplifter.function_map[entry] is function


def test_free_space_matches_every_function_without_incoming_references(
    optimized_sample,
) -> None:
    parsed, uplifter, free_space = optimized_sample

    expected_free = {
        Address.absolute(function.start_address)
        for function in parsed.functions
        if not function.incoming_references
    }
    expected_live = {
        Address.absolute(function.start_address)
        for function in parsed.functions
        if function.incoming_references
    }

    assert {space.start for space in free_space} == expected_free
    assert set(uplifter.function_map) == expected_live
    assert [space.start.value for space in free_space] == sorted(
        space.start.value for space in free_space
    )


def test_second_run_finds_no_remaining_unreferenced_functions(
    optimized_sample,
) -> None:
    _, uplifter, _ = optimized_sample

    assert (
        function_remover.run_optimizer(
            uplifter.binary, uplifter, uplifter.isa
        )
        == []
    )


def test_only_unreferenced_functions_are_removed() -> None:
    used = Function(
        name="used",
        file_offset=-1,
        start_address=0x2000,
        length=0x10,
    )
    used.incoming_references.append(
        Reference(Address.absolute(0x1000), Address.absolute(0x2000))
    )
    unused = Function(
        name="unused",
        file_offset=-1,
        start_address=0x2010,
        length=0x20,
    )
    function_map = {
        Address.absolute(used.start_address): used,
        Address.absolute(unused.start_address): unused,
    }
    uplifter = SimpleNamespace(function_map=function_map)

    free_space = function_remover.run_optimizer(None, uplifter, None)

    assert function_map == {Address.absolute(used.start_address): used}
    assert free_space == [
        FreeSpace(
            start=Address.absolute(unused.start_address),
            size=unused.length,
            diagnostic="unreferenced function unused",
        )
    ]
