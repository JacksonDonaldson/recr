"""Decode and reassemble the Intel 64-bit instruction form corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

from ir import Address
from isa.sleigher import X86Sleigher
from test.isa.known_gaps import KNOWN_CORPUS_GAPS

FORMS_PATH = (
    Path(__file__).parents[2]
    / "isa"
    / "x86_64"
    / "test"
    / "intel_64bit_forms.txt"
)
NEW_ORIGIN = 0x20

FORMS = [
    line.strip()
    for line in FORMS_PATH.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

_PARAMS = [
    pytest.param(
        form,
        marks=pytest.mark.xfail(
            reason=KNOWN_CORPUS_GAPS[form], strict=True
        ),
    )
    if form in KNOWN_CORPUS_GAPS
    else form
    for form in FORMS
]


def _immediate_target(assembly: str) -> int | None:
    parts = assembly.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[-1], 0)
    except ValueError:
        return None


def _expected_flows(
    form: str, assembly: str, address: int, length: int
) -> list[Address]:
    """Derive the expected flow targets from the Intel form and NASM line."""
    mnemonic = form.split()[0].upper()
    fallthrough = Address.absolute(address + length)

    if mnemonic in {"RET", "RETF", "IRET", "IRETD", "IRETQ"}:
        return []
    if mnemonic in {"CALL", "CALLF"}:
        if "rel" in form:
            target = _immediate_target(assembly)
            assert target is not None, form
            return list(dict.fromkeys([Address.absolute(target), fallthrough]))
        return list(dict.fromkeys([Address.unknown_nonlocal(), fallthrough]))
    if mnemonic in {"JMP", "JMPF"}:
        if "rel" in form:
            target = _immediate_target(assembly)
            assert target is not None, form
            return [Address.absolute(target)]
        return [Address.unknown_local()]
    if mnemonic.startswith("J") or mnemonic.startswith("LOOP"):
        target = _immediate_target(assembly)
        assert target is not None, form
        return list(dict.fromkeys([Address.absolute(target), fallthrough]))
    return [fallthrough]


@pytest.mark.parametrize("form", _PARAMS)
def test_intel_form(
    form: str,
    intel_cases: dict[str, dict[str, str]],
    intel_state_effects: dict[str, dict[str, list[str]]],
    sleigher: X86Sleigher,
) -> None:
    case = intel_cases[form]
    original = bytes.fromhex(case["old"])
    expected = bytes.fromhex(case["new"])

    instruction = sleigher.parse(original, address=0)
    assert instruction is not None
    assert instruction.length == len(original)
    assert instruction.original_data == original

    golden = intel_state_effects.get(form)
    if golden is not None:
        assert _state_keys(instruction.modifies) == golden["modifies"]
        assert _state_keys(instruction.depends_on) == golden["depends_on"]

    assert instruction.flows_from == [], form
    assert instruction.flows_to == _expected_flows(
        form, case["assembly"], 0, len(original)
    ), form

    flow = sleigher.parse_flow(original, address=0)
    assert flow is not None, form
    assert flow.address == instruction.address, form
    assert flow.length == instruction.length, form
    assert flow.type is instruction.type, form
    assert list(flow.flows_to) == instruction.flows_to, form

    relocated = sleigher.reassemble(instruction, NEW_ORIGIN)
    assert relocated is not None
    assert relocated.original_data == expected
    assert relocated.flows_from == [], form
    assert relocated.flows_to == _expected_flows(
        form, case["assembly"], NEW_ORIGIN, len(original)
    ), form


def _state_keys(states) -> list[str]:
    return sorted(
        {f"{state.kind.name.lower()}:{state.name}" for state in states}
    )


def test_intel_corpus_covers_every_form(
    intel_cases: dict[str, dict[str, str]]
) -> None:
    assert set(intel_cases) == set(FORMS)


def test_intel_state_corpus_covers_every_decodable_form(
    intel_state_effects: dict[str, dict[str, list[str]]],
) -> None:
    assert set(intel_state_effects) == set(FORMS) - set(KNOWN_CORPUS_GAPS)
