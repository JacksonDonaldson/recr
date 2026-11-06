"""Decode and reassemble the Intel 64-bit instruction form corpus."""

from __future__ import annotations

from pathlib import Path

import pytest

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

    relocated = sleigher.reassemble(instruction, NEW_ORIGIN)
    assert relocated is not None
    assert relocated.original_data == expected


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
