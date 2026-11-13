"""Hand-coded regressions found while auditing intel_state_effects.json."""

from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from ir import Address, StateSpaceKind
from isa.sleigher import X86Sleigher
from test.isa.known_gaps import KNOWN_CORPUS_GAPS

FLAGS = (StateSpaceKind.FLAG, "flags")
RAM = (StateSpaceKind.MEMORY, "ram")


def reg(name: str) -> tuple[StateSpaceKind, str]:
    return StateSpaceKind.REGISTER, name


def _assemble(instruction: str, tmp_path: Path) -> bytes:
    source = tmp_path / "audit.s"
    output = tmp_path / "audit.bin"
    source.write_text(f"bits 64\norg 0\n{instruction}\n", encoding="utf-8")

    result = subprocess.run(
        ["nasm", "-f", "bin", str(source), "-o", str(output)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"NASM failed for {instruction!r}: {result.stderr}")

    return output.read_bytes()


def _state_keys(states) -> set[tuple[StateSpaceKind, str]]:
    return {(state.kind, state.name) for state in states}


# Every case below failed against the committed golden or exposed a leak.
CASES: list[
    tuple[
        str,
        set[tuple[StateSpaceKind, str]],
        set[tuple[StateSpaceKind, str]],
    ]
] = [
    # v_offset_plus: the low 16 bits are a byte offset, not the whole value.
    ("movlhps xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM2")}),
    ("punpcklbw xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM1"), reg("ZMM2")}),
    ("punpcklbw mm0, mm1", {reg("MM0")}, {reg("MM0"), reg("MM1")}),
    ("punpcklwd xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM1"), reg("ZMM2")}),
    ("punpcklwd mm0, mm1", {reg("MM0")}, {reg("MM0"), reg("MM1")}),
    ("punpckldq xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM1"), reg("ZMM2")}),
    ("punpckldq mm0, mm1", {reg("MM0")}, {reg("MM1")}),
    ("punpcklqdq xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM2")}),
    ("unpcklpd xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM2")}),
    ("unpcklps xmm1, xmm2", {reg("ZMM1")}, {reg("ZMM1"), reg("ZMM2")}),
    ("movhpd xmm1, [rbx]", {reg("ZMM1")}, {RAM, reg("RBX")}),
    ("movhps xmm1, [rbx]", {reg("ZMM1")}, {RAM, reg("RBX")}),
    # A size handle is not a read of its operand.
    ("kunpckbw k1, k2, k3", {reg("K1")}, {reg("K2"), reg("K3")}),
    ("vcmppd k1, xmm2, xmm3, 1", {reg("K1")}, {reg("ZMM2"), reg("ZMM3")}),
    (
        "vcmppd k1{k2}, xmm2, xmm3, 1",
        {reg("K1")},
        {reg("K2"), reg("ZMM2"), reg("ZMM3")},
    ),
    (
        "vptestmb k2{k1}, xmm2, xmm3",
        {reg("K2")},
        {reg("K1"), reg("ZMM2"), reg("ZMM3")},
    ),
    (
        "vpcmpeqd k1{k2}, xmm2, xmm3",
        {reg("K1")},
        {reg("K2"), reg("ZMM2"), reg("ZMM3")},
    ),
    # SLEIGH scratch registers must not leak into the IR.
    (
        "vaddpd zmm1{k1}{z}, zmm2, zmm3",
        {reg("ZMM1")},
        {reg("ZMM1"), reg("ZMM2"), reg("ZMM3"), reg("K1")},
    ),
    ("cmppd xmm1, xmm2, 1", {reg("ZMM1")}, {reg("ZMM1"), reg("ZMM2")}),
    # x87 condition codes are flags, not independent registers.
    (
        "fcom st1",
        {reg("FPUInstructionPointer"), FLAGS, reg("FPUStatusWord")},
        {reg("ST0"), reg("ST1"), FLAGS},
    ),
    (
        "ftst",
        {reg("FPUInstructionPointer"), FLAGS, reg("FPUStatusWord")},
        {reg("ST0"), FLAGS},
    ),
    # The address-space input of LOAD is not a memory read.
    ("cmova rax, rcx", {reg("RAX")}, {FLAGS, reg("RCX")}),
]


@pytest.mark.parametrize(
    "instruction,expected_modifies,expected_sources",
    CASES,
    ids=[case[0] for case in CASES],
)
def test_audited_state_effects(
    instruction: str,
    expected_modifies: set[tuple[StateSpaceKind, str]],
    expected_sources: set[tuple[StateSpaceKind, str]],
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))

    assert decoded is not None, instruction
    assert _state_keys(decoded.modifies) == expected_modifies, instruction
    assert _state_keys(decoded.depends_on) == expected_sources, instruction
    assert decoded.flows_from == [], instruction
    assert decoded.flows_to == [Address.absolute(decoded.length)], instruction


# Userops with no output varnode carry side effects we cannot recover.
OPAQUE_CASES = [
    "rdtscp",
    "fxsave [rbx]",
    "out dx, eax",
    "cpuid",
    "vpscatterdd [rbx+xmm2*4]{k1}, xmm1",
]


@pytest.mark.parametrize("instruction", OPAQUE_CASES)
def test_opaque_callother_clobbers_all_state(
    instruction: str,
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))
    assert decoded is not None, instruction

    expected = {
        (state.kind, state.name)
        for state in sleigher.spec.all_state_spaces()
    }
    assert _state_keys(decoded.modifies) == expected, instruction
    assert _state_keys(decoded.depends_on) == expected, instruction
    assert decoded.flows_from == [], instruction
    assert decoded.flows_to == [Address.absolute(decoded.length)], instruction


# Userops whose results are fully described by p-code keep precise effects.
PRECISE_CALLOTHER_CASES = [
    ("rdtsc", {reg("RAX"), reg("RDX")}, set()),
    ("xgetbv", {reg("RAX"), reg("RDX")}, {reg("RCX"), reg("XCR0")}),
    (
        "lock add byte [rbx], 1",
        {FLAGS, RAM},
        {RAM, reg("RBX")},
    ),
    (
        "vaddpd zmm1{k1}{z}, zmm2, zmm3",
        {reg("ZMM1")},
        {reg("ZMM1"), reg("ZMM2"), reg("ZMM3"), reg("K1")},
    ),
]


@pytest.mark.parametrize(
    "instruction,expected_modifies,expected_sources",
    PRECISE_CALLOTHER_CASES,
    ids=[case[0] for case in PRECISE_CALLOTHER_CASES],
)
def test_known_callother_effects_stay_precise(
    instruction: str,
    expected_modifies: set[tuple[StateSpaceKind, str]],
    expected_sources: set[tuple[StateSpaceKind, str]],
    sleigher: X86Sleigher,
    tmp_path: Path,
) -> None:
    decoded = sleigher.parse(_assemble(instruction, tmp_path))
    assert decoded is not None, instruction

    assert _state_keys(decoded.modifies) == expected_modifies, instruction
    assert _state_keys(decoded.depends_on) == expected_sources, instruction
    assert decoded.flows_from == [], instruction
    assert decoded.flows_to == [Address.absolute(decoded.length)], instruction


def _is_temporary(name: str) -> bool:
    return name.startswith("xmmTmp") or name in {
        "XmmResult",
        "YmmResult",
        "ZmmResult",
        "XmmMask",
        "YmmMask",
        "ZmmMask",
        "contextreg",
        "BCST4",
        "BCST8",
        "BCST16",
        "BCST32",
        "BCST64",
    }


def test_corpus_has_no_sleigh_temporaries(
    intel_cases: dict[str, dict[str, str]],
    sleigher: X86Sleigher,
) -> None:
    for form, case in intel_cases.items():
        if form in KNOWN_CORPUS_GAPS:
            continue
        decoded = sleigher.parse(bytes.fromhex(case["old"]), address=0)
        assert decoded is not None, form
        for state in (*decoded.modifies, *decoded.depends_on):
            assert not _is_temporary(state.name), (form, state)
            assert state.name not in {"C0", "C1", "C2", "C3"}, (form, state)


def test_all_state_spaces_exclude_temporaries(
    sleigher: X86Sleigher,
) -> None:
    states = sleigher.spec.all_state_spaces()
    names = {state.name for state in states}

    assert FLAGS in {(state.kind, state.name) for state in states}
    assert RAM in {(state.kind, state.name) for state in states}
    assert not any(_is_temporary(name) for name in names)
    assert not names & {"C0", "C1", "C2", "C3"}
    assert {"RAX", "RSP", "RIP", "ZMM0", "K0"} <= names
