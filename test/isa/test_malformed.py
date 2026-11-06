"""Malformed and truncated byte sequences must be rejected."""

from __future__ import annotations

import random

import pytest

from isa.sleigher import X86Sleigher
from test.isa.known_gaps import GHIDRA_GAPS
from test.isa.test_intel_manual import FORMS

INVALID = {
    "empty": b"",
    "lone-rex.w": b"\x48",
    "lone-rex": b"\x40",
    "lone-operand-size": b"\x66",
    "lone-address-size": b"\x67",
    "lone-lock": b"\xf0",
    "lone-repne": b"\xf2",
    "lone-rep": b"\xf3",
    "lone-cs": b"\x2e",
    "lone-ss": b"\x36",
    "lone-ds": b"\x3e",
    "lone-es": b"\x26",
    "lone-fs": b"\x64",
    "lone-gs": b"\x65",
    "lone-opcode-0f": b"\x0f",
    "unknown-0f-ff": b"\x0f\xff",
    "unknown-66-0f-ff": b"\x66\x0f\xff",
    "unknown-f3-0f-ff": b"\xf3\x0f\xff",
    "invalid-fxsave-modrm": bytes.fromhex("0faee0"),
    "invalid-ptwrite-modrm": bytes.fromhex("480faee0"),
    "truncated-add": bytes.fromhex("83c0"),
    "truncated-mov-imm": bytes.fromhex("b8010203"),
    "truncated-movabs": bytes.fromhex("48b801"),
    "truncated-ff": b"\xff",
    "truncated-jmp": b"\xe9\x00\x00",
    "truncated-call": b"\xe8\x00",
    "lone-vex": bytes.fromhex("c5"),
    "truncated-vex2": bytes.fromhex("c5f3"),
    "lone-evex": bytes.fromhex("62"),
    "truncated-evex": bytes.fromhex("62f3ed08"),
}


@pytest.mark.parametrize(
    "data", INVALID.values(), ids=list(INVALID)
)
def test_invalid_bytes_are_rejected(
    data: bytes, sleigher: X86Sleigher
) -> None:
    assert sleigher.parse(data) is None


@pytest.mark.parametrize(
    "form",
    [form for form in FORMS if form not in GHIDRA_GAPS],
)
def test_proper_prefixes_are_rejected(
    form: str,
    intel_cases: dict[str, dict[str, str]],
    sleigher: X86Sleigher,
) -> None:
    data = bytes.fromhex(intel_cases[form]["old"])
    for length in range(1, len(data)):
        prefix = data[:length]
        decoded = sleigher.parse(prefix)
        if decoded is not None:
            # FWAIT (0x9b) is a complete instruction that also appears
            # before some x87 forms.  Accept only the standalone FWAIT.
            assert (
                prefix[:1] == b"\x9b"
                and decoded.original_data == b"\x9b"
                and decoded.length == 1
            ), (form, length, prefix.hex())


def test_random_bytes_that_decode_are_self_consistent(
    sleigher: X86Sleigher,
) -> None:
    rng = random.Random(0xC0DE21)
    for _ in range(2000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
        instruction = sleigher.parse(data)
        if instruction is None:
            continue
        assert 1 <= instruction.length <= 15
        assert instruction.length <= len(data)
        assert instruction.original_data == data[: instruction.length]
        again = sleigher.parse(instruction.original_data)
        assert again is not None
        assert again.length == instruction.length
