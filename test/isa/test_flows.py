"""Control-flow targets produced by x86-64 disassembly."""

from __future__ import annotations

import pytest

from ir import Address, Instruction, InstructionType
from isa.sleigher import X86Sleigher


def _parse(
    sleigher: X86Sleigher, data: bytes, address: int
) -> Instruction:
    instruction = sleigher.parse(data, address=address)
    assert instruction is not None
    assert instruction.address == address
    assert instruction.flows_from == []
    return instruction


def _decode(
    sleigher: X86Sleigher, encoded: str, address: int
) -> Instruction:
    return _parse(sleigher, bytes.fromhex(encoded), address)


def _absolute(value: int) -> Address:
    return Address.absolute(value)


def test_fallthrough_flow_uses_instruction_length(
    sleigher: X86Sleigher,
) -> None:
    cases = [
        ("90", 0x1000, 1),
        ("83c020", 0x400000, 3),
        ("488b0510000000", 0x1000, 7),
        ("f30f100540000000", 0x2000, 8),
    ]

    for encoded, address, length in cases:
        instruction = _decode(sleigher, encoded, address)
        assert instruction.length == length
        assert instruction.flows_to == [
            _absolute(address + instruction.length)
        ]


UNCONDITIONAL_JUMPS = [
    ("jmp rel8 forward", "eb0f", 0x1000, 0x1011),
    ("jmp rel8 backward", "ebf1", 0x1000, 0x0FF3),
    ("jmp rel8 maximum", "eb7f", 0x1000, 0x1081),
    ("jmp rel8 minimum", "eb80", 0x1000, 0x0F82),
    ("jmp rel8 self", "ebfe", 0x7FFFFFFFFFFF00, 0x7FFFFFFFFFFF00),
    ("jmp rel8 next", "eb00", 0x1000, 0x1002),
    ("jmp rel32 zero", "e900000000", 0xDEADBEEF, 0xDEADBEF4),
    ("jmp rel32 negative", "e9ffffffff", 0xDEADBEEF, 0xDEADBEF3),
    ("jmp rel32 maximum", "e9ffffff7f", 0x200000000, 0x280000004),
    ("jmp rel32 minimum", "e900000080", 0x100000000, 0x80000005),
    ("jmp rel16 prefix", "66e90000", 0x1000, 0x1004),
    ("jmp repne prefix", "f2e900000000", 0x1000, 0x1006),
    ("jmp address-size prefix", "67e900000000", 0x1000, 0x1006),
    ("jmp rex prefix", "48e900000000", 0x1000, 0x1006),
    ("jmp segment prefix", "2ee900000000", 0x1000, 0x1006),
    ("jmp rel8 high address", "eb0f", 0xFFFF800000000000, 0xFFFF800000000011),
    ("jmp rel32 high address", "e900000000", 0xFFFF800000000000, 0xFFFF800000000005),
]


@pytest.mark.parametrize(
    "name,encoded,address,target",
    UNCONDITIONAL_JUMPS,
    ids=[case[0] for case in UNCONDITIONAL_JUMPS],
)
def test_direct_unconditional_jump_targets(
    name: str,
    encoded: str,
    address: int,
    target: int,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, address)

    assert instruction.flows_to == [_absolute(target)], name


CONDITIONAL_BRANCHES = [
    ("je rel8 forward", "7422", 0x1000, 0x1024, 0x1002),
    ("je rel8 backward", "74f0", 0x1000, 0x0FF2, 0x1002),
    ("jne rel32", "0f850a000000", 0x5000, 0x5010, 0x5006),
    ("loop rel8", "e2fe", 0x1000, 0x1000, 0x1002),
    ("jrcxz rel8", "e3fe", 0x1000, 0x1000, 0x1002),
    ("jecxz address-size prefix", "67e3fe", 0x1000, 0x1001, 0x1003),
    ("jcc address-size prefix", "670f840a000000", 0x1000, 0x1011, 0x1007),
    (
        "jne rel32 high address",
        "0f850a000000",
        0xFFFF800000000000,
        0xFFFF800000000010,
        0xFFFF800000000006,
    ),
]


@pytest.mark.parametrize(
    "name,encoded,address,target,fallthrough",
    CONDITIONAL_BRANCHES,
    ids=[case[0] for case in CONDITIONAL_BRANCHES],
)
def test_conditional_branch_has_target_and_fallthrough(
    name: str,
    encoded: str,
    address: int,
    target: int,
    fallthrough: int,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, address)

    assert instruction.flows_to == [
        _absolute(target),
        _absolute(fallthrough),
    ], name


def test_conditional_branch_to_fallthrough_has_one_target(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "7400", 0x1000)

    assert instruction.flows_to == [_absolute(0x1002)]


INDIRECT_JUMPS = [
    ("jmp rax", "ffe0"),
    ("jmp [rax]", "ff20"),
    ("jmp [rax+rcx+0x10]", "ff640810"),
    ("jmp [rip+0x10]", "ff2510000000"),
    ("jmp far [rax]", "ff28"),
    ("jmp far [disp32]", "ff2c2500000000"),
    ("jmp ax with operand-size prefix", "66ffe0"),
    ("jmp rax with rex prefix", "40ffe0"),
    ("jmp rax with segment prefix", "2effe0"),
]


@pytest.mark.parametrize(
    "name,encoded",
    INDIRECT_JUMPS,
    ids=[case[0] for case in INDIRECT_JUMPS],
)
def test_indirect_jumps_are_unknown_local(
    name: str,
    encoded: str,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, 0x1000)

    assert instruction.flows_to == [Address.unknown_local()], name


DIRECT_CALLS = [
    ("call rel32", "e810000000", 0x4000, 0x4015, 0x4005),
    ("call rel32 backward", "e8f0ffffff", 0x4000, 0x3FF5, 0x4005),
    ("call rel16 prefix", "66e81000", 0x1000, 0x1014, 0x1004),
    ("call repne prefix", "f2e810000000", 0x1000, 0x1016, 0x1006),
    (
        "call rel32 high address",
        "e810000000",
        0xFFFF800000000000,
        0xFFFF800000000015,
        0xFFFF800000000005,
    ),
]


@pytest.mark.parametrize(
    "name,encoded,address,target,fallthrough",
    DIRECT_CALLS,
    ids=[case[0] for case in DIRECT_CALLS],
)
def test_direct_call_has_target_and_fallthrough(
    name: str,
    encoded: str,
    address: int,
    target: int,
    fallthrough: int,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, address)

    assert instruction.flows_to == [
        _absolute(target),
        _absolute(fallthrough),
    ], name


INDIRECT_CALLS = [
    ("call rax", "ffd0", 2),
    ("call [rax]", "ff10", 2),
    ("call [rip+0x10]", "ff1510000000", 6),
    ("call far [rax]", "ff18", 2),
    ("call far [rbx]", "ff1b", 2),
    ("call ax with operand-size prefix", "66ffd0", 3),
]


@pytest.mark.parametrize(
    "name,encoded,length",
    INDIRECT_CALLS,
    ids=[case[0] for case in INDIRECT_CALLS],
)
def test_indirect_call_has_unknown_target_and_fallthrough(
    name: str,
    encoded: str,
    length: int,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, 0x1000)

    assert instruction.length == length, name
    assert instruction.flows_to == [
        Address.unknown_nonlocal(),
        _absolute(0x1000 + length),
    ], name


RETURNS = [
    ("ret", "c3"),
    ("ret imm16", "c20800"),
    ("retf", "cb"),
    ("iret", "cf"),
    ("iretq", "48cf"),
]


@pytest.mark.parametrize(
    "name,encoded", RETURNS, ids=[case[0] for case in RETURNS]
)
def test_returns_have_no_flow_targets(
    name: str,
    encoded: str,
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, encoded, 0x1000)

    assert instruction.flows_to == [], name


def test_flow_only_decode_reports_hand_checked_flows(
    sleigher: X86Sleigher,
) -> None:
    # call rel32 from 0x4000 targets 0x4015 and falls through to 0x4005.
    call = sleigher.parse_flow(bytes.fromhex("e810000000"), address=0x4000)
    assert call is not None
    assert call.address == 0x4000
    assert call.length == 5
    assert call.type is InstructionType.CALL
    assert call.flows_to == (
        Address.absolute(0x4015),
        Address.absolute(0x4005),
    )

    # jne rel32 from 0x5000 targets 0x5010 and falls through to 0x5006.
    branch = sleigher.parse_flow(
        bytes.fromhex("0f850a000000"), address=0x5000
    )
    assert branch is not None
    assert branch.type is InstructionType.BRANCH
    assert branch.flows_to == (
        Address.absolute(0x5010),
        Address.absolute(0x5006),
    )

    # jmp [rax] is an unresolved local target with no fallthrough edge.
    indirect = sleigher.parse_flow(bytes.fromhex("ff20"), address=0x1000)
    assert indirect is not None
    assert indirect.flows_to == (Address.unknown_local(),)

    # ret ends the flow entirely.
    ret = sleigher.parse_flow(bytes.fromhex("c3"), address=0x1000)
    assert ret is not None
    assert ret.type is InstructionType.RET
    assert ret.flows_to == ()

    # nop falls through to the next instruction.
    nop = sleigher.parse_flow(bytes.fromhex("90"), address=0x1000)
    assert nop is not None
    assert nop.type is InstructionType.NOP
    assert nop.flows_to == (Address.absolute(0x1001),)


FLOW_ONLY_CASES = (
    [("90", 0x1000), ("83c020", 0x400000), ("488b0510000000", 0x1000)]
    + [(encoded, address) for _, encoded, address, _ in UNCONDITIONAL_JUMPS]
    + [
        (encoded, address)
        for _, encoded, address, _, _ in CONDITIONAL_BRANCHES
    ]
    + [(encoded, address) for _, encoded, address, _, _ in DIRECT_CALLS]
    + [(encoded, 0x1000) for _, encoded in INDIRECT_JUMPS]
    + [(encoded, 0x1000) for _, encoded, _ in INDIRECT_CALLS]
    + [(encoded, 0x1000) for _, encoded in RETURNS]
)


@pytest.mark.parametrize("encoded,address", FLOW_ONLY_CASES)
def test_flow_only_decode_matches_full_decode(
    encoded: str, address: int, sleigher: X86Sleigher
) -> None:
    instruction = _decode(sleigher, encoded, address)
    flow = sleigher.parse_flow(bytes.fromhex(encoded), address=address)

    assert flow is not None, encoded
    assert flow.address == instruction.address, encoded
    assert flow.length == instruction.length, encoded
    assert flow.type is instruction.type, encoded
    assert list(flow.flows_to) == instruction.flows_to, encoded


def test_reassemble_updates_fallthrough_flow(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "83c020", 0x1000)

    relocated = sleigher.reassemble(instruction, 0x2000)

    assert relocated is not None
    assert relocated.flows_from == []
    assert relocated.flows_to == [_absolute(0x2003)]


def test_reassemble_preserves_direct_jump_target(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "e910000000", 0x1000)
    assert instruction.flows_to == [_absolute(0x1015)]

    relocated = sleigher.reassemble(instruction, 0x2000)

    assert relocated is not None
    assert relocated.flows_from == []
    assert relocated.flows_to == [_absolute(0x1015)]


def test_reassemble_updates_conditional_branch_fallthrough(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "7422", 0x1000)
    assert instruction.flows_to == [_absolute(0x1024), _absolute(0x1002)]

    relocated = sleigher.reassemble(instruction, 0x1008)

    assert relocated is not None
    assert relocated.flows_from == []
    assert relocated.flows_to == [_absolute(0x1024), _absolute(0x100A)]


def test_reassemble_updates_indirect_call_fallthrough(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "ffd0", 0x1000)

    relocated = sleigher.reassemble(instruction, 0x2000)

    assert relocated is not None
    assert relocated.flows_from == []
    assert relocated.flows_to == [
        Address.unknown_nonlocal(),
        _absolute(0x2002),
    ]


def test_reassemble_preserves_indirect_jump_target_kind(
    sleigher: X86Sleigher,
) -> None:
    instruction = _decode(sleigher, "ffe0", 0x1000)

    relocated = sleigher.reassemble(instruction, 0x2000)

    assert relocated is not None
    assert relocated.flows_from == []
    assert relocated.flows_to == [Address.unknown_local()]
