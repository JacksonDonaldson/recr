"""Range-decoding API shared by every ISA backend.

These tests exercise the CPU implementations, so they run without a GPU.
"""

from __future__ import annotations

import pytest

from ir import Address, AddressKind, InstructionType
from isa.isa import DecodedFlow
from isa.x86_64 import X86_64ISA


class _MemoryBinary:
    """Minimal in-memory binary stand-in for range scans."""

    def __init__(self, data: bytes, base: int = 0) -> None:
        self.data = data
        self.base = base
        self._revision = 0

    def read(self, address: int, length: int) -> bytes:
        offset = address - self.base
        if offset < 0 or offset + length > len(self.data):
            raise ValueError(f"virtual address {address:#x} is not mapped")
        return self.data[offset : offset + length]

    def mapped_ranges(self) -> list[tuple[int, int]]:
        return [(self.base, len(self.data))]

    def try_interpret_as_pointer(self, address: int) -> None:  # pragma: no cover
        raise AssertionError("not part of the Binary protocol")


def _decode_range(isa: X86_64ISA, binary, start: int, end: int):
    return list(isa.decode_range(binary, start, end))


def test_decode_range_matches_decode_flows(x86_64_isa: X86_64ISA) -> None:
    data = bytes.fromhex(
        # mov rax, [rsp+8]; jne 0x0; nop; ret; call 0x0
        "488b442408"
        "7500"
        "90"
        "c3"
        "e800000000"
    )
    binary = _MemoryBinary(data)

    for address in range(len(data)):
        flows = _decode_range(x86_64_isa, binary, address, address + 1)
        try:
            expected = x86_64_isa.decode_flows(binary, address)
        except ValueError:
            expected = None
        assert flows == [expected], f"mismatch at {address:#x}"


def test_decode_range_yields_none_for_undecodable_bytes(
    x86_64_isa: X86_64ISA,
) -> None:
    # 0x00 0x00 decodes as ``add [rax], al``; a lone invalid prefix does not.
    binary = _MemoryBinary(b"\xf0\xf0\xf0")

    flows = _decode_range(x86_64_isa, binary, 0, 3)

    assert flows[0] is None
    with pytest.raises(ValueError):
        x86_64_isa.decode_flows(binary, 0)


def test_decode_range_stops_at_the_mapped_end(x86_64_isa: X86_64ISA) -> None:
    data = b"\x90" * 3 + bytes.fromhex("488b442408")
    binary = _MemoryBinary(data)

    flows = _decode_range(x86_64_isa, binary, 0, len(data))

    assert flows[0].length == 1
    assert flows[3] is not None
    assert flows[3].length == 5
    assert flows[3].address + flows[3].length == len(data)


def test_control_flow_range_skips_straight_line_instructions(
    x86_64_isa: X86_64ISA,
) -> None:
    data = bytes.fromhex("9090" "7500" "c3")
    binary = _MemoryBinary(data)

    flows = list(x86_64_isa.decode_control_flow_range(binary, 0, len(data)))

    assert [flow.address for flow in flows] == [2, 4]
    assert flows[0].type is InstructionType.BRANCH
    assert flows[1].type is InstructionType.RET


def test_control_flow_range_is_a_subset_of_decode_range(
    x86_64_isa: X86_64ISA,
) -> None:
    data = bytes.fromhex("488b442408" "e800000000" "7500" "c3")
    binary = _MemoryBinary(data)

    decoded = {
        flow.address: flow
        for flow in _decode_range(x86_64_isa, binary, 0, len(data))
        if flow is not None
    }
    control = {
        flow.address: flow
        for flow in x86_64_isa.decode_control_flow_range(binary, 0, len(data))
    }

    assert set(control) <= set(decoded)
    for address, flow in control.items():
        assert flow == decoded[address]
    assert all(
        flow.type not in (InstructionType.ARITHMETIC, InstructionType.NOP)
        for flow in control.values()
    )


def test_iter_pointer_references_matches_per_address_reads(
    x86_64_isa: X86_64ISA,
) -> None:
    target = 0x2000
    data = target.to_bytes(8, "little") + b"\0" * 8 + (0x3000).to_bytes(
        4, "little"
    )
    binary = _MemoryBinary(data, base=0x1000)

    found = list(
        x86_64_isa.iter_pointer_references(
            binary, 0x1000, 0x1000 + len(data), {target, 0x3000}
        )
    )

    expected = []
    for address in range(0x1000, 0x1000 + len(data)):
        for pointer in x86_64_isa.try_interpret_as_pointer(binary, address):
            if pointer.kind is AddressKind.ABSOLUTE and pointer.value in {
                target,
                0x3000,
            }:
                expected.append((address, pointer.value))
    assert sorted(found) == sorted(expected)
    assert (0x1000, target) in found
    assert (0x1010, 0x3000) in found


def test_iter_pointer_references_ignores_unknown_targets(
    x86_64_isa: X86_64ISA,
) -> None:
    binary = _MemoryBinary((0x4000).to_bytes(8, "little") + b"\0" * 8)

    assert list(
        x86_64_isa.iter_pointer_references(binary, 0, 16, {0x9999})
    ) == []


def test_decoded_flow_is_hashable() -> None:
    flow = DecodedFlow(
        address=1,
        length=2,
        type=InstructionType.BRANCH,
        flows_to=(Address.absolute(3),),
    )

    assert flow == DecodedFlow(
        address=1,
        length=2,
        type=InstructionType.BRANCH,
        flows_to=(Address.absolute(3),),
    )
