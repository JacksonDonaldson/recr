"""The CUDA range decoder must agree with the per-address CPU decoder.

Every test here compares against the CPU implementation, so a wrong kernel is
a test failure rather than a silently different binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gpu
from binary.binary import Binary
from ir import AddressKind, InstructionType
from isa.x86_64 import X86_64ISA


class _ImageBinary:
    """In-memory binary with one file-backed segment."""

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

    def mapped_segments(self) -> list[tuple[int, int, int, int]]:
        return [(self.base, 0, len(self.data), len(self.data))]

    def image_bytes(self) -> bytes:
        return self.data

    def image_revision(self) -> int:
        return self._revision


@pytest.fixture(scope="session")
def cuda_device_name() -> str:
    """Skip the calling test when no CUDA backend is usable."""
    name = gpu.device_name()
    if name is None:
        pytest.skip(f"CUDA backend unavailable: {gpu.build_error()}")
    return name


def _decode_range(isa: X86_64ISA, binary, start: int, end: int):
    return list(isa.decode_range(binary, start, end))


# Every Intel form is at most 8 bytes; the stride leaves a full window for each
# case so no case's decode can depend on the bytes of the case before it.
_INTEL_CASE_STRIDE = 16


def _intel_corpus_image(
    intel_cases: dict[str, dict[str, str]]
) -> tuple[bytes, dict[int, str]]:
    """Lay every corpus instruction out in one image, keyed by offset."""
    blob = bytearray()
    starts: dict[int, str] = {}
    for form, case in intel_cases.items():
        data = bytes.fromhex(case["old"])
        starts[len(blob)] = form
        blob.extend(data.ljust(_INTEL_CASE_STRIDE, b"\0"))
    return bytes(blob), starts


def _cpu_flow(isa: X86_64ISA, binary, address: int):
    try:
        return isa.decode_flows(binary, address)
    except ValueError:
        return None


def _compare_cpu(
    isa: X86_64ISA, binary, ranges: list[tuple[int, int]]
) -> int:
    checked = 0
    for start, size in ranges:
        flows = _decode_range(isa, binary, start, start + size)
        assert len(flows) == size
        for offset, flow in enumerate(flows):
            address = start + offset
            try:
                expected = isa.decode_flows(binary, address)
            except ValueError:
                expected = None
            assert flow == expected, f"mismatch at {address:#x}"
            checked += 1
    return checked


def test_decode_range_matches_cpu_on_sample(
    x86_64_isa: X86_64ISA, sample_elf: Path, cuda_device_name: str
) -> None:
    binary = Binary(sample_elf)

    checked = _compare_cpu(
        x86_64_isa, binary, sorted(binary.mapped_ranges())
    )

    assert checked > 5000


def test_decode_range_matches_cpu_on_opcode_corpus(
    x86_64_isa: X86_64ISA, opcodes_binary: Path, cuda_device_name: str
) -> None:
    data = opcodes_binary.read_bytes()
    binary = _ImageBinary(data, base=0x1000)

    checked = _compare_cpu(x86_64_isa, binary, [(0x1000, len(data))])

    assert checked > 100


def test_decode_range_matches_cpu_on_every_intel_corpus_instruction(
    x86_64_isa: X86_64ISA,
    intel_cases: dict[str, dict[str, str]],
    cuda_device_name: str,
) -> None:
    data, starts = _intel_corpus_image(intel_cases)
    binary = _ImageBinary(data)
    assert x86_64_isa.device(binary) is not None

    flows = _decode_range(x86_64_isa, binary, 0, len(data))
    assert len(flows) == len(data)

    mismatches = []
    for offset, form in starts.items():
        expected = _cpu_flow(x86_64_isa, binary, offset)
        if flows[offset] != expected:
            mismatches.append((form, offset, expected, flows[offset]))

    assert len(starts) == len(intel_cases)
    assert not mismatches, mismatches[:5]


def test_decode_range_matches_cpu_at_every_intel_corpus_byte(
    x86_64_isa: X86_64ISA,
    intel_cases: dict[str, dict[str, str]],
    cuda_device_name: str,
) -> None:
    data, starts = _intel_corpus_image(intel_cases)
    binary = _ImageBinary(data)
    assert x86_64_isa.device(binary) is not None

    flows = _decode_range(x86_64_isa, binary, 0, len(data))

    mismatches = []
    for address in range(len(data)):
        expected = _cpu_flow(x86_64_isa, binary, address)
        if flows[address] != expected:
            mismatches.append(
                (
                    address,
                    starts.get(address, "<mid-instruction>"),
                    expected,
                    flows[address],
                )
            )
            if len(mismatches) == 5:
                break

    assert not mismatches, mismatches


def test_decode_range_reports_undecodable_bytes(
    x86_64_isa: X86_64ISA, sample_elf: Path, cuda_device_name: str
) -> None:
    binary = Binary(sample_elf)
    start = sorted(binary.mapped_ranges())[0][0]

    # 0x400001 is inside the ELF header and does not decode.
    flows = _decode_range(x86_64_isa, binary, start + 1, start + 2)

    assert flows == [None]


def test_check_addresses_never_exceeds_the_cpu_instruction_window(
    x86_64_isa: X86_64ISA, cuda_device_name: str
) -> None:
    """The kernel must see exactly the bytes the CPU decoder can read."""
    data = b"\x90" * 64
    binary = _ImageBinary(data)
    device = x86_64_isa.device(binary)
    assert device is not None

    avail = device.check_addresses(0, len(data) + 1)

    expected = bytes(
        min(X86_64ISA._MAX_INSTRUCTION_LENGTH, len(data) - address)
        for address in range(len(data) + 1)
    )
    assert avail == expected


def test_control_flow_range_matches_decode_range(
    x86_64_isa: X86_64ISA, sample_elf: Path, cuda_device_name: str
) -> None:
    binary = Binary(sample_elf)
    start, size = sorted(binary.mapped_ranges())[0]

    decoded = {
        flow.address: flow
        for flow in _decode_range(x86_64_isa, binary, start, start + size)
        if flow is not None
    }
    control = list(
        x86_64_isa.decode_control_flow_range(binary, start, start + size)
    )

    assert control
    for flow in control:
        assert flow == decoded[flow.address]
        assert flow.type not in (
            InstructionType.ARITHMETIC,
            InstructionType.NOP,
        )
    expected = {
        address
        for address, flow in decoded.items()
        if flow.type
        not in (InstructionType.ARITHMETIC, InstructionType.NOP)
    }
    assert {flow.address for flow in control} == expected


def test_pointer_scan_matches_per_address_reads(
    x86_64_isa: X86_64ISA, sample_elf: Path, cuda_device_name: str
) -> None:
    binary = Binary(sample_elf)
    targets = {0x401150, 0x401156, 0x40182B}

    for start, size in sorted(binary.mapped_ranges()):
        found = list(
            x86_64_isa.iter_pointer_references(
                binary, start, start + size, targets
            )
        )
        expected = []
        for address in range(start, start + size):
            for pointer in x86_64_isa.try_interpret_as_pointer(
                binary, address
            ):
                if (
                    pointer.kind is AddressKind.ABSOLUTE
                    and pointer.value in targets
                ):
                    expected.append((address, pointer.value))
        assert sorted(found) == sorted(expected)


def test_device_is_rebuilt_after_patching(
    x86_64_isa: X86_64ISA, sample_elf: Path, cuda_device_name: str
) -> None:
    binary = Binary(sample_elf)
    start = sorted(binary.mapped_ranges())[0][0]
    address = start + 0x100

    original = _decode_range(x86_64_isa, binary, address, address + 1)[0]
    assert original is not None

    binary.write(address, b"\xcc")  # int3, one byte
    patched = _decode_range(x86_64_isa, binary, address, address + 1)[0]

    assert patched is not None
    assert patched.length == 1
    assert patched.address == address


def test_cpu_fallback_matches_cuda(
    x86_64_isa: X86_64ISA,
    sample_elf: Path,
    cuda_device_name: str,
    monkeypatch,
) -> None:
    binary = Binary(sample_elf)
    ranges = sorted(binary.mapped_ranges())

    accelerated = [
        list(x86_64_isa.decode_range(binary, start, start + size))
        for start, size in ranges
    ]

    monkeypatch.setattr(gpu, "available", lambda: False)
    fallback = [
        list(x86_64_isa.decode_range(binary, start, start + size))
        for start, size in ranges
    ]

    assert accelerated == fallback


def test_pointer_scan_falls_back_without_cuda(
    x86_64_isa: X86_64ISA,
    sample_elf: Path,
    cuda_device_name: str,
    monkeypatch,
) -> None:
    binary = Binary(sample_elf)
    start, size = sorted(binary.mapped_ranges())[0]
    targets = {0x401150, 0x401156}

    accelerated = list(
        x86_64_isa.iter_pointer_references(
            binary, start, start + size, targets
        )
    )
    monkeypatch.setattr(gpu, "available", lambda: False)
    fallback = list(
        x86_64_isa.iter_pointer_references(
            binary, start, start + size, targets
        )
    )

    assert accelerated == fallback
