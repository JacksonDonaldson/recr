"""Stack-relative operand biasing for the x86-64 ISA."""

from __future__ import annotations

import pytest

from ir import Address, Instruction
from isa.x86_64 import X86_64ISA

VARIANTS = (
    "rsp_disp8",
    "rsp_disp32",
    "esp_disp8",
    "esp_disp32",
    "rbp_disp8",
    "sib_disp8",
    "rbp_zero",
    "sib_zero",
    "rsp_zero",
    "sib_rsp_zero",
)


class _BytesBinary:
    """Minimal Binary stand-in for the disassembler."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, address: int, length: int) -> bytes:
        return self.data[address : address + length]


def _disassemble(isa: X86_64ISA, data: bytes) -> Instruction:
    return isa.disassemble(_BytesBinary(data), 0)


def _case_bytes(case: dict[str, object], field: str) -> bytes:
    data = bytes.fromhex(case[field])
    return data[int(case["instruction_offset"]) :]


def _state_keys(states) -> set[tuple[object, str]]:
    return {(state.kind, state.name) for state in states}


def _memory_forms(intel_cases: dict[str, dict[str, str]]) -> set[str]:
    return {
        form
        for form, case in intel_cases.items()
        if "[rbx" in case["assembly"]
    }


def test_stack_cases_cover_every_memory_form(
    intel_cases: dict[str, dict[str, str]],
    stack_cases: dict[str, object],
) -> None:
    memory_forms = _memory_forms(intel_cases)
    cases = stack_cases["cases"]
    assert stack_cases["memory_forms"] == len(memory_forms)
    assert {case["form"] for case in cases} == memory_forms


def test_every_memory_form_has_an_adjustable_case(
    intel_cases: dict[str, dict[str, str]],
    stack_cases: dict[str, object],
) -> None:
    memory_forms = _memory_forms(intel_cases)
    adjustable_forms = {
        case["form"]
        for case in stack_cases["cases"]
        if case["adjustable"]
    }
    assert adjustable_forms == memory_forms


def test_every_variant_has_cases(stack_cases: dict[str, object]) -> None:
    variants = {case["variant"] for case in stack_cases["cases"]}
    assert variants == set(VARIANTS)


def test_stack_cases_include_vsib_forms(
    intel_cases: dict[str, dict[str, str]],
    stack_cases: dict[str, object],
) -> None:
    vsib_forms = {
        form
        for form, case in intel_cases.items()
        if "[rbx+" in case["assembly"]
    }
    generated_forms = {case["form"] for case in stack_cases["cases"]}

    assert vsib_forms
    assert vsib_forms <= generated_forms


def test_stack_cases_exercise_evex_compressed_disp8(
    stack_cases: dict[str, object],
) -> None:
    reasons = {case["reason"] for case in stack_cases["cases"]}

    assert "evex_compressed" in reasons


@pytest.mark.parametrize("variant", VARIANTS)
def test_adjustable_stack_cases(
    variant: str,
    stack_cases: dict[str, object],
    x86_64_isa: X86_64ISA,
) -> None:
    cases = [
        case
        for case in stack_cases["cases"]
        if case["variant"] == variant and case["adjustable"]
    ]

    for case in cases:
        instruction = _disassemble(
            x86_64_isa, _case_bytes(case, "original")
        )
        adjusted = x86_64_isa.add_extra_stack_space(instruction, 8)

        assert adjusted.original_data == _case_bytes(case, "adjusted"), (
            case["form"]
        )
        assert adjusted.length == instruction.length, case["form"]
        assert adjusted.address == instruction.address, case["form"]
        assert adjusted.type is instruction.type, case["form"]
        assert (
            x86_64_isa.is_outlinable(instruction) is case["outlinable"]
        ), case["form"]


@pytest.mark.parametrize("variant", VARIANTS)
def test_unadjustable_stack_cases(
    variant: str,
    stack_cases: dict[str, object],
    x86_64_isa: X86_64ISA,
) -> None:
    cases = [
        case
        for case in stack_cases["cases"]
        if case["variant"] == variant and not case["adjustable"]
    ]

    for case in cases:
        instruction = _disassemble(
            x86_64_isa, _case_bytes(case, "original")
        )
        assert x86_64_isa.is_outlinable(instruction) is False, case["form"]
        with pytest.raises(ValueError):
            x86_64_isa.add_extra_stack_space(instruction, 8)


@pytest.mark.parametrize(
    "assembly, original, adjusted",
    [
        ("mov eax, [rbp]", "8b4500", "8b4500"),
        ("mov eax, [rbp+rax*4]", "8b448500", "8b448500"),
        ("mov eax, [rsp-0x80]", "8b442480", "8b442488"),
        ("mov eax, [rsp-0x79]", "8b442487", "8b44248f"),
        ("mov eax, [rsp+0x77]", "8b442477", "8b44247f"),
        ("mov eax, [rsp+0x7ffffff0]", "8b8424f0ffffff", "8b8424f8ffffff"),
        ("mov eax, [rsp-0x80000000]", "8b842400000080", "8b842408000080"),
        ("mov eax, [esp+8]", "678b442408", "678b442410"),
        ("mov eax, [ebp+8]", "678b4508", "678b4508"),
        ("lea rax, [rsp+8]", "488d442408", "488d442410"),
        ("mov rax, [rsp+8]", "488b442408", "488b442410"),
        ("mov [rsp+8], rax", "4889442408", "4889442410"),
    ],
)
def test_hand_written_adjustments(
    assembly: str,
    original: str,
    adjusted: str,
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))
    result = x86_64_isa.add_extra_stack_space(instruction, 8)

    assert result.original_data.hex() == adjusted, assembly
    assert x86_64_isa.is_outlinable(instruction) is True, assembly


def test_adjustment_preserves_state_effects(x86_64_isa: X86_64ISA) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex("488b442408"))
    adjusted = x86_64_isa.add_extra_stack_space(instruction, 8)

    assert _state_keys(adjusted.modifies) == _state_keys(
        instruction.modifies
    )
    assert _state_keys(adjusted.depends_on) == _state_keys(
        instruction.depends_on
    )


def test_adjustment_preserves_address_and_flows(x86_64_isa: X86_64ISA) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex("488b442408"))
    instruction.address = 0x401000
    instruction.flows_from = [Address.absolute(instruction.address)]
    instruction.flows_to = [
        Address.absolute(instruction.address + instruction.length)
    ]

    adjusted = x86_64_isa.add_extra_stack_space(instruction, 8)

    assert adjusted.address == instruction.address
    assert adjusted.flows_from == instruction.flows_from
    assert adjusted.flows_to == instruction.flows_to


@pytest.mark.parametrize(
    "original, pointer_size, adjusted",
    [
        ("8b442408", 1, "8b442409"),
        ("8b442408", 4, "8b44240c"),
        ("8b442408", 16, "8b442418"),
        ("488b4308", 16, "488b4308"),
    ],
)
def test_pointer_size_argument(
    original: str,
    pointer_size: int,
    adjusted: str,
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))
    result = x86_64_isa.add_extra_stack_space(instruction, pointer_size)

    assert result.original_data.hex() == adjusted


def test_moffs_forms_are_outlinable_and_unchanged(
    intel_cases: dict[str, dict[str, str]],
    x86_64_isa: X86_64ISA,
) -> None:
    moffs_forms = {
        form
        for form, case in intel_cases.items()
        if "0x404020" in case["assembly"]
    }
    assert moffs_forms

    for form in moffs_forms:
        data = bytes.fromhex(intel_cases[form]["old"])
        instruction = _disassemble(x86_64_isa, data)
        adjusted = x86_64_isa.add_extra_stack_space(instruction, 8)

        assert x86_64_isa.is_outlinable(instruction) is True, form
        assert adjusted.original_data == data, form


@pytest.mark.parametrize(
    "assembly, original",
    [
        ("mov eax, [rsp]", "8b0424"),
        ("mov eax, [rsp+rax*4]", "8b0484"),
        ("mov eax, [rsp+0x78]", "8b442478"),
        ("mov eax, [rsp+0x7ffffff8]", "8b8424f8ffff7f"),
        ("mov rax, rsp", "4889e0"),
        ("mov [rsp+8], rsp", "4889642408"),
        ("cmp rsp, [rsp+8]", "483b642408"),
        # EVEX disp8 is compressed even when a 67/64 legacy prefix is present.
        ("vmovups zmm0, [esp+0x40]", "6762f17c4810442401"),
        ("vmovups zmm0, fs:[rsp+0x40]", "6462f17c4810442401"),
        # These remain representable as a compressed disp8 after +8, so the
        # guard must reject them even though the raw byte would fit.
        ("vmovss xmm0{k1}, [rsp+0x10]", "62f17e0910442404"),
        ("vmovsd xmm0{k1}, [rsp+0x10]", "62f1ff0910442402"),
        ("vmovss xmm0{k1}, [esp+0x10]", "6762f17e0910442404"),
        ("vmovsd xmm0{k1}, fs:[rsp+0x10]", "6462f1ff0910442402"),
    ],
)
def test_unadjustable_hand_written_cases(
    assembly: str,
    original: str,
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))

    assert x86_64_isa.is_outlinable(instruction) is False, assembly
    with pytest.raises(ValueError):
        x86_64_isa.add_extra_stack_space(instruction, 8)


@pytest.mark.parametrize(
    "assembly, original",
    [
        ("mov rax, [rbx+8]", "488b4308"),
        ("mov eax, ebx", "89d8"),
        ("nop", "90"),
    ],
)
def test_non_stack_instructions_are_unchanged(
    assembly: str,
    original: str,
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))
    result = x86_64_isa.add_extra_stack_space(instruction, 8)

    assert result.original_data == instruction.original_data, assembly
    assert x86_64_isa.is_outlinable(instruction) is True, assembly


@pytest.mark.parametrize("original", ["8b442408", "8b0424", "4889e0"])
def test_zero_pointer_size_is_a_no_op(
    original: str, x86_64_isa: X86_64ISA
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))
    result = x86_64_isa.add_extra_stack_space(instruction, 0)

    assert result.original_data == instruction.original_data


def test_negative_pointer_size_is_rejected(x86_64_isa: X86_64ISA) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex("8b442408"))

    with pytest.raises(ValueError):
        x86_64_isa.add_extra_stack_space(instruction, -8)


@pytest.mark.parametrize(
    "assembly, original",
    [
        ("ret", "c3"),
        ("call 0x401000", "e800000000"),
        ("jmp 0x401000", "e900000000"),
        ("je 0x401000", "0f8400000000"),
        ("push rbp", "55"),
        ("pop rbp", "5d"),
        ("leave", "c9"),
        ("add rsp, 8", "4883c408"),
        ("mov rsp, rbp", "4889ec"),
        ("int 0x80", "cd80"),
        ("int1", "f1"),
        ("int3", "cc"),
        ("hlt", "f4"),
        ("ud2", "0f0b"),
        ("rsm", "0faa"),
    ],
)
def test_stack_and_control_flow_instructions_are_not_outlinable(
    assembly: str,
    original: str,
    x86_64_isa: X86_64ISA,
) -> None:
    instruction = _disassemble(x86_64_isa, bytes.fromhex(original))

    assert x86_64_isa.is_outlinable(instruction) is False, assembly
