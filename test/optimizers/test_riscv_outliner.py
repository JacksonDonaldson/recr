"""Assembler-backed tests for alternate-link outlining on RV32 and RV64."""

from __future__ import annotations

from pathlib import Path

import pytest

from binary.binary import Binary
from ir import Address, FreeSpace, Function, InstructionType
from optimizers import outliner
from test.isa.test_riscv import assemble, binutils
from uplifter import Uplifter


@pytest.fixture(params=(32, 64))
def fixture_builder(tmp_path: Path, request):
    def build(source: str, names: tuple[str, ...]) -> tuple[Binary, Uplifter, dict[str, Function]]:
        xlen = request.param
        obj = assemble(tmp_path, xlen, ".option norvc\n" + source)
        path = tmp_path / "outline.elf"
        binutils("ld", "-m", f"elf{xlen}lriscv", "--no-relax", "-e", "0", "-o", str(path), str(obj))
        image = Binary(path)
        uplifter = Uplifter(f"riscv{xlen}", image)
        functions = {}
        for name in names:
            start, end = image.symbol_address(name), image.symbol_address(f"{name}_end")
            assert start is not None and end is not None
            function = Function(name, image.virtual_to_file(start), start, end - start)
            uplifter.uplift_function(function)
            functions[name] = function
        return image, uplifter, functions
    return build


@pytest.mark.parametrize(
    "suffix,expected",
    [
        ("jalr zero,ra,0", True),
        ("addi a0,t0,1\njalr zero,ra,0", False),
        ("addi t0,zero,7\naddi a0,t0,1\njalr zero,ra,0", True),
        ("addi t0,t0,1\njalr zero,ra,0", False),
        ("jalr zero,t0,0", False),
        ("jalr ra,t0,0\njalr zero,ra,0", False),
        ("jalr ra,t1,0\njalr zero,ra,0", False),
        ("jalr t0,t1,0\njalr zero,ra,0", True),
        ("jalr t0,t0,0\njalr zero,ra,0", False),
        ("ecall\njalr zero,ra,0", False),
        ("lr.w a0,(a1)\nsc.w a0,a2,(a1)\njalr zero,ra,0", False),
        ("1: beq a1,zero,1b\njalr zero,ra,0", True),
        ("1: beq a1,zero,1b\njalr zero,t0,0", False),
        ("beq a1,zero,1f\naddi t0,zero,0\n1: add a0,a0,t0\njalr zero,ra,0", False),
        ("beq a1,zero,1f\naddi t0,zero,0\n1: addi t0,zero,1\nadd a0,a0,t0\njalr zero,ra,0", True),
        ("jal zero,outside", False),
    ],
)
def test_link_live_at_outline_site(fixture_builder, suffix: str, expected: bool):
    _, uplifter, functions = fixture_builder(
        f"subject:\nadd a0,a0,a1\n{suffix}\nsubject_end:\noutside:\njalr zero,ra,0",
        ("subject",),
    )
    function = functions["subject"]
    block = function.basic_blocks[0]
    assert uplifter.isa.can_outline_region(function, block, block.instructions, 0, 1) is expected


def test_liveness_checks_reordered_suffix(fixture_builder):
    _, uplifter, functions = fixture_builder(
        """
        subject:
            add a0,a0,a1
            addi t0,zero,7
            add a2,a2,t0
            jalr zero,ra,0
        subject_end:
        """,
        ("subject",),
    )
    function = functions["subject"]
    block = function.basic_blocks[0]
    candidate, defines_link, reads_link, ret = block.instructions
    assert uplifter.isa.can_outline_region(function, block, block.instructions, 0, 1)
    reordered = [defines_link, candidate, reads_link, ret]
    assert not uplifter.isa.can_outline_region(function, block, reordered, 1, 1)
    assert not uplifter.isa.is_outlinable(defines_link)
    assert not uplifter.isa.is_outlinable(reads_link)


def test_outline_drops_live_link_site_and_leaves_stack_operands_alone(fixture_builder):
    body = """
        addi sp,sp,-16
        sw a0,4(sp)
        lw a0,4(sp)
        addi a0,a0,3
        addi sp,sp,16
    """
    source = "\n".join(
        f"{name}:\n{body}\n"
        f"{'add a0,a0,t0' if name == 'live' else ''}\n"
        f"jalr zero,ra,0\n{name}_end:\n"
        for name in ("safe_a", "safe_b", "live")
    )
    source += "\nspare:\n.zero 128\n"
    image, uplifter, functions = fixture_builder(source, ("safe_a", "safe_b", "live"))
    live = functions["live"]
    original_live = image.read(live.start_address, live.length)
    safe = functions["safe_a"]
    expected_body = image.read(safe.start_address, safe.length - 4)
    start = image.symbol_address("spare")
    assert start is not None
    free_space = [FreeSpace(Address.absolute(start), 128, "test")]
    result = outliner.run_optimizer(image, uplifter, uplifter.isa, free_space)

    assert result is not None
    assert len(result.selected_matches) == len(result.extracted_instructions) == 1
    shared = result.extracted_instructions[0]
    shared_address = shared.start_location.value
    assert image.read(shared_address, len(expected_body)) == expected_body
    ret = image.read(shared_address + len(expected_body), 4)
    assert ret == bytes.fromhex("67800200")  # jalr zero,0(t0)
    assert [state.name for state in shared.instructions[-1].depends_on] == ["t0"]
    assert image.read(live.start_address, live.length) == original_live
    for name in ("safe_a", "safe_b"):
        call = functions[name].basic_blocks[0].instructions[0]
        assert call.type is InstructionType.OUTLINE_RESULT_CALL
        assert [state.name for state in call.modifies] == ["t0"]
        decoded = uplifter.isa.decode_flows(image, call.address)
        assert decoded.flows_to == (Address.absolute(shared_address), Address.absolute(call.address + 4))
        assert ((int.from_bytes(call.original_data, "little") >> 7) & 31) == 5
    assert sum(space.size for space in free_space) == 128 + 2 * (20 - 4) - (20 + 4)


def test_alternate_call_rejects_unencodable_placement(fixture_builder):
    _, uplifter, _ = fixture_builder("nop", ())
    isa = uplifter.isa
    call = isa.make_call_instruction()
    assert isa.can_encode(call, 0x1000)
    with pytest.raises(ValueError):
        isa.set_instruction_target(call, Address.absolute(0x100000))
    with pytest.raises(ValueError):
        isa.set_instruction_target(call, Address.absolute(3))
