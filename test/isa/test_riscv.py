"""GNU-assembled RISC-V fixtures with independent state and relocation oracles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile
import pytest

from ir import Address, InstructionType, StateSpaceKind
from isa import create_isa
from isa.isa import DecodedFlow, ISA
from isa.sleigher.sla import OP_INT_AND, SlaSpec


@dataclass(frozen=True)
class Image:
    data: bytes
    base: int = 0x1000
    gp: int | None = None

    def read(self, address: int, length: int) -> bytes:
        offset = address - self.base
        if offset < 0 or offset + length > len(self.data):
            raise ValueError("unmapped")
        return self.data[offset:offset + length]

    def symbol_address(self, name: str) -> int | None:
        assert name == "__global_pointer$"
        return self.gp


def binutils(command: str, *args: str) -> str:
    return subprocess.run(
        [f"riscv64-linux-gnu-{command}", *args], check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def assemble(path: Path, xlen: int, source: str, extensions: str = "") -> Path:
    asm, obj = path / "fixture.s", path / "fixture.o"
    asm.write_text(".text\n.option norelax\n" + source)
    binutils("as", f"-march=rv{xlen}gc{extensions}", "-mno-relax", "-o", str(obj), str(asm))
    return obj


def text_bytes(obj: Path) -> bytes:
    with obj.open("rb") as stream:
        return ELFFile(stream).get_section_by_name(".text").data()


@dataclass(frozen=True)
class Effects:
    asm: str
    writes: str
    reads: str


_BASE = (
    Effects("lui a0,0x12345", "a0", ""),
    Effects("auipc a0,0xfffff", "a0", ""),
    Effects("srai a0,a1,7", "a0", "a1"),
    Effects("andi a0,a1,-31", "a0", "a1"),
    Effects("add zero,a0,a1", "", "a0 a1"),
    Effects("addi a7,zero,-1", "a7", ""),
    Effects("addi zero,zero,0", "", ""),
    Effects("lb a0,12(gp)", "a0", "gp ram"),
    Effects("lhu a0,-112(s0)", "a0", "s0 ram"),
    Effects("lw zero,4(sp)", "", "sp ram"),
    Effects("sw a0,-2048(a7)", "ram", "a0 a7"),
    Effects("sb zero,2047(zero)", "ram", ""),
    Effects("divu a0,a1,a2", "a0", "a1 a2"),
    Effects("rem a0,a1,a2", "a0", "a1 a2"),
    Effects("mulh a0,a1,a2", "a0", "a1 a2"),
    Effects("amoadd.w.aqrl a0,a2,(a1)", "a0 ram", "a1 a2 ram"),
    Effects("flw fa0,8(a5)", "fa0", "a5 ram"),
    Effects("fsd fa1,-8(sp)", "ram", "fa1 sp"),
    Effects("fadd.s fa0,fa1,fa2,dyn", "fa0 csreg", "fa1 fa2 csreg"),
    Effects("fmadd.d fa0,fa1,fa2,fa3,rne", "fa0 csreg", "fa1 fa2 fa3 csreg"),
    Effects("fsgnj.d fa0,fa1,fa2", "fa0", "fa1 fa2"),
    Effects("fclass.s a0,fa1", "a0", "fa1"),
    Effects("fclass.d a0,fa1", "a0", "fa1"),
    Effects("fmv.w.x fa0,a1", "fa0", "a1"),
    Effects("csrrw a0,mscratch,a1", "a0 csreg", "a1 csreg"),
    Effects("csrrs a0,mscratch,zero", "a0", "csreg"),
    Effects("csrrwi zero,mscratch,3", "csreg", ""),
    Effects("csrsi mscratch,3", "csreg", "csreg"),
    Effects("c.nop", "", ""),
    Effects("c.li a0,-10", "a0", ""),
    Effects("c.addi s0,-11", "s0", "s0"),
    Effects("c.lui a0,0xfffea", "a0", ""),
    Effects("c.addi4spn a0,sp,256", "a0", "sp"),
    Effects("c.addi16sp sp,-128", "sp", "sp"),
    Effects("c.slli a0,7", "a0", "a0"),
    Effects("c.mv a0,t3", "a0", "t3"),
    Effects("c.and a0,a1", "a0", "a0 a1"),
    Effects("c.lw a0,76(a1)", "a0", "a1 ram"),
    Effects("c.sw a0,124(a1)", "ram", "a0 a1"),
    Effects("c.lwsp a0,140(sp)", "a0", "sp ram"),
    Effects("c.swsp a0,144(sp)", "ram", "a0 sp"),
    Effects("c.fld fa0,248(a1)", "fa0", "a1 ram"),
    Effects("c.fsdsp fa0,488(sp)", "ram", "fa0 sp"),
)

_RV64 = (
    Effects("addiw a0,a1,-2048", "a0", "a1"),
    Effects("sllw a0,a1,a2", "a0", "a1 a2"),
    Effects("ld a0,8(tp)", "a0", "tp ram"),
    Effects("lwu a0,-8(a1)", "a0", "a1 ram"),
    Effects("sd a0,2040(a1)", "ram", "a0 a1"),
    Effects("c.addiw a0,-8", "a0", "a0"),
    Effects("c.subw a0,a1", "a0", "a0 a1"),
    Effects("c.ld a0,248(a1)", "a0", "a1 ram"),
    Effects("c.sdsp a0,504(sp)", "ram", "a0 sp"),
)

_RV32 = (
    Effects("c.flw fa0,124(a1)", "fa0", "a1 ram"),
    Effects("c.fswsp fa0,252(sp)", "ram", "fa0 sp"),
)

_GPRS = (
    "zero ra sp gp tp t0 t1 t2 s0 s1 a0 a1 a2 a3 a4 a5 a6 a7 "
    "s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 t3 t4 t5 t6"
).split()

# Sweep every architectural field value with different source and destination
# register indices so a swapped operand field cannot accidentally pass.
_ALU = ("add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and")
_REGISTER_SWEEP = tuple(
    Effects(
        f"{mnemonic} {rd},{rs1},{rs2}", "" if rd == "zero" else rd,
        " ".join(r for r in (rs1, rs2) if r != "zero"),
    )
    for mnemonic in _ALU
    for i, rd in enumerate(_GPRS)
    for rs1, rs2 in [(_GPRS[(i + 7) % 32], _GPRS[(i + 13) % 32])]
)

_MEMORY_SWEEP = tuple(
    Effects(
        f"{mnemonic} {reg},{offset}({base})",
        ("" if reg == "zero" else reg) if load else "ram",
        " ".join(name for name in (base, "ram" if load else reg) if name != "zero"),
    )
    for mnemonic in ("lb", "lbu", "lh", "lhu", "lw", "sb", "sh", "sw")
    for load in [mnemonic.startswith("l")]
    for i, reg in enumerate(_GPRS)
    for base in [_GPRS[(i + 5) % 32]]
    for offset in (-2048, -1, 0, 2047)
)

_COMPRESSED_SWEEP = tuple(
    Effects(f"{mnemonic} {rd},{rs2}", rd, f"{rd} {rs2}")
    for mnemonic in ("c.and", "c.or", "c.xor", "c.sub")
    for rd in _GPRS[8:16]
    for rs2 in _GPRS[8:16]
)


@pytest.fixture(scope="module", params=[32, 64])
def backend(request):
    return create_isa(f"riscv{request.param}")


@pytest.fixture(scope="module")
def corpus(tmp_path_factory, backend):
    expected = (
        _BASE + (_RV32 if backend.xlen == 32 else _RV64)
        + _REGISTER_SWEEP + _MEMORY_SWEEP + _COMPRESSED_SWEEP
    )
    source = "\n".join(
        f".option {'rvc' if row.asm.startswith('c.') else 'norvc'}\ncase_{index}:\n{row.asm}"
        for index, row in enumerate(expected)
    )
    obj = assemble(tmp_path_factory.mktemp("riscv"), backend.xlen, source)
    data = text_bytes(obj)
    listing = binutils("objdump", "-d", "-M", "no-aliases", str(obj))
    # GNU's instruction boundaries come from the encoded object independently.
    records = re.findall(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4,8})\s+\S+", listing, re.M)
    assert len(records) == len(expected)
    return tuple(
        (row, int(offset, 16), len(encoding) // 2)
        for row, (offset, encoding) in zip(expected, records)
    ), Image(data)


def test_corpus_state_and_flow(backend, corpus):
    cases, image = corpus
    for row, offset, length in cases:
        address = image.base + offset
        actual = backend.disassemble(image, address)
        assert actual.original_data == image.read(address, length), row.asm
        assert actual.length == length, row.asm
        assert {s.name for s in actual.modifies} == set(row.writes.split()), row.asm
        assert {s.name for s in actual.depends_on} == set(row.reads.split()), row.asm
        for state in actual.modifies + actual.depends_on:
            if state.name in _GPRS:
                assert state.kind is StateSpaceKind.REGISTER and state.size == backend.pointer_size
            elif state.name.startswith("f"):
                assert state.kind is StateSpaceKind.REGISTER and state.size == 8
            else:
                assert state.kind is StateSpaceKind.MEMORY and state.size == 1
        assert actual.flows_from == []
        assert actual.flows_to == [Address.absolute(address + length)], row.asm
        assert backend.decode_flows(image, address) == DecodedFlow(
            address, length, actual.type, tuple(actual.flows_to),
        )


def test_corpus_rejects_every_proper_prefix(backend, corpus):
    cases, image = corpus
    for row, offset, length in cases:
        address = image.base + offset
        for truncated in range(length):
            partial = Image(image.read(address, truncated), address)
            with pytest.raises(ValueError):
                backend.disassemble(partial, address)
            with pytest.raises(ValueError):
                backend.decode_flows(partial, address)


@pytest.mark.parametrize("encoding", ["0000", "1f0000000000", "ffffffff", "0280", "0240", "67100000", "63200000"])
def test_invalid_encodings(backend, encoding):
    image = Image(bytes.fromhex(encoding))
    with pytest.raises(ValueError):
        backend.disassemble(image, image.base)


def test_same_bytes_different_xlen():
    image = Image(bytes.fromhex("8525"))  # RV32 C.JAL, RV64 C.ADDIW a1,1
    assert create_isa("riscv32").disassemble(image, image.base).type is InstructionType.CALL
    word = create_isa("riscv64").disassemble(image, image.base)
    assert word.type is InstructionType.ARITHMETIC
    assert [state.name for state in word.modifies] == ["a1"]


@pytest.mark.parametrize(
    "encoding,kind,targets",
    [
        ("ef000001", InstructionType.CALL, [0x1010, 0x1004]),
        ("ef020001", InstructionType.CALL, [0x1010, 0x1004]),
        ("6f030001", InstructionType.BRANCH, [0x1010]),
        ("e310b5fe", InstructionType.BRANCH, [0x0FE0, 0x1004]),
        ("8280", InstructionType.RET, []),
        ("8282", InstructionType.RET, []),
        ("67800200", InstructionType.RET, []),
        ("8285", InstructionType.BRANCH, [Address.unknown_local()]),
        ("8295", InstructionType.CALL_INDIRECT, [Address.unknown_nonlocal(), 0x1002]),
        ("e7003501", InstructionType.CALL_INDIRECT, [Address.unknown_nonlocal(), 0x1004]),
        ("67003001", InstructionType.BRANCH, [0x12]),
        ("73000000", InstructionType.CALL_INDIRECT, [Address.unknown_nonlocal(), 0x1004]),
        ("0290", InstructionType.CALL_INDIRECT, [Address.unknown_nonlocal(), 0x1002]),
        ("73002030", InstructionType.RET, []),
    ],
)
def test_control_flow(backend, encoding, kind, targets):
    image = Image(bytes.fromhex(encoding))
    expected = tuple(t if isinstance(t, Address) else Address.absolute(t) for t in targets)
    actual = backend.decode_flows(image, image.base)
    assert actual == DecodedFlow(image.base, len(image.data), kind, expected)
    instruction = backend.disassemble(image, image.base)
    assert instruction.type is kind and list(expected) == instruction.flows_to


def test_abi_transfer_state(backend):
    image = Image(bytes.fromhex("8295"))
    call = backend.disassemble(image, image.base)
    writes = {state.name for state in call.modifies}
    reads = {state.name for state in call.depends_on}
    assert {"a0", "fa0", "t0", "ra", "ram", "csreg"} <= writes
    assert not {"sp", "s0", "s11", "gp", "tp", "zero"} & writes
    assert {"a0", "a7", "fa0", "fa7", "sp", "a1", "ram"} <= reads
    ret = backend.disassemble(Image(bytes.fromhex("8282")), 0x1000)
    assert {state.name for state in ret.depends_on} == {"t0"}


@pytest.mark.xfail(strict=True, reason="Ghidra 12.2 C.JALR P-code omits the target low-bit mask")
def test_pinned_ghidra_compressed_jalr_masks_target(backend):
    data = bytes.fromhex("8295")
    resolved = backend.spec.resolve(data, backend.context)
    assert resolved is not None
    assert backend.spec.mnemonic(resolved) == "c.jalr"
    assert OP_INT_AND in {op.opcode for op, _ in backend.spec._semantic_ops(resolved)}


@pytest.mark.xfail(strict=True, reason="Ghidra 12.2 FCLASS.S omits its GPR destination")
def test_pinned_ghidra_fclass_models_destination(backend):
    image = Image(bytes.fromhex("539505e0"))
    resolved = backend.spec.resolve(image.data, backend.context)
    flow = backend.decode_flows(image, image.base)
    writes, _ = SlaSpec._compute_state_effects(
        backend.spec, image.data, flow, resolved, image.base,
    )
    assert {state.name for state in writes} == {"a0"}


def test_unimplemented_vector_effects_are_conservative(backend, tmp_path):
    obj = assemble(tmp_path, backend.xlen, "vadd.vv v10,v12,v11", "v")
    image = Image(text_bytes(obj))
    instruction = backend.disassemble(image, image.base)
    assert {s.name for s in instruction.modifies} >= {"v0", "v31", "ram", "csreg"}
    assert instruction.modifies == instruction.depends_on
    assert not backend.can_encode(instruction, image.base + 2)


def test_atomic_reservation_state(backend, tmp_path):
    obj = assemble(tmp_path, backend.xlen, "lr.w.aq a0,(a1)\nsc.w.rl a0,a2,(a1)")
    image = Image(text_bytes(obj))
    reserve = {"RESERVE", "RESERVE_ADDRESS", "RESERVE_LENGTH"}
    load = backend.disassemble(image, image.base)
    store = backend.disassemble(image, image.base + 4)
    assert {state.name for state in load.modifies} == reserve | {"a0"}
    assert {state.name for state in load.depends_on} == {"a1", "ram"}
    assert {state.name for state in store.modifies} == reserve | {"a0", "ram"}
    assert {state.name for state in store.depends_on} == reserve | {"a1", "a2"}


@pytest.mark.parametrize(
    "asm,encoding,displacements",
    [
        ("bne a0,a1,", "6310b500", (-4096, -2, 2, 4094)),
        ("jal ra,", "ef000000", (-1048576, -2, 2, 1048574)),
        ("c.beqz a0,", "01c1", (-256, -2, 2, 254)),
        ("c.bnez a1,", "81e1", (-256, -2, 2, 254)),
        ("c.j", "01a0", (-2048, -2, 2, 2046)),
        ("c.jal", "0120", (-2048, -2, 2, 2046)),
    ],
)
def test_relocation_against_gnu_assembler(backend, tmp_path, asm, encoding, displacements):
    if asm == "c.jal" and backend.xlen == 64:
        return  # The same parcel selects C.ADDIW on RV64.
    image = Image(bytes.fromhex(encoding), 0x400000)
    instruction = backend.disassemble(image, image.base)
    for displacement in displacements:
        origin = image.base - displacement
        assert backend.can_encode(instruction, origin)
        assert backend.required_length(instruction, origin) == instruction.length
        relocated = backend.relocate_instruction(instruction, origin)
        mode = "rvc" if asm.startswith("c.") else "norvc"
        obj = assemble(tmp_path, backend.xlen, f".option {mode}\n{asm} .{displacement:+d}")
        linked = tmp_path / "fixture.elf"
        binutils(
            "ld", "-m", f"elf{backend.xlen}lriscv", "--no-relax",
            f"-Ttext={origin:#x}", "-e", "0", "-o", str(linked), str(obj),
        )
        assert relocated.original_data == text_bytes(linked)
        assert relocated.flows_to[0] == Address.absolute(image.base)
        retargeted = backend.set_instruction_target(instruction, Address.absolute(image.base + displacement))
        assert retargeted.original_data == relocated.original_data
        assert retargeted.flows_to[0] == Address.absolute(image.base + displacement)

    for displacement in (displacements[0] - 2, displacements[-1] + 2):
        origin = image.base - displacement
        assert not backend.can_encode(instruction, origin)
        with pytest.raises(ValueError):
            backend.relocate_instruction(instruction, origin)
        with pytest.raises(ValueError):
            backend.required_length(instruction, origin)
        with pytest.raises(ValueError):
            backend.set_instruction_target(instruction, Address.absolute(image.base + displacement))
    assert not backend.can_encode(instruction, image.base + 1)
    with pytest.raises(ValueError):
        backend.set_instruction_target(instruction, Address.absolute(image.base + 1))
    with pytest.raises(ValueError):
        backend.set_instruction_target(instruction, Address.unknown_nonlocal())


def test_auipc_relocation(backend):
    origin = 0x1280
    image = Image(bytes.fromhex("1735ffff"), origin)  # AUIPC a0,-13 pages
    instruction = backend.disassemble(image, origin)
    assert instruction.type is InstructionType.PC_RELATIVE
    relocated = backend.relocate_instruction(instruction, origin + 0x2000)
    assert relocated.original_data == bytes.fromhex("1715ffff")
    assert relocated.flows_to == [Address.absolute(origin + 0x2004)]
    assert not backend.can_encode(instruction, origin + 2)
    with pytest.raises(ValueError):
        backend.set_instruction_target(instruction, Address.absolute(origin))


def test_rv32_flow_wraps_at_xlen():
    image = Image(bytes.fromhex("ef008000"), 0xFFFFFFFC)
    decoded = create_isa("riscv32").decode_flows(image, image.base)
    assert decoded.flows_to == (Address.absolute(4), Address.absolute(0))


def test_range_parity_and_pointer_widths(backend):
    image = Image(bytes.fromhex("ff0100ef0000010100"), 0x1001)
    start, end = image.base, image.base + len(image.data)
    flows = list(backend.decode_range(image, start, end))
    for address, flow in zip(range(start, end), flows, strict=True):
        if address % 2:
            assert flow is None
        else:
            assert flow == backend.decode_flows(image, address)
    assert flows[-2].length == 2
    assert backend.try_interpret_as_pointer(image, end - 4) == {Address.absolute(0x00010100)}
    assert backend.try_interpret_as_pointer(image, end - 3) == set()


@pytest.mark.parametrize("mixed_widths", [False, True])
def test_batched_pointer_scan_matches_scalar_at_range_boundaries(backend, mixed_widths):
    wide = 0x1234567800002000
    image = Image(b"\x7f" + wide.to_bytes(8, "little") + (0x3000).to_bytes(4, "little"))
    targets = {0x2000, 0x3000} | ({wide} if mixed_widths else set())
    for start, end in ((0x1000, 0x100D), (0x1000, 0x100A), (0x0FFF, 0x1003)):
        expected = {
            (address, pointer.value)
            for address in range(start, end)
            for pointer in backend.try_interpret_as_pointer(image, address)
            if pointer.value in targets
        }
        found = list(backend.iter_pointer_references(image, start, end, targets))
        assert sorted(found) == sorted(expected)


def test_batched_decode_skips_malformed_forms_and_reads_across_scan_end(backend):
    image = Image(bytes.fromhex("1f0013000000ef00000013"))
    for start, end in ((0x1000, 0x100B), (0x1000, 0x1008), (0x0FFF, 0x1003)):
        expected = []
        for address in range(start, end):
            try:
                expected.append(backend.decode_flows(image, address))
            except ValueError:
                expected.append(None)
        assert list(backend.decode_range(image, start, end)) == expected
    assert list(backend.decode_range(image, 0x1000, 0x100B))[-1] is None
    assert backend.decode_flows(image, 0x1006).type is InstructionType.CALL


def test_targeted_control_flow_scan_matches_full_decode(backend):
    image = Image(bytes.fromhex("63040000 6700c0ff ef004000 01a0 1f00"))
    far = (1 << (backend.pointer_size * 8)) - 4
    assert list(backend.iter_control_flow_references(
        image, 0x1000, 0x1010, {0x1004, 0x1008, 0x100C, far},
    )) == [(0x1000, 0x1008), (0x1000, 0x1004), (0x1004, far), (0x100C, 0x100C)]

    # Visit every possible first parcel, including reserved encodings and
    # starts of four-byte instructions.
    corpus = b"".join(word.to_bytes(2, "little") for word in range(1 << 16))
    image = Image(corpus)
    targets = {0, far, *range(image.base, image.base + len(corpus), 46)}
    for start, end in (
        (image.base, image.base + len(corpus) - 1),
        (image.base + 1, image.base + 0x800),
        (image.base - 1, image.base + 16),
    ):
        found = list(backend.iter_control_flow_references(image, start, end, targets))
        expected = list(ISA.iter_control_flow_references(backend, image, start, end, targets))
        assert found == expected


def test_riscv_pipeline_keeps_materialized_addresses(tmp_path, backend):
    from binary.binary import Binary
    from codezip import main
    from input_parser import parse_re_file
    from uplifter import Uplifter

    obj = assemble(tmp_path, backend.xlen, """
        .global _start
        .option norvc
    _start:
    high:
        auipc t1,%pcrel_hi(callback)
        addi t2,zero,7
    low:
        addi a0,t1,%pcrel_lo(high)
        jalr ra,a0,0
    absolute_hi:
        lui t1,%hi(absolute_target)
    absolute_low:
        jalr ra,t1,%lo(absolute_target)
        addi a0,zero,0
        addi a7,zero,93
        ecall
    startup_end:
        .option rvc
        .p2align 6
    callback:
        c.jr ra
    callback_end:
        .p2align 6
    absolute_target:
        c.jr ra
    absolute_target_end:
        .p2align 6
    unused:
        c.jr ra
    unused_end:
    """)
    path = tmp_path / "fixture.elf"
    binutils("ld", "-m", f"elf{backend.xlen}lriscv", "--no-relax", "-e", "_start", "-o", str(path), str(obj))
    image = Binary(path)
    entries = {name: image.symbol_address(name) for name in ("_start", "callback", "absolute_target", "unused")}
    assert all(entries.values())
    export = tmp_path / "fixture.xml"
    ranges = []
    for name, address in entries.items():
        end = image.symbol_address("startup_end" if name == "_start" else f"{name}_end")
        ranges.append(
            f'<FUNCTION NAME="{name}" ENTRY_POINT="ram:{address:x}">'
            f'<ADDRESS_RANGE START="ram:{address:x}" END="ram:{end - 1:x}"/>'
            '</FUNCTION>'
        )
    export.write_text(
        '<PROGRAM><PROCESSOR NAME="RISCV" '
        f'LANGUAGE_PROVIDER="RISCV:LE:{backend.xlen}:default:gcc"/>'
        f'<FUNCTIONS>{"".join(ranges)}</FUNCTIONS></PROGRAM>'
    )
    parsed = parse_re_file(str(export))
    uplifter = Uplifter(parsed.isa, image)
    for function in parsed.functions:
        uplifter.uplift_function(function)
    uplifter.build_xrefs()
    for name, site in (("callback", "low"), ("absolute_target", "absolute_low")):
        function = uplifter.function_map[Address.absolute(entries[name])]
        assert Address.absolute(image.symbol_address(site)) in [ref.from_ for ref in function.incoming_references]

    output, receipt = tmp_path / "output.elf", tmp_path / "receipt.yaml"
    assert main([str(path), str(export), "-o", str(output), "--receipt", str(receipt)]) == 0
    unused = entries["unused"]
    assert receipt.read_text() == f"freed:\n  - address: {unused:#x}\n    length: 0x2\n"
    patched = bytearray(path.read_bytes())
    offset = image.virtual_to_file(unused)
    patched[offset:offset + 2] = b"\xff\xff"
    assert output.read_bytes() == patched


def test_reference_scan_recovers_stripped_gp_and_an_odd_indirect_target(tmp_path, backend):
    obj = assemble(tmp_path, backend.xlen, """
        .option norvc
        auipc gp,1
        addi gp,gp,32
        jalr zero,ra,0
        addi a0,gp,64
        .option rvc
        c.lui s0,0x8
        c.addi s0,19
        c.jr s0
    """)
    # Prepend a byte in the mapped image and start the scan at the odd address.
    image = Image(b"\xff" + text_bytes(obj), 0x0FFF)
    refs = set(backend.iter_address_references(image, image.base, 0x1016, {0x2060, 0x8012}))
    assert (0x100C, 0x2060) in refs
    assert (0x1014, 0x8012) in refs


@pytest.mark.parametrize("memory,write", [("lw a0,68(a1)", False), ("sw a0,68(a1)", True)])
def test_moving_auipc_preserves_following_memory_address(tmp_path, backend, memory, write):
    obj = assemble(tmp_path, backend.xlen, f".option norvc\nauipc a1,2\n{memory}")
    image = Image(text_bytes(obj))
    upper = backend.disassemble(image, image.base)
    memory_bytes = image.data[4:]
    target = 0x3044  # 0x1000 + (2 << 12) + 68
    new_address = image.base + 0x1000
    assert backend.can_encode(upper, new_address)
    moved = backend.relocate_instruction(upper, new_address)
    moved_image = Image(moved.original_data + memory_bytes, new_address)
    for source in (image, moved_image):
        references = backend.iter_address_references(
            source, source.base, source.base + len(source.data), {target},
        )
        assert (source.base + 4, target) in references
        instruction = backend.disassemble(source, source.base + 4)
        effects = instruction.modifies if write else instruction.depends_on
        assert "ram" in {state.name for state in effects}
