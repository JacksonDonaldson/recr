# RISC-V ISA

The RV32 and RV64 little-endian backends use the shared packed SLEIGH parser.
The compiled specifications in `ghidra/` are from Ghidra 12.2,
`Ghidra/Processors/RISCV/data/languages/`. The corresponding processor specs
set `MXL` to 1 for ILP32D and 2 for LP64D.

| Specification | SHA-256 |
| --- | --- |
| `riscv.ilp32d.sla` | `1344c5d0875db3602a9d2a2752bf4d58d1fc6b495386465bb6a8bde29e5b4d6a` |
| `riscv.lp64d.sla` | `f9b79778dac6ed67836795cdc783b19be624fd78bbe51b937f54ce3b9f7af207` |

## Decoding and relocation

The decoder reads one 16-bit or 32-bit instruction at a time. It rejects
unaligned addresses, truncated parcels, unsupported longer instruction
lengths, and unresolved constructors. Integer and floating-point register
state uses ABI names. RAM, CSR accesses, and atomic reservations are tracked
separately. Instructions with absent P-code, including most vector forms in
the pinned spec, have opaque state effects.

Relocation preserves the absolute destinations of direct jumps and branches.
It preserves the value of an AUIPC result when the new PC leaves that value
encodable in the original instruction width. The encoder rejects relocation
that would require editing a separate low-immediate instruction.

## Outlining

The shared call uses `jal t0, target` and the return uses `jalr zero, 0(t0)`.
Both encodings are four bytes, and stack-relative operands keep their offsets.
A backward liveness analysis follows all CFG paths and checks the reordered
suffix at each candidate site. Calls and unresolved exits can observe a live
`t0` value. A standard ABI return leaves it dead unless the return uses it.
The shared block may contain scalar instructions that leave `t0` alone.
Functions with LR/SC are excluded to preserve reservation progress guarantees.

## Cross-references

The pipeline scans raw pointer values and direct control flow and runs the
RISC-V address-construction scan at every aligned offset in each mapped range,
including data. The address scan tracks constants through LUI, AUIPC, immediate
and register arithmetic, compressed forms, loads, and indirect jumps. It also
uses the ELF global pointer symbol or the conventional startup sequence that
initializes GP. The scan follows linear instruction sequences. References
that depend on runtime values or nonlocal register data flow remain outside
its scope.

## Tests

`test/isa/test_riscv.py` uses GNU RISC-V binutils to assemble both RV32 and RV64
fixtures. Tests check instruction boundaries against GNU objdump, register and
memory effects against independently specified results, branch relocations
against GNU-linked bytes, and every proper prefix of the assembled corpus.
The full RV64 pipeline also runs the pcre2 suite and pcre2grep corpus under QEMU.

```sh
python -m pytest -q test/isa/test_riscv.py
make -C test e2e-riscv
```
