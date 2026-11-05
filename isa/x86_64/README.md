# x86-64 ISA

The x86-64 backend will be driven by Ghidra's SLEIGH processor specification
instead of a hand-written instruction model. SLEIGH already defines the
address spaces, registers, context variables, disassembly semantics, and
P-code semantics we need for the IR.

## Layout

```text
isa/x86_64/
  __init__.py       # exports X86_64ISA
  isa.py            # current ISA backend scaffold
  ghidra/           # pinned Ghidra 12.2 x86-64 language files
  test/             # NASM assembly fixtures
```

## Ghidra specification

The files in `ghidra/` come from the latest Ghidra release, 12.2:

- `x86-64.sla` — compiled SLEIGH specification consumed by the SLEIGH runtime.
- `x86-64.slaspec` — top-level SLEIGH source. Rebuilding it requires the rest
  of Ghidra's `Processors/x86/data/languages` tree.
- `x86-64.pspec` — processor spec for `x86:LE:64:default`.
- `x86.ldefs` — language definitions used to locate the spec.

Source tag:
[`Ghidra_12.2_build`](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build),
`Ghidra/Processors/x86/data/languages/`.

The compiled `x86-64.sla` is byte-identical to the copy bundled with
`pypcode` 4.1.0, which vendors Ghidra 12.2.

## Python interface research

`pypcode` is the most practical existing Python interface. It is a
pybind11 binding to Ghidra's SLEIGH library and supports:

- disassembly (`Context.disassemble`),
- P-code translation (`Context.translate`),
- register and address-space metadata through `Varnode`,
- loading a specific compiled `.sla` through `Arch` and `ArchLanguage`.

`pypcode` exposes state spaces through varnodes (`Varnode.space`, `offset`, and
`size`) and register metadata. It does not expose the entire SLEIGH symbol
table, cannot enumerate all address spaces, and has no assembler/encoder API.
It is therefore not sufficient on its own for full state-space discovery or
reassembly.

Example using the pinned spec:

```python
from pathlib import Path

from pypcode import Arch, Context

spec_dir = Path("isa/x86_64/ghidra")
arch = Arch("x86", str(spec_dir / "x86.ldefs"))
language = next(
    lang for lang in arch.languages if lang.id == "x86:LE:64:default"
)
ctx = Context(language)
disassembly = ctx.disassemble(bytes.fromhex("83c020"))
```

Documentation: [pypcode](https://api.angr.io/projects/pypcode/en/latest/).

Alternatives:

- **PyGhidra** (official): exposes the full Ghidra Java API, including the
  complete SLEIGH address-space and symbol tables. It needs Ghidra and a JDK
  and is much heavier than `pypcode`.
  [PyGhidra README](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- **ghidra_bridge / Ghidrathon**: Python scripting inside or against a running
  Ghidra instance; useful for full-API access but not a standalone parser.
- **libsla**: Rust bindings to Ghidra's SLEIGH library, not a Python package.
  [libsla](https://crates.io/crates/libsla)
- **lifting-bits/sleigh**: C++ build and CLI for SLEIGH, no maintained Python
  binding. [lifting-bits/sleigh](https://github.com/lifting-bits/sleigh)

Current preference: use `pypcode` for fast, in-process disassembly and P-code,
but use the Ghidra Java API through PyGhidra when full state-space metadata or
reassembly is required.

## Reassembly

Ghidra's Java assembler (`ghidra.app.plugin.assembler.Assemblers`) is generic
over SLEIGH languages and can assemble x86-64. With Ghidra 12.2 headless:

```text
ADD EAX,0x20                 -> 83c020
MOV RAX,0x1122334455667788   -> 48b88877665544332211
```

It does not guarantee the encoding length or form we want. For example, at
`0x400000` it assembled `JMP 0x401070` as `66e96c10`, a 16-bit relative form.
Any use of the assembler must therefore constrain selection and verify the
result with disassembly, `can_encode`, and length checks.

Full state-space access is available through the Ghidra `Language` API:

- `Language.getAddressFactory().getAllAddressSpaces()`
- `Language.getRegisters()` / `Language.getContextRegisters()`
- `Language.parse(...)` for the matched `InstructionPrototype`

## Test fixture

`test/test.s` is a single `add eax, 0x20` instruction. Build it with:

```sh
make -C isa/x86_64/test
```
