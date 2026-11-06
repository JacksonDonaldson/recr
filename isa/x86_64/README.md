# x86-64 ISA

The x86-64 backend will be driven by Ghidra's SLEIGH processor specification
instead of a hand-written instruction model. SLEIGH already defines the
address spaces, registers, context variables, disassembly semantics, and
P-code semantics we need for the IR.

## Layout

```text
isa/x86_64/
  __init__.py       # exports X86_64ISA
  isa.py            # decoding, outlining checks, stack-space biasing
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

## Python interface research

Existing Python interfaces wrap Ghidra's SLEIGH library, but none expose both
the complete address-space/symbol metadata and an encoder suitable for
codezip's reassembly requirements.

Alternatives:

- **PyGhidra** (official): exposes the full Ghidra Java API, including the
  complete SLEIGH address-space and symbol tables. It needs Ghidra and a JDK
  and is much heavier.
  [PyGhidra README](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
- **ghidra_bridge / Ghidrathon**: Python scripting inside or against a running
  Ghidra instance; useful for full-API access but not a standalone parser.
- **libsla**: Rust bindings to Ghidra's SLEIGH library, not a Python package.
  [libsla](https://crates.io/crates/libsla)
- **lifting-bits/sleigh**: C++ build and CLI for SLEIGH, no maintained Python
  binding. [lifting-bits/sleigh](https://github.com/lifting-bits/sleigh)

Chosen approach: parse the compiled `.sla` directly in `isa/sleigher/`. It
exposes the full address spaces, symbol table, and the encoding path needed for
instruction relocation.

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

## Outlining and stack-relative operands

`X86_64ISA.is_outlinable` rejects control-flow instructions, anything that
modifies RSP, and anything that uses RSP as a value rather than only as an
address base.  It also rejects trap and control-transfer mnemonics such as
`INT`, `INT3`, `HLT`, `UD2`, and `RSM`, which the SLEIGH decoder classifies as
`ARITHMETIC`, and stack-relative memory operands that cannot be biased in
place.

`X86_64ISA.add_extra_stack_space` adds the pointer size to every explicit
memory operand whose base is RSP.  RBP is callee-saved and is not changed by
the outlining call, so its displacement is left alone.  The method re-encodes
the existing displacement field and refuses to change the instruction length.
Forms with no displacement field (for example `[rsp]` or `[rsp+rax*4]`) cannot
grow, and a disp8 that would overflow to disp32 is rejected.  EVEX disp8
operands are compressed by the instruction's tuple size; the pinned SLEIGH
specification does not expose that size reliably for every form, so those are
rejected conservatively rather than encoded with a possibly wrong effective
address.  The EVEX prefix is found after any legacy prefixes, so forms such as
`[esp+...]` and segment-relative operands are covered.  EVEX disp32 operands
are handled normally.  The pinned SLEIGH model for `INVPCID` also resolves its
register operand from the r/m field, so stack-relative `INVPCID` forms are
conservatively treated as RSP value uses.

## Test fixtures

`test/opcodes.s` holds the multi-opcode decoder matrix.
`test/intel_64bit_forms.txt` is the full
Intel 64-bit instruction-form corpus, assembled through NASM by
`test/intel_cases.py`. Build all fixtures with:

```sh
make -C isa/x86_64/test
```
