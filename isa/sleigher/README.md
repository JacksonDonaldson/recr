# sleigher

Direct reader and interpreter for Ghidra's compiled SLEIGH `.sla` files.

## Modules

- `sla.py` decodes the packed format, address spaces, symbol table,
  constructors, decision trees, pattern expressions, and P-code templates.
- `sleigher.py` is the base decoder interface (`parse`, `reassemble`).
- `x86_sleigher.py` binds the pinned x86-64 specification and context defaults.

## Current coverage

`X86Sleigher` decodes instructions by resolving the SLEIGH decision tree and
constructor operands recursively. It applies constructor context changes, which
covers prefix wrappers such as REX, VEX, and EVEX, and propagates the updated
context into nested constructors. Registers, flags, and memory effects are
derived from the constructor's P-code template.

Registers are canonicalized before they reach the IR: GPR subregisters map to
their 64-bit parent, vector views and XMM/YMM registers map to ZMM, MM views map
to MM, x87 high words map to ST, and flags/eflags/rflags as well as the x87
condition codes C0-C3 map to the single flag state. SLEIGH scratch registers
(for example `XmmResult`, `xmmTmp*`, and `BCST*`) are excluded rather than
leaked as machine state.

Opaque userops are handled conservatively. A `CALLOTHER` with no result
varnode, or the `cpuid` family (whose implicit input is not in P-code), is
treated as reading and writing every tracked register, flag, and memory state.
Userops whose results are fully described by P-code keep their precise effects.

Tests cover a data-driven matrix of x86-64 instructions, a hand-written
category matrix covering partial registers, SIMD, x87, mask registers, memory
addressing, and segments, and a committed golden file with canonical
modifies/depends-on sets for every decodable Intel form. Malformed and
truncated byte sequences are required to return `None`, and every proper prefix
of a valid corpus form is rejected (except the standalone `FWAIT` instruction).

The Intel 64-bit instruction corpus under `isa/x86_64/test/` covers all 3,377
unique valid forms from the Intel instruction tables. Every form is decoded and
reassembled, with bytes checked against NASM assembled at a relocated origin.
Five forms are marked xfail for one external-tool bug documented in
`other_peoples_bugs.md`: EVEX forms that Ghidra 12.2 SLEIGH decodes without
their trailing immediate.

`reassemble()` preserves position-independent encodings and repatches direct
relative branch/call and RIP-relative displacement fields so the absolute
target stays fixed. Dedicated tests cover RIP-relative loads, stores, `lea`,
`cmp`, `call`, `jmp`, vector loads, target preservation, and disp32 overflow
rejection.

This is not a full SLEIGH compiler. It implements the runtime subset needed for
instruction decoding, state-space recovery, and relative relocation.
