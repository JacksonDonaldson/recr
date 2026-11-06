# External tool bugs affecting the x86-64 test corpus

The x86-64 coverage suite keeps seven Intel-corpus entries as strict `xfail`
because the expected bytes come from external tools that disagree with the
pinned Ghidra specification. Both causes are external to codezip.

## Ghidra 12.2 SLEIGH: missing EVEX immediate

Affected forms:

- `VGETMANTSD xmm1 {k1}{z}, xmm2, xmm3/m64{sae}, imm8`
- `VGETMANTSS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8`
- `VREDUCESD xmm1 {k1}{z}, xmm2, xmm3/m64{sae}, imm8/r`
- `VREDUCESS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8`
- `VRNDSCALESS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8`

The pinned `x86-64.sla` constructor for each form ends after the ModRM byte and
does not consume the trailing `imm8`. For example, NASM encodes
`VGETMANTSD xmm1, xmm2, xmm3, 1` as seven bytes:

```text
62 f3 ed 08 27 cb 01
```

The SLEIGH decoder resolves only six bytes:

```text
62 f3 ed 08 27 cb
```

That leaves the final byte to be misread as a separate instruction, so these
forms cannot be safely decoded until the specification is updated or a targeted
workaround is added. The tests remain strict `xfail` so they start passing as
soon as the pinned specification is replaced.

## NASM 2.16.01: PTWRITE is emitted without `F3`

Affected forms:

- `PTWRITE r64/m64`
- `PTWRITE r32/m32`

Intel documents PTWRITE as `F3 0F AE /4` (`F3 REX.W 0F AE /4` for the 64-bit
form). NASM 2.16.01 on this machine emits the forms without the mandatory `F3`
prefix:

```text
PTWRITE rax  ->  48 0f ae e0
PTWRITE eax  ->     0f ae e0
```

The first byte sequence is not a valid PTWRITE. In fact
`48 0f ae e0` has ModRM `mod=11` for an `0F AE /0` opcode, which is invalid for
FXSAVE and has no matching constructor.

The pinned SLEIGH specification does decode correctly encoded PTWRITE. Both of
these are accepted as four- and five-byte instructions:

```text
f3 0f ae e0      -> PTWRITE (4 bytes)
f3 48 0f ae e0   -> PTWRITE (5 bytes)
```

The corpus generator should use those bytes directly (or a fixed NASM) rather
than relying on NASM's `PTWRITE` mnemonic. Until then the two corpus entries
remain strict `xfail`.

## Why keep them failing

The corpus test compares the decoder against NASM's original and relocated
encodings. Keeping the entries as strict `xfail` preserves the evidence and
makes the recovery condition explicit: remove the corresponding entry from
`test/isa/known_gaps.py` when the specification or assembler is fixed.
