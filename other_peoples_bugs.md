# External tool bugs affecting the x86-64 test corpus

The x86-64 coverage suite keeps five Intel-corpus entries as strict `xfail`
because the pinned Ghidra 12.2 SLEIGH specification disagrees with the
assembler. The cause is external to codezip.

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

## Resolved: NASM 2.16.01 PTWRITE prefix

NASM 2.16.01 emitted `PTWRITE r64/m64` and `PTWRITE r32/m32` without the
mandatory `F3` prefix:

```text
PTWRITE rax  ->  48 0f ae e0
PTWRITE eax  ->     0f ae e0
```

The cause was `x86/insns.dat` using the `np` ("no prefix") marker instead of
`f3`. The first byte sequence is not a valid PTWRITE: `48 0f ae e0` has ModRM
`mod=11` for an `0F AE /0` opcode and no matching constructor.

This was fixed upstream in commit `24275695ff2d952f754570391a2e141aa8a7305e`
(`x86/insns.dat: PTWRITE requires the F3 prefix`) and first released in NASM
2.16.02. The corpus is now generated with NASM 3.02, which emits
`f3 48 0f ae e0` and `f3 0f ae e0`; both decode and reassemble correctly, so no
PTWRITE entries remain in `test/isa/known_gaps.py`.

## Why keep the Ghidra entries failing

The corpus test compares the decoder against NASM's original and relocated
encodings. Keeping the five entries as strict `xfail` preserves the evidence
and makes the recovery condition explicit: remove the corresponding entry from
`test/isa/known_gaps.py` when the specification is fixed.
