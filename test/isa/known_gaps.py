"""Known mismatches in the external Intel-corpus fixtures."""

from __future__ import annotations


GHIDRA_GAPS = {
    "VGETMANTSD xmm1 {k1}{z}, xmm2, xmm3/m64{sae}, imm8": (
        "Ghidra 12.2 SLEIGH omits the trailing imm8; see other_peoples_bugs.md"
    ),
    "VGETMANTSS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8": (
        "Ghidra 12.2 SLEIGH omits the trailing imm8; see other_peoples_bugs.md"
    ),
    "VREDUCESD xmm1 {k1}{z}, xmm2, xmm3/m64{sae}, imm8/r": (
        "Ghidra 12.2 SLEIGH omits the trailing imm8; see other_peoples_bugs.md"
    ),
    "VREDUCESS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8": (
        "Ghidra 12.2 SLEIGH omits the trailing imm8; see other_peoples_bugs.md"
    ),
    "VRNDSCALESS xmm1 {k1}{z}, xmm2, xmm3/m32{sae}, imm8": (
        "Ghidra 12.2 SLEIGH omits the trailing imm8; see other_peoples_bugs.md"
    ),
}

KNOWN_CORPUS_GAPS = {**GHIDRA_GAPS}
