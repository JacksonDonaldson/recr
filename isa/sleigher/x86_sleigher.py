"""x86-64 SLEIGH decoder."""

from __future__ import annotations

from pathlib import Path

from isa.sleigher.sleigher import Sleigher

DEFAULT_SPEC_PATH = (
    Path(__file__).resolve().parent.parent / "x86_64" / "ghidra" / "x86-64.sla"
)


class X86Sleigher(Sleigher):
    """Decode x86-64 instructions from the pinned Ghidra SLA specification."""

    context_defaults = {
        "longMode": 1,
        "addrsize": 2,
        "opsize": 1,
        "rexprefix": 0,
    }

    def __init__(self, spec_path: str | Path | None = None) -> None:
        super().__init__(spec_path or DEFAULT_SPEC_PATH)
