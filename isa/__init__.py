"""ISA implementations and factory."""

from __future__ import annotations

from isa.isa import DecodedFlow, ISA
from isa.riscv import RISCV32ISA, RISCV64ISA
from isa.x86_64 import X86_64ISA

ISA_REGISTRY = {
    "x86_64": X86_64ISA,
    "riscv32": RISCV32ISA,
    "riscv64": RISCV64ISA,
}

__all__ = [
    "DecodedFlow", "ISA", "ISA_REGISTRY", "RISCV32ISA", "RISCV64ISA",
    "X86_64ISA", "create_isa",
]


def create_isa(name: str) -> ISA:
    """Instantiate the ISA implementation registered for ``name``."""
    try:
        isa_class = ISA_REGISTRY[name]
    except KeyError as exc:
        supported = ", ".join(sorted(ISA_REGISTRY))
        raise ValueError(f"unsupported ISA {name!r}; supported: {supported}") from exc
    return isa_class()
