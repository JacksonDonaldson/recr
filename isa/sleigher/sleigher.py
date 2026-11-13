"""Base interface for decoding instructions directly from a Ghidra SLA spec."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import ClassVar

from ir import Instruction
from isa.sleigher.sla import SlaSpec


class Sleigher:
    """Decode a byte stream with a parsed SLEIGH specification."""

    context_defaults: ClassVar[dict[str, int]] = {}

    def __init__(self, spec_path: str | Path) -> None:
        self.spec = SlaSpec(spec_path)
        self.context = self.spec.build_context(self.context_defaults)

    def parse(self, data: bytes, address: int = 0) -> Instruction | None:
        """Return the first instruction in ``data``, or ``None`` if unknown."""
        if not data:
            return None
        data = bytes(data)

        resolved = self.spec.resolve(data[:16], self.context)
        if resolved is None:
            return None
        if resolved.length <= 0 or resolved.length > len(data):
            return None
        return self.spec.make_instruction(data, address, resolved, self.context)

    def reassemble(
        self, instruction: Instruction, new_address: int
    ) -> Instruction | None:
        """Return ``instruction`` re-encoded for ``new_address``.

        Position-independent instructions keep their bytes.  Direct relative
        branches and calls keep their absolute target and have their
        displacement field repatched.  Returns ``None`` if the new
        displacement cannot be encoded.
        """
        if new_address < 0:
            raise ValueError("new address must be non-negative")

        data = bytes(instruction.original_data)
        resolved = self.spec.resolve(data, self.context)
        if resolved is not None:
            relative = self.spec.relative_target(
                resolved, data, instruction.address
            )
            if relative is not None:
                target, offset, size = relative
                displacement = target - (new_address + instruction.length)
                try:
                    encoded = displacement.to_bytes(size, "little", signed=True)
                except OverflowError:
                    return None
                data = (
                    data[:offset]
                    + encoded
                    + data[offset + size :]
                )

        flows_to = list(instruction.flows_to)
        if resolved is not None:
            flows_to = self.spec.flow_targets(
                resolved,
                data,
                new_address,
                self.spec.instruction_type(resolved),
            )

        return replace(
            instruction,
            original_data=data,
            address=new_address,
            modifies=list(instruction.modifies),
            depends_on=list(instruction.depends_on),
            flows_from=list(instruction.flows_from),
            flows_to=flows_to,
        )
