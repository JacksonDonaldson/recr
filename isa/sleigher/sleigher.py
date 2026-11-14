"""Base interface for decoding instructions directly from a Ghidra SLA spec."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import ClassVar

from ir import Instruction
from isa.isa import DecodedFlow
from isa.sleigher.sla import ResolvedConstructor, SlaSpec


class Sleigher:
    """Decode a byte stream with a parsed SLEIGH specification."""

    context_defaults: ClassVar[dict[str, int]] = {}

    def __init__(self, spec_path: str | Path) -> None:
        self.spec = SlaSpec(spec_path)
        self.context = self.spec.build_context(self.context_defaults)

    def parse(self, data: bytes, address: int = 0) -> Instruction | None:
        """Return the first instruction in ``data``, or ``None`` if unknown."""
        payload, resolved = self._resolve_first(data)
        if resolved is None:
            return None
        return self.spec.make_instruction(
            payload, address, resolved, self.context
        )

    def parse_flow(
        self, data: bytes, address: int = 0
    ) -> DecodedFlow | None:
        """Return the first instruction's control flow, or ``None``.

        This skips the state-effect analysis that :meth:`parse` performs; the
        result is identical for the fields it reports.
        """
        payload, resolved = self._resolve_first(data)
        if resolved is None:
            return None
        return self.spec.decode_flow(payload, address, resolved)

    def _resolve_first(
        self, data: bytes
    ) -> tuple[bytes, ResolvedConstructor | None]:
        """Return the bytes and constructor of the first instruction."""
        if not data:
            return b"", None

        payload = bytes(data)
        resolved = self.spec.resolve(payload[:16], self.context)
        if (
            resolved is None
            or resolved.length <= 0
            or resolved.length > len(payload)
        ):
            return payload, None
        return payload, resolved

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
