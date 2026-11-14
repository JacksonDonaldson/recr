"""Core intermediate representation shared by every stage.

The normative description of these types lives in ``ir.md``.  This module
defines the data model; ISA-specific behaviour lives on the ISA implementations.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class AddressKind(Enum):
    """How a control-flow or data-flow target is known."""

    ABSOLUTE = auto()
    UNK_LOCAL = auto()
    UNK_NONLOCAL = auto()


@dataclass(frozen=True, slots=True)
class Address:
    """A resolved or unresolved location.

    ``value`` is meaningful only for :attr:`AddressKind.ABSOLUTE`.
    """

    kind: AddressKind
    value: int = 0

    @classmethod
    def absolute(cls, value: int) -> "Address":
        return cls(AddressKind.ABSOLUTE, value)

    @classmethod
    def unknown_local(cls) -> "Address":
        return cls(AddressKind.UNK_LOCAL)

    @classmethod
    def unknown_nonlocal(cls) -> "Address":
        return cls(AddressKind.UNK_NONLOCAL)


class StateSpaceKind(Enum):
    REGISTER = auto()
    FLAG = auto()
    MEMORY = auto()


@dataclass(frozen=True, slots=True)
class StateSpace:
    """A unit of machine state used for dependency tracking.

    Registers are canonical (sub-registers map to their parent), all flags are
    one state space, and memory is conservatively aliased until an alias
    analysis exists.
    """

    kind: StateSpaceKind
    name: str
    size: int

    # TODO(alias analysis): add base/index/scale/displacement or an opaque
    # alias set for memory state spaces.


class InstructionType(Enum):
    CALL = auto()
    CALL_INDIRECT = auto()
    BRANCH = auto()
    RET = auto()
    NOP = auto()
    ARITHMETIC = auto()
    RIP_RELATIVE = auto()
    OUTLINE_RESULT_CALL = auto()


@dataclass
class Instruction:
    """A single decoded machine instruction."""

    original_data: bytes
    type: InstructionType
    length: int
    address: int = 0

    outline_target: Optional["BasicBlock"] = None

    modifies: list[StateSpace] = field(default_factory=list)
    depends_on: list[StateSpace] = field(default_factory=list)
    flows_from: list[Address] = field(default_factory=list)
    flows_to: list[Address] = field(default_factory=list)


@dataclass
class BasicBlock:
    """A maximal straight-line sequence ending at a branch or return.

    Calls do not end a block.  The block owns its instructions.
    """

    start_location: Address
    containing_function: Optional["Function"] = None
    instructions: list[Instruction] = field(default_factory=list)
    used_for_outlining: bool = False


@dataclass
class Function:
    """A function recovered from the input description."""

    name: str
    file_offset: int
    start_address: int
    length: int

    basic_blocks: list[BasicBlock] = field(default_factory=list)
    incoming_references: list["Reference"] = field(default_factory=list)
    outgoing_references: list["Reference"] = field(default_factory=list)

    def has_unk_local_reference(self) -> bool:
        """Return whether any outgoing reference is :attr:`AddressKind.UNK_LOCAL`."""
        return any(
            reference.to.kind is AddressKind.UNK_LOCAL
            for reference in self.outgoing_references
        )

    def uses_red_zone(self) -> bool:
        """Return whether the function accesses the stack below the stack pointer."""
        raise NotImplementedError

    def pretty_print(self) -> None:
        """Write a human-readable dump of the uplifted function to stdout."""
        instruction_count = sum(
            len(block.instructions) for block in self.basic_blocks
        )
        print(
            f"function {self.name} @ {self.start_address:#x} "
            f"({self.length:#x} bytes, "
            f"{_format_count(len(self.basic_blocks), 'block')}, "
            f"{_format_count(instruction_count, 'instruction')})"
        )
        if self.file_offset >= 0:
            print(f"  file offset: {self.file_offset:#x}")

        if self.incoming_references:
            print(
                "  incoming references "
                f"({_format_count(len(self.incoming_references), 'reference')}):"
            )
            for reference in self.incoming_references:
                print(
                    f"    {_format_address(reference.from_)} -> "
                    f"{_format_address(reference.to)}"
                )

        if self.outgoing_references:
            print(
                "  outgoing references "
                f"({_format_count(len(self.outgoing_references), 'reference')}):"
            )
            for reference in self.outgoing_references:
                print(
                    f"    {_format_address(reference.from_)} -> "
                    f"{_format_address(reference.to)}"
                )

        for index, block in enumerate(self.basic_blocks):
            if index:
                print()
            byte_length = sum(
                instruction.length for instruction in block.instructions
            )
            print(
                f"  block {index} @ {_format_address(block.start_location)} "
                f"({_format_count(len(block.instructions), 'instruction')}, "
                f"{byte_length:#x} bytes)"
            )
            for instruction in block.instructions:
                details: list[str] = []
                if instruction.modifies:
                    details.append(
                        "mod=" + _format_states(instruction.modifies)
                    )
                if instruction.depends_on:
                    details.append(
                        "dep=" + _format_states(instruction.depends_on)
                    )
                if instruction.flows_from:
                    details.append(
                        "from=" + _format_addresses(instruction.flows_from)
                    )
                if instruction.flows_to:
                    details.append(
                        "to=" + _format_addresses(instruction.flows_to)
                    )

                prefix = (
                    f"    {instruction.address:#x}  "
                    f"{instruction.original_data.hex():<30} "
                    f"{instruction.type.name.lower():<14}"
                ).rstrip()
                suffix = "  " + " ".join(details) if details else ""
                if len(prefix) + len(suffix) <= _PRETTY_WIDTH:
                    print(prefix + suffix)
                    continue
                print(prefix)
                for detail in details:
                    for line in textwrap.wrap(
                        detail,
                        width=_PRETTY_WIDTH,
                        initial_indent=_DETAIL_INDENT,
                        subsequent_indent=_DETAIL_INDENT,
                        break_long_words=False,
                        break_on_hyphens=False,
                    ):
                        print(line)


_PRETTY_WIDTH = 110
_DETAIL_INDENT = "      "
_STATE_LIST_LIMIT = 20
_STATE_SAMPLE = 8


def _format_count(count: int, singular: str) -> str:
    """Render a count with a singular or regular plural noun."""
    noun = singular if count == 1 else singular + "s"
    return f"{count} {noun}"


def _format_states(states: list[StateSpace]) -> str:
    """Render a state list, summarizing very large conservative sets."""
    names = [state.name for state in states]
    if len(names) <= _STATE_LIST_LIMIT:
        return ", ".join(names)
    sample = ", ".join(names[:_STATE_SAMPLE])
    omitted = len(names) - _STATE_SAMPLE
    return f"{len(names)} states ({sample}, ... +{omitted})"


def _format_address(address: Address) -> str:
    """Render an :class:`Address` for diagnostics."""
    if address.kind is AddressKind.ABSOLUTE:
        return f"{address.value:#x}"
    return address.kind.name


def _format_addresses(addresses: list[Address]) -> str:
    """Render a list of addresses for diagnostics."""
    return "[" + ", ".join(_format_address(address) for address in addresses) + "]"


@dataclass(frozen=True)
class Reference:
    """A reference between two addresses."""

    # ``from`` is a Python keyword, so the field is named ``from_``.
    from_: Address
    to: Address


@dataclass
class FreeSpace:
    """A contiguous range that is no longer occupied by live code."""

    start: Address
    size: int
    diagnostic: str = ""
