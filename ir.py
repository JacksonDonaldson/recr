"""Core intermediate representation shared by every stage.

The normative description of these types lives in ``ir.md``.  This module is
only a scaffold: it defines the data model and leaves the behavioural methods
unimplemented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class AddressKind(Enum):
    """How a control-flow or data-flow target is known."""

    ABSOLUTE = auto()
    UNK_LOCAL = auto()
    UNK_NONLOCAL = auto()


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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

    def is_outlinable(self) -> bool:
        """Return whether this instruction may be moved into an outlined block."""
        raise NotImplementedError

    def add_extra_stack_space(self, pointer_size: int) -> None:
        """Bias stack-relative memory operands by ``pointer_size`` bytes.

        Used for instructions that are outlined, because they run with that
        many more bytes on the stack.
        """
        raise NotImplementedError


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
        raise NotImplementedError

    def uses_red_zone(self) -> bool:
        """Return whether the function accesses the stack below the stack pointer."""
        raise NotImplementedError


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
