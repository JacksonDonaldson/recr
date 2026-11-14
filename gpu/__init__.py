"""Optional CUDA acceleration for whole-image instruction decoding.

The backend is optional: :func:`available` reports whether a device and a CUDA
compiler are present, and every caller has a CPU path.  Nothing here changes
decoding semantics; the kernels reimplement the same table-driven resolution as
:class:`isa.sleigher.sla.SlaSpec`.
"""

from __future__ import annotations

from gpu.backend import (
    KIND_ABSOLUTE,
    KIND_NONE,
    KIND_UNK_LOCAL,
    KIND_UNK_NONLOCAL,
    STATUS_DEFER,
    STATUS_FLOW,
    STATUS_STRAIGHT,
    STATUS_UNDECODED,
    BackendError,
    Device,
    Segment,
    build_error,
    library,
)
from gpu.tables import GpuTables, build_tables

__all__ = [
    "KIND_ABSOLUTE",
    "KIND_NONE",
    "KIND_UNK_LOCAL",
    "KIND_UNK_NONLOCAL",
    "STATUS_DEFER",
    "STATUS_FLOW",
    "STATUS_STRAIGHT",
    "STATUS_UNDECODED",
    "BackendError",
    "Device",
    "GpuTables",
    "Segment",
    "available",
    "build_error",
    "build_tables",
    "device_name",
]


def available() -> bool:
    """Return whether a usable CUDA device and compiler are present."""
    return build_error() is None


def device_name() -> str | None:
    """Return the CUDA device name, or ``None`` when unavailable."""
    try:
        return library().device_name()
    except BackendError:
        return None
