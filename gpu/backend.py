"""Probe, compile, and drive the optional CUDA backend.

The kernel library is compiled from :mod:`gpu.kernels` on first use and cached
in the system temporary directory, keyed by the source text and the compiler
version.  Everything here degrades to :class:`BackendError` when no compiler or
no device is available; callers fall back to the CPU path.
"""

from __future__ import annotations

from array import array
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import cache

SOURCE = Path(__file__).with_name("kernels.cu")
CACHE_ROOT = cache.CACHE_ROOT
BUILD_TIMEOUT = 300

# Status bytes returned per address.
STATUS_UNDECODED = 0
STATUS_STRAIGHT = 1
STATUS_DEFER = 2
STATUS_FLOW = 3

# Flow-target kinds returned per address.
KIND_ABSOLUTE = 0
KIND_UNK_LOCAL = 1
KIND_UNK_NONLOCAL = 2
KIND_NONE = 3


class BackendError(RuntimeError):
    """Raised when the CUDA backend cannot be built or used."""


def _nvcc_version(nvcc: str) -> str:
    result = subprocess.run(
        [nvcc, "--version"], capture_output=True, text=True, check=False
    )
    return result.stdout or result.stderr


def build_library() -> Path:
    """Compile the kernel library, reusing a cached build when possible."""
    nvcc = shutil.which("nvcc")
    if nvcc is None:
        raise BackendError("nvcc was not found on PATH")

    digest = hashlib.sha256()
    digest.update(SOURCE.read_bytes())
    digest.update(_nvcc_version(nvcc).encode())
    output_dir = CACHE_ROOT / digest.hexdigest()[:20]
    output = output_dir / "libcodezip_cuda.so"
    if output.exists():
        return output

    output_dir.mkdir(parents=True, exist_ok=True)
    temporary = output_dir / f".{os.getpid()}.so"
    command = [
        nvcc,
        "-O3",
        "-std=c++17",
        "-shared",
        "-Xcompiler",
        "-fPIC",
        "-o",
        str(temporary),
        str(SOURCE),
        "-lcudart",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            check=False,
        )
    except OSError as exc:
        raise BackendError(f"cannot run nvcc: {exc}") from exc
    if result.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = result.stderr.strip() or result.stdout.strip() or "nvcc produced no diagnostics"
        raise BackendError(f"{nvcc} failed to compile {SOURCE} (exit status {result.returncode}). {detail}")
    os.replace(temporary, output)
    return output


def _pointer(ctype, values) -> ctypes.Array:
    """Return a ctypes array that shares ``values``' buffer."""
    address, length = values.buffer_info()
    return ctypes.cast(address, ctypes.POINTER(ctype))


class Library:
    """The compiled kernel library with typed entry points."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lib = ctypes.CDLL(str(path))
        lib = self.lib

        lib.codezip_probe.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.codezip_probe.restype = ctypes.c_int
        lib.codezip_error.argtypes = [ctypes.c_int]
        lib.codezip_error.restype = ctypes.c_char_p

        lib.codezip_open.argtypes = [
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_int32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_int64,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.codezip_open.restype = ctypes.c_int
        lib.codezip_close.argtypes = [ctypes.c_void_p]
        lib.codezip_close.restype = None

        lib.codezip_check_addresses.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.codezip_check_addresses.restype = ctypes.c_int

        lib.codezip_decode_range.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_int,
            ctypes.c_int64,
            ctypes.c_int64,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.codezip_decode_range.restype = ctypes.c_int

        lib.codezip_scan_pointers.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int64,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_int64),
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_int,
        ]
        lib.codezip_scan_pointers.restype = ctypes.c_int

    def device_name(self) -> str | None:
        buffer = ctypes.create_string_buffer(256)
        count = self.lib.codezip_probe(buffer, len(buffer))
        if count <= 0:
            return None
        return buffer.value.decode("utf-8", "replace")

    def error(self, code: int) -> str:
        message = self.lib.codezip_error(code)
        return message.decode("utf-8", "replace") if message else str(code)


_library: Library | None = None
_library_error: str | None = None


def library() -> Library:
    """Return the compiled library, building it on first use."""
    global _library, _library_error
    if _library is not None:
        return _library
    if _library_error is not None:
        raise BackendError(_library_error)
    try:
        candidate = Library(build_library())
        if candidate.device_name() is None:
            raise BackendError("no CUDA device is available")
    except BackendError as exc:
        _library_error = str(exc)
        raise
    _library = candidate
    return _library


def build_error() -> str | None:
    """Return why the backend is unavailable, or ``None`` if it is usable."""
    try:
        library()
    except BackendError as exc:
        return str(exc)
    return None


@dataclass(frozen=True)
class Segment:
    virtual_address: int
    file_offset: int
    file_size: int
    memory_size: int


class Device:
    """Decode tables and a binary image resident on one CUDA device."""

    def __init__(
        self,
        tables: array,
        image: bytes,
        segments: list[Segment],
    ) -> None:
        self._handle = ctypes.c_void_p()
        if not segments:
            raise BackendError("an image needs at least one mapped segment")
        if any(segment.virtual_address + segment.memory_size >= 1 << 63 for segment in segments):
            raise BackendError("CUDA image addresses must fit in signed 64 bits")
        self._library = library()
        self._tables = tables
        self._image = image
        self._segments = segments

        table_array = ctypes.cast(
            _pointer(ctypes.c_uint32, tables), ctypes.POINTER(ctypes.c_uint32)
        )
        image_array = ctypes.cast(
            ctypes.c_char_p(image), ctypes.POINTER(ctypes.c_uint8)
        )
        segment_array = (ctypes.c_int64 * (4 * len(segments)))()
        for index, segment in enumerate(segments):
            base = index * 4
            segment_array[base] = segment.virtual_address
            segment_array[base + 1] = segment.file_offset
            segment_array[base + 2] = segment.file_size
            segment_array[base + 3] = segment.memory_size

        code = self._library.lib.codezip_open(
            table_array,
            len(tables),
            image_array,
            len(image),
            segment_array,
            len(segments),
            ctypes.byref(self._handle),
        )
        if code != 0:
            raise BackendError(f"CUDA image upload failed for {len(image)} bytes in {len(segments)} mapped segments. {self._library.error(code)}")

    def close(self) -> None:
        if self._handle:
            self._library.lib.codezip_close(self._handle)
            self._handle = ctypes.c_void_p()

    def __del__(self) -> None:
        self.close()

    def check_addresses(self, start: int, count: int) -> bytes:
        """Return the contiguous mapped byte count after each address."""
        if count <= 0:
            return b""
        buffer = (ctypes.c_uint8 * count)()
        code = self._library.lib.codezip_check_addresses(
            self._handle, start, count, buffer
        )
        if code != 0:
            raise BackendError(f"CUDA address check failed for {count} addresses from {start:#x}. {self._library.error(code)}")
        return bytes(buffer)

    def decode_range(
        self,
        start: int,
        count: int,
        avail: bytes,
        root: int,
        context: int,
    ):
        """Decode every address in one batch.

        Returns ``(status, types, lengths, targets, kinds)``.  ``targets`` holds
        two flow targets per address and ``kinds`` two kind bytes; unused slots
        are :data:`KIND_NONE`.
        """
        if count <= 0:
            return b"", b"", b"", (), b""
        availability = (ctypes.c_uint8 * count).from_buffer_copy(avail)
        status = (ctypes.c_uint8 * count)()
        types = (ctypes.c_uint8 * count)()
        length = (ctypes.c_uint16 * count)()
        targets = (ctypes.c_int64 * (count * 2))()
        kinds = (ctypes.c_uint8 * (count * 2))()
        code = self._library.lib.codezip_decode_range(
            self._handle,
            start,
            count,
            availability,
            root,
            context & 0xFFFFFFFF,
            (context >> 32) & 0xFFFFFFFF,
            status,
            types,
            length,
            targets,
            kinds,
        )
        if code != 0:
            raise BackendError(f"CUDA instruction decode failed for {count} addresses from {start:#x}. {self._library.error(code)}")
        return bytes(status), bytes(types), bytes(length), targets, bytes(kinds)

    def scan_pointers(
        self, start: int, count: int, entries: list[int]
    ) -> list[tuple[int, int]]:
        """Return ``(address, target)`` for pointer readings of known entries."""
        if count <= 0 or not entries:
            return []
        ordered = sorted(set(entries))
        values = array("q", ordered)
        maximum = count * 2
        hits = (ctypes.c_int64 * (maximum * 2))()
        written = ctypes.c_int(0)
        code = self._library.lib.codezip_scan_pointers(
            self._handle,
            start,
            count,
            _pointer(ctypes.c_int64, values),
            len(ordered),
            hits,
            ctypes.byref(written),
            maximum,
        )
        if code != 0:
            raise BackendError(f"CUDA pointer scan failed for {count} addresses from {start:#x}. {self._library.error(code)}")
        total = min(written.value, maximum)
        return [(hits[index * 2], hits[index * 2 + 1]) for index in range(total)]
