"""Shared on-disk cache for codezip's derived, disposable data.

Two things live here: the compiled CUDA kernel library and the parsed SLEIGH
specification.  Entries are keyed by a content digest, so changing the input
produces a different entry rather than a stale one.  Writers go through a
temporary file and an atomic rename, so concurrent runs either see a complete
entry or none at all.

The directory name predates the parse cache; everything derived and
disposable lives under this one root.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Callable

CACHE_ROOT = Path(tempfile.gettempdir()) / "codezip-cuda"


def entry_path(namespace: str, key: str, suffix: str) -> Path:
    """Return the path of one cache entry."""
    return CACHE_ROOT / namespace / f"{key}{suffix}"


def replace(target: Path, writer: Callable[[Path], None]) -> None:
    """Fill ``target`` through a temporary file, then rename it into place."""
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{os.getpid()}-{target.name}")
    try:
        writer(temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
