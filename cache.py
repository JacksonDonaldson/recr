"""Shared on-disk cache for codezip's derived, disposable data.

The compiled CUDA library and parsed SLEIGH specification live under one
root. Raw recr compaction uses a private per-user directory alongside it.
Entries are keyed by a content digest. Writers go through a temporary file
and an atomic rename so concurrent runs see only complete entries.
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
    with tempfile.TemporaryDirectory(dir=target.parent) as directory:
        temporary = Path(directory) / target.name
        writer(temporary)
        os.replace(temporary, target)
