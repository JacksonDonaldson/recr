"""Compile a .rec translation unit into a statically linkable ELF object."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import subprocess


HOOK_PREFIX = "__recr_hook_"
_C_TOKENS = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\[\s\S]|[^"\\])*"|'
    r"'(?:\\[\s\S]|[^'\\])*'|@(?P<hook>[A-Za-z_][A-Za-z_0-9]*)",
    re.DOTALL,
)
_CONFLICT = re.compile(
    r"(?:conflicting types for|(?:static|non-static) declaration of|)"
    r"\s*['‘]([A-Za-z_]\w*)['’](?: redeclared as different kind of symbol)?"
)


def rewrite_hooks(source: str) -> tuple[str, tuple[str, ...]]:
    hooks: dict[str, None] = {}

    def replace(match: re.Match[str]) -> str:
        name = match["hook"]
        if name is None:
            return match[0]
        hooks[name] = None
        return HOOK_PREFIX + name

    return _C_TOKENS.sub(replace, source), tuple(hooks)


def _shadowed(stderr: str, header: Path, names: set[str]) -> set[str]:
    found: set[str] = set()
    for line in stderr.splitlines():
        if not line.startswith("["):
            continue
        try:
            diagnostics = json.loads(line)
        except ValueError:
            continue
        for diagnostic in diagnostics:
            if diagnostic.get("kind") != "error":
                continue
            match = _CONFLICT.match(diagnostic.get("message", ""))
            if match is None or match[1] not in names:
                continue
            for note in diagnostic.get("children", []):
                if any(
                    location.get("caret", {}).get("file") == str(header)
                    for location in note.get("locations", [])
                ):
                    found.add(match[1])
    return found


def compile_rec(
    source: Path, rewritten: str, hooks: tuple[str, ...],
    declarations: dict[str, str], flags: list[str], compiler: str, directory: Path,
) -> Path:
    header = directory / "imports.h"
    translation_unit = directory / "extension.c"
    obj = directory / "extension.o"
    translation_unit.write_text(f"#line 1 {json.dumps(str(source))}\n{rewritten}", encoding="utf-8")
    roots = ["-Wl,--gc-sections", *(f"-Wl,-u,{HOOK_PREFIX}{name}" for name in hooks)] if hooks else []
    driver = shlex.split(compiler)
    if not driver:
        raise ValueError("missing GCC executable")
    command = [
        *driver, "-m64", "-std=gnu17", "-Os", "-fno-pie", "-fno-pic",
        "-fno-builtin", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables", "-fno-jump-tables", "-ffunction-sections",
        "-fdata-sections", "-fno-lto", "-Werror=implicit-function-declaration",
        "-iquote", str(source.parent), "-include", str(header), "-static",
        "-r", "-nostdlib", "-no-pie", *roots,
        str(translation_unit), *flags, "-fdiagnostics-format=json", "-o", str(obj),
    ]
    imported = dict(declarations)
    while True:
        header.write_text(
            "#include <stddef.h>\n#include <stdint.h>\n#include <sys/types.h>\n"
            + "\n".join(imported.values()) + "\n"
            + "\n".join(
                f"extern __typeof__({name}) {HOOK_PREFIX}{name};"
                for name in hooks if name in imported
            ) + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            command, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"},
        )
        if result.returncode == 0:
            return obj
        overridden = _shadowed(result.stderr, header, set(imported))
        if not overridden:
            result = subprocess.run(
                [arg for arg in command if arg != "-fdiagnostics-format=json"],
                capture_output=True, text=True,
            )
            raise ValueError(f"GCC failed to compile or link {source}:\n{result.stderr.strip()}")
        for name in overridden:
            del imported[name]
