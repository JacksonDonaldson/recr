"""Compile a .rec translation unit into a statically linkable ELF object."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from recompiler.target import Target


HOOK_PREFIX = "__recr_hook_"
_C_TOKENS = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\[\s\S]|[^"\\])*"|'
    r"'(?:\\[\s\S]|[^'\\])*'|@(?P<hook>[A-Za-z_][A-Za-z_0-9]*)",
    re.DOTALL,
)
_DIAGNOSTIC = re.compile(
    r"^(?P<file>.+?):\d+(?::\d+)?: (?P<kind>error|warning|note): (?P<message>.*)$"
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


def _shadowed(stderr: str, header: Path, names: set[str], protected: set[str]) -> set[str]:
    found: set[str] = set()
    pending = None
    for line in stderr.splitlines():
        diagnostic = _DIAGNOSTIC.match(line)
        if diagnostic is None:
            continue
        kind = diagnostic["kind"]
        if kind == "error":
            match = _CONFLICT.match(diagnostic["message"])
            pending = match[1] if match else None
            if pending in protected:
                return set()
        elif kind == "warning":
            pending = None
        elif pending is not None and pending in names and diagnostic["file"] == str(header):
            found.add(pending)
    return found


def compile_rec(
    source: Path, rewritten: str, hooks: tuple[str, ...],
    declarations: dict[str, str], flags: list[str], compiler: str, directory: Path,
    target: Target,
) -> Path:
    header = directory / "imports.h"
    translation_unit = directory / "extension.c"
    obj = directory / "extension.o"
    translation_unit.write_text(f"#line 1 {json.dumps(str(source))}\n{rewritten}", encoding="utf-8")
    roots = ["-Wl,--gc-sections", *(f"-Wl,-u,{HOOK_PREFIX}{name}" for name in hooks)] if hooks else []
    try:
        driver = shlex.split(compiler)
    except ValueError as exc:
        raise ValueError(f"invalid GCC command {compiler!r}. {exc}. Check --cc or CC") from exc
    if not driver:
        raise ValueError(f"missing GCC executable for {target.isa}. Set --cc or CC to a compiler command")
    command = [
        *driver, *target.compiler_flags, "-std=gnu17", "-Os", "-fno-pie", "-fno-pic",
        "-fno-builtin", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables", "-fno-jump-tables", "-ffunction-sections",
        "-fdata-sections", "-fno-lto", "-Werror=implicit-function-declaration",
        "-iquote", str(source.parent), "-include", str(header), "-static",
        "-r", "-nostdlib", "-no-pie", *roots,
        str(translation_unit), *flags, "-fdiagnostics-format=text", "-fdiagnostics-color=never", "-o", str(obj),
    ]
    protected = {*hooks, *(HOOK_PREFIX + name for name in hooks)}
    imported = {name: declaration for name, declaration in declarations.items() if name not in hooks}
    hook_declarations = "\n".join(
        f"{declarations[name]}\nextern __typeof__({name}) {HOOK_PREFIX}{name};" for name in hooks
    )
    while True:
        header.write_text(
            "#include <stddef.h>\n#include <stdint.h>\ntypedef __PTRDIFF_TYPE__ ssize_t;\n"
            + "\n".join(imported.values()) + "\n"
            + '#pragma GCC diagnostic push\n#pragma GCC diagnostic error "-Wstrict-prototypes"\n'
            + hook_declarations + "\n#pragma GCC diagnostic pop\n",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"},
            )
        except FileNotFoundError as exc:
            raise ValueError(f"GCC executable {driver[0]!r} was not found for {target.isa}. Check PATH or --cc") from exc
        if result.returncode == 0:
            return obj
        overridden = _shadowed(result.stderr, header, set(imported), protected)
        if not overridden:
            detail = result.stderr.strip() or result.stdout.strip() or "The compiler produced no diagnostics."
            raise ValueError(
                f"GCC failed to compile or link {source} for {target.isa} "
                f"using {shlex.join(driver)} (exit status {result.returncode}).\n{detail}"
            )
        for name in overridden:
            del imported[name]
