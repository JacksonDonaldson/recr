#!/usr/bin/env python3
"""Compile .rec hooks and place them in an ELF's codezip receipt ranges."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import xml.etree.ElementTree as ET

from elftools.common.exceptions import ELFError
import yaml

from binary.binary import Binary
import codezip
from input_parser import ParseError, parse_re_file
from ir import Address, FreeSpace, Function, Instruction, InstructionType
from isa.x86_64 import X86_64ISA
from recompiler.compiler import HOOK_PREFIX, compile_rec, rewrite_hooks
from recompiler.exports import Exports, read_exports
from recompiler.placement import Fragment, Object, Space, jump, place
from uplifter import Uplifter


_ENDBR64 = b"\xf3\x0f\x1e\xfa"
_JUMP_SIZE = 5


@dataclass(frozen=True)
class Hook:
    name: str
    start: int
    instructions: tuple[Instruction, ...]
    keep_endbr: bool

    @property
    def resume(self) -> int:
        last = self.instructions[-1]
        return last.address + last.length

    @property
    def size(self) -> int:
        return self.resume - self.start


def _hook(
    function: Function, binary: Binary, uplifter: Uplifter, exports: Exports,
) -> Hook:
    entry = function.start_address
    if not any(
        segment.flags & 1 and segment.start <= entry
        and entry + function.length <= segment.start + segment.size
        for segment in exports.segments
    ):
        raise ValueError(f"hook {function.name!r} is not in file-backed executable memory")
    uplifter.uplift_function(function)
    keep_endbr = binary.read(entry, min(function.length, 4)) == _ENDBR64
    start = entry + (4 if keep_endbr else 0)
    end = start
    stolen = []
    if function.has_unk_local_reference():
        raise ValueError(f"hook {function.name!r} has unresolved local control flow")
    for instruction in function.basic_blocks[0].instructions:
        if instruction.address < start:
            continue
        if instruction.type is InstructionType.RET:
            break
        stolen.append(instruction)
        end += instruction.length
        if end - start >= _JUMP_SIZE:
            break
    if end - start < _JUMP_SIZE:
        raise ValueError(f"hook {function.name!r} has no {_JUMP_SIZE}-byte entry window")
    if any(start < address < end for address in exports.references):
        raise ValueError(f"hook {function.name!r} has a reference into its entry window")
    for address_set in exports.addresses.values():
        if any(start < address < end for address in address_set):
            raise ValueError(f"hook {function.name!r} has a symbol inside its entry window")
    for block in function.basic_blocks:
        for instruction in block.instructions:
            if instruction.type not in (InstructionType.CALL, InstructionType.BRANCH):
                continue
            if not instruction.flows_to:
                continue
            target = instruction.flows_to[0].value
            if start < target < end or (
                instruction.type is InstructionType.BRANCH and entry <= target <= start
            ):
                raise ValueError(f"hook {function.name!r} has control flow into its entry window")
    return Hook(function.name.removeprefix("<EXTERNAL>::"), start, tuple(stolen), keep_endbr)


def _trampoline(hook: Hook, space: Space, isa: X86_64ISA) -> Fragment:
    prefix = _ENDBR64 if hook.keep_endbr else b""
    size = len(prefix) + hook.size + _JUMP_SIZE
    address = space.allocate(size, 1, 5)
    if address is None:
        raise ValueError(f"insufficient cleared executable space for {hook.name!r} trampoline")
    data = bytearray(prefix)
    for instruction in hook.instructions:
        destination = address + len(data)
        if not isa.can_encode(instruction, destination):
            raise ValueError(f"cannot relocate entry instruction of {hook.name!r}")
        moved = isa.relocate_instruction(instruction, destination)
        if moved.length != instruction.length:
            raise ValueError(f"cannot relocate entry instruction of {hook.name!r} in place")
        data.extend(moved.original_data)
    data.extend(jump(address + len(data), hook.resume))
    return Fragment(address, data)


def _build(args: argparse.Namespace, flags: list[str], directory: Path) -> None:
    if args.re_file.suffix.lower() != ".xml":
        raise ValueError("recr requires a typed Ghidra XML export")
    parsed = parse_re_file(str(args.re_file))
    if (args.isa or parsed.isa) != "x86_64":
        raise ValueError("recr currently supports x86-64")
    exports = read_exports(args.binary, args.re_file, parsed.functions)
    rewritten, names = rewrite_hooks(args.rec.read_text(encoding="utf-8"))
    isa = X86_64ISA()
    original = Binary(args.binary)
    uplifter = Uplifter("x86_64", original)
    hooks = []
    for name in names:
        functions = exports.functions.get(name, [])
        if len(functions) != 1:
            raise ValueError(f"hook {name!r} must match exactly one original function, found {len(functions)}")
        hooks.append(_hook(functions[0], original, uplifter, exports))
    if len({hook.start for hook in hooks}) != len(hooks):
        raise ValueError("multiple hooks alias the same function entry")

    extension = Object.read(compile_rec(
        args.rec.resolve(), rewritten, names, exports.declarations,
        flags, args.cc, directory,
    ))
    for name in names:
        hook = extension.symbols.get(HOOK_PREFIX + name)
        if hook is None or not extension.sections[hook.section].flags & 4:
            raise ValueError(f".rec must define a function for hook {name!r}")

    imports = {name: exports.address(name) for name in sorted(extension.imports())}
    protected = frozenset((*imports.values(), *(f.start_address for name in names for f in exports.functions[name])))
    compacted = directory / "compacted"
    receipt_path = directory / "codezip.yaml"
    options = codezip.build_arg_parser().parse_args([
        str(args.binary), str(args.re_file), "-o", str(compacted), "--receipt",
        str(receipt_path), *(["-v"] if args.verbose else []),
    ])
    if codezip.run_pipeline(options, protected_entries=protected):
        raise ValueError("codezip could not prepare the original binary")
    receipt = yaml.safe_load(receipt_path.read_text(encoding="utf-8"))
    free = [(item["address"], item["length"]) for item in receipt["freed"]]
    space = Space(free, exports)
    image = Binary(compacted)
    trampolines = []
    for hook in hooks:
        trampoline = _trampoline(hook, space, isa)
        if hook.name in imports:
            imports[hook.name] = trampoline.address
        trampolines.append(trampoline)
    placed = place(extension, space, imports, isa)
    patches = []
    for hook in hooks:
        symbol = extension.symbols[HOOK_PREFIX + hook.name]
        target = extension.sections[symbol.section].address(symbol.offset)
        patches.append(Fragment(
            hook.start, bytearray(jump(hook.start, target) + b"\x90" * (hook.size - _JUMP_SIZE)),
        ))

    for fragment in (*trampolines, *placed, *patches):
        image.write(fragment.address, fragment.data)

    # The completed image becomes visible only after all fixups succeed.
    with TemporaryDirectory(prefix=".recr-", dir=args.output.parent) as output_dir:
        pending = Path(output_dir) / "output"
        image.write_to_disk(pending)
        os.replace(pending, args.output)
    if args.receipt is not None:
        freed = [FreeSpace(Address.absolute(s.start), s.end - s.start) for s in space.ranges]
        modified = [
            FreeSpace(Address.absolute(entry["address"]), entry["length"])
            for entry in receipt.get("modified", [])
        ]
        modified.extend(
            FreeSpace(Address.absolute(item.address), len(item.data))
            for item in (*trampolines, *placed, *patches)
        )
        args.receipt.write_text(codezip._render_receipt(freed, modified), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    flags: list[str] = []
    if "--" in argv:
        index = argv.index("--")
        argv, flags = argv[:index], argv[index + 1:]
    parser = argparse.ArgumentParser(
        prog="recr", description="Place compiled .rec hooks into space recovered by codezip.",
        epilog="Pass additional GCC flags, objects, and static archives after --.",
    )
    parser.add_argument("binary", type=Path)
    parser.add_argument("re_file", type=Path)
    parser.add_argument("rec", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("-r", "--receipt", type=Path)
    parser.add_argument("--isa")
    parser.add_argument("--cc", default=os.environ.get("CC", "gcc"), help="GCC executable")
    parser.add_argument("-v", "--verbose", action="store_true")
    args, interspersed = parser.parse_known_args(argv)
    args.output = args.output or args.binary.with_name(args.binary.name + ".recr")
    try:
        if args.output.resolve() in {args.binary.resolve(), args.re_file.resolve(), args.rec.resolve()}:
            raise ValueError("recr output must use a separate path from the inputs")
        if args.receipt is not None and args.receipt.resolve() in {
            args.output.resolve(), args.binary.resolve(), args.re_file.resolve(), args.rec.resolve(),
        }:
            raise ValueError("recr receipt must use a separate path from input and output files")
        with TemporaryDirectory(prefix="recr-") as directory:
            _build(args, [*interspersed, *flags], Path(directory))
    except (ValueError, OSError, ParseError, ELFError, ET.ParseError) as exc:
        print(f"recr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
