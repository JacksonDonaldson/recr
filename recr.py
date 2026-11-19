#!/usr/bin/env python3
"""Compile .rec hooks and place them in regions reclaimed by codezip."""

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
from isa.isa import ISA
from parsers.yaml import EXTENSIONS as YAML_EXTENSIONS
from recompiler.compiler import HOOK_PREFIX, compile_rec, rewrite_hooks
from recompiler.exports import Exports, read_exports
from recompiler.placement import Fragment, Object, Space, place
from recompiler.raw import FUNCTION_OUTSIDE_EXECUTABLE_RANGE, SKIP_SHORT_FUNCTIONS, RawInput, read_raw_input
from recompiler.target import Target
from uplifter import Uplifter


IGNORING_THUNK_FUNCTION = "ignoring-thunk-function"


class WarningError(Exception):
    """A recr warning promoted to a build error."""


@dataclass(frozen=True)
class WarningOptions:
    all_warnings: bool
    warnings_as_errors: bool
    disabled: frozenset[str]

    def emit(
        self, message: str, option: str | None = None, *, enabled_by_default: bool = True,
    ) -> None:
        if not (enabled_by_default or self.all_warnings):
            return
        if option is not None:
            if option in self.disabled:
                return
            message = f"{message} [-W{option}]"
        if self.warnings_as_errors:
            raise WarningError(f"error: {message}")
        print(f"recr: warning: {message}", file=sys.stderr)


@dataclass(frozen=True)
class Hook:
    name: str
    start: int
    instructions: tuple[Instruction, ...]
    landing_pad: bytes

    @property
    def resume(self) -> int:
        last = self.instructions[-1]
        return last.address + last.length

    @property
    def size(self) -> int:
        return self.resume - self.start


def _select_hook_function(
    name: str, functions: list[Function], warnings: WarningOptions,
) -> tuple[Function, Function | None]:
    if len(functions) == 1:
        return functions[0], None
    if len(functions) == 2:
        shorter, longer = sorted(functions, key=lambda function: function.length)
        if shorter.length < 8 and shorter.length < longer.length and shorter.start_address != longer.start_address:
            warnings.emit(
                f"ignoring presumed thunk {shorter.name!r} at {shorter.start_address:#x} "
                f"({shorter.length} bytes) for hook {name!r}. Choosing "
                f"{longer.name!r} at {longer.start_address:#x} ({longer.length} bytes)",
                IGNORING_THUNK_FUNCTION,
            )
            return longer, shorter
    raise ValueError(f"hook {name!r} must match exactly one original function, found {len(functions)}")


def _hook(
    name: str, function: Function, binary: Binary, uplifter: Uplifter, exports: Exports,
) -> Hook:
    entry = function.start_address
    if not any(
        segment.flags & 1 and segment.start <= entry
        and entry + function.length <= segment.start + segment.size
        for segment in exports.segments
    ):
        raise ValueError(f"hook {function.name!r} is not in file-backed executable memory")
    uplifter.uplift_function(function)
    target = exports.target
    pad = target.landing_pad
    if pad and binary.read(entry, min(function.length, len(pad))) != pad:
        pad = b""
    start = entry + len(pad)
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
        if end - start >= target.jump_size:
            break
    if end - start < target.jump_size:
        raise ValueError(f"hook {function.name!r} has no {target.jump_size}-byte entry window")
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
    return Hook(name, start, tuple(stolen), pad)


def _trampoline(hook: Hook, space: Space, isa: ISA, target: Target) -> Fragment:
    size = len(hook.landing_pad) + hook.size + target.jump_size
    address = space.allocate(size, target.alignment, 5)
    if address is None:
        raise ValueError(f"insufficient cleared executable space for {hook.name!r} trampoline")
    data = bytearray(hook.landing_pad)
    for instruction in hook.instructions:
        destination = address + len(data)
        if not isa.can_encode(instruction, destination):
            raise ValueError(f"cannot relocate entry instruction of {hook.name!r}")
        moved = isa.relocate_instruction(instruction, destination)
        if moved.length != instruction.length:
            raise ValueError(f"cannot relocate entry instruction of {hook.name!r} in place")
        data.extend(moved.original_data)
    data.extend(target.jump(address + len(data), hook.resume))
    return Fragment(address, data)


def _build(
    args: argparse.Namespace, flags: list[str], directory: Path, raw: RawInput | None,
    warnings: WarningOptions,
) -> None:
    if raw is None:
        parsed = parse_re_file(str(args.re_file))
        exports = read_exports(args.binary, args.re_file, parsed.functions)
        original = Binary(args.binary)
    else:
        parsed, exports, original = raw.parsed, raw.exports, raw.binary
    target = exports.target
    if (args.isa or parsed.isa) != target.isa:
        raise ValueError(f"the export ISA does not match the {target.isa} executable")
    rewritten, names = rewrite_hooks(args.rec.read_text(encoding="utf-8"))
    uplifter = Uplifter(target.isa, original)
    isa = uplifter.isa
    hooks = []
    ignored_entries: dict[str, int] = {}
    declarations = dict(exports.declarations)
    for name in names:
        function, ignored = _select_hook_function(name, exports.functions.get(name, []), warnings)
        declaration = exports.function_declarations.get((name, function.start_address))
        if declaration is None:
            if args.re_file.suffix.lower() in YAML_EXTENSIONS:
                raise ValueError(
                    f"raw manifest has no declaration for hook {name!r}. "
                    "Add a C function prototype to its 'declaration' field."
                )
            raise ValueError(
                f"Ghidra XML export has no usable prototype for {function.name!r} at {function.start_address:#x}. "
                "Ghidra does not always include function prototypes in exports. "
                "When editing the function in Ghidra, select 'Commit all return/parameter details' "
                "and export the XML again."
            )
        declarations[name] = declaration
        hooks.append(_hook(name, function, original, uplifter, exports))
        if ignored is not None:
            ignored_entries[name] = ignored.start_address
    if len({hook.start for hook in hooks}) != len(hooks):
        raise ValueError("multiple hooks alias the same function entry")

    extension = Object.read(compile_rec(
        args.rec.resolve(), rewritten, names, declarations,
        flags, args.cc or target.compiler, directory, target,
    ), target)
    for name in names:
        hook = extension.symbols.get(HOOK_PREFIX + name)
        if hook is None or not extension.sections[hook.section].flags & 4:
            raise ValueError(f".rec must define a function for hook {name!r}")

    imports = {
        name: exports.address(name, ignored_entry=ignored_entries.get(name))
        for name in sorted(extension.imports())
    }
    protected = frozenset((*imports.values(), *(f.start_address for name in names for f in exports.functions[name])))
    if raw is not None:
        protected |= raw.protected_entries
    compacted = directory / "compacted"
    receipt_path = directory / "codezip.yaml"
    options = codezip.build_arg_parser().parse_args([
        str(args.binary), str(args.re_file), "-o", str(compacted), "--receipt",
        str(receipt_path), *(["-v"] if args.verbose else []),
        "--isa", target.isa,
    ])
    if codezip.run_pipeline(
        options, protected_entries=protected,
        binary=raw.binary if raw is not None else None,
        parsed=parsed, warn=warnings.emit,
    ):
        raise ValueError("codezip could not prepare the original binary")
    receipt = yaml.safe_load(receipt_path.read_text(encoding="utf-8"))
    free = [(item["address"], item["length"]) for item in receipt["freed"]]
    space = Space(free, exports)
    image = original if raw is not None else Binary(compacted)
    trampolines = []
    for hook in hooks:
        trampoline = _trampoline(hook, space, isa, target)
        if hook.name in imports:
            imports[hook.name] = trampoline.address
        trampolines.append(trampoline)
    placed = place(extension, space, imports, isa, target)
    patches = []
    for hook in hooks:
        symbol = extension.symbols[HOOK_PREFIX + hook.name]
        destination = extension.sections[symbol.section].address(symbol.offset)
        patches.append(Fragment(
            hook.start, bytearray(
                target.jump(hook.start, destination) + target.padding(hook.size - target.jump_size)
            ),
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
    suppress_range_warning = f"-Wno-{FUNCTION_OUTSIDE_EXECUTABLE_RANGE}"
    suppress_short_warning = f"-Wno-{SKIP_SHORT_FUNCTIONS}"
    suppress_thunk_warning = f"-Wno-{IGNORING_THUNK_FUNCTION}"
    suppressible_warnings = {
        suppress_range_warning: FUNCTION_OUTSIDE_EXECUTABLE_RANGE,
        suppress_short_warning: SKIP_SHORT_FUNCTIONS,
        suppress_thunk_warning: IGNORING_THUNK_FUNCTION,
    }
    parser = argparse.ArgumentParser(
        prog="recr", description="Place compiled .rec hooks into space recovered by codezip.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Warnings --\n"
            "  -Wall                                   enable all recr warnings\n"
            "  -Werror                                 treat warnings as errors\n"
            f"  {suppress_range_warning}  suppress warnings for raw functions outside executable regions\n"
            f"  {suppress_short_warning:<38}  suppress warnings for raw functions shorter than the target alignment\n"
            f"  {suppress_thunk_warning:<38}  suppress warnings when a short hook candidate is ignored\n"
            "\nPass additional GCC flags, objects, and static archives after --."
        ),
    )
    parser.add_argument("input", type=Path, metavar="INPUT", help="ELF executable or raw-image YAML manifest")
    parser.add_argument("re_file", type=Path, nargs="?", metavar="EXPORT", help="Ghidra XML function export")
    parser.add_argument("rec", type=Path, metavar="REC", help=".re.c source file")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("-r", "--receipt", type=Path)
    parser.add_argument("--isa")
    parser.add_argument("--cc", default=os.environ.get("CC"), help="GCC executable or command")
    parser.add_argument("-v", "--verbose", action="store_true")
    args, interspersed = parser.parse_known_intermixed_args(argv)
    warnings = WarningOptions(
        all_warnings="-Wall" in interspersed,
        warnings_as_errors="-Werror" in interspersed,
        disabled=frozenset(suppressible_warnings[flag] for flag in interspersed if flag in suppressible_warnings),
    )
    compiler_flags = [flag for flag in interspersed if flag not in suppressible_warnings] + flags
    try:
        raw = None
        if args.re_file is not None and args.re_file.suffix.lower() != ".xml":
            raise ValueError("the separate function export must be Ghidra XML")
        if args.input.suffix.lower() in YAML_EXTENSIONS:
            raw = read_raw_input(args.input, args.re_file, warn=warnings.emit)
            args.re_file = args.re_file or args.input
            args.binary = raw.binary.path
        else:
            if args.re_file is None:
                raise ValueError("an ELF input requires a typed Ghidra XML export")
            args.binary = args.input
        args.output = args.output or args.binary.with_name(args.binary.name + ".recr")
        inputs = {path.resolve() for path in (args.input, args.binary, args.re_file, args.rec)}
        if args.output.resolve() in inputs:
            raise ValueError("recr output must use a separate path from the inputs")
        if args.receipt is not None and args.receipt.resolve() in inputs | {args.output.resolve()}:
            raise ValueError("recr receipt must use a separate path from input and output files")
        with TemporaryDirectory(prefix="recr-") as directory:
            _build(args, compiler_flags, Path(directory), raw, warnings)
    except (ValueError, OSError, ParseError, ELFError, ET.ParseError, WarningError) as exc:
        print(f"recr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
