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
from input_parser import ParseError, ParseResult, parse_re_file
from ir import Address, AddressKind, FreeSpace, Function, Instruction, InstructionType
from isa.isa import ISA
from parsers.yaml import EXTENSIONS as YAML_EXTENSIONS
from recompiler import compaction_cache, riscv
from recompiler.compiler import HOOK_PREFIX, compile_rec, rewrite_hooks
from recompiler.exports import Exports, read_exports
from recompiler.placement import Fragment, Object, Space, place
from recompiler.raw import FUNCTION_OUTSIDE_EXECUTABLE_RANGE, SKIP_SHORT_FUNCTIONS, RawInput, read_raw_input
from recompiler.target import Target
from uplifter import FunctionExtentError, Uplifter


IGNORING_THUNK_FUNCTION = "ignoring-thunk-function"
INVALID_FUNCTION_EXTENT = "invalid-function-extent"


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
    if functions:
        candidates = ", ".join(f"{f.name!r} at {f.start_address:#x} ({f.length} bytes)" for f in functions)
        detail = f"Candidates are {candidates}. Give the intended function a unique final name in the export"
    else:
        detail = "Check the final component of the function name in the export and its executable mapping"
    raise ValueError(f"hook {name!r} must match exactly one original function, found {len(functions)}. {detail}")


def _hook(
    name: str, function: Function, binary: Binary, uplifter: Uplifter, exports: Exports,
) -> Hook:
    entry = function.start_address
    label = f"hook {function.name!r} at {entry:#x}"
    limit = entry + function.length
    if not any(
        segment.flags & 1 and segment.start <= entry
        and limit <= segment.start + segment.size
        for segment in exports.segments
    ):
        raise ValueError(f"{label} is not in file-backed executable memory. Its extent ends at {limit:#x} (exclusive)")
    uplifter.uplift_function(function)
    target = exports.target
    pad = target.landing_pad
    if pad and binary.read(entry, min(function.length, len(pad))) != pad:
        pad = b""
    start = entry + len(pad)
    end = start
    stolen = []
    if function.has_unk_local_reference():
        source = next(ref.from_.value for ref in function.outgoing_references if ref.to.kind is AddressKind.UNK_LOCAL)
        raise ValueError(f"{label} has unresolved local control flow from {source:#x}. The entry window cannot be verified")
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
        raise ValueError(f"{label} has no {target.jump_size}-byte entry window. Only {end - start} usable bytes from {start:#x}")
    reference = min((address for address in exports.references if start < address < end), default=None)
    window = f"[{start:#x}, {end:#x})"
    if reference is not None:
        raise ValueError(f"hook {function.name!r} has a reference into its entry window {window} at {reference:#x}")
    for symbol, address_set in exports.addresses.items():
        address = min((candidate for candidate in address_set if start < candidate < end), default=None)
        if address is not None:
            raise ValueError(f"hook {function.name!r} has a symbol inside its entry window {window}. {symbol!r} points to {address:#x}")
    for block in function.basic_blocks:
        for instruction in block.instructions:
            if instruction.type not in (InstructionType.CALL, InstructionType.BRANCH):
                continue
            if not instruction.flows_to:
                continue
            destination = instruction.flows_to[0].value
            if start < destination < end or (
                instruction.type is InstructionType.BRANCH and entry <= destination <= start
            ):
                raise ValueError(
                    f"{label} has control flow into its entry window {window} "
                    f"from instruction {instruction.address:#x} to {destination:#x}"
                )
    return Hook(name, start, tuple(stolen), pad)


def _trampoline(hook: Hook, space: Space, isa: ISA, target: Target) -> Fragment:
    return_offset = len(hook.landing_pad) + hook.size
    size = return_offset + target.jump_size
    lower, upper = isa.jump_displacement_range().sources(hook.resume)
    bounds = lower - return_offset, upper - return_offset
    failure = None
    for index, address in space.candidates(size, target.alignment, 5, bounds=bounds, near=hook.start, endpoints=True):
        try:
            fragment = _trampoline_at(hook, address, isa, target)
        except ValueError as exc:
            if failure is None:
                failure = exc
            continue
        space.take(index, address, size)
        return fragment
    if failure is not None:
        raise ValueError(f"no encodable trampoline placement for hook {hook.name!r}. {failure}") from failure
    raise ValueError(
        f"insufficient cleared executable space for {hook.name!r} trampoline ({size} contiguous bytes) "
        f"within jump range of its return to {hook.resume:#x}. "
        f"The trampoline {space.describe_capacity(target.alignment, 5, bounds)}"
    )


def _trampoline_at(hook: Hook, address: int, isa: ISA, target: Target) -> Fragment:
    data = bytearray(hook.landing_pad)
    for instruction in hook.instructions:
        destination = address + len(data)
        location = (
            f"entry instruction of {hook.name!r} from {instruction.address:#x} to {destination:#x} "
            f"({instruction.original_data.hex(' ')})"
        )
        if not isa.can_encode(instruction, destination):
            try:
                isa.required_length(instruction, destination)
            except ValueError as exc:
                raise ValueError(f"cannot relocate {location}. {exc}") from exc
            raise ValueError(f"cannot relocate {location} with an encodable instruction")
        try:
            moved = isa.relocate_instruction(instruction, destination)
        except ValueError as exc:
            raise ValueError(f"cannot relocate {location}. {exc}") from exc
        if moved.length != instruction.length:
            raise ValueError(f"cannot relocate {location} in place. Its size changes from {instruction.length} to {moved.length} bytes")
        data.extend(moved.original_data)
    try:
        data.extend(target.jump(address + len(data), hook.resume))
    except ValueError as exc:
        raise ValueError(f"trampoline return for hook {hook.name!r} at {hook.start:#x} failed. {exc}") from exc
    return Fragment(address, data)


def _compact(
    options: argparse.Namespace, parsed: ParseResult, raw: RawInput | None,
    protected: frozenset[int], warnings: WarningOptions, hooks: list[Hook],
) -> compaction_cache.Receipt:
    def warn_extent(start: int, covered_end: int, message: str) -> None:
        for hook in hooks:
            if hook.start < covered_end and start < hook.resume:
                raise ValueError(f"{message}. The rejected extent overlaps hook {hook.name!r}")
        warnings.emit(message, INVALID_FUNCTION_EXTENT)

    path = compaction_cache.entry_path(raw, protected) if raw is not None and not options.verbose else None
    if raw is not None and path is not None:
        cached = compaction_cache.load(path)
        if cached is not None:
            for event in cached.warnings:
                if isinstance(event, str):
                    warnings.emit(event)
                else:
                    warn_extent(*event)
            cached.apply(raw.binary)
            return cached.receipt

    events: list[compaction_cache.WarningEvent] = []

    def warn(message: str) -> None:
        warnings.emit(message)
        events.append(message)

    def warn_invalid_extent(function: Function, error: FunctionExtentError) -> None:
        event = function.start_address, error.covered_end, str(error)
        warn_extent(*event)
        events.append(event)

    if codezip.run_pipeline(
        options, protected_entries=protected, binary=raw.binary if raw is not None else None,
        parsed=parsed, warn=warn, warn_invalid_extent=warn_invalid_extent,
    ):
        raise ValueError(f"codezip could not prepare {options.binary} using {options.re_file}. See the compaction errors above")
    receipt = yaml.safe_load(options.receipt.read_text(encoding="utf-8"))
    if raw is not None and path is not None:
        compaction_cache.store(path, raw.binary, receipt, events)
    return receipt


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
    isa_name = args.isa or parsed.isa
    if isa_name != target.isa:
        selection = "--isa" if args.isa else str(args.re_file)
        raise ValueError(f"{selection} selects {isa_name!r}, but {args.binary} uses {target.isa!r}")
    try:
        source = args.rec.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"cannot read hook source {args.rec} as UTF-8. Invalid bytes at offset {exc.start:#x}") from exc
    rewritten, names = rewrite_hooks(source)
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
        aliases: dict[int, list[str]] = {}
        for hook in hooks:
            aliases.setdefault(hook.start, []).append(hook.name)
        shared = ", ".join(f"{', '.join(names)} at {address:#x}" for address, names in aliases.items() if len(names) > 1)
        raise ValueError(f"multiple hooks alias the same function entry. Conflicting hooks are {shared}")

    compiled = compile_rec(
        args.rec.resolve(), rewritten, names, declarations,
        flags, args.cc or target.compiler, directory, target,
    )
    try:
        extension = Object.read(compiled, target)
    except (ELFError, OSError, ValueError) as exc:
        raise ValueError(f"cannot load compiled extension for {args.rec}. {exc}") from exc
    for name in names:
        hook = extension.symbols.get(HOOK_PREFIX + name)
        if hook is None or not extension.sections[hook.section].flags & 4:
            raise ValueError(f"{args.rec} must define a function body for hook {name!r} using @{name}")

    imports = {}
    for name in sorted(extension.imports()):
        try:
            imports[name] = exports.address(name, ignored_entry=ignored_entries.get(name))
        except ValueError as exc:
            section, relocation = next(
                (section, relocation)
                for section in extension.sections.values() for relocation in section.relocations
                if relocation.symbol.name == name and relocation.symbol.section == "SHN_UNDEF"
            )
            site = relocation.describe(section, "import")
            raise ValueError(f"cannot resolve {site} using {args.re_file}. {exc}") from exc
    if target.machine == "EM_RISCV":
        # Imports of hooked functions resolve to trampolines whose addresses
        # are assigned after compaction.
        fixed_imports = {name: address for name, address in imports.items() if name not in names}
        riscv.validate_fixed_hi20(extension, fixed_imports, target.bits)
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

    receipt = _compact(options, parsed, raw, protected, warnings, hooks)
    free = [(item["address"], item["length"]) for item in receipt["freed"]]
    space = Space(free, exports)
    image = original if raw is not None else Binary(compacted)
    trampolines = []
    for hook in hooks:
        trampoline = _trampoline(hook, space, isa, target)
        if hook.name in imports:
            imports[hook.name] = trampoline.address
        trampolines.append(trampoline)
    entries = {extension.symbols[HOOK_PREFIX + hook.name]: hook.start for hook in hooks}
    placed = place(extension, space, imports, isa, target, hook_entries=entries)
    patches = []
    for hook in hooks:
        symbol = extension.symbols[HOOK_PREFIX + hook.name]
        destination = extension.sections[symbol.section].address(symbol.offset)
        try:
            entry_jump = target.jump(hook.start, destination)
            padding = target.padding(hook.size - target.jump_size)
        except ValueError as exc:
            raise ValueError(f"entry jump for hook {hook.name!r} failed. {exc}") from exc
        patches.append(Fragment(hook.start, bytearray(entry_jump + padding)))

    for fragment in (*trampolines, *placed, *patches):
        try:
            image.write(fragment.address, fragment.data)
        except ValueError as exc:
            raise ValueError(
                f"cannot apply {len(fragment.data)} extension bytes at {fragment.address:#x} in {args.binary}. {exc}"
            ) from exc

    # The completed image becomes visible only after all fixups succeed.
    try:
        with TemporaryDirectory(prefix=".recr-", dir=args.output.parent) as output_dir:
            pending = Path(output_dir) / "output"
            image.write_to_disk(pending)
            os.replace(pending, args.output)
    except OSError as exc:
        raise ValueError(f"cannot write patched image to {args.output}. {exc}") from exc
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
        try:
            args.receipt.write_text(codezip._render_receipt(freed, modified), encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"patched image written to {args.output}, but cannot write receipt to {args.receipt}. {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    flags: list[str] = []
    if "--" in argv:
        index = argv.index("--")
        argv, flags = argv[:index], argv[index + 1:]
    suppress_range_warning = f"-Wno-{FUNCTION_OUTSIDE_EXECUTABLE_RANGE}"
    suppress_short_warning = f"-Wno-{SKIP_SHORT_FUNCTIONS}"
    suppress_thunk_warning = f"-Wno-{IGNORING_THUNK_FUNCTION}"
    suppress_extent_warning = f"-Wno-{INVALID_FUNCTION_EXTENT}"
    suppressible_warnings = {
        suppress_range_warning: FUNCTION_OUTSIDE_EXECUTABLE_RANGE,
        suppress_short_warning: SKIP_SHORT_FUNCTIONS,
        suppress_thunk_warning: IGNORING_THUNK_FUNCTION,
        suppress_extent_warning: INVALID_FUNCTION_EXTENT,
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
            f"  {suppress_extent_warning:<38}  suppress warnings for inconsistent function extents\n"
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
            raise ValueError(f"the separate function export must be Ghidra XML. Received {args.re_file}")
        if args.input.suffix.lower() in YAML_EXTENSIONS:
            try:
                raw = read_raw_input(args.input, args.re_file, warn=warnings.emit)
            except (OSError, ValueError) as exc:
                raise ValueError(f"cannot use raw manifest {args.input}. {exc}") from exc
            args.re_file = args.re_file or args.input
            args.binary = raw.binary.path
        else:
            if args.re_file is None:
                raise ValueError(f"an ELF input requires a typed Ghidra XML export. Use recr {args.input} EXPORT.xml {args.rec}")
            args.binary = args.input
        args.output = args.output or args.binary.with_name(args.binary.name + ".recr")
        inputs = {path.resolve() for path in (args.input, args.binary, args.re_file, args.rec)}
        if args.output.resolve() in inputs:
            raise ValueError(f"recr output must use a separate path from the inputs. {args.output} resolves to an input file")
        if args.receipt is not None and args.receipt.resolve() in inputs | {args.output.resolve()}:
            raise ValueError(f"recr receipt must use a separate path from input and output files. {args.receipt} aliases one of them")
        with TemporaryDirectory(prefix="recr-") as directory:
            _build(args, compiler_flags, Path(directory), raw, warnings)
    except (ValueError, OSError, ParseError, ELFError, ET.ParseError, WarningError) as exc:
        print(f"recr: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
