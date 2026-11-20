# codezip

Modify an already-compiled binary to maximize unused space without changing
its semantics or its overall layout. Function entry points and extents stay
fixed; instructions may move within a function, and data is never appended.

## Status

The input parsers, ELF backend, x86-64 disassembler, function uplifter,
cross-reference recovery, unreferenced-function free-space detection, and CLI
wiring through writing the modified binary are implemented. The pipeline fills
every freed range with `0xff`, writes the result to the output path, and can
write a YAML receipt of freed and rewritten ranges. The outliner finds
profitable basic-block matches, extracts them into free space, replaces source
sites with calls, and regenerates the affected functions. Verification is still
a stub, so the written binary is unverified.

## Planned pipeline

1. **Parse** a reverse-engineering tool export (YAML or Ghidra XML) into
   function records.
2. **Uplift** each function into instructions, basic blocks, cross-references,
   and a control-flow graph.
3. **Optimize**:
   - remove unreferenced functions and fill their bytes with `0xff`;
   - outline repeated instruction regions aggressively.

The current CLI performs steps 1 and 2 and the free-space part of step 3, then
writes the modified binary.

## Layout

| Path | Purpose |
| --- | --- |
| `codezip.py` | CLI orchestrator driving parse → uplift → optimize → write |
| `input_parser.py` | Parser selection and entry point |
| `parsers/yaml.py` | YAML function export parser |
| `parsers/ghidra_xml.py` | Ghidra XML function export parser |
| `parsers/base.py` | Shared `ParseResult` type |
| `ir.py` | IR data model: `Address`, `StateSpace`, `Instruction`, `BasicBlock`, `Function`, `Reference`, `FreeSpace` |
| `ir.md` | Normative IR and ISA contract |
| `uplifter.py` | Function → IR conversion and cross-reference recovery |
| `isa/isa.py` | ISA superclass and encoding contract |
| `isa/sleigher/` | Direct parser/interpreter for compiled SLEIGH `.sla` files |
| `isa/x86_64/` | x86-64 backend and pinned Ghidra 12.2 SLEIGH spec |
| `optimizers/function_remover.py` | Unreferenced-function removal |
| `optimizers/outliner.py` | Repeated-region outlining |
| `binary/binary.py` | Binary file interface and format routing |
| `binary/elf.py` | ELF backend |
| `binary/pe.py` | PE backend (stub) |
| `binary/raw.py` | Explicit virtual-to-file mappings for raw images |
| `test/` | Grouped pytest suites, sample C input, NASM fixtures, and Ghidra exports |

## Input formats

YAML exports use `.yaml` or `.yml`. Use integer scalars for addresses, offsets,
and lengths. Use `-1` when the file offset is unknown. Extra top-level fields
are ignored.

```yaml
isa: x86_64
functions:
  main:
    start_address: 0x401020
    file_offset: 0x1020
    length: 0x40
```

Ghidra XML: see `test/fixtures/sample_ghidra.xml`. Ghidra exports virtual
addresses; the active `Binary` implementation maps them to file offsets.

## Usage

Install from the repository with Python 3.10 or newer.

```sh
python -m pip install -e .
codezip ./a.out ./functions.xml -o ./a.out.codezip
```

Add `-v` or `--verbose` to log pipeline progress and pretty-print every
uplifted function. The command writes the modified binary to `-o` (default:
`<binary>.codezip`). Verification is not implemented yet.

The temporary `--report-outline-matches` option prints every profitable
basic-block match and exits with status 1 without writing an output binary.

Pass `--receipt PATH` to also write a YAML receipt of the freed ranges and the
live code ranges rewritten by outlining:

```yaml
freed:
  - address: 0x4010a0
    length: 0x5
modified:
  - address: 0x401156
    length: 0x9
```

## Recompilation with recr

`recr` compiles a C extension for an x86-64, RV32, or RV64 non-PIE ELF using a
typed Ghidra XML export. Prefix a function definition with `@` to hook the
original function. Use the final component of a qualified Ghidra name, such as
`@AppVprintf` for `main_app::AppVprintf`. A hook name usually identifies one
function. When exactly two entries match and the shorter is under 8 bytes,
recr selects the longer entry and warns about the presumed thunk. Use
`-Wno-ignoring-thunk-function` to silence that warning. Calling the hook name
normally from the extension invokes the selected original through a trampoline.
C definitions in the extension take precedence over other imported names.

```sh
recr ./a.out ./functions.xml ./hooks.rec -o ./a.out.recr -- -Iinclude -Llib -lexample
```

Use `-p FILE` or `--patchstream FILE` to also save a binary patch stream for
an ELF or raw image. The stream contains the extension and the rewrites it
needs to use reclaimed space. Each record contains a virtual address, a byte
count, and that many replacement bytes. The address and count are unsigned
little-endian words, 4 bytes on RV32 and 8 bytes on RV64 and x86-64. Records
cover contiguous changed bytes within a file-backed mapping. A single
all-`0xff` address word terminates the stream.

GCC accepts extra compiler flags, object files, and static libraries after
`--`. Before `--`, `-Wall` enables all recr warnings and `-Werror` makes
enabled warnings fatal. Recr also passes both flags to GCC. Calls can use
shared-library imports already present in the original ELF. Recr uses Ghidra's
scalar, pointer, and array types for implicit declarations. Ghidra `string`
data is declared as a C `char[]`.
Each hook must match the original function's prototype. Recr uses the
prototype on the selected Ghidra function entry to declare the original for
calls from the extension. Ghidra does not always include function prototypes
in exports. If the prototype is missing, edit the function in Ghidra, select
**Commit all return/parameter details**, and export the XML again. Supply a C
declaration for other imports with missing or unsupported type metadata.

For RISC-V `__thiscall` functions, Ghidra must export `this` in `a0` as a
pointer to a named structure. Declare that pointer as the first C parameter
in the hook. A variadic hook can read arguments with `<stdarg.h>`. When it
calls the original, supply the variadic arguments explicitly. Pass a
`va_list` to a function declared to receive one.

Code can be split across executable receipt ranges. Each data section needs
a contiguous range and writable sections require writable space. Placement
fails if the extension cannot fit. The sample hook and test-only space are in
`test/fixtures/sample.rec` and `test/fixtures/recr_space.S`.

RISC-V builds default to `riscv64-linux-gnu-gcc`. Use `--cc` to select a
different cross-compiler. Hook and fragment jumps must reach their targets
with a single `JAL` so they leave registers intact. The RV64 sample and both
RISC-V hook tests run under QEMU in `test/test_recr_riscv.py`.

### Raw firmware images

Pass a `.yaml` or `.yml` manifest and the `.rec` file for a statically linked
raw image. Relative binary paths are resolved from the manifest directory.
The default output is `<binary>.recr`.

```sh
recr ./firmware.yaml ./hooks.rec -o ./firmware.patched.bin
recr ./firmware.yaml ./functions.xml ./hooks.rec -o ./firmware.patched.bin
```

```yaml
binary: firmware.bin
isa: x86_64
regions:
  - {start_address: 0x400000, file_offset: 0x10, length: 0x70}
  - {start_address: 0x410000, file_offset: 0x80, length: 0x100, permissions: rwx}
  - {start_address: 0x420000, file_offset: 0x180, length: 0x10, permissions: rw}
  - {start_address: 0x420010, length: 0x100, permissions: rw}
entry_points: [0x400000]
functions:
  _start: {start_address: 0x400000, length: 0x20}
  transform:
    start_address: 0x400020
    length: 0x10
    declaration: "extern int transform(int value);"
  spare: {start_address: 0x410000, length: 0x100}
symbols:
  counter: {address: 0x420000, declaration: "extern int counter;"}
```

Give each region a virtual start and byte length. Provide `file_offset` for
file-backed regions. Omit it for runtime-only memory such as BSS. Recr can
resolve Ghidra data symbols in those regions. Scanning, hook placement, and
binary writes are limited to file-backed regions. Regions may appear in any
order and must be disjoint in virtual memory and, where backed, in the file.
Permissions default to `rx`. Include file-backed data regions containing
pointers so codezip can scan them for live functions. List reset, interrupt,
and other entry addresses that firmware can reach from outside the mapped
image under `entry_points` so codezip preserves their functions.

Use `functions` to identify hooks and give codezip the extents it can analyze
for reclaimable space. Give every hooked function its original C prototype in
`declaration` when the manifest supplies the function records. Recr skips
functions whose full extent falls outside a single file-backed executable
region and warns by default. Use
`-Wno-function-outside-executable-range` to suppress this warning, including
with `-Wall` or `-Werror`. Recr also skips functions shorter than the target's
instruction alignment and warns by default. Use `-Wno-skip-short-functions`
to suppress that warning. The file offset of each retained function is
derived from the mapping. If you pass a Ghidra XML export,
it supplies the ISA, functions, and C types, so omit `isa` and `functions`
from the manifest. `symbols` binds additional names to fixed virtual addresses.
An optional `declaration` supplies the C declaration implicitly visible in
the `.rec` file. Raw RISC-V manifests must include the original architecture
and ABI, for example `riscv: {march: rv64gc, abi: lp64d}` with `isa: riscv64`.

## Development

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

To uplift and pretty-print every function in the sample input:

```sh
python test/uplift_sample.py
```

An opt-in end-to-end check builds pinned pcre2, rewrites its test executables
with codezip, re-runs pcre2's suite, and runs pcre2's pattern corpus through
`pcre2grep` to exercise its statically linked library (requires Ghidra and
network access, about 4 minutes):

```sh
make -C test e2e
```

The full check also runs on RV64 under QEMU. The little-endian RV32 and RV64
backends support function removal, instruction relocation, and outlining.

```sh
make -C test e2e-riscv
```

To check that the suite would notice a corrupted rewrite, run the mutation
sensitivity check after it:

```sh
make -C test e2e-mutation
```

The optimization pipeline now runs function removal and outlining before
writing the output.
