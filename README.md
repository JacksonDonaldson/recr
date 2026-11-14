# codezip

Modify an already-compiled binary to maximize unused space without changing
its semantics or its overall layout. Function entry points and extents stay
fixed; instructions may move within a function, and data is never appended.

## Status

The input parsers, ELF backend, x86-64 disassembler, function uplifter,
cross-reference recovery, unreferenced-function free-space detection, and CLI
wiring through writing the modified binary are implemented. The pipeline fills
every freed range with `0xff`, writes the result to the output path, and can
write a YAML receipt of the freed ranges. The outliner and verification are
still stubs, so the written binary is unverified.

## Planned pipeline

1. **Parse** a reverse-engineering tool export (YAML or Ghidra XML) into
   function records.
2. **Uplift** each function into instructions, basic blocks, cross-references,
   and a control-flow graph.
3. **Optimize**:
   - remove unreferenced functions and fill their bytes with `0xff`;
   - outline repeated instruction regions aggressively (not implemented).
4. **Verify** the result statically and dynamically, reverting any function
   that fails a check (not implemented).

The current CLI performs steps 1 and 2 and the free-space part of step 3, then
writes the modified binary without verifying it.

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
| `binary/raw.py` | Raw binary backend (stub) |
| `verify.py` | Static and dynamic equivalence checks |
| `test/` | Grouped pytest suites, sample C input, NASM fixtures, and Ghidra exports |

## Input formats

YAML:

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

```sh
python codezip.py ./a.out ./functions.yaml -o ./a.out.codezip
```

Add `-v` or `--verbose` to log pipeline progress and pretty-print every
uplifted function. The command writes the modified binary to `-o` (default:
`<binary>.codezip`). Verification is not implemented yet.

Pass `--receipt PATH` to also write a YAML receipt of the freed ranges:

```yaml
freed:
  - address: 0x4010a0
    length: 0x5
  - address: 0x401af7
    length: 0x34
```

## Development

```sh
python -m pip install -r requirements.txt
pytest
```

To uplift and pretty-print every function in the sample input:

```sh
python test/uplift_sample.py
```

An opt-in end-to-end check builds pinned pcre2, rewrites its test executables
with codezip, and re-runs pcre2's suite (requires Ghidra and network access,
about 15 minutes):

```sh
make -C test e2e
```

The optimization pipeline still stops before outlining.
