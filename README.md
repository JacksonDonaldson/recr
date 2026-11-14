# codezip

Modify an already-compiled binary to maximize unused space without changing
its semantics or its overall layout. Function entry points and extents stay
fixed; instructions may move within a function, and data is never appended.

## Status

The input parsers, ELF backend, x86-64 disassembler, function uplifter, and CLI
wiring through the uplift stage are implemented. Cross-reference recovery, the
optimization passes, and verification are still stubs that raise
`NotImplementedError`, so no binary modification behavior is implemented yet.

## Planned pipeline

1. **Parse** a reverse-engineering tool export (YAML or Ghidra XML) into
   function records.
2. **Uplift** each function into instructions, basic blocks, cross-references,
   and a control-flow graph.
3. **Optimize**:
   - remove unreferenced functions;
   - outline repeated instruction regions aggressively.
4. **Verify** the result statically and dynamically, reverting any function
   that fails a check.

The current CLI performs steps 1 and 2, then exits with an error because the
remaining stages are not implemented.

## Layout

| Path | Purpose |
| --- | --- |
| `codezip.py` | CLI orchestrator driving parse → uplift → optimize → verify |
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
uplifted function. The command currently stops after uplifting and exits
nonzero because optimization and verification are not implemented.

## Development

```sh
python -m pip install -r requirements.txt
pytest
```

To uplift and pretty-print every function in the sample input:

```sh
python test/uplift_sample.py
```

The optimization pipeline still stops at its first unimplemented stage.
