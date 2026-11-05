# codezip

Modify an already-compiled binary to maximize unused space without changing
its semantics or its overall layout. Function entry points and extents stay
fixed; instructions may move within a function, and data is never appended.

## Status

This is the **first-pass scaffold**. The project structure, IR data model, and
module interfaces are in place, but the pipeline stages are stubs that raise
`NotImplementedError`. No binary modification behavior is implemented yet.

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
| `isa/x86_64.py` | x86-64 backend (will use Capstone) |
| `optimizers/function_remover.py` | Unreferenced-function removal |
| `optimizers/outliner.py` | Repeated-region outlining |
| `binary/binary.py` | Binary file interface |
| `binary/elf.py` | ELF backend |
| `binary/pe.py` | PE backend |
| `binary/raw.py` | Raw binary backend |
| `verify.py` | Static and dynamic equivalence checks |
| `test/` | Smoke tests, skipped parser tests, and fixtures |

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

## Usage (planned)

```sh
python codezip.py ./a.out ./functions.yaml -o ./a.out.codezip
```

## Development

```sh
python -m pip install -r requirements.txt
pytest
```

All commands currently stop at the first unimplemented stage.
