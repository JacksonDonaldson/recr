# Contributing to codezip

## Read first

1. `plan.txt` — project goals, planned passes, and module responsibilities.
2. `ir.md` — the normative IR data model and ISA encoding contract.
3. `parsers/ghidra_xml.py` — the first fully implemented pipeline stage.

If a change affects the IR or ISA contract, update `ir.py` and `ir.md` together.

## Workflow

Before implementing a change, look around the repository, write an
implementation plan, and ask any questions that come up. Settle the plan and
open questions before editing code.

At the end of every run, update the "Current state" section below so it matches
the repository. Keep it concise: record what is implemented, what is still a
stub, and any essential constraints. Do not add task logs, changelogs, or
transient notes.

## Non-negotiable constraints

- Binary semantics must not change.
- Function entry points and extents must not move. Instructions may move within a function. Never append data to the binary.
- Functions must not grow. Reject any relocation that cannot be encoded at its new address.
- No instruction may be relocated without an `isa.can_encode` check.
- `BasicBlock` owns its instructions; `Function` owns its basic blocks.
- `flows_from` / `flows_to` contain absolute addresses, not block-relative addresses.
- Every instruction that can be outlined must report `is_outlinable() == True`.

When in doubt, be conservative: reject an optimization rather than risk changing behavior.

## Layout

| Path | Responsibility |
| --- | --- |
| `codezip.py` | CLI and pipeline orchestration |
| `input_parser.py` | Select and run an input parser |
| `parsers/` | YAML and Ghidra XML exports |
| `ir.py` | IR data model |
| `uplifter.py` | Bytes → instructions → basic blocks → CFG |
| `isa/` | ISA interface and x86-64 backend |
| `optimizers/` | Function removal and outlining |
| `binary/` | ELF, PE, and raw binary access |
| `verify.py` | Static and dynamic equivalence checks |
| `test/` | Tests, sample C input, Ghidra export fixture |

## Current state

Implemented:

- Ghidra XML parsing (`parsers/ghidra_xml.py`) and parser dispatch with
  `ParseError` handling; tests are pinned to a real Ghidra 12.2 export.
- ELF access (`binary/elf.py`) using `pyelftools`: `PT_LOAD` virtual-to-file
  mapping, reads with BSS zero-fill, full-file writes, and a no-op `finish()`.
  `Binary(path)` routes by magic bytes; PE and raw inputs raise
  `UnsupportedBinaryFormat` for now.
- ELF tests (`test/test_elf.py`) build `test/build/sample` with `make` when
  missing or stale, then verify Ghidra-derived `main` bytes and ELF mapping.
- x86-64 package (`isa/x86_64/`) contains the pinned Ghidra 12.2 SLEIGH files
  and a NASM `add eax, 0x20` fixture. `pypcode` 4.1.0 handles disassembly and
  P-code; full address-space access and reassembly need Ghidra's Java API
  (PyGhidra).

Still stubs:

- YAML parser
- PE and raw binary backends
- x86-64 ISA
- Uplifter
- Function remover and outliner
- Verification passes

Do not assume an unimplemented module works. Add tests as each stub is filled in.

## Setup and checks

```sh
python -m pip install -r requirements.txt
python -m pytest -q
```

Build and run the sample ELF:

```sh
make -C test
./test/build/sample
```

Regenerate the Ghidra XML export:

```sh
make -C test ghidra-xml
# writes test/build/sample_ghidra.xml
```

Ghidra 12.2 requires JDK 25. On the current development machine:

- Ghidra: `~/opt/ghidra`
- JDK 25: `~/opt/jdk-25`
- `JAVA_HOME_OVERRIDE` is set in Ghidra's `support/launch.properties`

Override `GHIDRA_HOME` on the make command line if Ghidra lives elsewhere.

## Parser conventions

- Ghidra XML provides virtual addresses, not original file offsets. Use
  `UNKNOWN_FILE_OFFSET` for `Function.file_offset`; `Binary` resolves offsets later.
- Skip functions in Ghidra's artificial `EXTERNAL` memory block.
- Do not skip a function solely because its name starts with `<EXTERNAL>::`;
  Ghidra also uses that prefix for real PLT stubs.
- Multi-range functions are currently skipped with a warning. Only add support
  after the IR has a way to represent function chunks.
- Parsers return `ParseResult`; they do not print or modify the binary.
- Raise `ParseError` for invalid input. `is_supported` must return `False`
  instead of raising.
- Keep parser tests pinned to exact fixture metadata so regressions are visible.

## Code style

- Python 3.10+ with type hints.
- Use `from __future__ import annotations`.
- Prefer dataclasses and small, focused modules.
- Follow the existing import and naming style.
- Module docstrings should say what the module does, not restate the design
  document or the author's reasoning.
- Keep comments for non-obvious constraints, not for narration.
- Avoid new dependencies unless they are necessary; update `requirements.txt`.

## Tests

- Use pytest.
- Add tests for new behavior and failure paths.
- Use `tmp_path` for malformed or temporary inputs; do not write into the repo.
- Do not use blanket module-level skips. Mark individual pending tests.
- If `test/sample.c` changes, rebuild it and regenerate the Ghidra fixture.
- Generated fixtures must not contain machine-specific paths, usernames, or
  timestamps. Sanitize them before committing.
- Run the full suite before finishing:

```sh
python -m pytest -q
```

## Documentation

- Keep the main `README.md` high-level. Do not add incidental build logs or
  environment notes there; put those in `test/Makefile`, this file, or
  module-level documentation.
- Update `plan.txt` only for intentional design changes.
- Update `ir.md` for any IR or ISA contract change.

## Definition of done

- [ ] Relevant tests added or updated
- [ ] Full test suite passes
- [ ] No change to binary semantics or layout constraints
- [ ] Encoding/relocation failures are rejected, not assumed safe
- [ ] IR and ISA docs updated if their contract changed
- [ ] `AGENTS.md` "Current state" is accurate and concise
- [ ] No machine-specific data committed
