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

Before committing, verify the staged change set, not just the working tree.
Untracked conftest files, fixtures, or tests are not part of the commit; run the
suite against a clean checkout of the index when a change spans several files.

When a change can alter the number of freed bytes (outlining, function removal,
free-space placement, or stack analysis), measure the same cached pcre2 inputs
before and after. Use `test/build/e2e/x86_64/pcre2/{pcre2test,pcre2grep}` with
the matching `test/build/e2e/x86_64/results/<name>.xml`, run
`python codezip.py <binary> <xml> -o <output> --receipt <receipt>`, and sum the
lengths in the receipt's `freed:` section. To measure the old code, create a
detached worktree at the parent commit and run the same command there. If the
cached fixtures are missing, run `make -C test e2e` first. Record the result in
the "Current state" breakdown.

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
- Every instruction that can be outlined must return `True` from
  `isa.is_outlinable(instruction)`.

When in doubt, be conservative: reject an optimization rather than risk changing behavior.

## Decoder implementation checklist

- Treat spec-format data as untrusted. Enumerate every constant kind and
  selector; unknown values must raise `SlaError`, not return `None`. Silent
  `None` returns hide missing P-code writes and varnode locations.
- Context is constructor-local. After applying context changes, store the
  updated value on the resolved constructor and use it for nested operand
  resolution, varnode lookup, and state recovery. Never reuse the root context
  for nested constructors.
- A constructor with an unresolved required subtable operand is not a valid
  decode. Reject it instead of accepting a prefix-sized partial instruction.
- Canonicalize registers at the parser/IR boundary exactly as `ir.md`
  specifies. Never leak `AL`, `AH`, `XMM0_Qa`, or other SLEIGH sub-varnodes as
  independent machine state.
- Test state effects, not only lengths and bytes. Cover partial registers,
  SIMD/AVX, x87, mask registers, memory addressing, segments, and control flow;
  keep a corpus-wide golden and hand-check representative cases.
- Test the negative space: lone prefixes, truncated encodings, invalid ModRM
  combinations, and every proper prefix of a valid instruction must be
  rejected. `FWAIT` is the documented exception because it is a standalone
  instruction.
- Verify relocation invariants directly: the absolute target before and after
  relocation must match, length must not change, and out-of-range displacements
  must be rejected. Include RIP-relative loads and stores.
- Do not derive expected values only from the implementation. Use an
  independent oracle or hand-computed cases, especially for state effects.
- Validate external fixtures before declaring an upstream bug. Record the tool,
  version, exact bytes, and evidence in `other_peoples_bugs.md`, and keep the
  test strict `xfail` until the external cause is fixed.
- Never let missing NASM, make, or other tooling skip silently. Fixture build
  and execution failures are test failures.
- Add the failure-path test in the same change as the feature. A decoder change
  without malformed-input coverage is incomplete.

## Layout

| Path | Responsibility |
| --- | --- |
| `codezip.py` | CLI and pipeline orchestration |
| `recr.py`, `recompiler/` | Compile and place .rec extensions and function hooks |
| `input_parser.py` | Select and run an input parser |
| `parsers/` | YAML and Ghidra XML exports |
| `ir.py` | IR data model |
| `cache.py` | Shared on-disk cache root for the CUDA build and SLA parse |
| `uplifter.py` | Bytes → instructions → basic blocks → CFG |
| `isa/` | ISA interface and x86-64 backend |
| `gpu/` | Optional CUDA backend for whole-image range scans |
| `optimizers/` | Function removal and outlining |
| `binary/` | ELF, PE, and raw binary access |
| `test/` | Grouped pytest suites, sample C input, NASM fixtures, Ghidra export |
| `test/e2e/` | Opt-in pcre2 end-to-end codezip check and RISC-V baseline |

## Current state

Implemented:

- `pyproject.toml` defines the `recr` distribution for editable and wheel installs.
  It provides the `codezip` and `recr` commands and bundles the x86-64 and RISC-V
  SLEIGH tables and the optional CUDA kernel source. The project code is
  available under MIT or the Unlicense. The distribution includes the Apache
  2.0 license and notice for the bundled Ghidra tables.
- `recr` compiles .rec hooks for x86-64, RV32, and RV64 non-PIE ELF with typed
  Ghidra XML. Hooks match the final component of Ghidra function names. When
  exactly two distinct entries match and one is both shorter and under eight
  bytes, recr selects the longer entry and warns with `ignoring-thunk-function`.
  Both entries stay protected. Other ambiguous hook names are rejected.
  It retains original functions used by the extension, places code and data
  in codezip receipt ranges, and installs fixed-width entry jumps and original
  call trampolines. GCC checks each hook against the selected original's
  prototype, which also declares the original for calls from the extension.
  The prototype comes from the Ghidra function entry or the raw manifest.
  Ghidra `string` data imports are declared as C character arrays.
  RISC-V `__thiscall` entries use the exported `this` structure pointer in
  `a0` as the first C parameter and retain the variadic marker.
  Missing Ghidra prototypes trigger a diagnostic with instructions to commit
  the return and parameter details before re-exporting. Recr rejects hooks
  with a Ghidra memory reference into the interior of the overwritten entry window.
  Code can span disjoint ranges.
  Writable data requires writable cleared space. GCC accepts flags, objects,
  and static libraries.
  Recr checks fixed RISC-V HI20 relocations before compaction. RISC-V
  placement checks JAL reach, relinks ELF immediates, and keeps
  AUIPC/JALR call pairs together. The RISC-V tests run the RV64 sample and
  execute hooked RV64 and RV32 ELF fixtures under QEMU.
  Recr constrains trampoline returns, hook entries, and split-section
  continuation jumps to the ISA's fixed-width jump range before allocation.
  Candidate trampolines also pass relocation checks before consuming space.
  Relocation errors identify the section offset, symbol, and encoding limit
  when known. Placement errors report permissions, alignment, and available
  cleared space. Hook errors identify conflicting entries or reference addresses.
  During compaction, unreachable decoded instructions and instructions crossing
  a declared function end warn with `invalid-function-extent`. Recr excludes
  those ranges, protects overlapping functions and recovered reference targets,
  and requires valid hook extents. Standalone codezip rejects those two extent
  errors. Both CLIs warn and skip functions whose final instruction can fall
  through, protecting any function that contains the continuation address.
  Returns and unconditional jumps, including tail jumps to the next address,
  pass the termination check. Recr applies `invalid-function-extent` to this
  warning and rejects a hook targeting such an extent.
  `--patchstream FILE` (`-p FILE`) writes an additional output for ELF and raw
  images. It includes extension writes and the function rewrites and shared
  blocks needed to reclaim their space. Each record stores the address and
  byte count as little-endian ISA words, followed by the changed bytes. A
  single all-`0xff` address word terminates the stream.
- `recr <manifest.yaml> [<functions.xml>] <hooks.rec>` also accepts static
  raw images. The manifest names the image, gives disjoint virtual regions
  with permissions, and lists entry points to preserve. Regions without a
  `file_offset` allow Ghidra data imports. Only file-backed regions are
  scanned, patched, or used for placement.
  Non-verbose raw builds reuse completed compaction from a private per-user
  temporary cache keyed by the input bytes, mappings, function metadata,
  protected addresses, and implementation. Warnings are rechecked on reuse.
  Functions and C declarations come from the manifest or a Ghidra export.
  Functions shorter than the target's instruction alignment or extending
  outside one file-backed executable region are skipped with warnings. Recr
  accepts `-Wno-skip-short-functions` and `-Wno-function-outside-executable-range`
  alongside `-Wall` and `-Werror` before `--`. RISC-V raw images declare
  their architecture and ABI. Native x86-64 and QEMU RV64 tests build static
  fixtures, patch the raw bytes, and execute them at their mapped addresses
  using both metadata sources.
- Ghidra XML parsing (`parsers/ghidra_xml.py`) and parser dispatch with
  `ParseError` handling; tests are pinned to a real Ghidra 12.2 export.  The
  parser accepts address-space-qualified values such as `ram:00011220`, which
  Ghidra 12.2 emits for RISC-V. The generic little-endian RISC-V languages
  select the RV32 or RV64 implementation. The parser skips multi-range bodies
  and starts single-range bodies at the exported entry, omitting any bytes
  before it. If the export marks no memory sections as artificial, the parser
  skips functions named in the `<EXTERNAL>` namespace.
  Ghidra `caseD_<hex>` pseudo-functions in any namespace and `default` entries
  in generated switch namespaces are excluded from compaction and hook
  selection. Their declared ranges protect overlapping functions and possible
  continuations during compaction. Hook entry spans that overlap these ranges
  are rejected.
- YAML parsing (`parsers/yaml.py`) validates function records from `.yaml`
  and `.yml` exports. A paired sample fixture matches the Ghidra function
  records, rewritten ELF, and receipt.
- ELF access (`binary/elf.py`) using `pyelftools`: `PT_LOAD` virtual-to-file
  mapping, reads with BSS zero-fill, in-memory patching via
  `write(address, data)`, `write_to_disk(path)` (metadata fixups are currently
  a no-op), and `mapped_ranges()` for enumerating loadable virtual-address
  ranges. `mapped_segments()`, `image_bytes()`, and `image_revision()` expose
  the file image that the CUDA backend uploads. `write` rejects unmapped and
  non-file-backed ranges and never touches the input file. `Binary(path)` routes
  ELF by magic bytes; PE is unimplemented and raw images use the explicit
  `RawBinary` mapping backend. Raw reads can span adjacent virtual regions,
  writes stay within one region, and unmapped file bytes are preserved.
- ELF tests (`test/binary/test_elf.py`) build `test/build/sample` with `make`
  when missing or stale, then verify Ghidra-derived `main` bytes and ELF
  mapping. Fixture-build failures are test failures, not skips.
- x86-64 package (`isa/x86_64/`) contains the pinned Ghidra 12.2 SLEIGH files
  and NASM fixtures. `X86_64ISA` decodes through the SLEIGH backend, exposes
  `is_outlinable` and `add_extra_stack_space`, and delegates relocation to the
  SLEIGH backend. `decode_flows` returns only address, length, type, and
  `flows_to`, skipping the state-effect analysis that dominates decode cost;
  its reported fields match `disassemble`. RSP-relative operands are shifted
  by the outline call;
  RBP-relative operands are left unchanged because RBP is callee-saved. Forms
  with no displacement field, disp8 overflow, RSP value use, and EVEX
  compressed disp8 (including after legacy prefixes) are conservatively
  rejected. Trap and control-transfer mnemonics that the decoder classifies as
  arithmetic are rejected explicitly, as are `ENDBR32`/`ENDBR64` so a CET
  indirect-branch target keeps its mark. Fallthrough detection is relative to
  the instruction's own address, not its predecessor. `disassemble` clamps its
  read to the mapped range so instructions at the end of a segment still
  decode.
  `try_interpret_as_pointer` reads the bytes at an offset as both
  little-endian 64-bit and 32-bit addresses and returns every readable value,
  which lets xref recovery find immediates such as `_start`'s
  `mov rdi, main`. NASM-generated tests cover every Intel
  memory form in the corpus across RSP/ESP/RBP/SIB and disp8/disp32 variants.
  `set_instruction_target` repatches relative displacement fields and rejects
  targets that do not fit. `make_call_instruction` and
  `make_return_instruction` synthesize the outline call and return.
  `uses_red_zone` tracks symbolic RSP/RBP offsets through the CFG, so
  RBP-relative locals in a function that never subtracts from RSP are treated
  as red-zone accesses. `can_outline_region` uses the same analysis to allow a
  red-zone function when the outline call's `[rsp-8, rsp)` return-address slot
  is dead on every path: the moved window must not touch it, and no path may
  read it before a covering store, a call or push at the same stack depth, or a
  return. Unmodeled stack updates, unknown RBP state, indirect flows, calls at
  a different stack depth, RSP/RBP aliases, and sites whose stack pointer is
  not pointer-aligned are rejected. The red-zone verdict and block-entry
  states are cached per function for the planning pass. The outliner drops
  only the unsafe source sites and recomputes the match's savings.
- `isa/riscv/` implements little-endian RV32 and RV64 with Ghidra 12.2 SLEIGH.
  It decodes standard and compressed instructions, tracks ABI register, RAM,
  CSR and reservation state, relocates direct branches and calls, and
  preserves AUIPC results when the new displacement fits. Missing P-code
  yields opaque effects. The mapped-image scan recovers pointers assembled
  across instructions, including GP-relative references. The direct-flow scan
  checks candidate destinations against known entries before decoding them
  with SLEIGH. It also decodes parcels whose fallthrough is a known entry.
  Outlining uses the alternate link register t0 without adjusting the stack.
  Backward CFG liveness checks the reordered suffix at every site, and functions with
  LR/SC are excluded. GNU binutils fixtures check state, malformed input,
  relocation, link liveness, and exact CLI output.
- `isa/sleigher/` parses the packed `.sla` directly: address spaces, symbols,
  constructors, decision trees, context changes, and P-code templates. The
  x86-64 decoder recovers modified and source register/flag/memory states,
  fills `flows_to` (fallthrough, direct branch/call targets, `UNK_LOCAL` for
  indirect branches, `UNK_NONLOCAL` for indirect calls, none for returns),
  propagates constructor context into nested operands, and canonicalizes
  subregisters to their root register (GPR to 64-bit, vector to ZMM, MM, ST).
  `flows_from` is left for the code-flow recovery pass.  Reassembly refreshes
  fallthrough targets while preserving absolute branch and call targets.
  x87 condition codes map to the flag state, SLEIGH scratch registers are
  excluded, and opaque userops conservatively clobber all tracked state.
  Unknown transfers (calls, returns, and indirect branches) depend on the
  System V AMD64 argument state where applicable and clobber every tracked
  state space except callee-saved RBX, RBP, R12-R15. Traps and system transfers
  that the pinned specification decodes as arithmetic (`INT`, `INT3`, `HLT`,
  `UD0`-`UD2`, `RSM`, system-call and virtualization instructions) conservatively
  clobber and depend on every tracked state, so dependency analysis cannot
  reorder code across them.
  Constructor resolution and state effects are cached per (instruction bytes,
  context); state spaces name register, flag, and memory classes and never
  carry an address, so the state-effect cache is address-independent.
  The parsed specification is also cached on disk between runs, keyed by a
  SHA-256 of the raw `.sla` bytes; the entry records the digest of `sla.py`
  itself, so a changed parser reparses and overwrites the entry. Identical
  P-code templates are hash-consed during the parse, which keeps the cached
  state compact.
  Tests cover an opcode matrix, hand-authored state-effect categories for
  partial registers/SIMD/x87/memory/segments, a committed state-effect golden
  for every decodable Intel form, hand-coded audit regressions, malformed or
  truncated byte rejection, and RIP-relative relocation. Reassembly preserves absolute targets by repatching
  relative displacement fields and is checked against NASM at a relocated
  origin. Five Intel forms are strict xfail for the external bug documented in
  `other_peoples_bugs.md`: EVEX forms missing an immediate in Ghidra 12.2
  SLEIGH.
- `uplifter.py` implements `Uplifter.uplift_function`: a strict linear decode of
  the declared extent, code-flow recovery from the entry that fills
  `flows_from` and `outgoing_references`, and basic-block construction where
  branches and returns end blocks and calls fall through. Decode overruns,
  in-function targets that are not instruction boundaries, and instructions
  unreachable from the entry are rejected, except that a reachable unresolved
  local flow (such as an indirect switch jump) lets the remaining decoded bytes
  become additional entry regions. Those functions keep an `UNK_LOCAL`
  outgoing reference, and `Function.has_unk_local_reference()` reports it so
  CFG-dependent passes can skip them. `Function.pretty_print()` renders the
  result, including incoming and outgoing references, to stdout.
  `test/uplift_sample.py` uplifts and prints every sample function;
  `test/test_uplifter.py` covers the sample, the sample's real GCC jump-table
  switch (`switch_dispatch`), a hand-authored indirect-jump case, and
  rejection paths.
- `Uplifter.build_xrefs()` scans every mapped virtual address for 64-bit and
  32-bit values and successfully decoded control-flow instructions that target a
  known function entry, then records unique incoming references. The
  instruction scan uses the ISA's flow-only decode, so it does not compute
  state effects. Ordinary fallthrough edges are not cross-references. It uses
  `ISA.iter_pointer_references` and `ISA.decode_control_flow_range`. The x86-64
  backend batches both scans on the GPU when available. RISC-V reads mapped
  ranges in bulk on the CPU, with scalar lookahead at range boundaries.
- `gpu/` is an optional CUDA backend for whole-image range scans. `gpu.available()`
  probes for `nvcc` and a device; `gpu/kernels.cu` is compiled on first use into
  the system temporary directory, keyed by the source text and compiler version.
  Without a compiler or device every caller falls back to the CPU path. The
  kernel is a table interpreter over a flattened copy of the parsed SLEIGH
  spec (`gpu/tables.py`): decision-tree matching, constructor matching, operand
  layout, context ops, expression evaluation, nested-subtable recursion, and
  P-code opcode aggregation all run one thread per address. It also builds the
  flow targets, so no address is handed back to Python. A second kernel does
  address checking (contiguous mapped bytes after an address) and a third scans
  for pointer-sized readings of known function entries. `test/gpu/` compares
  every mapped address against the per-address CPU decoder, and compares the
  whole Intel form corpus instruction by instruction (and at every byte of the
  concatenated corpus). The GPU suite requires a usable CUDA device.
- `optimizers/function_remover.py` implements `run_optimizer`: any function with
  no incoming references is dropped from the uplifter's function map and its
  whole declared extent is reported as one `FreeSpace` block with a diagnostic.
  The pass only reports ranges; the pipeline fills them.
  `test/optimizers/test_function_remover.py` covers the detection,
  preservation of referenced functions, exact free-space extents,
  and idempotence; the sample's `unreferenced_function` is the live fixture.
- `optimizers/outliner.py` implements the full outlining pass.
  `extract_instruction_regions` matches regions, generates replacement bytes,
  and regenerates the affected functions; `relink_in_instructions` places the
  shared blocks and rewrites the source call sites. It indexes outlinable
  instructions by position-invariant bytes (each instruction is re-linked to
  address zero first), groups blocks that share the same instruction set, and
  estimates net free-space savings after the inserted call, the stored shared
  block, and its return. The search starts with rare encodings and skips
  candidate groups that cannot pay for the call. It computes intersections
  once per distinct encoding set among an anchor's candidate blocks. Matches
  are capped at 10 per source block and deduplicated globally. The pass reuses
  canonical encodings for matching and planning. Functions with an unresolved local reference or
  an implicit fallthrough from their last instruction are skipped. Red-zone
  functions are eligible: each candidate source site is checked with `can_outline_region`,
  sites that are unsafe or cannot be reordered are dropped from the match, and
  the savings are recomputed. Plans with dropped sites are deferred until full
  matches have claimed their blocks. Planning groups sites by the existing
  order of the selected instructions and caches validated windows. Block
  reordering indexes instruction positions and checks dependencies and
  control transfers while making the selected window contiguous.
  Selected matches are applied greedily without overlapping source blocks.
  Function regeneration relocates every instruction, repatches branch targets,
  rejects any instruction that would grow, and drops the plans for a function
  if it cannot be regenerated. Retries reuse layouts for functions with the
  same replacements. RISC-V placement filters candidate addresses by
  displacement bounds when the address space cannot wrap. Placement checks
  call reach before relocating a shared block into the smallest compatible
  free range. RSP-relative instructions
  are biased for the call, and source calls are patched to the target. Freed
  function tails and modified live-code ranges are reported separately. The
  sample's `mix_a`/`mix_b`/`mix_c` chain shares a straight-line expression;
  those functions call helpers, so they allocate frames instead of using the
  red zone, and the sample exercises a selected match and freed function tails.
  `test/optimizers/red_zone_outline.s` covers dead slots, post-window reads,
  deeper slots, covering writes and calls, reads inside the window, register
  aliases, and dropping only the unsafe site.
  The temporary `--report-outline-matches` CLI option remains a dry run that
  prints candidates and exits 1 without writing.
- `codezip.py` parses the export, opens the binary, uplifts every function,
  recovers cross-references, runs the unreferenced-function pass, runs the
  outliner, fills every remaining free range with `0xff`, and writes the
  modified binary to `--output` (default `<binary>.codezip`). `--receipt PATH`
  also writes a YAML receipt with `freed` and `modified` ranges.
  `-v/--verbose` logs pipeline progress, parser warnings, free-space results,
  outline selections, and per-function results, and pretty-prints every
  uplifted function. `test/test_codezip.py` covers the CLI flags, verbose
  output, receipt contents, output bytes, and exit codes.
  CLI input, decode, and write errors identify the affected file and retain
  parser locations or decoder details where available.
- End-to-end check (`test/e2e/run_e2e.py`, `make -C test e2e`) builds pinned
  pcre2 10.49 with `-O0 -g3 -fno-pie ...`, exports its
  functions with Ghidra, codezips `pcre2test` and `pcre2grep`, and requires
  pcre2's `make check` to pass before and after. It also extracts patterns and
  subjects from pcre2's `testdata` and runs them through `pcre2grep` in plain
  and UTF modes to exercise the statically linked library; curated cases in
  `test/e2e/survivor_cases.json` cover rare subject escapes, compile-error
  paths, and default line-output paths. The corpus is filtered against a
  reference binary and cached under `test/build/e2e/x86_64/grep-corpus/`. The
  check is opt-in, needs Ghidra and network access, and records the freed
  ranges and byte count under `test/build/e2e/<arch>/results/`. The verifier
  requires freed ranges to be `0xff` and allows other changes only inside the
  receipt's `modified` ranges. The built `pcre2test`/`pcre2grep` binaries are
  cached in `test/build/e2e/<arch>/baseline/`, and Ghidra exports are reused
  when their binary and script hashes match, so only changed inputs are
  rebuilt or re-exported.
  The current standalone freed-byte breakdown is `pcre2test` 519 bytes in 60 ranges and
  `pcre2grep` 2161 bytes in 51 ranges (2680 bytes total). Before fallthrough
  extents were skipped, the counts were 515 and 2146 bytes (2661 total).
  The pre-red-zone baseline was 360 and 2105 bytes (2465 total).
  Switch jump tables are uplifted conservatively as unresolved local flow, so
  the build does not disable them.
- `make -C test e2e-riscv` runs the full pcre2 check on RV64 under QEMU,
  including receipt verification, the original and rewritten `make check`,
  and the plain and UTF corpus. RV64 frees 1640 bytes in 177 ranges from
  `pcre2test` and 2652 bytes in 90 ranges from `pcre2grep` (4292 total).
  Before fallthrough extents were skipped, `pcre2grep` freed 2654 bytes in
  91 ranges (4294 total).
  The RV64 pre-outlining counts were 112 and 2056 bytes (2168 total).
- Mutation sensitivity check (`test/e2e/mutation_check.py`, `make -C test
  e2e-mutation`, native x86-64 only) flips random bytes in the cached
  codezipped binaries and runs the matching pcre2 test script, plus the
  library corpus for `pcre2grep`. It
  defaults to one executable byte per trial, 20 trials per binary, and a 40%
  minimum detection rate; `--region`, `--flips`, and `--trials` adjust the
  measurement. Per-trial logs and `mutation.json` go under
  `test/build/e2e/x86_64/`. The bulk corpus raises single-byte detection for
  `pcre2grep` from roughly 22% to 52% before survivor triage. The 178 curated
  cases in `test/e2e/survivor_cases.json` come from three triaged samples:
  they catch 38 of 57 flips in the first, 18 of 42 in the second, and 122 of
  346 in the third (eight seeds of 100 trials). The 267 remaining mutations
  are equivalent, unreachable internal-error/UTF paths, or need a library API
  that `pcre2grep` does not expose. Those cannot be killed by an output-based
  CLI test, so 90% remains out of reach.

Still stubs:

- PE binary backend
- Verification passes

Do not assume an unimplemented module works. Add tests as each stub is filled in.

## Setup and checks

```sh
python -m pip install -e '.[test]'
python -m pytest -q
```

CUDA acceleration is optional for the CLI. The GPU tests require `nvcc`
and access to a CUDA device. The backend loads the shared library built from
`gpu/kernels.cu` using `ctypes`. Both the kernel build and
the parsed SLEIGH specification are cached under the system temporary
directory (`codezip-cuda/`); delete that directory to force a rebuild or a
fresh parse.

Use NASM 2.16.02 or newer. The corpus is generated with NASM 3.02; NASM
2.16.01 emits PTWRITE without the mandatory `F3` prefix (see
`other_peoples_bugs.md`).

The RISC-V decoder tests require `binutils-riscv64-linux-gnu`, which can
assemble and link both RV32 and RV64 fixtures.
The RISC-V recompilation tests also require the cross GCC, QEMU for both word
sizes, and the RV64 sysroot. The tests accept `RISCV64_CC`, `RISCV64_QEMU`,
`RISCV32_QEMU`, and `RISCV64_SYSROOT` overrides.

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

Run the opt-in end-to-end pcre2 check (Ghidra, network on first run, about
4 minutes):

```sh
make -C test e2e
# writes test/build/e2e/x86_64/results/summary.json
```

Run the RISC-V end-to-end check with `riscv64-linux-gnu-gcc`, QEMU, and the
matching sysroot. The runner accepts `RISCV64_CC`, `RISCV64_QEMU`, and
`RISCV64_SYSROOT` overrides.

```sh
make -C test e2e-riscv
# writes test/build/e2e/riscv64/results/summary.json
```

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
- Do not add defensive handling for exceptional I/O or environment failures.
  It is fine to let `OSError` and similar exceptions propagate unhandled; catch
  only errors that are expected and can be reported meaningfully.

## Tests

- Use pytest.
- Add tests for new behavior and failure paths.
- Inspect which optional records each consumer receives from pinned exports.
  Supplement sections that are absent or empty with populated fixtures that
  follow the export format. Cover absent and incomplete records where they
  have distinct behavior.
- Assert both the data extracted from optional records and the configuration
  passed through to the next stage, such as the ISA and ABI. Run regression
  tests against the old code to verify that they reproduce the reported failure.
- Exercise metadata that governs safe rewriting through the CLI. Include a
  permitted boundary and a nearby rejected value. Check the diagnostic and
  the contents of any existing binary and receipt after rejection.
- Use `tmp_path` for malformed or temporary inputs; do not write into the repo.
- Do not use blanket module-level skips. Mark individual pending tests.
- If `test/sample.c` changes, rebuild it and regenerate the Ghidra and
  equivalent YAML fixtures, including the RV64 Ghidra metadata used by recr.
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
- Do not claim an oracle, cross-check, or coverage number in documentation
  unless a test actually exercises it.

## Definition of done

- [ ] Relevant tests added or updated
- [ ] Full test suite passes
- [ ] No change to binary semantics or layout constraints
- [ ] Encoding/relocation failures are rejected, not assumed safe
- [ ] IR and ISA docs updated if their contract changed
- [ ] `AGENTS.md` "Current state" is accurate and concise
- [ ] No machine-specific data committed
