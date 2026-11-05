# Critique — `codezip` / `plan.txt`

## Status

- **Editorial pass:** applied to a staged copy at `/root/.opencode/plan/plan.edited.txt` (57 replacements, no semantic changes). `/in/plan.txt` is untouched because this session is in Plan mode and writes outside the plan directory are blocked.
- **This file:** `/root/.opencode/plan/critique.md`.
- **IDs** are stable so we can walk them one at a time: **B** = blocker, **H** = high, **M** = medium, **L** = low.

## Verdict

The skeleton is right: parse → lift → optimize → verify, with an ISA abstraction and a free-space model. The problem is that the two "aggressive" passes — dead-code removal and outlining — are the two hardest problems in binary rewriting, and the plan specifies them as straightforward loops. As written, the plan cannot honor "the semantics of the binary cannot change." It can honor a narrower, provable version. Recommend keeping the skeleton and cutting scope.

---

## 0. Questions that change the design

**Q1. What is the free space for?** Total bytes, largest contiguous executable hole, or a specific alignment? The objective and the allocator differ. If the answer is "one large region," function-level removal is the only mechanism that produces one; outlining only produces tail slivers.

Goal here: produce maximum amount of unused space in the binary. Continuity irrelevant.

**Q2. Target format?** ELF64 x86-64 only? PIE or non-PIE? Stripped? Signed or self-checksummed? Are C++ exceptions / unwinding in scope? Each answer removes whole classes of work.

We're gonna support everything. ELF, PE, raw binary. x86-64 to start, planned extension to other reasonable ISAs.

**Q3. What does "functions do not move" mean?** Entry points and extents fixed, or literally no instruction may change address? The outliner relocates instructions inside functions, so the literal reading is already violated. This determines whether return addresses, interior labels, and unwind ranges are allowed to change.

The entry point & extents don't change. Everything else is fair game. 

**Q4. What counts as semantics?** Return values + memory + syscalls only, or also stack traces, timing, signal delivery, debugger visibility? Outlining adds a stack frame, which is observable to profilers, sanitizers, and unwinders even when registers are identical.

Just the things normally visible. Stupid question.

**Q5. Is the input function list complete?** The plan says it may be partial (line 162). If so, dead-code removal must be conservative, and "no incoming references" is not enough.

The function list may be incomplete, but we're gonna be really conservative about dead code removal more on that later.

**Q6. Fill byte and idempotence?** `0x00`, `0xCC`, or `0x90`? Does the tool need to re-run on its own output? Zeroed regions disassemble as garbage and pollute the next analysis.

Non idempotent. Fill byte irrelevant. Stupid question.
---

## 1. Blockers

### B1. Dead-function removal is unsound

**Location:** `optimizers/function_remover.py` (232–241), `Uplifter.build_xrefs` (158–175).

**Problem:** "no incoming references" ≠ unreachable. Missing roots: entry point, exported/dynamic symbols, `.init_array` / `.fini_array` / `.preinit_array`, `.eh_frame` personality/LSDA, relocations, jump tables in `.rodata`, vtables/RTTI, TLS callbacks, PLT/GOT, signal handlers, `atexit` targets, `dlsym` targets, IFUNCs. Indirect calls (`call [rax+0x18]`) and runtime-computed pointers are invisible to the scan.

Also incomplete: one pass of "no incoming refs" never removes mutually-referencing dead cycles, and never re-examines functions whose only caller was just removed.

**Fix:** mark-and-sweep from an explicit root set, iterated to a fixpoint; treat tail calls (`jmp other_func`) as call edges; scan data sections + relocations (not every byte); validate that no reference, relocation, symbol, or unwind entry points inside a freed range; check interval overlap before freeing.

We're sweeping the full binary for two things at every offset:
    - Anything that can be interpreted as a pointer to the start of the function
    - Anything that can be interpreted as an instruction that would cause control flow to transition to the start of the function
We can have specific formats add a list extra function addresses to avoid (i.e. ELF should add everything in the export list)
Indirect calls should be fine if we're working on the assumption that we're working targeting something that's effectively normal c:
    - doing math on function pointers is illegal in c, so the pointer must exist somewhere to get pulled in for the indirect jump
Am I missing anything here?


### B2. Outlining soundness conditions are missing

**Location:** `optimizers/outliner.py` (244–324).

**Problem:** replacing an inline window with `call` + `ret` changes the machine state in ways the plan never checks. The genuine hazards:

- **Terminators.** A window containing `ret`, `jmp`, or any branch out cannot be closed with a single appended `ret`; the `ret` would return to the call site instead of the original destination. Only straight-line, single-entry/single-exit fallthrough windows are legal.

Correct. Excluded these from basic block comparison by adding is_outlinable to instructions

- **Stack balance.** `ret` pops from the current `rsp`. If the window leaves the stack unbalanced (unmatched `push`/`pop`, `leave`, `add rsp, N`), `ret` returns to garbage. Require net-zero stack delta.

Correct. Excluded these from basic block comparison by adding is_outlinable to instructions for simplicity

- **`rsp`-relative operands.** After `call`, `rsp` is 8 lower, so `[rsp+off]` addresses the wrong slot. Either reject windows with `rsp`-relative memory, or rewrite the displacement to `[rsp+off+8]` in the shared copy (uniform, since every call site pushes 8).

Yeah, let's relocate them

- **Red zone.** The `call` writes the return address at `[rsp-8]`, inside the caller's 128-byte red zone. A leaf function that relies on the red zone across the window breaks. Reject windows in functions that use the red zone.

let's exclude those. Added.

- **Nested calls.** If the window contains a `call`, the callee now sees `rsp % 16 == 0` instead of `8` (or vice versa), violating the SysV alignment rule. Reject call-containing windows, or insert `sub rsp, 8` / `add rsp, 8`.
Calls are excluded now because they modify the stack register

- **Unwind.** The shared block has no FDE; unwinding or a signal handler that walks the stack from inside it sees an extra frame. Declare this out of scope or add an FDE (which needs free space in `.eh_frame`).
Not gonna handle this for now at least

**Fix:** adopt the explicit checklist in §6; reject any candidate that fails, rather than trying to repair it.

### B3. Matching keyed on raw instruction bytes is semantically wrong

**Location:** line 251 (`position_invariant_instruction_encoding`), 265–270.

**Problem:** identical bytes at two different addresses do not mean identical behavior for position-dependent instructions. `mov rax, [rip+disp]` at two sites reads two different addresses. `call rel32` at two sites calls two different targets. `jmp rel8` at two sites jumps to two different places. Keying on raw bytes silently merges semantically different windows; keying only on "position-invariant" encodings throws away most real matches, and the term is never defined.

**Fix:** define a canonical key — mnemonic + normalized operands, with branch and `rip`-relative targets resolved to absolute addresses. Re-encode the shared copy with the correct targets. This both makes the key correct and increases the match rate.

position_invariant_instruction_encoding is just the bytes of the function re-linked to a standard address -> noted explicitly

### B4. No target hole exists before the source rewrite

**Location:** `outliner.run_optimizer` (253–258).

**Problem:** `extract_instruction_regions` rewrites source sites into `call`s, then `relink_in_instructions` places the shared blocks into free space. But the free space is produced by the same pass (shrinking functions) or by the previous remover pass. If there is no pre-existing hole (e.g., no dead functions), there is nowhere to put the first shared block, and the outliner is a no-op. If a hole is later reclaimed by the remover, a live shared block can be erased.

**Fix:** a single allocator with a defined order: (1) reachability + reclaim dead functions, (2) reserve/allocate target blocks, (3) rewrite source sites, (4) coalesce leftovers. Never allocate into a region owned by a later pass.

noted that outliner must run after the function remover. The freed space is already being generated before relink_in_instructions runs - by extract_instruction_regions. I think this is fine.

### B5. Instruction reordering is unsound as specified

**Location:** `convert_basic_block_to_given_instruction_order_and_minimize_instruction_distance` (424–454), `can_swap_instruction` (457–469).

**Problem:** `modifies` / `depends_on` over `StateSpace{name, size}` cannot express memory aliasing, sub-register overlap (`eax`/`rax`/`al`), implicit operands (`rsp` for push/pop, `rsi`/`rdi`/`rcx` for string ops, `rbp` for `leave`, flags), or `rip`-relative addressing. Without an alias analysis, the only safe rule is "reject any pair where either instruction touches memory," which eliminates most useful reordering. Moving a flag-setting instruction across a flag-reading one changes behavior. Moving a `rip`-relative load changes what it reads.

**Fix:** do not reorder in v1. If it stays, it needs flags as a first-class state, a register hierarchy, an alias/memory model, liveness, and a proper scheduling objective — i.e., an IR. That is a research project, not a pass.

### B6. There is no encoder/patcher

**Location:** `isa/x86_64.py` (480–481), `ISA.relocate_instruction` / `set_instruction_target` (475–477).

**Problem:** Capstone is a disassembler. It cannot synthesize `call`, `jmp`, `ret`, `push`, or `pop`, and it cannot re-encode a relocated instruction. Every rewrite path needs an encoder.

**Fix:** you do not need a full assembler. (a) For relocated existing instructions, patch only the displacement/immediate field in the original bytes; Capstone exposes `disp_offset`/`disp_size` and `imm_offset`/`imm_size` in detail mode. This preserves prefixes and encoding choices. (b) For synthesized instructions, a tiny table-driven encoder for `call rel32` (5 bytes), `jmp rel8/rel32`, `ret` (1 byte), `push`/`pop`, and `sub/add rsp, imm8` is enough. Add a round-trip test: disassemble and re-emit every original instruction at its original address; require byte identity.

For both B5 and B6: Yeah, the Instruction class is gonna be pretty extensive. I think it's fair to call it a full IR - please split out the relevant bits from plan.txt to their own doc.

### B7. No metadata updates

**Location:** absent.

**Problem:** moving instructions invalidates `.eh_frame` / `.pdata` (unwinding, C++ exceptions, backtraces), `.rela.text` relocations pointing into moved code, symbol sizes, and DWARF line info. Zeroing a dead function leaves a stale FDE/symbol pointing at zeros. If any of these is in scope, the plan is incomplete; if not, the "semantics unchanged" claim is scoped down and must say so.

**Fix:** a metadata module that either rewrites these in place (needs free space in the metadata sections) or explicitly documents the exclusion. Minimum: update/remove FDEs and relocations for every modified function.

Let's add a pass to the 
### B8. Basic blocks are `TODO`

**Location:** lines 153–154.

**Problem:** the outliner is defined entirely in terms of basic blocks, but block boundaries, CFG edges, dominators, and liveness are undefined. This is the foundation, not a detail.

**Fix:** define a block as a maximal straight-line sequence ending at a branch/ret (calls do not terminate a block for outlining purposes, but they are barriers for B2's nested-call rule). Build the CFG from recursive descent from function entries and known targets, not from a linear sweep. Separately define an **outline window** (single-entry/single-exit straight-line region) — it is not the same thing as a CFG basic block.

Sounds good to me. Add to the plan.

### B9. Cross-reference construction is noisy and incomplete

**Location:** `build_xrefs` (158–175).

**Problem:** linear-sweeping and disassembling from every offset decodes data as code and fabricates edges; pointer-scanning every offset produces false positives. More importantly, it misses relative jump tables (PIE GCC emits 4-byte offsets relative to the table base or entry, not absolute 8-byte addresses), tail calls, PLT thunks, and `rip`-relative GOT loads. False negatives here are the dangerous ones.

**Fix:** recursive descent from known entries; scan `.data`/`.rodata` with relocations; detect jump-table patterns (`cmp`/`ja` + `jmp [table + reg*8]` or `[table + reg*4]`) and read the table; treat `jmp other_func` as a call edge; treat PLT stubs as functions and follow the GOT entry. Accept false positives (they only block removal), never accept unproven false negatives.

Which of these are actually a problem if we're scanning for pointers too? Can GCC actually emit function calls using a relative jump table? That should just be for switch statements (and we're already avoiding functions with relative jumps entirely)

### B10. "Test the modified binary" has no method

**Location:** step 4 (28–29).

**Problem:** this is the hardest part of the project and gets one bullet.

**Fix:** a verification ladder (see §7). At minimum: round-trip byte identity, static invariant checks, per-function emulation with record/replay, and whole-binary differential testing. Per-function rollback on failure.

Yeah, fair. Throw on a few things.
One thing we definitely want:
An end-to-end test that validates we didn't break anything. Find some large, well-tested C project where we can build a binary, then run *their* full test suite against that binary. Then run the full test suite again after our modifications - make sure we didn't break anything (and we get all those good tests for free!)
---

## 2. High

### H1. Code growth / jump relaxation is unhandled

**Location:** 303–312.

**Problem:** the plan assumes functions only shrink. Relocating an instruction can turn a `jmp rel8` into `jmp rel32`, or force a `mov` to a longer form, cascading and potentially making a function longer. The two-pass relocation scheme has no fixpoint and no growth path.

**Fix:** require non-growth. If any relocated branch would exceed its range, reject that candidate and leave the function unchanged. This is simpler and safe. A full relaxation pass is a later project.

Sure, go ahead and add the requirement.

### H2. Cost model is incomplete

**Location:** 341–342.

**Problem:** `((L_common - call_len) * N) - ret_len` ignores: `call rel32` range (±2 GB), the source site must have at least `call_len` bytes to replace (otherwise the function grows), target-hole availability/alignment/padding, stack fixups (`sub`/`add rsp, 8`) for nested calls, and the cost of an FDE if one is added. It also assumes the common window is already contiguous; if it is not, the reordering cost is unbounded.

**Fix:** model all of the above, and require the net result to be positive *after* placement. Derive the minimum match count from the cost model instead of hardcoding 3.

This is nonsense. I'm not convinced this is actually a problem

### H3. `find_basic_block_matches` uses set union, not a common window

**Location:** 328–363.

**Problem:** unioning instruction *sets* and hashing them treats `{a,b,c}` as equal to `{c,b,a}` and to `{a,b,c,d}` merged with another block. Two blocks that share 10 scattered instructions are not outlineable. The ordering the rest of the algorithm depends on is destroyed.

**Fix:** canonicalize each block's sequence; find repeated contiguous windows via n-gram hashing (or LCS followed by a contiguity check); cluster blocks by the same window. If reordering is kept, the window can be a subsequence, but then B5 applies.

Yeah, that's why try_generate_replacement_bytes goes in an attempts reordering the basic block to undo the scattering, duh.


### H4. The "3 matches" threshold is arbitrary

**Location:** 349.

**Problem:** the profitability threshold depends on window length, call/ret encoding, and target placement; a fixed 3 is both too low for short windows and unnecessarily high for long ones.

**Fix:** `savings(window, sites) = sites * (len(window) - call_len) - (len(window) + ret_len + placement_padding)`; require `savings > 0` and `len(window) >= call_len`.

Sure, go for it.

### H5. Outliner complexity is unbounded

**Location:** 344–363.

**Problem:** pairwise set unions over all basic blocks are roughly O(n²) with large set operations; on a real binary this will not finish. No time/memory budget is stated.

**Fix:** n-gram index (hash each k-gram to a list of positions), then only compare blocks that share a k-gram. Cap candidate count and document the budget.

Not gonna worry about this yet.

### H6. Pseudocode control-flow bugs

**Location:** 289–295, 396, 414, 431.

**Problem:**
- line 295: `if extracted_instruction_windows and basic_blocks_to_regenerate are empty` should be `or` (if either is empty, there is nothing to link).
fixed

- line 289/366: `matching_basic_block` vs `matching_basic_blocks` (fixed editorially, but the type is a tuple, not a set).
- line 414: returns on the first successful ordering without comparing profitability.

Huh? (lost the line number in edits)

- line 431: `while` loop has no progress bound; swaps can oscillate.

Sure, add one 

- line 396: `tuple(a, b)` is not valid Python (fixed).

**Fix:** rewrite as explicit pseudocode with pre/postconditions and a termination argument.

### H7. API contracts are undefined

**Location:** `ISA` (474–478), call sites (304, 308, 324).

**Problem:** `relocate_instruction(instruction, new_base_address)` and `set_instruction_target(instruction, new_target_address)` are called with missing arguments in several places (fixed editorially), but more importantly the contract is undefined: does `relocate` preserve the absolute target of a `call`? Does it recompute `rip`-relative displacements? Does it return a new instruction or mutate in place? Does `set_instruction_target` handle `jmp rel8` range overflow?

**Fix:** write the contract as docstrings with pre/postconditions; add a `can_encode` / `required_length` query so callers can reject growth before committing.

go for it

### H8. `UNK_LOCAL` / `UNK_NONLOCAL` are never assigned

**Location:** 150, 188–195, 310.

**Problem:** the flags are referenced by the outliner and the remover, but no pass sets them. The `>2 targets` rule (310) is also unclear: a conditional branch has 2 targets (taken + fallthrough); an indirect branch has many. Define the exact condition and who sets it.

**Fix:** set `UNK_LOCAL` when a function contains an indirect branch whose targets cannot be resolved to a finite set inside the function; set `UNK_NONLOCAL` when a target is outside the function or is not a known function entry. Propagate to the function. Document that both make the function unoutlinable.



### H9. Partial-input assumption is not propagated

**Location:** 162–164 vs 236–239.

**Problem:** the plan acknowledges the function list may be partial, then removes functions based on incoming references from that partial list. That is exactly the unsafe combination.

**Fix:** if the input is partial, disable removal by default; require `--allow-unsafe-removal` and a full-binary analysis mode. Document the trust level of each input format.

nope, this is fine because wew always analyze all bytes of the file as instructions anyways. We don't rely on function bounds for that part.
---

## 3. Medium

**M1. `StateSpace` is too weak** (212–214): no flags, sub-registers, memory, or implicit operands. Even if reordering is cut, the outliner's matching and the remover's validation need a real operand model.

Yeah, we're gonna fix this since we're moving to a full intermediate representation

**M2. Duplicate instruction storage** (184 vs 226): `Function.instructions` and `BasicBlock.instructions` are both authoritative. Pick one (blocks own instructions; the function owns blocks).
Yeah, do that

**M3. `Instruction.type` is too small** (199–202): no `branch`, `ret`, `nop`, `indirect`, `rip_relative`, `call_indirect`. The passes need to distinguish these.
Add those

**M4. `Address` sentinels as strings** (191–195): `UNK_LOCAL` / `UNK_NONLOCAL` mixed with numeric addresses will cause type confusion. Use a tagged union or an enum plus an optional address.
Sure

**M5. `has_unk_local_reference` checks the wrong field** (188–189): `outgoing_references` is `list[Reference]`, not `list[Address]`. It should check `ref.to` for the sentinel.
Fix it

**M6. Parser drops the ISA** (104, 115): `parse()` returns `list[Function]`, but the YAML has a top-level `isa`. Return a `ParseResult(isa, functions, warnings)`.
Go for it

**M7. Ghidra XML gives VAs, not file offsets** (106–115): you need a VA→file-offset mapping from ELF program headers. The referenced `sample_ghidra.xml` is not in the repo.
Yup, that's the responsibility of the Binary class now

**M8. Parser dispatch by "try to parse"** (71–78): a malformed YAML will fall through to the XML parser and produce a confusing error. Dispatch by extension plus a content sniff, and report the specific parse error.
Sure

**M9. Package/module naming** (52–56): `isa/isa.py` inside package `isa` is confusing; `uplifter.py` holds `Function`/`Instruction`/`Address`/`BasicBlock`, forcing parsers to import the uplifter just for types. Move the model to `model.py`; rename `isa/isa.py` to `isa/base.py`.

**M10. `code_xrefs` is declared but never used** (124): either wire it into `build_xrefs` or delete it.
Do whatever makes sense

**M11. Pass ordering / state ownership** (234–258): `function_remover` returns free space, `outliner` takes `free_space` as an argument, and the outliner also produces free space. There is no coalescing, no ownership rule, and no guarantee that a later pass won't reclaim a region holding live outlined code.
Future problem
**M12. CLI/determinism unspecified** (485–486): no options, exit codes, `--dry-run`, `--report-only`, `--allow-unsafe`, deterministic ordering (dict/set iteration), or idempotence.
Future problem
**M13. No tests/fixtures/CI**: unit tests for parsers, encoder round-trip, CFG, each pass; integration tests on small C binaries built with known flags; golden manifests.
Future problem
---

## 4. Low

**L1.** `disassemble` and `try_interpret_as_pointer` take a byte array in the ISA definition (476, 478) but are called with an address (138, 168, 172). Pick one; probably `(binary, address) -> ...`.
Go for it

## 5. Where I over-corrected in the first pass

This matters because it changes the recommended scope:

1. **Flags are not a problem for outlining.** `call` and `ret` do not modify EFLAGS, so the shared block's flag effects are identical to the inline sequence. The flag problem is real for *reordering* (B5), not for outlining. Do not add `pushfq`/`popfq` to the outliner; it would only waste bytes.
what are you even saying here?

4. **Jump relaxation can be avoided, not implemented.** Reject any candidate that would grow a branch out of range. That is a one-line check, not a relaxation pass.
Yeah, add that

## 8. Milestones

- **M0 (analysis only):** model, parser, disassembler, CFG, references, free-space report. No rewriting. This alone is useful and testable.
- **M1 (encoder gate):** byte-patcher + tiny encoder; round-trip every original instruction byte-identically.
- **M2 (dead code):** reachability removal + metadata updates + verification + per-function rollback.
- **M3 (outlining):** only §6-clean windows; allocator; FDE or documented exclusion.
- **M4 (research):** reordering on an IR (P-code/VEX/LLVM), if ever.
