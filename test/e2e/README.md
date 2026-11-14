# End-to-end codezip check

`run_e2e.py` builds a pinned pcre2 release, exports its functions with Ghidra,
runs pcre2's own test suite, rewrites `pcre2test` and `pcre2grep` with codezip,
and requires the same suite to pass again. It is intentionally outside the
default pytest run: it needs network access on the first invocation and takes
about 4 minutes on the development machine. The first run also clones pcre2 and
builds the corpus. `mutation_check.py` then measures whether that suite would
actually notice a corrupted rewrite.

```sh
make -C test e2e
```

## Prerequisites

- Linux x86-64 with a C compiler, `make`, `git`, and autotools
  (`autoconf`, `automake`, `libtoolize`).
- Ghidra 12.2 with JDK 25, at `~/opt/ghidra` by default. Override the location
  with `GHIDRA_HOME`.
- Network access the first time the source checkout is created.

## What it does

1. Clones `pcre2` tag `pcre2-10.49` (commit
   `6f9d7c1373262c541324a16a358785b33ef116cf`) into `test/build/e2e/pcre2`.
   A cached checkout at the wrong commit is replaced.
2. Configures and builds it with

   ```text
   --disable-shared --disable-jit
   CFLAGS=-O0 -g3 -fno-pie -fno-inline -fno-omit-frame-pointer
          -falign-functions=1
   LDFLAGS=-no-pie
   ```

   The finished `pcre2test` and `pcre2grep` binaries are saved under
   `test/build/e2e/baseline/`, keyed by the pinned commit, build flags, and
   binary hashes. Later runs reuse them instead of rebuilding.
3. Runs `make check` as a baseline.
4. Builds the `pcre2grep` library corpus (see below) and captures its output.
5. Exports `pcre2test` and `pcre2grep` with the repository's
   `ExportGhidraXml.java`, unless an export already matches the binary and
   script hashes recorded in `test/build/e2e/results/ghidra-exports.json`.
6. Runs codezip on both binaries with `--receipt`.
7. Checks that the output keeps the file size and differs from the input only
   by `0xff` bytes inside the receipt ranges.
8. Installs the codezipped binaries, runs `make check` and the library corpus
   again, and restores the originals even if either check fails.

Logs, exports, receipts, and `summary.json` are written under
`test/build/e2e/`. Remove that directory to force a fresh checkout, build, and
Ghidra export.

## pcre2grep library corpus

`RunGrepTest` concentrates on pcre2grep's file and option handling and barely
touches the statically linked pcre2 library. `grep_corpus.py` extracts the
`/pattern/` lines and subject strings from pcre2's own `testdata/testinput*`
files and runs them through the binary in plain and UTF (`-u`) modes. Inline
equivalents of pcre2test's `i`, `m`, `s`, `x`, `ucp`, and related modifiers are
added where pcre2grep has no per-pattern option.

Each candidate pattern is compiled and run against the whole subject corpus
using a reference binary. Patterns that fail, write to stderr, or take longer
than half a second are dropped. `test/e2e/survivor_cases.json` holds verified
single-pattern cases for code that the bulk corpus cannot reach: 158 special
cases (normal `-o` output, sometimes with an extra option such as `-v`,
`-P`, or `-U`), 16 compile-error cases (run separately so one bad pattern does
not abort the corpus), and 4 default-output cases (run without `-o`). Cases
can also supply raw `subjects_hex` bytes. The result is
cached under `test/build/e2e/grep-corpus/<digest>/`, keyed by the testdata,
the reference binary, the curated cases, and the filter limits, so the build
happens once per checkout. The bulk corpus has roughly 3,000 plain and 1,800
UTF patterns over about 4,000 subject lines; running both modes takes roughly
10-15 seconds, and the special cases add a few seconds.

`run_e2e.py` captures the corpus output before codezip and requires the
codezipped `pcre2grep` to produce identical stdout, stderr, and exit status.
`mutation_check.py` uses the same corpus as an additional oracle.

## Mutation sensitivity check

A passing suite is only useful if it would notice a broken rewrite.
`mutation_check.py` flips random bytes in the codezipped binaries and runs the
matching pcre2 script (`RunTest` for `pcre2test`; `RunGrepTest` plus the
library corpus for `pcre2grep`):

```sh
make -C test e2e-mutation
# or: test/e2e/mutation_check.py --trials 40 --flips 8
```

By default it uses 20 trials per binary, flips one executable byte per trial,
and exits nonzero if a detection rate falls below 40%. `--region mapped` and
`--region file` widen the mutation pool to loadable bytes or the whole file;
debug sections, symbol tables, and read-only data are not executed, so those
regions dilute the measurement.

The sensible expectation is not 100%, and single-byte detection has a hard
ceiling. Even `pcre2test`'s `RunTest`, which executes about 97% of the match
engine, notices only 64% of single-byte flips (22 of 33 flips inside `match`
are semantically inert). The bulk library corpus raises `pcre2grep` from about
22% to 52% in a 100-trial run at one flip. Three survivor samples have since
been triaged one by one. The 57 survivors of the first sample produced 38
witnesses and the 42 survivors of a second 100-trial sample (seed 2) produced
18 more. A third sample, eight 100-trial runs (seeds 3-10), left 346
survivors; triage produced 122 more witnesses, taking that sample from 56.8%
to 72%. The 267 mutations still uncaught across the three samples are
equivalent mutants, unreachable internal-error/UTF paths, or need a library
API that `pcre2grep` does not expose (partial matching, offset limits,
invalid-UTF checking, copied subjects, alternate compile contexts). Increasing
`--flips` makes the corruption large enough to reach observable state. Use
`--region code --flips 1` for the strictest measurement of the bytes the
programs execute, or `--flips 8` for a coarser check.

Because each `pcre2grep` trial also runs the corpus, a 20-trial run takes
several minutes. The first run also pays the one-time corpus build.

The script writes per-trial logs for detected mutations, plus a JSON record of
every mutation and outcome, under `test/build/e2e/`. It requires the
`pcre2test.codezip` and `pcre2grep.codezip` artifacts from `make -C test e2e`.

## Build flag notes

GCC emits switch jump tables even at `-O0`. The uplifter cannot resolve the
targets of the resulting indirect jump, so when a reachable instruction has an
unresolved local flow it treats the remaining decoded bytes as additional entry
regions. The function keeps its `UNK_LOCAL` outgoing reference, which lets
passes that need a complete CFG skip it. The fixture therefore does not need
`-fno-jump-tables`.

## Recorded result

On the pinned build used during development, both suites passed before and
after the rewrite:

| Binary | Freed bytes | Freed ranges |
| --- | ---: | ---: |
| `pcre2test` | 61 | 4 |
| `pcre2grep` | 1881 | 23 |
| **Total** | **1942** | **27** |

The exact counts depend on the compiler and glibc, so the script records them
in `summary.json` and asserts only that the rewrite freed at least one byte and
left the rest of each image unchanged.
