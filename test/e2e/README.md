# End-to-end codezip check

`run_e2e.py` builds a pinned pcre2 release, exports its functions with Ghidra,
runs pcre2's own test suite, rewrites `pcre2test` and `pcre2grep` with codezip,
and requires the same suite to pass again. It is intentionally outside the
default pytest run: it needs network access on the first invocation and takes
roughly 15 minutes.

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
          -falign-functions=1 -fno-jump-tables
   LDFLAGS=-no-pie
   ```

3. Runs `make check` as a baseline.
4. Exports `pcre2test` and `pcre2grep` with the repository's
   `ExportGhidraXml.java`.
5. Runs codezip on both binaries with `--receipt`.
6. Checks that the output keeps the file size and differs from the input only
   by `0xff` bytes inside the receipt ranges.
7. Installs the codezipped binaries, runs `make check` again, and restores the
   originals even if the suite fails.

Logs, exports, receipts, and `summary.json` are written under
`test/build/e2e/`. Remove that directory to force a fresh checkout.

## Build flag notes

`-fno-jump-tables` is required by the current uplifter. GCC emits switch jump
tables even at `-O0`, and the uplifter rejects decoded instructions that are
not reachable from the function entry through an absolute flow edge. Without
the flag, 37 of `pcre2test`'s functions failed to uplift on the development
build (for example `pcre2_printint_8`), so codezip exited before writing an
output. Handling indirect switch flow is a separate pipeline change; this
fixture deliberately keeps dispatch straight-line so the end-to-end check
exercises function removal rather than that known gap.

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
