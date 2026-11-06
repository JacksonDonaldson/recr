# x86-64 test fixtures

- `test.s` — single `add eax, 0x20` instruction.
- `opcodes.s` — 50+ instruction matrix used by the SLEIGH decoder tests.
- `intel_64bit_forms.txt` — every unique valid 64-bit instruction form from
  the Intel instruction tables, as published in
  [x86-csv](https://github.com/GregoryComer/x86-csv), a machine-readable copy
  of the Intel 64 and IA-32 Architectures Software Developer's Manual
  instruction tables.
- `intel_cases.py` — converts the Intel forms to NASM syntax and builds
  `build/intel_cases.json` with bytes assembled at the original and relocated
  origins.
- `intel_state_effects.json` — committed canonical modifies/depends-on golden
  for every decodable form. Regenerate with `make -C isa/x86_64/test
  state-golden` after an intentional decoder change.

Build everything with:

```sh
make -C isa/x86_64/test
```
