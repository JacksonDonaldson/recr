# x86-64 test fixtures

- `opcodes.s` — 50+ instruction matrix used by the SLEIGH decoder tests.
- `intel_64bit_forms.txt` — every unique valid 64-bit instruction form from
  the Intel instruction tables, as published in
  [x86-csv](https://github.com/GregoryComer/x86-csv), a machine-readable copy
  of the Intel 64 and IA-32 Architectures Software Developer's Manual
  instruction tables.
- `intel_cases.py` — converts the Intel forms to NASM syntax and builds
  `build/intel_cases.json` with bytes assembled at the original and relocated
  origins.
- `stack_cases.py` — builds `build/stack_cases.json`, assembling every memory
  form with RSP, ESP, and RBP bases plus the same form biased by the pointer
  size.  RBP variants are unchanged because the outlining call preserves RBP.
- `intel_state_effects.json` — committed canonical modifies/depends-on golden
  for every decodable form. Regenerate with `make -C isa/x86_64/test
  state-golden` after an intentional decoder change.

Build everything with:

```sh
make -C isa/x86_64/test
```
