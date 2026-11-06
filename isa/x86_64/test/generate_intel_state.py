"""Generate the committed state-effect golden for the Intel form corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from isa.sleigher import X86Sleigher  # noqa: E402
from test.isa.known_gaps import KNOWN_CORPUS_GAPS  # noqa: E402


def _state_keys(states) -> list[str]:
    return sorted(
        {f"{state.kind.name.lower()}:{state.name}" for state in states}
    )


def generate(cases_path: Path, output_path: Path) -> None:
    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    sleigher = X86Sleigher()

    cases: dict[str, dict[str, list[str]]] = {}
    for case in payload["cases"]:
        form = case["form"]
        if form in KNOWN_CORPUS_GAPS:
            continue
        instruction = sleigher.parse(bytes.fromhex(case["old"]), address=0)
        if instruction is None:
            raise RuntimeError(f"could not decode {form!r}")
        cases[form] = {
            "modifies": _state_keys(instruction.modifies),
            "depends_on": _state_keys(instruction.depends_on),
        }

    output_path.write_text(
        json.dumps(
            {
                "source": payload.get("source", "intel_64bit_forms.txt"),
                "cases": cases,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.cases, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
