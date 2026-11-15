# Shared pytest paths and build fixtures for the codezip test suite.

from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from isa.sleigher import X86Sleigher
from isa.x86_64 import X86_64ISA

TEST_DIR = Path(__file__).parent
PROJECT_ROOT = TEST_DIR.parent

SAMPLE_SOURCE = TEST_DIR / "sample.c"
SAMPLE_ELF = TEST_DIR / "build" / "sample"
GHIDRA_XML = TEST_DIR / "fixtures" / "sample_ghidra.xml"

ASM_DIR = PROJECT_ROOT / "isa" / "x86_64" / "test"
OPCODES_SOURCE = ASM_DIR / "opcodes.s"
OPCODES_BINARY = ASM_DIR / "build" / "opcodes.bin"
RED_ZONE_SOURCE = TEST_DIR / "optimizers" / "red_zone_outline.s"
RED_ZONE_OBJECT = TEST_DIR / "build" / "red_zone_outline.o"
INTEL_FORMS = ASM_DIR / "intel_64bit_forms.txt"
INTEL_CASES = ASM_DIR / "build" / "intel_cases.json"
STACK_CASES = ASM_DIR / "build" / "stack_cases.json"
INTEL_STATE_EFFECTS = ASM_DIR / "intel_state_effects.json"
STACK_CASES_SOURCES = (
    INTEL_FORMS,
    ASM_DIR / "intel_cases.py",
    ASM_DIR / "stack_cases.py",
    PROJECT_ROOT / "ir.py",
    *sorted((PROJECT_ROOT / "isa" / "sleigher").glob("*.py")),
)


def _ensure_built(
    make_dir: Path,
    target: Path,
    sources: Path | tuple[Path, ...],
    description: str,
) -> Path:
    if not isinstance(sources, tuple):
        sources = (sources,)
    newest = max(source.stat().st_mtime for source in sources)
    if target.is_file() and target.stat().st_mtime >= newest:
        return target

    try:
        result = subprocess.run(
            ["make", "-C", str(make_dir)],
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        pytest.fail(f"could not run make to build {description}: {exc}")

    if result.returncode != 0:
        pytest.fail(
            f"could not build {description}; run 'make -C {make_dir}'\n"
            f"{result.stdout}{result.stderr}"
        )

    assert target.is_file()
    return target


@pytest.fixture(scope="session")
def sample_elf() -> Path:
    """Return the built sample ELF."""
    return _ensure_built(
        TEST_DIR, SAMPLE_ELF, SAMPLE_SOURCE, "test/build/sample"
    )


@pytest.fixture(scope="session")
def opcodes_binary() -> Path:
    """Return the multi-opcode NASM fixture."""
    return _ensure_built(
        ASM_DIR, OPCODES_BINARY, OPCODES_SOURCE, "opcodes.bin"
    )


@pytest.fixture(scope="session")
def red_zone_object() -> Path:
    """Return the red-zone outlining NASM fixture."""
    return _ensure_built(
        TEST_DIR,
        RED_ZONE_OBJECT,
        RED_ZONE_SOURCE,
        "red_zone_outline.o",
    )


@pytest.fixture(scope="session")
def intel_cases() -> dict[str, dict[str, str]]:
    """Return NASM-generated cases keyed by the Intel instruction form."""
    path = _ensure_built(
        ASM_DIR,
        INTEL_CASES,
        (INTEL_FORMS, ASM_DIR / "intel_cases.py"),
        "intel_cases.json",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {case["form"]: case for case in payload["cases"]}


@pytest.fixture(scope="session")
def stack_cases() -> dict[str, object]:
    """Return NASM-generated stack-relative cases."""
    path = _ensure_built(
        ASM_DIR,
        STACK_CASES,
        STACK_CASES_SOURCES,
        "stack_cases.json",
    )
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def intel_state_effects() -> dict[str, dict[str, list[str]]]:
    """Return committed state-effect expectations keyed by instruction form."""
    payload = json.loads(INTEL_STATE_EFFECTS.read_text(encoding="utf-8"))
    return payload["cases"]


@pytest.fixture(scope="session")
def sleigher() -> X86Sleigher:
    return X86Sleigher()


@pytest.fixture(scope="session")
def x86_64_isa() -> X86_64ISA:
    return X86_64ISA()
