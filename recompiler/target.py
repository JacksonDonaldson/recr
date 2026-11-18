"""Executable ABI and machine encodings used by recr."""

from __future__ import annotations

from dataclasses import dataclass
import re

from elftools.elf.elffile import ELFFile

from isa.riscv.encoding import JUMP


@dataclass(frozen=True)
class Target:
    isa: str
    machine: str
    bits: int
    flags: int = 0
    march: str = ""

    @property
    def compiler(self) -> str:
        return "gcc" if self.machine == "EM_X86_64" else "riscv64-linux-gnu-gcc"

    @property
    def compressed(self) -> bool:
        return self.machine == "EM_RISCV" and bool(self.flags & 1)

    @property
    def alignment(self) -> int:
        if self.machine == "EM_X86_64":
            return 1
        return 2 if self.compressed else 4

    @property
    def jump_size(self) -> int:
        return 5 if self.machine == "EM_X86_64" else 4

    @property
    def landing_pad(self) -> bytes:
        return b"\xf3\x0f\x1e\xfa" if self.machine == "EM_X86_64" else b""

    @property
    def compiler_flags(self) -> tuple[str, ...]:
        if self.machine == "EM_X86_64":
            return ("-m64",)
        float_abi = ("", "f", "d")[(self.flags & 6) >> 1]
        abi = ("lp64" if self.bits == 64 else "ilp32") + float_abi
        return (
            f"-march={self.march}", f"-mabi={abi}", "-mcmodel=medlow",
            "-mno-relax", "-Wl,--no-relax", "-msmall-data-limit=0", "-ffreestanding",
        )

    def accepts_object(self, elf: ELFFile) -> bool:
        if (
            elf.header.e_type != "ET_REL" or elf.header.e_machine != self.machine
            or elf.elfclass != self.bits or not elf.little_endian
        ):
            return False
        if self.machine == "EM_X86_64":
            return True
        flags = elf.header.e_flags
        return flags & 14 == self.flags & 14 and (self.compressed or not flags & 1)

    def jump(self, source: int, destination: int) -> bytes:
        try:
            if self.machine == "EM_RISCV":
                if source % self.alignment or destination % self.alignment:
                    raise ValueError("unaligned RISC-V jump")
                return JUMP.encode(0x6F, destination - source).to_bytes(4, "little")
            return b"\xe9" + (destination - source - 5).to_bytes(4, "little", signed=True)
        except (OverflowError, ValueError) as exc:
            raise ValueError(f"cannot encode jump from {source:#x} to {destination:#x}: {exc}") from exc

    def padding(self, size: int) -> bytes:
        if self.machine == "EM_X86_64":
            return b"\x90" * size
        word, remainder = divmod(size, 4)
        if remainder and (remainder != 2 or not self.compressed):
            raise ValueError("unaligned RISC-V hook padding")
        return b"\x13\x00\x00\x00" * word + (b"\x01\x00" if remainder else b"")


X86_64 = Target("x86_64", "EM_X86_64", 64)


def raw_target(isa: str, riscv: object) -> Target:
    """Select an extension ABI for an image with no executable header."""
    if isa == X86_64.isa:
        return X86_64
    if isa not in ("riscv32", "riscv64"):
        raise ValueError(f"unsupported raw image ISA {isa!r}")
    if not isinstance(riscv, dict):
        raise ValueError("a raw RISC-V image requires a 'riscv' mapping with 'march' and 'abi'")
    bits = int(isa[-2:])
    march = riscv.get("march")
    if not isinstance(march, str) or not re.fullmatch(rf"rv{bits}[ig][a-z0-9_]*", march):
        raise ValueError(f"'riscv.march' must be an RV{bits} GCC architecture string")
    base = "ilp32" if bits == 32 else "lp64"
    abis = (base, base + "f", base + "d")
    abi = riscv.get("abi")
    if abi not in abis:
        raise ValueError(f"'riscv.abi' must be one of {', '.join(abis)}")
    first, *extensions = march[4:].split("_")
    compressed = "c" in first or any(re.fullmatch(r"(?:c|zca)(?:[0-9]+p[0-9]+)?", ext) for ext in extensions)
    flags = (abis.index(abi) << 1) | compressed
    return Target(isa, "EM_RISCV", bits, flags, march)


def executable_target(elf: ELFFile) -> Target:
    if elf.header.e_type != "ET_EXEC" or not elf.little_endian:
        raise ValueError("recr requires a little-endian non-PIE ELF executable")
    if elf.header.e_machine == "EM_X86_64" and elf.elfclass == 64:
        return X86_64
    if elf.header.e_machine != "EM_RISCV" or elf.elfclass not in (32, 64):
        raise ValueError("recr supports x86-64, RV32, and RV64 ELF executables")

    flags = elf.header.e_flags
    if flags & 8 or flags & 6 == 6:
        raise ValueError("unsupported RISC-V embedded or quad-float ABI")
    bits = elf.elfclass
    attributes = elf.get_section_by_name(".riscv.attributes")
    if hasattr(attributes, "iter_subsections"):
        for subsection in attributes.iter_subsections():
            for scope in subsection.iter_subsubsections():
                for attribute in scope.iter_attributes():
                    if attribute.tag == "TAG_ARCH":
                        return Target(f"riscv{bits}", "EM_RISCV", bits, flags, attribute.value)

    letters = ("", "f", "fd")[(flags & 6) >> 1]
    march = f"rv{bits}i{letters}{'c' if flags & 1 else ''}_zicsr"
    return Target(f"riscv{bits}", "EM_RISCV", bits, flags, march)
