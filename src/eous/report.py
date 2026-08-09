# Decides whether a file gets a digest, and names the cause when it does without.


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from eous import disasm, loader
from eous.digest import NGRAM
from eous.digest import digest as build_digest

UNREADABLE = "unreadable"
UNSUPPORTED_FORMAT = "unsupported_format"
UNSUPPORTED_ARCH = "unsupported_arch"
PACKED = "packed"
MANAGED = "managed"
NO_CODE = "no_code"
PACKED_SHARE = 0.5


@dataclass(frozen=True)
class Refusal:
    reason: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    path: Path
    digest: str | None
    refusal: Refusal | None


def disassemble(binary: loader.Binary) -> disasm.Disassembly:
    return disasm.disassemble(binary, repeat_cap=NGRAM, minimum_run=NGRAM)


def analyse(path: Path) -> Analysis:
    path = Path(path)

    try:
        binary = loader.load(path)
    except loader.UnsupportedFormatError as exc:
        return _refuse(path, UNSUPPORTED_FORMAT, str(exc))
    except loader.UnsupportedArchError as exc:
        return _refuse(path, UNSUPPORTED_ARCH, str(exc))
    except loader.LoaderError as exc:
        return _refuse(path, UNREADABLE, str(exc))

    if binary.is_il_only and not binary.has_managed_native:
        return _refuse(path, MANAGED, "il only, no native code")

    executable = binary.executable_sections
    if not executable:
        return _refuse(path, NO_CODE, "no executable section")

    if binary.format == "pe":
        writable = next((section.name for section in executable if section.writable), None)
        if writable is not None:
            return _refuse(path, PACKED, f"executable section {writable} is writable")

    disassembly = disassemble(binary)
    if disassembly.compressed_share >= PACKED_SHARE:
        share = f"{disassembly.compressed_share:.0%} of executable code is compressed"
        return _refuse(path, PACKED, share)

    text = build_digest(disassembly.runs, binary.target)

    if text is None:
        return _refuse(path, UNREADABLE, "too little readable code")

    return Analysis(path=path, digest=text, refusal=None)


def _refuse(path: Path, reason: str, detail: str) -> Analysis:
    return Analysis(path=path, digest=None, refusal=Refusal(reason=reason, detail=detail))
