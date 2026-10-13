# Decides whether a file gets a digest, and names the cause when it does without.


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from eous import disasm, loader
from eous.digest import digest as build_digest

UNREADABLE = "unreadable"
UNSUPPORTED_FORMAT = "unsupported_format"
UNSUPPORTED_ARCH = "unsupported_arch"
PACKED = "packed"
MANAGED = "managed"
NO_CODE = "no_code"
TOO_LARGE = "too_large"
PACKED_SHARE = 0.5

# 7.0 catches 44.1% of packed files, against 41.7% at 7.2, with the same 0.1% false alarms.
ENTROPY_THRESHOLD = 7.0


@dataclass(frozen=True)
class Refusal:
    reason: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    path: Path
    digest: str | None
    refusal: Refusal | None


def analyse(path: Path) -> Analysis:
    try:
        return _analyse(path)
    except MemoryError:
        return _refuse(path, TOO_LARGE, "out of memory")


def crashed(path: Path) -> Analysis:
    return _refuse(path, UNREADABLE, "the analysis process ended abruptly")


def _analyse(path: Path) -> Analysis:
    try:
        binary = loader.load(path)
    except loader.CodeTooLargeError as exc:
        return _refuse(path, TOO_LARGE, str(exc))
    except loader.UnsupportedFormatError as exc:
        return _refuse(path, UNSUPPORTED_FORMAT, str(exc))
    except loader.UnsupportedArchError as exc:
        return _refuse(path, UNSUPPORTED_ARCH, str(exc))
    except loader.LoaderError as exc:
        return _refuse(path, UNREADABLE, str(exc))

    if binary.is_il_only and not binary.has_managed_native:
        return _refuse(path, MANAGED, "il only, no native code")

    if not binary.sections:
        return _refuse(path, NO_CODE, "no executable section")

    if binary.format == "pe":
        writable = next((section.name for section in binary.sections if section.writable), None)
        if writable is not None:
            return _refuse(path, PACKED, f"executable section {writable} is writable")

    readable = [
        section
        for section in binary.sections
        if loader.data_entropy(section.data) < ENTROPY_THRESHOLD
    ]
    share = _compressed_share(binary.sections, readable)
    if share >= PACKED_SHARE:
        return _refuse(path, PACKED, f"{share:.0%} of executable code is compressed")

    text = build_digest(disasm.disassemble(readable, binary.arch).runs, binary.target)

    if text is None:
        return _refuse(path, UNREADABLE, "too little readable code")

    return Analysis(path=path, digest=text, refusal=None)


# Weighed by bytes, so a stub-sized section cannot outvote the real code.
def _compressed_share(
    sections: tuple[loader.Section, ...], readable: list[loader.Section]
) -> float:
    total = sum(len(section.data) for section in sections)
    if not total:
        return 0.0
    return (total - sum(len(section.data) for section in readable)) / total


def _refuse(path: Path, reason: str, detail: str) -> Analysis:
    return Analysis(path=path, digest=None, refusal=Refusal(reason=reason, detail=detail))
