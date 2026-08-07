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

# A binary keeping a tenth of its code readable still has code worth digesting.
PACKED_SHARE = 0.9


@dataclass(frozen=True)
class Refusal:
    gate: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    path: Path
    digest: str | None
    refusal: Refusal | None


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

    # Judged before the sweep, since an assembly holding only bytecode has no native
    # instructions to read.
    if binary.is_il_only and not binary.has_managed_native:
        return _refuse(path, MANAGED, "il only, no native code")

    sweep = disasm.sweep(binary)
    if sweep.compressed_share >= PACKED_SHARE:
        share = f"{sweep.compressed_share:.0%} of executable code is compressed"
        return _refuse(path, PACKED, share)

    text = build_digest(sweep.chunks, binary.arch)

    if text is None:
        return _refuse(path, UNREADABLE, "too little readable code")

    return Analysis(path=path, digest=text, refusal=None)


def _refuse(path: Path, gate: str, detail: str) -> Analysis:
    return Analysis(path=path, digest=None, refusal=Refusal(gate=gate, detail=detail))
