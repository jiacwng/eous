# Decides whether a file gets a digest, and names the cause when it does without.


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from eous import disasm, loader
from eous.digest import digest as build_digest

UNREADABLE = "unreadable"
UNSUPPORTED_FORMAT = "unsupported_format"
UNSUPPORTED_ARCH = "unsupported_arch"

GATES = (UNREADABLE, UNSUPPORTED_FORMAT, UNSUPPORTED_ARCH)


@dataclass(frozen=True)
class Refusal:
    gate: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    path: Path
    digest: str | None
    refusal: Refusal | None
    binary: loader.Binary | None
    sweep: disasm.SweepResult | None


def analyse(path: Path) -> Analysis:
    path = Path(path)

    try:
        binary = loader.load(path)
    except loader.UnsupportedFormatError as exc:
        return _refuse(path, UNSUPPORTED_FORMAT, _detail(exc, "holds"))
    except loader.UnsupportedArchError as exc:
        return _refuse(path, UNSUPPORTED_ARCH, _detail(exc, "targets"))
    except loader.LoaderError as exc:
        return _refuse(path, UNREADABLE, str(exc))

    sweep = disasm.sweep(binary)
    text = build_digest(sweep.chunks, binary.arch)

    if text is None:
        return _refuse(path, UNREADABLE, "too little readable code", binary, sweep)

    return Analysis(path=path, digest=text, refusal=None, binary=binary, sweep=sweep)


def _refuse(
    path: Path,
    gate: str,
    detail: str,
    binary: loader.Binary | None = None,
    sweep: disasm.SweepResult | None = None,
) -> Analysis:
    return Analysis(
        path=path,
        digest=None,
        refusal=Refusal(gate=gate, detail=detail),
        binary=binary,
        sweep=sweep,
    )


def _detail(error: Exception, marker: str) -> str:
    # The loader phrases these as "<path> holds macho, outside PE and ELF". The cause is
    # the part after the marker, so the refusal names what the file is.
    text = str(error)
    _, _, tail = text.partition(f" {marker} ")
    return (tail.split(",")[0] or text).strip()
