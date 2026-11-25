# Decides whether a file gets a digest, and names the cause when it does without.


from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from eous import _native, loader

UNREADABLE = "unreadable"
UNSUPPORTED_FORMAT = "unsupported_format"
UNSUPPORTED_ARCH = "unsupported_arch"
PACKED = "packed"
MANAGED = "managed"
NO_CODE = "no_code"
INTERNAL_ERROR = "internal_error"
PACKED_SHARE = 0.5

# 7.0 catches 44.1% of packed files, against 41.7% at 7.2, with the same 0.1% false alarms.
ENTROPY_THRESHOLD = 7.0


@dataclass(frozen=True)
class Refusal:
    reason: str
    detail: str


@dataclass(frozen=True)
class Function:
    address: int
    length: int
    digest: str


@dataclass(frozen=True)
class Analysis:
    path: Path
    sha256: str | None
    digest: str | None
    refusal: Refusal | None
    functions: tuple[Function, ...] | None = None


def analyse(path: Path) -> Analysis:
    try:
        return _analyse(path, functions=False)
    except MemoryError:
        return _refuse(path, UNREADABLE, "out of memory")


def analyse_functions(path: Path) -> Analysis:
    try:
        return _analyse(path, functions=True)
    except MemoryError:
        return _refuse(path, UNREADABLE, "out of memory")


def crashed(path: Path) -> Analysis:
    return _refuse(path, UNREADABLE, "the analysis process ended abruptly")


def failed(path: Path, exc: BaseException) -> Analysis:
    return _refuse(path, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")


def overran(path: Path, seconds: float) -> Analysis:
    return _refuse(path, UNREADABLE, f"the analysis exceeded its {seconds:.0f} s time limit")


def _analyse(path: Path, functions: bool) -> Analysis:
    try:
        binary = loader.load(path, entry_points=functions)
    except loader.UnsupportedFormatError as exc:
        return _refuse(path, UNSUPPORTED_FORMAT, str(exc), exc.sha256)
    except loader.UnsupportedArchError as exc:
        return _refuse(path, UNSUPPORTED_ARCH, str(exc), exc.sha256)
    except loader.LoaderError as exc:
        return _refuse(path, UNREADABLE, str(exc), exc.sha256)

    if binary.is_il_only and not binary.has_managed_native:
        return _refuse(path, MANAGED, "il only, no native code", binary.sha256)

    if not binary.sections:
        return _refuse(path, NO_CODE, "no executable section", binary.sha256)

    if binary.format == "pe":
        writable = next(
            (section.name for section in binary.sections if section.writable and section.data),
            None,
        )
        if writable is not None:
            return _refuse(
                path, PACKED, f"executable section {writable} is writable", binary.sha256
            )

    readable = [
        section
        for section in binary.sections
        if loader.data_entropy(section.data) < ENTROPY_THRESHOLD
    ]
    share = _compressed_share(binary.sections, readable)
    if share >= PACKED_SHARE:
        return _refuse(path, PACKED, f"{share:.0%} of executable code is compressed", binary.sha256)

    bits = loader.BITS[binary.arch]
    text = _native.digest([section.data for section in readable], bits, binary.target)

    if text is None:
        return _refuse(path, UNREADABLE, "too little readable code", binary.sha256)

    found = None
    if functions:
        found = tuple(
            Function(binary.image_base + start, length, digest)
            for start, length, digest in _native.functions(
                [(section.virtual_address, section.data) for section in readable],
                bits,
                binary.target,
                list(binary.entry_points),
            )
        )
    return Analysis(path=path, sha256=binary.sha256, digest=text, refusal=None, functions=found)


# Weighed by bytes, so a stub-sized section cannot outvote the real code.
def _compressed_share(
    sections: tuple[loader.Section, ...], readable: list[loader.Section]
) -> float:
    total = sum(len(section.data) for section in sections)
    if not total:
        return 0.0
    return (total - sum(len(section.data) for section in readable)) / total


def _refuse(path: Path, reason: str, detail: str, sha256: str | None = None) -> Analysis:
    return Analysis(
        path=path, sha256=sha256, digest=None, refusal=Refusal(reason=reason, detail=detail)
    )
