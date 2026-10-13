# Reads a PE or ELF file and describes where its code lives.
#
# Unsupported formats and architectures raise here. Everything else becomes a field.

from __future__ import annotations

import math
import struct
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief
import numpy

lief.logging.disable()

CLR_DIRECTORY_KEY = lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER
COR20_SIZE = 72
COR20_FLAGS_OFFSET = 16
COR20_NATIVE_OFFSET = 64
COR20_IL_ONLY = 0x1

PE_ARCHES = {"I386": "x86", "AMD64": "x86-64"}
ELF_ARCHES = {"I386": "x86", "X86_64": "x86-64"}

BITS = {"x86": 32, "x86-64": 64}

MIB = 1 << 20
# Twice the largest code found on a Windows 11 machine, 264.7 MiB in msedge.dll.
CODE_LIMIT = 512 * MIB
ENTROPY_CHUNK = MIB


class LoaderError(Exception):
    pass


class UnsupportedFormatError(LoaderError):
    pass


class UnsupportedArchError(LoaderError):
    pass


class CodeTooLargeError(LoaderError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    writable: bool
    data: bytes


@dataclass(frozen=True)
class Binary:
    format: str
    arch: str
    # ELF names the width in EI_CLASS and PE in the optional header magic. The machine
    # field names the instruction set, and the two disagree on the x32 ABI.
    bits: int
    sections: tuple[Section, ...]
    is_il_only: bool
    has_managed_native: bool

    @property
    def target(self) -> str:
        return f"{self.format}{self.bits}"


def data_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    view = numpy.frombuffer(data, dtype=numpy.uint8)
    counts = numpy.zeros(256, dtype=numpy.int64)
    for start in range(0, view.size, ENTROPY_CHUNK):
        counts += numpy.bincount(view[start : start + ENTROPY_CHUNK], minlength=256)
    share = counts[counts > 0] / len(data)
    return float(-numpy.sum(share * numpy.log2(share)))


def read_clr(binary: Any) -> tuple[bool, bool]:
    directory = binary.data_directory(CLR_DIRECTORY_KEY)
    if directory is None or directory.size == 0:
        return (False, False)

    try:
        header = bytes(binary.get_content_from_virtual_address(directory.rva, COR20_SIZE))
    except (TypeError, ValueError, RuntimeError):
        header = b""

    # ECMA-335 fixes this field at 72, so a forged directory pointing at ordinary code fails.
    if len(header) < COR20_SIZE or struct.unpack_from("<I", header, 0)[0] != COR20_SIZE:
        return (False, False)

    flags = struct.unpack_from("<I", header, COR20_FLAGS_OFFSET)[0]
    _, native_size = struct.unpack_from("<II", header, COR20_NATIVE_OFFSET)

    il_only = bool(flags & COR20_IL_ONLY)
    has_native = native_size != 0
    return (il_only, has_native)


def load(path: Path) -> Binary:
    try:
        directory, regular = path.is_dir(), path.is_file()
    except (OSError, ValueError) as exc:
        raise LoaderError("path cannot be read") from exc
    if directory:
        raise LoaderError("path is a directory")
    if not regular:
        raise LoaderError("file is absent")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LoaderError(f"cannot read: {exc.strerror}") from exc

    try:
        parsed = lief.parse(raw)
    except Exception as exc:
        raise LoaderError(f"cannot parse: {exc}") from exc

    if parsed is None:
        raise LoaderError("no recognised container")

    if isinstance(parsed, lief.PE.Binary):
        return _load_pe(parsed)
    if isinstance(parsed, lief.ELF.Binary):
        return _load_elf(parsed)

    family = type(parsed).__module__.rsplit(".", 1)[-1].lower()
    raise UnsupportedFormatError(family)


def _load_pe(parsed: lief.PE.Binary) -> Binary:
    arch = _arch(lambda: parsed.header.machine, PE_ARCHES)
    characteristics = lief.PE.Section.CHARACTERISTICS
    executable = [s for s in parsed.sections if s.has_characteristic(characteristics.MEM_EXECUTE)]
    _check_limit(executable)
    sections = [
        Section(
            name=_text(section.name),
            virtual_address=section.virtual_address,
            writable=section.has_characteristic(characteristics.MEM_WRITE),
            data=bytes(section.content),
        )
        for section in executable
    ]
    is_il_only, has_managed_native = read_clr(parsed)

    return Binary(
        format="pe",
        arch=arch,
        bits=64 if parsed.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 32,
        sections=_ordered(sections),
        is_il_only=is_il_only,
        has_managed_native=has_managed_native,
    )


def _load_elf(parsed: lief.ELF.Binary) -> Binary:
    arch = _arch(lambda: parsed.header.machine_type, ELF_ARCHES)
    flags = lief.ELF.Section.FLAGS
    executable = [s for s in parsed.sections if s.has(flags.EXECINSTR)]
    _check_limit(executable)
    sections = [
        Section(
            name=_text(section.name),
            virtual_address=section.virtual_address,
            writable=section.has(flags.WRITE),
            data=bytes(section.content),
        )
        for section in executable
    ]
    # A stripped ELF keeps its loadable segments, which is the usual shape of packed ELF.
    if not sections:
        sections = _executable_segments(parsed)

    return Binary(
        format="elf",
        arch=arch,
        bits=64 if parsed.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32,
        sections=_ordered(sections),
        is_il_only=False,
        has_managed_native=False,
    )


def _executable_segments(parsed: lief.ELF.Binary) -> list[Section]:
    flags = lief.ELF.Segment.FLAGS
    executable = [(index, s) for index, s in enumerate(parsed.segments) if s.has(flags.X)]
    _check_limit([segment for _, segment in executable])
    return [
        Section(
            name=f"segment{index}",
            virtual_address=segment.virtual_address,
            writable=segment.has(flags.W),
            data=bytes(segment.content),
        )
        for index, segment in executable
    ]


def _check_limit(regions: list[Any]) -> None:
    size = sum(len(region.content) for region in regions)
    if size > CODE_LIMIT:
        raise CodeTooLargeError(
            f"{math.ceil(size * 10 / MIB) / 10} MiB of executable code, "
            f"limit {CODE_LIMIT // MIB} MiB"
        )


def _ordered(sections: list[Section]) -> tuple[Section, ...]:
    return tuple(sorted(sections, key=lambda section: section.virtual_address))


def _text(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _arch(read: Callable[[], object], arches: dict[str, str]) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        value = read()
    name = getattr(value, "name", None)
    machine = name if isinstance(name, str) else str(value)
    arch = arches.get(machine)
    if arch is None:
        raise UnsupportedArchError(machine)
    return arch
