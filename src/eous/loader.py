# Reads a PE or ELF file and describes where its code lives.
#
# Unsupported formats and architectures raise here. Everything else becomes a field.

from __future__ import annotations

import struct
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import lief
import numpy

lief.logging.disable()

# 7.0 catches 44.1% of packed files, against 41.7% at 7.2, with the same 0.1% false alarms.
ENTROPY_THRESHOLD = 7.0

CLR_DIRECTORY_KEY = lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER
COR20_SIZE = 72
COR20_FLAGS_OFFSET = 16
COR20_NATIVE_OFFSET = 64
COR20_IL_ONLY = 0x1

PE_ARCHES = {"I386": "x86", "AMD64": "x86-64"}
ELF_ARCHES = {"I386": "x86", "X86_64": "x86-64"}

BITS = {"x86": 32, "x86-64": 64}


class LoaderError(Exception):
    pass


class UnsupportedFormatError(LoaderError):
    pass


class UnsupportedArchError(LoaderError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    executable: bool
    writable: bool
    data: bytes

    @property
    def entropy(self) -> float:
        return data_entropy(self.data)


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
    def executable_sections(self) -> tuple[Section, ...]:
        executable = [s for s in self.sections if s.executable]
        return tuple(sorted(executable, key=lambda s: s.virtual_address))

    @property
    def target(self) -> str:
        return f"{self.format}{self.bits}"


def data_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = numpy.bincount(numpy.frombuffer(data, dtype=numpy.uint8), minlength=256)
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
        parsed = lief.parse(str(path))
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
    sections = tuple(
        Section(
            name=_text(section.name),
            virtual_address=section.virtual_address,
            executable=section.has_characteristic(characteristics.MEM_EXECUTE),
            writable=section.has_characteristic(characteristics.MEM_WRITE),
            data=bytes(section.content),
        )
        for section in parsed.sections
    )
    is_il_only, has_managed_native = read_clr(parsed)

    return Binary(
        format="pe",
        arch=arch,
        bits=64 if parsed.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS else 32,
        sections=sections,
        is_il_only=is_il_only,
        has_managed_native=has_managed_native,
    )


def _load_elf(parsed: lief.ELF.Binary) -> Binary:
    arch = _arch(lambda: parsed.header.machine_type, ELF_ARCHES)
    flags = lief.ELF.Section.FLAGS
    sections = tuple(
        Section(
            name=_text(section.name),
            virtual_address=section.virtual_address,
            executable=section.has(flags.EXECINSTR),
            writable=section.has(flags.WRITE),
            data=bytes(section.content),
        )
        for section in parsed.sections
    )
    # A stripped ELF keeps its loadable segments, which is the usual shape of packed ELF.
    if not any(section.executable for section in sections):
        sections = sections + tuple(_executable_segments(parsed))

    return Binary(
        format="elf",
        arch=arch,
        bits=64 if parsed.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32,
        sections=sections,
        is_il_only=False,
        has_managed_native=False,
    )


def _executable_segments(parsed: lief.ELF.Binary) -> Iterator[Section]:
    flags = lief.ELF.Segment.FLAGS
    for index, segment in enumerate(parsed.segments):
        if segment.has(flags.X):
            yield Section(
                name=f"segment{index}",
                virtual_address=segment.virtual_address,
                executable=True,
                writable=segment.has(flags.W),
                data=bytes(segment.content),
            )


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
