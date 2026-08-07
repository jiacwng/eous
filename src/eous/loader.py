# Reads a PE or ELF file and describes where its code lives.
#
# Unsupported formats and architectures raise here. Everything else becomes a field.


from __future__ import annotations

import math
import struct
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import lief
import numpy

lief.logging.disable()

# 7.0 catches 44.1% of packed files, against 41.7% at 7.2, with the same 0.1% false alarms.
ENTROPY_THRESHOLD = 7.0

# Rounding holds the swept-or-skipped decision steady across platform maths libraries.
ENTROPY_DECIMALS = 6

PE_SECTION_EXECUTE = 0x20000000
PE_SECTION_WRITE = 0x80000000
ELF_SECTION_EXECUTE = 0x4
ELF_SECTION_WRITE = 0x1
ELF_SEGMENT_EXECUTE = 0x1
ELF_SEGMENT_WRITE = 0x2

CLR_DIRECTORY_KEY = lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER
COR20_MINIMUM = 72
COR20_FLAGS_OFFSET = 16
COR20_NATIVE_OFFSET = 64
COR20_IL_ONLY = 0x1

PE_ARCHES = {"I386": "x86", "AMD64": "x86-64"}
ELF_ARCHES = {"I386": "x86", "X86_64": "x86-64"}


class ClrDirectory(Protocol):
    @property
    def rva(self) -> int: ...

    @property
    def size(self) -> int: ...


class ClrSource(Protocol):
    def data_directory(self, kind: Any) -> ClrDirectory | None: ...

    def get_content_from_virtual_address(self, rva: int, size: int) -> Any: ...


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
    virtual_size: int
    raw_size: int
    executable: bool
    writable: bool
    data: bytes

    @property
    def entropy(self) -> float:
        # Computed on first read and kept. A binary carries far more data than code, and
        # entropy is consulted for the executable regions alone.
        cached = self.__dict__.get("_entropy")
        if cached is None:
            cached = data_entropy(self.data)
            object.__setattr__(self, "_entropy", cached)
        return float(cached)


@dataclass(frozen=True)
class Binary:
    path: Path
    format: str
    arch: str
    entry_point: int
    sections: tuple[Section, ...]
    is_il_only: bool
    has_managed_native: bool

    @property
    def executable_sections(self) -> tuple[Section, ...]:
        executable = [s for s in self.sections if s.executable]
        return tuple(sorted(executable, key=lambda s: s.virtual_address))


def shannon(counts: Sequence[int]) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0

    accumulated = 0.0
    for count in counts:
        if count:
            share = count / total
            accumulated -= share * math.log2(share)
    return accumulated


def data_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = numpy.bincount(numpy.frombuffer(data, dtype=numpy.uint8), minlength=256)
    return round(shannon(counts.tolist()), ENTROPY_DECIMALS)


def read_clr(binary: ClrSource) -> tuple[bool, bool]:
    directory = binary.data_directory(CLR_DIRECTORY_KEY)
    if directory is None or directory.size == 0:
        return (False, False)

    try:
        header = bytes(binary.get_content_from_virtual_address(directory.rva, COR20_MINIMUM))
    except (TypeError, ValueError, RuntimeError):
        header = b""

    if len(header) < COR20_MINIMUM:
        return (False, False)

    # ECMA-335 fixes this field at 72. Demanding the exact value stops a forged data
    # directory from pointing at ordinary code and handing us arbitrary flags.
    declared_size = struct.unpack_from("<I", header, 0)[0]
    if declared_size != COR20_MINIMUM:
        return (False, False)

    flags = struct.unpack_from("<I", header, COR20_FLAGS_OFFSET)[0]
    _, native_size = struct.unpack_from("<II", header, COR20_NATIVE_OFFSET)

    il_only = bool(flags & COR20_IL_ONLY)
    # A non-empty ManagedNativeHeader means precompiled native code, whatever IL-only says.
    has_native = native_size != 0
    return (il_only, has_native)


def load(path: Path) -> Binary:
    path = Path(path)
    if path.is_dir():
        raise LoaderError("path is a directory")
    if not path.is_file():
        raise LoaderError("file is absent")

    try:
        parsed = lief.parse(str(path))
    except Exception as exc:
        raise LoaderError(f"cannot parse: {exc}") from exc

    if parsed is None:
        raise LoaderError("no recognised container")

    if isinstance(parsed, lief.PE.Binary):
        return _load_pe(path, parsed)
    if isinstance(parsed, lief.ELF.Binary):
        return _load_elf(path, parsed)

    family = type(parsed).__module__.rsplit(".", 1)[-1].lower()
    raise UnsupportedFormatError(family)


def _load_pe(path: Path, parsed: lief.PE.Binary) -> Binary:
    machine = _machine_name(lambda: parsed.header.machine)
    arch = PE_ARCHES.get(machine)
    if arch is None:
        raise UnsupportedArchError(machine)

    sections = tuple(
        _build_section(
            name=section.name,
            virtual_address=section.virtual_address,
            virtual_size=section.virtual_size,
            content=section.content,
            executable=bool(section.characteristics & PE_SECTION_EXECUTE),
            writable=bool(section.characteristics & PE_SECTION_WRITE),
        )
        for section in parsed.sections
    )
    is_il_only, has_managed_native = read_clr(parsed)

    return Binary(
        path=path,
        format="pe",
        arch=arch,
        entry_point=parsed.optional_header.addressof_entrypoint,
        sections=sections,
        is_il_only=is_il_only,
        has_managed_native=has_managed_native,
    )


def _load_elf(path: Path, parsed: lief.ELF.Binary) -> Binary:
    machine = _machine_name(lambda: parsed.header.machine_type)
    arch = ELF_ARCHES.get(machine)
    if arch is None:
        raise UnsupportedArchError(machine)

    sections = tuple(
        _build_section(
            name=section.name,
            virtual_address=section.virtual_address,
            virtual_size=section.size,
            content=section.content,
            executable=bool(section.flags & ELF_SECTION_EXECUTE),
            writable=bool(section.flags & ELF_SECTION_WRITE),
        )
        for section in parsed.sections
    )
    # A stripped ELF keeps its loadable segments, which is the usual shape of packed ELF.
    if not any(section.executable for section in sections):
        sections = sections + _executable_segments(parsed)

    return Binary(
        path=path,
        format="elf",
        arch=arch,
        entry_point=parsed.header.entrypoint,
        sections=sections,
        is_il_only=False,
        has_managed_native=False,
    )


def _executable_segments(parsed: lief.ELF.Binary) -> tuple[Section, ...]:
    built = []
    for index, segment in enumerate(parsed.segments):
        flags = int(segment.flags)
        if not flags & ELF_SEGMENT_EXECUTE:
            continue
        built.append(
            _build_section(
                name=f"segment{index}",
                virtual_address=segment.virtual_address,
                virtual_size=segment.virtual_size,
                content=segment.content,
                executable=True,
                writable=bool(flags & ELF_SEGMENT_WRITE),
            )
        )
    return tuple(built)


def _text(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _machine_name(read: Callable[[], object]) -> str:
    # LIEF raises a Python warning when the machine field holds a value it fails to
    # recognise, and returns a raw int. Both are handled here rather than reaching stderr.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        value = read()
    return _name_of(value)


def _name_of(value: object) -> str:
    # LIEF hands back an enum for architectures it knows and a raw int for the rest, so a
    # crafted machine field would otherwise reach `.name` on an integer and raise.
    name = getattr(value, "name", None)
    return name if isinstance(name, str) else str(value)


def _build_section(
    name: str | bytes,
    virtual_address: int,
    virtual_size: int,
    content: memoryview,
    executable: bool,
    writable: bool,
) -> Section:
    data = bytes(content)
    return Section(
        name=_text(name),
        virtual_address=virtual_address,
        virtual_size=virtual_size,
        raw_size=len(data),
        executable=executable,
        writable=writable,
        data=data,
    )
