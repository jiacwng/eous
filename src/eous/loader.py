# Reads a PE or ELF file and describes where its code lives.
#
# Unsupported formats and architectures raise here. Everything else becomes a field.

from __future__ import annotations

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

DOS_HEADER_SIZE = 0x40
DOS_LFANEW_OFFSET = 0x3C
COFF_SECTION_COUNT_OFFSET = 6
COFF_HEADER_END = 24
SECTION_HEADER_SIZE = 40
SECTION_RAW_SIZE_OFFSET = 16

PE_ARCHES = {"I386": "x86", "AMD64": "x86-64"}
ELF_ARCHES = {"I386": "x86", "X86_64": "x86-64"}
PE_BITS: dict[object, int] = {lief.PE.PE_TYPE.PE32: 32, lief.PE.PE_TYPE.PE32_PLUS: 64}
ELF_BITS: dict[object, int] = {lief.ELF.Header.CLASS.ELF32: 32, lief.ELF.Header.CLASS.ELF64: 64}

BITS = {"x86": 32, "x86-64": 64}

ENTROPY_CHUNK = 1 << 20

SECTION_DATA_RATIO = 2

PE_CONFIG = lief.PE.ParserConfig()
PE_CONFIG.parse_signature = False
PE_CONFIG.parse_exports = False
PE_CONFIG.parse_imports = False
PE_CONFIG.parse_rsrc = False
PE_CONFIG.parse_reloc = False

ELF_CONFIG = lief.ELF.ParserConfig()
ELF_CONFIG.parse_dyn_symbols = False
ELF_CONFIG.parse_symtab_symbols = False
ELF_CONFIG.parse_symbol_versions = False
ELF_CONFIG.parse_relocations = False
ELF_CONFIG.parse_notes = False
ELF_CONFIG.parse_overlay = False


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
        with path.open("rb") as handle:
            head = handle.read(32)
            if head[:2] != b"MZ" and head[:4] != b"\x7fELF":
                if lief.is_macho(list(head)):
                    raise UnsupportedFormatError("macho")
                if lief.is_coff(path):
                    raise UnsupportedFormatError("coff")
                raise LoaderError("no recognised container")
            raw = head + handle.read()
    except OSError as exc:
        raise LoaderError(f"cannot read: {exc.strerror}") from exc

    _check_pe_sections(raw)
    try:
        parsed = _parse(raw)
        if parsed is None:
            raise LoaderError("no recognised container")
        if isinstance(parsed, lief.PE.Binary):
            return _load_pe(parsed, len(raw))
        return _load_elf(parsed, len(raw))
    except (LoaderError, MemoryError):
        raise
    except Exception as exc:
        raise LoaderError(f"cannot parse: {exc}") from exc


def _parse(raw: bytes) -> lief.PE.Binary | lief.ELF.Binary | None:
    if raw[:2] == b"MZ":
        return lief.PE.parse(raw, PE_CONFIG)
    return lief.ELF.parse(raw, ELF_CONFIG)


def _load_pe(parsed: lief.PE.Binary, size: int) -> Binary:
    arch = _arch(lambda: parsed.header.machine, PE_ARCHES)
    characteristics = lief.PE.Section.CHARACTERISTICS
    executable = [s for s in parsed.sections if s.has_characteristic(characteristics.MEM_EXECUTE)]
    _check_overlap(executable, size)
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
        bits=_bits(lambda: parsed.optional_header.magic, PE_BITS),
        sections=_ordered(sections),
        is_il_only=is_il_only,
        has_managed_native=has_managed_native,
    )


def _load_elf(parsed: lief.ELF.Binary, size: int) -> Binary:
    arch = _arch(lambda: parsed.header.machine_type, ELF_ARCHES)
    flags = lief.ELF.Section.FLAGS
    executable = [s for s in parsed.sections if s.has(flags.EXECINSTR)]
    _check_overlap(executable, size)
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
        sections = _executable_segments(parsed, size)

    return Binary(
        format="elf",
        arch=arch,
        bits=_bits(lambda: parsed.header.identity_class, ELF_BITS),
        sections=_ordered(sections),
        is_il_only=False,
        has_managed_native=False,
    )


def _executable_segments(parsed: lief.ELF.Binary, size: int) -> list[Section]:
    flags = lief.ELF.Segment.FLAGS
    executable = [(index, s) for index, s in enumerate(parsed.segments) if s.has(flags.X)]
    _check_overlap([segment for _, segment in executable], size)
    return [
        Section(
            name=f"segment{index}",
            virtual_address=segment.virtual_address,
            writable=segment.has(flags.W),
            data=bytes(segment.content),
        )
        for index, segment in executable
    ]


def _check_pe_sections(raw: bytes) -> None:
    if len(raw) < DOS_HEADER_SIZE or raw[:2] != b"MZ":
        return
    header = struct.unpack_from("<I", raw, DOS_LFANEW_OFFSET)[0]
    if header + COFF_HEADER_END > len(raw) or raw[header : header + 4] != b"PE\0\0":
        return
    count, _, _, _, optional_size = struct.unpack_from(
        "<HIIIH", raw, header + COFF_SECTION_COUNT_OFFSET
    )
    table = header + COFF_HEADER_END + optional_size
    end = min(table + SECTION_HEADER_SIZE * count, len(raw))
    claimed = 0
    for entry in range(table, end - SECTION_HEADER_SIZE + 1, SECTION_HEADER_SIZE):
        raw_size, pointer = struct.unpack_from("<II", raw, entry + SECTION_RAW_SIZE_OFFSET)
        claimed += min(raw_size, max(0, len(raw) - pointer))
    if claimed > SECTION_DATA_RATIO * len(raw):
        raise LoaderError(
            f"sections overlap, {claimed} bytes of section data in a {len(raw)} byte file"
        )


def _check_overlap(regions: list[Any], size: int) -> None:
    code = sum(len(region.content) for region in regions)
    if code > size:
        raise LoaderError(f"executable code overlaps, {code} bytes of code in a {size} byte file")


def _ordered(sections: list[Section]) -> tuple[Section, ...]:
    return tuple(sorted(sections, key=lambda section: section.virtual_address))


def _text(value: str | bytes) -> str:
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _bits(read: Callable[[], object], widths: dict[object, int]) -> int:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        value = read()
    if value not in widths:
        raise LoaderError(f"unknown header class {value}")
    return widths[value]


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
