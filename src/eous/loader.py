# Reads a PE or ELF file and describes where its code lives.
#
# Unsupported formats and architectures raise here. Everything else becomes a field.


from __future__ import annotations

import math
import struct
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import lief

ENTROPY_THRESHOLD = 7.2
SUPPORTED_FORMATS = ("pe", "elf")
SUPPORTED_ARCHES = ("x86", "x86-64")

ENTROPY_BLOCK = 1 << 20

PE_SECTION_EXECUTE = 0x20000000
PE_SECTION_WRITE = 0x80000000
ELF_SECTION_EXECUTE = 0x4
ELF_SECTION_WRITE = 0x1

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
    entropy: float
    data: bytes


@dataclass(frozen=True)
class Binary:
    path: Path
    format: str
    arch: str
    entry_point: int
    sections: tuple[Section, ...]
    has_section_table: bool
    import_count: int
    is_managed: bool
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
    return shannon(list(Counter(data).values()))


def file_entropy(path: Path) -> float:
    counts = [0] * 256
    try:
        with path.open("rb") as handle:
            while block := handle.read(ENTROPY_BLOCK):
                for value, seen in Counter(block).items():
                    counts[value] += seen
    except OSError as exc:
        raise LoaderError(f"cannot read {path}: {exc}") from exc

    return shannon(counts)


def read_clr(binary: ClrSource) -> tuple[bool, bool, bool]:
    directory = binary.data_directory(CLR_DIRECTORY_KEY)
    if directory is None or directory.size == 0:
        return (False, False, False)

    try:
        header = bytes(
            binary.get_content_from_virtual_address(
                directory.rva, max(directory.size, COR20_MINIMUM)
            )
        )
    except (TypeError, ValueError, RuntimeError):
        header = b""

    if len(header) < COR20_MINIMUM:
        # The directory exists, so the file is managed. Whether native code rides along
        # stays unknown, and an unknown reads as absent.
        return (True, False, False)

    flags = struct.unpack_from("<I", header, COR20_FLAGS_OFFSET)[0]
    native_rva, native_size = struct.unpack_from("<II", header, COR20_NATIVE_OFFSET)

    il_only = bool(flags & COR20_IL_ONLY)
    has_native = native_rva != 0 and native_size != 0
    return (True, il_only, has_native)


def load(path: Path) -> Binary:
    path = Path(path)
    if not path.is_file():
        raise LoaderError(f"cannot read {path}: it is absent or is a directory")

    try:
        parsed = lief.parse(str(path))
    except Exception as exc:
        raise LoaderError(f"cannot parse {path}: {exc}") from exc

    if parsed is None:
        raise LoaderError(f"cannot parse {path}: no recognised container")

    if isinstance(parsed, lief.PE.Binary):
        return _load_pe(path, parsed)
    if isinstance(parsed, lief.ELF.Binary):
        return _load_elf(path, parsed)

    # lief.parse also returns Mach-O and COFF objects, and the module they come from
    # names the family.
    family = type(parsed).__module__.rsplit(".", 1)[-1].lower()
    raise UnsupportedFormatError(f"{path} holds {family}, outside PE and ELF")


def _load_pe(path: Path, parsed: lief.PE.Binary) -> Binary:
    machine = parsed.header.machine.name
    arch = PE_ARCHES.get(machine)
    if arch is None:
        raise UnsupportedArchError(f"{path} targets {machine}, outside x86 and x86-64")

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
    is_managed, is_il_only, has_managed_native = read_clr(parsed)

    return Binary(
        path=path,
        format="pe",
        arch=arch,
        entry_point=parsed.optional_header.addressof_entrypoint,
        sections=sections,
        has_section_table=bool(sections),
        import_count=len(parsed.imports),
        is_managed=is_managed,
        is_il_only=is_il_only,
        has_managed_native=has_managed_native,
    )


def _load_elf(path: Path, parsed: lief.ELF.Binary) -> Binary:
    machine = parsed.header.machine_type.name
    arch = ELF_ARCHES.get(machine)
    if arch is None:
        raise UnsupportedArchError(f"{path} targets {machine}, outside x86 and x86-64")

    # An ELF section reports one size, where a PE section separates its memory size from
    # its size on disk.
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

    return Binary(
        path=path,
        format="elf",
        arch=arch,
        entry_point=parsed.header.entrypoint,
        sections=sections,
        has_section_table=len(parsed.sections) > 0,
        import_count=len(parsed.imported_functions),
        is_managed=False,
        is_il_only=False,
        has_managed_native=False,
    )


def _text(value: str | bytes) -> str:
    # LIEF declares a section name as either text or raw bytes.
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


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
        entropy=data_entropy(data),
        data=data,
    )
