import random
import struct
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import lief
import pytest

from conftest import ELF64, FIXTURES, JUNK, MACHO, NAMES, PE64, elf_header
from eous import disasm, loader, report


@pytest.mark.parametrize("name", NAMES)
def test_a_clean_fixture_yields_a_digest_and_no_refusal(name: str) -> None:
    result = report.analyse(FIXTURES / name)
    assert result.path == FIXTURES / name
    assert result.refusal is None
    assert result.digest is not None
    assert result.digest.startswith("EO1:")


# A field holding section bytes or runs would scale a batch's memory with the folder.
def test_an_analysis_carries_only_what_is_printed() -> None:
    assert [f.name for f in fields(report.Analysis)] == ["path", "digest", "refusal"]


def test_a_missing_file_refuses_as_unreadable(tmp_path: Path) -> None:
    result = report.analyse(tmp_path / "absent.bin")
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.UNREADABLE


def test_junk_bytes_refuse_as_unreadable(tmp_path: Path) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(JUNK)
    assert report.analyse(target).refusal.reason == report.UNREADABLE


def test_macho_refuses_by_format_and_names_it(tmp_path: Path) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(MACHO)
    refusal = report.analyse(target).refusal
    assert refusal.reason == report.UNSUPPORTED_FORMAT
    assert "mach" in refusal.detail.lower()


@pytest.mark.parametrize(("machine", "label"), [(183, "aarch64"), (8, "mips"), (40, "arm")])
def test_other_architectures_refuse_by_arch_and_name_it(
    tmp_path: Path, machine: int, label: str
) -> None:
    target = tmp_path / f"{label}.elf"
    target.write_bytes(elf_header(machine))
    refusal = report.analyse(target).refusal
    assert refusal.reason == report.UNSUPPORTED_ARCH
    assert refusal.detail


# ARM64. The ELF path above and this one are the two halves of the same documented refusal.
def test_a_pe_for_another_architecture_refuses_by_arch(tmp_path: Path) -> None:
    raw = bytearray(PE64.read_bytes())
    header = struct.unpack_from("<I", raw, 0x3C)[0]
    struct.pack_into("<H", raw, header + 4, 0xAA64)
    target = tmp_path / "arm64.exe"
    target.write_bytes(bytes(raw))

    refusal = report.analyse(target).refusal
    assert refusal is not None
    assert refusal.reason == report.UNSUPPORTED_ARCH


def compressed_copy(source: Path, target: Path, *, seed: int = 0, limit: int | None = None) -> Path:
    # Real container, executable bytes replaced by noise, which is the shape of a packed file.
    parsed = lief.parse(str(source))
    raw = bytearray(source.read_bytes())
    rng = random.Random(seed)
    filled = 0
    for section in parsed.sections:
        executable = (
            section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
            if isinstance(parsed, lief.PE.Binary)
            else section.has(lief.ELF.Section.FLAGS.EXECINSTR)
        )
        if not executable or not section.size:
            continue
        if limit is not None and filled >= limit:
            continue
        start, size = section.offset, section.size
        raw[start : start + size] = bytes(rng.randrange(256) for _ in range(size))
        filled += 1
    target.write_bytes(bytes(raw))
    return target


@pytest.mark.parametrize("name", ["fixture-pe-x64.exe", "fixture-pe-x86.exe"])
def test_a_compressed_binary_refuses_as_packed(tmp_path: Path, name: str) -> None:
    target = compressed_copy(FIXTURES / name, tmp_path / name)
    result = report.analyse(target)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.PACKED
    assert result.refusal.detail.endswith("of executable code is compressed")
    assert result.refusal.detail.startswith(("9", "100"))


def test_one_readable_section_keeps_the_digest(tmp_path: Path) -> None:
    parsed = lief.parse(str(PE64))
    execute = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
    executable = [s for s in parsed.sections if s.has_characteristic(execute)]
    if len(executable) < 2:
        pytest.skip("fixture carries one executable section")
    target = compressed_copy(PE64, tmp_path / "partial.exe", limit=1)
    assert report.analyse(target).digest is not None


def pose(monkeypatch: pytest.MonkeyPatch, binary: loader.Binary) -> None:
    monkeypatch.setattr(report.loader, "load", lambda _: binary)


def with_writable_code(source: loader.Binary) -> loader.Binary:
    sections = tuple(replace(s, writable=s.writable or s.executable) for s in source.sections)
    return replace(source, sections=sections)


# No clean PE in 15,435 has a writable code section. The rule is PE-only, because `loader`
# synthesises ELF sections from segments, where read-write-execute is ordinary.
def test_a_writable_executable_section_refuses_as_packed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pose(monkeypatch, with_writable_code(loader.load(PE64)))

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.PACKED
    assert "writable" in result.refusal.detail


def test_a_writable_executable_segment_keeps_an_elf_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pose(monkeypatch, with_writable_code(loader.load(ELF64)))

    result = report.analyse(ELF64)
    assert result.refusal is None
    assert result.digest is not None


def test_code_too_short_to_shingle_refuses_as_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = loader.load(PE64)
    executable = next(s for s in source.sections if s.executable)
    short = replace(executable, writable=False, data=b"\xc3\xc3")
    pose(monkeypatch, replace(source, sections=(short,)))

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.UNREADABLE
    assert result.refusal.detail == "too little readable code"


# A resource-only library carries no code and is not packed, so it gets its own name.
def test_a_binary_with_no_executable_section_refuses_as_no_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = loader.load(PE64)
    pose(
        monkeypatch, replace(source, sections=tuple(s for s in source.sections if not s.executable))
    )

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.NO_CODE
    assert result.refusal.detail == "no executable section"


def managed(
    monkeypatch: pytest.MonkeyPatch, *, il_only: bool, native: bool, entropy_bytes: bytes = b""
) -> None:
    source = loader.load(PE64)
    sections = source.sections
    if entropy_bytes:
        sections = tuple(
            replace(s, data=entropy_bytes if s.executable else s.data) for s in sections
        )
    pose(
        monkeypatch,
        replace(source, sections=sections, is_il_only=il_only, has_managed_native=native),
    )


def test_an_il_only_assembly_refuses_as_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=False)
    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.MANAGED
    assert result.refusal.detail == "il only, no native code"


def test_a_mixed_mode_assembly_still_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=True)
    assert report.analyse(PE64).digest is not None


def test_an_assembly_carrying_native_code_still_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=False, native=False)
    assert report.analyse(PE64).digest is not None


# Managed is judged before disassembly, so an il-only assembly never reports as packed.
def test_managed_is_judged_before_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=False, entropy_bytes=random.randbytes(8192))
    assert report.analyse(PE64).refusal.reason == report.MANAGED


def test_the_managed_refusal_disassembles_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(*args: object, **kwargs: object) -> object:
        raise AssertionError("the disassembler ran")

    managed(monkeypatch, il_only=True, native=False)
    monkeypatch.setattr(report.disasm, "disassemble", unreachable)
    assert report.analyse(PE64).refusal.reason == report.MANAGED


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("absent.bin", None),
        ("junk.bin", JUNK),
        ("thing.macho", MACHO),
        ("arm64.elf", elf_header(183)),
    ],
    ids=["absent", "junk", "macho", "arm64"],
)
def test_a_refusal_detail_holds_the_cause_alone(
    tmp_path: Path, name: str, payload: bytes | None
) -> None:
    target = tmp_path / name
    if payload is not None:
        target.write_bytes(payload)
    detail = report.analyse(target).refusal.detail
    assert detail
    assert str(tmp_path) not in detail
    assert name not in detail


# Format is decided before architecture, so a Mach-O file reports what it is rather than
# what processor it targets.
def test_format_is_judged_before_architecture(tmp_path: Path) -> None:
    target = tmp_path / "arm64.macho"
    target.write_bytes(MACHO)
    assert report.analyse(target).refusal.reason == report.UNSUPPORTED_FORMAT


def test_every_result_is_frozen() -> None:
    binary = loader.load(ELF64)
    found = disasm.disassemble(binary)
    results = [
        (binary, "arch"),
        (binary.sections[0], "name"),
        (found, "total_decoded"),
        (found.reports[0], "decoded"),
        (report.analyse(ELF64), "digest"),
        (report.Refusal(report.UNREADABLE, "gone"), "reason"),
    ]
    for result, field in results:
        with pytest.raises(FrozenInstanceError):
            setattr(result, field, None)
