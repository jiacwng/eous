import random
import struct
from dataclasses import fields
from pathlib import Path

import lief
import pytest

from eous import loader, report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"

CLEAN = ["fixture-pe-x64.exe", "fixture-pe-x86.exe", "fixture-elf-x64", "fixture-elf-x86"]
PE64 = FIXTURES / "fixture-pe-x64.exe"


def elf_header(machine: int) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4:8] = bytes((2, 1, 1, 0))
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header)


@pytest.mark.parametrize("name", CLEAN)
def test_a_clean_fixture_yields_a_digest(name: str) -> None:
    result = report.analyse(FIXTURES / name)
    assert result.digest is not None
    assert result.refusal is None
    assert result.digest.startswith("EO1:")


@pytest.mark.parametrize("name", CLEAN)
def test_a_clean_fixture_names_the_path_it_read(name: str) -> None:
    assert report.analyse(FIXTURES / name).path == FIXTURES / name


# A field holding section bytes or chunks would scale a batch's memory with the folder.
def test_an_analysis_carries_only_what_is_printed() -> None:
    assert [f.name for f in fields(report.Analysis)] == ["path", "digest", "refusal"]


# Exactly one of digest and refusal is set. A tool that returns both, or neither, would
# leave the caller guessing.
@pytest.mark.parametrize("name", CLEAN)
def test_the_invariant_holds_on_success(name: str) -> None:
    result = report.analyse(FIXTURES / name)
    assert (result.digest is None) != (result.refusal is None)


def test_a_missing_file_refuses_as_unreadable(tmp_path: Path) -> None:
    result = report.analyse(tmp_path / "absent.bin")
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.UNREADABLE


def test_junk_bytes_refuse_as_unreadable(tmp_path: Path) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"plain text, forever" * 20)
    assert report.analyse(target).refusal.reason == report.UNREADABLE


def test_macho_refuses_by_format_and_names_it(tmp_path: Path) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
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


def compressed_copy(
    source: Path, target: Path, *, seed: int = 0, regions: int | None = None
) -> Path:
    # Real container, executable bytes replaced by noise, which is the shape of a packed file.
    parsed = lief.parse(str(source))
    raw = bytearray(source.read_bytes())
    rng = random.Random(seed)
    filled = 0
    for section in parsed.sections:
        executable = (
            section.characteristics & loader.PE_SECTION_EXECUTE
            if isinstance(parsed, lief.PE.Binary)
            else section.flags & loader.ELF_SECTION_EXECUTE
        )
        if not executable or not section.size:
            continue
        if regions is not None and filled >= regions:
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


@pytest.mark.parametrize("name", CLEAN)
def test_a_clean_binary_is_not_refused_as_packed(name: str) -> None:
    assert report.analyse(FIXTURES / name).refusal is None


def test_one_readable_region_keeps_the_digest(tmp_path: Path) -> None:
    source = FIXTURES / "fixture-pe-x64.exe"
    parsed = lief.parse(str(source))
    executable = [s for s in parsed.sections if s.characteristics & loader.PE_SECTION_EXECUTE]
    if len(executable) < 2:
        pytest.skip("fixture carries one executable section")
    target = compressed_copy(source, tmp_path / "partial.exe", regions=1)
    assert report.analyse(target).digest is not None


def posed_as(monkeypatch: pytest.MonkeyPatch, sections: tuple[loader.Section, ...]) -> None:
    source = report.loader.load(FIXTURES / "fixture-pe-x64.exe")
    posed = loader.Binary(
        path=source.path,
        format=source.format,
        arch=source.arch,
        bits=source.bits,
        entry_point=source.entry_point,
        sections=sections,
        is_il_only=False,
        has_managed_native=False,
    )
    monkeypatch.setattr(report.loader, "load", lambda _: posed)


# No clean PE in 15,435 has a writable code section. The rule is PE-only, because `loader`
# synthesises ELF sections from segments, where read-write-execute is ordinary.
def test_a_writable_executable_section_refuses_as_packed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = report.loader.load(FIXTURES / "fixture-pe-x64.exe")
    sections = tuple(
        loader.Section(
            name=s.name,
            virtual_address=s.virtual_address,
            virtual_size=s.virtual_size,
            raw_size=s.raw_size,
            executable=s.executable,
            writable=True if s.executable else s.writable,
            data=s.data,
        )
        for s in source.sections
    )
    posed_as(monkeypatch, sections)

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.PACKED
    assert "writable" in result.refusal.detail


# `loader` synthesises ELF sections from segments, and a read-write-execute segment is
# ordinary there. The rule stays with the PE evidence it was measured on.
def test_a_writable_executable_segment_keeps_an_elf_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = report.loader.load(FIXTURES / "fixture-elf-x64")
    posed = loader.Binary(
        path=source.path,
        format=source.format,
        arch=source.arch,
        bits=source.bits,
        entry_point=source.entry_point,
        sections=tuple(
            loader.Section(
                name=s.name,
                virtual_address=s.virtual_address,
                virtual_size=s.virtual_size,
                raw_size=s.raw_size,
                executable=s.executable,
                writable=True if s.executable else s.writable,
                data=s.data,
            )
            for s in source.sections
        ),
        is_il_only=False,
        has_managed_native=False,
    )
    monkeypatch.setattr(report.loader, "load", lambda _: posed)

    result = report.analyse(FIXTURES / "fixture-elf-x64")
    assert result.refusal is None
    assert result.digest is not None


def test_code_too_short_to_shingle_refuses_as_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = report.loader.load(FIXTURES / "fixture-pe-x64.exe")
    executable = next(s for s in source.sections if s.executable)
    posed_as(
        monkeypatch,
        (
            loader.Section(
                name=executable.name,
                virtual_address=executable.virtual_address,
                virtual_size=executable.virtual_size,
                raw_size=2,
                executable=True,
                writable=False,
                data=b"\xc3\xc3",
            ),
        ),
    )

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.UNREADABLE
    assert result.refusal.detail == "too little readable code"


# A resource-only library carries no code and is not packed, so it gets its own name.
def test_a_binary_with_no_executable_section_refuses_as_no_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = report.loader.load(FIXTURES / "fixture-pe-x64.exe")
    posed_as(monkeypatch, tuple(s for s in source.sections if not s.executable))

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.NO_CODE
    assert result.refusal.detail == "no executable section"


def managed(
    monkeypatch: pytest.MonkeyPatch, *, il_only: bool, native: bool, entropy_bytes: bytes = b""
) -> None:
    source = report.loader.load(FIXTURES / "fixture-pe-x64.exe")
    sections = source.sections
    if entropy_bytes:
        sections = tuple(
            loader.Section(
                name=s.name,
                virtual_address=s.virtual_address,
                virtual_size=s.virtual_size,
                raw_size=len(entropy_bytes),
                executable=s.executable,
                writable=s.writable,
                data=entropy_bytes if s.executable else s.data,
            )
            for s in sections
        )
    posed = loader.Binary(
        path=source.path,
        format=source.format,
        arch=source.arch,
        bits=source.bits,
        entry_point=source.entry_point,
        sections=sections,
        is_il_only=il_only,
        has_managed_native=native,
    )
    monkeypatch.setattr(report.loader, "load", lambda _: posed)


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


# Managed is judged before the sweep, so an il-only assembly never reports as packed.
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
        ("junk.bin", b"plain text, forever" * 20),
        ("thing.macho", struct.pack("<I", 0xFEEDFACF) + bytes(4096)),
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
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    assert report.analyse(target).refusal.reason == report.UNSUPPORTED_FORMAT


def test_results_are_frozen() -> None:
    result = report.analyse(FIXTURES / "fixture-elf-x64")
    with pytest.raises(AttributeError):
        result.digest = "x"  # type: ignore[misc]


def test_a_refusal_is_frozen() -> None:
    refusal = report.Refusal(report.UNREADABLE, "gone")
    with pytest.raises(AttributeError):
        refusal.reason = "other"  # type: ignore[misc]


def test_analysis_repeats(tmp_path: Path) -> None:
    path = FIXTURES / "fixture-pe-x64.exe"
    assert report.analyse(path).digest == report.analyse(path).digest
