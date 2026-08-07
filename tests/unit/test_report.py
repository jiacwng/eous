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
    assert result.refusal.gate == report.UNREADABLE


def test_junk_bytes_refuse_as_unreadable(tmp_path: Path) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"plain text, forever" * 20)
    assert report.analyse(target).refusal.gate == report.UNREADABLE


def test_macho_refuses_by_format_and_names_it(tmp_path: Path) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    refusal = report.analyse(target).refusal
    assert refusal.gate == report.UNSUPPORTED_FORMAT
    assert "mach" in refusal.detail.lower()


@pytest.mark.parametrize(("machine", "label"), [(183, "aarch64"), (8, "mips"), (40, "arm")])
def test_other_architectures_refuse_by_arch_and_name_it(
    tmp_path: Path, machine: int, label: str
) -> None:
    target = tmp_path / f"{label}.elf"
    target.write_bytes(elf_header(machine))
    refusal = report.analyse(target).refusal
    assert refusal.gate == report.UNSUPPORTED_ARCH
    assert refusal.detail


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
    assert result.refusal.gate == report.PACKED
    assert result.refusal.detail.endswith("of executable code is compressed")
    assert result.refusal.detail.startswith(("9", "100"))


@pytest.mark.parametrize("name", CLEAN)
def test_a_clean_binary_stays_clear_of_the_packed_gate(name: str) -> None:
    assert report.analyse(FIXTURES / name).refusal is None


def test_one_readable_region_keeps_the_digest(tmp_path: Path) -> None:
    source = FIXTURES / "fixture-pe-x64.exe"
    parsed = lief.parse(str(source))
    executable = [s for s in parsed.sections if s.characteristics & loader.PE_SECTION_EXECUTE]
    if len(executable) < 2:
        pytest.skip("fixture carries one executable section")
    target = compressed_copy(source, tmp_path / "partial.exe", regions=1)
    assert report.analyse(target).digest is not None


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
    assert result.refusal.gate == report.MANAGED
    assert result.refusal.detail == "il only, no native code"


def test_a_mixed_mode_assembly_still_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=True)
    assert report.analyse(PE64).digest is not None


def test_an_assembly_carrying_native_code_still_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=False, native=False)
    assert report.analyse(PE64).digest is not None


# The header is attacker-controlled, so a distrusted one reads as not-il-only and the
# binary gets swept rather than waved through.
def test_a_distrusted_header_leaves_the_binary_swept(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=False, native=False)
    assert report.analyse(PE64).digest is not None


# Managed is judged before the sweep, so an il-only assembly never reports as packed.
def test_managed_is_judged_before_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=False, entropy_bytes=random.randbytes(8192))
    assert report.analyse(PE64).refusal.gate == report.MANAGED


def test_the_managed_gate_runs_no_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreachable(*args: object, **kwargs: object) -> object:
        raise AssertionError("the sweep ran")

    managed(monkeypatch, il_only=True, native=False)
    monkeypatch.setattr(report.disasm, "sweep", unreachable)
    assert report.analyse(PE64).refusal.gate == report.MANAGED


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
    assert report.analyse(target).refusal.gate == report.UNSUPPORTED_FORMAT


def test_results_are_frozen() -> None:
    result = report.analyse(FIXTURES / "fixture-elf-x64")
    with pytest.raises(AttributeError):
        result.digest = "x"  # type: ignore[misc]


def test_a_refusal_is_frozen() -> None:
    refusal = report.Refusal(report.UNREADABLE, "gone")
    with pytest.raises(AttributeError):
        refusal.gate = "other"  # type: ignore[misc]


def test_analysis_repeats(tmp_path: Path) -> None:
    path = FIXTURES / "fixture-pe-x64.exe"
    assert report.analyse(path).digest == report.analyse(path).digest
