import struct
from pathlib import Path

import pytest

from eous import report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"

CLEAN = ["fixture-pe-x64.exe", "fixture-pe-x86.exe", "fixture-elf-x64", "fixture-elf-x86"]


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
def test_a_clean_fixture_carries_its_intermediate_stages(name: str) -> None:
    result = report.analyse(FIXTURES / name)
    assert result.binary is not None
    assert result.sweep is not None
    assert result.path == FIXTURES / name


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


# The detail states the cause, so a reader learns what the file was without opening it.
def test_a_refusal_detail_names_a_cause() -> None:
    refusal = report.Refusal(report.UNSUPPORTED_ARCH, "aarch64")
    assert refusal.gate in report.GATES
    assert refusal.detail == "aarch64"


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


def test_the_gate_names_are_declared_in_order() -> None:
    assert report.GATES[:3] == (
        report.UNREADABLE,
        report.UNSUPPORTED_FORMAT,
        report.UNSUPPORTED_ARCH,
    )


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
