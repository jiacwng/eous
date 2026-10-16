import random
import struct
from dataclasses import replace
from pathlib import Path

import lief
import pytest

from conftest import ELF64, FIXTURES, MACHO, PE64, elf_header
from eous import loader, report


def test_a_missing_file_refuses_as_unreadable(tmp_path: Path) -> None:
    result = report.analyse(tmp_path / "absent.bin")
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.UNREADABLE


def test_other_architectures_refuse_by_arch_and_name_it(tmp_path: Path) -> None:
    target = tmp_path / "aarch64.elf"
    target.write_bytes(elf_header(183))
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


def compressed_copy(source: Path, target: Path) -> Path:
    # Real container, executable bytes replaced by noise, which is the shape of a packed file.
    raw = bytearray(source.read_bytes())
    rng = random.Random(0)
    parsed = lief.PE.parse(str(source))
    for section in parsed.sections:
        if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
            start, size = section.offset, section.size
            raw[start : start + size] = rng.randbytes(size)
    target.write_bytes(bytes(raw))
    return target


def test_a_compressed_binary_refuses_as_packed(tmp_path: Path) -> None:
    target = compressed_copy(FIXTURES / "fixture-pe-x64.exe", tmp_path / "packed.exe")
    result = report.analyse(target)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.PACKED
    assert result.refusal.detail.endswith("of executable code is compressed")
    assert result.refusal.detail.startswith(("9", "100"))


def pose(monkeypatch: pytest.MonkeyPatch, binary: loader.Binary) -> None:
    monkeypatch.setattr(report.loader, "load", lambda _: binary)


def with_writable_code(source: loader.Binary) -> loader.Binary:
    sections = tuple(replace(s, writable=True) for s in source.sections)
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
    short = replace(source.sections[0], writable=False, data=b"\xc3\xc3")
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
    pose(monkeypatch, replace(source, sections=()))

    result = report.analyse(PE64)
    assert result.digest is None
    assert result.refusal is not None
    assert result.refusal.reason == report.NO_CODE
    assert result.refusal.detail == "no executable section"


NOISE = random.Random(20261012).randbytes(8192)
CODE = b"\x31\xc0\x50" * 4 + b"\xc3"


def with_code(monkeypatch: pytest.MonkeyPatch, *blobs: bytes) -> report.Analysis:
    source = loader.load(PE64)
    sections = tuple(
        loader.Section(f".s{index}", 0x1000 * (index + 1), False, blob)
        for index, blob in enumerate(blobs)
    )
    pose(monkeypatch, replace(source, sections=sections))
    return report.analyse(PE64)


def test_a_compressed_section_alone_refuses_as_fully_packed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = with_code(monkeypatch, NOISE)
    assert result.refusal == report.Refusal(report.PACKED, "100% of executable code is compressed")


# 128 equally frequent bytes carry exactly log2(128) = 7.0 bits, which is the threshold, so
# these two pin that the comparison includes its boundary.
def test_a_section_exactly_at_the_threshold_counts_as_compressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    edge = bytes(range(128)) * 64
    assert loader.data_entropy(edge) == report.ENTROPY_THRESHOLD
    assert with_code(monkeypatch, edge).refusal.reason == report.PACKED


def test_a_substantial_readable_section_keeps_the_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    assert with_code(monkeypatch, NOISE, CODE * 2048).digest is not None


# A section holds at most log2(size) bits of entropy, so a tiny readable section can sit
# beside a compressed one without meaning the binary is readable.
def test_a_tiny_readable_section_leaves_the_binary_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = with_code(monkeypatch, NOISE, CODE)
    assert result.refusal == report.Refusal(report.PACKED, "100% of executable code is compressed")


def test_half_the_code_compressed_refuses_as_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = with_code(monkeypatch, NOISE[:4096], CODE * 315 + b"\xc3")
    assert result.refusal == report.Refusal(report.PACKED, "50% of executable code is compressed")


def test_filler_alone_refuses_as_unreadable(monkeypatch: pytest.MonkeyPatch) -> None:
    for filler in (b"\x90", b"\xcc", b"\x00\x00"):
        result = with_code(monkeypatch, filler * 32768)
        assert result.refusal == report.Refusal(report.UNREADABLE, "too little readable code")


def test_an_empty_section_is_not_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    result = with_code(monkeypatch, b"")
    assert result.refusal == report.Refusal(report.UNREADABLE, "too little readable code")


def test_running_out_of_memory_refuses_that_file_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    def exhausted(path: Path) -> loader.Binary:
        raise MemoryError

    monkeypatch.setattr(report.loader, "load", exhausted)
    assert report.analyse(PE64).refusal == report.Refusal(report.UNREADABLE, "out of memory")


def managed(
    monkeypatch: pytest.MonkeyPatch, *, il_only: bool, native: bool, entropy_bytes: bytes = b""
) -> None:
    source = loader.load(PE64)
    sections = source.sections
    if entropy_bytes:
        sections = tuple(replace(s, data=entropy_bytes) for s in sections)
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


# Managed is judged before disassembly, so an il-only assembly never reports as packed.
def test_managed_is_judged_before_packed(monkeypatch: pytest.MonkeyPatch) -> None:
    managed(monkeypatch, il_only=True, native=False, entropy_bytes=random.randbytes(8192))
    assert report.analyse(PE64).refusal.reason == report.MANAGED


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("absent.bin", None),
        ("thing.macho", MACHO),
    ],
    ids=["absent", "macho"],
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
