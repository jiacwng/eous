import math
import struct
from pathlib import Path

import lief
import pytest

from conftest import ELF64, FIXTURES, JUNK, MACHO, PE64, elf_header, stripped_elf
from eous import loader, report
from eous.loader import LoaderError, UnsupportedArchError, UnsupportedFormatError

CASES = [
    ("fixture-pe-x64.exe", "pe", "x86-64", "pe64"),
    ("fixture-pe-x86.exe", "pe", "x86", "pe32"),
    ("fixture-elf-x64", "elf", "x86-64", "elf64"),
    ("fixture-elf-x86", "elf", "x86", "elf32"),
]


@pytest.mark.parametrize(("name", "fmt", "arch", "target"), CASES, ids=[c[0] for c in CASES])
def test_every_fixture_parses(name: str, fmt: str, arch: str, target: str) -> None:
    binary = loader.load(FIXTURES / name)
    assert binary.format == fmt
    assert binary.arch == arch
    assert binary.target == target
    assert binary.is_il_only is False
    assert binary.has_managed_native is False

    sections = binary.sections
    assert sections
    assert all(0.0 <= loader.data_entropy(s.data) <= 8.0 for s in sections)
    assert [s.virtual_address for s in sections] == sorted(s.virtual_address for s in sections)
    assert any(len(s.data) > 0 for s in sections)


def test_only_executable_sections_are_kept() -> None:
    parsed = lief.PE.parse(str(PE64))
    assert parsed is not None
    execute = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
    expected = {s.name for s in parsed.sections if s.has_characteristic(execute)}
    assert len(expected) < len(parsed.sections)
    assert {s.name for s in loader.load(PE64).sections} == expected


def test_data_entropy_of_two_equal_symbols_is_one_bit() -> None:
    assert loader.data_entropy(b"\x00\xff" * 50) == pytest.approx(1.0)


def test_data_entropy_of_empty_input_is_zero() -> None:
    assert loader.data_entropy(b"") == 0.0


def test_data_entropy_of_every_byte_once_is_eight() -> None:
    assert loader.data_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_data_entropy_of_a_repeated_byte_is_zero() -> None:
    assert loader.data_entropy(b"\x00" * 4096) == 0.0


def test_data_entropy_is_the_same_counted_in_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    data = loader.load(PE64).sections[0].data
    whole = loader.data_entropy(data)
    monkeypatch.setattr(loader, "ENTROPY_CHUNK", 7)
    assert loader.data_entropy(data) == whole


def overlapping_elf(copies: int) -> bytes:
    raw = ELF64.read_bytes()
    table_offset = struct.unpack_from("<Q", raw, 0x28)[0]
    entry_size, count = struct.unpack_from("<HH", raw, 0x3A)
    table = raw[table_offset : table_offset + entry_size * count]
    body = bytearray(raw[:table_offset])
    extra = struct.pack("<IIQQQQIIQQ", 0, 1, 0x6, 0x400000, 0, len(body), 0, 0, 16, 0)
    out = body + table + extra * copies
    struct.pack_into("<Q", out, 0x28, len(body))
    struct.pack_into("<H", out, 0x3C, count + copies)
    return bytes(out)


def test_executable_sections_that_overlap_are_refused(tmp_path: Path) -> None:
    target = tmp_path / "overlap.elf"
    target.write_bytes(overlapping_elf(2))
    with pytest.raises(LoaderError, match="executable code overlaps"):
        loader.load(target)


def test_a_pe_whose_code_sections_share_raw_data_is_refused(tmp_path: Path) -> None:
    raw = bytearray(PE64.read_bytes())
    header = struct.unpack_from("<I", raw, 0x3C)[0]
    count = struct.unpack_from("<H", raw, header + 6)[0]
    table = header + 24 + struct.unpack_from("<H", raw, header + 20)[0]
    entries = [table + 40 * index for index in range(count)]
    code = next(e for e in entries if struct.unpack_from("<I", raw, e + 36)[0] & 0x20000000)
    other = next(e for e in entries if e != code)
    raw[other + 8 : other + 12] = raw[code + 8 : code + 12]
    raw[other + 16 : other + 24] = raw[code + 16 : code + 24]
    struct.pack_into("<I", raw, other + 36, struct.unpack_from("<I", raw, code + 36)[0])
    target = tmp_path / "shared.exe"
    target.write_bytes(bytes(raw))
    with pytest.raises(LoaderError, match="executable code overlaps"):
        loader.load(target)


def test_a_stripped_elf_whose_segments_overlap_is_refused(tmp_path: Path) -> None:
    raw = bytearray(stripped_elf(b"\x31\xc0\xc3" * 64))
    program = bytes(raw[64:120])
    struct.pack_into("<H", raw, 56, 3)
    target = tmp_path / "segments.elf"
    target.write_bytes(bytes(raw[:120]) + program * 2 + bytes(raw[120:]))
    with pytest.raises(LoaderError, match="executable code overlaps"):
        loader.load(target)


def test_compiled_code_entropy_stays_under_the_threshold() -> None:
    binary = loader.load(PE64)
    text = binary.sections[0]
    assert loader.data_entropy(text.data) < report.ENTROPY_THRESHOLD


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="absent"):
        loader.load(tmp_path / "absent.bin")


def test_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="is a directory"):
        loader.load(tmp_path)


def test_unparseable_bytes_raise(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(JUNK)
    with pytest.raises(LoaderError, match="no recognised container"):
        loader.load(junk)


def test_macho_is_refused_by_format(tmp_path: Path) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(MACHO)
    with pytest.raises(UnsupportedFormatError) as caught:
        loader.load(target)
    assert "mach" in str(caught.value).lower()


def test_a_known_machine_is_refused_by_its_name(tmp_path: Path) -> None:
    target = tmp_path / "aarch64.elf"
    target.write_bytes(elf_header(183))
    with pytest.raises(UnsupportedArchError, match="AARCH64"):
        loader.load(target)


@pytest.mark.parametrize(("machine", "label"), [(8, "mips"), (40, "arm"), (20, "ppc")])
def test_other_architectures_are_refused_by_name(tmp_path: Path, machine: int, label: str) -> None:
    target = tmp_path / f"{label}.elf"
    target.write_bytes(elf_header(machine))
    with pytest.raises(UnsupportedArchError):
        loader.load(target)


# LIEF returns a raw int for a machine value outside its table, so the refusal reports the
# number.
@pytest.mark.parametrize("machine", [999, 4242, 65535, 250, 4660])
def test_an_unrecognised_machine_refuses_by_arch(tmp_path: Path, machine: int) -> None:
    target = tmp_path / f"m{machine}.elf"
    target.write_bytes(elf_header(machine))
    with pytest.raises(UnsupportedArchError, match=str(machine)):
        loader.load(target)


def test_a_stripped_elf_still_presents_its_code(tmp_path: Path) -> None:
    code = (b"\x31\xc0" + b"\xc3") * 20
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf(code))

    binary = loader.load(target)
    assert binary.format == "elf"
    assert binary.arch == "x86-64"
    assert binary.sections
    assert b"".join(s.data for s in binary.sections) == code


def test_a_stripped_elf_reports_its_segment_as_executable(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf((b"\x31\xc0" + b"\xc3") * 20))

    sections = loader.load(target).sections
    assert len(sections) == 1
    assert sections[0].name == "segment0"
    assert sections[0].writable is False
    assert sections[0].virtual_address == 0x400078


def test_a_binary_keeping_its_sections_ignores_the_segment_fallback() -> None:
    binary = loader.load(ELF64)
    assert all(not s.name.startswith("segment") for s in binary.sections)


def test_a_parser_failure_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(_: bytes) -> object:
        raise RuntimeError("parser gave up")

    target = tmp_path / "anything.bin"
    target.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(loader.lief, "parse", explode)
    with pytest.raises(LoaderError, match="parser gave up"):
        loader.load(target)


def test_a_file_that_cannot_be_read_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(_: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    target = tmp_path / "locked.bin"
    target.write_bytes(PE64.read_bytes())
    monkeypatch.setattr(Path, "read_bytes", refuse)
    with pytest.raises(LoaderError, match="cannot read: Permission denied"):
        loader.load(target)


def test_a_name_outside_ascii_loads(tmp_path: Path) -> None:
    target = tmp_path / "café 程序.exe"
    target.write_bytes(PE64.read_bytes())
    assert loader.load(target).target == "pe64"


def test_an_unrecognised_container_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "anything.bin"
    target.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(loader.lief, "parse", lambda _: None)
    with pytest.raises(LoaderError, match="no recognised container"):
        loader.load(target)


class FakeDirectory:
    def __init__(self, rva: int, size: int) -> None:
        self.rva = rva
        self.size = size


class FakePE:
    def __init__(self, rva: int, size: int, content: bytes) -> None:
        self._directory = FakeDirectory(rva, size)
        self._content = content

    def data_directory(self, kind: object) -> FakeDirectory:
        return self._directory

    def get_content_from_virtual_address(self, rva: int, size: int) -> bytes:
        return self._content[:size]


COR20_IL_ONLY = 0x1


def make_cor20(flags: int, native_rva: int = 0, native_size: int = 0) -> bytes:
    header = bytearray(72)
    struct.pack_into("<I", header, 0, 72)
    struct.pack_into("<I", header, 16, flags)
    struct.pack_into("<II", header, 64, native_rva, native_size)
    return bytes(header)


def test_absent_clr_directory_reads_as_native() -> None:
    assert loader.read_clr(FakePE(0, 0, b"")) == (False, False)


# Data directory 14 is attacker-controlled. Pointing it at ordinary code would otherwise
# hand the loader arbitrary flags, letting a native binary claim to be pure bytecode and
# so escape being disassembled.
def test_a_header_declaring_an_impossible_size_is_distrusted() -> None:
    forged = bytearray(make_cor20(flags=COR20_IL_ONLY))
    struct.pack_into("<I", forged, 0, 0xDEADBEEF)
    assert loader.read_clr(FakePE(0x2000, 72, bytes(forged))) == (False, False)


def test_arbitrary_code_bytes_are_distrusted_as_a_header() -> None:
    text = bytes(range(72))
    il_only, native = loader.read_clr(FakePE(0x2000, 72, text))
    assert (il_only, native) == (False, False)


# The spec biases toward looking: a non-empty ManagedNativeHeader means precompiled native
# code whatever the IL-only bit says, and size alone settles it.
def test_a_native_header_with_a_zero_address_still_counts() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=COR20_IL_ONLY, native_rva=0, native_size=64))
    assert loader.read_clr(fake) == (True, True)


def test_a_missing_clr_directory_reads_as_native() -> None:
    class NoDirectory:
        def data_directory(self, kind: object) -> None:
            return None

        def get_content_from_virtual_address(self, rva: int, size: int) -> bytes:
            return b""

    assert loader.read_clr(NoDirectory()) == (False, False)


def test_il_only_assembly_is_pure_managed() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=0x1))
    assert loader.read_clr(fake) == (True, False)


def test_mixed_mode_assembly_keeps_native_code() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=0x0))
    il_only, native = loader.read_clr(fake)
    assert (il_only, native) == (False, False)


def test_ready_to_run_assembly_is_flagged_native() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=0x1, native_rva=0x5000, native_size=64))
    assert loader.read_clr(fake) == (True, True)


def test_unreadable_cor20_falls_back_to_presence() -> None:
    fake = FakePE(0x2000, 72, b"")
    assert loader.read_clr(fake) == (False, False)


def test_entropy_stays_within_eight_bits() -> None:
    # A byte carries at most 8 bits, so a skewed distribution must stay under the ceiling.
    data = bytes(byte for byte in range(256) for _ in range(byte))
    assert loader.data_entropy(data) <= 8.0 + math.ulp(8.0)
