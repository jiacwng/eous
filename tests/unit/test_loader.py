import math
import struct
from pathlib import Path

import pytest

from conftest import ELF64, FIXTURES, JUNK, MACHO, PE64, elf_header, stripped_elf
from eous import loader
from eous.loader import LoaderError, UnsupportedArchError, UnsupportedFormatError

CASES = [
    ("fixture-pe-x64.exe", "pe", "x86-64", "pe64"),
    ("fixture-pe-x86.exe", "pe", "x86", "pe32"),
    ("fixture-elf-x64", "elf", "x86-64", "elf64"),
    ("fixture-elf-x86", "elf", "x86", "elf32"),
]


@pytest.mark.parametrize(("name", "fmt", "arch", "target"), CASES, ids=[c[0] for c in CASES])
def test_every_fixture_parses(name: str, fmt: str, arch: str, target: str) -> None:
    path = FIXTURES / name
    binary = loader.load(path)
    assert binary.path == path
    assert binary.format == fmt
    assert binary.arch == arch
    assert binary.target == target
    assert binary.entry_point > 0
    assert len(binary.sections) > 1
    assert all(0.0 <= s.entropy <= 8.0 for s in binary.sections)
    assert binary.is_il_only is False
    assert binary.has_managed_native is False

    executable = binary.executable_sections
    assert executable
    assert all(s.executable for s in executable)
    assert [s.virtual_address for s in executable] == sorted(s.virtual_address for s in executable)
    assert any(len(s.data) > 0 for s in executable)


def test_data_entropy_of_two_equal_symbols_is_one_bit() -> None:
    assert loader.data_entropy(b"\x00\xff" * 50) == pytest.approx(1.0)


def test_data_entropy_of_empty_input_is_zero() -> None:
    assert loader.data_entropy(b"") == 0.0


def test_data_entropy_of_every_byte_once_is_eight() -> None:
    assert loader.data_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_data_entropy_of_a_repeated_byte_is_zero() -> None:
    assert loader.data_entropy(b"\x00" * 4096) == 0.0


def test_compiled_code_entropy_stays_under_the_threshold() -> None:
    binary = loader.load(PE64)
    text = binary.executable_sections[0]
    assert text.entropy < loader.ENTROPY_THRESHOLD


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
    assert binary.executable_sections
    assert b"".join(s.data for s in binary.executable_sections) == code


def test_a_stripped_elf_reports_its_segment_as_executable(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf((b"\x31\xc0" + b"\xc3") * 20))

    regions = loader.load(target).executable_sections
    assert len(regions) == 1
    assert regions[0].executable
    assert regions[0].writable is False
    assert regions[0].virtual_address == 0x400078


def test_a_binary_keeping_its_sections_ignores_the_segment_fallback() -> None:
    binary = loader.load(ELF64)
    assert all(not s.name.startswith("segment") for s in binary.executable_sections)


def test_a_parser_failure_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(_: str) -> object:
        raise RuntimeError("parser gave up")

    target = tmp_path / "anything.bin"
    target.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(loader.lief, "parse", explode)
    with pytest.raises(LoaderError, match="parser gave up"):
        loader.load(target)


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
