import math
import struct
from pathlib import Path

import pytest

from eous import loader
from eous.loader import LoaderError, UnsupportedArchError, UnsupportedFormatError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"

CASES = [
    ("fixture-pe-x64.exe", "pe", "x86-64"),
    ("fixture-pe-x86.exe", "pe", "x86"),
    ("fixture-elf-x64", "elf", "x86-64"),
    ("fixture-elf-x86", "elf", "x86"),
]


@pytest.fixture(params=CASES, ids=[c[0] for c in CASES])
def fixture_case(request: pytest.FixtureRequest) -> tuple[Path, str, str]:
    name, fmt, arch = request.param
    return FIXTURES / name, fmt, arch


def test_every_fixture_parses(fixture_case: tuple[Path, str, str]) -> None:
    path, fmt, arch = fixture_case
    binary = loader.load(path)
    assert binary.format == fmt
    assert binary.arch == arch
    assert binary.path == path


def test_entry_point_is_set(fixture_case: tuple[Path, str, str]) -> None:
    binary = loader.load(fixture_case[0])
    assert binary.entry_point > 0


def test_sections_are_present(fixture_case: tuple[Path, str, str]) -> None:
    binary = loader.load(fixture_case[0])
    assert len(binary.sections) > 1


def test_exactly_the_executable_sections_are_reported(
    fixture_case: tuple[Path, str, str],
) -> None:
    binary = loader.load(fixture_case[0])
    executable = binary.executable_sections
    assert executable
    assert all(s.executable for s in executable)
    assert [s.virtual_address for s in executable] == sorted(s.virtual_address for s in executable)


def test_executable_section_carries_bytes(fixture_case: tuple[Path, str, str]) -> None:
    binary = loader.load(fixture_case[0])
    assert any(len(s.data) > 0 for s in binary.executable_sections)


def test_section_entropy_is_within_range(fixture_case: tuple[Path, str, str]) -> None:
    binary = loader.load(fixture_case[0])
    assert all(0.0 <= s.entropy <= 8.0 for s in binary.sections)


def test_compiled_fixtures_read_as_native(fixture_case: tuple[Path, str, str]) -> None:
    binary = loader.load(fixture_case[0])
    assert binary.is_il_only is False
    assert binary.has_managed_native is False


def test_binary_is_frozen() -> None:
    binary = loader.load(FIXTURES / "fixture-elf-x64")
    with pytest.raises(AttributeError):
        binary.arch = "x86"  # type: ignore[misc]


def test_section_is_frozen() -> None:
    section = loader.load(FIXTURES / "fixture-elf-x64").sections[0]
    with pytest.raises(AttributeError):
        section.name = "renamed"  # type: ignore[misc]


# ---- entropy ----------------------------------------------------------------


def test_data_entropy_of_two_equal_symbols_is_one_bit() -> None:
    assert loader.data_entropy(b"\x00\xff" * 50) == pytest.approx(1.0)


def test_data_entropy_of_empty_input_is_zero() -> None:
    assert loader.data_entropy(b"") == 0.0


def test_data_entropy_of_every_byte_once_is_eight() -> None:
    assert loader.data_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_data_entropy_of_a_repeated_byte_is_zero() -> None:
    assert loader.data_entropy(b"\x00" * 4096) == 0.0


# Entropy decides whether a region is swept, so the value must land identically on any
# platform maths library. Rounding removes the last bits from that decision.
def test_entropy_is_rounded_to_a_fixed_precision() -> None:
    value = loader.data_entropy(bytes(range(256)) * 7 + b"\x01\x02\x03")
    assert value == round(value, loader.ENTROPY_DECIMALS)


def test_compiled_code_entropy_stays_under_the_threshold() -> None:
    binary = loader.load(FIXTURES / "fixture-pe-x64.exe")
    text = binary.executable_sections[0]
    assert text.entropy < loader.ENTROPY_THRESHOLD


# ---- refusals ---------------------------------------------------------------


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="absent"):
        loader.load(tmp_path / "absent.bin")


def test_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="is a directory"):
        loader.load(tmp_path)


def test_unparseable_bytes_raise(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"this is text, never an executable" * 10)
    with pytest.raises(LoaderError, match="no recognised container"):
        loader.load(junk)


def make_elf_header(machine: int, elf_class: int = 2) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = elf_class
    header[5] = 1
    header[6] = 1
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header)


def test_macho_is_refused_by_format(tmp_path: Path) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    with pytest.raises(UnsupportedFormatError) as caught:
        loader.load(target)
    assert "mach" in str(caught.value).lower()


def test_arm64_elf_is_refused_by_arch(tmp_path: Path) -> None:
    target = tmp_path / "arm64.elf"
    target.write_bytes(make_elf_header(machine=183))
    with pytest.raises(UnsupportedArchError) as caught:
        loader.load(target)
    assert "aarch64" in str(caught.value).lower() or "arm" in str(caught.value).lower()


@pytest.mark.parametrize(("machine", "label"), [(8, "mips"), (40, "arm"), (20, "ppc")])
def test_other_architectures_are_refused_by_name(tmp_path: Path, machine: int, label: str) -> None:
    target = tmp_path / f"{label}.elf"
    target.write_bytes(make_elf_header(machine=machine))
    with pytest.raises(UnsupportedArchError):
        loader.load(target)


# Found by fuzzing: LIEF returns a raw int for machine values it fails to recognise, so
# reading `.name` from one raised instead of refusing.
@pytest.mark.parametrize("machine", [999, 4242, 65535, 250, 4660])
def test_an_unrecognised_machine_refuses_by_arch(tmp_path: Path, machine: int) -> None:
    target = tmp_path / f"m{machine}.elf"
    target.write_bytes(make_elf_header(machine=machine))
    with pytest.raises(UnsupportedArchError, match=str(machine)):
        loader.load(target)


def test_a_known_machine_still_reports_its_name(tmp_path: Path) -> None:
    target = tmp_path / "aarch64.elf"
    target.write_bytes(make_elf_header(machine=183))
    with pytest.raises(UnsupportedArchError, match="AARCH64"):
        loader.load(target)


def test_unsupported_errors_are_loader_errors(tmp_path: Path) -> None:
    assert issubclass(UnsupportedFormatError, LoaderError)
    assert issubclass(UnsupportedArchError, LoaderError)


# ---- stripped ELF -----------------------------------------------------------


def make_stripped_elf(code: bytes, machine: int = 62) -> bytes:
    # An ELF64 carrying one loadable executable segment, with the section table stripped.
    # This is the ordinary shape of a packed or hostile ELF.
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4:8] = bytes((2, 1, 1, 0))
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    struct.pack_into("<Q", header, 24, 0x400078)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<Q", header, 40, 0)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 1, 0, 0, 0)

    program = bytearray(56)
    struct.pack_into("<II", program, 0, 1, 0x5)
    struct.pack_into("<QQQ", program, 8, 120, 0x400078, 0x400078)
    struct.pack_into("<QQQ", program, 32, len(code), len(code), 0x1000)

    return bytes(header) + bytes(program) + code


def test_a_stripped_elf_still_presents_its_code(tmp_path: Path) -> None:
    code = (b"\x31\xc0" + b"\xc3") * 20
    target = tmp_path / "stripped.elf"
    target.write_bytes(make_stripped_elf(code))

    binary = loader.load(target)
    assert binary.format == "elf"
    assert binary.arch == "x86-64"
    assert binary.executable_sections
    assert b"".join(s.data for s in binary.executable_sections) == code


def test_a_stripped_elf_reports_its_segment_as_executable(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(make_stripped_elf((b"\x31\xc0" + b"\xc3") * 20))

    regions = loader.load(target).executable_sections
    assert len(regions) == 1
    assert regions[0].executable
    assert regions[0].writable is False
    assert regions[0].virtual_address == 0x400078


def test_a_binary_keeping_its_sections_ignores_the_segment_fallback() -> None:
    binary = loader.load(FIXTURES / "fixture-elf-x64")
    assert all(not s.name.startswith("segment") for s in binary.executable_sections)


# ---- CLR --------------------------------------------------------------------


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


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("fixture-pe-x64.exe", "pe64"),
        ("fixture-pe-x86.exe", "pe32"),
        ("fixture-elf-x64", "elf64"),
        ("fixture-elf-x86", "elf32"),
    ],
)
def test_the_target_names_the_format_and_the_width(name: str, target: str) -> None:
    assert loader.load(FIXTURES / name).target == target
