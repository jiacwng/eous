# PE and ELF parsing: the containers accepted, the ones refused, and the code they present.

import struct
import sys
from pathlib import Path

import lief
import pytest

from conftest import ELF64, MACHO, PE64, elf_header, stripped_elf
from eous import loader
from eous.loader import LoaderError, UnsupportedArchError


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


def section_table(raw: bytes) -> tuple[int, int]:
    header = struct.unpack_from("<I", raw, 0x3C)[0]
    count = struct.unpack_from("<H", raw, header + 6)[0]
    return header + 24 + struct.unpack_from("<H", raw, header + 20)[0], count


def test_a_pe_whose_code_sections_share_raw_data_is_refused(tmp_path: Path) -> None:
    raw = bytearray(PE64.read_bytes())
    table, count = section_table(raw)
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


def pe_with_every_section_claiming_the_file() -> bytes:
    raw = bytearray(PE64.read_bytes())
    table, count = section_table(raw)
    for index in range(count):
        struct.pack_into("<II", raw, table + 40 * index + 16, len(raw), 0)
    return bytes(raw)


def test_a_pe_whose_sections_claim_the_file_many_times_is_refused_before_lief(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "claims.exe"
    target.write_bytes(pe_with_every_section_claiming_the_file())

    def parse(raw: bytes) -> None:
        raise AssertionError("LIEF was reached")

    monkeypatch.setattr(loader, "_parse", parse)
    with pytest.raises(LoaderError, match="sections overlap"):
        loader.load(target)


def test_a_truncated_pe_header_is_left_to_lief() -> None:
    claims = pe_with_every_section_claiming_the_file()
    table, _ = section_table(claims)
    for cut in (0x50, table + 40 * 2 + 10):
        loader._check_pe_sections(PE64.read_bytes()[:cut])
        loader._check_pe_sections(claims[:cut])


def test_lief_skips_the_pe_tables_eous_never_reads() -> None:
    raw = PE64.read_bytes()
    assert len(lief.PE.parse(raw).imports) > 0
    parsed = loader._parse(raw)
    assert isinstance(parsed, lief.PE.Binary)
    assert len(parsed.imports) == 0
    assert not parsed.has_resources


def test_lief_skips_the_elf_symbols_eous_never_reads() -> None:
    raw = ELF64.read_bytes()
    assert len(lief.ELF.parse(raw).symbols) > 0
    parsed = loader._parse(raw)
    assert isinstance(parsed, lief.ELF.Binary)
    assert len(parsed.symbols) == 0


def test_a_stripped_elf_whose_segments_overlap_is_refused(tmp_path: Path) -> None:
    raw = bytearray(stripped_elf(b"\x31\xc0\xc3" * 64))
    program = bytes(raw[64:120])
    struct.pack_into("<H", raw, 56, 3)
    target = tmp_path / "segments.elf"
    target.write_bytes(bytes(raw[:120]) + program * 2 + bytes(raw[120:]))
    with pytest.raises(LoaderError, match="executable code overlaps"):
        loader.load(target)


def test_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(LoaderError, match="is a directory"):
        loader.load(tmp_path)


def never(*_: object) -> None:
    pytest.fail("a parser ran")


@pytest.mark.parametrize(
    ("payload", "refusal"),
    [
        (b"plain text\n" * 100, "no recognised container"),
        (MACHO, "macho"),
        (bytes.fromhex("6486") + bytes(200), "coff"),
    ],
    ids=["text", "macho", "coff"],
)
def test_a_file_neither_pe_nor_elf_reaches_no_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes, refusal: str
) -> None:
    for module in (lief, lief.PE, lief.ELF):
        monkeypatch.setattr(module, "parse", never)
    target = tmp_path / "sample"
    target.write_bytes(payload)
    with pytest.raises(LoaderError, match=refusal):
        loader.load(target)


def test_an_mz_file_with_no_pe_header_is_no_recognised_container(tmp_path: Path) -> None:
    target = tmp_path / "stub.exe"
    target.write_bytes(b"MZ" + bytes(62))
    with pytest.raises(LoaderError, match="no recognised container"):
        loader.load(target)


def test_a_known_machine_is_refused_by_its_name(tmp_path: Path) -> None:
    target = tmp_path / "aarch64.elf"
    target.write_bytes(elf_header(183))
    with pytest.raises(UnsupportedArchError, match="AARCH64"):
        loader.load(target)


def test_an_unrecognised_machine_refuses_by_arch(tmp_path: Path) -> None:
    target = tmp_path / "m4242.elf"
    target.write_bytes(elf_header(4242))
    with pytest.raises(UnsupportedArchError, match="4242"):
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


def test_a_parser_failure_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(_: bytes) -> object:
        raise RuntimeError("parser gave up")

    target = tmp_path / "anything.bin"
    target.write_bytes(b"\x7fELF" + bytes(60))
    monkeypatch.setattr(loader, "_parse", explode)
    with pytest.raises(LoaderError, match="parser gave up"):
        loader.load(target)


def test_a_file_that_cannot_be_read_becomes_a_loader_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_: object) -> None:
        raise PermissionError(13, "Permission denied")

    target = tmp_path / "locked.bin"
    target.write_bytes(PE64.read_bytes())
    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(LoaderError, match="cannot read: Permission denied"):
        loader.load(target)


@pytest.mark.skipif(sys.platform == "win32", reason="needs a sparse file")
def test_a_large_file_of_another_kind_is_refused_without_being_read(tmp_path: Path) -> None:
    target = tmp_path / "disk.iso"
    with target.open("wb") as handle:
        handle.write(b"CD001")
        handle.truncate(1 << 36)
    with pytest.raises(LoaderError, match="no recognised container"):
        loader.load(target)


@pytest.mark.filterwarnings("error")
def test_an_unknown_pe_optional_header_magic_is_refused(tmp_path: Path) -> None:
    raw = bytearray(PE64.read_bytes())
    header = struct.unpack_from("<I", raw, 0x3C)[0]
    struct.pack_into("<H", raw, header + 24, 0xBEEF)
    target = tmp_path / "magic.exe"
    target.write_bytes(bytes(raw))
    with pytest.raises(LoaderError, match="unknown header class"):
        loader.load(target)


@pytest.mark.filterwarnings("error")
def test_an_unknown_elf_class_is_refused(tmp_path: Path) -> None:
    raw = bytearray(ELF64.read_bytes())
    raw[4] = 0xA3
    target = tmp_path / "class.elf"
    target.write_bytes(bytes(raw))
    with pytest.raises(LoaderError):
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


def test_a_header_declaring_an_impossible_size_is_distrusted() -> None:
    forged = bytearray(make_cor20(flags=COR20_IL_ONLY))
    struct.pack_into("<I", forged, 0, 0xDEADBEEF)
    assert loader.read_clr(FakePE(0x2000, 72, bytes(forged))) == (False, False)


def test_a_native_header_with_a_zero_address_still_counts() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=COR20_IL_ONLY, native_rva=0, native_size=64))
    assert loader.read_clr(fake) == (True, True)


def test_il_only_assembly_is_pure_managed() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=COR20_IL_ONLY))
    assert loader.read_clr(fake) == (True, False)


def test_a_header_without_the_il_only_flag_is_not_managed() -> None:
    fake = FakePE(0x2000, 72, make_cor20(flags=0))
    assert loader.read_clr(fake) == (False, False)


def test_an_empty_cor20_header_is_not_managed() -> None:
    fake = FakePE(0x2000, 72, b"")
    assert loader.read_clr(fake) == (False, False)


def test_an_accessor_that_throws_after_parsing_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(parsed: lief.PE.Binary, size: int) -> loader.Binary:
        raise RuntimeError("bad section table")

    monkeypatch.setattr(loader, "_load_pe", broken)
    with pytest.raises(LoaderError, match="cannot parse: bad section table"):
        loader.load(PE64)
