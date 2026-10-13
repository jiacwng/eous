import random
import tomllib
from pathlib import Path

import pytest
from test_disasm import ENDS_A_RUN, FALLS_THROUGH

import reference
from conftest import FIXTURES, NAMES, stripped_elf
from eous import _native, loader

CARGO = Path(__file__).resolve().parents[2] / "native" / "Cargo.toml"
RULES = ENDS_A_RUN + FALLS_THROUGH
BODY = b"\x55\x48\x89\xe5\x31\xc0\x48\x01\xc3\x48\x29\xd8\x50"


def both(sections: list[loader.Section], arch: str, target: str) -> tuple[str | None, str | None]:
    native = _native.digest([section.data for section in sections], loader.BITS[arch], target)
    expected = reference.digest(reference.disassemble(sections, arch).runs, target)
    return native, expected


def section(data: bytes, address: int = 0x1000) -> loader.Section:
    return loader.Section(name=".text", virtual_address=address, writable=False, data=data)


@pytest.mark.parametrize("name", NAMES)
def test_every_fixture_matches_the_reference(name: str) -> None:
    binary = loader.load(FIXTURES / name)
    native, expected = both(list(binary.sections), binary.arch, binary.target)
    assert native is not None
    assert native == expected


# Flipped bytes land on invalid encodings, prefixes, repeats and cut runs, the edges of decoding.
@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("seed", range(50))
def test_mutated_code_matches_the_reference(name: str, seed: int) -> None:
    binary = loader.load(FIXTURES / name)
    rng = random.Random(seed)
    mutated = []
    for original in binary.sections:
        data = bytearray(original.data)
        for _ in range(max(1, len(data) // 64)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        mutated.append(section(bytes(data), original.virtual_address))
    native, expected = both(mutated, binary.arch, binary.target)
    assert native == expected


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x90" * 4096,
        b"\xcc" * 64,
        b"\x00\x00" * 512,
        b"\xff\xff" * 32,
        b"\x31\xc0" * 40 + b"\xc3",
        (b"\x31\xc0\x50" * 4 + b"\xc3") * 50,
        bytes(range(256)) * 16,
        random.Random(20261013).randbytes(65536),
    ],
    ids=[
        "empty",
        "nops",
        "int3",
        "zeros",
        "invalid",
        "one_root",
        "short_runs",
        "every_byte",
        "noise",
    ],
)
@pytest.mark.parametrize("arch", ["x86", "x86-64"])
def test_crafted_code_matches_the_reference(data: bytes, arch: str) -> None:
    native, expected = both([section(data)], arch, "pe32" if arch == "x86" else "pe64")
    assert native == expected


# A long body around each instruction, so a run left open changes the shingles and the count.
@pytest.mark.parametrize("encoding", [p[0] for p in RULES], ids=[p[1] for p in RULES])
def test_every_run_rule_matches_the_reference(encoding: bytes) -> None:
    native, expected = both([section((BODY + encoding + BODY) * 4)], "x86-64", "pe64")
    assert native is not None
    assert native == expected


@pytest.mark.parametrize("count", [5, 6, 7, 40])
def test_the_repeat_cap_matches_the_reference(count: int) -> None:
    code = b"\x31\xc0\x50\x48\x89\xe5" + b"\x90" * count + b"\x48\x01\xc3\x48\x29\xd8\xc3"
    native, expected = both([section(code * 3)], "x86-64", "pe64")
    assert native == expected


def test_a_run_never_crosses_from_one_section_into_the_next() -> None:
    first = section(b"\x31\xc0\x50" * 3, 0x1000)
    second = section(b"\x31\xc0\x50" * 3 + b"\xc3", 0x2000)
    native, expected = both([first, second], "x86", "pe32")
    assert native == expected


def test_a_stripped_elf_matches_the_reference(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    code = b"\x31\xc0" + b"\x50" + b"\x48\x89\xe5" + b"\x48\x01\xc0" + b"\x48\x29\xc0" + b"\xc3"
    target.write_bytes(stripped_elf(code * 200))
    binary = loader.load(target)
    native, expected = both(list(binary.sections), binary.arch, binary.target)
    assert native is not None
    assert native == expected


def test_an_unsupported_bitness_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="bitness"):
        _native.digest([b"\x90"], 8, "pe32")


def test_an_unsupported_target_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="target"):
        _native.digest([b"\x90"], 32, "bogus")


def test_the_reported_decoder_is_the_one_compiled_in() -> None:
    pinned = tomllib.loads(CARGO.read_text(encoding="utf-8"))["dependencies"]["iced-x86"]
    assert pinned["version"] == f"={_native.ICED_X86}"
