import hashlib
import random
import tomllib
from pathlib import Path

import pytest

import reference
from conftest import PE32, PE64
from eous import _native, loader

CARGO = Path(__file__).resolve().parents[2] / "native" / "Cargo.toml"
BODY = b"\x55\x48\x89\xe5\x31\xc0\x48\x01\xc3\x48\x29\xd8\x50"
XOR_PUSH = b"\x31\xc0\x50"
RET = b"\xc3"
NOP = b"\x90"

# One encoding per kind of control flow iced reports. The last two fall through.
RULES = [
    (b"\xc3", "ret"),
    (b"\xeb\x00", "jmp"),
    (b"\xff\xe0", "jmp rax"),
    (b"\xe8\x00\x00\x00\x00", "call"),
    (b"\xff\xd0", "call rax"),
    (b"\x74\x00", "je"),
    (b"\x0f\x05", "syscall"),
    (b"\x0f\x0b", "ud2"),
    (b"\xcc", "int3"),
    (b"\x90", "nop"),
]


def section(data: bytes, address: int = 0x1000) -> loader.Section:
    return loader.Section(name=".text", virtual_address=address, writable=False, data=data)


def native_of(code: bytes) -> str | None:
    return _native.digest([code], 64, "pe64")


def both(sections: list[loader.Section], arch: str, target: str) -> tuple[str | None, str | None]:
    native = _native.digest([section.data for section in sections], loader.BITS[arch], target)
    expected = reference.digest(reference.disassemble(sections, arch).runs, target)
    return native, expected


# iced names data bytes and failed decodes with these, and never emits them for an instruction.
PLACEHOLDERS = {"invalid", "db", "dw", "dd", "dq", "zero_bytes"}


def test_every_mnemonic_iced_names_has_a_root() -> None:
    emitted = set(reference.MNEMONICS.values()) - PLACEHOLDERS
    assert sorted(emitted - set(reference.roots())) == []


# Every entry shapes digests, so the table is pinned the way the golden vectors are.
def test_the_table_is_the_one_the_vectors_were_taken_from() -> None:
    raw = reference.ROOTS_FILE.read_bytes()
    assert len(reference.roots()) == 1888
    assert len(set(reference.roots().values())) == 84
    assert hashlib.sha256(raw).hexdigest() == (
        "f441e11ea08a7ea9233dc9be0da8b34e6bfe7fb97341d6eb7764241bbe559092"
    )


def test_a_run_shorter_than_a_shingle_gives_no_digest() -> None:
    assert native_of(XOR_PUSH * 2 + RET) is None
    assert native_of(XOR_PUSH * 3) is not None


def test_a_branch_ends_the_run_and_a_nop_does_not() -> None:
    half = XOR_PUSH + XOR_PUSH[:2]
    assert native_of(half + RET + half) is None
    assert native_of(half + NOP + half) is not None


@pytest.mark.parametrize("path", [PE32, PE64], ids=["pe32", "pe64"])
def test_every_fixture_matches_the_reference(path: Path) -> None:
    binary = loader.load(path)
    native, expected = both(list(binary.sections), binary.arch, binary.target)
    assert native is not None
    assert native == expected


# Flipped bytes land on invalid encodings, prefixes, repeats and cut runs, the edges of decoding.
@pytest.mark.parametrize("path", [PE32, PE64], ids=["pe32", "pe64"])
def test_mutated_code_matches_the_reference(path: Path) -> None:
    binary = loader.load(path)
    for seed in range(50):
        rng = random.Random(seed)
        mutated = []
        for original in binary.sections:
            data = bytearray(original.data)
            for _ in range(max(1, len(data) // 64)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            mutated.append(section(bytes(data), original.virtual_address))
        native, expected = both(mutated, binary.arch, binary.target)
        assert native == expected, f"seed {seed}"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xcc" * 64,
        b"\xff\xff" * 32,
        (XOR_PUSH * 4 + RET) * 50,
        random.Random(20261013).randbytes(65536),
    ],
    ids=["empty", "int3", "invalid", "short_runs", "noise"],
)
def test_crafted_code_matches_the_reference(data: bytes) -> None:
    native, expected = both([section(data)], "x86-64", "pe64")
    assert native == expected


# A long body around each instruction, so a run left open changes the shingles and the count.
@pytest.mark.parametrize("encoding", [p[0] for p in RULES], ids=[p[1] for p in RULES])
def test_every_run_rule_matches_the_reference(encoding: bytes) -> None:
    native, expected = both([section((BODY + encoding + BODY) * 4)], "x86-64", "pe64")
    assert native is not None
    assert native == expected


def test_a_run_never_crosses_from_one_section_into_the_next() -> None:
    first = section(XOR_PUSH * 3, 0x1000)
    second = section(XOR_PUSH * 3 + RET, 0x2000)
    native, expected = both([first, second], "x86", "pe32")
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
