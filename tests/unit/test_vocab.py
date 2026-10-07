import hashlib
from importlib import resources

import pytest

from eous import disasm, vocab


def test_load_is_cached() -> None:
    assert vocab.load() is vocab.load()


def test_every_entry_is_a_mnemonic_the_decoder_emits() -> None:
    assert set(vocab.load()) <= set(disasm.MNEMONICS.values())


# Every entry shapes digests, so the table is pinned the way the golden vectors are.
def test_the_table_is_the_one_the_vectors_were_taken_from() -> None:
    raw = resources.files("eous").joinpath("data").joinpath(vocab.DATA_FILE).read_bytes()
    assert len(vocab.load()) == 1394
    assert len(set(vocab.load().values())) == 84
    assert hashlib.sha256(raw).hexdigest() == (
        "52bfae704f5f7d5c7eaefcd2b06444f14e9d4d5e0103132a15fa7d27e0b74546"
    )


def test_an_unknown_mnemonic_has_no_root() -> None:
    assert vocab.load().get("definitely_not_an_instruction") is None


# A prefix scan would file popcnt under pop and xorps under xor. Exact membership keeps each
# on its own root.
@pytest.mark.parametrize(
    ("mnemonic", "collides_with"),
    [
        ("popcnt", "pop"),
        ("xorps", "xor"),
        ("addps", "add"),
        ("subps", "sub"),
        ("andn", "and"),
        ("incsspd", "inc"),
    ],
)
def test_lookalike_mnemonics_keep_their_own_root(mnemonic: str, collides_with: str) -> None:
    roots = vocab.load()
    assert roots[mnemonic] != roots[collides_with]


def test_the_string_move_and_the_scalar_move_differ() -> None:
    roots = vocab.load()
    assert roots["movsd"] != roots["movsb"]


def test_common_instructions_are_covered() -> None:
    everyday = [
        "mov",
        "push",
        "pop",
        "call",
        "ret",
        "jmp",
        "je",
        "add",
        "sub",
        "lea",
        "test",
        "cmp",
        "xor",
        "nop",
        "leave",
        "imul",
        "movzx",
        "shl",
        "and",
        "or",
    ]
    assert [m for m in everyday if m not in vocab.load()] == []
