import pytest

from eous import vocab

ARCHES = ["x86", "x86-64"]


@pytest.fixture(params=ARCHES)
def v(request: pytest.FixtureRequest) -> vocab.Vocab:
    return vocab.load(request.param)


def test_load_caches_per_arch() -> None:
    assert vocab.load("x86") is vocab.load("x86")


def test_every_root_a_member_uses_has_a_category(v: vocab.Vocab) -> None:
    uncategorised = set(v.members.values()) - set(v.root_to_category)
    assert uncategorised == set()


def test_every_declared_root_is_reachable_from_some_mnemonic(v: vocab.Vocab) -> None:
    unreachable = set(v.root_to_category) - set(v.members.values())
    assert unreachable == set()


def test_categories_are_ten(v: vocab.Vocab) -> None:
    assert len(set(v.root_to_category.values())) == 10


def test_unknown_mnemonic_returns_none(v: vocab.Vocab) -> None:
    assert v.root_of("definitely_not_an_instruction") is None


# The bug this vocabulary exists to avoid: a prefix scan files popcnt under pop and
# xorps under xor. Exact membership keeps each on its own root.
@pytest.mark.parametrize(
    ("mnemonic", "collides_with"),
    [
        ("popcnt", "pop"),
        ("xorps", "xor"),
        ("notrack", "not"),
        ("addps", "add"),
        ("subps", "sub"),
        ("andn", "and"),
        ("incsspd", "inc"),
    ],
)
def test_lookalike_mnemonics_keep_their_own_root(
    v: vocab.Vocab, mnemonic: str, collides_with: str
) -> None:
    root = v.root_of(mnemonic)
    assert root is not None
    assert root != v.root_of(collides_with)


# movsd is a scalar move and movsb is a string move, and only exact membership tells them
# apart. The decoder reports a `rep` prefix separately, so neither name ever carries one.
def test_the_string_move_and_the_scalar_move_differ(v: vocab.Vocab) -> None:
    assert v.root_of("movsd") != v.root_of("movsb")


@pytest.mark.parametrize(
    ("mnemonic", "category"),
    [
        ("mov", "transfer"),
        ("add", "arithmetic"),
        ("xor", "logic"),
        ("shl", "shift"),
        ("cmp", "comparison"),
        ("call", "branch"),
        ("movsb", "string"),
        ("fadd", "float"),
        ("addps", "vector"),
        ("cpuid", "system"),
    ],
)
def test_representative_mnemonics_land_in_expected_category(
    v: vocab.Vocab, mnemonic: str, category: str
) -> None:
    root = v.root_of(mnemonic)
    assert root is not None
    assert v.root_to_category[root] == category


def test_common_instructions_are_covered(v: vocab.Vocab) -> None:
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
    assert [m for m in everyday if v.root_of(m) is None] == []
