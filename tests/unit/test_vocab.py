import pytest

from eous import vocab
from eous.vocab import VocabError

ARCHES = ["x86", "x86-64"]


@pytest.fixture(params=ARCHES)
def v(request: pytest.FixtureRequest) -> vocab.Vocab:
    return vocab.load(request.param)


def test_load_rejects_unknown_arch() -> None:
    with pytest.raises(VocabError):
        vocab.load("arm64")


def test_load_caches_per_arch() -> None:
    assert vocab.load("x86") is vocab.load("x86")


def test_arch_is_recorded(v: vocab.Vocab) -> None:
    assert v.arch in ARCHES


def test_every_member_root_is_declared(v: vocab.Vocab) -> None:
    assert set(v.members.values()) <= v.roots


def test_every_root_has_a_category(v: vocab.Vocab) -> None:
    assert v.roots == set(v.root_to_category)


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


# movsd is genuinely ambiguous in x86: bare it is an SSE scalar move, prefixed by rep it
# is a string move. Exact-match-before-strip is what separates them.
def test_repeated_string_move_differs_from_scalar_move(v: vocab.Vocab) -> None:
    assert v.root_of("rep movsd") == v.root_of("rep movsb")
    assert v.root_of("movsd") != v.root_of("rep movsd")


@pytest.mark.parametrize("prefix", ["lock", "rep", "repe", "repz", "repne", "repnz", "bnd"])
def test_known_prefixes_are_stripped(v: vocab.Vocab, prefix: str) -> None:
    assert v.root_of(f"{prefix} xadd") == v.root_of("xadd")


def test_unknown_prefix_stays_unknown(v: vocab.Vocab) -> None:
    assert v.root_of("wibble xadd") is None


def test_prefix_is_stripped_once_only(v: vocab.Vocab) -> None:
    assert v.root_of("rep rep xadd") is None


def test_bare_prefix_without_operand_is_unknown(v: vocab.Vocab) -> None:
    assert v.root_of("rep") is None


@pytest.mark.parametrize(
    ("mnemonic", "category"),
    [
        ("mov", "transfer"),
        ("add", "arithmetic"),
        ("xor", "logic"),
        ("shl", "shift"),
        ("cmp", "comparison"),
        ("call", "branch"),
        ("rep movsb", "string"),
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


def test_vocab_is_frozen(v: vocab.Vocab) -> None:
    with pytest.raises(AttributeError):
        v.arch = "x86"  # type: ignore[misc]


# Everything below drives the failure paths. The data file is a build artefact, so a
# corrupted one has to be simulated rather than committed.


@pytest.fixture
def fresh_caches() -> object:
    vocab.load.cache_clear()
    vocab.read_data_file.cache_clear()
    yield
    vocab.load.cache_clear()
    vocab.read_data_file.cache_clear()


def install_data_file(monkeypatch: pytest.MonkeyPatch, text: str | None) -> None:
    class Source:
        def joinpath(self, name: str) -> "Source":
            return self

        def read_text(self, encoding: str = "utf-8") -> str:
            if text is None:
                raise FileNotFoundError(vocab.DATA_FILE)
            return text

    class Resources:
        @staticmethod
        def files(package: str) -> Source:
            return Source()

    monkeypatch.setattr(vocab, "resources", Resources)


@pytest.mark.usefixtures("fresh_caches")
def test_missing_data_file_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    install_data_file(monkeypatch, None)
    with pytest.raises(VocabError, match="missing"):
        vocab.load("x86")


@pytest.mark.usefixtures("fresh_caches")
def test_malformed_json_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    install_data_file(monkeypatch, "{ this is not json")
    with pytest.raises(VocabError, match="malformed"):
        vocab.load("x86")


@pytest.mark.usefixtures("fresh_caches")
def test_payload_that_is_not_an_object_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    install_data_file(monkeypatch, "[]")
    with pytest.raises(VocabError, match="list"):
        vocab.load("x86")


@pytest.mark.usefixtures("fresh_caches")
def test_entry_missing_its_tables_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    install_data_file(monkeypatch, '{"x86": {"members": {}}}')
    with pytest.raises(VocabError, match="malformed vocabulary entry"):
        vocab.load("x86")


@pytest.mark.usefixtures("fresh_caches")
def test_root_without_a_category_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = '{"x86": {"members": {"mov": "ghost"}, "root_to_category": {"real": "transfer"}}}'
    install_data_file(monkeypatch, payload)
    with pytest.raises(VocabError, match="ghost"):
        vocab.load("x86")


@pytest.mark.usefixtures("fresh_caches")
def test_unknown_arch_names_the_known_ones(monkeypatch: pytest.MonkeyPatch) -> None:
    install_data_file(monkeypatch, '{"x86": {"members": {}, "root_to_category": {}}}')
    with pytest.raises(VocabError, match="x86"):
        vocab.load("mips")
