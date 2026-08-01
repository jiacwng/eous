import random
from pathlib import Path

import pytest

from eous import digest, disasm, loader
from eous.digest import DigestError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"

# Real mnemonics, since invented names resolve to the unknown token.
# fmt: off
POOL = [
    "mov", "push", "pop", "add", "sub", "xor", "and", "or", "cmp", "test",
    "lea", "inc", "dec", "shl", "shr", "sar", "rol", "ror", "imul", "mul",
    "div", "neg", "adc", "sbb", "xchg", "bswap", "movzx", "movsx", "bt", "bts",
    "bsf", "bsr", "cdq", "cwde", "setne", "sete", "cmovne", "cmove", "nop", "leave",
]
# fmt: on


def chunk(*mnemonics: str) -> tuple[str, ...]:
    return tuple(mnemonics)


def straight(length: int, mnemonic: str = "mov") -> tuple[tuple[str, ...], ...]:
    return (tuple([mnemonic] * length),)


def varied(length: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    return [rng.choice(POOL) for _ in range(length)]


def sketch_of(text: str) -> digest.Sketch:
    return digest.parse(text)


# ---- constants and derivation -----------------------------------------------


def test_the_sketch_is_512_bits() -> None:
    assert digest.PERMUTATIONS * digest.SLOT_BITS == 512
    assert digest.SKETCH_HEX == 128


def test_the_modulus_is_the_mersenne_prime() -> None:
    assert digest.MODULUS == 2**61 - 1


def test_every_permutation_multiplier_is_non_zero() -> None:
    # A zero multiplier maps every input to the offset and destroys the permutation.
    assert all(a > 0 for a, _ in digest.COEFFICIENTS)


def test_permutations_stay_inside_the_modulus() -> None:
    assert all(a < digest.MODULUS and b < digest.MODULUS for a, b in digest.COEFFICIENTS)


def test_permutations_are_distinct() -> None:
    assert len(set(digest.COEFFICIENTS)) == digest.PERMUTATIONS


def test_permutations_follow_their_stated_derivation() -> None:
    # Recomputing one pair from the rule proves the table came from the rule.
    label = (7).to_bytes(4, "big")
    expected_a = digest.h64(b"a" + label, b"eous-prm") % (digest.MODULUS - 1) + 1
    expected_b = digest.h64(b"b" + label, b"eous-prm") % digest.MODULUS
    assert digest.COEFFICIENTS[7] == (expected_a, expected_b)


def test_the_hash_is_stable_across_calls() -> None:
    assert digest.h64(b"payload", b"eous-ng") == digest.h64(b"payload", b"eous-ng")


def test_the_two_personalisations_differ() -> None:
    assert digest.h64(b"x", b"eous-ng") != digest.h64(b"x", b"eous-prm")


# ---- normalisation ----------------------------------------------------------


def test_mnemonics_become_roots() -> None:
    result = digest.normalise((chunk("mov", "push", "ret"),), "x86-64")
    assert result == [["mov", "push", "ret"]]


def test_an_unknown_mnemonic_becomes_the_oov_token() -> None:
    result = digest.normalise((chunk("mov", "wibble", "ret"),), "x86-64")
    assert result == [["mov", digest.OOV, "ret"]]


# Removing it would join two instructions that were apart, inventing a sequence.
def test_the_unknown_token_keeps_its_position() -> None:
    result = digest.normalise((chunk("push", "wibble", "pop"),), "x86-64")
    assert len(result[0]) == 3
    assert result[0][1] == digest.OOV


def test_prefixed_mnemonics_resolve_through_the_vocabulary() -> None:
    result = digest.normalise((chunk("repz ret", "notrack jmp"),), "x86-64")
    assert result == [["ret", "jmp"]]


# ---- shingles ---------------------------------------------------------------


def test_a_chunk_shorter_than_the_window_yields_nothing() -> None:
    assert digest.shingles([["mov"] * (digest.NGRAM - 1)]) == set()


def test_a_chunk_exactly_the_window_yields_one() -> None:
    assert len(digest.shingles([["mov"] * digest.NGRAM])) == 1


def test_windows_slide_by_one() -> None:
    tokens = [f"op{i}" for i in range(digest.NGRAM + 3)]
    assert len(digest.shingles([tokens])) == 4


def test_windows_stay_inside_one_chunk() -> None:
    half = digest.NGRAM // 2 + 1
    left = [f"a{i}" for i in range(half)]
    right = [f"b{i}" for i in range(half)]
    assert digest.shingles([left, right]) == set()


def test_duplicate_windows_collapse() -> None:
    # A set is what lets the digest survive loop unrolling.
    once = digest.shingles([["mov"] * digest.NGRAM])
    many = digest.shingles([["mov"] * (digest.NGRAM * 8)])
    assert once == many


def test_one_unknown_token_is_tolerated() -> None:
    tokens = ["mov"] * (digest.NGRAM - 1) + [digest.OOV]
    assert len(digest.shingles([tokens])) == 1


def test_two_unknown_tokens_discard_the_window() -> None:
    tokens = ["mov"] * (digest.NGRAM - 2) + [digest.OOV, digest.OOV]
    assert digest.shingles([tokens]) == set()


# ---- packing ----------------------------------------------------------------


def test_the_packed_value_fits_the_sketch() -> None:
    packed = digest.pack(digest.shingles([["mov"] * 40]))
    assert 0 <= packed < 1 << (digest.PERMUTATIONS * digest.SLOT_BITS)


def test_packing_is_stable() -> None:
    grams = digest.shingles([[f"op{i}" for i in range(60)]])
    assert digest.pack(grams) == digest.pack(grams)


def test_set_order_leaves_the_sketch_unchanged() -> None:
    grams = digest.shingles([[f"op{i}" for i in range(60)]])
    assert digest.pack(grams) == digest.pack(set(reversed(list(grams))))


# ---- the digest string ------------------------------------------------------


def test_a_digest_carries_four_fields() -> None:
    text = digest.digest(straight(40), "x86-64")
    assert text is not None
    assert text.split(":")[0] == "EO1"
    assert text.split(":")[1] == "x86-64"
    assert len(text.split(":")[3]) == digest.SKETCH_HEX


def test_cardinality_counts_distinct_shingles() -> None:
    tokens = varied(digest.NGRAM + 2, seed=1)
    text = digest.digest((tuple(tokens),), "x86")
    assert text is not None
    assert int(text.split(":")[2]) == len(digest.shingles([tokens]))


def test_unrecognisable_mnemonics_yield_no_digest() -> None:
    assert digest.digest((tuple(f"wibble{i}" for i in range(400)),), "x86-64") is None


def test_too_little_code_yields_no_digest() -> None:
    assert digest.digest((chunk("mov", "ret"),), "x86-64") is None


def test_an_empty_sweep_yields_no_digest() -> None:
    assert digest.digest((), "x86-64") is None


def test_an_unsupported_architecture_raises() -> None:
    with pytest.raises(DigestError, match="mips"):
        digest.digest(straight(40), "mips")


def test_the_same_input_digests_the_same_way() -> None:
    assert digest.digest(straight(40), "x86") == digest.digest(straight(40), "x86")


# ---- parsing ----------------------------------------------------------------


def test_a_digest_round_trips() -> None:
    text = digest.digest(straight(40), "x86-64")
    assert text is not None
    assert digest.parse(text).render() == text


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("EO1:x86:12", "4 fields"),
        ("EO2:x86:12:" + "a" * 128, "version"),
        ("EO1:mips:12:" + "a" * 128, "architecture"),
        ("EO1:x86:many:" + "a" * 128, "integer"),
        ("EO1:x86:12:" + "a" * 127, "hex"),
        ("EO1:x86:12:" + "A" * 128, "hex"),
        ("EO1:x86:12:" + "z" * 128, "hex"),
    ],
)
def test_a_malformed_digest_raises(text: str, complaint: str) -> None:
    with pytest.raises(DigestError, match=complaint):
        digest.parse(text)


# ---- comparison -------------------------------------------------------------


def test_a_digest_matches_itself_completely() -> None:
    text = digest.digest(straight(60), "x86-64")
    assert text is not None
    assert digest.compare(text, text).similarity == pytest.approx(100.0)


def test_unrelated_inputs_score_near_zero() -> None:
    left = digest.digest((tuple(varied(600, seed=11)),), "x86-64")
    right = digest.digest((tuple(varied(600, seed=22)),), "x86-64")
    assert left is not None and right is not None
    assert digest.compare(left, right).similarity < 25.0


def test_overlapping_inputs_score_between() -> None:
    shared = varied(400, seed=33)
    left = digest.digest((tuple(shared + varied(400, seed=44)),), "x86-64")
    right = digest.digest((tuple(shared + varied(400, seed=55)),), "x86-64")
    assert left is not None and right is not None
    score = digest.compare(left, right).similarity
    assert 10.0 < score < 95.0


def test_comparison_accepts_parsed_sketches() -> None:
    text = digest.digest(straight(60), "x86")
    assert text is not None
    assert digest.compare(sketch_of(text), sketch_of(text)).similarity == pytest.approx(100.0)


def test_differing_architectures_raise() -> None:
    left = digest.digest(straight(60), "x86")
    right = digest.digest(straight(60), "x86-64")
    assert left is not None and right is not None
    with pytest.raises(DigestError, match="architectures differ"):
        digest.compare(left, right)


def test_differing_versions_raise() -> None:
    text = digest.digest(straight(60), "x86")
    assert text is not None
    original = digest.parse(text)
    other = digest.Sketch("EO9", original.arch, original.cardinality, original.slots)
    with pytest.raises(DigestError, match="versions differ"):
        digest.compare(original, other)


def test_uncertainty_is_reported_and_bounded() -> None:
    left = digest.digest((tuple(varied(600, seed=66)),), "x86-64")
    right = digest.digest((tuple(varied(600, seed=77)),), "x86-64")
    assert left is not None and right is not None
    scores = digest.compare(left, right)
    assert 0.0 <= scores.uncertainty < 20.0


def test_identical_sketches_carry_zero_uncertainty() -> None:
    text = digest.digest(straight(60), "x86-64")
    assert text is not None
    assert digest.compare(text, text).uncertainty == pytest.approx(0.0)


# ---- containment ------------------------------------------------------------


def test_containment_is_reported_both_ways_at_similar_sizes() -> None:
    text = digest.digest((tuple(varied(400, seed=88)),), "x86-64")
    assert text is not None
    scores = digest.compare(text, text)
    assert scores.left_in_right == pytest.approx(100.0)
    assert scores.right_in_left == pytest.approx(100.0)


def test_containment_is_withheld_in_both_directions_beyond_the_ratio() -> None:
    small = digest.digest((tuple(varied(30, seed=99)),), "x86-64")
    large = digest.digest((tuple(varied(3000, seed=99)),), "x86-64")
    assert small is not None and large is not None
    scores = digest.compare(small, large)
    assert scores.left_in_right is None
    assert scores.right_in_left is None


# The gap between the two directions is the useful part: it names the superset.
def test_a_subset_shows_the_asymmetry() -> None:
    tokens = varied(900, seed=41)
    whole = digest.digest((tuple(tokens),), "x86-64")
    part = digest.digest((tuple(tokens[: len(tokens) // 2]),), "x86-64")
    assert whole is not None and part is not None

    scores = digest.compare(part, whole)
    assert scores.left_in_right is not None and scores.right_in_left is not None
    assert scores.left_in_right > scores.right_in_left


def test_the_directions_swap_with_the_arguments() -> None:
    tokens = varied(900, seed=42)
    whole = digest.digest((tuple(tokens),), "x86-64")
    part = digest.digest((tuple(tokens[: len(tokens) // 2]),), "x86-64")
    assert whole is not None and part is not None

    forward = digest.compare(part, whole)
    backward = digest.compare(whole, part)
    assert forward.left_in_right == pytest.approx(backward.right_in_left)
    assert forward.right_in_left == pytest.approx(backward.left_in_right)


# ---- against the real fixtures ----------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["fixture-pe-x64.exe", "fixture-pe-x86.exe", "fixture-elf-x64", "fixture-elf-x86"],
)
def test_every_fixture_digests(name: str) -> None:
    binary = loader.load(FIXTURES / name)
    text = digest.digest(disasm.sweep(binary).chunks, binary.arch)
    assert text is not None
    assert digest.parse(text).arch == binary.arch


def test_a_fixture_digests_the_same_way_twice() -> None:
    binary = loader.load(FIXTURES / "fixture-pe-x64.exe")
    chunks = disasm.sweep(binary).chunks
    assert digest.digest(chunks, binary.arch) == digest.digest(chunks, binary.arch)


def test_the_two_pe_fixtures_share_their_source() -> None:
    left = loader.load(FIXTURES / "fixture-pe-x64.exe")
    right = loader.load(FIXTURES / "fixture-pe-x86.exe")
    a = digest.digest(disasm.sweep(left).chunks, left.arch)
    b = digest.digest(disasm.sweep(right).chunks, right.arch)
    assert a is not None and b is not None
    with pytest.raises(DigestError, match="architectures differ"):
        digest.compare(a, b)


def test_the_same_architecture_across_formats_compares() -> None:
    pe = loader.load(FIXTURES / "fixture-pe-x64.exe")
    elf = loader.load(FIXTURES / "fixture-elf-x64")
    a = digest.digest(disasm.sweep(pe).chunks, pe.arch)
    b = digest.digest(disasm.sweep(elf).chunks, elf.arch)
    assert a is not None and b is not None
    scores = digest.compare(a, b)
    assert 0.0 <= scores.similarity <= 100.0
