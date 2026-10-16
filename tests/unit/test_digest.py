import random

import pytest

import reference
from eous import digest
from eous.digest import DigestError

# Real mnemonics, since invented names resolve to the unknown token.
# fmt: off
POOL = [
    "mov", "push", "pop", "add", "sub", "xor", "and", "or", "cmp", "test",
    "lea", "inc", "dec", "shl", "shr", "sar", "rol", "ror", "imul", "mul",
    "div", "neg", "adc", "sbb", "xchg", "bswap", "movzx", "movsx", "bt", "bts",
    "bsf", "bsr", "cdq", "cwde", "setne", "sete", "cmovne", "cmove", "nop", "leave",
]
# fmt: on
BODY = "a" * digest.SKETCH_HEX


def varied(length: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    return [rng.choice(POOL) for _ in range(length)]


def sketch_of(*runs: list[str]) -> digest.Sketch:
    text = reference.digest(tuple(tuple(run) for run in runs), "pe64")
    assert text is not None
    return digest.parse(text)


# `'²'.isdigit()` is true and `int('²')` raises, so the cardinality is read as ASCII digits.
def test_a_numeric_character_that_is_not_a_digit_is_refused() -> None:
    with pytest.raises(DigestError, match="non-negative integer"):
        digest.parse(f"EO1:pe64:²:{BODY}")


def test_a_cardinality_beyond_float_precision_is_refused() -> None:
    with pytest.raises(DigestError, match="exceeds"):
        digest.parse(f"EO1:pe64:{digest.MAX_CARDINALITY + 1}:{BODY}")


def test_a_cardinality_past_the_integer_conversion_limit_is_refused() -> None:
    with pytest.raises(DigestError, match="exceeds"):
        digest.parse(f"EO1:pe64:{'9' * 5000}:{BODY}")


def test_the_largest_representable_cardinality_parses() -> None:
    parsed = digest.parse(f"EO1:pe64:{digest.MAX_CARDINALITY}:{BODY}")
    assert parsed.cardinality == digest.MAX_CARDINALITY


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("EO1:pe32:12", "4 fields"),
        ("EO2:pe32:12:" + BODY, "version"),
        ("EO1:mips:12:" + BODY, "target"),
        ("EO1:pe32:many:" + BODY, "integer"),
        ("EO1:pe32:12:" + BODY[:-1], "hex"),
    ],
)
def test_a_malformed_digest_raises(text: str, complaint: str) -> None:
    with pytest.raises(DigestError, match=complaint):
        digest.parse(text)


def test_unpacking_recovers_every_slot() -> None:
    sketch = sketch_of(varied(300, seed=0))
    slots = digest.unpack(sketch)
    assert len(slots) == digest.PERMUTATIONS
    # Read the bits back off the printed digest, so the check uses the published format.
    body = int(reference.render(sketch).rsplit(":", 1)[-1], 16)
    assert [int(value) for value in slots] == [
        (body >> (digest.PERMUTATIONS - 1 - index) * digest.SLOT_BITS) & digest.MASK
        for index in range(digest.PERMUTATIONS)
    ]


# Below chance agreement the score is clamped at zero, and the margin still has to come
# from the slots that agree.
def test_the_margin_of_error_comes_from_the_slots_and_not_the_score() -> None:
    zeros = digest.Sketch("pe64", 100, 0)
    ones = digest.Sketch("pe64", 100, int("01" * 256, 2))
    mixed = digest.Sketch("pe64", 100, int("00" * 32 + "01" * 224, 2))
    assert digest.compare(zeros, ones).uncertainty == pytest.approx(0.519, abs=0.001)
    assert digest.compare(zeros, mixed).uncertainty == pytest.approx(2.952, abs=0.001)

    scored, spread = digest.score(digest.unpack_all([ones, mixed]), digest.unpack(zeros))
    assert list(scored) == [0.0, 0.0]
    assert float(spread[0]) == pytest.approx(0.519, abs=0.001)
    assert float(spread[1]) == pytest.approx(2.952, abs=0.001)


def test_the_batch_path_equals_compare_on_every_pair() -> None:
    group = [sketch_of(varied(300, seed=seed)) for seed in range(12)]
    table = digest.unpack_all(group)
    for left in group:
        scored, spread = digest.score(table, digest.unpack(left))
        for index, right in enumerate(group):
            pair = digest.compare(left, right)
            assert float(scored[index]) == pair.similarity
            assert float(spread[index]) == pair.uncertainty


def test_identical_sketches_keep_a_margin() -> None:
    sketch = sketch_of(["mov", "push"] * 30)
    scores = digest.compare(sketch, sketch)
    assert scores.similarity == 100.0
    assert scores.uncertainty == pytest.approx(0.519, abs=0.001)


# The gap between the two directions is the useful part: it names the superset.
def test_a_subset_shows_the_asymmetry() -> None:
    tokens = varied(900, seed=41)
    whole, part = sketch_of(tokens), sketch_of(tokens[: len(tokens) // 2])

    forward = digest.compare(part, whole)
    backward = digest.compare(whole, part)
    assert forward.left_in_right is not None and forward.right_in_left is not None
    assert forward.left_in_right > forward.right_in_left
    assert forward.left_in_right == pytest.approx(backward.right_in_left)
    assert forward.right_in_left == pytest.approx(backward.left_in_right)


def test_containment_respects_the_cardinality_ratio_when_every_slot_agrees() -> None:
    small = digest.Sketch("pe64", 100, 0)
    large = digest.Sketch("pe64", 200, 0)
    scores = digest.compare(large, small)
    assert scores.left_in_right == pytest.approx(50.0)
    assert scores.right_in_left == pytest.approx(100.0)
