# Digest parsing, the similarity and containment scores, and their margin of error.

import random

import pytest

from conftest import WILSON_MARGIN_AT_FULL_AGREEMENT
from eous import _native, digest
from eous.digest import DigestError

POOL = [
    bytes.fromhex(code)
    for code in (
        "4889d8 50 58 4801d8 4829d8 31c0 4821d8 4809d8 4839d8 4885d8 488d4308 48ffc0 48ffc8 "
        "48d1e0 48d1e8 48d1f8 48d1c0 48d1c8 480fafc3 48f7e3 48f7d8 4811d8 4819d8 4893 480fc8 "
        "0fb6c3 0fbec3 480fa3d8 480fabd8 480fbcc3 480fbdc3 99 98 0f95c0 0f94c0 480f45c3 "
        "480f44c3 90 c9"
    ).split()
]
BODY = "a" * digest.SKETCH_HEX


def varied(length: int, seed: int) -> list[bytes]:
    rng = random.Random(seed)
    return [rng.choice(POOL) for _ in range(length)]


def sketch_of(code: list[bytes]) -> digest.Sketch:
    text = _native.digest([b"".join(code)], 64, "pe64")
    assert text is not None
    return digest.parse(text)


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
    text = _native.digest([b"".join(varied(300, seed=0))], 64, "pe64")
    assert text is not None
    slots = digest.unpack(digest.parse(text))
    assert len(slots) == digest.PERMUTATIONS
    body = int(text.rsplit(":", 1)[-1], 16)
    assert [int(value) for value in slots] == [
        (body >> (digest.PERMUTATIONS - 1 - index) * digest.SLOT_BITS) & digest.MASK
        for index in range(digest.PERMUTATIONS)
    ]


def test_the_margin_of_error_comes_from_the_slots_and_not_the_score() -> None:
    zeros = digest.Sketch("pe64", 100, 0)
    ones = digest.Sketch("pe64", 100, int("01" * 256, 2))
    mixed = digest.Sketch("pe64", 100, int("00" * 32 + "01" * 224, 2))
    assert digest.compare(zeros, ones).uncertainty == pytest.approx(WILSON_MARGIN_AT_FULL_AGREEMENT)
    assert digest.compare(zeros, mixed).uncertainty == pytest.approx(2.952, abs=0.001)

    rows = digest.unpack_all([ones, mixed])
    cardinalities = digest.cardinalities([ones, mixed])
    scored, spread = digest.score(rows, cardinalities, digest.unpack(zeros), zeros.cardinality)
    assert list(scored) == [0.0, 0.0]
    assert float(spread[0]) == pytest.approx(WILSON_MARGIN_AT_FULL_AGREEMENT)
    assert float(spread[1]) == pytest.approx(2.952, abs=0.001)


def test_a_cardinality_gap_caps_the_similarity() -> None:
    small = digest.Sketch("pe64", 100, 0)
    large = digest.Sketch("pe64", 1000, 0)
    assert digest.compare(small, large).similarity == pytest.approx(10.0)
    assert digest.compare(large, small).similarity == pytest.approx(10.0)


@pytest.mark.parametrize(("left", "right", "expected"), [(0, 0, 100.0), (0, 50, 0.0)])
def test_an_empty_cardinality_bounds_without_dividing_by_zero(
    left: int, right: int, expected: float
) -> None:
    scores = digest.compare(digest.Sketch("pe64", left, 0), digest.Sketch("pe64", right, 0))
    assert scores.similarity == expected


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
