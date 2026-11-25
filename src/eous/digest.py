# Parses EO1 digests and scores them against each other.

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from statistics import NormalDist

import numpy

from eous import _native

VERSION = _native.VERSION
PERMUTATIONS = _native.PERMUTATIONS
SLOT_BITS = _native.SLOT_BITS
TARGETS = tuple(_native.TARGETS)

MAX_CONTAINMENT_RATIO = 4.0

MAX_CARDINALITY = 2**53

CONFIDENCE = 0.95
Z = NormalDist().inv_cdf((1 + CONFIDENCE) / 2)

FLOOR = 2.0**-SLOT_BITS
MASK = (1 << SLOT_BITS) - 1
SKETCH_BYTES = PERMUTATIONS * SLOT_BITS // 8
SKETCH_HEX = SKETCH_BYTES * 2

SKETCH_PATTERN = re.compile(f"^[0-9a-f]{{{SKETCH_HEX}}}$")


class DigestError(Exception):
    pass


@dataclass(frozen=True)
class Sketch:
    target: str
    cardinality: int
    slots: int


@dataclass(frozen=True)
class Scores:
    similarity: float
    uncertainty: float
    left_in_right: float | None
    right_in_left: float | None


def parse(text: str) -> Sketch:
    fields = text.split(":")
    if len(fields) != 4:
        raise DigestError(f"expected 4 fields, found {len(fields)}")

    version, target, cardinality, body = fields
    if version != VERSION:
        raise DigestError(f"expected version {VERSION}, found {version!r}")
    if target not in TARGETS:
        raise DigestError(f"unsupported target {target!r}, expected one of: {', '.join(TARGETS)}")
    if not (cardinality.isascii() and cardinality.isdigit()):
        raise DigestError(f"cardinality {cardinality!r} is a non-negative integer")
    if len(cardinality) > len(str(MAX_CARDINALITY)) or int(cardinality) > MAX_CARDINALITY:
        raise DigestError(f"cardinality exceeds {MAX_CARDINALITY}")
    if not SKETCH_PATTERN.match(body):
        raise DigestError(f"sketch is {SKETCH_HEX} lower-case hex characters")

    return Sketch(target, int(cardinality), int(body, 16))


def unpack(sketch: Sketch) -> numpy.ndarray:
    raw = numpy.frombuffer(sketch.slots.to_bytes(SKETCH_BYTES, "big"), dtype=numpy.uint8)
    columns = [
        (raw >> numpy.uint8(8 - SLOT_BITS * (place + 1))) & numpy.uint8(MASK)
        for place in range(8 // SLOT_BITS)
    ]
    return numpy.stack(columns, axis=1).reshape(-1)


def unpack_all(sketches: Sequence[Sketch]) -> numpy.ndarray:
    return numpy.stack([unpack(sketch) for sketch in sketches])


def cardinalities(sketches: Sequence[Sketch]) -> numpy.ndarray:
    return numpy.array([sketch.cardinality for sketch in sketches], dtype=numpy.float64)


def pack(sketches: Sequence[Sketch]) -> bytes:
    return b"".join(sketch.slots.to_bytes(SKETCH_BYTES, "big") for sketch in sketches)


def agreement(rows: bytes, one: bytes) -> numpy.ndarray:
    differing = numpy.frombuffer(_native.differing_slots(rows, one), dtype=numpy.uint16)
    return 1 - differing / PERMUTATIONS


def similarity(
    agreed: numpy.ndarray, row_cardinalities: numpy.ndarray, cardinality: float
) -> numpy.ndarray:
    # Two unrelated sets already agree on one slot in four, so chance agreement comes off,
    # and their Jaccard cannot exceed the smaller cardinality over the larger.
    estimate = numpy.maximum(0.0, (agreed - FLOOR) / (1 - FLOOR)) * 100
    smaller = numpy.minimum(row_cardinalities, cardinality)
    larger = numpy.maximum(row_cardinalities, cardinality)
    bound = numpy.divide(smaller, larger, out=numpy.ones_like(larger), where=larger > 0)
    capped: numpy.ndarray = numpy.minimum(estimate, bound * 100)
    return capped


def margin(agreed: numpy.ndarray) -> numpy.ndarray:
    return _wilson_margin(agreed) / (1 - FLOOR) * 100


def score(
    rows: numpy.ndarray, row_cardinalities: numpy.ndarray, one: numpy.ndarray, cardinality: int
) -> tuple[numpy.ndarray, numpy.ndarray]:
    agreed = numpy.count_nonzero(rows == one, axis=1) / PERMUTATIONS
    return similarity(agreed, row_cardinalities, cardinality), margin(agreed)


def _wilson_margin(agreed: numpy.ndarray) -> numpy.ndarray:
    denominator = 1 + Z**2 / PERMUTATIONS
    centre = (agreed + Z**2 / (2 * PERMUTATIONS)) / denominator
    half = (
        Z
        * numpy.sqrt(agreed * (1 - agreed) / PERMUTATIONS + Z**2 / (4 * PERMUTATIONS**2))
        / denominator
    )
    widest: numpy.ndarray = numpy.maximum(agreed - (centre - half), centre + half - agreed)
    return widest


def compare(left: Sketch, right: Sketch) -> Scores:
    if left.target != right.target:
        raise DigestError(f"different targets: {left.target} and {right.target}")

    similarity, uncertainty = score(
        unpack(left).reshape(1, -1), cardinalities([left]), unpack(right), right.cardinality
    )
    overlap = float(similarity[0])
    left_in_right, right_in_left = _containment(overlap / 100, left.cardinality, right.cardinality)
    return Scores(overlap, float(uncertainty[0]), left_in_right, right_in_left)


def _containment(jaccard: float, left: int, right: int) -> tuple[float | None, float | None]:
    smaller, larger = sorted((left, right))
    if smaller == 0 or larger > smaller * MAX_CONTAINMENT_RATIO:
        return (None, None)

    shared = jaccard * (left + right) / (1 + jaccard)
    return (min(1.0, shared / left) * 100, min(1.0, shared / right) * 100)
