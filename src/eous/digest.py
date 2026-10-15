# Parses EO1 digests and scores them against each other.

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

import numpy

VERSION = "EO1"

PERMUTATIONS = 256
SLOT_BITS = 2

MAX_CONTAINMENT_RATIO = 4.0

MAX_CARDINALITY = 2**53

FLOOR = 2.0**-SLOT_BITS
MASK = (1 << SLOT_BITS) - 1
SKETCH_BYTES = PERMUTATIONS * SLOT_BITS // 8
SKETCH_HEX = SKETCH_BYTES * 2

TARGETS = ("pe32", "pe64", "elf32", "elf64")
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
    left_in_right_uncertainty: float | None
    right_in_left_uncertainty: float | None


def _check_target(target: str) -> None:
    if target not in TARGETS:
        raise DigestError(f"unsupported target {target!r}, expected one of: {', '.join(TARGETS)}")


def parse(text: str) -> Sketch:
    fields = text.split(":")
    if len(fields) != 4:
        raise DigestError(f"expected 4 fields, found {len(fields)}")

    version, target, cardinality, body = fields
    if version != VERSION:
        raise DigestError(f"expected version {VERSION}, found {version!r}")
    _check_target(target)
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


def score(rows: numpy.ndarray, one: numpy.ndarray) -> tuple[numpy.ndarray, numpy.ndarray]:
    # Two unrelated sets already agree on one slot in four, so chance agreement comes off.
    agreed = numpy.count_nonzero(rows == one, axis=1) / PERMUTATIONS
    similarity = numpy.maximum(0.0, (agreed - FLOOR) / (1 - FLOOR)) * 100
    return similarity, _wilson_margin(agreed) / (1 - FLOOR) * 100


def _wilson_margin(agreed: numpy.ndarray) -> numpy.ndarray:
    denominator = 1 + 1 / PERMUTATIONS
    centre = (agreed + 1 / (2 * PERMUTATIONS)) / denominator
    half = (
        numpy.sqrt(agreed * (1 - agreed) / PERMUTATIONS + 1 / (4 * PERMUTATIONS**2)) / denominator
    )
    margin: numpy.ndarray = numpy.maximum(agreed - (centre - half), centre + half - agreed)
    return margin


def compare(left: Sketch | str, right: Sketch | str) -> Scores:
    first = parse(left) if isinstance(left, str) else left
    second = parse(right) if isinstance(right, str) else right

    if first.target != second.target:
        raise DigestError(f"different targets: {first.target} and {second.target}")

    similarity, uncertainty = score(unpack(first).reshape(1, -1), unpack(second))
    overlap = float(similarity[0]) / 100
    spread = float(uncertainty[0])

    left_in_right, right_in_left, left_error, right_error = _containment(
        overlap, spread / 100, first.cardinality, second.cardinality
    )
    return Scores(
        similarity=overlap * 100,
        uncertainty=spread,
        left_in_right=left_in_right,
        right_in_left=right_in_left,
        left_in_right_uncertainty=left_error,
        right_in_left_uncertainty=right_error,
    )


def _containment(
    jaccard: float, error: float, left: int, right: int
) -> tuple[float | None, float | None, float | None, float | None]:
    smaller, larger = sorted((left, right))
    if smaller == 0 or larger > smaller * MAX_CONTAINMENT_RATIO:
        return (None, None, None, None)

    jaccard = min(jaccard, smaller / larger)
    shared = jaccard * (left + right) / (1 + jaccard)
    spread = error * (left + right) / (1 + jaccard) ** 2
    return (
        min(1.0, shared / left) * 100,
        min(1.0, shared / right) * 100,
        min(100.0, spread / left * 100),
        min(100.0, spread / right * 100),
    )
