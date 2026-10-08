# Turns straight-line runs of mnemonics into an EO1 digest, and scores digests against each other.

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache

import numpy

from eous.vocab import load as load_vocab

VERSION = "EO1"

NGRAM = 6

PERMUTATIONS = 256
SLOT_BITS = 2

# Prime keeps the affine map a bijection; Mersenne keeps the arithmetic inside 61 bits.
MODULUS = (1 << 61) - 1

SEPARATOR = b"\x1f"
OOV = "<oov>"

MAX_CONTAINMENT_RATIO = 4.0

MAX_CARDINALITY = 2**53

PERMUTATION_PERSON = b"eous-prm"
SHINGLE_PERSON = b"eous-ng"

FLOOR = 2.0**-SLOT_BITS
MASK = (1 << SLOT_BITS) - 1
SKETCH_BYTES = PERMUTATIONS * SLOT_BITS // 8
SKETCH_HEX = SKETCH_BYTES * 2

TARGETS = ("pe32", "pe64", "elf32", "elf64")
SKETCH_PATTERN = re.compile(f"^[0-9a-f]{{{SKETCH_HEX}}}$")


class DigestError(Exception):
    pass


def h64(payload: bytes, person: bytes) -> int:
    # BLAKE2b, since Python's built-in hash() is salted per process and would digest the
    # same file differently on every run.
    return int.from_bytes(hashlib.blake2b(payload, digest_size=8, person=person).digest(), "big")


def _derive_permutations() -> tuple[tuple[int, int], ...]:
    pairs = []
    for index in range(PERMUTATIONS):
        label = index.to_bytes(4, "big")
        multiplier = h64(b"a" + label, PERMUTATION_PERSON) % (MODULUS - 1) + 1
        offset = h64(b"b" + label, PERMUTATION_PERSON) % MODULUS
        pairs.append((multiplier, offset))
    return tuple(pairs)


COEFFICIENTS = _derive_permutations()

BLOCK = 4096


# multiplier * hash needs 122 bits and numpy holds 64, so each number is multiplied in halves.
@dataclass(frozen=True, eq=False)
class _Table:
    upper: numpy.ndarray
    lower: numpy.ndarray
    offsets: numpy.ndarray
    modulus: numpy.uint64
    width: numpy.uint64
    split: numpy.uint64
    half: numpy.uint64
    carry_shift: numpy.uint64
    carry: numpy.uint64
    two: numpy.uint64


@lru_cache(maxsize=1)
def _table(coefficients: tuple[tuple[int, int], ...], modulus: int) -> _Table:
    width = modulus.bit_length()
    split = (width + 1) // 2
    half = (1 << split) - 1
    multipliers = numpy.array([pair[0] for pair in coefficients], dtype=numpy.uint64).reshape(-1, 1)
    return _Table(
        upper=multipliers >> numpy.uint64(split),
        lower=multipliers & numpy.uint64(half),
        offsets=numpy.array([pair[1] for pair in coefficients], dtype=numpy.uint64).reshape(-1, 1),
        modulus=numpy.uint64(modulus),
        width=numpy.uint64(width),
        split=numpy.uint64(split),
        half=numpy.uint64(half),
        carry_shift=numpy.uint64(width - split),
        carry=numpy.uint64((1 << (width - split)) - 1),
        two=numpy.uint64(2),
    )


def _fold(values: numpy.ndarray, table: _Table) -> numpy.ndarray:
    folded = (values & table.modulus) + (values >> table.width)
    return folded - table.modulus * (folded >= table.modulus)


def _shift(values: numpy.ndarray, table: _Table) -> numpy.ndarray:
    carried = ((values & table.carry) << table.split) + (values >> table.carry_shift)
    return _fold(carried, table)


def _minima(hashes: numpy.ndarray) -> numpy.ndarray:
    table = _table(COEFFICIENTS, MODULUS)
    smallest = numpy.full(len(COEFFICIENTS), MODULUS, dtype=numpy.uint64)
    for start in range(0, hashes.size, BLOCK):
        block = _fold(hashes[start : start + BLOCK], table)
        upper, lower = block >> table.split, block & table.half
        permuted = _fold(
            _fold(table.two * (table.upper * upper), table)
            + _shift(_fold(table.upper * lower + table.lower * upper, table), table)
            + _fold(table.lower * lower, table)
            + table.offsets,
            table,
        )
        smallest = numpy.minimum(smallest, permuted.min(axis=1))
    return smallest


@dataclass(frozen=True)
class Sketch:
    version: str
    target: str
    cardinality: int
    slots: int

    def render(self) -> str:
        body = self.slots.to_bytes(SKETCH_BYTES, "big").hex()
        return f"{self.version}:{self.target}:{self.cardinality}:{body}"


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


def normalise(runs: tuple[tuple[str, ...], ...], target: str) -> list[list[str]]:
    _check_target(target)
    roots = load_vocab()
    return [[roots.get(mnemonic, OOV) for mnemonic in run] for run in runs]


def shingles(runs: list[list[str]]) -> set[tuple[str, ...]]:
    return {
        tuple(run[start : start + NGRAM]) for run in runs for start in range(len(run) - NGRAM + 1)
    }


def pack(grams: set[tuple[str, ...]]) -> int:
    if not grams:
        raise DigestError("a sketch describes one shingle or more")

    hashes = numpy.fromiter(
        (
            h64(SEPARATOR.join(token.encode("utf-8") for token in gram), SHINGLE_PERSON)
            for gram in grams
        ),
        dtype=numpy.uint64,
        count=len(grams),
    )

    accumulated = 0
    for smallest in _minima(hashes):
        accumulated = (accumulated << SLOT_BITS) | (int(smallest) & MASK)
    return accumulated


def digest(runs: tuple[tuple[str, ...], ...], target: str) -> str | None:
    grams = shingles(normalise(runs, target))
    if not grams:
        return None

    return Sketch(VERSION, target, len(grams), pack(grams)).render()


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
    if int(cardinality) > MAX_CARDINALITY:
        raise DigestError(f"cardinality {cardinality!r} exceeds {MAX_CARDINALITY}")
    if not SKETCH_PATTERN.match(body):
        raise DigestError(f"sketch is {SKETCH_HEX} lower-case hex characters")

    return Sketch(version, target, int(cardinality), int(body, 16))


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
    uncertainty = numpy.sqrt(agreed * (1 - agreed) / PERMUTATIONS) / (1 - FLOOR) * 100
    return similarity, uncertainty


def compare(left: Sketch | str, right: Sketch | str) -> Scores:
    first = parse(left) if isinstance(left, str) else left
    second = parse(right) if isinstance(right, str) else right

    if first.version != second.version:
        raise DigestError(f"versions differ: {first.version} and {second.version}")
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

    shared = jaccard * (left + right) / (1 + jaccard)
    spread = error * (left + right) / (1 + jaccard) ** 2
    return (
        min(1.0, shared / left) * 100,
        min(1.0, shared / right) * 100,
        min(100.0, spread / left * 100),
        min(100.0, spread / right * 100),
    )
