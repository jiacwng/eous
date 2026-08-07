# Turns chunks of mnemonics into an EO1 digest, and scores digests against each other.
#
# A digest reads EO1:arch:cardinality:sketch. Changing any constant below changes every digest.

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from math import sqrt

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
MAX_OOV_PER_SHINGLE = 1

MAX_CONTAINMENT_RATIO = 4.0

PERMUTATION_PERSON = b"eous-prm"
SHINGLE_PERSON = b"eous-ng"

FLOOR = 2.0**-SLOT_BITS
MASK = (1 << SLOT_BITS) - 1
SKETCH_BYTES = PERMUTATIONS * SLOT_BITS // 8
SKETCH_HEX = SKETCH_BYTES * 2

SUPPORTED_ARCHES = ("x86", "x86-64")
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

# Hashes are permuted in batches, so memory stays near 8 MB however many shingles there are.
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
    multipliers = numpy.array([pair[0] for pair in coefficients], dtype=numpy.uint64).reshape(-1, 1)
    return _Table(
        upper=multipliers >> numpy.uint64(split),
        lower=multipliers & numpy.uint64((1 << split) - 1),
        offsets=numpy.array([pair[1] for pair in coefficients], dtype=numpy.uint64).reshape(-1, 1),
        modulus=numpy.uint64(modulus),
        width=numpy.uint64(width),
        split=numpy.uint64(split),
        half=numpy.uint64((1 << split) - 1),
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
        # A hash spans the full 64 bits, so it takes two folds to land under the modulus.
        block = _fold(_fold(hashes[start : start + BLOCK], table), table)
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
    arch: str
    cardinality: int
    slots: int

    def render(self) -> str:
        body = self.slots.to_bytes(SKETCH_BYTES, "big").hex()
        return f"{self.version}:{self.arch}:{self.cardinality}:{body}"


@dataclass(frozen=True)
class Scores:
    similarity: float
    uncertainty: float
    left_in_right: float | None
    right_in_left: float | None


def normalise(chunks: tuple[tuple[str, ...], ...], arch: str) -> list[list[str]]:
    vocab = load_vocab(arch)
    return [[vocab.root_of(mnemonic) or OOV for mnemonic in chunk] for chunk in chunks]


def shingles(chunks: list[list[str]]) -> set[tuple[str, ...]]:
    grams: set[tuple[str, ...]] = set()
    for chunk in chunks:
        for start in range(len(chunk) - NGRAM + 1):
            window = tuple(chunk[start : start + NGRAM])
            if window.count(OOV) <= MAX_OOV_PER_SHINGLE:
                grams.add(window)
    return grams


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


def digest(chunks: tuple[tuple[str, ...], ...], arch: str) -> str | None:
    if arch not in SUPPORTED_ARCHES:
        raise DigestError(f"unsupported architecture {arch!r}")

    grams = shingles(normalise(chunks, arch))
    if not grams:
        # Too little readable code to describe, so the caller names the cause instead.
        return None

    return Sketch(VERSION, arch, len(grams), pack(grams)).render()


def parse(text: str) -> Sketch:
    fields = text.split(":")
    if len(fields) != 4:
        raise DigestError(f"expected 4 fields, found {len(fields)}")

    version, arch, cardinality, body = fields
    if version != VERSION:
        raise DigestError(f"expected version {VERSION}, found {version!r}")
    if arch not in SUPPORTED_ARCHES:
        raise DigestError(f"unsupported architecture {arch!r}")
    if not cardinality.isdigit():
        raise DigestError(f"cardinality {cardinality!r} is a non-negative integer")
    if not SKETCH_PATTERN.match(body):
        raise DigestError(f"sketch is {SKETCH_HEX} lower-case hex characters")

    return Sketch(version, arch, int(cardinality), int(body, 16))


def unpack(sketch: Sketch) -> numpy.ndarray:
    raw = numpy.frombuffer(sketch.slots.to_bytes(SKETCH_BYTES, "big"), dtype=numpy.uint8)
    columns = [
        (raw >> numpy.uint8(8 - SLOT_BITS * (place + 1))) & numpy.uint8(MASK)
        for place in range(8 // SLOT_BITS)
    ]
    return numpy.stack(columns, axis=1).reshape(-1)


def unpack_all(sketches: Sequence[Sketch]) -> numpy.ndarray:
    if not sketches:
        return numpy.empty((0, PERMUTATIONS), dtype=numpy.uint8)
    return numpy.stack([unpack(sketch) for sketch in sketches])


def _agreement(rows: numpy.ndarray, one: numpy.ndarray) -> numpy.ndarray:
    matched: numpy.ndarray = numpy.count_nonzero(rows == one, axis=1)
    return matched / PERMUTATIONS


def _jaccard(agreed: numpy.ndarray) -> numpy.ndarray:
    # Two unrelated sets already agree on one slot in four, so chance agreement comes off.
    return numpy.maximum(0.0, (agreed - FLOOR) / (1 - FLOOR))


def similarities(rows: numpy.ndarray, one: numpy.ndarray) -> numpy.ndarray:
    # One sketch against many, so N digests unpack N times and score in one pass.
    return _jaccard(_agreement(rows, one)) * 100.0


def compare(left: Sketch | str, right: Sketch | str) -> Scores:
    first = parse(left) if isinstance(left, str) else left
    second = parse(right) if isinstance(right, str) else right

    if first.version != second.version:
        raise DigestError(f"versions differ: {first.version} and {second.version}")
    if first.arch != second.arch:
        raise DigestError(f"architectures differ: {first.arch} and {second.arch}")

    agreed = _agreement(unpack(first).reshape(1, -1), unpack(second))
    observed = float(agreed[0])
    overlap = float(_jaccard(agreed)[0])
    uncertainty = sqrt(observed * (1 - observed) / PERMUTATIONS) / (1 - FLOOR) * 100

    left_in_right, right_in_left = _containment(overlap, first.cardinality, second.cardinality)
    return Scores(
        similarity=overlap * 100,
        uncertainty=uncertainty,
        left_in_right=left_in_right,
        right_in_left=right_in_left,
    )


def _containment(jaccard: float, left: int, right: int) -> tuple[float | None, float | None]:
    # Both directions carry the same information as jaccard plus the two cardinalities.
    smaller, larger = sorted((left, right))
    if smaller == 0 or larger > smaller * MAX_CONTAINMENT_RATIO:
        return (None, None)

    shared = jaccard * (left + right) / (1 + jaccard)
    return (min(1.0, shared / left) * 100, min(1.0, shared / right) * 100)
