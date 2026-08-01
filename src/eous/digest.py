# Turns chunks of mnemonics into an EO1 digest, and compares two digests.
#
# A digest reads EO1:arch:cardinality:sketch. Changing any constant below changes every
# digest, so the version string changes with them.

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from math import sqrt

from eous.vocab import load as load_vocab

VERSION = "EO1"

NGRAM = 6

# At a fixed 512-bit sketch, permutations trade against bits per slot. Two bits minimises
# worst-case standard error: 4.17 points, against 4.42 at one bit and 4.71 at four.
PERMUTATIONS = 256
SLOT_BITS = 2

# Prime keeps the affine map a bijection; Mersenne keeps the arithmetic inside 61 bits.
MODULUS = (1 << 61) - 1

SEPARATOR = b"\x1f"
OOV = "<oov>"
MAX_OOV_PER_SHINGLE = 1

# Above this size ratio the estimate turns unreliable: at ratio 67 a strict subset
# reported containment 0.0 in 12 of 40 trials.
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


@dataclass(frozen=True)
class Sketch:
    version: str
    arch: str
    cardinality: int
    slots: int

    def slot(self, index: int) -> int:
        shift = (PERMUTATIONS - 1 - index) * SLOT_BITS
        return (self.slots >> shift) & MASK

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
    hashes = [
        h64(SEPARATOR.join(token.encode("utf-8") for token in gram), SHINGLE_PERSON)
        for gram in grams
    ]

    accumulated = 0
    for multiplier, offset in COEFFICIENTS:
        smallest = min((multiplier * value + offset) % MODULUS for value in hashes)
        accumulated = (accumulated << SLOT_BITS) | (smallest & MASK)
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


def compare(left: Sketch | str, right: Sketch | str) -> Scores:
    first = parse(left) if isinstance(left, str) else left
    second = parse(right) if isinstance(right, str) else right

    if first.version != second.version:
        raise DigestError(f"versions differ: {first.version} and {second.version}")
    if first.arch != second.arch:
        raise DigestError(f"architectures differ: {first.arch} and {second.arch}")

    matches = sum(1 for i in range(PERMUTATIONS) if first.slot(i) == second.slot(i))
    observed = matches / PERMUTATIONS

    # Two unrelated sets already agree on one slot in four, so chance agreement comes off.
    jaccard = max(0.0, (observed - FLOOR) / (1 - FLOOR))
    uncertainty = sqrt(observed * (1 - observed) / PERMUTATIONS) / (1 - FLOOR) * 100

    left_in_right, right_in_left = _containment(jaccard, first.cardinality, second.cardinality)
    return Scores(
        similarity=jaccard * 100,
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
