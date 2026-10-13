# The pure Python digest pipeline, kept as the reference the native one must match.

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from functools import cache, lru_cache
from pathlib import Path

import numpy
from iced_x86 import Decoder, FlowControl, Mnemonic

from eous.digest import SKETCH_BYTES, TARGETS, VERSION, DigestError, Sketch
from eous.loader import BITS, Section

ROOTS_FILE = Path(__file__).resolve().parents[1] / "native" / "roots.json"

NGRAM = 6
PERMUTATIONS = 256
SLOT_BITS = 2
MODULUS = (1 << 61) - 1
SEPARATOR = b"\x1f"
OOV = "<oov>"
PERMUTATION_PERSON = b"eous-prm"
SHINGLE_PERSON = b"eous-ng"
MASK = (1 << SLOT_BITS) - 1
BLOCK = 4096

CONTINUES = frozenset({FlowControl.NEXT, FlowControl.INTERRUPT})
MNEMONICS = {
    value: name.lower()
    for name, value in vars(Mnemonic).items()
    if name.isupper() and isinstance(value, int)
}


@cache
def roots() -> dict[str, str]:
    table: dict[str, str] = json.loads(ROOTS_FILE.read_text(encoding="utf-8"))
    return table


@dataclass(frozen=True)
class Disassembly:
    runs: tuple[tuple[str, ...], ...]
    total_decoded: int


def disassemble(sections: Sequence[Section], arch: str) -> Disassembly:
    runs: list[tuple[str, ...]] = []
    total_decoded = 0
    for section in sections:
        section_runs, decoded = _disassemble_section(section.data, BITS[arch])
        runs.extend(section_runs)
        total_decoded += decoded
    return Disassembly(runs=tuple(runs), total_decoded=total_decoded)


def _disassemble_section(data: bytes, bitness: int) -> tuple[list[tuple[str, ...]], int]:
    decoder = Decoder(bitness, data)
    runs: list[tuple[str, ...]] = []
    current: list[str] = []
    decoded = 0
    repeated = 0
    previous = ""

    def close_run() -> None:
        nonlocal repeated, previous
        if current:
            runs.append(tuple(current))
            current.clear()
        repeated = 0
        previous = ""

    while decoder.can_decode:
        position = decoder.position
        instruction = decoder.decode()
        if instruction.is_invalid:
            decoder.position = position + 1
            close_run()
            continue
        mnemonic = MNEMONICS[instruction.mnemonic]
        repeated = repeated + 1 if mnemonic == previous else 1
        previous = mnemonic
        if repeated <= NGRAM:
            current.append(mnemonic)
        decoded += 1
        if instruction.flow_control not in CONTINUES:
            close_run()

    close_run()
    return runs, decoded


def h64(payload: bytes, person: bytes) -> int:
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


def normalise(runs: Sequence[Sequence[str]]) -> list[list[str]]:
    table = roots()
    return [[table.get(mnemonic, OOV) for mnemonic in run] for run in runs]


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


def digest(runs: Sequence[Sequence[str]], target: str) -> str | None:
    if target not in TARGETS:
        raise DigestError(f"unsupported target {target!r}")
    grams = shingles(normalise(runs))
    if len({root for gram in grams for root in gram}) < 2:
        return None
    return render(Sketch(target, len(grams), pack(grams)))


def render(sketch: Sketch) -> str:
    body = sketch.slots.to_bytes(SKETCH_BYTES, "big").hex()
    return f"{VERSION}:{sketch.target}:{sketch.cardinality}:{body}"
