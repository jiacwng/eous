# Scores the functions of one file against the functions of stored files.

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy

from eous import _native, digest

MATCH = 50.0
FUNCTION_BYTES = _native.FUNCTION_BYTES


@dataclass(frozen=True)
class Table:
    lengths: numpy.ndarray
    cardinalities: numpy.ndarray
    sketches: bytes


@dataclass(frozen=True)
class Matched:
    files: numpy.ndarray
    in_file: numpy.ndarray
    closest: numpy.ndarray
    named: numpy.ndarray


def table(functions: Sequence[tuple[int, digest.Sketch]]) -> Table:
    packed = b"".join(sketch.slots.to_bytes(digest.SKETCH_BYTES, "big") for _, sketch in functions)
    return Table(
        numpy.array([length for length, _ in functions], dtype=numpy.float64),
        digest.cardinalities([sketch for _, sketch in functions]),
        packed,
    )


def scores(stored: Table, sketch: bytes, cardinality: float) -> numpy.ndarray:
    counted = _native.differing_slots(stored.sketches, sketch)
    agreed = 1 - numpy.frombuffer(counted, dtype=numpy.uint16) / digest.PERMUTATIONS
    similarity = numpy.maximum(0.0, (agreed - digest.FLOOR) / (1 - digest.FLOOR)) * 100
    smaller = numpy.minimum(stored.cardinalities, cardinality)
    larger = numpy.maximum(stored.cardinalities, cardinality)
    bound = numpy.divide(smaller, larger, out=numpy.ones_like(larger), where=larger > 0)
    capped: numpy.ndarray = numpy.minimum(similarity, bound * 100)
    return capped


# MCRIT's convention. Each function takes its best match in the other file, a match counts
# from a score of 50, and the matched bytes, weighted by that score, are a share of the
# function bytes of both files. `starts` is where each stored file begins in `stored`, and
# `names` lists the stored functions that carry a name.
def match(query: Table, stored: Table, starts: numpy.ndarray, names: numpy.ndarray) -> Matched:
    in_file = numpy.empty((len(query.lengths), len(starts)), dtype=numpy.float64)
    closest = numpy.empty(len(query.lengths), dtype=numpy.intp)
    named = numpy.full(len(query.lengths), -1, dtype=numpy.intp)
    in_query = numpy.zeros(len(stored.lengths), dtype=numpy.float64)

    for row, cardinality in enumerate(query.cardinalities):
        first = row * digest.SKETCH_BYTES
        scored = scores(stored, query.sketches[first : first + digest.SKETCH_BYTES], cardinality)
        in_file[row] = numpy.maximum.reduceat(scored, starts)
        closest[row] = scored.argmax()
        numpy.maximum(in_query, scored, out=in_query)
        if names.size:
            best = names[scored[names].argmax()]
            if scored[best] >= MATCH:
                named[row] = best

    forward = query.lengths @ _gain(in_file)
    back = numpy.add.reduceat(stored.lengths * _gain(in_query), starts)
    both = query.lengths.sum() + numpy.add.reduceat(stored.lengths, starts)
    return Matched((forward + back) * 100 / both, in_file, closest, named)


def _gain(scored: numpy.ndarray) -> numpy.ndarray:
    return numpy.where(scored >= MATCH, scored / 100, 0.0)
