# Groups the digests of one target by single linkage.

from __future__ import annotations

from collections.abc import Sequence

import numpy

from eous import digest


# Two digests share a cluster when a chain of pairs scoring at least the minimum joins them.
# Clusters come back in the order of their first member, each as positions into the input.
def clusters(sketches: Sequence[digest.Sketch], minimum: float) -> list[list[int]]:
    rows = digest.pack(sketches)
    cardinalities = digest.cardinalities(sketches)
    labels = numpy.arange(len(sketches))

    for left in range(len(sketches) - 1):
        after = (left + 1) * digest.SKETCH_BYTES
        agreed = digest.agreement(rows[after:], rows[after - digest.SKETCH_BYTES : after])
        scores = digest.similarity(agreed, cardinalities[left + 1 :], sketches[left].cardinality)
        joined = numpy.unique(labels[left + 1 :][scores >= minimum])
        joined = joined[joined != labels[left]]
        if joined.size:
            labels[numpy.isin(labels, joined)] = labels[left]

    found: dict[int, list[int]] = {}
    for place, label in enumerate(labels.tolist()):
        found.setdefault(label, []).append(place)
    return list(found.values())
