# Single-linkage clustering of digests: chains, the threshold, the cardinality bound and order.

from eous import cluster, digest

BASE = "0" * 128
NEAR = "5" * 16 + "0" * 112
FAR = "5" * 16 + "a" * 16 + "0" * 96
OPPOSITE = "f" * 128


def sketch(body: str, cardinality: int = 1000) -> digest.Sketch:
    return digest.parse(f"EO1:pe64:{cardinality}:{body}")


def test_a_chain_joins_two_digests_that_score_below_the_minimum() -> None:
    chain = [sketch(BASE), sketch(NEAR), sketch(FAR)]
    assert digest.compare(chain[0], chain[2]).similarity < 80
    assert cluster.clusters(chain, 80) == [[0, 1, 2]]


def test_a_later_digest_joins_two_earlier_clusters() -> None:
    assert cluster.clusters([sketch(BASE), sketch(FAR), sketch(NEAR)], 80) == [[0, 1, 2]]


def test_a_minimum_above_every_score_leaves_each_digest_alone() -> None:
    assert cluster.clusters([sketch(BASE), sketch(NEAR), sketch(FAR)], 90) == [[0], [1], [2]]


def test_a_score_equal_to_the_minimum_joins() -> None:
    assert cluster.clusters([sketch(BASE), sketch(BASE)], 100) == [[0, 1]]


def test_clusters_follow_their_first_member_and_members_keep_their_order() -> None:
    mixed = [sketch(BASE), sketch(OPPOSITE), sketch(NEAR), sketch(OPPOSITE)]
    assert cluster.clusters(mixed, 80) == [[0, 2], [1, 3]]


def test_a_cardinality_gap_keeps_equal_sketches_apart() -> None:
    assert cluster.clusters([sketch(BASE, 100), sketch(BASE, 1000)], 50) == [[0], [1]]


def test_one_digest_is_its_own_cluster() -> None:
    assert cluster.clusters([sketch(BASE)], 0) == [[0]]
