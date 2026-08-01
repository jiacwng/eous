import hashlib
import json
from pathlib import Path

import pytest

from eous import digest, disasm, loader

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures" / "bin"
VECTORS = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))

FILES = VECTORS["files"]
IDS = [entry["name"] for entry in FILES]


# These assertions exist to fail. A red golden test means a change altered the digest, so
# every stored digest anywhere no longer compares against a fresh one.
@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_reproduces_its_recorded_digest(entry: dict[str, object]) -> None:
    path = FIXTURES / str(entry["name"])
    binary = loader.load(path)
    produced = digest.digest(disasm.sweep(binary).chunks, binary.arch)
    assert produced == entry["digest"]


# The fixture has to be the same file, otherwise a rebuilt binary would look like an
# algorithm change.
@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_is_the_file_the_vector_was_taken_from(entry: dict[str, object]) -> None:
    raw = (FIXTURES / str(entry["name"])).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_the_stages_before_the_digest_stay_put(entry: dict[str, object]) -> None:
    binary = loader.load(FIXTURES / str(entry["name"]))
    sweep = disasm.sweep(binary)
    assert binary.arch == entry["arch"]
    assert sweep.total_decoded == entry["decoded"]
    assert len(sweep.chunks) == entry["chunks"]


# Hand-written chunks, so an algorithm change and a rebuilt fixture fail separately.
def test_the_synthetic_case_reproduces() -> None:
    case = VECTORS["synthetic"]
    chunks = tuple(tuple(chunk) for chunk in case["chunks"])
    assert digest.digest(chunks, case["arch"]) == case["digest"]


def test_the_recorded_parameters_match_the_code() -> None:
    assert VECTORS["version"] == digest.VERSION
    assert VECTORS["ngram"] == digest.NGRAM
    assert VECTORS["permutations"] == digest.PERMUTATIONS
    assert VECTORS["slot_bits"] == digest.SLOT_BITS


def test_every_fixture_has_a_vector() -> None:
    on_disk = {p.name for p in FIXTURES.iterdir()}
    recorded = {str(entry["name"]) for entry in FILES}
    assert on_disk == recorded


# Proof the golden test can fail: perturbing any parameter changes the digest.
@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("NGRAM", 5),
        ("SLOT_BITS", 1),
        ("MODULUS", (1 << 31) - 1),
        ("COEFFICIENTS", digest.COEFFICIENTS[:128]),
        ("COEFFICIENTS", tuple(reversed(digest.COEFFICIENTS))),
    ],
    ids=["ngram", "slot_bits", "modulus", "fewer_permutations", "permutation_order"],
)
def test_a_changed_parameter_breaks_the_vector(
    monkeypatch: pytest.MonkeyPatch, attribute: str, value: object
) -> None:
    case = VECTORS["synthetic"]
    chunks = tuple(tuple(chunk) for chunk in case["chunks"])
    monkeypatch.setattr(digest, attribute, value)
    assert digest.digest(chunks, case["arch"]) != case["digest"]


# `pack` walks COEFFICIENTS while `Sketch.slot` indexes by PERMUTATIONS, so the two
# drifting apart would pack one length and read back another.
def test_the_permutation_count_matches_its_table() -> None:
    assert len(digest.COEFFICIENTS) == digest.PERMUTATIONS


def test_a_changed_separator_breaks_the_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    case = VECTORS["synthetic"]
    chunks = tuple(tuple(chunk) for chunk in case["chunks"])
    monkeypatch.setattr(digest, "SEPARATOR", b"\x00")
    assert digest.digest(chunks, case["arch"]) != case["digest"]


def test_a_changed_personalisation_breaks_the_vector(monkeypatch: pytest.MonkeyPatch) -> None:
    case = VECTORS["synthetic"]
    chunks = tuple(tuple(chunk) for chunk in case["chunks"])
    monkeypatch.setattr(digest, "SHINGLE_PERSON", b"eous-xx")
    assert digest.digest(chunks, case["arch"]) != case["digest"]
