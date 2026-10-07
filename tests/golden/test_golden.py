import hashlib
import json
from pathlib import Path

import pytest

from conftest import FIXTURES
from eous import cli, digest, loader, report, toolchain

VECTORS = json.loads((Path(__file__).resolve().parent / "vectors.json").read_text(encoding="utf-8"))

FILES = VECTORS["files"]
IDS = [entry["name"] for entry in FILES]


# These assertions exist to fail. A red golden test means a change altered the digest, so
# every stored digest anywhere no longer compares against a fresh one.
@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_reproduces_its_recorded_digest(entry: dict[str, object]) -> None:
    path = FIXTURES / str(entry["name"])
    binary = loader.load(path)
    produced = digest.digest(report.disassemble(binary).runs, binary.target)
    assert produced == entry["digest"]


# The command hashes in worker processes, and Linux starts them differently from Windows.
def test_the_pooled_command_reproduces_every_vector(capsys: pytest.CaptureFixture[str]) -> None:
    paths = [str(FIXTURES / str(entry["name"])) for entry in FILES]
    assert len(paths) > 1, "a single path skips the pool, which is the thing under test"

    assert cli.main(["hash", *paths]) == 0

    printed = capsys.readouterr().out
    for entry, path in zip(FILES, paths, strict=True):
        assert f"{path}  {entry['digest']}" in printed


# The fixture has to be the same file, otherwise a rebuilt binary would look like an
# algorithm change.
@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_is_the_file_the_vector_was_taken_from(entry: dict[str, object]) -> None:
    raw = (FIXTURES / str(entry["name"])).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_the_stages_before_the_digest_stay_put(entry: dict[str, object]) -> None:
    binary = loader.load(FIXTURES / str(entry["name"]))
    found = report.disassemble(binary)
    assert binary.target == entry["target"]
    assert found.total_decoded == entry["decoded"]
    assert len(found.runs) == entry["runs"]


# Hand-written runs, so an algorithm change and a rebuilt fixture fail separately.
def test_the_synthetic_case_reproduces() -> None:
    case = VECTORS["synthetic"]
    runs = tuple(tuple(run) for run in case["runs"])
    assert digest.digest(runs, case["target"]) == case["digest"]


# A digest is only reproducible under the decoder that produced it.
def test_the_recorded_engines_are_the_installed_ones() -> None:
    assert toolchain.engines() == VECTORS["engines"]


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
        ("SEPARATOR", b"\x00"),
        ("SHINGLE_PERSON", b"eous-xx"),
    ],
    ids=[
        "ngram",
        "slot_bits",
        "modulus",
        "fewer_permutations",
        "permutation_order",
        "separator",
        "personalisation",
    ],
)
def test_a_changed_parameter_breaks_the_vector(
    monkeypatch: pytest.MonkeyPatch, attribute: str, value: object
) -> None:
    case = VECTORS["synthetic"]
    runs = tuple(tuple(run) for run in case["runs"])
    monkeypatch.setattr(digest, attribute, value)
    assert digest.digest(runs, case["target"]) != case["digest"]
