# Pins the EO1 format: every fixture and one hand-written case must reproduce its recorded digest.

import hashlib
import json
from pathlib import Path

import pytest

from conftest import FIXTURES
from eous import _native, cli, loader, toolchain

VECTORS = json.loads((Path(__file__).resolve().parent / "vectors.json").read_text(encoding="utf-8"))

FILES = VECTORS["files"]
IDS = [entry["name"] for entry in FILES]


def test_the_recorded_pipeline_constants_are_the_compiled_ones() -> None:
    recorded = {key: VECTORS[key] for key in ("version", "ngram", "permutations", "slot_bits")}
    assert recorded == {
        "version": _native.VERSION,
        "ngram": _native.NGRAM,
        "permutations": _native.PERMUTATIONS,
        "slot_bits": _native.SLOT_BITS,
    }


@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_reproduces_its_recorded_digest(entry: dict[str, object]) -> None:
    path = FIXTURES / str(entry["name"])
    binary = loader.load(path)
    sections = [section.data for section in binary.sections]
    produced = _native.digest(sections, loader.BITS[binary.arch], binary.target)
    assert produced == entry["digest"]


def test_the_pooled_command_reproduces_every_vector(capsys: pytest.CaptureFixture[str]) -> None:
    paths = [str(FIXTURES / str(entry["name"])) for entry in FILES]
    assert cli.main(["hash", *paths]) == cli.OK

    printed = capsys.readouterr().out
    for entry, path in zip(FILES, paths, strict=True):
        assert f"{path}  {entry['digest']}" in printed


@pytest.mark.parametrize("entry", FILES, ids=IDS)
def test_a_fixture_is_the_file_the_vector_was_taken_from(entry: dict[str, object]) -> None:
    raw = (FIXTURES / str(entry["name"])).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"]


def test_the_synthetic_case_reproduces() -> None:
    case = VECTORS["synthetic"]
    code = bytes.fromhex(case["code"])
    assert _native.digest([code], case["bitness"], case["target"]) == case["digest"]


def test_the_recorded_engines_are_the_installed_ones() -> None:
    assert toolchain.engines() == VECTORS["engines"]


def test_every_fixture_has_a_vector() -> None:
    on_disk = {p.name for p in FIXTURES.iterdir()}
    recorded = {str(entry["name"]) for entry in FILES}
    assert on_disk == recorded
