import hashlib
import json
import tomllib
from pathlib import Path

import pytest

from eous import _native

NATIVE = Path(__file__).resolve().parents[2] / "native"


# Every entry shapes digests, so the table is pinned the way the golden vectors are.
def test_the_table_is_the_one_the_vectors_were_taken_from() -> None:
    raw = (NATIVE / "roots.json").read_bytes()
    table = json.loads(raw)
    assert len(table) == 1888
    assert len(set(table.values())) == 84
    assert hashlib.sha256(raw).hexdigest() == (
        "f441e11ea08a7ea9233dc9be0da8b34e6bfe7fb97341d6eb7764241bbe559092"
    )


def test_an_unsupported_bitness_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="bitness"):
        _native.digest([b"\x90"], 8, "pe32")


def test_an_unsupported_target_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="target"):
        _native.digest([b"\x90"], 32, "bogus")


def test_the_reported_decoder_is_the_one_compiled_in() -> None:
    manifest = tomllib.loads((NATIVE / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["dependencies"]["iced-x86"]["version"] == f"={_native.ICED_X86}"
