# The Python binding of the Rust pipeline: its root table, its argument checks and its decoder pin.

import hashlib
import json
import tomllib
from pathlib import Path

import pytest

from eous import _native

NATIVE = Path(__file__).resolve().parents[2] / "native"


def test_the_table_is_the_one_the_vectors_were_taken_from() -> None:
    raw = (NATIVE / "roots.json").read_bytes()
    assert len(set(json.loads(raw).values())) == 84
    assert hashlib.sha256(raw).hexdigest() == (
        "f441e11ea08a7ea9233dc9be0da8b34e6bfe7fb97341d6eb7764241bbe559092"
    )


@pytest.mark.parametrize(
    ("bitness", "target", "complaint"), [(8, "pe32", "bitness"), (32, "bogus", "target")]
)
def test_an_unsupported_bitness_or_target_is_a_value_error(
    bitness: int, target: str, complaint: str
) -> None:
    with pytest.raises(ValueError, match=complaint):
        _native.digest([b"\x90"], bitness, target)


def test_the_reported_decoder_is_the_one_compiled_in() -> None:
    manifest = tomllib.loads((NATIVE / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["dependencies"]["iced-x86"]["version"] == f"={_native.ICED_X86}"
