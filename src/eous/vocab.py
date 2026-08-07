# Maps a mnemonic to a semantic root.
#
# The table ships as a data file, so a digest never depends on the installed decoder version.

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib import resources
from types import MappingProxyType

DATA_FILE = "categories.json"


@dataclass(frozen=True)
class Vocab:
    members: Mapping[str, str]
    root_to_category: Mapping[str, str]

    def root_of(self, mnemonic: str) -> str | None:
        return self.members.get(mnemonic)


@cache
def load(arch: str) -> Vocab:
    entry = read_data_file()[arch]
    return Vocab(
        members=MappingProxyType(dict(entry["members"])),
        root_to_category=MappingProxyType(dict(entry["root_to_category"])),
    )


@lru_cache(maxsize=1)
def read_data_file() -> dict[str, dict[str, dict[str, str]]]:
    source = resources.files("eous").joinpath("data").joinpath(DATA_FILE)
    payload: dict[str, dict[str, dict[str, str]]] = json.loads(source.read_text(encoding="utf-8"))
    return payload
