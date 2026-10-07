# Maps a mnemonic to a semantic root.
#
# The table holds the names iced-x86 emits, so a decoder release that adds one is a digest
# change and goes through the golden vectors.

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache
from importlib import resources
from types import MappingProxyType

DATA_FILE = "roots.json"


@cache
def load() -> Mapping[str, str]:
    source = resources.files("eous").joinpath("data").joinpath(DATA_FILE)
    table: dict[str, str] = json.loads(source.read_text(encoding="utf-8"))
    return MappingProxyType(table)
