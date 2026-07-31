# Maps a raw Capstone mnemonic to a semantic root.
#
# data/categories.json should be included in /src/eous/data with it.
# Deriving it at import time from Capstone helpers would tie
# every digest to whichever Capstone version happens to be installed.

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache, lru_cache
from importlib import resources
from types import MappingProxyType

DATA_FILE = "categories.json"

# Prefixes the disassembler prints ahead of a mnemonic, separated by one space. Verified
# against Capstone: `notrack` appears in CET builds, and `xacquire` and `xrelease` appear
# on transactional forms such as `xacquire lock xor`.
# fmt: off
PREFIXES = frozenset({
    "lock", "rep", "repe", "repz", "repne", "repnz", "bnd",
    "notrack", "xacquire", "xrelease",
})
# fmt: on


class VocabError(Exception):
    pass


@dataclass(frozen=True)
class Vocab:
    arch: str
    members: Mapping[str, str]
    roots: frozenset[str]
    root_to_category: Mapping[str, str]

    def root_of(self, mnemonic: str) -> str | None:
        root = self.members.get(mnemonic)
        if root is not None:
            return root

        # Capstone prints more than one prefix on some forms, `xacquire lock xor` among
        # them, so leading prefix tokens come off one at a time. Each token is matched
        # exactly against PREFIXES, which keeps this an exact lookup at every step.
        remainder = mnemonic
        while True:
            prefix, separator, rest = remainder.partition(" ")
            if not separator or prefix not in PREFIXES:
                break
            remainder = rest

        if remainder == mnemonic:
            return None
        return self.members.get(remainder)


@cache
def load(arch: str) -> Vocab:
    payload = read_data_file()

    entry = payload.get(arch)
    if entry is None:
        known = ", ".join(sorted(payload))
        raise VocabError(f"unsupported architecture {arch!r}, expected one of: {known}")

    try:
        members = dict(entry["members"])
        root_to_category = dict(entry["root_to_category"])
    except (KeyError, TypeError) as exc:
        raise VocabError(f"malformed vocabulary entry for {arch!r}") from exc

    roots = frozenset(root_to_category)
    unknown = set(members.values()) - roots
    if unknown:
        raise VocabError(f"{len(unknown)} roots lack a category, first: {sorted(unknown)[0]!r}")

    return Vocab(
        arch=arch,
        members=MappingProxyType(members),
        roots=roots,
        root_to_category=MappingProxyType(root_to_category),
    )


@lru_cache(maxsize=1)
def read_data_file() -> dict[str, dict[str, dict[str, str]]]:
    source = resources.files("eous").joinpath("data").joinpath(DATA_FILE)
    try:
        text = source.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise VocabError(f"vocabulary data file {DATA_FILE} is missing") from exc
    except (OSError, ValueError, ModuleNotFoundError) as exc:
        # ValueError covers UnicodeDecodeError, so a byte-corrupt file reports as a
        # vocabulary problem with the rest.
        raise VocabError(f"vocabulary data file {DATA_FILE} is unreadable: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VocabError(f"vocabulary data file {DATA_FILE} is malformed") from exc

    if not isinstance(payload, dict):
        raise VocabError(f"vocabulary data file {DATA_FILE} holds {type(payload).__name__}")

    return payload
