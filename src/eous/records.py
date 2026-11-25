# Reads the files the commands take: a digest list, a labels file and a names file.

from __future__ import annotations

import codecs
import io
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from eous import digest

SHA256_PATTERN = re.compile("[0-9a-f]{64}")

ADDRESS_SPACE = 1 << 64


class RecordsError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    sha256: str
    path: str
    eous: str
    sketch: digest.Sketch
    functions: object


@dataclass(frozen=True)
class Function:
    address: int
    length: int
    sketch: digest.Sketch


@dataclass(frozen=True)
class Digests:
    entries: list[Entry]
    unparsed: int
    repeated: int


def open_text(path: Path) -> TextIO:
    # Windows tools put a byte-order mark in front of UTF-8 text, and the `>` of
    # Windows PowerShell 5.1 writes UTF-16.
    handle = path.open("rb")
    mark = handle.peek(2)[:2]
    encoding = "utf-16" if mark in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else "utf-8-sig"
    return io.TextIOWrapper(handle, encoding=encoding, errors="replace")


# One record per line, as `eous hash --json` writes them. A record of a file that got no
# digest is passed over, and a sha256 already read is counted and dropped.
def digests(path: Path, functions: bool = False) -> Digests:
    entries: list[Entry] = []
    seen: set[str] = set()
    unparsed = 0
    repeated = 0

    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (ValueError, RecursionError):
                record = None
            if not isinstance(record, dict):
                unparsed += 1
                continue
            if record.get("reason") is not None:
                continue
            entry = _as_entry(record, functions)
            if entry is None:
                unparsed += 1
            elif entry.sha256 in seen:
                repeated += 1
            else:
                seen.add(entry.sha256)
                entries.append(entry)

    versions = sorted({entry.eous for entry in entries})
    if len(versions) > 1:
        raise RecordsError(f"holds digests of several eous versions: {', '.join(versions)}")
    return Digests(entries, unparsed, repeated)


def _as_entry(record: dict[str, object], functions: bool) -> Entry | None:
    sha256 = record.get("sha256")
    path = record.get("path")
    written = record.get("eous")
    text = record.get("digest")
    if not (isinstance(sha256, str) and isinstance(path, str)):
        return None
    if not (isinstance(written, str) and isinstance(text, str)):
        return None
    if not SHA256_PATTERN.fullmatch(sha256):
        return None
    try:
        held = record.get("functions") if functions else None
        return Entry(sha256, path, written, digest.parse(text), held)
    except digest.DigestError:
        return None


def functions_of(entry: Entry, target: str) -> tuple[list[Function], int]:
    found: list[Function] = []
    unparsed = 0
    for item in entry.functions if isinstance(entry.functions, list) else []:
        try:
            address, length, text = item
            sketch = digest.parse(text)
        except (TypeError, ValueError, AttributeError, digest.DigestError):
            unparsed += 1
            continue
        whole = type(address) is int and type(length) is int
        bounded = whole and 0 <= address < ADDRESS_SPACE and 0 < length < ADDRESS_SPACE
        if bounded and sketch.target == target:
            found.append(Function(address, length, sketch))
        else:
            unparsed += 1
    return found, unparsed


def labels(path: Path) -> tuple[dict[str, str], int]:
    read: dict[str, str] = {}
    unparsed = 0

    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            sha256, _, label = line.partition("\t")
            sha256, label = sha256.strip().lower(), label.strip()
            if not SHA256_PATTERN.fullmatch(sha256) or label in ("", "-"):
                unparsed += 1
            elif read.get(sha256, label) != label:
                raise RecordsError(f"{sha256} carries two labels")
            else:
                read[sha256] = label
    return read, unparsed


def names(path: Path) -> tuple[dict[tuple[str, int], str], int]:
    read: dict[tuple[str, int], str] = {}
    unparsed = 0

    with open_text(path) as handle:
        for line in handle:
            if not line.strip():
                continue
            sha256, _, rest = line.partition("\t")
            place, _, name = rest.partition("\t")
            sha256, name = sha256.strip().lower(), name.strip()
            try:
                key = (sha256, int(place, 16))
            except ValueError:
                unparsed += 1
                continue
            if not SHA256_PATTERN.fullmatch(sha256) or key[1] < 0 or not name:
                unparsed += 1
            elif read.get(key, name) != name:
                raise RecordsError(f"{sha256} {key[1]:#x} carries two names")
            else:
                read[key] = name
    return read, unparsed
