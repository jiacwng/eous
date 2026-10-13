#!/usr/bin/env python3
#
# Regenerates vectors.json. Run this only when a change to the digest is intended, and
# review the diff before committing: every altered line means every stored digest in the
# world has changed.
#
#     python tests/golden/generate.py

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import reference  # noqa: E402
from eous import _native, digest, loader, toolchain  # noqa: E402

FIXTURES = HERE.parent / "fixtures" / "bin"
VECTORS = HERE / "vectors.json"

# A hand-written case, so a rebuilt fixture and an altered algorithm fail differently.
SYNTHETIC_RUNS = (
    ("push", "mov", "sub", "mov", "xor", "call", "add", "pop", "ret"),
    ("mov", "test", "je", "lea", "mov", "call", "mov", "ret"),
    ("xor", "inc", "cmp", "jne", "mov", "shl", "or", "and", "not", "ret"),
)
SYNTHETIC_TARGET = "pe64"


def build() -> dict[str, object]:
    files = []
    for path in sorted(FIXTURES.iterdir()):
        raw = path.read_bytes()
        binary = loader.load(path)
        found = reference.disassemble(binary.sections, binary.arch)
        sections = [section.data for section in binary.sections]
        files.append(
            {
                "name": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "target": binary.target,
                "decoded": found.total_decoded,
                "runs": sum(len(run) >= reference.NGRAM for run in found.runs),
                "digest": _native.digest(sections, loader.BITS[binary.arch], binary.target),
            }
        )

    return {
        "version": digest.VERSION,
        "ngram": reference.NGRAM,
        "permutations": digest.PERMUTATIONS,
        "slot_bits": digest.SLOT_BITS,
        "engines": toolchain.engines(),
        "files": files,
        "synthetic": {
            "target": SYNTHETIC_TARGET,
            "runs": [list(run) for run in SYNTHETIC_RUNS],
            "digest": reference.digest(SYNTHETIC_RUNS, SYNTHETIC_TARGET),
        },
    }


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {VECTORS}")
