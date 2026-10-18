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
from pathlib import Path

from eous import _native, loader, toolchain

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures" / "bin"
VECTORS = HERE / "vectors.json"

# A hand-written x86-64 case, so a rebuilt fixture and an altered algorithm fail differently.
SYNTHETIC_CODE = (
    "55 4889e5 4883ec20 48897df8 31c0 4801d8 5d c3 "
    "4889f8 4885c0 488d4808 4889ca 48ffc2 4839c2 48d1e0 4809c8 4821d0 48f7d0 c3"
).replace(" ", "")
SYNTHETIC_TARGET = "pe64"
SYNTHETIC_BITNESS = 64


def build() -> dict[str, object]:
    files = []
    for path in sorted(FIXTURES.iterdir()):
        binary = loader.load(path)
        sections = [section.data for section in binary.sections]
        files.append(
            {
                "name": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "target": binary.target,
                "digest": _native.digest(sections, loader.BITS[binary.arch], binary.target),
            }
        )

    code = bytes.fromhex(SYNTHETIC_CODE)
    return {
        "version": _native.VERSION,
        "ngram": _native.NGRAM,
        "permutations": _native.PERMUTATIONS,
        "slot_bits": _native.SLOT_BITS,
        "engines": toolchain.engines(),
        "files": files,
        "synthetic": {
            "target": SYNTHETIC_TARGET,
            "bitness": SYNTHETIC_BITNESS,
            "code": SYNTHETIC_CODE,
            "digest": _native.digest([code], SYNTHETIC_BITNESS, SYNTHETIC_TARGET),
        },
    }


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {VECTORS}")
