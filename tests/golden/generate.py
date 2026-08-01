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

from eous import digest, disasm, loader

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures" / "bin"
VECTORS = HERE / "vectors.json"

# A hand-written case, so a rebuilt fixture and an altered algorithm fail differently.
SYNTHETIC_CHUNKS = (
    ("push", "mov", "sub", "mov", "xor", "call", "add", "pop", "ret"),
    ("mov", "test", "je", "lea", "mov", "call", "mov", "ret"),
    ("xor", "inc", "cmp", "jne", "mov", "shl", "or", "and", "not", "ret"),
)
SYNTHETIC_ARCH = "x86-64"


def build() -> dict[str, object]:
    files = []
    for path in sorted(FIXTURES.iterdir()):
        raw = path.read_bytes()
        binary = loader.load(path)
        sweep = disasm.sweep(binary)
        files.append(
            {
                "name": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "arch": binary.arch,
                "decoded": sweep.total_decoded,
                "chunks": len(sweep.chunks),
                "digest": digest.digest(sweep.chunks, binary.arch),
            }
        )

    return {
        "version": digest.VERSION,
        "ngram": digest.NGRAM,
        "permutations": digest.PERMUTATIONS,
        "slot_bits": digest.SLOT_BITS,
        "files": files,
        "synthetic": {
            "arch": SYNTHETIC_ARCH,
            "chunks": [list(chunk) for chunk in SYNTHETIC_CHUNKS],
            "digest": digest.digest(SYNTHETIC_CHUNKS, SYNTHETIC_ARCH),
        },
    }


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(build(), indent=1) + "\n", encoding="utf-8")
    print(f"wrote {VECTORS}")
