from __future__ import annotations

from importlib.metadata import version

import capstone


def engines() -> dict[str, str]:
    # capstone's wheel version and its decoder version differ, and the decoder shapes the digest.
    return {"capstone": str(capstone.__version__), "lief": version("lief")}
