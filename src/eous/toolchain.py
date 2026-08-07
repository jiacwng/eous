from __future__ import annotations

from importlib.metadata import version


def engines() -> dict[str, str]:
    # The decoder shapes the digest, so its version is reported too.
    return {"iced-x86": version("iced-x86"), "lief": version("lief")}
