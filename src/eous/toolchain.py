# The versions of the decoder and the parser a digest depends on.

from __future__ import annotations

from importlib.metadata import version

from eous import _native


def engines() -> dict[str, str]:
    # The decoder shapes the digest, so its version is reported too.
    return {"iced-x86": _native.ICED_X86, "lief": version("lief")}
