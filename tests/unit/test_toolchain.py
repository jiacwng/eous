import re

import capstone
import lief

from eous import toolchain

RELEASE = re.compile(r"^\d+\.\d+\.\d+$")


def test_both_engines_are_reported() -> None:
    assert set(toolchain.engines()) == {"capstone", "lief"}


def test_every_version_is_a_release_number() -> None:
    assert all(RELEASE.match(value) for value in toolchain.engines().values())


def test_the_capstone_version_is_the_engine_not_the_wheel() -> None:
    assert toolchain.engines()["capstone"] == capstone.__version__


def test_the_lief_build_suffix_is_dropped() -> None:
    assert lief.__version__.startswith(toolchain.engines()["lief"])


def test_the_reading_repeats() -> None:
    assert toolchain.engines() == toolchain.engines()
