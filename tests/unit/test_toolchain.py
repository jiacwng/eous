from importlib.metadata import version

from eous import toolchain


def test_the_decoder_version_is_the_installed_one() -> None:
    assert toolchain.engines()["iced-x86"] == version("iced-x86")
