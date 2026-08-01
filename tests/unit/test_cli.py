import json
import struct
from pathlib import Path

import pytest

from eous import cli

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"
CLEAN = FIXTURES / "fixture-pe-x64.exe"


def run(*args: str) -> tuple[int, str, str]:
    return cli.main(list(args)), "", ""


@pytest.fixture
def output(capsys: pytest.CaptureFixture[str]) -> pytest.CaptureFixture[str]:
    return capsys


def test_hashing_a_clean_file_succeeds(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", str(CLEAN)]) == cli.OK
    captured = output.readouterr()
    assert captured.out.startswith("EO1:")
    assert captured.err == ""


def test_hashing_several_files_prints_one_line_each(
    output: pytest.CaptureFixture[str],
) -> None:
    names = ["fixture-pe-x64.exe", "fixture-elf-x64", "fixture-elf-x86"]
    assert cli.main(["hash", *[str(FIXTURES / n) for n in names]]) == cli.OK
    lines = output.readouterr().out.strip().splitlines()
    assert len(lines) == 3
    assert all("EO1:" in line for line in lines)


# Several files means several names, so each digest says which file it belongs to.
def test_several_files_are_labelled(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["hash", str(CLEAN), str(FIXTURES / "fixture-elf-x64")])
    out = output.readouterr().out
    assert "fixture-pe-x64.exe" in out
    assert "fixture-elf-x64" in out


def test_one_file_prints_the_digest_alone(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["hash", str(CLEAN)])
    assert output.readouterr().out.count(":") == 3


# ---- refusals ---------------------------------------------------------------


def test_a_refused_file_exits_one(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    assert cli.main(["hash", str(target)]) == cli.REFUSED


def test_a_refusal_names_its_gate_on_stderr(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    cli.main(["hash", str(target)])
    captured = output.readouterr()
    assert "unsupported_format" in captured.err
    assert "mach" in captured.err.lower()
    assert captured.out == ""


def test_one_refusal_among_many_still_exits_one(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"text" * 50)
    assert cli.main(["hash", str(CLEAN), str(target)]) == cli.REFUSED
    captured = output.readouterr()
    assert "EO1:" in captured.out
    assert "unreadable" in captured.err


def test_quiet_holds_back_the_refusal_text(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"text" * 50)
    assert cli.main(["hash", "--quiet", str(target)]) == cli.REFUSED
    assert output.readouterr().err == ""


# ---- json -------------------------------------------------------------------


def test_json_output_parses(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["hash", "--json", str(CLEAN)])
    payload = json.loads(output.readouterr().out)
    assert payload[0]["digest"].startswith("EO1:")
    assert payload[0]["path"].endswith("fixture-pe-x64.exe")


def test_json_carries_the_refusal(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"text" * 50)
    cli.main(["hash", "--json", str(target)])
    payload = json.loads(output.readouterr().out)
    assert payload[0]["digest"] is None
    assert payload[0]["gate"] == "unreadable"


def test_json_stays_on_stdout_alone(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"text" * 50)
    cli.main(["hash", "--json", str(target)])
    assert output.readouterr().err == ""


# ---- usage ------------------------------------------------------------------


def test_no_arguments_is_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == cli.USAGE


def test_an_unknown_command_is_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["frobnicate", str(CLEAN)]) == cli.USAGE


def test_hash_without_a_file_is_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash"]) == cli.USAGE


def test_version_prints_and_succeeds(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == cli.OK
    assert output.readouterr().out.strip()


# ---- help -------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_exits_zero_through_main(flag: str, output: pytest.CaptureFixture[str]) -> None:
    assert cli.main([flag]) == cli.OK
    assert "EO1:" in output.readouterr().out


def test_help_for_a_subcommand_exits_zero(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--help"]) == cli.OK


def test_a_bad_flag_is_still_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--nonsense", str(CLEAN)]) == cli.USAGE


def test_help_explains_the_digest_format(output: pytest.CaptureFixture[str]) -> None:
    text = cli.build_parser().format_help()
    assert "EO1:" in text
    assert "the format version" in text
    assert "the architecture" in text


def test_help_lists_every_exit_code(output: pytest.CaptureFixture[str]) -> None:
    text = cli.build_parser().format_help()
    for code in ["0", "1", "2", "3"]:
        assert f"  {code}  " in text


def test_help_shows_a_runnable_example(output: pytest.CaptureFixture[str]) -> None:
    text = cli.build_parser().format_help()
    assert "eous hash program.exe" in text


def test_help_states_the_supported_scope(output: pytest.CaptureFixture[str]) -> None:
    text = cli.build_parser().format_help()
    assert "PE and ELF" in text
    assert "x86-64" in text


def test_the_hash_command_has_its_own_help() -> None:
    text = cli.build_parser().format_help()
    assert "hash" in text


# ---- exit codes -------------------------------------------------------------


def test_the_exit_codes_are_distinct() -> None:
    assert len({cli.OK, cli.REFUSED, cli.USAGE, cli.INTERNAL}) == 4
    assert (cli.OK, cli.REFUSED, cli.USAGE, cli.INTERNAL) == (0, 1, 2, 3)


# An unexpected failure exits 3 and says so, which keeps a bug distinguishable from a
# refusal the tool made deliberately.
def test_an_unexpected_failure_exits_three(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    def explode(path: Path) -> object:
        raise RuntimeError("something gave way")

    monkeypatch.setattr(cli.report, "analyse", explode)
    assert cli.main(["hash", str(CLEAN)]) == cli.INTERNAL
    assert "something gave way" in output.readouterr().err
