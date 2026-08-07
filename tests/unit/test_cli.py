import errno
import io
import json
import struct
import sys
from pathlib import Path

import pytest

from eous import cli, report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"
CLEAN = FIXTURES / "fixture-pe-x64.exe"


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


# ---- directories ------------------------------------------------------------


def plant(root: Path, *names: str) -> None:
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(CLEAN.read_bytes())


def test_a_directory_digests_every_file_under_it(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "a.exe", "b.exe")
    assert cli.main(["hash", str(tmp_path)]) == cli.OK
    assert len(output.readouterr().out.strip().splitlines()) == 2


def test_a_directory_is_walked_to_the_bottom(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "top.exe", "one/middle.exe", "one/two/deep.exe")
    assert cli.main(["hash", str(tmp_path)]) == cli.OK
    assert len(output.readouterr().out.strip().splitlines()) == 3


# Two runs over one folder must agree, so the walk is sorted before it is digested.
def test_a_directory_is_walked_in_a_settled_order(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "c.exe", "a.exe", "b.exe")
    cli.main(["hash", str(tmp_path)])
    first = output.readouterr().out
    cli.main(["hash", str(tmp_path)])
    assert output.readouterr().out == first
    assert [line.split("  ")[0] for line in first.strip().splitlines()] == [
        str(tmp_path / name) for name in ("a.exe", "b.exe", "c.exe")
    ]


# The caller named the folder, so every line says which file it found.
def test_a_walked_file_carries_its_path(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    plant(tmp_path, "v1/prog.exe", "v2/prog.exe")
    cli.main(["hash", str(tmp_path)])
    lines = output.readouterr().out.strip().splitlines()
    assert lines[0].startswith(f"{tmp_path / 'v1' / 'prog.exe'}  ")
    assert lines[1].startswith(f"{tmp_path / 'v2' / 'prog.exe'}  ")


def test_one_file_in_a_directory_is_still_labelled(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "only.exe")
    cli.main(["hash", str(tmp_path)])
    assert output.readouterr().out.startswith(str(tmp_path / "only.exe"))


def test_an_empty_directory_digests_nothing(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["hash", str(tmp_path)]) == cli.OK
    captured = output.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_a_directory_and_a_named_file_run_together(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "inside.exe")
    assert cli.main(["hash", str(tmp_path), str(CLEAN)]) == cli.OK
    assert len(output.readouterr().out.strip().splitlines()) == 2


def test_a_refusal_inside_a_directory_exits_one(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "good.exe")
    (tmp_path / "junk.bin").write_bytes(b"text" * 50)
    assert cli.main(["hash", str(tmp_path)]) == cli.REFUSED
    captured = output.readouterr()
    assert "EO1:" in captured.out
    assert str(tmp_path / "junk.bin") in captured.err


def test_one_file_named_twice_is_digested_once(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "one.exe")
    target = str(tmp_path / "one.exe")
    assert cli.main(["hash", target, target]) == cli.OK
    assert len(output.readouterr().out.strip().splitlines()) == 1


# A junction pointing at its own parent hands the walk the same file at every level.
def test_a_directory_reached_twice_is_digested_once(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "sub/one.exe")
    assert cli.main(["hash", str(tmp_path), str(tmp_path / "sub")]) == cli.OK
    assert len(output.readouterr().out.strip().splitlines()) == 1


def test_a_directory_carries_its_paths_into_json(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "one.exe", "sub/two.exe")
    cli.main(["hash", "--json", str(tmp_path)])
    payload = json.loads(output.readouterr().out)
    assert [row["path"] for row in payload["results"]] == [
        str(tmp_path / "one.exe"),
        str(tmp_path / "sub" / "two.exe"),
    ]


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


# ---- a closed reader ---------------------------------------------------------


class ClosedPipe(io.StringIO):
    def __init__(self, code: int) -> None:
        super().__init__()
        self.code = code

    def write(self, text: str) -> int:
        raise OSError(self.code, "the reader is gone")


# `eous hash samples/ | head` closes the pipe mid-run, and neither platform's error for
# that is an internal fault.
@pytest.mark.parametrize("code", cli.CLOSED_PIPE)
def test_a_closed_reader_ends_the_run_quietly(
    code: int, monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(code))
    assert cli.main(["hash", str(CLEAN)]) == cli.OK
    assert output.readouterr().err == ""


def test_a_closed_reader_ends_a_comparison_quietly(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EPIPE))
    assert cli.main(["compare", str(CLEAN), str(CLEAN)]) == cli.OK


def test_an_unrelated_os_error_is_still_internal(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EACCES))
    assert cli.main(["hash", str(CLEAN)]) == cli.INTERNAL
    assert "internal error" in output.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="EINVAL is the closed-pipe error here")
def test_einval_stays_internal_away_from_windows(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EINVAL))
    assert cli.main(["hash", str(CLEAN)]) == cli.INTERNAL


def test_quietening_stdout_swallows_what_follows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.txt"
    with target.open("w") as handle:
        monkeypatch.setattr(sys, "stdout", handle)
        cli._quieten_stdout()
        handle.write("this reaches the null device")
    assert target.read_text() == ""


def test_the_help_names_the_closed_reader(output: pytest.CaptureFixture[str]) -> None:
    assert "closed the output" in cli.build_parser().format_help()


# ---- json -------------------------------------------------------------------


def test_json_output_parses(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["hash", "--json", str(CLEAN)])
    payload = json.loads(output.readouterr().out)
    assert payload["results"][0]["digest"].startswith("EO1:")
    assert payload["results"][0]["path"].endswith("fixture-pe-x64.exe")


def test_json_carries_the_refusal(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(b"text" * 50)
    cli.main(["hash", "--json", str(target)])
    payload = json.loads(output.readouterr().out)
    assert payload["results"][0]["digest"] is None
    assert payload["results"][0]["gate"] == "unreadable"


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
    assert "eous hash samples/" in text


def test_help_states_the_supported_scope(output: pytest.CaptureFixture[str]) -> None:
    text = cli.build_parser().format_help()
    assert "PE and ELF" in text
    assert "x86-64" in text


def test_the_hash_command_has_its_own_help() -> None:
    text = cli.build_parser().format_help()
    assert "hash" in text


# ---- compare ----------------------------------------------------------------

ELF64 = FIXTURES / "fixture-elf-x64"


def test_a_file_compared_with_itself_scores_full(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(CLEAN), str(CLEAN)]) == cli.OK
    assert "100.0%" in output.readouterr().out


def test_comparison_prints_the_margin_of_error_and_its_range(
    output: pytest.CaptureFixture[str],
) -> None:
    cli.main(["compare", str(CLEAN), str(CLEAN)])
    out = output.readouterr().out
    assert "similarity:" in out
    assert "+/-" in out
    assert "to" in out
    assert "containment:" in out


@pytest.mark.parametrize(
    "args",
    [
        ["compare", str(CLEAN), str(CLEAN)],
        ["compare", str(CLEAN), str(ELF64)],
        ["hash", str(CLEAN)],
        ["--help"],
        ["compare", "--help"],
    ],
    ids=["compare_same", "compare_withheld", "hash", "help", "compare_help"],
)
def test_every_line_of_output_is_ascii(args: list[str], output: pytest.CaptureFixture[str]) -> None:
    cli.main(args)
    captured = output.readouterr()
    assert (captured.out + captured.err).isascii()


def test_two_digest_strings_compare(output: pytest.CaptureFixture[str]) -> None:
    first = report.analyse(CLEAN).digest
    second = report.analyse(ELF64).digest
    assert cli.main(["compare", first, second]) == cli.OK
    assert "similarity:" in output.readouterr().out


def test_a_file_compares_against_a_digest(output: pytest.CaptureFixture[str]) -> None:
    text = report.analyse(ELF64).digest
    assert cli.main(["compare", str(CLEAN), text]) == cli.OK


# The filesystem answers first, so a mistyped path reports as absent rather than being
# read as a malformed digest.
def test_a_mistyped_path_reports_as_a_digest_problem(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", "no/such/file.exe", str(CLEAN)]) == cli.USAGE
    assert output.readouterr().err


def test_a_refused_file_stops_the_comparison(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(struct.pack("<I", 0xFEEDFACF) + bytes(4096))
    assert cli.main(["compare", str(target), str(CLEAN)]) == cli.REFUSED
    captured = output.readouterr()
    assert "unsupported_format" in captured.err
    assert captured.out == ""


def test_differing_architectures_are_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    x64 = report.analyse(CLEAN).digest
    x86 = report.analyse(FIXTURES / "fixture-pe-x86.exe").digest
    assert cli.main(["compare", x64, x86]) == cli.USAGE
    assert "architectures differ" in output.readouterr().err


def test_a_malformed_digest_is_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", "EO1:x86:notanumber:ab", str(CLEAN)]) == cli.USAGE


def test_compare_needs_two_inputs(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(CLEAN)]) == cli.USAGE
    assert cli.main(["compare"]) == cli.USAGE


def test_compare_json_carries_the_range(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["compare", "--json", str(CLEAN), str(CLEAN)])
    payload = json.loads(output.readouterr().out)
    scores = payload["comparison"]
    assert scores["similarity"] == pytest.approx(100.0)
    assert scores["low"] <= scores["similarity"] <= scores["high"]
    assert scores["left_in_right"] == pytest.approx(100.0)
    assert scores["right_in_left"] == pytest.approx(100.0)
    assert scores["left"].endswith("fixture-pe-x64.exe")


def test_withheld_containment_says_why(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["compare", str(CLEAN), str(ELF64)])
    assert "n/a" in output.readouterr().out


# Both directions print, each naming its own, so no convention has to be remembered.
def test_containment_names_both_directions(output: pytest.CaptureFixture[str]) -> None:
    cli.main(["compare", str(CLEAN), str(CLEAN)])
    lines = [line for line in output.readouterr().out.splitlines() if "in" in line]
    assert len(lines) == 2
    assert all("fixture-pe-x64.exe" in line for line in lines)


def test_files_sharing_a_basename_stay_distinguishable(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    left, right = tmp_path / "v1" / "prog.exe", tmp_path / "v2" / "prog.exe"
    for target in (left, right):
        target.parent.mkdir()
        target.write_bytes(CLEAN.read_bytes())

    cli.main(["compare", str(left), str(right)])
    lines = [line for line in output.readouterr().out.splitlines() if " in " in line]
    assert len(lines) == 2
    assert str(left) in lines[0]
    assert str(right) in lines[0]


def test_json_labels_distinguish_files_sharing_a_basename(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    left, right = tmp_path / "v1" / "prog.exe", tmp_path / "v2" / "prog.exe"
    for target in (left, right):
        target.parent.mkdir()
        target.write_bytes(CLEAN.read_bytes())

    cli.main(["compare", "--json", str(left), str(right)])
    payload = json.loads(output.readouterr().out)
    scores = payload["comparison"]
    assert scores["left"] == str(left)
    assert scores["right"] == str(right)
    assert scores["left"] != scores["right"]


def test_digest_inputs_are_labelled_left_and_right(output: pytest.CaptureFixture[str]) -> None:
    text = report.analyse(CLEAN).digest
    cli.main(["compare", text, text])
    lines = output.readouterr().out.splitlines()
    directions = [" ".join(line.split()) for line in lines if " in " in line]
    assert any(d.startswith("containment: left in right 100.0%") for d in directions)
    assert any(d.startswith("right in left 100.0%") for d in directions)


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


# ---- output cannot be forged by the sample ---------------------------------


# A section name is attacker-controlled. A newline in one would forge a second refusal line
# for a file that was never scanned, and an escape sequence would erase the real one.
def test_a_section_name_cannot_forge_a_refusal_line(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    hostile = ".text\x1b[2K\reous: /bin/ls: unreadable: no recognised container\neous: trusted"
    monkeypatch.setattr(
        cli.report,
        "analyse",
        lambda path: report.Analysis(
            path=Path(path),
            digest=None,
            refusal=report.Refusal(report.PACKED, f"executable section {hostile} is writable"),
        ),
    )
    assert cli.main(["hash", str(CLEAN)]) == cli.REFUSED

    printed = output.readouterr().err
    assert len(printed.splitlines()) == 1
    assert "\x1b" not in printed
    assert "\r" not in printed
    assert r"\x1b" in printed
    assert r"\x0a" in printed


def test_a_file_name_cannot_forge_a_digest_line(
    monkeypatch: pytest.MonkeyPatch, output: pytest.CaptureFixture[str]
) -> None:
    hostile = Path("a\nEO1:x86-64:9999:" + "f" * 128)
    digested = [
        report.Analysis(path=hostile, digest="EO1:x86:1:" + "0" * 128, refusal=None),
        report.Analysis(path=Path(CLEAN), digest="EO1:x86:2:" + "0" * 128, refusal=None),
    ]
    monkeypatch.setattr(cli, "_expand", lambda paths: [hostile, Path(CLEAN)])
    monkeypatch.setattr(cli, "_analyse", lambda paths: iter(digested))
    assert cli.main(["hash", str(CLEAN), str(CLEAN)]) == cli.OK

    lines = [line for line in output.readouterr().out.splitlines() if line]
    assert len(lines) == 2, "the newline in the name opened a third record"
    assert r"\x0a" in lines[0]
