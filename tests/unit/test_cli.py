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
PE32 = FIXTURES / "fixture-pe-x86.exe"
ELF64 = FIXTURES / "fixture-elf-x64"


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
    assert "the target" in text


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
        ["match", str(CLEAN), "--help"],
        ["hash", str(CLEAN)],
        ["--help"],
        ["compare", "--help"],
    ],
    ids=["compare_same", "match_help", "hash", "help", "compare_help"],
)
def test_every_line_of_output_is_ascii(args: list[str], output: pytest.CaptureFixture[str]) -> None:
    cli.main(args)
    captured = output.readouterr()
    assert (captured.out + captured.err).isascii()


def test_two_digest_strings_compare(output: pytest.CaptureFixture[str]) -> None:
    first = report.analyse(CLEAN).digest
    assert first is not None
    second = first[:-1] + ("0" if first[-1] != "0" else "1")
    assert cli.main(["compare", first, second]) == cli.OK
    assert "similarity:" in output.readouterr().out


def test_a_file_compares_against_a_digest(output: pytest.CaptureFixture[str]) -> None:
    text = report.analyse(CLEAN).digest
    assert text is not None
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


def test_differing_targets_are_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    wide = report.analyse(CLEAN).digest
    narrow = report.analyse(FIXTURES / "fixture-pe-x86.exe").digest
    assert cli.main(["compare", wide, narrow]) == cli.USAGE
    assert "different targets" in output.readouterr().err


def test_a_windows_binary_refuses_against_a_linux_one(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(CLEAN), str(ELF64)]) == cli.USAGE
    assert "different targets" in output.readouterr().err


def test_a_malformed_digest_is_a_usage_error(output: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", "EO1:pe64:notanumber:ab", str(CLEAN)]) == cli.USAGE


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
    body = "0" * 128
    cli.main(["compare", f"EO1:pe64:10:{body}", f"EO1:pe64:1000:{body}"])
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


# ---- match ------------------------------------------------------------------


def known_file(tmp_path: Path, *paths: Path, labelled: bool = True) -> Path:
    target = tmp_path / "known.txt"
    lines = []
    for path in paths:
        text = report.analyse(path).digest
        lines.append(f"{path}  {text}" if labelled else str(text))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def test_match_ranks_the_closest_first(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    # Two comparable entries, so the order is something this test can be wrong about.
    text = report.analyse(CLEAN).digest
    assert text is not None
    weaker = text[:-32] + "0" * 32

    known = known_file(tmp_path, CLEAN, ELF64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker}\n")

    assert cli.main(["match", str(CLEAN), str(known)]) == cli.OK
    lines = [line for line in output.readouterr().out.splitlines() if line]
    assert len(lines) == 2
    assert lines[0].startswith("100.0%")
    assert str(CLEAN) in lines[0]
    assert "weaker" in lines[1]


def test_match_reads_the_bare_digest_form_hash_writes(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, labelled=False)
    assert cli.main(["match", str(CLEAN), str(known)]) == cli.OK
    assert output.readouterr().out.splitlines()[0].startswith("100.0%")


# A corpus file holds every target, and only one of them can be compared against.
def test_match_skips_entries_built_for_another_target(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, PE32, ELF64)
    assert cli.main(["match", str(CLEAN), str(known)]) == cli.OK
    captured = output.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "2 built for another target" in captured.err


def test_match_is_a_usage_error_when_nothing_shares_the_target(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE32, ELF64)
    assert cli.main(["match", str(CLEAN), str(known)]) == cli.USAGE
    captured = output.readouterr()
    assert captured.out == ""
    assert "holds no pe64 digest" in captured.err


def test_match_limits_the_list(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN, CLEAN)
    assert cli.main(["match", str(CLEAN), str(known), "--top", "2"]) == cli.OK
    assert len([line for line in output.readouterr().out.splitlines() if line]) == 2


def test_match_skips_a_line_that_is_not_a_digest(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN)
    known.write_text(known.read_text(encoding="utf-8") + "notes.txt  not-a-digest\n\n", "utf-8")
    assert cli.main(["match", str(CLEAN), str(known)]) == cli.OK
    captured = output.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "1 lines held no digest" in captured.err


def test_match_takes_a_digest_string_as_the_query(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    text = report.analyse(CLEAN).digest
    known = known_file(tmp_path, CLEAN)
    assert cli.main(["match", str(text), str(known)]) == cli.OK
    assert output.readouterr().out.splitlines()[0].startswith("100.0%")


def test_match_refuses_a_query_it_cannot_digest(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"plain text, forever" * 20)
    known = known_file(tmp_path, CLEAN)
    assert cli.main(["match", str(junk), str(known)]) == cli.REFUSED
    assert "unreadable" in output.readouterr().err


def test_match_refuses_a_digests_file_it_cannot_read(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    absent = tmp_path / "absent.txt"
    assert cli.main(["match", str(CLEAN), str(absent)]) == cli.REFUSED
    printed = output.readouterr().err
    assert str(absent) in printed
    assert "No such file" in printed


def test_match_json_carries_the_target_and_the_ranking(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, ELF64)
    assert cli.main(["match", str(CLEAN), str(known), "--json"]) == cli.OK
    payload = json.loads(output.readouterr().out)
    assert payload["target"] == "pe64"
    assert payload["other_target"] == 1
    assert payload["matches"][0]["uncertainty"] == pytest.approx(0.0)
    assert payload["matches"][0]["similarity"] == pytest.approx(100.0)


def test_match_escapes_a_hostile_label(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    text = report.analyse(CLEAN).digest
    known = tmp_path / "known.txt"
    known.write_text(f"a\x1b[2Kb  {text}\n", encoding="utf-8")
    assert cli.main(["match", str(CLEAN), str(known)]) == cli.OK
    printed = output.readouterr().out
    assert "\x1b" not in printed
    assert r"\x1b" in printed


def test_a_negative_top_is_a_usage_error(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN)
    assert cli.main(["match", str(CLEAN), str(known), "--top", "-1"]) == cli.USAGE
    assert "--top" in output.readouterr().err


def test_match_holds_back_anything_below_the_minimum(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    text = report.analyse(CLEAN).digest
    assert text is not None
    weaker = text[:-32] + "0" * 32

    known = known_file(tmp_path, CLEAN)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker}\n")

    assert cli.main(["match", str(CLEAN), str(known), "--min", "99"]) == cli.OK
    captured = output.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert len(lines) == 1
    assert lines[0].startswith("100.0%")
    assert "1 scored below 99%" in captured.err


def test_a_minimum_above_one_hundred_is_a_usage_error(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN)
    assert cli.main(["match", str(CLEAN), str(known), "--min", "100.1"]) == cli.USAGE
    assert "--min" in output.readouterr().err


def test_a_minimum_nothing_clears_prints_no_ranking(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, ELF64)
    query = report.analyse(ELF64).digest
    assert query is not None
    weaker = query[:-32] + "0" * 32
    known.write_text(f"weaker  {weaker}\n", encoding="utf-8")

    assert cli.main(["match", str(ELF64), str(known), "--min", "99"]) == cli.OK
    captured = output.readouterr()
    assert captured.out.strip() == ""
    assert "1 scored below 99%" in captured.err


def test_the_minimum_keeps_an_exact_score(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN)
    assert cli.main(["match", str(CLEAN), str(known), "--min", "100"]) == cli.OK
    assert len([line for line in output.readouterr().out.splitlines() if line]) == 1


def test_a_negative_minimum_is_a_usage_error(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN)
    assert cli.main(["match", str(CLEAN), str(known), "--min", "-1"]) == cli.USAGE
    assert "--min" in output.readouterr().err


def test_match_json_counts_what_the_minimum_held_back(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    text = report.analyse(CLEAN).digest
    assert text is not None
    known = known_file(tmp_path, CLEAN)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {text[:-32] + '0' * 32}\n")

    assert cli.main(["match", str(CLEAN), str(known), "--min", "99", "--json"]) == cli.OK
    payload = json.loads(output.readouterr().out)
    assert payload["below_minimum"] == 1
    assert len(payload["matches"]) == 1


def test_the_minimum_applies_before_top(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    # --top 2 on three entries where one falls below, so the count separates the two orders.
    text = report.analyse(CLEAN).digest
    assert text is not None
    known = known_file(tmp_path, CLEAN, CLEAN)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {text[:-32] + '0' * 32}\n")

    assert cli.main(["match", str(CLEAN), str(known), "--top", "3", "--min", "99"]) == cli.OK
    assert len([line for line in output.readouterr().out.splitlines() if line]) == 2


# ---- cross ------------------------------------------------------------------


def test_cross_scores_every_pair_once(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    # Four digests give 4 x 3 / 2 = 6 pairs, and a pair counted twice would print 12.
    known = known_file(tmp_path, CLEAN, CLEAN, CLEAN, CLEAN)
    assert cli.main(["cross", str(known)]) == cli.OK
    captured = output.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 6
    assert "6 pairs scored across pe64" in captured.err


def test_cross_names_both_sides_of_a_pair(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, ELF64)
    known.write_text(
        f"left  {report.analyse(CLEAN).digest}\nright  {report.analyse(CLEAN).digest}\n",
        encoding="utf-8",
    )
    assert cli.main(["cross", str(known)]) == cli.OK
    line = output.readouterr().out.splitlines()[0]
    assert line.startswith("100.0%")
    assert line.endswith("left  right")


# A corpus file holds every target, and a pair only forms inside one of them.
def test_cross_pairs_inside_each_target(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN, ELF64, ELF64)
    assert cli.main(["cross", str(known)]) == cli.OK
    captured = output.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 2
    assert "2 pairs scored across elf64, pe64" in captured.err


def test_cross_holds_back_anything_below_the_minimum(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    text = report.analyse(CLEAN).digest
    assert text is not None
    known = tmp_path / "known.txt"
    known.write_text(f"a  {text}\nb  {text}\nc  {text[:-32] + '0' * 32}\n", encoding="utf-8")

    assert cli.main(["cross", str(known), "--min", "99"]) == cli.OK
    captured = output.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "2 scored below 99%" in captured.err


def test_cross_is_a_usage_error_when_no_target_holds_two(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, ELF64, PE32)
    assert cli.main(["cross", str(known)]) == cli.USAGE
    captured = output.readouterr()
    assert captured.out == ""
    assert "holds no two digests of one target" in captured.err


def test_cross_counts_a_line_that_is_not_a_digest(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN)
    known.write_text(known.read_text(encoding="utf-8") + "notes.txt  not-a-digest\n", "utf-8")
    assert cli.main(["cross", str(known)]) == cli.OK
    assert "1 lines held no digest" in output.readouterr().err


def test_cross_refuses_a_digests_file_it_cannot_read(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    absent = tmp_path / "absent.txt"
    assert cli.main(["cross", str(absent)]) == cli.REFUSED
    printed = output.readouterr().err
    assert str(absent) in printed
    assert "No such file" in printed


def test_cross_rejects_a_minimum_outside_the_range(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN)
    assert cli.main(["cross", str(known), "--min", "101"]) == cli.USAGE
    assert "--min" in output.readouterr().err


def test_cross_json_carries_every_pair_and_its_targets(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, CLEAN, CLEAN, ELF64, ELF64)
    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    payload = json.loads(output.readouterr().out)
    assert payload["digests"] == 4
    assert payload["targets"] == ["elf64", "pe64"]
    assert payload["pairs_scored"] == 2
    assert {row["target"] for row in payload["pairs"]} == {"elf64", "pe64"}
    assert payload["pairs"][0]["similarity"] == pytest.approx(100.0)


def test_cross_escapes_a_hostile_label(tmp_path: Path, output: pytest.CaptureFixture[str]) -> None:
    text = report.analyse(CLEAN).digest
    known = tmp_path / "known.txt"
    known.write_text(f"a\x1b[2Kb  {text}\nplain  {text}\n", encoding="utf-8")
    assert cli.main(["cross", str(known)]) == cli.OK
    printed = output.readouterr().out
    assert "\x1b" not in printed
    assert r"\x1b" in printed


# The two commands read the same file through one reader and score on one path, so every
# pair one of them reports must carry the identical score in the other.
def test_cross_and_match_agree_on_every_pair(
    tmp_path: Path, output: pytest.CaptureFixture[str]
) -> None:
    text = report.analyse(CLEAN).digest
    assert text is not None
    names = ["a", "b", "c", "d"]
    weakened = [text[: len(text) - 8 * step] + "0" * (8 * step) for step in range(len(names))]
    known = tmp_path / "known.txt"
    known.write_text(
        "".join(f"{name}  {value}\n" for name, value in zip(names, weakened, strict=True)),
        encoding="utf-8",
    )

    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    from_cross = {
        (row["left"], row["right"]): row["similarity"]
        for row in json.loads(output.readouterr().out)["pairs"]
    }
    assert len(from_cross) == 6

    for name, value in zip(names, weakened, strict=True):
        assert cli.main(["match", value, str(known), "--top", "99", "--json"]) == cli.OK
        for row in json.loads(output.readouterr().out)["matches"]:
            pair = (name, row["label"])
            if pair in from_cross:
                assert from_cross[pair] == pytest.approx(row["similarity"])
