# The eous command line end to end: the four commands, their output, exit codes and refusals.

import errno
import io
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import time
from functools import cache
from importlib.metadata import version
from pathlib import Path

import pytest

from conftest import ELF64, JUNK, MACHO, PE32, PE64, WILSON_MARGIN_AT_FULL_AGREEMENT
from eous import _native, cli, digest, pool, report


@cache
def digest_of(path: Path) -> str:
    text = report.analyse(path).digest
    assert text is not None
    return text


def weaker(text: str) -> str:
    return text[:-32] + "0" * 32


def test_hashing_one_file_prints_the_digest_alone(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", str(PE64)]) == cli.OK
    captured = capsys.readouterr()
    assert captured.out.startswith("EO1:")
    assert captured.out.count(":") == 3
    assert captured.err == ""


def plant(root: Path, *names: str) -> None:
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(PE64.read_bytes())


def test_a_directory_is_walked_in_sorted_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "c.exe", "a.exe", "b.exe")
    cli.main(["hash", str(tmp_path)])
    assert [line.split("  ")[0] for line in capsys.readouterr().out.splitlines()] == [
        str(tmp_path / name) for name in ("a.exe", "b.exe", "c.exe")
    ]


def test_one_file_in_a_directory_is_still_labelled(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "only.exe")
    cli.main(["hash", str(tmp_path)])
    assert capsys.readouterr().out.startswith(str(tmp_path / "only.exe"))


def test_an_empty_directory_says_it_holds_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["hash", str(tmp_path)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no file to hash" in captured.err
    assert str(tmp_path) in captured.err


def test_an_over_long_path_is_refused_rather_than_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["hash", str(tmp_path / ("a" * 400))]) == cli.REFUSED
    captured = capsys.readouterr()
    assert "internal error" not in captured.err
    assert "unreadable" in captured.err


def test_a_directory_reached_twice_is_digested_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "sub/one.exe")
    assert cli.main(["hash", str(tmp_path), str(tmp_path / "sub")]) == cli.OK
    assert len(capsys.readouterr().out.strip().splitlines()) == 1


def test_a_directory_carries_its_paths_into_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "one.exe", "sub/two.exe")
    cli.main(["hash", "--json", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert [row["path"] for row in payload["results"]] == [
        str(tmp_path / "one.exe"),
        str(tmp_path / "sub" / "two.exe"),
    ]


def test_a_refused_file_exits_one_and_names_its_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "thing.macho"
    target.write_bytes(MACHO)
    assert cli.main(["hash", str(target)]) == cli.REFUSED
    captured = capsys.readouterr()
    assert "unsupported_format" in captured.err
    assert "mach" in captured.err.lower()
    assert captured.out == ""


def test_one_refusal_among_many_still_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(JUNK)
    assert cli.main(["hash", str(PE64), str(target)]) == cli.REFUSED
    captured = capsys.readouterr()
    assert "EO1:" in captured.out
    assert "unreadable" in captured.err


def test_quiet_holds_back_the_refusal_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(JUNK)
    assert cli.main(["hash", "--quiet", str(target)]) == cli.REFUSED
    assert capsys.readouterr().err == ""


class ClosedPipe(io.StringIO):
    def __init__(self, code: int) -> None:
        super().__init__()
        self.code = code

    def write(self, text: str) -> int:
        raise OSError(self.code, "the reader is gone")


@pytest.mark.parametrize("code", cli.CLOSED_PIPE)
def test_a_closed_reader_ends_the_run_quietly(
    code: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(code))
    assert cli.main(["hash", str(PE64)]) == cli.OK
    assert capsys.readouterr().err == ""


def test_an_unrelated_os_error_is_still_internal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EACCES))
    assert cli.main(["hash", str(PE64)]) == cli.INTERNAL
    assert "internal error" in capsys.readouterr().err


def test_a_refusal_outlives_a_closed_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(JUNK)
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EPIPE))
    assert cli.main(["hash", str(junk), str(PE64)]) == cli.REFUSED


def run_eous(*args: str, **env: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "eous.cli", *args],
        capture_output=True,
        env={**os.environ, **env},
        timeout=120,
        check=False,
    )


def test_the_installed_command_exits_zero_one_and_two(tmp_path: Path) -> None:
    command = shutil.which("eous", path=sysconfig.get_path("scripts"))
    assert command is not None
    junk = tmp_path / "junk.bin"
    junk.write_bytes(JUNK)
    for args, code in ((["hash", str(PE64)], 0), (["hash", str(junk)], 1), (["hash"], 2)):
        process = subprocess.run([command, *args], capture_output=True, timeout=120, check=False)
        assert process.returncode == code, args


def test_a_closed_reader_exits_zero_in_a_real_process() -> None:
    process = subprocess.Popen(
        [sys.executable, "-m", "eous.cli", "hash", "--json", str(PE64)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None and process.stderr is not None
    process.stdout.close()
    err = process.stderr.read()
    assert process.wait(timeout=120) == cli.OK
    assert err == b""


@pytest.mark.skipif(not Path("/dev/full").exists(), reason="needs a device that is always full")
def test_a_full_device_exits_as_an_internal_error() -> None:
    with open("/dev/full", "w") as full:
        process = subprocess.run(
            [sys.executable, "-m", "eous.cli", "hash", str(PE64)],
            stdout=full,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    assert process.returncode == cli.INTERNAL
    assert process.stderr.count(b"\n") == 1


def test_a_name_the_terminal_cannot_encode_is_escaped(tmp_path: Path) -> None:
    accented = tmp_path / "café.exe"
    accented.write_bytes(PE64.read_bytes())
    process = run_eous("hash", str(accented), str(PE64), PYTHONIOENCODING="ascii")
    assert process.returncode == cli.OK
    assert b"caf\\xe9.exe  EO1:" in process.stdout
    assert process.stdout.count(b"EO1:") == 2


def test_json_output_parses(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["hash", "--json", str(PE64)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["results"][0]["digest"].startswith("EO1:")
    assert payload["results"][0]["path"].endswith("fixture-pe-x64.exe")


def test_json_carries_the_refusal_on_stdout_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(JUNK)
    cli.main(["hash", "--json", str(target)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["results"][0]["digest"] is None
    assert payload["results"][0]["reason"] == "unreadable"
    assert captured.err == ""


def test_every_json_document_opens_with_the_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64, ELF64)
    for args in (
        ["hash", "--json", str(PE64)],
        ["compare", "--json", str(PE64), str(PE64)],
        ["match", "--json", str(PE64), str(known)],
        ["cross", "--json", str(known)],
    ):
        assert cli.main(args) == cli.OK
        document, _ = json.JSONDecoder().raw_decode(capsys.readouterr().out)
        assert document["meta"] == {
            "eous": version("eous"),
            "iced-x86": _native.ICED_X86,
            "lief": version("lief"),
        }
    assert document["skipped_alone_in_target"] == 1


def test_hash_without_a_file_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash"]) == cli.USAGE


def test_version_prints_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == cli.OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("eous ")
    assert lines[1:] == [f"iced-x86 {_native.ICED_X86}", f"lief {version('lief')}"]


def test_help_exits_zero_through_main(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == cli.OK
    assert "EO1:" in capsys.readouterr().out


def test_a_bad_flag_is_still_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--nonsense", str(PE64)]) == cli.USAGE


def test_a_file_compared_with_itself_scores_full(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(PE64), str(PE64)]) == cli.OK
    out = capsys.readouterr().out
    assert out.isascii()
    assert "similarity:  100.0% +/- 0.5" in out
    lines = [line for line in out.splitlines() if "in" in line]
    assert len(lines) == 2
    assert all(line.endswith("100.0%") for line in lines)
    assert all("fixture-pe-x64.exe" in line for line in lines)


@pytest.mark.parametrize(
    "args",
    [
        ["hash", "no/such/file.exe"],
        ["compare", "no/such/file.exe", str(PE64)],
        ["match", "no/such/file.exe", str(PE64)],
    ],
    ids=["hash", "compare", "match"],
)
def test_a_mistyped_path_is_refused_as_absent(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(args) == cli.REFUSED
    assert f"{Path('no/such/file.exe')}: unreadable: file is absent" in capsys.readouterr().err


def test_differing_targets_are_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(PE64), str(ELF64)]) == cli.USAGE
    assert "different targets" in capsys.readouterr().err


def test_compare_needs_two_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["compare", str(PE64)]) == cli.USAGE
    assert cli.main(["compare"]) == cli.USAGE


def test_compare_json_carries_both_scores(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["compare", "--json", str(PE64), str(PE64)])
    payload = json.loads(capsys.readouterr().out)
    scores = payload["comparison"]
    assert scores["similarity"] == pytest.approx(100.0)
    assert scores["uncertainty"] == pytest.approx(WILSON_MARGIN_AT_FULL_AGREEMENT, abs=1e-4)
    assert scores["left_in_right"] == pytest.approx(100.0)
    assert scores["right_in_left"] == pytest.approx(100.0)
    assert scores["left"].endswith("fixture-pe-x64.exe")


def test_withheld_containment_says_why(capsys: pytest.CaptureFixture[str]) -> None:
    body = "0" * 128
    cli.main(["compare", f"EO1:pe64:10:{body}", f"EO1:pe64:1000:{body}"])
    assert "n/a" in capsys.readouterr().out


def test_files_sharing_a_basename_stay_distinguishable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    left, right = tmp_path / "v1" / "prog.exe", tmp_path / "v2" / "prog.exe"
    for target in (left, right):
        target.parent.mkdir()
        target.write_bytes(PE64.read_bytes())

    cli.main(["compare", str(left), str(right)])
    lines = [line for line in capsys.readouterr().out.splitlines() if " in " in line]
    assert len(lines) == 2
    assert str(left) in lines[0]
    assert str(right) in lines[0]


def test_digest_inputs_are_labelled_left_and_right(capsys: pytest.CaptureFixture[str]) -> None:
    text = digest_of(PE64)
    cli.main(["compare", text, text])
    lines = capsys.readouterr().out.splitlines()
    directions = [" ".join(line.split()) for line in lines if " in " in line]
    assert any(d.startswith("containment: left in right 100.0%") for d in directions)
    assert any(d.startswith("right in left 100.0%") for d in directions)


def explode(path: Path) -> object:
    raise RuntimeError("something gave way")


def test_an_unexpected_failure_exits_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(report, "analyse", explode)
    assert cli.main(["hash", str(PE64)]) == cli.INTERNAL
    assert "something gave way" in capsys.readouterr().err


HOSTILE_SECTION = ".text\x1b[2K\reous: /bin/ls: unreadable: no recognised container\neous: trusted"


def hostile_refusal(path: Path) -> report.Analysis:
    detail = f"executable section {HOSTILE_SECTION} is writable"
    return report.Analysis(path=path, digest=None, refusal=report.Refusal(report.PACKED, detail))


def test_a_section_name_cannot_forge_a_refusal_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(report, "analyse", hostile_refusal)
    assert cli.main(["hash", str(PE64)]) == cli.REFUSED

    printed = capsys.readouterr().err
    assert len(printed.splitlines()) == 1
    assert "\x1b" not in printed
    assert "\r" not in printed
    assert r"\x1b" in printed
    assert r"\x0a" in printed


def test_a_file_name_cannot_forge_a_digest_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = Path("a\nEO1:pe64:9999:" + "f" * 128)
    digested = [
        report.Analysis(path=hostile, digest="EO1:pe64:1:" + "0" * 128, refusal=None),
        report.Analysis(path=Path(PE64), digest="EO1:pe64:2:" + "0" * 128, refusal=None),
    ]
    monkeypatch.setattr(cli, "_expand", lambda paths: [hostile, Path(PE64)])
    monkeypatch.setattr(cli, "_analyse", lambda paths: iter(digested))
    assert cli.main(["hash", str(PE64), str(PE64)]) == cli.OK

    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    assert len(lines) == 2, "the newline in the name opened a third record"
    assert r"\x0a" in lines[0]


ANALYSE = report.analyse


def analyse_or_die(path: Path) -> report.Analysis:
    if path.name.startswith("crash"):
        os._exit(1)
    return ANALYSE(path)


def test_a_worker_that_dies_costs_only_its_own_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "a.exe", "b.exe", "crash1.exe", "crash2.exe", "d.exe")
    monkeypatch.setattr(report, "analyse", analyse_or_die)
    assert cli.main(["hash", str(tmp_path)]) == cli.REFUSED

    captured = capsys.readouterr()
    digested = [line.split("  ")[0] for line in captured.out.splitlines()]
    assert digested == [str(tmp_path / name) for name in ("a.exe", "b.exe", "d.exe")]
    refused = captured.err.splitlines()
    assert len(refused) == 2
    assert all("unreadable: the analysis process ended abruptly" in line for line in refused)


def analyse_or_stall(path: Path) -> report.Analysis:
    if path.name.startswith("stall"):
        time.sleep(60)
    return ANALYSE(path)


def test_a_file_past_its_deadline_costs_only_its_own_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "stall.exe", "t.exe", "u.exe")
    monkeypatch.setattr(report, "analyse", analyse_or_stall)
    monkeypatch.setattr(pool, "TIME_BASE", 5.0)
    assert cli.main(["hash", "--json", str(tmp_path)]) == cli.REFUSED

    results = json.loads(capsys.readouterr().out)["results"]
    assert [row["path"] for row in results] == [
        str(tmp_path / name) for name in ("stall.exe", "t.exe", "u.exe")
    ]
    assert results[0]["detail"] == "the analysis exceeded its 5 s time limit"
    assert all(row["digest"] for row in results[1:])


def test_compare_gives_a_file_the_same_deadline_as_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "stall.exe")
    monkeypatch.setattr(report, "analyse", analyse_or_stall)
    monkeypatch.setattr(pool, "TIME_BASE", 5.0)
    assert cli.main(["compare", str(tmp_path / "stall.exe"), str(PE64)]) == cli.REFUSED
    assert "time limit" in capsys.readouterr().err


def known_file(tmp_path: Path, *paths: Path, labelled: bool = True) -> Path:
    target = tmp_path / "known.txt"
    lines = [f"{path}  {digest_of(path)}" if labelled else digest_of(path) for path in paths]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def args_for(command: str, known: Path) -> list[str]:
    return [command, str(PE64), str(known)] if command == "match" else [command, str(known)]


def test_match_ranks_the_closest_first(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, ELF64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker(digest_of(PE64))}\n")

    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    assert len(lines) == 2
    assert lines[0].startswith("100.0%")
    assert str(PE64) in lines[0]
    assert "weaker" in lines[1]


def test_match_reads_the_bare_digest_form_hash_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, labelled=False)
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    assert capsys.readouterr().out.splitlines()[0].startswith("100.0%")


def test_match_reads_a_digests_file_that_starts_with_a_byte_order_mark(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.txt"
    known.write_text(digest_of(PE64) + "\n", encoding="utf-8-sig")
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert captured.out.startswith("100.0%")
    assert "did not parse" not in captured.err


def test_match_skips_entries_built_for_another_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE32, ELF64)
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "2 digests skipped, built for another target" in captured.err


def test_match_is_a_usage_error_when_nothing_shares_the_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE32, ELF64)
    assert cli.main(["match", str(PE64), str(known)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "contains no pe64 digest" in captured.err


def test_match_limits_the_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, PE64, PE64)
    assert cli.main(["match", str(PE64), str(known), "--top", "2"]) == cli.OK
    assert len([line for line in capsys.readouterr().out.splitlines() if line]) == 2


def test_match_skips_a_line_that_is_not_a_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    known.write_text(known.read_text(encoding="utf-8") + "notes.txt  not-a-digest\n\n", "utf-8")
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "1 line did not parse" in captured.err


def test_match_refuses_a_query_it_cannot_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(JUNK)
    known = known_file(tmp_path, PE64)
    assert cli.main(["match", str(junk), str(known)]) == cli.REFUSED
    assert "unreadable" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["match", "cross"])
def test_an_absent_digests_file_is_a_usage_error(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    absent = tmp_path / "absent.txt"
    assert cli.main(args_for(command, absent)) == cli.USAGE
    printed = capsys.readouterr().err
    assert str(absent) in printed
    assert "No such file" in printed


def test_match_json_carries_the_target_and_the_ranking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, ELF64)
    assert cli.main(["match", str(PE64), str(known), "--json"]) == cli.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["target"] == "pe64"
    assert payload["skipped_other_target"] == 1
    assert payload["matches"][0]["uncertainty"] == pytest.approx(
        WILSON_MARGIN_AT_FULL_AGREEMENT, abs=1e-4
    )
    assert payload["matches"][0]["similarity"] == pytest.approx(100.0)


@pytest.mark.parametrize("command", ["match", "cross"])
def test_a_hostile_label_is_escaped(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    known = tmp_path / "known.txt"
    known.write_text(f"a\x1b[2Kb  {text}\nplain  {text}\n", encoding="utf-8")
    assert cli.main(args_for(command, known)) == cli.OK
    printed = capsys.readouterr().out
    assert "\x1b" not in printed
    assert r"\x1b" in printed


@pytest.mark.parametrize(
    ("command", "flag", "value"),
    [
        ("match", "--top", "-1"),
        ("match", "--min", "100.1"),
        ("cross", "--min", "101"),
    ],
)
def test_a_value_outside_its_range_is_a_usage_error(
    command: str, flag: str, value: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    assert cli.main([*args_for(command, known), flag, value]) == cli.USAGE
    assert flag in capsys.readouterr().err


def test_the_help_example_is_the_digest_the_fixture_produces() -> None:
    text = digest_of(PE64)
    shown = next(
        line.strip() for line in cli.EPILOGUE.splitlines() if line.strip().startswith("EO1:")
    )
    assert shown.rstrip(".") == text[: len(shown.rstrip("."))]


def test_a_digest_too_long_to_be_a_filename_is_read_as_a_digest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    text = digest_of(PE64)
    body = text.rsplit(":", 1)[1]
    assert cli.main(["compare", f"EO1:pe64:{'9' * 400}:{body}", text]) == cli.USAGE
    assert "internal error" not in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="Windows refuses an escape in a file name")
def test_compare_escapes_a_hostile_filename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "evil\x1b[31mRED.exe"
    target.write_bytes(PE64.read_bytes())
    assert cli.main(["compare", str(target), str(target)]) == cli.OK
    printed = capsys.readouterr().out
    assert "\x1b" not in printed
    assert r"\x1b" in printed


def test_match_holds_back_anything_below_the_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker(digest_of(PE64))}\n")

    assert cli.main(["match", str(PE64), str(known), "--min", "99"]) == cli.OK
    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert len(lines) == 1
    assert lines[0].startswith("100.0%")
    assert "1 digest scored below 99%" in captured.err


def test_the_minimum_keeps_an_exact_score(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    assert cli.main(["match", str(PE64), str(known), "--min", "100"]) == cli.OK
    assert len([line for line in capsys.readouterr().out.splitlines() if line]) == 1


def test_match_json_counts_what_the_minimum_held_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker(digest_of(PE64))}\n")

    assert cli.main(["match", str(PE64), str(known), "--min", "99", "--json"]) == cli.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["below_minimum"] == 1
    assert len(payload["matches"]) == 1


def test_the_minimum_applies_before_top(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(f"weaker  {weaker(digest_of(PE64))}\n")

    assert cli.main(["match", str(PE64), str(known), "--top", "3", "--min", "99"]) == cli.OK
    assert len([line for line in capsys.readouterr().out.splitlines() if line]) == 2


def test_cross_scores_every_pair_once(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, PE64, PE64, PE64)
    assert cli.main(["cross", str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 4 * 3 // 2
    assert "6 pairs scored across pe64" in captured.err


def test_cross_names_both_sides_of_a_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.txt"
    known.write_text(f"left  {digest_of(PE64)}\nright  {digest_of(PE64)}\n", encoding="utf-8")
    assert cli.main(["cross", str(known)]) == cli.OK
    line = capsys.readouterr().out.splitlines()[0]
    assert line.startswith("100.0%")
    assert line.endswith("left  right")


def test_cross_pairs_inside_each_target(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, PE64, ELF64, ELF64)
    assert cli.main(["cross", str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 2
    assert "2 pairs scored across pe64, elf64" in captured.err


def test_cross_holds_back_anything_below_the_minimum(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    known = tmp_path / "known.txt"
    known.write_text(f"a  {text}\nb  {text}\nc  {weaker(text)}\n", encoding="utf-8")

    assert cli.main(["cross", str(known), "--min", "99"]) == cli.OK
    captured = capsys.readouterr()
    assert len([line for line in captured.out.splitlines() if line]) == 1
    assert "2 pairs scored below 99%" in captured.err


def test_cross_is_a_usage_error_when_no_target_holds_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, ELF64, PE32)
    assert cli.main(["cross", str(known)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "contains fewer than two digests" in captured.err


def test_cross_json_writes_one_object_per_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64, ELF64, ELF64)
    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]

    header, *pairs, summary = lines
    assert header["digests"] == 4
    assert header["targets"] == ["pe64", "elf64"]
    assert header["unparsed"] == 0
    assert header["skipped_alone_in_target"] == 0
    assert summary == {"pairs_scored": 2, "below_minimum": 0}
    assert [row["target"] for row in pairs] == ["pe64", "elf64"]
    assert pairs[0]["similarity"] == pytest.approx(100.0)


def test_cross_and_match_agree_on_every_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    names = ["a", "b", "c", "d"]
    prefix, target, _, body = text.split(":")
    cardinalities = [100, 400, 1600, 6400]
    weakened = [
        f"{prefix}:{target}:{cardinality}:{body[: len(body) - 8 * step]}{'0' * (8 * step)}"
        for step, cardinality in enumerate(cardinalities)
    ]
    by_name = dict(zip(names, weakened, strict=True))
    known = tmp_path / "known.txt"
    known.write_text(
        "".join(f"{name}  {value}\n" for name, value in zip(names, weakened, strict=True)),
        encoding="utf-8",
    )

    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    from_cross = {(r["left"], r["right"]): r["similarity"] for r in rows if "left" in r}
    assert len(from_cross) == 6

    for name, value in zip(names, weakened, strict=True):
        assert cli.main(["match", value, str(known), "--top", "99", "--json"]) == cli.OK
        for row in json.loads(capsys.readouterr().out)["matches"]:
            pair = (name, row["label"])
            if pair in from_cross:
                assert from_cross[pair] == pytest.approx(row["similarity"])
            expected = digest.compare(digest.parse(value), digest.parse(by_name[row["label"]]))
            assert row["similarity"] == pytest.approx(expected.similarity, abs=1e-4)


def test_the_cli_imports_no_parser_until_a_binary_is_read() -> None:
    probe = "import sys, eous.cli; print('lief' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, check=True)
    assert result.stdout.strip() == b"False"
