# The eous command line end to end: its commands, their output, exit codes and refusals.

import codecs
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import threading
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
    assert [row["path"] for row in records(capsys.readouterr().out)] == [
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


@pytest.mark.skipif(sys.platform == "win32", reason="EINVAL is the closed-pipe error here")
def test_einval_stays_internal_away_from_windows(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdout", ClosedPipe(errno.EINVAL))
    assert cli.main(["hash", str(PE64)]) == cli.INTERNAL


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
    assert process.returncode == 3
    assert process.stderr.count(b"\n") == 1


def test_a_name_the_terminal_cannot_encode_is_escaped(tmp_path: Path) -> None:
    accented = tmp_path / "café.exe"
    accented.write_bytes(PE64.read_bytes())
    process = run_eous("hash", str(accented), str(PE64), PYTHONIOENCODING="ascii")
    assert process.returncode == cli.OK
    assert b"caf\\xe9.exe  EO1:" in process.stdout
    assert process.stdout.count(b"EO1:") == 2


def records(printed: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in printed.splitlines()]


def test_hash_json_writes_one_record_per_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--json", str(PE64), str(ELF64)]) == cli.OK
    first, second = records(capsys.readouterr().out)
    assert first == {
        "sha256": hashlib.sha256(PE64.read_bytes()).hexdigest(),
        "digest": digest_of(PE64),
        "path": str(PE64),
        "reason": None,
        "detail": None,
        "eous": version("eous"),
    }
    assert second["path"] == str(ELF64)


def test_json_carries_the_refusal_on_stdout_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "junk.bin"
    target.write_bytes(JUNK)
    cli.main(["hash", "--json", str(target)])
    captured = capsys.readouterr()
    [record] = records(captured.out)
    assert record["digest"] is None
    assert record["reason"] == "unreadable"
    assert record["sha256"] is None
    assert captured.err == ""


def test_a_refused_container_keeps_its_sha256(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "cut.exe"
    target.write_bytes(PE64.read_bytes()[:200])
    assert cli.main(["hash", "--json", str(target)]) == cli.REFUSED
    [record] = records(capsys.readouterr().out)
    assert record["digest"] is None
    assert record["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()


def test_every_json_report_opens_with_the_versions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    meta = {"eous": version("eous"), "iced-x86": _native.ICED_X86, "lief": version("lief")}
    for args in (
        ["compare", "--json", str(PE64), str(PE64)],
        ["match", "--json", str(PE64), str(known)],
        ["cross", "--json", str(known)],
        ["cluster", "--json", str(known), "--min", "50"],
    ):
        assert cli.main(args) == cli.OK
        document, _ = json.JSONDecoder().raw_decode(capsys.readouterr().out)
        assert document["meta"] == meta


def test_cross_counts_a_digest_alone_in_its_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64, ELF64)
    assert cli.main(["cross", "--json", str(known)]) == cli.OK
    header = json.loads(capsys.readouterr().out.splitlines()[0])
    assert header["skipped_alone_in_target"] == 1


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
    assert "similarity:  100.0% +/- 2.0" in out
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


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a named pipe")
def test_a_named_pipe_is_refused_as_not_a_regular_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    os.mkfifo(tmp_path / "pipe")
    assert cli.main(["hash", str(tmp_path / "pipe")]) == cli.REFUSED
    assert "unreadable: not a regular file" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["match", "a", "b", "--min", "abc"], "'abc' is not a percentage from 0 to 100"),
        (["match", "a", "b", "--min", "101"], "'101' is not a percentage from 0 to 100"),
        (["match", "a", "b", "--min", "nan"], "'nan' is not a percentage from 0 to 100"),
        (["match", "a", "b", "--top", "x"], "'x' is not a count of 0 or more"),
        (["match", "a", "b", "--top", "-1"], "'-1' is not a count of 0 or more"),
    ],
    ids=["min text", "min high", "min nan", "top text", "top negative"],
)
def test_a_bad_number_is_a_usage_error_that_names_it(
    args: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(args) == cli.USAGE
    assert message in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="a symlink needs privilege on Windows")
def test_a_symlink_loop_is_refused_as_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    assert cli.main(["hash", str(tmp_path / "a")]) == cli.REFUSED
    assert "unreadable: file is absent" in capsys.readouterr().err


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
    return report.Analysis(
        path=path, sha256=None, digest=None, refusal=report.Refusal(report.PACKED, detail)
    )


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
        report.Analysis(path=hostile, sha256=None, digest="EO1:pe64:1:" + "0" * 128, refusal=None),
        report.Analysis(
            path=Path(PE64), sha256=None, digest="EO1:pe64:2:" + "0" * 128, refusal=None
        ),
    ]
    monkeypatch.setattr(cli, "_expand", lambda paths: ([hostile, Path(PE64)], []))
    monkeypatch.setattr(cli, "_analyse", lambda paths, functions: iter(digested))
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

    results = records(capsys.readouterr().out)
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


def sha256_at(place: int) -> str:
    return f"{place:064x}"


def record_line(name: str, text: str, place: int, written: str | None = None) -> str:
    record = {
        "sha256": sha256_at(place),
        "digest": text,
        "path": name,
        "eous": written or version("eous"),
    }
    return json.dumps(record) + "\n"


def store(tmp_path: Path, *named: tuple[str, str]) -> Path:
    target = tmp_path / "known.jsonl"
    lines = [record_line(name, text, place) for place, (name, text) in enumerate(named)]
    target.write_text("".join(lines), encoding="utf-8")
    return target


def known_file(tmp_path: Path, *paths: Path) -> Path:
    return store(tmp_path, *((str(path), digest_of(path)) for path in paths))


def args_for(command: str, known: Path) -> list[str]:
    if command == "match":
        return [command, str(PE64), str(known)]
    if command == "cluster":
        return [command, str(known), "--min", "50"]
    return [command, str(known)]


def test_match_ranks_the_closest_first(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, ELF64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(record_line("weaker", weaker(digest_of(PE64)), 99))

    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    lines = [line for line in capsys.readouterr().out.splitlines() if line]
    assert len(lines) == 2
    assert lines[0].startswith("100.0%")
    assert str(PE64) in lines[0]
    assert "weaker" in lines[1]


def test_match_reads_a_digests_file_that_starts_with_a_byte_order_mark(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.jsonl"
    known.write_text(record_line("one", digest_of(PE64), 0), encoding="utf-8-sig")
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


@pytest.mark.parametrize("command", ["match", "cross", "cluster"])
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


@pytest.mark.parametrize("command", ["match", "cross", "cluster"])
def test_a_hostile_label_is_escaped(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    known = store(tmp_path, ("a\x1b[2Kb", text), ("plain", text))
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
        ("cluster", "--min", "-1"),
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
        handle.write(record_line("weaker", weaker(digest_of(PE64)), 99))

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
        handle.write(record_line("weaker", weaker(digest_of(PE64)), 99))

    assert cli.main(["match", str(PE64), str(known), "--min", "99", "--json"]) == cli.OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["below_minimum"] == 1
    assert len(payload["matches"]) == 1


def test_the_minimum_applies_before_top(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = known_file(tmp_path, PE64, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(record_line("weaker", weaker(digest_of(PE64)), 99))

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
    known = store(tmp_path, ("left", digest_of(PE64)), ("right", digest_of(PE64)))
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
    known = store(tmp_path, ("a", text), ("b", text), ("c", weaker(text)))

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
    known = store(tmp_path, *zip(names, weakened, strict=True))

    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    rows = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]
    from_cross = {(r["left"], r["right"]): r["similarity"] for r in rows if "left" in r}
    assert len(from_cross) == 6

    for name, value in zip(names, weakened, strict=True):
        assert cli.main(["match", value, str(known), "--top", "99", "--json"]) == cli.OK
        for row in json.loads(capsys.readouterr().out)["matches"]:
            pair = (name, row["path"])
            if pair in from_cross:
                assert from_cross[pair] == pytest.approx(row["similarity"])
            expected = digest.compare(digest.parse(value), digest.parse(by_name[row["path"]]))
            assert row["similarity"] == pytest.approx(expected.similarity, abs=1e-4)


def test_cluster_gives_every_digest_a_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    known = store(tmp_path, ("a", text), ("c", weaker(text)), ("b", text))

    assert cli.main(["cluster", str(known), "--min", "99"]) == cli.OK
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [
        f"pe64:1  {sha256_at(0)}  a",
        f"pe64:1  {sha256_at(2)}  b",
        f"pe64:2  {sha256_at(1)}  c",
    ]
    assert "3 digests in 2 clusters, 1 holding one digest" in captured.err


def test_cluster_stays_inside_each_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, ELF64, PE64)
    assert cli.main(["cluster", str(known), "--min", "0"]) == cli.OK
    names = [line.split()[0] for line in capsys.readouterr().out.splitlines()]
    assert names == ["pe64:1", "pe64:1", "elf64:1"]


def test_cluster_json_writes_one_object_per_cluster(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, ELF64, PE64)
    assert cli.main(["cluster", str(known), "--min", "50", "--json"]) == cli.OK
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line]

    header, *found, summary = lines
    assert header["digests"] == 3
    assert header["targets"] == ["pe64", "elf64"]
    assert header["unparsed"] == 0
    assert [(row["cluster"], row["size"]) for row in found] == [("pe64:1", 2), ("elf64:1", 1)]
    assert found[0]["members"] == [
        {"path": str(PE64), "sha256": sha256_at(place), "label": None} for place in (0, 2)
    ]
    assert summary == {"clusters": 2, "singletons": 1}


def test_cluster_gives_a_lone_digest_its_own_cluster(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = store(tmp_path, ("one", digest_of(PE64)))
    assert cli.main(["cluster", str(known), "--min", "100"]) == cli.OK
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [f"pe64:1  {sha256_at(0)}  one"]
    assert "1 digest in 1 cluster, 1 holding one digest" in captured.err


def test_cluster_without_a_minimum_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    assert cli.main(["cluster", str(known)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--min" in captured.err


def test_cluster_is_a_usage_error_when_no_line_is_a_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.txt"
    known.write_text("not a digest\n", encoding="utf-8")
    assert cli.main(["cluster", str(known), "--min", "50"]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "contains no digest" in captured.err


def test_the_cli_imports_no_parser_until_a_binary_is_read() -> None:
    probe = "import sys, eous.cli; print('lief' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, check=True)
    assert result.stdout.strip() == b"False"


def test_an_internal_error_finishes_the_batch_and_exits_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def analysed(paths: list[Path], functions: bool) -> list[report.Analysis]:
        return [report.failed(paths[0], RuntimeError("boom")), report.analyse(paths[1])]

    monkeypatch.setattr(cli, "_analyse", analysed)
    assert cli.main(["hash", str(PE64), str(PE32)]) == cli.INTERNAL
    captured = capsys.readouterr()
    assert "internal_error: RuntimeError: boom" in captured.err
    assert str(PE32) in captured.out


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions and no root"
)
def test_an_unreadable_directory_is_refused_and_the_rest_is_hashed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plant(tmp_path, "a.exe", "locked/b.exe")
    (tmp_path / "locked").chmod(0)
    try:
        assert cli.main(["hash", str(tmp_path)]) == cli.REFUSED
    finally:
        (tmp_path / "locked").chmod(0o700)
    captured = capsys.readouterr()
    assert f"{tmp_path / 'locked'}: unreadable: Permission denied" in captured.err
    assert captured.out.startswith(str(tmp_path / "a.exe"))


def test_a_missing_file_without_a_suffix_is_refused_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert cli.main(["compare", "program", str(PE64)]) == cli.REFUSED
    assert "program: unreadable: file is absent" in capsys.readouterr().err


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions and no root"
)
def test_an_unreadable_directory_alone_is_a_json_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert cli.main(["hash", "--json", str(locked)]) == cli.REFUSED
    finally:
        locked.chmod(0o700)
    [record] = records(capsys.readouterr().out)
    assert record == {
        "sha256": None,
        "digest": None,
        "path": str(locked),
        "reason": "unreadable",
        "detail": "Permission denied",
        "eous": version("eous"),
    }


def test_match_reads_what_hash_json_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(JUNK)
    assert cli.main(["hash", "--json", str(PE64), str(junk), str(ELF64)]) == cli.REFUSED
    known = tmp_path / "known.jsonl"
    known.write_text(capsys.readouterr().out, encoding="utf-8")

    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    sha256 = hashlib.sha256(PE64.read_bytes()).hexdigest()
    assert captured.out.splitlines() == [f"100.0% +/- 2.0  {sha256}  {PE64}"]
    assert "did not parse" not in captured.err


@pytest.mark.parametrize("command", ["match", "cross", "cluster"])
def test_a_sha256_read_twice_counts_once(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(record_line("again", digest_of(PE64), 0))
    assert cli.main(args_for(command, known)) == cli.OK
    captured = capsys.readouterr()
    assert "again" not in captured.out
    assert "1 digest skipped, sha256 already read" in captured.err


@pytest.mark.parametrize("command", ["match", "cross", "cluster"])
def test_digests_of_two_eous_versions_are_a_usage_error(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(record_line("older", digest_of(PE64), 99, written="0.0.1"))
    assert cli.main(args_for(command, known)) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"holds digests of several eous versions: 0.0.1, {version('eous')}" in captured.err


def test_match_refuses_a_file_against_digests_of_another_eous_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.jsonl"
    known.write_text(record_line("older", digest_of(PE64), 0, written="0.0.1"), encoding="utf-8")
    assert cli.main(["match", str(PE64), str(known)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"written by eous 0.0.1, this is eous {version('eous')}" in captured.err

    assert cli.main(["match", digest_of(PE64), str(known)]) == cli.OK
    assert len(capsys.readouterr().out.splitlines()) == 1


@pytest.mark.parametrize(
    "broken",
    [
        "[1, 2]",
        "{",
        "[" * 100_000,
        json.dumps({"digest": "EO1:pe64:1:" + "0" * 128, "path": "p", "eous": "1"}),
        json.dumps(
            {"sha256": "0" * 63, "digest": "EO1:pe64:1:" + "0" * 128, "path": "p", "eous": "1"}
        ),
        json.dumps({"sha256": 5, "digest": 5, "path": 5, "eous": 5}),
        json.dumps(
            {"sha256": "g" * 64, "digest": "EO1:pe64:1:" + "0" * 128, "path": "p", "eous": "1"}
        ),
        json.dumps(
            {
                "sha256": "0" * 64 + "\n",
                "digest": "EO1:pe64:1:" + "0" * 128,
                "path": "p",
                "eous": "1",
            }
        ),
        json.dumps({"sha256": "1" * 64, "digest": "EO1:pe64:1:" + "0" * 128, "path": "p"}),
        json.dumps({"sha256": "1" * 64, "digest": "EO1:pe64:1:zz", "path": "p", "eous": "1"}),
    ],
    ids=[
        "a list",
        "cut short",
        "nested deep",
        "no sha256",
        "short sha256",
        "numbers",
        "sha256 not hex",
        "sha256 with a newline",
        "no eous",
        "digest not a digest",
    ],
)
def test_a_malformed_record_is_counted_and_skipped(
    broken: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    with known.open("a", encoding="utf-8") as handle:
        handle.write(broken + "\n")
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    assert len(captured.out.splitlines()) == 1
    assert "1 line did not parse" in captured.err


def labels_file(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "labels.tsv"
    target.write_text(text, encoding="utf-8")
    return target


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_a_utf_16_digests_file_and_labels_file_are_read(
    encoding: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mark = {"utf-16-le": codecs.BOM_UTF16_LE, "utf-16-be": codecs.BOM_UTF16_BE}.get(encoding, b"")
    known = tmp_path / "known.jsonl"
    known.write_bytes(mark + record_line("one", digest_of(PE64), 0).encode(encoding))
    labels = tmp_path / "labels.tsv"
    labels.write_bytes(mark + f"{sha256_at(0)}\tMirai\r\n".encode(encoding))
    assert cli.main(["match", str(PE64), str(known), "--labels", str(labels)]) == cli.OK
    captured = capsys.readouterr()
    assert captured.out == f"100.0% +/- 2.0  Mirai  {sha256_at(0)}  one\n"
    assert "did not parse" not in captured.err


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a named pipe")
def test_a_digests_file_read_from_a_pipe_keeps_its_first_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = known_file(tmp_path, PE64, PE64).read_bytes()
    pipe = tmp_path / "pipe"
    os.mkfifo(pipe)
    writer = threading.Thread(target=pipe.write_bytes, args=(text,), daemon=True)
    writer.start()
    assert cli.main(["cross", str(pipe)]) == cli.OK
    writer.join(timeout=10)
    assert not writer.is_alive()
    captured = capsys.readouterr()
    assert captured.out.startswith("100.0%")
    assert "1 pair scored" in captured.err


def test_a_lone_utf_16_mark_is_an_empty_digests_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = tmp_path / "known.jsonl"
    known.write_bytes(codecs.BOM_UTF16_LE + b"\x00")
    assert cli.main(["cluster", str(known), "--min", "50"]) == cli.USAGE
    assert "contains no digest" in capsys.readouterr().err


def test_cross_shows_the_label_of_each_side(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = digest_of(PE64)
    known = store(tmp_path, ("one", text), ("two", text), ("alone", digest_of(ELF64)))
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tAgent Tesla\n")
    args = ["cross", str(known), "--labels", str(labels)]
    assert cli.main(args) == cli.OK
    captured = capsys.readouterr()
    assert captured.out == "100.0% +/- 2.0  Agent Tesla  one  -  two\n"
    assert "1 digest without a label" in captured.err
    assert cli.main([*args, "--json"]) == cli.OK
    pair = json.loads(capsys.readouterr().out.splitlines()[1])
    assert (pair["left_label"], pair["right_label"]) == ("Agent Tesla", None)
    assert cli.main(["cross", str(known), "--json"]) == cli.OK
    pair = json.loads(capsys.readouterr().out.splitlines()[1])
    assert (pair["left_label"], pair["right_label"]) == (None, None)
    assert cli.main([*args[:3], str(tmp_path / "absent.tsv")]) == cli.USAGE


def test_match_shows_the_label_of_each_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = store(tmp_path, ("one", digest_of(PE64)), ("two", weaker(digest_of(PE64))))
    labels = labels_file(tmp_path, f"{sha256_at(0).upper()}\tAgent Tesla\n{sha256_at(7)}\tMirai\n")
    assert cli.main(["match", str(PE64), str(known), "--labels", str(labels)]) == cli.OK
    captured = capsys.readouterr()
    first, second = captured.out.splitlines()
    assert first == f"100.0% +/- 2.0  Agent Tesla  {sha256_at(0)}  one"
    assert second.endswith(f"  -  {sha256_at(1)}  two")
    assert "1 digest without a label" in captured.err


def test_match_json_carries_the_label(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    known = store(tmp_path, ("one", digest_of(PE64)), ("two", weaker(digest_of(PE64))))
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tMirai\n")
    assert cli.main(["match", str(PE64), str(known), "--labels", str(labels), "--json"]) == cli.OK
    matches = json.loads(capsys.readouterr().out)["matches"]
    assert [(row["path"], row["sha256"], row["label"]) for row in matches] == [
        ("one", sha256_at(0), "Mirai"),
        ("two", sha256_at(1), None),
    ]


def test_cluster_shows_the_label_of_each_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = store(tmp_path, ("one", digest_of(PE64)), ("two", digest_of(PE64)))
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tMirai\n{sha256_at(1)}\tGafgyt\n")
    assert cli.main(["cluster", str(known), "--min", "90", "--labels", str(labels)]) == cli.OK
    assert capsys.readouterr().out.splitlines() == [
        "pe64:1  2 digests: Gafgyt 1, Mirai 1",
        f"pe64:1  Mirai  {sha256_at(0)}  one",
        f"pe64:1  Gafgyt  {sha256_at(1)}  two",
    ]


def test_cluster_counts_the_labels_of_each_cluster(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    named = [(name, digest_of(PE64)) for name in ("one", "two", "three", "four")]
    known = store(tmp_path, *named, ("apart", digest_of(ELF64)))
    labels = labels_file(
        tmp_path, f"{sha256_at(0)}\tMirai\n{sha256_at(1)}\tGafgyt\n{sha256_at(2)}\tMirai\n"
    )
    arguments = ["cluster", str(known), "--min", "90", "--labels", str(labels)]

    assert cli.main(arguments) == cli.OK
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "pe64:1  4 digests: Mirai 2, Gafgyt 1, - 1"
    assert len(lines) == 6
    assert lines[5].startswith("elf64:1  -  ")

    assert cli.main([*arguments, "--json"]) == cli.OK
    found = [json.loads(row) for row in capsys.readouterr().out.splitlines()][1:3]
    assert [row["labels"] for row in found] == [{"Mirai": 2, "Gafgyt": 1}, {}]

    assert cli.main(["cluster", str(known), "--min", "90", "--json"]) == cli.OK
    assert json.loads(capsys.readouterr().out.splitlines()[1])["labels"] is None


def test_match_counts_the_labels_it_shows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = store(
        tmp_path,
        ("one", digest_of(PE64)),
        ("two", digest_of(PE64)),
        ("three", weaker(digest_of(PE64))),
    )
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tMirai\n{sha256_at(1)}\tMirai\n")
    arguments = ["match", str(PE64), str(known), "--labels", str(labels)]

    assert cli.main(arguments) == cli.OK
    assert "eous: 3 digests: Mirai 2, - 1" in capsys.readouterr().err

    assert cli.main([*arguments, "--top", "1"]) == cli.OK
    assert "digests:" not in capsys.readouterr().err

    assert cli.main([*arguments, "--top", "2", "--json"]) == cli.OK
    assert json.loads(capsys.readouterr().out)["labels"] == {"Mirai": 2}


@pytest.mark.parametrize("command", ["match", "cluster"])
def test_a_sha256_with_two_labels_is_a_usage_error(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64, PE64)
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tMirai\n{sha256_at(0)}\tGafgyt\n")
    assert cli.main([*args_for(command, known), "--labels", str(labels)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"{sha256_at(0)} carries two labels" in captured.err


def test_a_malformed_label_line_is_counted_and_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    labels = labels_file(
        tmp_path,
        f"no tab here\nshort\tMirai\n{sha256_at(0)}\t\n\n"
        f"{sha256_at(0)}\t-\n{sha256_at(0)}\tMirai\n",
    )
    assert cli.main(["match", str(PE64), str(known), "--labels", str(labels)]) == cli.OK
    captured = capsys.readouterr()
    assert "  Mirai  " in captured.out
    assert "4 label lines did not parse" in captured.err


def test_a_hostile_family_label_is_escaped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    labels = labels_file(tmp_path, f"{sha256_at(0)}\tMirai\x1b[2K\tsecond\n")
    assert cli.main(["match", str(PE64), str(known), "--labels", str(labels)]) == cli.OK
    printed = capsys.readouterr().out
    assert "\x1b" not in printed
    assert r"Mirai\x1b[2K\x09second" in printed


def test_an_absent_labels_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known = known_file(tmp_path, PE64)
    absent = tmp_path / "absent.tsv"
    assert cli.main(["match", str(PE64), str(known), "--labels", str(absent)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "No such file" in captured.err
