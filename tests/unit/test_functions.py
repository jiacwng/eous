# Function digests end to end: the packed score, the file score, and the functions command.

import json
import random
from importlib.metadata import version
from pathlib import Path

import lief
import numpy
import pytest

from conftest import ELF32, ELF64, PE32, PE64
from eous import _native, cli, digest, functions, loader, report

SLOTS = digest.PERMUTATIONS * digest.SLOT_BITS


def sketch(seed: int, cardinality: int = 100) -> digest.Sketch:
    return digest.Sketch("pe64", cardinality, random.Random(seed).getrandbits(SLOTS))


def blended(left: digest.Sketch, right: digest.Sketch, kept: int) -> digest.Sketch:
    low = (1 << kept) - 1
    return digest.Sketch("pe64", left.cardinality, (left.slots & ~low) | (right.slots & low))


def table(*held: tuple[int, digest.Sketch]) -> functions.Table:
    return functions.table(list(held))


def places(*found: int) -> numpy.ndarray:
    return numpy.array(found, dtype=numpy.intp)


def test_the_packed_score_is_the_score_of_two_digests() -> None:
    one = sketch(0, 70)
    stored = [sketch(seed, 40 + seed) for seed in range(1, 30)]
    stored += [blended(one, sketch(99), kept) for kept in range(0, SLOTS, 37)]
    expected, _ = digest.score(
        digest.unpack_all(stored), digest.cardinalities(stored), digest.unpack(one), 70
    )
    scored = functions.scores(table(*((256, s) for s in stored)), table((256, one)).words[0], 70)
    assert numpy.allclose(scored, expected)
    assert expected.max() == 100.0
    assert 0.0 < numpy.median(expected) < 100.0


def test_an_empty_cardinality_scores_without_dividing_by_zero() -> None:
    empty = digest.Sketch("pe64", 0, sketch(0).slots)
    scored = functions.scores(table((256, empty)), table((256, empty)).words[0], 0)
    assert scored.tolist() == [100.0]


def test_the_file_score_is_the_matched_share_of_both_files_function_bytes() -> None:
    shared, alone, other = sketch(1), sketch(2), sketch(3)
    query = table((300, shared), (700, alone))
    stored = table((300, shared), (500, other))
    matched = functions.match(query, stored, places(0, 1), places())
    assert matched.files.tolist() == pytest.approx([(300 + 300) / (1000 + 300) * 100, 0.0])
    assert matched.in_file[0].tolist() == pytest.approx([100.0, 0.0], abs=20)
    assert matched.closest[0] == 0
    assert matched.named.tolist() == [-1, -1]


def test_a_match_under_fifty_counts_for_nothing() -> None:
    one = sketch(1)
    weak = blended(one, sketch(2), SLOTS * 3 // 4)
    strong = blended(one, sketch(2), SLOTS // 4)
    matched = functions.match(
        table((400, one)), table((400, weak), (400, strong)), places(0, 1), places()
    )
    assert 0.0 < matched.in_file[0, 0] < functions.MATCH < matched.in_file[0, 1] < 100.0
    assert matched.files[0] == 0.0
    assert matched.files[1] == pytest.approx(matched.in_file[0, 1])


def test_the_name_is_the_closest_named_match() -> None:
    one = sketch(1)
    close = blended(one, sketch(2), SLOTS // 8)
    closer = blended(one, sketch(3), SLOTS // 16)
    stored = table((400, sketch(4)), (400, close), (400, closer), (400, one))
    starts = places(0, 2)
    assert functions.match(table((400, one)), stored, starts, places(0, 1, 2)).named.tolist() == [2]
    assert functions.match(table((400, one)), stored, starts, places(0)).named.tolist() == [-1]


def test_the_loader_gives_entry_points_only_when_asked() -> None:
    assert loader.load(PE64).entry_points == ()
    asked = loader.load(PE64, entry_points=True)
    assert asked.image_base == 0x140000000
    assert asked.entry_points
    assert all(0 < address < asked.image_base for address in asked.entry_points)
    elf = loader.load(ELF64, entry_points=True)
    assert elf.image_base == 0
    assert any(
        section.virtual_address <= address < section.virtual_address + len(section.data)
        for address in elf.entry_points
        for section in elf.sections
    )


def test_a_table_lief_cannot_read_costs_only_its_own_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(self: object) -> object:
        raise RuntimeError("bad export table")

    whole = loader.load(PE64, entry_points=True).entry_points
    monkeypatch.setattr(lief.PE.Binary, "get_export", broken)
    monkeypatch.setattr(lief.PE.Binary, "has_exports", property(lambda self: True))
    assert set(loader.load(PE64, entry_points=True).entry_points) <= set(whole)
    assert loader.load(PE64, entry_points=True).entry_points


def test_functions_are_found_only_when_asked() -> None:
    assert report.analyse(PE64).functions is None
    result = report.analyse_functions(PE64)
    assert result.digest == report.analyse(PE64).digest
    assert result.functions
    assert all(f.length >= _native.FUNCTION_BYTES for f in result.functions)
    assert all(f.address > 0x140000000 for f in result.functions)
    assert all(digest.parse(f.digest).target == "pe64" for f in result.functions)
    assert report.analyse_functions(PE64.with_suffix(".absent")).functions is None
    elf = report.analyse_functions(ELF64)
    assert elf.digest == report.analyse(ELF64).digest
    assert elf.functions
    assert all(digest.parse(f.digest).target == "elf64" for f in elf.functions)


def test_hash_adds_the_functions_to_each_record(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--json", "--functions", str(PE64)]) == cli.OK
    record = json.loads(capsys.readouterr().out)
    expected = report.analyse_functions(PE64).functions
    assert expected is not None
    assert record["functions"] == [[f.address, f.length, f.digest] for f in expected]


def test_hash_functions_without_json_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["hash", "--functions", str(PE64)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--functions needs --json" in captured.err


def hashed(capsys: pytest.CaptureFixture[str], *args: str) -> list[dict[str, object]]:
    cli.main(["hash", "--json", *args])
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def sha256_at(place: int) -> str:
    return f"{place:064x}"


def store(tmp_path: Path, records: list[dict[str, object]]) -> Path:
    target = tmp_path / "functions.jsonl"
    renamed = [record | {"sha256": sha256_at(place)} for place, record in enumerate(records)]
    target.write_text("".join(json.dumps(record) + "\n" for record in renamed), encoding="utf-8")
    return target


@pytest.fixture
def known(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    return store(tmp_path, hashed(capsys, "--functions", str(PE64), str(PE32), str(ELF64)))


def first_function(path: Path) -> report.Function:
    found = report.analyse_functions(path).functions
    assert found
    return found[0]


def test_a_copy_under_another_sha256_matches_every_function(
    known: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["functions", str(PE64), str(known)]) == cli.OK
    captured = capsys.readouterr()
    files, _, rows = captured.out.partition("\n\n")
    assert files == f"functions 100.0%  file 100.0% +/- 0.5  {sha256_at(0)}  {PE64}"
    lines = rows.splitlines()
    function = first_function(PE64)
    assert lines[0] == (
        f"{function.address:#x}  {function.length} bytes  100.0%  1 file  "
        f"{sha256_at(0)}:{function.address:#x}"
    )
    assert all("  100.0%  1 file  " in line for line in lines)
    assert f"{len(lines)} functions, {len(lines)} matched in 1 file" in captured.err
    assert "2 files skipped, built for another target" in captured.err


def test_the_query_itself_is_not_a_match(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "functions.jsonl"
    [record] = hashed(capsys, "--functions", str(PE64))
    target.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert cli.main(["functions", str(PE64), str(target)]) == cli.USAGE
    assert "contains no pe64 file with functions" in capsys.readouterr().err


def test_a_file_stored_without_functions_is_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with_functions = hashed(capsys, "--functions", str(PE64))
    target = store(tmp_path, with_functions + hashed(capsys, str(PE64)))
    assert cli.main(["functions", str(PE64), str(target)]) == cli.OK
    assert "1 file skipped, stored without functions" in capsys.readouterr().err


def test_a_function_record_that_does_not_parse_is_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    elf = first_function(ELF64)
    broken = [
        None,
        [],
        [1, 2],
        ["1", 300, kept[0][2]],
        [True, 300, kept[0][2]],
        [-1, 300, kept[0][2]],
        [1, 0, kept[0][2]],
        [1, 300, "EO1:pe64:1:zz"],
        [1, 300, 5],
        [1 << 64, 300, kept[0][2]],
        [1, 10**400, kept[0][2]],
        [1, 1 << 64, kept[0][2]],
        [elf.address, elf.length, elf.digest],
    ]
    target = store(tmp_path, [record | {"functions": kept + broken}, record | {"functions": 7}])
    assert cli.main(["functions", "--json", str(PE64), str(target)]) == cli.OK
    document = json.loads(capsys.readouterr().out)
    assert document["unparsed"] == len(broken)
    assert document["skipped_without_functions"] == 1
    assert all(row["files"] == 1 for row in document["functions"])
    assert cli.main(["functions", str(PE64), str(target)]) == cli.OK
    assert f"{len(broken)} stored functions did not parse" in capsys.readouterr().err


def test_the_largest_stored_lengths_still_give_a_score(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    huge = [[address, (1 << 64) - 1, text] for address, _, text in kept]
    target = store(tmp_path, [record | {"functions": huge}])
    assert cli.main(["functions", "--json", str(PE64), str(target)]) == cli.OK
    document = json.loads(capsys.readouterr().out)
    assert 0.0 < document["files"][0]["function_score"] <= 100.0


def test_match_and_cluster_drop_the_stored_functions(
    known: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    read = cli._read_digests(known)
    assert read is not None
    assert all(entry.functions is None for entry in read[0])
    assert cli.main(["match", str(PE64), str(known)]) == cli.OK
    assert capsys.readouterr().out.startswith("100.0%")


def test_a_file_with_no_large_function_is_refused(
    known: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["functions", str(ELF32), str(known)]) == cli.REFUSED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no function of 256 bytes or more" in captured.err


def test_a_refused_query_names_its_reason(
    tmp_path: Path, known: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["functions", str(tmp_path / "absent.exe"), str(known)]) == cli.REFUSED
    assert "unreadable: file is absent" in capsys.readouterr().err


def test_a_store_written_by_another_version_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    target = store(tmp_path, [record | {"eous": "0.0.1"}])
    assert cli.main(["functions", str(PE64), str(target)]) == cli.USAGE
    assert f"written by eous 0.0.1, this is eous {version('eous')}" in capsys.readouterr().err


def test_functions_needs_a_file_and_a_digests_file(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["functions", str(PE64)]) == cli.USAGE
    assert "usage" in capsys.readouterr().err


def test_labels_are_counted_on_each_function_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    target = store(tmp_path, [record, record, record])
    labels = tmp_path / "families.tsv"
    labels.write_text(f"{sha256_at(0)}\tVidar\n{sha256_at(1)}\tVidar\n", encoding="utf-8")
    assert cli.main(["functions", str(PE64), str(target), "--labels", str(labels)]) == cli.OK
    captured = capsys.readouterr()
    files, _, rows = captured.out.partition("\n\n")
    assert f"  Vidar  {sha256_at(0)}  " in files.splitlines()[0]
    assert f"  -  {sha256_at(2)}  " in files.splitlines()[2]
    assert all("  3 files  Vidar 2, - 1  " in line for line in rows.splitlines())
    assert "1 digest without a label" in captured.err


def names_file(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "names.tsv"
    target.write_text(text, encoding="utf-8")
    return target


def test_a_named_function_gives_its_name_to_the_match(
    known: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    function = first_function(PE64)
    names = names_file(
        tmp_path,
        f"{sha256_at(0).upper()}\t{function.address:#x}\trc4_init\n"
        f"{sha256_at(0)}\t{function.address:x}\trc4_init\n"
        f"{sha256_at(0)}\tnot hex\tname\nshort\t10\tname\n{sha256_at(0)}\t10\t\nno tab\n",
    )
    assert cli.main(["functions", str(PE64), str(known), "--names", str(names)]) == cli.OK
    captured = capsys.readouterr()
    lines = captured.out.partition("\n\n")[2].splitlines()
    assert lines[0].endswith(f"{sha256_at(0)}:{function.address:#x}  rc4_init")
    assert sum("rc4_init" in line for line in lines) == 1
    assert "4 name lines did not parse" in captured.err


def test_a_name_from_another_file_says_where_it_is(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    weaker = [[address, length, text[:-32] + "0" * 32] for address, length, text in kept]
    target = store(tmp_path, [record | {"functions": kept[1:2]}, record | {"functions": weaker}])
    address = kept[1][0]
    names = names_file(tmp_path, f"{sha256_at(1)}\t{address:x}\trc4_init\n")
    args = ["functions", str(PE64), str(target), "--names", str(names)]
    assert cli.main(args) == cli.OK
    lines = capsys.readouterr().out.partition("\n\n")[2].splitlines()
    assert lines[1].endswith(
        f"{sha256_at(0)}:{address:#x}  rc4_init at {sha256_at(1)}:{address:#x}"
    )
    assert cli.main([*args, "--json"]) == cli.OK
    row = json.loads(capsys.readouterr().out)["functions"][1]
    assert row["match"]["sha256"] == sha256_at(0)
    assert row["name"] == {
        "path": str(PE64),
        "sha256": sha256_at(1),
        "label": None,
        "address": address,
        "name": "rc4_init",
    }


def test_one_function_with_two_names_is_a_usage_error(
    known: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    names = names_file(tmp_path, f"{sha256_at(0)}\t10\tone\n{sha256_at(0)}\t0x10\ttwo\n")
    assert cli.main(["functions", str(PE64), str(known), "--names", str(names)]) == cli.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"{sha256_at(0)} 0x10 carries two names" in captured.err


def test_an_absent_names_file_is_a_usage_error(
    known: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    absent = tmp_path / "absent.tsv"
    assert cli.main(["functions", str(PE64), str(known), "--names", str(absent)]) == cli.USAGE
    assert "No such file" in capsys.readouterr().err


def test_a_hostile_function_name_is_escaped(
    known: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    function = first_function(PE64)
    names = names_file(tmp_path, f"{sha256_at(0)}\t{function.address:x}\tinit\x1b[2K\n")
    assert cli.main(["functions", str(PE64), str(known), "--names", str(names)]) == cli.OK
    printed = capsys.readouterr().out
    assert "\x1b" not in printed
    assert r"init\x1b[2K" in printed


def sizes(printed: str) -> list[int]:
    rows = printed.partition("\n\n")[2].splitlines()
    return [int(row.split("  ")[1].removesuffix(" bytes")) for row in rows]


def addresses(printed: str) -> list[int]:
    return [int(row.split("  ")[0], 16) for row in printed.partition("\n\n")[2].splitlines()]


def test_the_function_lines_follow_the_sort(
    known: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["functions", str(PE64), str(known)]) == cli.OK
    by_address = capsys.readouterr().out
    assert addresses(by_address) == sorted(addresses(by_address))
    assert sizes(by_address) != sorted(sizes(by_address), reverse=True)

    assert cli.main(["functions", str(PE64), str(known), "--sort", "size"]) == cli.OK
    by_size = capsys.readouterr().out
    assert sorted(addresses(by_size)) == addresses(by_address)
    assert sizes(by_size) == sorted(sizes(by_size), reverse=True)


def test_score_files_and_labels_each_sort_largest_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    weaker = [[address, length, text[:-32] + "0" * 32] for address, length, text in kept]
    target = store(
        tmp_path,
        [
            record | {"functions": kept[2:3]},
            record | {"functions": kept[1:3]},
            record | {"functions": weaker[:1]},
        ],
    )
    labels = tmp_path / "families.tsv"
    labels.write_text(f"{sha256_at(0)}\tVidar\n{sha256_at(1)}\tStealc\n", encoding="utf-8")
    first, second, third = (function[0] for function in kept[:3])

    def leading(key: str) -> list[int]:
        args = ["functions", str(PE64), str(target), "--labels", str(labels), "--sort", key]
        assert cli.main(args) == cli.OK
        return addresses(capsys.readouterr().out)[:3]

    assert leading("address") == [first, second, third]
    assert leading("score") == [second, third, first]
    assert leading("files") == [third, first, second]
    assert leading("labels") == [third, second, first]


def test_sorting_by_labels_needs_labels(known: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["functions", str(PE64), str(known), "--sort", "labels"]) == cli.USAGE
    assert "--sort labels needs --labels" in capsys.readouterr().err


def test_top_limits_the_stored_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    target = store(tmp_path, [record, record, record])
    assert cli.main(["functions", str(PE64), str(target), "--top", "2"]) == cli.OK
    assert len(capsys.readouterr().out.partition("\n\n")[0].splitlines()) == 2


def test_an_unmatched_function_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    target = store(tmp_path, [record | {"functions": kept[:1]}])
    assert cli.main(["functions", str(PE64), str(target)]) == cli.OK
    captured = capsys.readouterr()
    function = first_function(PE64)
    rows = captured.out.partition("\n\n")[2].splitlines()
    assert rows[0].startswith(f"{function.address:#x}  {function.length} bytes  100.0%  1 file  ")
    assert rows[-1].endswith(" bytes  no match")
    assert not captured.out.startswith("functions 100.0%")


def test_functions_json_carries_the_files_and_every_function(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    [record] = hashed(capsys, "--functions", str(PE64))
    kept = record["functions"]
    assert isinstance(kept, list)
    target = store(tmp_path, [record | {"functions": kept[:1]}])
    labels = tmp_path / "families.tsv"
    labels.write_text(f"{sha256_at(0)}\tVidar\n", encoding="utf-8")
    function = first_function(PE64)
    names = names_file(tmp_path, f"{sha256_at(0)}\t{function.address:x}\trc4_init\n")
    args = ["functions", "--json", str(PE64), str(target)]
    assert cli.main([*args, "--labels", str(labels), "--names", str(names)]) == cli.OK
    document = json.loads(capsys.readouterr().out)
    member = {"path": str(PE64), "sha256": sha256_at(0), "label": "Vidar"}
    assert document["query"] == str(PE64)
    assert document["sha256"] == record["sha256"]
    assert document["target"] == "pe64"
    assert document["files"][0] | member == document["files"][0]
    assert document["files"][0]["similarity"] == 100.0
    assert 0.0 < document["files"][0]["function_score"] < 100.0
    assert document["functions"][0] == {
        "address": function.address,
        "length": function.length,
        "score": 100.0,
        "files": 1,
        "labels": {"Vidar": 1},
        "match": member | {"address": function.address},
        "name": member | {"address": function.address, "name": "rc4_init"},
    }
    assert (
        document["functions"][-1] | {"score": None, "files": 0, "match": None, "name": None}
        == (document["functions"][-1])
    )
