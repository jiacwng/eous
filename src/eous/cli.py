# Argument parsing, output formatting and exit codes.

from __future__ import annotations

import argparse
import contextlib
import errno
import io
import itertools
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

import numpy

from eous import cluster, digest, functions, records, toolchain

if TYPE_CHECKING:
    from eous import report

OK = 0
REFUSED = 1
USAGE = 2
INTERNAL = 3

SORTS = ("address", "size", "score", "files", "labels")

# Windows reports a write to a closed pipe as EINVAL where POSIX raises EPIPE.
CLOSED_PIPE = (errno.EPIPE, errno.EINVAL) if sys.platform == "win32" else (errno.EPIPE,)


DESCRIPTION = """\
Code-similarity digests for PE and ELF binaries on x86 and x86-64.

A digest summarises the instruction sequences a program contains, so two binaries
built from similar code produce digests that agree in many places."""

EPILOGUE = """\
digest format:
  EO1:pe64:1694:37e6ad029a3a70b0...
   |   |    |    |
   |   |    |    the sketch, 512 bits as 128 hex characters
   |   |    how many distinct instruction sequences were found
   |   the target: pe32, pe64, elf32 or elf64
   the format version, so two digests compare only when it matches

two digests compare only when their targets match. Rebuilding the same source
for another target changes which instructions the compiler emits, so the score
lands where unrelated files already sit and carries no information.

exit codes:
  0  every file digested, or the reader closed the output early
  1  at least one file or directory got no digest, with the cause on stderr
  2  usage error
  3  internal error

examples:
  eous hash program.exe
  eous hash samples/
  eous hash --json samples/ > digests.jsonl
  eous compare old.exe new.exe
  eous compare EO1:pe64:2841:1f0a... EO1:pe64:1694:37e6...
  eous match suspect.exe digests.jsonl
  eous match suspect.exe digests.jsonl --min 80 --labels families.tsv
  eous cross digests.jsonl --min 40
  eous cluster digests.jsonl --min 90
  eous hash --json --functions samples/ > functions.jsonl
  eous functions suspect.exe functions.jsonl --labels families.tsv --sort files

reading a comparison:
  similarity:  36.5% +/- 8.1
  containment: old.exe in new.exe   96.0%
               new.exe in old.exe   37.0%

  The +/- figure is the 95% margin of error, since 256 slots estimate the overlap.
  Treat results whose ranges overlap as too close to rank.

  Containment runs both ways, and the gap between them says which side is the
  superset. Above a 4x size difference both figures are withheld.

a skipped file names its cause:
  eous: sample.macho:  unsupported_format: macho
  eous: sample.elf:    unsupported_arch: AARCH64
  eous: packed.exe:    packed: 100% of executable code is compressed
  eous: library.dll:   managed: il only, no native code
  eous: resources.dll: no_code: no executable section
  eous: notes.txt:     unreadable: no recognised container

every file eous declines to digest is reported with its cause. A digest is
withheld whenever the code inside stays unreadable."""


FUNCTIONS_DESCRIPTION = """\
Find the functions of one file and look each of them up in a file that
`eous hash --json --functions` wrote.

The stored files come first, best first, each with its function score beside
its whole-file score. The function score is the share of the function bytes of
both files that match, each match weighted by its score and counting from a
score of 50.

One line per function of the query follows: its address, its size, its best
score, how many stored files hold a match, and the file and address of the
best match. With --labels each line counts the labels of those files. With
--names it ends with the name of the closest named match, and with where that
match is when it is not the best match.

A function starts at the target of a direct call, at the entry point, at an
export, at a TLS callback or an ELF constructor, and at the destination of a
direct jump from any of these. A function reached only by an indirect call is
missed, and one that follows it is then read as part of the function before.
Only functions of 256 bytes or more get a digest. Addresses are virtual
addresses at the preferred image base."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eous",
        description=DESCRIPTION,
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")

    commands = parser.add_subparsers(dest="command", metavar="command")
    hash_command = commands.add_parser(
        "hash",
        help="print a digest for each file",
        description="Print one digest per file, or the cause when a file is skipped. "
        "A directory is walked, and every file under it is digested.",
    )
    hash_command.add_argument("paths", nargs="+", type=Path, metavar="FILE-OR-DIR")
    hash_command.add_argument(
        "--quiet", action="store_true", help="suppress the lines for skipped files on stderr"
    )
    hash_command.add_argument(
        "--functions",
        action="store_true",
        help="with --json, add a digest for each function of 256 bytes or more",
    )

    compare_command = commands.add_parser(
        "compare",
        help="score two files or two digests against each other",
        description="Score two inputs. Each may be a file or a digest string.",
    )
    compare_command.add_argument("left", metavar="FILE-OR-DIGEST")
    compare_command.add_argument("right", metavar="FILE-OR-DIGEST")

    match_command = commands.add_parser(
        "match",
        help="rank a file or digest against a file of digests",
        description="Score one input against every digest in a file, best first. "
        "The file is what `eous hash --json` writes, one record per line. Entries built "
        "for another target are skipped.",
    )
    match_command.add_argument("query", metavar="FILE-OR-DIGEST")
    match_command.add_argument("known", type=Path, metavar="DIGESTS-FILE")
    match_command.add_argument(
        "--top", type=_count, default=10, help="how many results to print, default 10"
    )

    cross_command = commands.add_parser(
        "cross",
        help="score every pair in a file of digests",
        description="Score each digest in a file against every other, in the order they "
        "were read. The file is what `eous hash --json` writes. Each line is a score, then "
        "the paths of the two digests. With --labels the label of each digest comes before "
        "its path. Pairs are scored inside each "
        "target, since two digests compare only when their targets match, and the "
        "targets follow in the order they first appear.",
    )
    cross_command.add_argument("known", type=Path, metavar="DIGESTS-FILE")

    cluster_command = commands.add_parser(
        "cluster",
        help="group the digests in a file by similarity",
        description="Give every digest in a file a cluster by single-linkage clustering. Two "
        "digests share a cluster when a chain of pairs scoring at least --min joins them, so "
        "a low --min chains unrelated files together. The file is what `eous hash --json` "
        "writes. Each line is a cluster name, then the sha256 and path of one digest. With "
        "--labels the label comes first, and a cluster of two or more digests opens with a "
        "count of its labels. The name is the target and a number, counted in the order the "
        "clusters first appear, and a digest that joins nothing gets a cluster to "
        "itself. A cluster stays inside one target, since two digests compare only when "
        "their targets match, and the targets follow in the order they first appear.",
    )
    cluster_command.add_argument("known", type=Path, metavar="DIGESTS-FILE")
    cluster_command.add_argument(
        "--min",
        type=_percentage,
        required=True,
        dest="minimum",
        metavar="PERCENT",
        help="join two digests scoring at least this percentage",
    )

    functions_command = commands.add_parser(
        "functions",
        help="match the functions of a file against the functions of stored files",
        description=FUNCTIONS_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    functions_command.add_argument("query", type=Path, metavar="FILE")
    functions_command.add_argument("known", type=Path, metavar="DIGESTS-FILE")
    functions_command.add_argument(
        "--top", type=_count, default=10, help="how many stored files to print, default 10"
    )
    functions_command.add_argument(
        "--sort",
        choices=SORTS,
        default="address",
        help="order the function lines: by address, or largest first by size, score, "
        "matching files or distinct labels; default address",
    )
    functions_command.add_argument(
        "--names",
        type=Path,
        metavar="NAMES-FILE",
        help="a file of sha256, a tab, a hexadecimal address, a tab, then a function name",
    )

    for command in (match_command, cross_command, cluster_command, functions_command):
        command.add_argument(
            "--labels",
            type=Path,
            metavar="LABELS-FILE",
            help="a file of sha256, a tab, then a label, shown beside each digest",
        )
    for command in (match_command, cross_command):
        command.add_argument(
            "--min",
            type=_percentage,
            default=0.0,
            dest="minimum",
            metavar="PERCENT",
            help="omit results scoring below this percentage",
        )
    for command in commands.choices.values():
        command.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def _count(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        value = -1
    if value < 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a count of 0 or more")
    return value


def _percentage(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = math.nan
    if not 0.0 <= value <= 100.0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a percentage from 0 to 100")
    return value


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command is None and not args.version:
            parser.error("a command is required")
    except SystemExit as exc:
        return OK if exc.code == 0 else USAGE

    try:
        code = _dispatch(args)
        sys.stdout.flush()
    except Exception as exc:
        if _closed_pipe(exc):
            _quieten_stdout()
            return OK
        _warn(f"internal error: {exc}")
        try:
            sys.stdout.flush()
        except OSError:
            _quieten_stdout()
        return INTERNAL
    return code


def _dispatch(args: argparse.Namespace) -> int:
    if args.version:
        print(f"eous {_installed_version()}")
        for name, value in toolchain.engines().items():
            print(f"{name} {value}")
        return OK
    runners: dict[str, Callable[[argparse.Namespace], int]] = {
        "hash": _run_hash,
        "compare": _run_compare,
        "match": _run_match,
        "cross": _run_cross,
        "cluster": _run_cluster,
        "functions": _run_functions,
    }
    return runners[args.command](args)


def _closed_pipe(exc: Exception) -> bool:
    return isinstance(exc, OSError) and exc.errno in CLOSED_PIPE


def _warn(message: str) -> None:
    print(f"eous: {message}", file=sys.stderr)


def _quieten_stdout() -> None:
    with contextlib.suppress(OSError, ValueError):
        target = sys.stdout.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, target)
        os.close(devnull)


def _run_hash(args: argparse.Namespace) -> int:
    from eous import report

    if args.functions and not args.json:
        _warn("--functions needs --json")
        return USAGE

    paths, failures = _expand(args.paths)
    unwalked = [
        report.Analysis(
            Path(str(failure.filename)),
            None,
            None,
            report.Refusal(report.UNREADABLE, str(failure.strerror)),
        )
        for failure in failures
    ]
    if not paths and not unwalked:
        named = ", ".join(_readable(str(path)) for path in args.paths)
        _warn(f"{named}: no file to hash")
        return USAGE

    labelled = len(paths) > 1 or paths != args.paths or bool(unwalked)
    refused = False
    failed = False

    try:
        analysed = _analyse(paths, args.functions) if paths else ()
        for result in itertools.chain(unwalked, analysed):
            refused = refused or result.refusal is not None
            failed = failed or _failed(result)
            if args.json:
                print(json.dumps(_as_record(result)), flush=True)
            else:
                _print_line(result, labelled=labelled, quiet=args.quiet)
    except OSError as exc:
        if not (refused and _closed_pipe(exc)):
            raise
        _quieten_stdout()

    return INTERNAL if failed else REFUSED if refused else OK


def _failed(result: report.Analysis) -> bool:
    from eous import report

    return result.refusal is not None and result.refusal.reason == report.INTERNAL_ERROR


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _looks_like_a_path(text: str) -> bool:
    return ":" not in text or "/" in text or "\\" in text or Path(text).suffix != ""


def _as_digest(text: str) -> tuple[str | None, int]:
    if not os.path.isfile(text) and not _looks_like_a_path(text):
        return (text, OK)

    [result] = _analyse([Path(text)], with_functions=False)
    if result.refusal is not None:
        _warn(_refusal_line(result.path, result.refusal))
        return (None, INTERNAL if _failed(result) else REFUSED)
    return (result.digest, OK)


def _run_compare(args: argparse.Namespace) -> int:
    resolved: list[str] = []
    named: list[str | None] = []
    for text in (args.left, args.right):
        found, code = _as_digest(text)
        if found is None:
            return code
        resolved.append(found)
        named.append(None if found is text else text)

    try:
        left, right = (digest.parse(text) for text in resolved)
        scores = digest.compare(left, right)
    except digest.DigestError as exc:
        _warn(str(exc))
        return USAGE

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "target": left.target,
                    "comparison": _as_scores(scores, named),
                },
                indent=1,
            )
        )
    else:
        labels = [name or side for name, side in zip(named, ("left", "right"), strict=True)]
        _print_scores(scores, labels)
    return OK


def _read[T](path: Path, reader: Callable[[Path], T]) -> T | None:
    try:
        return reader(path)
    except OSError as exc:
        _warn(f"{_readable(str(path))}: {exc.strerror}")
    except records.RecordsError as exc:
        _warn(f"{_readable(str(path))}: {_readable(str(exc))}")
    return None


def _read_digests(path: Path, functions: bool = False) -> tuple[list[records.Entry], int] | None:
    read = _read(path, lambda held: records.digests(held, functions))
    if read is None:
        return None
    if read.unparsed:
        _warn(f"{_plural(read.unparsed, 'line')} did not parse")
    if read.repeated:
        _warn(f"{_plural(read.repeated, 'digest')} skipped, sha256 already read")
    return read.entries, read.unparsed


def _written_here(path: Path, entries: list[records.Entry]) -> bool:
    if not entries or entries[0].eous == _installed_version():
        return True
    _warn(
        f"{_readable(str(path))}: written by eous {_readable(entries[0].eous)}, "
        f"this is eous {_installed_version()}"
    )
    return False


def _read_labels(path: Path) -> dict[str, str] | None:
    read = _read(path, records.labels)
    if read is None:
        return None
    labels, unparsed = read
    if unparsed:
        _warn(f"{_plural(unparsed, 'label line')} did not parse")
    return labels


def _labels_for(path: Path, entries: list[records.Entry]) -> dict[str, str] | None:
    labels = _read_labels(path)
    if labels is None:
        return None
    bare = sum(1 for entry in entries if entry.sha256 not in labels)
    if bare:
        _warn(f"{_plural(bare, 'digest')} without a label")
    return labels


def _described(entry: records.Entry, labels: dict[str, str] | None) -> str:
    fields = [entry.sha256, entry.path]
    if labels is not None:
        fields = [labels.get(entry.sha256, "-"), *fields]
    return "  ".join(_readable(field) for field in fields)


def _as_member(entry: records.Entry, labels: dict[str, str] | None) -> dict[str, str | None]:
    label = None if labels is None else labels.get(entry.sha256)
    return {"path": entry.path, "sha256": entry.sha256, "label": label}


def _label_counts(
    held: list[records.Entry], labels: dict[str, str] | None
) -> dict[str, int] | None:
    if labels is None:
        return None
    counts = Counter(labels[entry.sha256] for entry in held if entry.sha256 in labels)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _counted(held: list[records.Entry], counts: dict[str, int]) -> str:
    parts = [f"{_readable(label)} {count}" for label, count in counts.items()]
    bare = len(held) - sum(counts.values())
    if bare:
        parts.append(f"- {bare}")
    return ", ".join(parts)


def _summary(held: list[records.Entry], counts: dict[str, int]) -> str:
    return f"{_plural(len(held), 'digest')}: {_counted(held, counts)}"


def _run_match(args: argparse.Namespace) -> int:
    text, code = _as_digest(args.query)
    if text is None:
        return code

    try:
        query = digest.parse(text)
    except digest.DigestError as exc:
        _warn(str(exc))
        return USAGE

    read = _read_digests(args.known)
    if read is None:
        return USAGE
    entries, unparsed = read
    hashed_here = text != args.query
    if hashed_here and not _written_here(args.known, entries):
        return USAGE
    kept = [entry for entry in entries if entry.sketch.target == query.target]
    other_target = len(entries) - len(kept)

    if not kept:
        _warn(f"{_readable(str(args.known))}: contains no {query.target} digest")
        return USAGE

    labels = None
    if args.labels is not None:
        labels = _labels_for(args.labels, kept)
        if labels is None:
            return USAGE

    sketches = [entry.sketch for entry in kept]
    scored, spread = digest.score(
        digest.unpack_all(sketches),
        digest.cardinalities(sketches),
        digest.unpack(query),
        query.cardinality,
    )
    order = sorted(zip(scored, spread, kept, strict=True), key=lambda row: -row[0])
    cleared = [row for row in order if row[0] >= args.minimum]
    ranked = cleared[: args.top]
    below_minimum = len(order) - len(cleared)
    shown = [entry for _, _, entry in ranked]
    counts = _label_counts(shown, labels)

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "query": args.query,
                    "target": query.target,
                    "skipped_other_target": other_target,
                    "unparsed": unparsed,
                    "below_minimum": below_minimum,
                    "labels": counts,
                    "matches": [
                        {**_as_member(entry, labels), **_rounded(score, margin)}
                        for score, margin, entry in ranked
                    ],
                },
                indent=1,
            )
        )
    else:
        for score, margin, entry in ranked:
            print(f"{_scored(score, margin)}  {_described(entry, labels)}")

    if counts is not None and len(shown) > 1:
        _warn(_summary(shown, counts))
    if other_target:
        _warn(f"{_plural(other_target, 'digest')} skipped, built for another target")
    if below_minimum:
        _warn(f"{_plural(below_minimum, 'digest')} scored below {args.minimum:g}%")
    return OK


def _by_target(sketches: list[digest.Sketch]) -> dict[str, list[int]]:
    grouped: dict[str, list[int]] = {}
    for index, sketch in enumerate(sketches):
        grouped.setdefault(sketch.target, []).append(index)
    return grouped


def _run_cross(args: argparse.Namespace) -> int:
    read = _read_digests(args.known)
    if read is None:
        return USAGE
    entries, unparsed = read
    paths = [entry.path for entry in entries]
    sketches = [entry.sketch for entry in entries]

    grouped = {target: rows for target, rows in _by_target(sketches).items() if len(rows) > 1}
    if not grouped:
        _warn(f"{_readable(str(args.known))}: contains fewer than two digests of any one target")
        return USAGE

    labels = None
    if args.labels is not None:
        paired = [entries[index] for rows in grouped.values() for index in rows]
        labels = _labels_for(args.labels, paired)
        if labels is None:
            return USAGE

    named = [None if labels is None else labels.get(entry.sha256) for entry in entries]
    shown = [
        _readable(path) if labels is None else f"{_readable(name or '-')}  {_readable(path)}"
        for name, path in zip(named, paths, strict=True)
    ]
    targets = list(grouped)
    alone = len(sketches) - sum(len(grouped[target]) for target in targets)
    below_minimum = 0
    total = 0

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "digests": len(sketches),
                    "targets": targets,
                    "unparsed": unparsed,
                    "skipped_alone_in_target": alone,
                }
            )
        )

    for target in targets:
        members = grouped[target]
        rows = digest.pack([sketches[index] for index in members])
        cardinalities = digest.cardinalities([sketches[index] for index in members])
        for offset in range(len(members) - 1):
            left = members[offset]
            after = (offset + 1) * digest.SKETCH_BYTES
            agreed = digest.agreement(rows[after:], rows[after - digest.SKETCH_BYTES : after])
            scores = digest.similarity(
                agreed, cardinalities[offset + 1 :], sketches[left].cardinality
            )
            total += len(scores)
            kept = numpy.flatnonzero(scores >= args.minimum)
            below_minimum += len(scores) - len(kept)
            spread = digest.margin(agreed[kept])
            for step, score, margin in zip(kept.tolist(), scores[kept], spread, strict=True):
                right = members[offset + 1 + step]
                if args.json:
                    print(
                        json.dumps(
                            {
                                "left": paths[left],
                                "right": paths[right],
                                "left_label": named[left],
                                "right_label": named[right],
                                "target": target,
                                **_rounded(score, margin),
                            }
                        )
                    )
                else:
                    print(f"{_scored(score, margin)}  {shown[left]}  {shown[right]}")

    if args.json:
        print(json.dumps({"pairs_scored": total, "below_minimum": below_minimum}))

    _warn(f"{_plural(total, 'pair')} scored across {', '.join(targets)}")
    if alone:
        _warn(f"{_plural(alone, 'digest')} skipped, alone in its target")
    if below_minimum:
        _warn(f"{_plural(below_minimum, 'pair')} scored below {args.minimum:g}%")
    return OK


def _run_cluster(args: argparse.Namespace) -> int:
    read = _read_digests(args.known)
    if read is None:
        return USAGE
    entries, unparsed = read
    sketches = [entry.sketch for entry in entries]

    if not sketches:
        _warn(f"{_readable(str(args.known))}: contains no digest")
        return USAGE

    labels = None
    if args.labels is not None:
        labels = _labels_for(args.labels, entries)
        if labels is None:
            return USAGE

    grouped = _by_target(sketches)
    total = 0
    alone = 0

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "digests": len(sketches),
                    "targets": list(grouped),
                    "unparsed": unparsed,
                }
            )
        )

    for target, members in grouped.items():
        found = cluster.clusters([sketches[index] for index in members], args.minimum)
        total += len(found)
        alone += sum(1 for places in found if len(places) == 1)
        for number, places in enumerate(found, start=1):
            name = f"{target}:{number}"
            held = [entries[members[place]] for place in places]
            counts = _label_counts(held, labels)
            if args.json:
                print(
                    json.dumps(
                        {
                            "cluster": name,
                            "target": target,
                            "size": len(held),
                            "labels": counts,
                            "members": [_as_member(entry, labels) for entry in held],
                        }
                    )
                )
            else:
                if counts is not None and len(held) > 1:
                    print(f"{name}  {_summary(held, counts)}")
                for entry in held:
                    print(f"{name}  {_described(entry, labels)}")

    if args.json:
        print(json.dumps({"clusters": total, "singletons": alone}))

    _warn(
        f"{_plural(len(sketches), 'digest')} in {_plural(total, 'cluster')}, "
        f"{alone} holding one digest"
    )
    return OK


@dataclass(frozen=True)
class _Row:
    function: records.Function
    score: float
    holding: list[records.Entry]
    closest: records.Entry
    closest_address: int
    name: str | None
    named: records.Entry
    named_address: int


def _read_names(path: Path) -> dict[tuple[str, int], str] | None:
    read = _read(path, records.names)
    if read is None:
        return None
    names, unparsed = read
    if unparsed:
        _warn(f"{_plural(unparsed, 'name line')} did not parse")
    return names


@dataclass(frozen=True)
class _Stored:
    kept: list[records.Entry]
    held: list[records.Function]
    owners: list[int]
    starts: list[int]
    other_target: int
    bare: int
    broken: int


def _stored(entries: list[records.Entry], target: str) -> _Stored:
    kept: list[records.Entry] = []
    held: list[records.Function] = []
    owners: list[int] = []
    starts: list[int] = []
    other_target = 0
    bare = 0
    broken = 0
    for entry in entries:
        if entry.sketch.target != target:
            other_target += 1
            continue
        found, failed = records.functions_of(entry, target)
        broken += failed
        if not found:
            bare += 1
            continue
        starts.append(len(held))
        owners += [len(kept)] * len(found)
        held += found
        kept.append(entry)
    return _Stored(kept, held, owners, starts, other_target, bare, broken)


def _rows(
    asked: list[records.Function],
    matched: functions.Matched,
    stored: _Stored,
    names: dict[tuple[str, int], str],
) -> list[_Row]:
    kept, held, owners = stored.kept, stored.held, stored.owners
    rows: list[_Row] = []
    for place, function in enumerate(asked):
        best = int(matched.closest[place])
        named = int(matched.named[place])
        source = named if named >= 0 else best
        rows.append(
            _Row(
                function,
                float(matched.in_file[place].max()),
                [
                    kept[file]
                    for file in numpy.flatnonzero(matched.in_file[place] >= functions.MATCH)
                ],
                kept[owners[best]],
                held[best].address,
                names[kept[owners[source]].sha256, held[source].address] if named >= 0 else None,
                kept[owners[source]],
                held[source].address,
            )
        )
    return rows


def _table(found: list[records.Function]) -> functions.Table:
    return functions.table([(function.length, function.sketch) for function in found])


def _run_functions(args: argparse.Namespace) -> int:
    [result] = _analyse([args.query], with_functions=True)
    if result.refusal is not None:
        _warn(_refusal_line(result.path, result.refusal))
        return INTERNAL if _failed(result) else REFUSED
    if result.digest is None or result.functions is None:
        raise RuntimeError("a digested file came back without its functions")
    query = digest.parse(result.digest)
    asked = [
        records.Function(f.address, f.length, digest.parse(f.digest)) for f in result.functions
    ]
    if not asked:
        size = functions.FUNCTION_BYTES
        _warn(f"{_readable(str(args.query))}: no function of {size} bytes or more")
        return REFUSED

    read = _read_digests(args.known, functions=True)
    if read is None:
        return USAGE
    entries, unparsed = read
    if not _written_here(args.known, entries):
        return USAGE

    stored = _stored([entry for entry in entries if entry.sha256 != result.sha256], query.target)
    kept, held, owners = stored.kept, stored.held, stored.owners
    other_target, bare, broken = stored.other_target, stored.bare, stored.broken
    if broken:
        _warn(f"{_plural(broken, 'stored function')} did not parse")
    if not kept:
        _warn(f"{_readable(str(args.known))}: contains no {query.target} file with functions")
        return USAGE

    labels = None
    if args.labels is not None:
        labels = _labels_for(args.labels, kept)
        if labels is None:
            return USAGE
    if args.sort == "labels" and labels is None:
        _warn("--sort labels needs --labels")
        return USAGE
    names: dict[tuple[str, int], str] = {}
    if args.names is not None:
        read_names = _read_names(args.names)
        if read_names is None:
            return USAGE
        names = read_names

    with_names = [
        place
        for place, (function, owner) in enumerate(zip(held, owners, strict=True))
        if (kept[owner].sha256, function.address) in names
    ]
    matched = functions.match(
        _table(asked),
        _table(held),
        numpy.array(stored.starts, dtype=numpy.intp),
        numpy.array(with_names, dtype=numpy.intp),
    )

    sketches = [entry.sketch for entry in kept]
    whole, spread = digest.score(
        digest.unpack_all(sketches),
        digest.cardinalities(sketches),
        digest.unpack(query),
        query.cardinality,
    )
    ranked = sorted(range(len(kept)), key=lambda place: -matched.files[place])[: args.top]
    files = [
        {
            **_as_member(kept[place], labels),
            "function_score": round(float(matched.files[place]), 4),
            **_rounded(whole[place], spread[place]),
        }
        for place in ranked
    ]

    rows = _rows(asked, matched, stored, names)
    keys: dict[str, Callable[[_Row], float]] = {
        "address": lambda row: 0.0,
        "size": lambda row: row.function.length,
        "score": lambda row: row.score,
        "files": lambda row: len(row.holding),
        "labels": lambda row: len(_label_counts(row.holding, labels) or {}),
    }
    rows.sort(key=lambda row: (-keys[args.sort](row), row.function.address))
    hit = sum(1 for row in rows if row.holding)

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "query": str(args.query),
                    "sha256": result.sha256,
                    "target": query.target,
                    "skipped_other_target": other_target,
                    "skipped_without_functions": bare,
                    "unparsed": unparsed + broken,
                    "files": files,
                    "functions": [_as_function(row, labels) for row in rows],
                },
                indent=1,
            )
        )
    else:
        for place, file in zip(ranked, files, strict=True):
            scored = _scored(whole[place], spread[place])
            print(
                f"functions {file['function_score']:5.1f}%  file {scored}  "
                f"{_described(kept[place], labels)}"
            )
        print()
        for row in rows:
            print(_function_line(row, labels))

    _warn(f"{_plural(len(asked), 'function')}, {hit} matched in {_plural(len(kept), 'file')}")
    if other_target:
        _warn(f"{_plural(other_target, 'file')} skipped, built for another target")
    if bare:
        _warn(f"{_plural(bare, 'file')} skipped, stored without functions")
    return OK


def _as_function(row: _Row, labels: dict[str, str] | None) -> dict[str, object]:
    matched = bool(row.holding)
    return {
        "address": row.function.address,
        "length": row.function.length,
        "score": round(row.score, 4) if matched else None,
        "files": len(row.holding),
        "labels": _label_counts(row.holding, labels),
        "match": {**_as_member(row.closest, labels), "address": row.closest_address}
        if matched
        else None,
        "name": {**_as_member(row.named, labels), "address": row.named_address, "name": row.name}
        if row.name is not None
        else None,
    }


def _function_line(row: _Row, labels: dict[str, str] | None) -> str:
    fields = [f"{row.function.address:#x}", f"{row.function.length} bytes"]
    if not row.holding:
        return "  ".join([*fields, "no match"])
    fields += [f"{row.score:5.1f}%", _plural(len(row.holding), "file")]
    counts = _label_counts(row.holding, labels)
    if counts is not None:
        fields.append(_counted(row.holding, counts))
    closest = f"{row.closest.sha256}:{row.closest_address:#x}"
    fields.append(closest)
    if row.name is not None:
        named = f"{row.named.sha256}:{row.named_address:#x}"
        fields.append(
            _readable(row.name) if named == closest else f"{_readable(row.name)} at {named}"
        )
    return "  ".join(fields)


def _scored(score: float, margin: float) -> str:
    return f"{float(score):5.1f}% +/- {float(margin):3.1f}"


def _print_scores(scores: digest.Scores, labels: list[str]) -> None:
    print(f"similarity:  {scores.similarity:.1f}% +/- {scores.uncertainty:.1f}")

    if scores.left_in_right is None or scores.right_in_left is None:
        ratio = f"{digest.MAX_CONTAINMENT_RATIO:g}x"
        print(f"containment: n/a (the two differ in size by more than {ratio})")
        return

    left, right = (_readable(label) for label in labels)
    width = max(len(left), len(right))
    print(f"containment: {left:<{width}} in {right:<{width}}  {scores.left_in_right:>5.1f}%")
    print(f"             {right:<{width}} in {left:<{width}}  {scores.right_in_left:>5.1f}%")


def _rounded(score: float, margin: float) -> dict[str, float]:
    return {"similarity": round(float(score), 4), "uncertainty": round(float(margin), 4)}


def _as_scores(scores: digest.Scores, labels: list[str | None]) -> dict[str, object]:
    def rounded(value: float | None) -> float | None:
        return None if value is None else round(value, 4)

    return {
        "left": labels[0],
        "right": labels[1],
        **_rounded(scores.similarity, scores.uncertainty),
        "left_in_right": rounded(scores.left_in_right),
        "right_in_left": rounded(scores.right_in_left),
    }


def _analyse(paths: list[Path], with_functions: bool) -> Iterator[report.Analysis]:
    from eous import pool, report

    return pool.analyse(paths, report.analyse_functions if with_functions else report.analyse)


def _expand(paths: list[Path]) -> tuple[list[Path], list[OSError]]:
    found: list[Path] = []
    seen: set[Path] = set()
    failures: list[OSError] = []
    for path in paths:
        if os.path.isdir(path):
            walked = sorted(
                p
                for root, _, names in os.walk(path, onerror=failures.append)
                for p in (Path(root) / name for name in names)
                if os.path.isfile(p)
            )
        else:
            walked = [path]
        for candidate in walked:
            real = Path(os.path.realpath(candidate))
            if real not in seen:
                seen.add(real)
                found.append(candidate)
    return found, failures


def _readable(text: str) -> str:
    # A section name and a file name both come from the sample. A newline in one would
    # forge a second line of output, and an escape sequence would rewrite the terminal.
    return "".join(
        character
        if character.isprintable()
        else f"\\x{ord(character):02x}"
        if ord(character) < 256
        else f"\\u{ord(character):04x}"
        for character in text
    )


def _refusal_line(path: Path, refusal: report.Refusal) -> str:
    return f"{_readable(str(path))}: {refusal.reason}: {_readable(refusal.detail)}"


def _print_line(result: report.Analysis, labelled: bool, quiet: bool) -> None:
    if result.digest is not None:
        path = _readable(str(result.path))
        line = f"{path}  {result.digest}" if labelled else result.digest
        print(line, flush=True)
    elif result.refusal is not None and not quiet:
        _warn(_refusal_line(result.path, result.refusal))


def _as_record(result: report.Analysis) -> dict[str, object]:
    record: dict[str, object] = {
        "sha256": result.sha256,
        "digest": result.digest,
        "path": str(result.path),
        "reason": result.refusal.reason if result.refusal else None,
        "detail": result.refusal.detail if result.refusal else None,
        "eous": _installed_version(),
    }
    if result.functions is not None:
        record["functions"] = [[f.address, f.length, f.digest] for f in result.functions]
    return record


def _meta() -> dict[str, str]:
    return {"eous": _installed_version(), **toolchain.engines()}


def _installed_version() -> str:
    try:
        return version("eous")
    except PackageNotFoundError:
        return "0.0.0+unknown"


if __name__ == "__main__":
    sys.exit(main())
