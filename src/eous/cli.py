# Argument parsing, output formatting and exit codes.

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import os
import sys
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from eous import digest, report, toolchain

OK = 0
REFUSED = 1
USAGE = 2
INTERNAL = 3

# Windows reports a write to a closed pipe as EINVAL where POSIX raises EPIPE.
CLOSED_PIPE = (errno.EPIPE, errno.EINVAL) if sys.platform == "win32" else (errno.EPIPE,)


DESCRIPTION = """\
Code-similarity digests for PE and ELF binaries on x86 and x86-64.

A digest summarises the instruction sequences a program contains, so two binaries
built from similar code produce digests that agree in many places."""

EPILOGUE = """\
digest format:
  EO1:pe64:3155:5cfc520f897cc0cf...
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
  1  at least one file refused, with the cause on stderr
  2  usage error
  3  internal error

examples:
  eous hash program.exe
  eous hash samples/ > digests.txt
  eous hash --json samples/ > digests.json
  eous compare old.exe new.exe
  eous compare EO1:pe64:2841:1f0a... EO1:pe64:3155:5cfc...
  eous match suspect.exe digests.txt
  eous match suspect.exe digests.txt --min 80
  eous cross digests.txt --min 40

reading a comparison:
  similarity:  27.6% +/- 8.0 (19.6% to 35.6%)
  containment: old.exe in new.exe   94.1% +/- 12
               new.exe in old.exe   41.2% +/- 5

  The +/- figure is the margin of error, since 256 slots estimate the overlap.
  It narrows as scores approach 100%. Two results whose ranges overlap are
  not separable.

  Containment runs both ways, and the gap between them says which side is the
  superset. It comes from the same estimate, so its margin is wider, and it
  grows with the size difference. Above 4x both figures are withheld.

a refusal names its cause:
  eous: sample.macho: unsupported_format: macho
  eous: sample.elf:   unsupported_arch: AARCH64
  eous: packed.exe:   packed: 100% of executable code is compressed
  eous: library.dll:  managed: il only, no native code
  eous: notes.txt:    unreadable: no recognised container

every file eous declines to digest is reported with its cause. A digest is
withheld whenever the code inside stays unreadable."""


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
        description="Print one digest per file, or the cause when a file is refused. "
        "A directory is walked, and every file under it is digested.",
    )
    hash_command.add_argument("paths", nargs="*", type=Path, metavar="FILE-OR-DIR")
    hash_command.add_argument("--json", action="store_true", help="machine-readable output")
    hash_command.add_argument(
        "--quiet", action="store_true", help="suppress the refusal lines on stderr"
    )

    compare_command = commands.add_parser(
        "compare",
        help="score two files or two digests against each other",
        description="Score two inputs. Each may be a file or a digest string.",
    )
    compare_command.add_argument("left", nargs="?", metavar="FILE-OR-DIGEST")
    compare_command.add_argument("right", nargs="?", metavar="FILE-OR-DIGEST")
    compare_command.add_argument("--json", action="store_true", help="machine-readable output")

    match_command = commands.add_parser(
        "match",
        help="rank a file or digest against a file of digests",
        description="Score one input against every digest in a file, best first. "
        "The file is what `eous hash` writes, one digest per line, with or without "
        "a leading path. Entries built for another target are skipped.",
    )
    match_command.add_argument("query", nargs="?", metavar="FILE-OR-DIGEST")
    match_command.add_argument("known", nargs="?", type=Path, metavar="DIGESTS-FILE")
    match_command.add_argument(
        "--top", type=int, default=10, help="how many results to print, default 10"
    )
    match_command.add_argument(
        "--min",
        type=float,
        default=0.0,
        dest="minimum",
        metavar="PERCENT",
        help="omit results scoring below this percentage",
    )
    match_command.add_argument("--json", action="store_true", help="machine-readable output")

    cross_command = commands.add_parser(
        "cross",
        help="score every pair in a file of digests",
        description="Score each digest in a file against every other, in the order they "
        "were read. The file is what `eous hash` writes. Pairs are scored inside each "
        "target, since two digests compare only when their targets match.",
    )
    cross_command.add_argument("known", nargs="?", type=Path, metavar="DIGESTS-FILE")
    cross_command.add_argument(
        "--min",
        type=float,
        default=0.0,
        dest="minimum",
        metavar="PERCENT",
        help="omit results scoring below this percentage",
    )
    cross_command.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return OK if exc.code == 0 else USAGE

    if args.version:
        print(f"eous {_installed_version()}")
        for name, value in toolchain.engines().items():
            print(f"{name} {value}")
        return OK

    try:
        if args.command == "hash" and args.paths:
            return _run_hash(args)
        if args.command == "compare" and args.left and args.right:
            return _run_compare(args)
        if args.command == "match" and args.query and args.known:
            return _run_match(args)
        if args.command == "cross" and args.known:
            return _run_cross(args)
    except Exception as exc:
        if isinstance(exc, OSError) and exc.errno in CLOSED_PIPE:
            _quieten_stdout()
            return OK
        _warn(f"internal error: {exc}")
        return INTERNAL

    parser.print_usage(sys.stderr)
    return USAGE


def _warn(message: str) -> None:
    print(f"eous: {message}", file=sys.stderr)


def _quieten_stdout() -> None:
    with contextlib.suppress(OSError, ValueError):
        target = sys.stdout.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, target)
        os.close(devnull)


def _run_hash(args: argparse.Namespace) -> int:
    paths = _expand(args.paths)
    if not paths:
        named = ", ".join(_readable(str(path)) for path in args.paths)
        _warn(f"{named}: no file to hash")
        return USAGE

    labelled = len(paths) > 1 or paths != args.paths
    records: list[dict[str, object]] = []
    refused = False

    for result in _analyse(paths):
        refused = refused or result.refusal is not None
        if args.json:
            records.append(_as_record(result))
        else:
            _print_line(result, labelled=labelled, quiet=args.quiet)

    if args.json:
        print(json.dumps({"meta": _meta(), "results": records}, indent=1))

    return REFUSED if refused else OK


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _looks_like_a_path(text: str) -> bool:
    return "/" in text or "\\" in text or Path(text).suffix != ""


def _as_digest(text: str) -> tuple[str | None, int]:
    path = Path(text)
    if not os.path.isfile(path):
        if _looks_like_a_path(text):
            _warn(f"{_readable(text)}: no such file")
            return (None, USAGE)
        return (text, OK)

    result = report.analyse(path)
    if result.refusal is not None:
        _warn(_refusal_line(result.path, result.refusal))
        return (None, REFUSED)
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
        scores = digest.compare(resolved[0], resolved[1])
    except digest.DigestError as exc:
        _warn(str(exc))
        return USAGE

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "target": digest.parse(resolved[0]).target,
                    "comparison": _as_scores(scores, named),
                },
                indent=1,
            )
        )
    else:
        labels = [name or side for name, side in zip(named, ("left", "right"), strict=True)]
        _print_scores(scores, labels)
    return OK


def _read_digests(path: Path) -> tuple[list[str], list[digest.Sketch], int] | None:
    labels: list[str] = []
    sketches: list[digest.Sketch] = []
    unparsed = 0

    try:
        # PowerShell writes a byte-order mark on every redirect, and `eous hash > known.txt`
        # is the documented way to build this file.
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as exc:
        _warn(f"{_readable(str(path))}: {exc.strerror}")
        return None

    for line in lines:
        fields = line.split()
        if not fields:
            continue
        try:
            sketch = digest.parse(fields[-1])
        except digest.DigestError:
            unparsed += 1
            continue
        labels.append(line[: line.rindex(fields[-1])].strip() or fields[-1])
        sketches.append(sketch)

    if unparsed:
        _warn(f"{_plural(unparsed, 'line')} did not parse")
    return labels, sketches, unparsed


def _run_match(args: argparse.Namespace) -> int:
    if args.top < 0:
        _warn("--top is a count of 0 or more")
        return USAGE
    if not 0.0 <= args.minimum <= 100.0:
        _warn("--min is a percentage from 0 to 100")
        return USAGE

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
    labels, sketches, unparsed = read
    kept = [pair for pair in zip(labels, sketches, strict=True) if pair[1].target == query.target]
    other_target = len(sketches) - len(kept)

    if not kept:
        _warn(f"{_readable(str(args.known))}: contains no {query.target} digest")
        return USAGE

    rows = digest.unpack_all([sketch for _, sketch in kept])
    scored, spread = digest.score(rows, digest.unpack(query))
    order = sorted(
        zip(scored, spread, (label for label, _ in kept), strict=True), key=lambda row: -row[0]
    )
    cleared = [row for row in order if row[0] >= args.minimum]
    ranked = cleared[: args.top]
    below_minimum = len(order) - len(cleared)

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
                    "matches": [
                        {
                            "label": label,
                            "similarity": round(float(score), 4),
                            "uncertainty": round(float(margin), 4),
                        }
                        for score, margin, label in ranked
                    ],
                },
                indent=1,
            )
        )
    else:
        for score, margin, label in ranked:
            print(f"{float(score):5.1f}% +/- {float(margin):3.1f}  {_readable(label)}")

    if other_target:
        _warn(f"{_plural(other_target, 'digest')} skipped, built for another target")
    if below_minimum:
        _warn(f"{_plural(below_minimum, 'digest')} scored below {args.minimum:g}%")
    return OK


def _by_target(sketches: list[digest.Sketch]) -> dict[str, list[int]]:
    grouped: dict[str, list[int]] = {}
    for index, sketch in enumerate(sketches):
        grouped.setdefault(sketch.target, []).append(index)
    return {target: rows for target, rows in grouped.items() if len(rows) > 1}


def _run_cross(args: argparse.Namespace) -> int:
    if not 0.0 <= args.minimum <= 100.0:
        _warn("--min is a percentage from 0 to 100")
        return USAGE

    read = _read_digests(args.known)
    if read is None:
        return USAGE
    labels, sketches, unparsed = read

    grouped = _by_target(sketches)
    if not grouped:
        _warn(f"{_readable(str(args.known))}: contains fewer than two digests of any one target")
        return USAGE

    shown = [_readable(label) for label in labels]
    targets = sorted(grouped)
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
        rows = digest.unpack_all([sketches[index] for index in members])
        for offset in range(len(members) - 1):
            scores, spread = digest.score(rows[offset + 1 :], rows[offset])
            left = members[offset]
            total += len(scores)
            for step, (score, margin) in enumerate(zip(scores, spread, strict=True)):
                if score < args.minimum:
                    below_minimum += 1
                    continue
                right = members[offset + 1 + step]
                if args.json:
                    print(
                        json.dumps(
                            {
                                "left": labels[left],
                                "right": labels[right],
                                "target": target,
                                "similarity": round(float(score), 4),
                                "uncertainty": round(float(margin), 4),
                            }
                        )
                    )
                else:
                    print(
                        f"{float(score):5.1f}% +/- {float(margin):3.1f}  "
                        f"{shown[left]}  {shown[right]}"
                    )

    if args.json:
        print(json.dumps({"pairs_scored": total, "below_minimum": below_minimum}))

    _warn(f"{_plural(total, 'pair')} scored across {', '.join(targets)}")
    if alone:
        _warn(f"{_plural(alone, 'digest')} skipped, alone in its target")
    if below_minimum:
        _warn(f"{_plural(below_minimum, 'pair')} scored below {args.minimum:g}%")
    return OK


def _print_scores(scores: digest.Scores, labels: list[str]) -> None:
    low = max(0.0, scores.similarity - scores.uncertainty)
    high = min(100.0, scores.similarity + scores.uncertainty)
    print(
        f"similarity:  {scores.similarity:.1f}% +/- {scores.uncertainty:.1f} "
        f"({low:.1f}% to {high:.1f}%)"
    )

    if scores.left_in_right is None or scores.right_in_left is None:
        ratio = f"{digest.MAX_CONTAINMENT_RATIO:g}x"
        print(f"containment: n/a (the two differ in size by more than {ratio})")
        return

    left, right = (_readable(label) for label in labels)
    width = max(len(left), len(right))
    print(
        f"containment: {left:<{width}} in {right:<{width}}  {scores.left_in_right:>5.1f}%"
        f" +/- {scores.left_in_right_uncertainty:.0f}"
    )
    print(
        f"             {right:<{width}} in {left:<{width}}  {scores.right_in_left:>5.1f}%"
        f" +/- {scores.right_in_left_uncertainty:.0f}"
    )


def _as_scores(scores: digest.Scores, labels: list[str | None]) -> dict[str, object]:
    def rounded(value: float | None) -> float | None:
        return None if value is None else round(value, 4)

    return {
        "left": labels[0],
        "right": labels[1],
        "similarity": round(scores.similarity, 4),
        "uncertainty": round(scores.uncertainty, 4),
        "low": round(max(0.0, scores.similarity - scores.uncertainty), 4),
        "high": round(min(100.0, scores.similarity + scores.uncertainty), 4),
        "left_in_right": rounded(scores.left_in_right),
        "right_in_left": rounded(scores.right_in_left),
        "left_in_right_uncertainty": rounded(scores.left_in_right_uncertainty),
        "right_in_left_uncertainty": rounded(scores.right_in_left_uncertainty),
    }


def _analyse(paths: list[Path]) -> Iterator[report.Analysis]:
    if len(paths) < 2:
        yield from (report.analyse(path) for path in paths)
        return

    with ProcessPoolExecutor() as pool:
        yield from pool.map(report.analyse, paths)


def _expand(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        if os.path.isdir(path):
            walked = sorted(p for p in path.rglob("*") if os.path.isfile(p))
        else:
            walked = [path]
        for candidate in walked:
            real = candidate.resolve()
            if real not in seen:
                seen.add(real)
                found.append(candidate)
    return found


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
    return {
        "path": str(result.path),
        "digest": result.digest,
        "reason": result.refusal.reason if result.refusal else None,
        "detail": result.refusal.detail if result.refusal else None,
    }


def _meta() -> dict[str, str]:
    return {"eous": _installed_version(), **toolchain.engines()}


def _installed_version() -> str:
    try:
        return version("eous")
    except PackageNotFoundError:
        return "0.0.0+unknown"


if __name__ == "__main__":
    sys.exit(main())
