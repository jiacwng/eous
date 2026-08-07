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
  EO1:pe64:3136:5cfc520f897cc0cf...
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
  eous compare EO1:pe64:56:eb7d... EO1:pe64:3136:5cfc...
  eous match suspect.exe digests.txt

reading a comparison:
  similarity:  27.6% +/- 8.0 (19.6% to 35.6%)
  containment: old.exe in new.exe   94.1% +/- 12
               new.exe in old.exe   41.2% +/- 5

  The +/- figure is the margin of error, since 256 slots estimate the overlap.
  It narrows as scores approach 100%. Two results whose ranges overlap stay
  unranked against each other.

  Containment runs both ways, and the gap between them says which side is the
  superset. It comes from the same estimate, so its margin is wider, and it
  grows with the size difference. Above 4x both figures are withheld.

a refusal names its cause:
  eous: sample.macho: unsupported_format: macho
  eous: sample.elf:   unsupported_arch: AARCH64
  eous: packed.exe:   packed: 100% of executable code is compressed
  eous: library.dll:  managed: il only, no native code
  eous: notes.txt:    unreadable: no recognised container

files eous declines to digest are reported rather than guessed at. A digest is
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
    hash_command.add_argument("--quiet", action="store_true", help="hold back refusal text")

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
    match_command.add_argument("--top", type=int, default=10, help="how many to print")
    match_command.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        # argparse exits 0 after printing help or a version, and 2 on a bad argument.
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
    except Exception as exc:
        if isinstance(exc, OSError) and exc.errno in CLOSED_PIPE:
            _quieten_stdout()
            return OK
        print(f"eous: internal error: {exc}", file=sys.stderr)
        return INTERNAL

    parser.print_usage(sys.stderr)
    return USAGE


def _quieten_stdout() -> None:
    # The reader is gone, so the interpreter's closing flush needs somewhere to land.
    with contextlib.suppress(OSError, ValueError):
        target = sys.stdout.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, target)
        os.close(devnull)


def _run_hash(args: argparse.Namespace) -> int:
    paths = _expand(args.paths)
    labelled = len(paths) > 1 or paths != args.paths
    records: list[dict[str, object]] = []
    refused = False

    # Each result is printed and dropped, so a folder scan holds one file at a time.
    for result in _analyse(paths):
        refused = refused or result.refusal is not None
        if args.json:
            records.append(_as_record(result))
        else:
            _print_line(result, labelled=labelled, quiet=args.quiet)

    if args.json:
        print(json.dumps({"meta": _meta(), "results": records}, indent=1))

    return REFUSED if refused else OK


def _as_digest(text: str) -> str | None:
    # A path that exists is a file; anything else is read as a digest string.
    path = Path(text)
    if not path.is_file():
        return text

    result = report.analyse(path)
    if result.digest is None:
        cause = result.refusal
        reason = f"{cause.gate}: {_readable(cause.detail)}" if cause else "no digest"
        print(f"eous: {_readable(str(path))}: {reason}", file=sys.stderr)
        return None
    return result.digest


def _run_compare(args: argparse.Namespace) -> int:
    resolved: list[str] = []
    labels: list[str] = []
    for text, side in ((args.left, "left"), (args.right, "right")):
        found = _as_digest(text)
        if found is None:
            return REFUSED
        resolved.append(found)
        labels.append(side if found is text else text)

    try:
        scores = digest.compare(resolved[0], resolved[1])
    except digest.DigestError as exc:
        print(f"eous: {exc}", file=sys.stderr)
        return USAGE

    if args.json:
        print(json.dumps({"meta": _meta(), "comparison": _as_scores(scores, labels)}, indent=1))
    else:
        _print_scores(scores, labels)
    return OK


def _read_known(path: Path, target: str) -> tuple[list[str], list[digest.Sketch], int, int]:
    """The digests sharing the target, their labels, and what each kind of skip cost."""
    labels: list[str] = []
    sketches: list[digest.Sketch] = []
    other_target = 0
    unreadable = 0

    # PowerShell writes a byte-order mark on every redirect, and `eous hash > known.txt`
    # is the documented way to build this file.
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            sketch = digest.parse(fields[-1])
        except digest.DigestError:
            unreadable += 1
            continue
        if sketch.target != target:
            other_target += 1
            continue
        # `hash` writes the path first, so whatever precedes the digest is the label.
        labels.append(line[: line.rindex(fields[-1])].strip() or fields[-1])
        sketches.append(sketch)

    return labels, sketches, other_target, unreadable


def _run_match(args: argparse.Namespace) -> int:
    if args.top < 0:
        print("eous: --top counts from zero", file=sys.stderr)
        return USAGE

    text = _as_digest(args.query)
    if text is None:
        return REFUSED

    try:
        query = digest.parse(text)
    except digest.DigestError as exc:
        print(f"eous: {exc}", file=sys.stderr)
        return USAGE

    try:
        labels, sketches, other_target, unreadable = _read_known(args.known, query.target)
    except OSError as exc:
        print(f"eous: {_readable(str(args.known))}: {exc.strerror}", file=sys.stderr)
        return REFUSED

    if not sketches:
        print(
            f"eous: {_readable(str(args.known))}: holds no {query.target} digest",
            file=sys.stderr,
        )
        return USAGE

    scored = digest.similarities(digest.unpack_all(sketches), digest.unpack(query))
    spread = digest.margins(scored)
    ranked = sorted(zip(scored, spread, labels, strict=True), key=lambda row: -row[0])[: args.top]

    if args.json:
        print(
            json.dumps(
                {
                    "meta": _meta(),
                    "query": args.query,
                    "target": query.target,
                    "other_target": other_target,
                    "unreadable": unreadable,
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
        print(f"eous: {other_target} built for another target", file=sys.stderr)
    if unreadable:
        print(f"eous: {unreadable} lines held no digest", file=sys.stderr)
    return OK


def _print_scores(scores: digest.Scores, labels: list[str]) -> None:
    low = max(0.0, scores.similarity - scores.uncertainty)
    high = min(100.0, scores.similarity + scores.uncertainty)
    # ASCII only: stdout takes the environment's encoding.
    print(
        f"similarity:  {scores.similarity:.1f}% +/- {scores.uncertainty:.1f} "
        f"({low:.1f}% to {high:.1f}%)"
    )

    if scores.left_in_right is None or scores.right_in_left is None:
        print("containment: n/a (the two differ in size by more than 4x)")
        return

    left, right = labels
    width = max(len(left), len(right))
    print(
        f"containment: {left:<{width}} in {right:<{width}}  {scores.left_in_right:>5.1f}%"
        f" +/- {scores.left_in_right_uncertainty:.0f}"
    )
    print(
        f"             {right:<{width}} in {left:<{width}}  {scores.right_in_left:>5.1f}%"
        f" +/- {scores.right_in_left_uncertainty:.0f}"
    )


def _as_scores(scores: digest.Scores, labels: list[str]) -> dict[str, object]:
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
    # One file pays more to start a worker than to read itself.
    if len(paths) < 2:
        yield from (report.analyse(path) for path in paths)
        return

    with ProcessPoolExecutor() as pool:
        yield from pool.map(report.analyse, paths)


def _expand(paths: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        walked = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
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


def _print_line(result: report.Analysis, labelled: bool, quiet: bool) -> None:
    if result.digest is not None:
        path = _readable(str(result.path))
        line = f"{path}  {result.digest}" if labelled else result.digest
        print(line, flush=True)
    elif result.refusal is not None and not quiet:
        gate, detail = result.refusal.gate, _readable(result.refusal.detail)
        print(f"eous: {_readable(str(result.path))}: {gate}: {detail}", file=sys.stderr)


def _as_record(result: report.Analysis) -> dict[str, object]:
    return {
        "path": str(result.path),
        "digest": result.digest,
        "gate": result.refusal.gate if result.refusal else None,
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
