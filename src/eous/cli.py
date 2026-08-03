# Argument parsing, output formatting and exit codes.

from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from eous import digest, report

OK = 0
REFUSED = 1
USAGE = 2
INTERNAL = 3


DESCRIPTION = """\
Code-similarity digests for PE and ELF binaries on x86 and x86-64.

A digest summarises the instruction sequences a program contains, so two binaries
built from similar code produce digests that agree in many places."""

EPILOGUE = """\
digest format:
  EO1:x86-64:3136:5cfc520f897cc0cf...
   |    |      |    |
   |    |      |    the sketch, 512 bits as 128 hex characters
   |    |      how many distinct instruction sequences were found
   |    the architecture the code targets
   the format version, so two digests compare only when it matches

exit codes:
  0  every file digested
  1  at least one file refused, with the cause on stderr
  2  usage error
  3  internal error

examples:
  eous hash program.exe
  eous hash --json bin/* > digests.json
  eous compare old.exe new.exe
  eous compare EO1:x86-64:56:eb7d... EO1:x86-64:3136:5cfc...

reading a comparison:
  similarity:  27.6% +/- 8.0 (19.6% to 35.6%)
  containment: old.exe in new.exe   94.1%
               new.exe in old.exe   41.2%

  The band is sampling error, since 256 slots estimate the overlap rather than
  measure it. It narrows as scores approach 100%. Two results whose bands
  overlap stay unranked against each other.

  Containment runs both ways, and the gap between them says which side is the
  superset. Above a 4x size difference both are withheld, since the estimate
  stops being reliable there.

a refusal names its cause:
  eous: packed.exe: unsupported_format: macho

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
        description="Print one digest per file, or the cause when a file is refused.",
    )
    hash_command.add_argument("paths", nargs="*", type=Path, metavar="FILE")
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        # argparse exits 0 after printing help or a version, and 2 on a bad argument.
        return OK if exc.code == 0 else USAGE

    if args.version:
        print(_installed_version())
        return OK

    try:
        if args.command == "hash" and args.paths:
            return _run_hash(args)
        if args.command == "compare" and args.left and args.right:
            return _run_compare(args)
    except Exception as exc:
        print(f"eous: internal error: {exc}", file=sys.stderr)
        return INTERNAL

    parser.print_usage(sys.stderr)
    return USAGE


def _run_hash(args: argparse.Namespace) -> int:
    results = [report.analyse(path) for path in args.paths]

    if args.json:
        print(json.dumps([_as_record(r) for r in results], indent=1))
    else:
        _print_lines(results, labelled=len(results) > 1, quiet=args.quiet)

    return REFUSED if any(r.refusal for r in results) else OK


def _run_compare(args: argparse.Namespace) -> int:
    resolved: list[str] = []
    labels: list[str] = []
    for text, side in ((args.left, "left"), (args.right, "right")):
        # A path that exists is a file; anything else is read as a digest string. The
        # filesystem answers first, so a mistyped path reports as absent.
        path = Path(text)
        if not path.is_file():
            resolved.append(text)
            labels.append(side)
            continue

        result = report.analyse(path)
        if result.digest is None:
            cause = result.refusal
            reason = f"{cause.gate}: {cause.detail}" if cause else "no digest"
            print(f"eous: {path.name}: {reason}", file=sys.stderr)
            return REFUSED
        resolved.append(result.digest)
        labels.append(text)

    try:
        scores = digest.compare(resolved[0], resolved[1])
    except digest.DigestError as exc:
        print(f"eous: {exc}", file=sys.stderr)
        return USAGE

    if args.json:
        print(json.dumps(_as_scores(scores, labels), indent=1))
    else:
        _print_scores(scores, labels)
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
    print(f"containment: {left:<{width}} in {right:<{width}}  {scores.left_in_right:>5.1f}%")
    print(f"             {right:<{width}} in {left:<{width}}  {scores.right_in_left:>5.1f}%")


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
    }


def _print_lines(results: list[report.Analysis], labelled: bool, quiet: bool) -> None:
    for result in results:
        if result.digest is not None:
            line = f"{result.path.name}  {result.digest}" if labelled else result.digest
            print(line)
        elif result.refusal is not None and not quiet:
            gate, detail = result.refusal.gate, result.refusal.detail
            print(f"eous: {result.path.name}: {gate}: {detail}", file=sys.stderr)


def _as_record(result: report.Analysis) -> dict[str, object]:
    return {
        "path": str(result.path),
        "digest": result.digest,
        "gate": result.refusal.gate if result.refusal else None,
        "detail": result.refusal.detail if result.refusal else None,
    }


def _installed_version() -> str:
    try:
        return version("eous")
    except PackageNotFoundError:
        return "0.0.0+unknown"


if __name__ == "__main__":
    sys.exit(main())
