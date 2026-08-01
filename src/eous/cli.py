# Argument parsing, output formatting and exit codes.

from __future__ import annotations

import argparse
import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from eous import report

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
  eous hash --quiet suspicious.dll ; echo $?

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

    if args.command != "hash" or not args.paths:
        parser.print_usage(sys.stderr)
        return USAGE

    try:
        results = [report.analyse(path) for path in args.paths]
    except Exception as exc:
        print(f"eous: internal error: {exc}", file=sys.stderr)
        return INTERNAL

    if args.json:
        print(json.dumps([_as_record(r) for r in results], indent=1))
    else:
        _print_lines(results, labelled=len(results) > 1, quiet=args.quiet)

    return REFUSED if any(r.refusal for r in results) else OK


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
