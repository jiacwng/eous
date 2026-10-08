# Disassembles the executable sections of a binary into straight-line runs of mnemonics.
#
# A run ends wherever control leaves the straight line, so the shingles built from it later
# describe paths the program really takes.

from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import Decoder, FlowControl, Mnemonic

from eous.loader import BITS, ENTROPY_THRESHOLD, Binary

ENTROPY = "ENTROPY"

CONTINUES = frozenset({FlowControl.NEXT, FlowControl.INTERRUPT})

MNEMONICS = {
    value: name.lower()
    for name, value in vars(Mnemonic).items()
    if name.isupper() and isinstance(value, int)
}


@dataclass(frozen=True)
class SectionReport:
    name: str
    decoded: int
    skipped: str | None
    undecodable: int
    size: int


@dataclass(frozen=True)
class Disassembly:
    runs: tuple[tuple[str, ...], ...]
    reports: tuple[SectionReport, ...]
    total_decoded: int

    @property
    def compressed_share(self) -> float:
        # Weighed by bytes, so a stub-sized section cannot outvote the real code.
        total = sum(r.size for r in self.reports)
        if not total:
            return 0.0
        return sum(r.size for r in self.reports if r.skipped == ENTROPY) / total


def disassemble(
    binary: Binary,
    *,
    repeat_cap: int | None = None,
    minimum_run: int = 1,
) -> Disassembly:
    bitness = BITS[binary.arch]
    runs: list[tuple[str, ...]] = []
    reports: list[SectionReport] = []

    for section in binary.executable_sections:
        if section.entropy >= ENTROPY_THRESHOLD:
            reports.append(SectionReport(section.name, 0, ENTROPY, 0, len(section.data)))
            continue

        section_runs, report = _disassemble_section(
            data=section.data,
            name=section.name,
            bitness=bitness,
            repeat_cap=repeat_cap,
            minimum_run=minimum_run,
        )
        runs.extend(section_runs)
        reports.append(report)

    return Disassembly(
        runs=tuple(runs),
        reports=tuple(reports),
        total_decoded=sum(report.decoded for report in reports),
    )


def _disassemble_section(
    data: bytes,
    name: str,
    bitness: int,
    repeat_cap: int | None,
    minimum_run: int,
) -> tuple[list[tuple[str, ...]], SectionReport]:
    decoder = Decoder(bitness, data)

    runs: list[tuple[str, ...]] = []
    current: list[str] = []
    decoded = 0
    undecodable = 0
    repeated = 0
    previous = ""

    def close_run() -> None:
        nonlocal repeated, previous
        if current:
            if len(current) >= minimum_run:
                runs.append(tuple(current))
            current.clear()
        repeated = 0
        previous = ""

    while decoder.can_decode:
        position = decoder.position
        instruction = decoder.decode()

        if instruction.is_invalid:
            # Resume one byte on, so an undecodable byte costs exactly one byte.
            decoder.position = position + 1
            close_run()
            undecodable += 1
            continue

        mnemonic = MNEMONICS[instruction.mnemonic]
        repeated = repeated + 1 if mnemonic == previous else 1
        previous = mnemonic
        if repeat_cap is None or repeated <= repeat_cap:
            current.append(mnemonic)
        decoded += 1

        if instruction.flow_control not in CONTINUES:
            close_run()

    close_run()
    return runs, SectionReport(
        name=name, decoded=decoded, skipped=None, undecodable=undecodable, size=len(data)
    )
