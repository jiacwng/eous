# Sweeps the executable sections of a binary into chunks of mnemonics.
#
# A chunk is a straight-line run of instructions. It ends wherever control leaves that
# line, so the shingles built from it later describe paths the program really takes.

from __future__ import annotations

from dataclasses import dataclass

from iced_x86 import Decoder, FlowControl, Mnemonic

from eous.loader import BITS, ENTROPY_THRESHOLD, Binary

PADDING_RUN = 8

# `add` belongs here because a run of zero bytes decodes as `add [eax], al`.
PADDING_MNEMONICS = frozenset({"nop", "int3", "add"})

ENTROPY = "ENTROPY"
EMPTY = "EMPTY"
BUDGET = "BUDGET"
STALLED = "STALLED"

CONTINUES = frozenset({FlowControl.NEXT, FlowControl.INTERRUPT})

MNEMONICS = {
    value: name.lower()
    for name, value in vars(Mnemonic).items()
    if name.isupper() and isinstance(value, int)
}


class DisasmError(Exception):
    pass


@dataclass(frozen=True)
class RegionReport:
    name: str
    decoded: int
    skipped: str | None
    stalls: int
    size: int


@dataclass(frozen=True)
class SweepResult:
    chunks: tuple[tuple[str, ...], ...]
    reports: tuple[RegionReport, ...]
    total_decoded: int

    @property
    def compressed_share(self) -> float:
        # Weighed by bytes, so a stub-sized section cannot outvote the real code.
        total = sum(r.size for r in self.reports)
        if not total:
            return 0.0
        return sum(r.size for r in self.reports if r.skipped == ENTROPY) / total


def sweep(
    binary: Binary,
    *,
    max_instructions: int | None = None,
    max_stalls: int | None = None,
    padding_run: int = PADDING_RUN,
    minimum_run: int = 1,
) -> SweepResult:
    bitness = BITS.get(binary.arch)
    if bitness is None:
        raise DisasmError(f"no decoder for architecture {binary.arch}")

    chunks: list[tuple[str, ...]] = []
    reports: list[RegionReport] = []

    for section in binary.executable_sections:
        if not section.data:
            reports.append(RegionReport(section.name, 0, EMPTY, 0, len(section.data)))
            continue

        if section.entropy >= ENTROPY_THRESHOLD:
            reports.append(RegionReport(section.name, 0, ENTROPY, 0, len(section.data)))
            continue

        region_chunks, report = _sweep_region(
            data=section.data,
            name=section.name,
            bitness=bitness,
            max_instructions=max_instructions,
            max_stalls=max_stalls,
            padding_run=padding_run,
            minimum_run=minimum_run,
        )
        chunks.extend(region_chunks)
        reports.append(report)

    return SweepResult(
        chunks=tuple(chunks),
        reports=tuple(reports),
        total_decoded=sum(report.decoded for report in reports),
    )


def _sweep_region(
    data: bytes,
    name: str,
    bitness: int,
    max_instructions: int | None,
    max_stalls: int | None,
    padding_run: int,
    minimum_run: int,
) -> tuple[list[tuple[str, ...]], RegionReport]:

    decoder = Decoder(bitness, data)
    budget = len(data) if max_instructions is None else max_instructions
    ceiling = len(data) if max_stalls is None else max_stalls

    chunks: list[tuple[str, ...]] = []
    current: list[str] = []
    decoded = 0
    stalls = 0
    skipped: str | None = None

    def close_chunk() -> None:
        if current:
            collapsed = _collapse_padding(current, padding_run)
            if len(collapsed) >= minimum_run:
                chunks.append(tuple(collapsed))
            current.clear()

    while decoder.can_decode:
        if decoded >= budget:
            skipped = BUDGET
            break
        if stalls >= ceiling:
            skipped = STALLED
            break

        position = decoder.position
        instruction = decoder.decode()

        if instruction.is_invalid:
            # Resume one byte on, so an undecodable byte costs exactly one byte.
            decoder.position = position + 1
            close_chunk()
            stalls += 1
            continue

        current.append(MNEMONICS[instruction.mnemonic])
        decoded += 1

        if instruction.flow_control not in CONTINUES:
            close_chunk()

    close_chunk()
    return chunks, RegionReport(
        name=name, decoded=decoded, skipped=skipped, stalls=stalls, size=len(data)
    )


def _collapse_padding(mnemonics: list[str], padding_run: int) -> list[str]:
    collapsed: list[str] = []
    index = 0

    while index < len(mnemonics):
        mnemonic = mnemonics[index]
        end = index
        while end < len(mnemonics) and mnemonics[end] == mnemonic:
            end += 1

        run = end - index
        if mnemonic in PADDING_MNEMONICS and run >= padding_run:
            collapsed.append(mnemonic)
        else:
            collapsed.extend(mnemonics[index:end])
        index = end

    return collapsed
