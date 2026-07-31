# Sweeps the executable sections of a binary into chunks of mnemonics.
#
# A chunk is a straight-line run of instructions. It ends wherever control leaves that
# line, so the shingles built from it later describe paths the program really takes.

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from eous.loader import ENTROPY_THRESHOLD, Binary

# Each region carries its own budget. A shared pool drained in parse order would tie the
# digest to the order sections appear in the file. Measured cosine 0.997 to 1.000 against
# a full sweep, at roughly half the time. Measured 2026-08-01 over 160 corpus binaries:
# the median file decodes 5,825 instructions and 2 of 160 reach this ceiling.
MAX_INSTRUCTIONS = 500_000

# Resync budget for regions holding data. Policy: a region needing this many resyncs is
# data, and the sweep abandons it there.
MAX_STALLS = 20_000

# Decode window, so a multi-megabyte region avoids quadratic behaviour.
WINDOW_BYTES = 65_536

# Filler runs of this length or more collapse to a single mnemonic. Policy: measured
# 2026-08-01 over 160 corpus binaries, runs of 2 to 7 are ordinary code while every run
# reaching 8 was alignment filler. M5 revisits whether set semantics make this redundant.
PADDING_RUN = 8

# Section addresses are attacker-controlled, and an address near 2**64 makes the decoder
# wrap. Masking keeps the arithmetic inside 64 bits, and offsets advance by instruction
# size, which holds a wrapped address moving forward through the region.
ADDRESS_MASK = (1 << 64) - 1

# `add` belongs here because a run of zero bytes decodes as `add [eax], al`.
PADDING_MNEMONICS = frozenset({"nop", "int3", "add"})

ENTROPY = "ENTROPY"
EMPTY = "EMPTY"
BUDGET = "BUDGET"
STALLED = "STALLED"

MODES = {"x86": CS_MODE_32, "x86-64": CS_MODE_64}

# fmt: off
_CONDITIONS = (
    "a", "ae", "b", "be", "c", "e", "g", "ge", "l", "le", "na", "nae", "nb", "nbe", "nc",
    "ne", "ng", "nge", "nl", "nle", "no", "np", "ns", "nz", "o", "p", "pe", "po", "s", "z",
)

# Instructions after which execution continues somewhere else. `call` is included because
# the callee runs in between, so the executed stream separates the call from the address
# that follows it. Validated against Capstone's jump, call and ret groups in M4.3.
TERMINATORS = frozenset(
    {
        "jmp", "ljmp", "call", "lcall",
        "ret", "retf", "retfq", "iret", "iretd", "iretq",
        "hlt", "ud0", "ud1", "ud2",
        "syscall", "sysenter", "sysexit", "sysret",
        "loop", "loope", "loopne", "loopnz", "loopz",
        "jcxz", "jecxz", "jrcxz",
    }
    | {f"j{condition}" for condition in _CONDITIONS}
)
# fmt: on


class DisasmError(Exception):
    pass


@dataclass(frozen=True)
class RegionReport:
    name: str
    decoded: int
    skipped: str | None
    stalls: int


@dataclass(frozen=True)
class SweepResult:
    chunks: tuple[tuple[str, ...], ...]
    reports: tuple[RegionReport, ...]
    total_decoded: int

    @property
    def all_regions_skipped_for_entropy(self) -> bool:
        return bool(self.reports) and all(r.skipped == ENTROPY for r in self.reports)


def sweep(
    binary: Binary,
    *,
    max_instructions: int = MAX_INSTRUCTIONS,
    max_stalls: int = MAX_STALLS,
    window_bytes: int = WINDOW_BYTES,
    padding_run: int = PADDING_RUN,
    entropy_threshold: float = ENTROPY_THRESHOLD,
) -> SweepResult:
    mode = MODES.get(binary.arch)
    if mode is None:
        raise DisasmError(f"no decoder for architecture {binary.arch}")

    chunks: list[tuple[str, ...]] = []
    reports: list[RegionReport] = []

    for section in binary.executable_sections:
        if not section.data:
            reports.append(RegionReport(section.name, 0, EMPTY, 0))
            continue

        # Compressed and encrypted bytes decode into noise with a resync on almost every
        # byte. Measured 30 seconds of garbage on one 3 MB section at entropy 7.96.
        if section.entropy >= entropy_threshold:
            reports.append(RegionReport(section.name, 0, ENTROPY, 0))
            continue

        region_chunks, report = _sweep_region(
            data=section.data,
            base=section.virtual_address,
            name=section.name,
            mode=mode,
            max_instructions=max_instructions,
            max_stalls=max_stalls,
            window_bytes=window_bytes,
            padding_run=padding_run,
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
    base: int,
    name: str,
    mode: int,
    max_instructions: int,
    max_stalls: int,
    window_bytes: int,
    padding_run: int,
) -> tuple[list[tuple[str, ...]], RegionReport]:
    decoder = Cs(CS_ARCH_X86, mode)
    decoder.detail = False

    chunks: list[tuple[str, ...]] = []
    current: list[str] = []
    offset = 0
    decoded = 0
    stalls = 0
    skipped: str | None = None

    def close_chunk() -> None:
        if current:
            chunks.append(tuple(_collapse_padding(current, padding_run)))
            current.clear()

    while offset < len(data):
        if decoded >= max_instructions:
            skipped = BUDGET
            break
        if stalls >= max_stalls:
            skipped = STALLED
            break

        window = data[offset : offset + window_bytes]
        advanced = False

        for instruction in decoder.disasm(window, (base + offset) & ADDRESS_MASK):
            mnemonic = instruction.mnemonic
            next_offset = offset + instruction.size

            current.append(mnemonic)
            decoded += 1
            offset = next_offset
            advanced = True

            # Capstone prints prefixes ahead of the mnemonic, so `repz ret` and
            # `notrack jmp` reach the set through their final token.
            if mnemonic.rsplit(" ", 1)[-1] in TERMINATORS:
                close_chunk()
            if decoded >= max_instructions:
                break

        # Capstone halts at the first undecodable byte, so a window yielding zero
        # instructions means the byte at `offset` is junk: step over it and close
        # the chunk there.
        if not advanced:
            close_chunk()
            stalls += 1
            offset += 1

    close_chunk()
    return chunks, RegionReport(name=name, decoded=decoded, skipped=skipped, stalls=stalls)


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
