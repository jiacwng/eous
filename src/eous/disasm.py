# Sweeps the executable sections of a binary into chunks of mnemonics.
#
# A chunk is a straight-line run of instructions. It ends wherever control leaves that
# line, so the shingles built from it later describe paths the program really takes.

from __future__ import annotations

from dataclasses import dataclass

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from eous.loader import ENTROPY_THRESHOLD, Binary

WINDOW_BYTES = 65_536
PADDING_RUN = 8

# Section addresses are attacker-controlled, and one near 2**64 wraps the decoder.
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

# `call` belongs here because the callee runs in between, so the executed stream separates
# a call from the address following it.
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
            reports.append(RegionReport(section.name, 0, EMPTY, 0, len(section.data)))
            continue

        if section.entropy >= entropy_threshold:
            reports.append(RegionReport(section.name, 0, ENTROPY, 0, len(section.data)))
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
    max_instructions: int | None,
    max_stalls: int | None,
    window_bytes: int,
    padding_run: int,
) -> tuple[list[tuple[str, ...]], RegionReport]:
    decoder = Cs(CS_ARCH_X86, mode)
    decoder.detail = False

    budget = len(data) if max_instructions is None else max_instructions
    ceiling = len(data) if max_stalls is None else max_stalls

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
        if decoded >= budget:
            skipped = BUDGET
            break
        if stalls >= ceiling:
            skipped = STALLED
            break

        window = data[offset : offset + window_bytes]
        advanced = False

        # disasm_lite yields plain tuples. The object form builds a ctypes-backed
        # instruction per decode, and only the mnemonic and the size are read here.
        for _, size, mnemonic, _ in decoder.disasm_lite(window, (base + offset) & ADDRESS_MASK):
            next_offset = offset + size

            current.append(mnemonic)
            decoded += 1
            offset = next_offset
            advanced = True

            # Capstone prints prefixes ahead of the mnemonic, so `repz ret` reaches the
            # set through its final token. The space check comes first.
            if mnemonic in TERMINATORS or (
                " " in mnemonic and mnemonic.rsplit(" ", 1)[-1] in TERMINATORS
            ):
                close_chunk()
            if decoded >= budget:
                break

        # Capstone halts at the first undecodable byte, so zero instructions means the
        # byte at `offset` is junk.
        if not advanced:
            close_chunk()
            stalls += 1
            offset += 1

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
