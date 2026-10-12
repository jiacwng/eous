# Disassembles executable sections into straight-line runs of mnemonics.
#
# A run ends wherever control leaves the straight line, so the shingles built from it later
# describe paths the program really takes.

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from iced_x86 import Decoder, FlowControl, Mnemonic

from eous.digest import NGRAM
from eous.loader import BITS, Section

CONTINUES = frozenset({FlowControl.NEXT, FlowControl.INTERRUPT})

MNEMONICS = {
    value: name.lower()
    for name, value in vars(Mnemonic).items()
    if name.isupper() and isinstance(value, int)
}


@dataclass(frozen=True)
class Disassembly:
    runs: tuple[tuple[str, ...], ...]
    total_decoded: int


def disassemble(sections: Sequence[Section], arch: str) -> Disassembly:
    bitness = BITS[arch]
    runs: list[tuple[str, ...]] = []
    total_decoded = 0

    for section in sections:
        section_runs, decoded = _disassemble_section(section.data, bitness)
        runs.extend(section_runs)
        total_decoded += decoded

    return Disassembly(runs=tuple(runs), total_decoded=total_decoded)


def _disassemble_section(data: bytes, bitness: int) -> tuple[list[tuple[str, ...]], int]:
    decoder = Decoder(bitness, data)

    runs: list[tuple[str, ...]] = []
    current: list[str] = []
    decoded = 0
    repeated = 0
    previous = ""

    def close_run() -> None:
        nonlocal repeated, previous
        if current:
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
            continue

        mnemonic = MNEMONICS[instruction.mnemonic]
        repeated = repeated + 1 if mnemonic == previous else 1
        previous = mnemonic
        if repeated <= NGRAM:
            current.append(mnemonic)
        decoded += 1

        if instruction.flow_control not in CONTINUES:
            close_run()

    close_run()
    return runs, decoded
