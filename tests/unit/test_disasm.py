import os
from pathlib import Path

import pytest

from conftest import FIXTURES, NAMES, stripped_elf
from eous import digest, disasm, loader

NOP = b"\x90"
RET = b"\xc3"
INT3 = b"\xcc"
ZEROS = b"\x00\x00"
INVALID = b"\xff\xff"
XOR_EAX = b"\x31\xc0"
PUSH_EAX = b"\x50"


def section(
    data: bytes,
    name: str = ".text",
    virtual_address: int = 0x1000,
    executable: bool = True,
) -> loader.Section:
    return loader.Section(
        name=name,
        virtual_address=virtual_address,
        executable=executable,
        writable=False,
        data=data,
    )


def binary(*sections: loader.Section, arch: str = "x86") -> loader.Binary:
    return loader.Binary(
        format="pe",
        arch=arch,
        bits=loader.BITS[arch],
        sections=tuple(sections),
        is_il_only=False,
        has_managed_native=False,
    )


def mnemonics(result: disasm.Disassembly) -> list[str]:
    return [m for run in result.runs for m in run]


def test_a_terminator_ends_the_run() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + RET + XOR_EAX + RET)))
    assert result.runs == (("xor", "ret"), ("xor", "ret"))


def test_a_decode_failure_ends_the_run() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + INVALID + XOR_EAX)))
    assert ("xor",) in result.runs
    assert result.reports[0].undecodable > 0


def test_the_end_of_a_section_ends_the_run() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + PUSH_EAX)))
    assert result.runs == (("xor", "push"),)


def test_each_section_starts_a_fresh_run() -> None:
    first = section(XOR_EAX, name=".text", virtual_address=0x1000)
    second = section(PUSH_EAX, name=".code", virtual_address=0x2000)
    result = disasm.disassemble(binary(first, second))
    assert result.runs == (("xor",), ("push",))


# Each instruction goes after a body and has to close the run.
BODY = b"\x55\x48\x89\xe5\x31\xc0"

ENDS_A_RUN = [
    (b"\xc3", "ret"),
    (b"\x48\xcb", "retfq"),
    (b"\xeb\x00", "jmp"),
    (b"\xff\xe0", "jmp rax"),
    (b"\xe8\x00\x00\x00\x00", "call"),
    (b"\xff\xd0", "call rax"),
    (b"\x0f\x05", "syscall"),
    (b"\x0f\x0b", "ud2"),
    (b"\x74\x00", "je"),
    (b"\x75\x00", "jne"),
    (b"\x77\x00", "ja"),
    (b"\x76\x00", "jbe"),
    (b"\x7f\x00", "jg"),
    (b"\x7e\x00", "jle"),
    (b"\xe2\x00", "loop"),
    (b"\xe3\x00", "jrcxz"),
    (b"\xf3\xc3", "repz ret"),
    (b"\x3e\xff\xe0", "notrack jmp"),
    (b"\x3e\xff\xd0", "notrack call"),
    (b"\xf2\xe9\x00\x00\x00\x00", "bnd jmp"),
]


@pytest.mark.parametrize(("encoding", "label"), ENDS_A_RUN, ids=[p[1] for p in ENDS_A_RUN])
def test_control_flow_ends_the_run(encoding: bytes, label: str) -> None:
    result = disasm.disassemble(binary(section((BODY + encoding) * 2), arch="x86-64"))
    assert len(result.runs) == 2, f"{label} left the run open: {result.runs}"


# int3 is usually padding between functions, so a run continues through it.
FALLS_THROUGH = [(b"\xcc", "int3"), (b"\xf4", "hlt"), (b"\x90", "nop")]


@pytest.mark.parametrize(("encoding", "label"), FALLS_THROUGH, ids=[p[1] for p in FALLS_THROUGH])
def test_an_instruction_that_falls_through_keeps_the_run_open(encoding: bytes, label: str) -> None:
    result = disasm.disassemble(binary(section(BODY + encoding + BODY + b"\xc3"), arch="x86-64"))
    assert len(result.runs) == 1, f"{label} closed the run: {result.runs}"


def test_a_prefixed_ordinary_instruction_leaves_the_run_open() -> None:
    # `rep movsb` repeats in place, so execution does fall through to the next address.
    # The decoder reports the prefix separately, so the mnemonic arrives here as `movsb`.
    data = b"\x31\xc0" + b"\xf3\xa4" + b"\x31\xc0" + b"\xc3"
    result = disasm.disassemble(binary(section(data), arch="x86-64"))
    assert result.runs == (("xor", "movsb", "xor", "ret"),)


# Filler between functions is one instruction repeated. A window past the cap repeats a
# window already produced, so the cap is the shingle width and no number of its own.
CAP = digest.NGRAM


def test_a_long_repeat_is_capped_at_the_shingle_width() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + NOP * 20 + RET)), repeat_cap=CAP)
    assert mnemonics(result) == ["xor"] + ["nop"] * CAP + ["ret"]


def test_a_repeat_shorter_than_the_cap_survives_intact() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + NOP * 3 + RET)), repeat_cap=CAP)
    assert mnemonics(result) == ["xor", "nop", "nop", "nop", "ret"]


def test_a_repeat_exactly_at_the_cap_survives_intact() -> None:
    result = disasm.disassemble(binary(section(NOP * CAP + RET)), repeat_cap=CAP)
    assert mnemonics(result) == ["nop"] * CAP + ["ret"]


def test_zero_bytes_are_capped_like_any_repeat() -> None:
    result = disasm.disassemble(binary(section(ZEROS * 20 + RET)), repeat_cap=CAP)
    assert mnemonics(result) == ["add"] * CAP + ["ret"]


def test_two_repeats_are_capped_separately() -> None:
    result = disasm.disassemble(binary(section(NOP * 10 + INT3 * 10 + RET)), repeat_cap=CAP)
    assert mnemonics(result) == ["nop"] * CAP + ["int3"] * CAP + ["ret"]


def test_no_cap_keeps_every_instruction() -> None:
    result = disasm.disassemble(binary(section(NOP * 20 + RET)))
    assert mnemonics(result) == ["nop"] * 20 + ["ret"]


# The cap exists because these two sets are equal, which is what lets it carry no number.
def test_capping_gives_the_shingle_set_that_keeping_everything_gives() -> None:
    data = XOR_EAX + NOP * 40 + RET + PUSH_EAX * 9 + RET
    capped = disasm.disassemble(binary(section(data), arch="x86-64"), repeat_cap=CAP).runs
    whole = disasm.disassemble(binary(section(data), arch="x86-64")).runs
    assert digest.shingles(digest.normalise(capped, "pe64")) == digest.shingles(
        digest.normalise(whole, "pe64")
    )


def test_a_run_shorter_than_the_minimum_is_dropped() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + RET + (XOR_EAX * 3) + RET)), minimum_run=3)
    assert result.runs == (("xor", "xor", "xor", "ret"),)


def test_a_high_entropy_section_is_skipped_by_name() -> None:
    packed = section(os.urandom(8192))
    assert packed.entropy > loader.ENTROPY_THRESHOLD
    result = disasm.disassemble(binary(packed))
    assert result.runs == ()
    assert result.reports[0].skipped == disasm.ENTROPY


# 128 equally frequent bytes carry exactly log2(128) = 7.0 bits, which is the threshold, so
# these two pin that the comparison includes its boundary.
def test_a_section_exactly_at_the_threshold_is_skipped() -> None:
    edge = section(bytes(range(128)) * 64)
    assert edge.entropy == loader.ENTROPY_THRESHOLD
    result = disasm.disassemble(binary(edge))
    assert result.reports[0].skipped == disasm.ENTROPY


def test_a_section_just_under_the_threshold_is_disassembled() -> None:
    edge = section(bytes(range(127)) * 64)
    assert edge.entropy < loader.ENTROPY_THRESHOLD
    result = disasm.disassemble(binary(edge))
    assert result.reports[0].skipped is None


def test_an_empty_section_decodes_nothing() -> None:
    result = disasm.disassemble(binary(section(b"")))
    assert result.runs == ()
    assert result.reports[0].decoded == 0
    assert result.reports[0].skipped is None


def test_a_disassembled_section_leaves_its_skip_reason_empty() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + RET)))
    assert result.reports[0].skipped is None


def test_non_executable_sections_are_left_alone() -> None:
    data = section(XOR_EAX + RET, name=".rdata", executable=False)
    result = disasm.disassemble(binary(data))
    assert result.reports == ()
    assert result.runs == ()


def test_a_section_of_one_byte_instructions_is_read_to_its_end() -> None:
    result = disasm.disassemble(binary(section(PUSH_EAX * 5000 + RET)))
    assert result.reports[0].skipped is None
    assert result.reports[0].decoded == 5001


def test_a_section_that_never_decodes_is_read_to_its_end() -> None:
    result = disasm.disassemble(binary(section(INVALID * 2000)))
    assert result.reports[0].skipped is None
    assert result.reports[0].undecodable == 4000


def test_section_order_leaves_the_result_unchanged() -> None:
    low = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    high = section(PUSH_EAX + RET, name=".b", virtual_address=0x2000)
    forward = disasm.disassemble(binary(low, high))
    backward = disasm.disassemble(binary(high, low))
    assert forward.runs == backward.runs


def test_total_decoded_sums_the_sections() -> None:
    first = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    second = section(PUSH_EAX + RET, name=".b", virtual_address=0x2000)
    result = disasm.disassemble(binary(first, second))
    assert result.total_decoded == sum(r.decoded for r in result.reports)


def test_every_section_gets_a_named_report() -> None:
    result = disasm.disassemble(binary(section(XOR_EAX + RET, name=".text")))
    assert [r.name for r in result.reports] == [".text"]


def test_every_section_compressed_gives_a_full_share() -> None:
    packed = section(os.urandom(8192))
    assert disasm.disassemble(binary(packed)).compressed_share == 1.0


def test_a_substantial_readable_section_lowers_the_share() -> None:
    packed = section(os.urandom(8192), name=".a", virtual_address=0x1000)
    clean = section((XOR_EAX + RET) * 4096, name=".b", virtual_address=0x2000)
    assert disasm.disassemble(binary(packed, clean)).compressed_share < 0.5


# A section holds at most log2(size) bits of entropy, so a tiny readable section can sit
# beside a compressed one without meaning the binary is readable.
def test_a_tiny_readable_section_leaves_the_share_high() -> None:
    packed = section(os.urandom(8192), name=".a", virtual_address=0x1000)
    clean = section(XOR_EAX + RET, name=".b", virtual_address=0x2000)
    assert disasm.disassemble(binary(packed, clean)).compressed_share > 0.99


def test_a_binary_holding_only_data_has_no_share() -> None:
    quiet = section(XOR_EAX, name=".rdata", executable=False)
    assert disasm.disassemble(binary(quiet)).compressed_share == 0.0


def test_an_empty_section_has_no_share() -> None:
    assert disasm.disassemble(binary(section(b""))).compressed_share == 0.0


def test_a_readable_binary_has_no_compressed_share() -> None:
    clean = section((XOR_EAX + RET) * 64)
    assert disasm.disassemble(binary(clean)).compressed_share == 0.0


def test_both_architectures_decode() -> None:
    for arch in ("x86", "x86-64"):
        result = disasm.disassemble(binary(section(XOR_EAX + RET), arch=arch))
        assert mnemonics(result) == ["xor", "ret"]


def test_a_section_addressed_near_the_top_of_memory_still_decodes() -> None:
    data = (XOR_EAX + RET) * 40
    low = disasm.disassemble(binary(section(data, virtual_address=0x1000), arch="x86-64"))
    high = disasm.disassemble(
        binary(section(data, virtual_address=0xFFFFFFFFFFFFFFF8), arch="x86-64")
    )
    assert high.runs == low.runs
    assert high.reports[0].undecodable == 0
    assert high.reports[0].skipped is None


def test_a_wrapping_address_decodes_every_instruction() -> None:
    data = NOP * 64 + RET
    result = disasm.disassemble(
        binary(section(data, virtual_address=0xFFFFFFFFFFFFFF00), arch="x86-64")
    )
    assert result.total_decoded == 65
    assert result.reports[0].undecodable == 0


@pytest.mark.parametrize("name", NAMES)
def test_every_fixture_decodes(name: str) -> None:
    # The smallest fixture is a stripped 2,328-byte ELF that decodes 97 instructions.
    result = disasm.disassemble(loader.load(FIXTURES / name))
    assert result.total_decoded > 50
    assert result.runs
    assert all(run for run in result.runs)
    assert all(report.skipped is None for report in result.reports)


def test_a_stripped_elf_decodes_to_real_mnemonics(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf((XOR_EAX + RET) * 20))

    result = disasm.disassemble(loader.load(target))
    assert result.total_decoded == 40
    assert result.runs == (("xor", "ret"),) * 20
    assert result.reports[0].skipped is None


def test_a_stripped_elf_decodes_the_same_way_as_a_sectioned_one(tmp_path: Path) -> None:
    code = (XOR_EAX + RET) * 20
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf(code))

    from_segment = disasm.disassemble(loader.load(target))
    from_section = disasm.disassemble(
        binary(section(code, virtual_address=0x400078), arch="x86-64")
    )
    assert from_segment.runs == from_section.runs
