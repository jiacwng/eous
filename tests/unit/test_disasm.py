from pathlib import Path

import pytest

import reference
from conftest import FIXTURES, NAMES, stripped_elf
from eous import loader

NOP = b"\x90"
RET = b"\xc3"
INT3 = b"\xcc"
ZEROS = b"\x00\x00"
INVALID = b"\xff\xff"
XOR_EAX = b"\x31\xc0"
PUSH_EAX = b"\x50"


def section(data: bytes, name: str = ".text", virtual_address: int = 0x1000) -> loader.Section:
    return loader.Section(name=name, virtual_address=virtual_address, writable=False, data=data)


def disassemble(*sections: loader.Section, arch: str = "x86") -> reference.Disassembly:
    return reference.disassemble(sections, arch)


def from_file(path: Path) -> reference.Disassembly:
    binary = loader.load(path)
    return reference.disassemble(binary.sections, binary.arch)


def mnemonics(result: reference.Disassembly) -> list[str]:
    return [m for run in result.runs for m in run]


def test_a_terminator_ends_the_run() -> None:
    result = disassemble(section(XOR_EAX + RET + XOR_EAX + RET))
    assert result.runs == (("xor", "ret"), ("xor", "ret"))


def test_a_decode_failure_ends_the_run() -> None:
    result = disassemble(section(XOR_EAX + INVALID + XOR_EAX))
    assert result.runs[0] == ("xor",)


def test_the_end_of_a_section_ends_the_run() -> None:
    result = disassemble(section(XOR_EAX + PUSH_EAX))
    assert result.runs == (("xor", "push"),)


def test_each_section_starts_a_fresh_run() -> None:
    first = section(XOR_EAX, name=".text", virtual_address=0x1000)
    second = section(PUSH_EAX, name=".code", virtual_address=0x2000)
    result = disassemble(first, second)
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
    result = disassemble(section((BODY + encoding) * 2), arch="x86-64")
    assert len(result.runs) == 2, f"{label} left the run open: {result.runs}"


# int3 is usually padding between functions, so a run continues through it.
FALLS_THROUGH = [(b"\xcc", "int3"), (b"\xf4", "hlt"), (b"\x90", "nop")]


@pytest.mark.parametrize(("encoding", "label"), FALLS_THROUGH, ids=[p[1] for p in FALLS_THROUGH])
def test_an_instruction_that_falls_through_keeps_the_run_open(encoding: bytes, label: str) -> None:
    result = disassemble(section(BODY + encoding + BODY + b"\xc3"), arch="x86-64")
    assert len(result.runs) == 1, f"{label} closed the run: {result.runs}"


def test_a_prefixed_ordinary_instruction_leaves_the_run_open() -> None:
    # `rep movsb` repeats in place, so execution does fall through to the next address.
    # The decoder reports the prefix separately, so the mnemonic arrives here as `movsb`.
    data = b"\x31\xc0" + b"\xf3\xa4" + b"\x31\xc0" + b"\xc3"
    result = disassemble(section(data), arch="x86-64")
    assert result.runs == (("xor", "movsb", "xor", "ret"),)


# Filler between functions is one instruction repeated. A window past the cap repeats a
# window already produced, so the cap is the shingle width and no number of its own.
CAP = reference.NGRAM


def test_a_long_repeat_is_capped_at_the_shingle_width() -> None:
    result = disassemble(section(XOR_EAX + NOP * 20 + RET))
    assert mnemonics(result) == ["xor"] + ["nop"] * CAP + ["ret"]


def test_a_repeat_shorter_than_the_cap_survives_intact() -> None:
    result = disassemble(section(XOR_EAX + NOP * 3 + RET))
    assert mnemonics(result) == ["xor", "nop", "nop", "nop", "ret"]


def test_a_repeat_exactly_at_the_cap_survives_intact() -> None:
    result = disassemble(section(NOP * CAP + RET))
    assert mnemonics(result) == ["nop"] * CAP + ["ret"]


def test_zero_bytes_are_capped_like_any_repeat() -> None:
    result = disassemble(section(ZEROS * 20 + RET))
    assert mnemonics(result) == ["add"] * CAP + ["ret"]


def test_two_repeats_are_capped_separately() -> None:
    result = disassemble(section(NOP * 10 + INT3 * 10 + RET))
    assert mnemonics(result) == ["nop"] * CAP + ["int3"] * CAP + ["ret"]


# The cap exists because these two sets are equal, which is what lets it carry no number.
def test_capping_gives_the_shingle_set_that_keeping_everything_gives() -> None:
    capped = disassemble(section(XOR_EAX + NOP * 40 + RET + PUSH_EAX * 9 + RET), arch="x86-64")
    whole = (("xor", *["nop"] * 40, "ret"), ("push",) * 9 + ("ret",))
    assert reference.shingles(reference.normalise(capped.runs)) == reference.shingles(
        reference.normalise(whole)
    )


def test_a_short_run_is_kept_for_the_shingles_to_skip() -> None:
    result = disassemble(section(XOR_EAX + RET + (XOR_EAX * 3) + RET))
    assert result.runs == (("xor", "ret"), ("xor", "xor", "xor", "ret"))
    assert reference.shingles(reference.normalise(result.runs)) == set()


def test_an_empty_section_decodes_nothing() -> None:
    result = disassemble(section(b""))
    assert result.runs == ()
    assert result.total_decoded == 0


def test_a_section_of_one_byte_instructions_is_read_to_its_end() -> None:
    result = disassemble(section(PUSH_EAX * 5000 + RET))
    assert result.total_decoded == 5001


def test_a_section_that_never_decodes_is_read_to_its_end() -> None:
    result = disassemble(section(INVALID * 2000))
    assert result.runs == ()
    assert result.total_decoded == 0


def test_section_order_is_the_order_given() -> None:
    low = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    high = section(PUSH_EAX + RET, name=".b", virtual_address=0x2000)
    assert disassemble(low, high).runs == (("xor", "ret"), ("push", "ret"))


def test_total_decoded_sums_the_sections() -> None:
    first = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    second = section(PUSH_EAX + NOP + RET, name=".b", virtual_address=0x2000)
    assert disassemble(first, second).total_decoded == 5


def test_both_architectures_decode() -> None:
    for arch in ("x86", "x86-64"):
        result = disassemble(section(XOR_EAX + RET), arch=arch)
        assert mnemonics(result) == ["xor", "ret"]


def test_a_section_addressed_near_the_top_of_memory_still_decodes() -> None:
    data = (XOR_EAX + RET) * 40
    low = disassemble(section(data, virtual_address=0x1000), arch="x86-64")
    high = disassemble(section(data, virtual_address=0xFFFFFFFFFFFFFFF8), arch="x86-64")
    assert high.runs == low.runs
    assert high.total_decoded == 80


def test_a_wrapping_address_decodes_every_instruction() -> None:
    data = NOP * 64 + RET
    result = disassemble(section(data, virtual_address=0xFFFFFFFFFFFFFF00), arch="x86-64")
    assert result.total_decoded == 65


@pytest.mark.parametrize("name", NAMES)
def test_every_fixture_decodes(name: str) -> None:
    # The smallest fixture is a stripped 2,328-byte ELF that decodes 97 instructions.
    result = from_file(FIXTURES / name)
    assert result.total_decoded > 50
    assert result.runs
    assert all(run for run in result.runs)


def test_a_stripped_elf_decodes_to_real_mnemonics(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf((XOR_EAX + RET) * 20))

    result = from_file(target)
    assert result.total_decoded == 40
    assert result.runs == (("xor", "ret"),) * 20


def test_a_stripped_elf_decodes_the_same_way_as_a_sectioned_one(tmp_path: Path) -> None:
    code = (XOR_EAX + RET) * 20
    target = tmp_path / "stripped.elf"
    target.write_bytes(stripped_elf(code))

    from_segment = from_file(target)
    from_section = disassemble(section(code, virtual_address=0x400078), arch="x86-64")
    assert from_segment.runs == from_section.runs
