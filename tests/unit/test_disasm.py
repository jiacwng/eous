import os
import struct
from pathlib import Path

import pytest

from eous import disasm, loader

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bin"

NOP = b"\x90"
RET = b"\xc3"
INT3 = b"\xcc"
ZEROS = b"\x00\x00"
JMP_SELF = b"\xeb\xfe"
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
        virtual_size=len(data),
        raw_size=len(data),
        executable=executable,
        writable=False,
        data=data,
    )


def binary(*sections: loader.Section, arch: str = "x86") -> loader.Binary:
    return loader.Binary(
        path=Path("synthetic"),
        format="pe",
        arch=arch,
        entry_point=0x1000,
        sections=tuple(sections),
        is_il_only=False,
        has_managed_native=False,
    )


def mnemonics(result: disasm.SweepResult) -> list[str]:
    return [m for chunk in result.chunks for m in chunk]


# ---- chunk boundaries -------------------------------------------------------


def test_a_terminator_ends_the_chunk() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + RET + XOR_EAX + RET)))
    assert result.chunks == (("xor", "ret"), ("xor", "ret"))


def test_a_decode_failure_ends_the_chunk() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + INVALID + XOR_EAX)))
    assert ("xor",) in result.chunks
    assert result.reports[0].stalls > 0


def test_the_end_of_a_region_ends_the_chunk() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + PUSH_EAX)))
    assert result.chunks == (("xor", "push"),)


def test_each_section_starts_a_fresh_chunk() -> None:
    first = section(XOR_EAX, name=".text", virtual_address=0x1000)
    second = section(PUSH_EAX, name=".code", virtual_address=0x2000)
    result = disasm.sweep(binary(first, second))
    assert result.chunks == (("xor",), ("push",))


@pytest.mark.parametrize("terminator", ["ret", "jmp", "call", "hlt", "syscall"])
def test_the_terminator_set_names_real_instructions(terminator: str) -> None:
    assert terminator in disasm.TERMINATORS


def test_conditional_branches_all_terminate() -> None:
    for mnemonic in ["je", "jne", "jz", "jnz", "ja", "jbe", "jg", "jle"]:
        assert mnemonic in disasm.TERMINATORS


def test_the_64_bit_far_return_terminates() -> None:
    assert "retfq" in disasm.TERMINATORS


# `repz ret` is the GCC x86-64 epilogue, so overlooking it merges adjacent functions.
PREFIXED_TERMINATORS = [
    (b"\xf3\xc3", "repz ret"),
    (b"\x48\xcb", "retfq"),
    (b"\x3e\xff\xe0", "notrack jmp"),
    (b"\x3e\xff\xd0", "notrack call"),
    (b"\xf2\xe9\x00\x00\x00\x00", "bnd jmp"),
]


@pytest.mark.parametrize(
    ("encoding", "label"), PREFIXED_TERMINATORS, ids=[p[1] for p in PREFIXED_TERMINATORS]
)
def test_a_prefixed_terminator_still_ends_the_chunk(encoding: bytes, label: str) -> None:
    body = b"\x55\x48\x89\xe5\x31\xc0"
    data = (body + encoding) * 2
    result = disasm.sweep(binary(section(data), arch="x86-64"))
    assert len(result.chunks) == 2, f"{label} failed to close the chunk: {result.chunks}"


def test_a_prefixed_ordinary_instruction_leaves_the_chunk_open() -> None:
    # `rep movsb` repeats in place, so execution does fall through to the next address.
    data = b"\x31\xc0" + b"\xf3\xa4" + b"\x31\xc0" + b"\xc3"
    result = disasm.sweep(binary(section(data), arch="x86-64"))
    assert result.chunks == (("xor", "rep movsb", "xor", "ret"),)


# ---- padding ----------------------------------------------------------------


def test_a_long_padding_run_collapses_to_one() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + NOP * 20 + RET)))
    assert mnemonics(result) == ["xor", "nop", "ret"]


def test_a_short_padding_run_survives_intact() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + NOP * 3 + RET)))
    assert mnemonics(result) == ["xor", "nop", "nop", "nop", "ret"]


def test_a_run_exactly_at_the_threshold_collapses() -> None:
    result = disasm.sweep(binary(section(NOP * disasm.PADDING_RUN + RET)))
    assert mnemonics(result) == ["nop", "ret"]


def test_one_below_the_threshold_survives() -> None:
    count = disasm.PADDING_RUN - 1
    result = disasm.sweep(binary(section(NOP * count + RET)))
    assert mnemonics(result) == ["nop"] * count + ["ret"]


def test_a_run_of_zero_bytes_collapses_as_padding() -> None:
    result = disasm.sweep(binary(section(ZEROS * 20 + RET)))
    assert mnemonics(result) == ["add", "ret"]


def test_int3_padding_collapses() -> None:
    result = disasm.sweep(binary(section(INT3 * 20 + RET)))
    assert mnemonics(result) == ["int3", "ret"]


def test_padding_of_differing_mnemonics_stays_separate() -> None:
    result = disasm.sweep(binary(section(NOP * 10 + INT3 * 10 + RET)))
    assert mnemonics(result) == ["nop", "int3", "ret"]


def test_ordinary_instructions_survive_a_long_run() -> None:
    result = disasm.sweep(binary(section(PUSH_EAX * 20 + RET)))
    assert mnemonics(result).count("push") == 20


# ---- skip reasons -----------------------------------------------------------


def test_a_high_entropy_region_is_skipped_by_name() -> None:
    packed = section(os.urandom(8192))
    assert packed.entropy > loader.ENTROPY_THRESHOLD
    result = disasm.sweep(binary(packed))
    assert result.chunks == ()
    assert result.reports[0].skipped == disasm.ENTROPY


def test_a_region_exactly_at_the_threshold_is_skipped() -> None:
    edge = section(XOR_EAX * 50)
    result = disasm.sweep(binary(edge), entropy_threshold=edge.entropy)
    assert result.reports[0].skipped == disasm.ENTROPY


def test_a_region_just_under_the_threshold_is_swept() -> None:
    edge = section(XOR_EAX * 50 + RET)
    result = disasm.sweep(binary(edge), entropy_threshold=edge.entropy + 0.000001)
    assert result.reports[0].skipped is None


def test_an_empty_region_is_skipped_by_name() -> None:
    result = disasm.sweep(binary(section(b"")))
    assert result.reports[0].skipped == disasm.EMPTY


def test_a_region_of_pure_noise_is_skipped_for_stalls() -> None:
    result = disasm.sweep(binary(section(INVALID * 200)), max_stalls=10)
    assert result.reports[0].skipped == disasm.STALLED


def test_the_instruction_budget_is_reported_by_name() -> None:
    result = disasm.sweep(binary(section(PUSH_EAX * 100)), max_instructions=10)
    assert result.reports[0].skipped == disasm.BUDGET
    assert result.reports[0].decoded == 10


def test_a_swept_region_leaves_its_skip_reason_empty() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + RET)))
    assert result.reports[0].skipped is None


def test_non_executable_sections_are_left_alone() -> None:
    data = section(XOR_EAX + RET, name=".rdata", executable=False)
    result = disasm.sweep(binary(data))
    assert result.reports == ()
    assert result.chunks == ()


# ---- budgets are per region -------------------------------------------------


# A shared budget would tie the digest to the order sections appear in.
def test_the_budget_applies_to_each_region_separately() -> None:
    first = section(PUSH_EAX * 20, name=".a", virtual_address=0x1000)
    second = section(PUSH_EAX * 20, name=".b", virtual_address=0x2000)
    result = disasm.sweep(binary(first, second), max_instructions=10)
    assert [r.decoded for r in result.reports] == [10, 10]


def test_section_order_leaves_the_result_unchanged() -> None:
    low = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    high = section(PUSH_EAX + RET, name=".b", virtual_address=0x2000)
    forward = disasm.sweep(binary(low, high))
    backward = disasm.sweep(binary(high, low))
    assert forward.chunks == backward.chunks


# ---- results ----------------------------------------------------------------


def test_total_decoded_sums_the_regions() -> None:
    first = section(XOR_EAX + RET, name=".a", virtual_address=0x1000)
    second = section(PUSH_EAX + RET, name=".b", virtual_address=0x2000)
    result = disasm.sweep(binary(first, second))
    assert result.total_decoded == sum(r.decoded for r in result.reports)


def test_every_region_gets_a_named_report() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + RET, name=".text")))
    assert [r.name for r in result.reports] == [".text"]


def test_every_region_compressed_gives_a_full_share() -> None:
    packed = section(os.urandom(8192))
    assert disasm.sweep(binary(packed)).compressed_share == 1.0


def test_a_substantial_readable_region_lowers_the_share() -> None:
    packed = section(os.urandom(8192), name=".a", virtual_address=0x1000)
    clean = section((XOR_EAX + RET) * 4096, name=".b", virtual_address=0x2000)
    assert disasm.sweep(binary(packed, clean)).compressed_share < 0.5


# A section holds at most log2(size) bits of entropy, so a tiny readable region can sit
# beside a compressed one without meaning the binary is readable.
def test_a_tiny_readable_region_leaves_the_share_high() -> None:
    packed = section(os.urandom(8192), name=".a", virtual_address=0x1000)
    clean = section(XOR_EAX + RET, name=".b", virtual_address=0x2000)
    assert disasm.sweep(binary(packed, clean)).compressed_share > 0.99


def test_a_binary_holding_only_data_has_no_share() -> None:
    quiet = section(XOR_EAX, name=".rdata", executable=False)
    assert disasm.sweep(binary(quiet)).compressed_share == 0.0


def test_an_empty_region_has_no_share() -> None:
    assert disasm.sweep(binary(section(b""))).compressed_share == 0.0


def test_a_readable_binary_has_no_compressed_share() -> None:
    clean = section((XOR_EAX + RET) * 64)
    assert disasm.sweep(binary(clean)).compressed_share == 0.0


def test_results_are_frozen() -> None:
    result = disasm.sweep(binary(section(XOR_EAX + RET)))
    with pytest.raises(AttributeError):
        result.total_decoded = 0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.reports[0].decoded = 0  # type: ignore[misc]


# ---- architecture -----------------------------------------------------------


def test_both_architectures_decode() -> None:
    for arch in ("x86", "x86-64"):
        result = disasm.sweep(binary(section(XOR_EAX + RET), arch=arch))
        assert mnemonics(result) == ["xor", "ret"]


def test_an_unknown_architecture_raises() -> None:
    with pytest.raises(disasm.DisasmError, match="mips"):
        disasm.sweep(binary(section(XOR_EAX), arch="mips"))


# ---- adversarial addresses --------------------------------------------------


def test_a_section_addressed_near_the_top_of_memory_still_sweeps() -> None:
    data = (XOR_EAX + RET) * 40
    low = disasm.sweep(binary(section(data, virtual_address=0x1000), arch="x86-64"))
    high = disasm.sweep(binary(section(data, virtual_address=0xFFFFFFFFFFFFFFF8), arch="x86-64"))
    assert high.chunks == low.chunks
    assert high.reports[0].stalls == 0
    assert high.reports[0].skipped is None


def test_a_wrapping_address_decodes_every_instruction() -> None:
    data = NOP * 64 + RET
    result = disasm.sweep(binary(section(data, virtual_address=0xFFFFFFFFFFFFFF00), arch="x86-64"))
    assert result.total_decoded == 65
    assert result.reports[0].stalls == 0


# ---- the real fixtures ------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["fixture-pe-x64.exe", "fixture-pe-x86.exe", "fixture-elf-x64", "fixture-elf-x86"],
)
def test_every_fixture_sweeps(name: str) -> None:
    # The smallest fixture is a stripped 2,328-byte ELF that decodes 97 instructions.
    result = disasm.sweep(loader.load(FIXTURES / name))
    assert result.total_decoded > 50
    assert result.chunks
    assert all(chunk for chunk in result.chunks)
    assert all(report.skipped is None for report in result.reports)


def make_stripped_elf(code: bytes) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4:8] = bytes((2, 1, 1, 0))
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<Q", header, 24, 0x400078)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<Q", header, 40, 0)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 1, 0, 0, 0)

    program = bytearray(56)
    struct.pack_into("<II", program, 0, 1, 0x5)
    struct.pack_into("<QQQ", program, 8, 120, 0x400078, 0x400078)
    struct.pack_into("<QQQ", program, 32, len(code), len(code), 0x1000)

    return bytes(header) + bytes(program) + code


def test_a_stripped_elf_sweeps_to_real_mnemonics(tmp_path: Path) -> None:
    target = tmp_path / "stripped.elf"
    target.write_bytes(make_stripped_elf((XOR_EAX + RET) * 20))

    result = disasm.sweep(loader.load(target))
    assert result.total_decoded == 40
    assert result.chunks == (("xor", "ret"),) * 20
    assert result.reports[0].skipped is None


def test_a_stripped_elf_sweeps_the_same_way_as_a_sectioned_one(tmp_path: Path) -> None:
    code = (XOR_EAX + RET) * 20
    target = tmp_path / "stripped.elf"
    target.write_bytes(make_stripped_elf(code))

    from_segment = disasm.sweep(loader.load(target))
    from_section = disasm.sweep(binary(section(code, virtual_address=0x400078), arch="x86-64"))
    assert from_segment.chunks == from_section.chunks


def test_a_fixture_sweeps_the_same_way_twice() -> None:
    path = FIXTURES / "fixture-elf-x64"
    assert disasm.sweep(loader.load(path)).chunks == disasm.sweep(loader.load(path)).chunks


def test_fixture_chunks_are_short() -> None:
    # Measured: these fixtures average 7 to 10, real corpus binaries 4.61. T-1's subject.
    result = disasm.sweep(loader.load(FIXTURES / "fixture-pe-x64.exe"))
    mean = result.total_decoded / len(result.chunks)
    assert 1.0 < mean < 20.0
