# The fixture binaries and the hand-built containers the test files share.

import struct
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "bin"
NAMES = ["fixture-pe-x64.exe", "fixture-pe-x86.exe", "fixture-elf-x64", "fixture-elf-x86"]
PE64 = FIXTURES / "fixture-pe-x64.exe"
PE32 = FIXTURES / "fixture-pe-x86.exe"
ELF64 = FIXTURES / "fixture-elf-x64"

MACHO = struct.pack("<I", 0xFEEDFACF) + bytes(4096)
JUNK = b"plain text, forever" * 20


def elf_header(machine: int) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4:8] = bytes((2, 1, 1, 0))
    struct.pack_into("<HHI", header, 16, 2, machine, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header)


# An ELF64 carrying one loadable executable segment, with the section table stripped. This is
# the ordinary shape of a packed or hostile ELF.
def stripped_elf(code: bytes) -> bytes:
    header = bytearray(elf_header(62))
    struct.pack_into("<Q", header, 24, 0x400078)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<Q", header, 40, 0)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 1, 0, 0, 0)

    program = bytearray(56)
    struct.pack_into("<II", program, 0, 1, 0x5)
    struct.pack_into("<QQQ", program, 8, 120, 0x400078, 0x400078)
    struct.pack_into("<QQQ", program, 32, len(code), len(code), 0x1000)

    return bytes(header) + bytes(program) + code
