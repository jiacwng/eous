# Fixture provenance

Every binary in `bin/` is built from the committed source in `src/`, with the
toolchain and commands recorded here. Rebuilding with the same toolchain
reproduces the same files.

## Toolchain

| Item | Value |
|---|---|
| Compiler | zig 0.16.0 |
| Tarball | `zig-x86_64-linux-0.16.0.tar.xz` |
| Tarball SHA-256 | `70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00` |
| Source | https://ziglang.org/download/0.16.0/ |

## Source

`src/fixture.c` — a deterministic program: a xorshift generator fills a buffer,
an FNV-1a checksum of the buffer is printed. Loops, branches, calls, shifts and
multiplications give the disassembler varied instructions to read. Every run
prints the same value, which doubles as a sanity check.

## Build

```
bash build.sh
```

The script runs, in order:

```
zig cc -target x86_64-windows-gnu -O1 -s -o bin/fixture-pe-x64.exe src/fixture.c
zig cc -target x86-windows-gnu   -O1 -s -o bin/fixture-pe-x86.exe src/fixture.c
zig cc -target x86_64-linux-gnu  -O1 -s -o bin/fixture-elf-x64 src/fixture.c
zig cc -target x86-linux-gnu     -O1 -s -o bin/fixture-elf-x86 src/fixture.c
```

The ABI is explicit in each target triple so the same triple produces the same
layout on any host. `-s` strips debug information: the PE pair would otherwise
ship a `.pdb` file each, and every binary would carry symbol tables the tests
ignore. The ELF pair links dynamically, keeping libc out of the file — tests
parse these binaries and leave them unexecuted, so runtime linking is free.
Measured sizes: 72 KB and 82 KB for PE, 3.4 KB and 2.3 KB for ELF.

## Binaries

| File | Format | Arch | Size | SHA-256 |
|---|---|---|---|---|
| `bin/fixture-pe-x64.exe` | PE, 7 sections | x86-64 | 73728 | `e0939ea16a2b2075e6785a93c4838a864c8134b72a992c0acd33de3c8f32927a` |
| `bin/fixture-pe-x86.exe` | PE, 6 sections | x86 | 83968 | `c9a127f34186746f04ef079d7a378c744b8e521d7b45b03df0bff3bb41ec2a41` |
| `bin/fixture-elf-x64` | ELF | x86-64 | 3520 | `36c222f7ef0f9b0e28e5ecb88f4e55f9549053d011c80196f45a45cfc5d3b61a` |
| `bin/fixture-elf-x86` | ELF | x86 | 2328 | `5dfb0c244e850ee14c050cfbb4663bc79dc697e9c4a1f54f4eb24a991d1e6155` |

Architecture was confirmed by reading the machine field directly: ELF `e_machine` at
offset 18 holds `0x3E` and `0x03`; PE `Machine` in the COFF header holds `0x8664`
and `0x014C`.

Program output, verified on `fixture-elf-x64` under Linux and `fixture-pe-x64.exe`
under Windows: `d7575bb2`. The value is identical across formats and architectures,
which confirms the four binaries carry the same program.
