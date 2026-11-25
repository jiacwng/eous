# eous

[![ci](https://github.com/jiacwng/eous/actions/workflows/ci.yml/badge.svg)](https://github.com/jiacwng/eous/actions/workflows/ci.yml)

eous is a fuzzy hashing tool for PE and ELF binaries. It is made for malware triage: given a
new sample, it finds the known samples that share its code. It reads the mnemonics/opcodes of
an x86 or x86-64 executable and turns them into a 512-bit hash. Comparing two hashes gives a
similarity score from 0 to 100%. Builds of the same program score high even when their bytes
differ.

```
$ eous hash rg-14.0.0.exe
EO1:pe32:7160:0b3513e7d37451457b891713b0b2082822736fabf3074e5dc1993f0368c520d6c5...
```

## Install

```
pip install eous
```

Python 3.12 or later, on Linux, Windows or macOS.

## Usage

`hash` prints a digest for each file. A directory is walked recursively.

```
$ eous hash samples/
samples/fd-10.2.0.exe  EO1:pe32:5230:f8e49feddbf691757b84371b737e1862e23363aabb07cc...
samples/rg-13.0.0.exe  EO1:pe32:6503:0b271dd5c3785149fb82c71363f20828207b9fabb36740...
samples/rg-14.0.0.exe  EO1:pe32:7160:0b3513e7d37451457b891713b0b2082822736fabf3074e...
samples/rg-14.1.0.exe  EO1:pe32:7102:3b05d3c7d37411757b8b172370b20828227363abf3074e...
```

`compare` scores two files or two digests. Containment says how much of one file's code is
found in the other.

```
$ eous compare rg-14.0.0.exe rg-14.1.0.exe
similarity:  82.3% +/- 3.0
containment: rg-14.0.0.exe in rg-14.1.0.exe   89.9%
             rg-14.1.0.exe in rg-14.0.0.exe   90.7%
```

`match` ranks a list of digests against one file, closest first. `hash --json` writes that
list, one line per file with its sha256.

```
$ eous hash --json samples/ > known.jsonl
$ eous match suspect.exe known.jsonl
 70.8% +/- 3.6  37b10903cc0f...  samples/rg-14.1.0.exe
 67.7% +/- 3.7  18ffabc518bb...  samples/rg-14.0.0.exe
 54.2% +/- 4.0  4125309a857e...  samples/rg-13.0.0.exe
 44.3% +/- 4.1  afacf221d0d2...  samples/fd-10.2.0.exe
```

`cross` scores every pair in a list of digests. Pairs print in scan order, so memory stays
flat on a large list. Pipe through `sort -rn` to read them best first.

```
$ eous cross known.jsonl --min 55 | sort -rn
```

`cluster` groups a list of digests. Two files share a cluster when a chain of pairs scoring
at least `--min` joins them.

```
$ eous cluster known.jsonl --min 55
pe32:1  afacf221d0d2...  samples/fd-10.2.0.exe
pe32:2  4125309a857e...  samples/rg-13.0.0.exe
pe32:2  18ffabc518bb...  samples/rg-14.0.0.exe
pe32:2  37b10903cc0f...  samples/rg-14.1.0.exe
```

`functions` compares one file with a list function by function. `hash --json --functions`
writes that list, with one digest for each function of 256 bytes or more. The first lines
rank the stored files by how much of their function code matches. Then each function of the
file gets a line: its address, its size, its best score, how many stored files hold a match,
and where the best match is.

```
$ eous hash --json --functions samples/ > functions.jsonl
$ eous functions suspect.exe functions.jsonl --sort score
functions  52.8%  file  70.8% +/- 3.6  37b10903cc0f...  samples/rg-14.1.0.exe
functions  48.0%  file  67.7% +/- 3.7  18ffabc518bb...  samples/rg-14.0.0.exe
functions  13.6%  file  54.2% +/- 4.0  4125309a857e...  samples/rg-13.0.0.exe
functions   8.5%  file  44.3% +/- 4.1  afacf221d0d2...  samples/fd-10.2.0.exe

0x4465e0  277 bytes  100.0%  2 files  37b10903cc0f...:0x45a950
0x4674c0  276 bytes  100.0%  4 files  18ffabc518bb...:0x47a910
0x48ab20  485 bytes  100.0%  4 files  18ffabc518bb...:0x4b7830
```

Every command takes `--json`. `match` and `cross` take `--min PERCENT`. `match` and
`functions` take `--top N`. `match`, `cross`, `cluster` and `functions` take `--labels FILE`.
A labels file holds a sha256, a tab and a name on each line. The name is then printed beside
each file. `functions` also takes `--sort` and `--names FILE`, a file of sha256, address and
function name.

Use scores to rank files, not as a yes or no. Programs written in the same language share
library code, so unrelated programs never score near zero. In the example, fd scores 44%
against ripgrep although it is a different program. Every ripgrep version scores higher.

Exit codes: 0 when every file got a digest, 1 when a file or directory was refused, 2 for a
usage error, 3 for an internal error.

## How it works

eous disassembles the code of the file. It replaces each instruction with its general kind,
so `add` and `adc` count as the same thing. It then collects every sequence of three
instructions in a row and keeps a compact summary of that collection, a MinHash sketch. The
more sequences two files share, the higher their score.

Recompiling a program moves its code and changes its addresses. The sequences of
instructions mostly stay the same, so the score stays high.

## How well it works

eous was tested on 2,900 malware samples and about 116,000 program files, beside the tools
people already use for this:

- tlsh and ssdeep compare the raw bytes of two files.
- imports compares the lists of system functions two files call. imphash is a hash of that
  list.
- File size alone is the baseline every tool must beat.

Each cell gives two numbers. The first is AUC: the chance that a related pair scores higher
than an unrelated one, where 0.5 is a coin flip and 1.0 is perfect. The second is how often
the closest match to a file is related to it.

### Malware

Two samples count as related when they belong to the same malware family. Identical copies
count once.

| tool | MalwareBazaar Windows, 768 | MalwareBazaar Linux, 278 | MOTIF Windows, 1,828 |
|---|---|---|---|
| eous | 0.786 / 67% | 0.735 / 80% | 0.635 / 60% |
| imports | 0.781 / 48% | | 0.709 / 62% |
| tlsh | 0.734 / 63% | 0.728 / 79% | 0.708 / 54% |
| imphash | 0.593 / 31% | | 0.509 / 21% |
| ssdeep | 0.506 / 20% | 0.506 / 42% | 0.512 / 21% |
| file size | 0.705 / 32% | 0.722 / 63% | 0.678 / 19% |

On malware, eous, tlsh and imports are close, and none of them clearly wins. imphash works on
Windows files only. imports finds almost nothing in Linux malware, so it is left out there.

`functions` was built and tried on 1,617 MalwareBazaar samples. For 400 of them, the closest
other file was of the same family 334 times by function score and 331 times by file score.

### Rebuilt programs

The programs come from Assemblage, a public dataset of GitHub projects built with many
compilers and settings. Two files count as related when they are the same program. eous was
tuned on this dataset.

| tool | Windows, 56,145 files | Linux, 59,990 files |
|---|---|---|
| imports | 0.977 / 79% | 0.981 / 84% |
| eous | 0.807 / 48% | 0.898 / 66% |
| tlsh | 0.794 / 47% | 0.947 / 70% |
| imphash | 0.597 / 48% | |
| ssdeep | 0.592 / 32% | 0.650 / 54% |
| file size | 0.794 / 6% | 0.916 / 18% |

eous does best when the same code is built a different way. Matching a Debug build to the
Release build of the same Windows program, eous scores 0.726 and tlsh 0.570.

### Speed

eous hashes a file in 18.5 ms on one core. tlsh takes 17.6 ms and ssdeep 23.8 ms. With
`--functions`, eous takes 103 ms.

## Limits

- If a file still has its list of imported functions, comparing that list works better than
  any fuzzy hash. eous is for files where that list is missing or useless: static builds,
  stripped binaries and malware.
- On Linux programs, eous scores below tlsh and below file size.
- eous has not been tested against obfuscated code.
- eous only reads native code. It refuses .NET bytecode (`managed`), packed files (`packed`),
  files that are not PE or ELF (`unsupported_format`), other processors (`unsupported_arch`)
  and files with no code (`no_code`). Of 2,250 MalwareBazaar samples it refused 577, mostly
  .NET and packed files.
- eous spots packed files by how random their code looks. A packer that avoids that gets
  through, and eous then hashes the packer instead of the program.
- eous cannot match malware samples that share no code, even when they carry the same family
  name. One MOTIF family, IcedID, has 135 samples whose code barely overlaps.
- `functions` finds a function when something calls it directly or when it is an entry
  point. It misses a function reached only through a pointer.
- Digests only compare within one target: pe32, pe64, elf32 or elf64.

## Digest format

```
EO1:pe32:7160:0b3513e7...
 |   |    |    the sketch, 128 hex characters
 |   |    how many distinct instruction sequences were found
 |   target: pe32, pe64, elf32 or elf64
 format version
```

## Licence

MIT.
