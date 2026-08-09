# eous

eous is a fuzzy hashing tool for executables. It is an alternative to ssdeep and tlsh. You run it against a
PE or ELF binary on x86 or x86-64, and it produces a 512-bit hash of the program's code.

eous works on instruction mnemonics. It disassembles every executable section and maps each
mnemonic to one of 84 instruction categories, so for example `add`, `adc` and `xadd` map to
one category. It forms the 6-grams (shingles) of the category sequence, stopping each at a
control-flow instruction, then reduces the n-gram set to a 512-bit MinHash sketch.
Recompilation moves bytes and rewrites addresses. The mnemonic sequence survives both, so
two builds of one source still produce similar digests.

```
$ eous hash rg-14.0.0.exe
EO1:pe32:40045:780e1dde12b1bc2283e0bb3e4f33fb2cfe5e4a69e95ef4ef03a523b3ee...
```

## Install

```
pip install eous
```

Python 3.11 or later. LIEF parses PE and ELF, iced-x86 disassembles, numpy is used for MinHash and arithmetic.

## Usage

**Hash** a file, or a directory walked recursively:

```
$ eous hash samples/
samples/rg-12.1.0.exe  EO1:pe32:33280:c80f19ef1e7bbb6d26d3fa0e9efcff44be8a4a5e95de759...
samples/rg-12.1.1.exe  EO1:pe32:32625:d80fdbdf787bbead02e3fabedfbc6f4416c64a5ad5de75d...
```

**Compare** two inputs, each a file or a digest. Containment runs both ways and is
withheld beyond a 4x size difference:

```
$ eous compare rg-14.0.0.exe rg-14.0.1.exe
similarity:  95.8% +/- 1.4 (94.4% to 97.3%)
containment: rg-14.0.0.exe in rg-14.0.1.exe   97.8% +/- 1
             rg-14.0.1.exe in rg-14.0.0.exe   97.9% +/- 1
```

**Match** one input against a collection, best first:

```
$ eous hash samples/ > known.txt
$ eous match suspect.exe known.txt --min 80
```

**Cross** scores every pair in a collection, for triage with no query file:

```
$ eous cross known.txt --min 40
```

`--json` on any command. `--top N` and `--min PERCENT` bound the output of `match`; `--min`
bounds `cross`.

## Supported

| | |
|---|---|
| Architectures | x86, x86-64 |
| Formats | PE, ELF |
| Targets | pe32, pe64, elf32, elf64 |

Two digests compare only when their target matches; `match` and `cross` skip mismatched
entries and report the count. eous reads native code, when it declines, it names the
reason: a .NET assembly holding only bytecode (`managed`), a file whose code
sections are packed (`packed`), a container that is neither PE nor ELF
(`unsupported_format`), an architecture it does not support (`unsupported_arch`), a file with
no executable section (`no_code`).


## Results

eous was tested on 26 open-source programs, 599 binaries: 274 PE and 325 ELF, against ssdeep, tlsh, only imports and size as a baseline. A pair is related when both
binaries build from the same program.
The metrics are: **AUC**, the area under the ROC curve. **P@1**, precision at rank one. **MRR**, mean reciprocal rank.
**Recall at 1% FPR**, The false positive rate is the share of unrelated pairs a threshold
wrongly accepts. **Cross-compiler P@1**, which restricts P@1 to one source version built by another compiler, or
against another C library, on a subset of 37 PE pairs and 74 ELF pairs.

PE, 19,788 pairs:

| tool | AUC | P@1 | MRR | recall at 1% FPR | cross-compiler P@1 |
|---|---|---|---|---|---|
| imports | 0.965 | 1.000 | 1.000 | 0.650 | 0.770 |
| **eous** | 0.949 | 0.982 | 0.988 | 0.347 | **0.973** |
| tlsh | 0.940 | 0.964 | 0.975 | 0.429 | 0.689 |
| size | 0.894 | 0.803 | 0.862 | 0.209 | 0.676 |
| imphash | 0.621 | 0.686 | 0.689 | 0.243 | 0.514 |
| ssdeep | 0.512 | 0.193 | 0.200 | 0.024 | 0.270 |

ELF, 35,364 pairs:

| tool | AUC | P@1 | MRR | recall at 1% FPR | cross-compiler P@1 |
|---|---|---|---|---|---|
| tlsh | 0.972 | 0.994 | 0.995 | 0.717 | 0.892 |
| **eous** | 0.956 | 0.975 | 0.986 | 0.626 | **0.980** |
| size | 0.952 | 0.843 | 0.892 | 0.390 | 0.527 |
| ssdeep | 0.519 | 0.172 | 0.178 | 0.037 | 0.162 |

imports and telfhash read 139 and 218 of the 325 ELF binaries, the rest being statically
linked, too few to rank on.

## Limits

- eous reads native code, so it refuses anything it cannot disassemble. On a feed of 200
  malware samples it produced 107 digests. It refused 65 as .NET and 28 as packed. A
  pipeline using eous alone therefore needs a second tool for those two cases.
- If eous were to accept packed files, packers would leave the unpacking stub as the only readable code, so unrelated programs packed the same way share one digest.
- Tested on 26 open-source programs only, the tuning of a few constants were made on another dataset to ensure portability.

## Output format

```
EO1:pe32:40045:780e1dde...
 |   |     |     the 512-bit sketch, 128 hex characters
 |   |     distinct 6-grams found
 |   architecture and format
 the tool's version
```

A digest always begins `EO1:`, so it is greppable in a log.

## Licence

MIT.
