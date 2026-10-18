# eous

[![ci](https://github.com/jiacwng/eous/actions/workflows/ci.yml/badge.svg)](https://github.com/jiacwng/eous/actions/workflows/ci.yml)

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

Python 3.12 or later. LIEF parses PE and ELF, iced-x86 disassembles in a native Rust module,
numpy does the scoring arithmetic.

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
similarity:  95.8% +/- 1.4
containment: rg-14.0.0.exe in rg-14.0.1.exe   97.8%
             rg-14.0.1.exe in rg-14.0.0.exe   97.9%
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

eous was tested on 31 open-source programs, 426 binaries: 246 PE and 180 ELF, against ssdeep,
tlsh, file size and import-based baselines. A pair is related when both binaries build from
the same program. The metrics are AUC, the area under the ROC curve, and P@1, precision at
rank one. File size alone reaches AUC 0.914, so every figure is reported beside it.

PE, 246 binaries:

| tool | AUC | P@1 |
|---|---|---|
| imports | 0.946 | 0.943 |
| **eous** | **0.947** | 0.927 |
| tlsh | 0.943 | 0.931 |
| size | 0.908 | 0.724 |
| imphash | 0.632 | 0.724 |
| ssdeep | 0.560 | 0.313 |

ELF, 180 binaries:

| tool | AUC | P@1 |
|---|---|---|
| telfhash | 0.942 | 0.797 |
| tlsh | 0.935 | 0.992 |
| size | 0.917 | 0.828 |
| imports | 0.913 | 0.992 |
| **eous** | 0.897 | 0.922 |
| ssdeep | 0.503 | 0.141 |

On ELF, telfhash reads 96% of the binaries and imports 71%, the rest being statically
linked. P@1 is measured on the 128-file set all backends cover.

The case eous is built for is cross-compiler similarity, one source built by a different
compiler or against another C library. On the 31 such PE pairs eous reaches AUC 0.976,
against imports 0.863, size 0.852 and tlsh 0.848.

## Limits

- eous reads native code, so it refuses anything it cannot disassemble. On 2250 malware
  samples from MalwareBazaar it produced 1673 digests and refused 577: 296 as .NET bytecode
  and 279 as packed. A pipeline using eous alone needs a second tool for those two cases.
- If eous accepted packed files, the packer would leave only its unpacking stub as readable
  code, so unrelated programs packed the same way would share one digest.
- ELF is the weaker target. eous reaches AUC 0.897 against telfhash 0.942, and on distant
  versions 0.597 against telfhash 0.923.
- Go binaries carry the Go runtime, so two unrelated Go programs reach a median similarity
  of 35%, measured on 10 programs. On Go, tlsh separates programs better: AUC 0.998 against
  0.978 for eous.
- Tested on 31 open-source programs. A few constants were tuned on a separate dataset so the
  thresholds do not fit the test set.

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
