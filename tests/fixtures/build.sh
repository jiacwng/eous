#!/bin/sh
set -eu
cd "$(dirname "$0")"

ZIG="${ZIG:-zig}"
mkdir -p bin

"$ZIG" cc -target x86_64-windows-gnu -O1 -s -o bin/fixture-pe-x64.exe src/fixture.c
"$ZIG" cc -target x86-windows-gnu   -O1 -s -o bin/fixture-pe-x86.exe src/fixture.c
"$ZIG" cc -target x86_64-linux-gnu  -O1 -s -o bin/fixture-elf-x64 src/fixture.c
"$ZIG" cc -target x86-linux-gnu     -O1 -s -o bin/fixture-elf-x86 src/fixture.c

sha256sum bin/fixture-pe-x64.exe bin/fixture-pe-x86.exe bin/fixture-elf-x64 bin/fixture-elf-x86
