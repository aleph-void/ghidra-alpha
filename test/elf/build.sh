#!/usr/bin/env bash
# Reassemble the relocation test object (needs binutils configured --target=alpha-linux-gnu).
#   test/elf/build.sh <bindir>
set -euo pipefail
cd "$(dirname "$0")"
"$1/alpha-linux-gnu-as" -o relocs.o relocs.s
