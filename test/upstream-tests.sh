#!/usr/bin/env bash
# Upstream's decode tests (tests/*.hex with the expected disassembly in tests/*.asm*), run with
# Ghidra instead of the sleigh-lift tool tests/runtest needs. Same CPU/OS combinations as
# tests/Makefile; the expected file is <name>.asm<OS><CPU>, else <name>.asm<OS>, else <name>.asm.
# "BAD" in an expected file marks a word that must not decode.
#   test/upstream-tests.sh <workdir>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
T=$HERE/../tests
W=$(readlink -m "$1"); mkdir -p "$W"
pass=0 fail=0
for combo in "21064 VMS vms" "21164 UNIX unix" "21264 NT nt"; do
	set -- $combo
	cpu=$1 os=$2 lang=$1:LE:64:$3
	for h in "$T"/*.hex; do
		j=$(basename "$h" .hex)
		exp=$T/$j.asm$os$cpu
		[[ -f $exp ]] || exp=$T/$j.asm$os
		[[ -f $exp ]] || exp=$T/$j.asm
		grep -v '^#' "$h" | tr -d ' \n' | xxd -r -p >"$W/$j.bin"
		"$HERE/ghidra-dis.sh" "$lang" "$W/$j.bin" "$W/$j.$os$cpu.dis"
		# DumpDisasm "<offset> <bytes> <text>" -> runtest's "0x<offset>: <text>"
		n=$(grep -c . "$exp" || true)
		awk -v n="$n" 'NR <= n { o=$1; $1=""; $2=""; sub(/^  /, ""); printf "0x%s: %s\n", o, $0 }' \
			"$W/$j.$os$cpu.dis" >"$W/$j.$os$cpu.out"
		# compare ignoring spacing, case and number spelling (0x40 = 0x00000040; branch targets
		# below address 0 wrap to 64 bits)
		if python3 -I - "$exp" "$W/$j.$os$cpu.out" >"$W/$j.$os$cpu.diff" <<'PY'
import re, sys
def norm(l):
    l = l.strip().lower().replace(" ", "")
    if ":bad" in l:              # undecodable word: Ghidra appends the reason
        return l.split(":bad")[0] + ":bad"
    return re.sub(r"-?0x[0-9a-f]+", lambda m: str(int(m.group(0), 16) & (2**64 - 1)), l)
a = [l for l in open(sys.argv[1]) if l.strip()]
b = [l for l in open(sys.argv[2]) if l.strip()]
bad = [(x.rstrip(), y.rstrip()) for x, y in zip(a, b) if norm(x) != norm(y)]
for x, y in bad:
    print(f"  expected {x}\n  got      {y}")
sys.exit(1 if bad or len(a) != len(b) else 0)
PY
		then
			pass=$((pass + 1))
		else
			fail=$((fail + 1))
			echo "FAIL $j ($cpu $os):"; cat "$W/$j.$os$cpu.diff"
		fi
	done
done
echo "upstream tests: $pass passed, $fail failed"
