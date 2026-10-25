#!/usr/bin/env bash
# ELF relocation handler check: import each relocatable object (Ghidra applies its relocations
# at addresses it chooses), link the same object with GNU ld (alpha-linux-gnu) at those
# addresses and compare (reloc_check.py: bytes with ld, gp-relative sites with their formulas).
#   test/reloc-check.sh <ld> <workdir> <object.o>...
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LD=$1 W=$(readlink -m "$2")
shift 2
mkdir -p "$W"
for o in "$@"; do
	n=$(basename "$o")
	p=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/alpha-rel.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$(readlink -f "$o")" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" 0 \
		-postScript DumpMem.java "$W/$n.mem" -deleteProject >"$W/$n.log" 2>&1 || tail -20 "$W/$n.log"
	rm -rf "$p"
	args=()
	for b in $(sed -n 's/^blocks: //p' "$W/$n.sum"); do
		case ${b%@*} in
		EXTERNAL|.comment|.note*) ;;
		%got) ;;
		*) args+=("--section-start=${b%@*}=0x${b#*@}") ;;
		esac
	done
	for s in $(sed -n 's/^external symbols: //p' "$W/$n.sum"); do
		args+=("--defsym=${s%@*}=0x${s#*@}")
	done
	# gp-relative sites may overflow in ld's layout (see reloc_check.py); they are not compared
	"$LD" -e _start -static --no-relax --no-warn-rwx-segments --noinhibit-exec "${args[@]}" "$o" \
		-o "$W/$n.ld.elf" >"$W/$n.ld.log" 2>&1 || true
	echo "-- $n: $(grep '^relocations' "$W/$n.sum"); $(python3 "$HERE/reloc_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" | tail -1)"
	python3 "$HERE/reloc_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" >/dev/null || python3 "$HERE/reloc_check.py" "$o" "$W/$n.sum" "$W/$n.mem" "$W/$n.ld.elf" | head -20
done
