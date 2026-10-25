#!/usr/bin/env bash
# Real-world binary check: import each sample headless with NO -processor flag (the ELF opinion
# must pick the language), auto-analyze, decompile every function (RealCheck.java), and diff
# Ghidra's disassembly of every instruction it found against GNU objdump at the same addresses.
#
#   test/fetch-real-samples.sh <samples>     # download the pinned Debian alpha samples once
#   test/real-binaries.sh <samples> <workdir>
#
# GHIDRA_INSTALL_DIR: Ghidra with this module under Ghidra/Processors/Alpha and lib/Alpha.jar
# built (test/build-jar.sh). OBJDUMP: binutils with the alpha target. DECOMP_TIMEOUT: seconds
# per function (default 60; 0 skips decompiling). PROJ_DIR: where the throw-away Ghidra projects go.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
: "${OBJDUMP:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump}"
TMO=${DECOMP_TIMEOUT:-60}
SAMPLES=$(readlink -f "$1")
W=$(readlink -m "$2")
mkdir -p "$W"
files=(libz.so.1.3.2 ls sort libc.so.6.1 busybox palcode-clipper
	miktex.dll dvips.exe bibtex.exe makeindex.exe unzip.exe unz512x-axp.exe)

run_one() { # file
	local f=$1 n p
	n=$(basename "$f")
	# Ghidra rejects project paths with a dot-directory (e.g. ~/.cache); PROJ_DIR may point at
	# a symlink to disk instead (default: $TMPDIR).
	p=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/alpha-real.XXXXXX")
	local imp=()
	if [[ $n == *-axp.exe ]]; then
		# OpenVMS image: Ghidra has no loader for it; lay its sections out flat and seed the
		# procedure entries (vms_flat.py), then import raw as 21264 (VMS)
		"$OBJDUMP" -h "$f" >"$W/$n.h"
		python3 -I "$HERE/vms_flat.py" "$f" "$W/$n.h" "$W/$n.flat" >"$W/$n.flatinfo"
		local base seeds
		base=0x$(sed -n 's/^base //p' "$W/$n.flatinfo")
		seeds="$(sed -n 's/^code //p' "$W/$n.flatinfo") $(sed -n 's/^entries //p' "$W/$n.flatinfo" | sed 's/[0-9a-f]\+/0x&/g')"
		imp=(-loader BinaryLoader -loader-baseAddr "$base" -processor 21264:LE:64:vms
			-preScript SeedEntries.java $seeds)
		f=$W/$n.flat
	fi
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$f" "${imp[@]}" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "$TMO" \
		-deleteProject >"$W/$n.log" 2>&1 || { tail -20 "$W/$n.log" >&2; }
	rm -rf "$p"
	rm -f "$W/$n.flat"
}
echo "== headless import + analysis + decompile (${#files[@]} files)"
for f in "${files[@]}"; do run_one "$SAMPLES/$f" & done
wait
echo "== results"
for n in "${files[@]}"; do
	f=$SAMPLES/$n
	if [[ $n == *.exe || $n == *.dll ]]; then
		if [[ $n == *-axp.exe ]]; then
			"$OBJDUMP" -d "$f" >"$W/$n.od"
		else      # Windows NT PE: binutils has no Alpha PE support; disassemble the code sections
			: >"$W/$n.od"
			python3 -I "$HERE/pe_code.py" "$f" "$W/$n.code" | while read -r bin va; do
				"$OBJDUMP" -D -b binary -m alpha --adjust-vma="$va" "$bin" >>"$W/$n.od"
				rm -f "$bin"
			done
		fi
		echo "-- $n"
		grep -E "^(language|functions|instructions|fallthrough|bad-instruction|error bookmarks|relocations|decompile|functions whose)" "$W/$n.sum" | sed 's/^/   /'
		os=nt; [[ $n == *-axp.exe ]] && os=vms
		echo "   vs objdump: $(python3 "$HERE/real_compare.py" "$W/$n.lst" "$W/$n.od" 10 0 $os | tee "$W/$n.cmp" | head -1)"
		continue
	fi
	etype=$(python3 -I -c 'import sys; print(int.from_bytes(open(sys.argv[1],"rb").read(18)[16:18],"little"))' "$f")
	delta=0
	[[ $etype == 3 ]] && delta=$(sed -n 's/^image base: //p' "$W/$n.sum")
	# the ELF header does not name the CPU: PALcode needs objdump's EV6 opcode table
	m=(); [[ $n == palcode-clipper ]] && m=(-m alpha:ev6)
	"$OBJDUMP" -d "${m[@]}" "$f" >"$W/$n.od"
	echo "-- $n (e_type $etype)"
	grep -E "^(language|functions|instructions|fallthrough|bad-instruction|error bookmarks|relocations|decompile|functions whose)" "$W/$n.sum" | sed 's/^/   /'
	echo "   vs objdump: $(python3 "$HERE/real_compare.py" "$W/$n.lst" "$W/$n.od" 10 "$delta" | tee "$W/$n.cmp" | head -1)"
done
echo "(full outputs: $W/<file>.{sum,lst,c,cmp,log})"
