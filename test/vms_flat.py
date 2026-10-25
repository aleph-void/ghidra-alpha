#!/usr/bin/env python3
"""Flatten an OpenVMS Alpha image for a raw import: lay its loaded sections (from objdump -h)
out at their virtual addresses, and list procedure entry points.

  vms_flat.py <image.exe> <objdump-h.txt> <out.bin>
prints "base <hex>", "code code=<start>-<end> ..." (the code sections) and "entries <hex> <hex> ..." (every 8-byte-aligned quadword in a data
section that points into a code section: procedure descriptors and linkage pairs hold the
entry addresses of the procedures they describe)."""
import re
import struct
import sys

img = open(sys.argv[1], "rb").read()
secs = []
lines = open(sys.argv[2]).read().splitlines()
for i, l in enumerate(lines):
    m = re.match(r"\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", l)
    if m and i + 1 < len(lines) and "ALLOC" in lines[i + 1]:
        name, size, vma, off = m.group(1), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
        if vma == 0 or vma >= 0x7f000000:          # shareable images, stack
            continue
        secs.append((name, vma, size, off, "CONTENTS" in lines[i + 1], "CODE" in lines[i + 1]))
base = min(s[1] for s in secs) & ~0xffff
end = max(s[1] + s[2] for s in secs)
flat = bytearray(end - base)
for name, vma, size, off, contents, code in secs:
    if contents:
        flat[vma - base:vma - base + size] = img[off:off + size]
open(sys.argv[3], "wb").write(flat)
code = [(v, v + s) for _, v, s, _, _, c in secs if c]
entries = set()
for name, vma, size, off, contents, c in secs:
    if not contents or c:
        continue
    for i in range(0, size - 7, 8):
        q = struct.unpack_from("<Q", flat, vma - base + i)[0]
        if q % 4 == 0 and any(a <= q < b for a, b in code):
            entries.add(q)
print(f"base {base:x}")
print("code " + " ".join(f"code=0x{a:x}-0x{b - 1:x}" for a, b in code))
print("entries " + " ".join(f"{e:x}" for e in sorted(entries)))
