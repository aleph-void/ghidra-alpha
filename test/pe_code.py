#!/usr/bin/env python3
"""Extract the code sections of a PE image for objdump -b binary.

  pe_code.py <image.exe> <outprefix>
writes <outprefix>.<n>.bin for each executable section and prints "<file> <virtual address>"
lines (absolute addresses: image base + RVA)."""
import struct
import sys

d = open(sys.argv[1], "rb").read()
pe = struct.unpack_from("<I", d, 0x3c)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
opt = pe + 24
magic = struct.unpack_from("<H", d, opt)[0]
base = struct.unpack_from("<I", d, opt + 28)[0] if magic == 0x10b else struct.unpack_from("<Q", d, opt + 24)[0]
sec = opt + optsz
for i in range(nsec):
    name, vsize, rva, rawsz, rawoff = struct.unpack_from("<8sIIII", d, sec + 40 * i)
    chars = struct.unpack_from("<I", d, sec + 40 * i + 36)[0]
    if chars & 0x20000020:          # IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE
        out = f"{sys.argv[2]}.{i}.bin"
        open(out, "wb").write(d[rawoff:rawoff + min(vsize, rawsz)])
        print(out, hex(base + rva))
