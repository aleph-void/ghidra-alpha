#!/usr/bin/env python3
"""Relocation-handler check for relocatable objects. Ghidra imported <object.o> and applied its
relocations (memory dump from DumpMem.java, block list from RealCheck.java's summary); GNU ld
linked the same object with its sections at Ghidra's addresses (<linked.elf>). Bytes are
compared with ld's output (except .eh_frame, which ld edits; its SREL32 fields are checked as
S + A - P), except at gp-relative relocation sites: Ghidra's gp and GOT (an
artificial %got block) differ from ld's (ld puts gp 0x8000 into its own .got, which at Ghidra's
addresses leaves .sdata out of 16-bit range), so those sites are checked against the relocation
formulas with the symbol addresses Ghidra assigned: GPDISP must compute gp, LITERAL must load a
GOT entry holding S, GPREL16/GPRELHIGH+GPRELLOW/GPREL32 must give S + A.

  reloc_check.py <object.o> <ghidra.sum> <ghidra.mem> <linked.elf>
"""
import re
import sys
from collections import Counter

import struct


class Elf:
    """minimal ELF64 little-endian reader: sections, symbols, RELA entries"""

    def __init__(self, path):
        d = self.d = open(path, "rb").read()
        shoff, = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
        self.sh = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize)
            self.sh.append(dict(name=name, type=typ, flags=flags, addr=addr, off=off, size=size,
                                link=link, info=info, entsize=entsize))
        stro = self.sh[shstrndx]["off"]
        for h in self.sh:
            h["name"] = self.cstr(stro, h["name"])

    def cstr(self, base, off):
        e = self.d.index(b"\0", base + off)
        return self.d[base + off:e].decode()

    def data(self, h):
        return self.d[h["off"]:h["off"] + h["size"]]

    def symbols(self, h):
        stro = self.sh[h["link"]]["off"]
        out = []
        for i in range(h["size"] // 24):
            name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.d, h["off"] + 24 * i)
            out.append(dict(name=self.cstr(stro, name), shndx=shndx, value=value, other=other))
        return out

    def relas(self, h):
        for i in range(h["size"] // 24):
            off, info, add = struct.unpack_from("<QQq", self.d, h["off"] + 24 * i)
            yield off, info & 0xffffffff, info >> 32, add

obj, gsum, gmem, lelf = sys.argv[1:5]

blocks = {}
ext = {}
for line in open(gsum):
    if line.startswith("external symbols:"):
        for b in line.split()[2:]:
            n, a = b.rsplit("@", 1)
            ext[n] = int(a, 16)
    if line.startswith("blocks:"):
        for b in line.split()[1:]:
            n, a = b.rsplit("@", 1)
            blocks[n] = int(a, 16)
G = {}
for line in open(gmem):
    a, b = line.split()
    G[int(a, 16)] = int(b, 16)
# Ghidra's gp: 0x8000 past the lowest of its %got block and the small-data sections
gp_g = min([blocks[n] for n in ("%got", ".sdata", ".sbss", ".lit4", ".lit8", ".lita") if n in blocks]) + 0x8000

L = {}
lf = Elf(lelf)
for sec in lf.sh:
    if sec["flags"] & 2 and sec["type"] != 8:          # SHF_ALLOC, not SHT_NOBITS
        for i, x in enumerate(lf.data(sec)):
            L[sec["addr"] + i] = x

def rd(m, a, n):
    return int.from_bytes(bytes(m[a + i] for i in range(n)), "little")

def s16(v):
    return v - 0x10000 if v & 0x8000 else v

def disp(m, a):
    return s16(rd(m, a, 4) & 0xffff)

of = Elf(obj)
syms = of.symbols(next(h for h in of.sh if h["type"] == 2))
sites = []                 # (type, P, symbol key, addend, S)
for sec in of.sh:
    if sec["type"] != 4:                                  # SHT_RELA
        continue
    target = of.sh[sec["info"]]["name"]
    if target not in blocks:
        continue
    for off, t, si, add in of.relas(sec):
        sym = syms[si]
        sname = sym["name"] or of.sh[sym["shndx"]]["name"]
        if sym["shndx"] == 0:
            S = ext.get(sym["name"])
        elif sym["shndx"] < 0xff00:
            S = blocks.get(of.sh[sym["shndx"]]["name"], 0) + sym["value"]
        else:
            S = sym["value"]
        sites.append((t, blocks[target] + off, (sname, add), add, S))

GPREL = {3: "GPREL32", 4: "LITERAL", 6: "GPDISP", 17: "GPRELHIGH", 18: "GPRELLOW", 19: "GPREL16"}
skip = set()
ok, bad = Counter(), Counter()
msgs = []
def check(name, cond, what):
    (ok if cond else bad)[name] += 1
    if not cond and len(msgs) < 20:
        msgs.append(f"  {name}: {what}")

high = {}
for t, P, key, add, S in sites:
    if t not in GPREL:
        continue
    name = GPREL[t]
    skip.update(range(P, P + 4))
    if t == 6:                                   # ldah at P, lda at P + addend
        skip.update(range(P + add, P + add + 4))
        g = P + (disp(G, P) << 16) + disp(G, P + add)
        check(name, g == gp_g, f"{P:x}: computes gp {g:x}, expect {gp_g:x}")
    elif t == 4:
        v = rd(G, gp_g + disp(G, P), 8)
        check(name, v == S + add, f"{P:x}: GOT entry holds {v:x}, expect {S + add:x}")
    elif t == 19:
        check(name, gp_g + disp(G, P) == S + add, f"{P:x}: gives {gp_g + disp(G, P):x}, expect {S + add:x}")
    elif t == 3:
        v = rd(G, P, 4)
        v = v - (1 << 32) if v >> 31 else v
        check(name, gp_g + v == S + add, f"{P:x}: gives {gp_g + v:x}, expect {S + add:x}")
    elif t == 17:
        high.setdefault(key, []).append(P)
# ld edits .eh_frame (it drops FDE padding), so its bytes are not compared; its SREL32 fields
# are checked against S + A - P instead
eh = blocks.get(".eh_frame")
for t, P, key, add, S in sites:
    if t == 10 and eh is not None and P >= eh:
        v = rd(G, P, 4)
        check("SREL32", v == (S + add - P) & 0xffffffff, f"{P:x}: {v:x}, expect {(S + add - P) & 0xffffffff:x}")
if eh is not None:
    end = min([a for a in blocks.values() if a > eh] + [1 << 64])
    skip.update(a for a in G if eh <= a < end)
for t, P, key, add, S in sites:
    if t == 18:
        for H in high.get(key, []):
            e = gp_g + (disp(G, H) << 16) + disp(G, P)
            check("GPRELHIGH/LOW", e == S + add, f"{H:x}/{P:x}: gives {e:x}, expect {S + add:x}")

n = nb = 0
for a, v in G.items():
    if a in skip or a not in L:
        continue
    n += 1
    if L[a] != v:
        nb += 1
        if len(msgs) < 20:
            msgs.append(f"  byte {a:x}: ghidra {v:02x} ld {L[a]:02x}")
print("\n".join(msgs))
print(f"gp-relative sites: {dict(ok)} agree, {dict(bad)} differ; other bytes: {n} compared, {nb} differ")
sys.exit(1 if bad or nb else 0)
