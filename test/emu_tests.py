#!/usr/bin/env python3
"""Alpha p-code emulator tests: hand-assembled sequences with hand-computed results.

  emu_tests.py <outdir>     writes emu.bin (raw little-endian image loaded at 0) and emu.txt

emu.txt lines (read by EmuCheck.java):
  <name> <start-hex> <stop-hex> <init|-> <expect>
init/expect are comma-separated "reg=hex" or "m<size>:<addr-hex>=hex" items. Register names are
the UNIX variant's (v0, t0.., a0.., ra, pv, at, GP, SP, f0..).
Every expected value below was worked out by hand from the Alpha Architecture Handbook
(EC-QD2KC-TE) instruction descriptions, not by running the module.
"""
import struct, sys

R = {n: i for i, n in enumerate("v0 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 fp a0 a1 a2 a3 a4 a5 t8 t9 t10 t11 ra pv at gp sp zero".split())}

def reg(x):
    return x if isinstance(x, int) else R[x]

def opr(op, fn, ra, rb, rc):          # register operate format
    return op << 26 | reg(ra) << 21 | reg(rb) << 16 | fn << 5 | reg(rc)

def opl(op, fn, ra, lit, rc):         # literal operate format
    return op << 26 | reg(ra) << 21 | (lit & 0xff) << 13 | 1 << 12 | fn << 5 | reg(rc)

def mem(op, ra, disp, rb):
    return op << 26 | reg(ra) << 21 | reg(rb) << 16 | (disp & 0xffff)

def bra(op, ra, words):               # displacement in instructions from the next one
    return op << 26 | reg(ra) << 21 | (words & 0x1fffff)

def jmp(kind, ra, rb, hint=0):
    return 0x1a << 26 | reg(ra) << 21 | reg(rb) << 16 | kind << 14 | (hint & 0x3fff)

def fp(op, fn, fa, fb, fc):
    return op << 26 | fa << 21 | fb << 16 | fn << 5 | fc

def misc(fn, ra=31, rb=31):
    return 0x18 << 26 | reg(ra) << 21 | reg(rb) << 16 | fn

NOP = opr(0x11, 0x20, 31, 31, 31)
ADDQ = lambda a, b, c: opr(0x10, 0x20, a, b, c)
ADDQi = lambda a, l, c: opl(0x10, 0x20, a, l, c)
RET = jmp(2, 31, "ra", 1)

DATA = 0x8000      # data area inside the image
SP = 0xf000

tests = []         # (name, [words], init, expect)
def T(name, words, init, expect):
    tests.append((name, words, init, expect))

# ---- integer arithmetic ----
T("addq", [ADDQ("t0", "t1", "t2")], "t0=5,t1=7", "t2=c")
T("addl_sext", [opr(0x10, 0x00, "t0", "t1", "t2")], "t0=7fffffff,t1=1", "t2=ffffffff80000000")
T("subq_lit", [opl(0x10, 0x29, "t0", 3, "t2")], "t0=a", "t2=7")
T("s4addq_s8subl", [opr(0x10, 0x22, "t0", "t1", "t2"), opr(0x10, 0x1b, "t0", "t1", "t3")],
  "t0=3,t1=5", "t2=11,t3=13")        # 3*4+5 = 17; 3*8-5 = 19
T("negq_pseudo", [opr(0x10, 0x29, "zero", "t0", "t1")], "t0=5", "t1=fffffffffffffffb")
T("cmp", [opr(0x10, 0x1d, "t0", "t1", "t2"), opr(0x10, 0x4d, "t0", "t1", "t3"),
          opr(0x10, 0x2d, "t0", "t0", "t4"), opr(0x10, 0x6d, "t1", "t0", "t5")],
  "t0=1,t1=ffffffffffffffff", "t2=1,t3=0,t4=1,t5=1")   # 1 <u -1; 1 <s -1 false; -1 <=s 1
T("cmpbge", [opr(0x10, 0x0f, "t0", "t1", "t2")], "t0=0102030405060708,t1=0808080808080808", "t2=1")
T("mul", [opr(0x13, 0x20, "t0", "t1", "t2"), opr(0x13, 0x30, "t3", "t1", "t4"),
          opr(0x13, 0x00, "t5", "t5", "t6")],
  "t0=6,t1=2,t3=ffffffffffffffff,t5=10000", "t2=c,t4=1,t6=0")   # umulh(2^64-1, 2) = 1; mull 2^16*2^16 -> 0
T("logic", [opr(0x11, 0x00, "t0", "t1", "t2"), opr(0x11, 0x08, "t0", "t1", "t3"),
            opr(0x11, 0x40, "t0", "t1", "t4"), opr(0x11, 0x28, "zero", "t0", "t5"),
            opr(0x11, 0x48, "t0", "t1", "t6")],
  "t0=ff00,t1=0ff0", "t2=f00,t3=f000,t4=f0f0,t5=ffffffffffff00ff,t6=ffffffffffff0f0f")
T("bis_lit_same_reg", [opl(0x11, 0x20, "t0", 8, "t0")], "t0=10", "t0=18")   # literal bits 20:16 = Ra: was decoded as MOV 8,t0
T("cmov", [opr(0x11, 0x24, "t0", "t1", "t2"), opr(0x11, 0x26, "t0", "t1", "t3"),
           opr(0x11, 0x16, "t4", "t1", "t5")],
  "t0=0,t1=2a,t2=1,t3=1,t4=6,t5=1", "t2=2a,t3=1,t5=2a")      # cmoveq taken, cmovne not, cmovlbc taken
T("shift", [opl(0x12, 0x39, "t0", 4, "t1"), opl(0x12, 0x34, "t2", 4, "t3"),
            opl(0x12, 0x3c, "t2", 4, "t4"), opr(0x12, 0x39, "t0", "t5", "t6")],
  "t0=1,t2=8000000000000000,t5=41", "t1=10,t3=800000000000000,t4=f800000000000000,t6=2")  # shift count mod 64
# ---- byte manipulation ----
T("zap_zapnot", [opl(0x12, 0x30, "t0", 0xf0, "t1"), opl(0x12, 0x31, "t0", 0x81, "t2")],
  "t0=1122334455667788", "t1=55667788,t2=1100000000000088")
T("ext", [opl(0x12, 0x06, "t0", 3, "t1"), opl(0x12, 0x16, "t0", 6, "t2"), opl(0x12, 0x5a, "t0", 7, "t3"),
          opl(0x12, 0x36, "t0", 4, "t4"), opl(0x12, 0x7a, "t0", 4, "t5")],
  "t0=1122334455667788",
  "t1=55,t2=1122,t3=8800,t4=11223344,t5=5566778800000000")
T("extqh_pos0", [opl(0x12, 0x7a, "t0", 8, "t1"), opl(0x12, 0x5a, "t0", 0, "t2")],
  "t0=1122334455667788", "t1=1122334455667788,t2=7788")   # byte position 0: shift (64-0) mod 64 = 0
T("ins_msk", [opl(0x12, 0x0b, "t0", 2, "t1"), opl(0x12, 0x57, "t0", 7, "t2"), opl(0x12, 0x02, "t3", 1, "t4"),
              opl(0x12, 0x52, "t3", 7, "t5")],
  "t0=abcd,t3=ffffffffffffffff", "t1=cd0000,t2=ab,t4=ffffffffffff00ff,t5=ffffffffffffff00")
T("sext_count", [opr(0x1c, 0x00, "zero", "t0", "t1"), opr(0x1c, 0x01, "zero", "t0", "t2"),
                 opr(0x1c, 0x30, "zero", "t0", "t3"), opr(0x1c, 0x32, "zero", "t0", "t4"),
                 opr(0x1c, 0x33, "zero", "t0", "t5"), opr(0x1c, 0x33, "zero", "zero", "t6")],
  "t0=8080", "t1=ffffffffffffff80,t2=ffffffffffff8080,t3=2,t4=30,t5=7,t6=40")
# ---- address arithmetic, loads and stores ----
T("lda_ldah", [mem(0x09, "t0", 1, "zero"), mem(0x08, "t0", -1, "t0"), mem(0x09, "t1", -1, "t0")],
  "-", "t0=ffff,t1=ffffffffffffffff")       # 0x10000-1 ; 0xffff - 0x10000
T("stq_ldq", [mem(0x2d, "t1", 8, "sp"), mem(0x29, "t2", 8, "sp")],
  f"sp={SP:x},t1=123456789abcdef0", f"t2=123456789abcdef0,m8:{SP + 8:x}=123456789abcdef0")
T("ldl_sext_ldbu_ldwu", [mem(0x28, "t1", 0, "t0"), mem(0x0a, "t2", 3, "t0"), mem(0x0c, "t3", 2, "t0")],
  f"t0={DATA:x},m4:{DATA:x}=80000001", "t1=ffffffff80000001,t2=80,t3=8000")
T("stb_stw_stl", [mem(0x0e, "t1", 0, "t0"), mem(0x0d, "t1", 2, "t0"), mem(0x2c, "t1", 4, "t0")],
  f"t0={DATA + 0x10:x},t1=1122334455667788,m8:{DATA + 0x10:x}=0", f"m8:{DATA + 0x10:x}=5566778877880088")
T("ldq_u_stq_u", [mem(0x0b, "t1", 3, "t0"), mem(0x0f, "t2", 0xf, "t0")],
  f"t0={DATA + 0x20:x},t2=99,m8:{DATA + 0x20:x}=1111111111111111,m8:{DATA + 0x28:x}=0",
  f"t1=1111111111111111,m8:{DATA + 0x28:x}=99")
# ---- flow ----
T("beq_taken", [opr(0x11, 0x20, "zero", "zero", "t1"), bra(0x39, "t0", 1), ADDQi("t1", 1, "t1"), ADDQi("t1", 2, "t1")],
  "t0=0,t1=5", "t1=2")
T("bne_not_taken", [bra(0x3d, "t0", 1), ADDQi("t1", 1, "t1"), ADDQi("t1", 2, "t1")], "t0=0,t1=0", "t1=3")
T("blbs_bge_bgt", [bra(0x3c, "t0", 1), ADDQi("t1", 1, "t1"), bra(0x3e, "t2", 1), ADDQi("t1", 2, "t1"),
                   bra(0x3f, "zero", 1), ADDQi("t1", 4, "t1")],
  "t0=3,t1=0,t2=8000000000000000", "t1=6")   # blbs taken; bge(-) not; bgt 0 not
T("br_link", [bra(0x30, "t3", 1), NOP, NOP], "-", "t3=4")
T("bsr_ret", [bra(0x34, "ra", 2), ADDQi("t1", 1, "t1"), bra(0x30, "zero", 2), ADDQi("t1", 0x10, "t1"), RET],
  "t1=0", "t1=11,ra=4")   # call, add 0x10, return to 4, add 1, branch out
T("jsr_reg", [jmp(1, "ra", "pv"), ADDQi("t1", 1, "t1"), bra(0x30, "zero", 1), RET],
  "pv=c,t1=7", "t1=8,ra=4")
T("jmp_same_reg", [jmp(0, "t0", "t0"), NOP, NOP], "t0=8", "t0=4")   # target read before link write
# ---- floating point ----
T("itoft_addt_ftoit", [fp(0x14, 0x024, R["t0"], 31, 1), fp(0x16, 0x0a0, 1, 1, 2), opr(0x1c, 0x70, 2, 31, "t3")],
  "t0=3ff8000000000000", "t3=4008000000000000,f2=4008000000000000")   # 1.5 + 1.5 = 3.0
T("cvtqt_cvttq", [fp(0x14, 0x024, R["t0"], 31, 1), fp(0x16, 0x0be, 31, 1, 2), fp(0x16, 0x02f, 31, 2, 3)],
  "t0=7", "f2=401c000000000000,f3=7")
T("lds_sts", [mem(0x22, 1, 0, "t0"), opr(0x1c, 0x70, 1, 31, "t1"), mem(0x26, 1, 4, "t0")],
  f"t0={DATA + 0x30:x},m8:{DATA + 0x30:x}=3f800000",
  f"t1=3ff0000000000000,m8:{DATA + 0x30:x}=3f8000003f800000")   # 1.0f widened, stored back as 4 bytes
T("cmpteq_cmptlt", [fp(0x16, 0x0a5, 1, 2, 3), fp(0x16, 0x0a6, 2, 1, 4)],
  "f1=3ff0000000000000,f2=3ff0000000000000", "f3=4000000000000000,f4=0")
T("cpysn_cpyse", [fp(0x17, 0x021, 1, 1, 2), fp(0x17, 0x022, 3, 1, 4)],
  "f1=3ff0000000000000,f3=c010000000000000", "f2=bff0000000000000,f4=c010000000000000")
T("cvtql_cvtlq", [fp(0x17, 0x030, 31, 1, 2), fp(0x17, 0x010, 31, 2, 3)],
  "f1=00000000ffffff85", "f3=ffffffffffffff85")   # longword -123 through the FP register format
T("negt_zero", [fp(0x16, 0x0a1, 31, 1, 2), fp(0x16, 0x0a1, 31, 3, 4)],
  "f1=0,f3=3ff0000000000000", "f2=0,f4=bff0000000000000")   # SUBT F31,+0 = +0, not -0
T("fbeq_fcmov", [fp(0x17, 0x02a, 1, 2, 3), bra(0x31, 1, 1), ADDQi("t1", 1, "t1"), NOP],
  "f1=8000000000000000,f2=4000000000000000,f3=0,t1=0", "f3=4000000000000000,t1=0")   # -0.0 == 0
# ---- MVI (byte/word min/max, pixel error) ----
T("mvi_min_max", [opr(0x1c, 0x3a, "t0", "t1", "t2"), opr(0x1c, 0x3e, "t0", "t1", "t3"),
                  opr(0x1c, 0x39, "t0", "t1", "t4"), opr(0x1c, 0x3d, "t0", "t1", "t5")],
  "t0=01ff7f8000102030,t1=02fe807f00112f31",
  "t2=01fe7f7f00102030,t3=02ff7f7f00112f31,t4=01ff807f00102030,t5=02fe807f00112f31")
T("mvi_perr", [opr(0x1c, 0x31, "t0", "t1", "t2")], "t0=01ff7f8000102030,t1=02fe807f00112f31", "t2=15")
# ---- register formats: bit-exact S, F and G moves ----
# LDS maps S bits to the T layout (exponent 255 -> 2047, a denormal keeps exponent 0); STS maps back
T("lds_sts_bits", [mem(0x22, 1, 0, "t0"), mem(0x22, 2, 4, "t0"), mem(0x26, 1, 8, "t0"), mem(0x26, 2, 12, "t0")],
  f"t0={DATA + 0x40:x},m8:{DATA + 0x40:x}=000000017fc12345",
  f"f1=7ff82468a0000000,f2=20000000,m8:{DATA + 0x48:x}=000000017fc12345")
T("itofs_ftois_bits", [fp(0x14, 0x004, R["t0"], 31, 1), opr(0x1c, 0x78, 1, 31, "t1")],
  "t0=ffffffff80000001", "f1=8000000020000000,t1=ffffffff80000001")   # -denormal, sign-extended back
# VAX F 1.0 is 0x4080 in its first word; VAX G 1.0 is word 0x4010 first
T("ldf_stf_ldg_stg", [mem(0x20, 1, 0, "t0"), mem(0x21, 2, 8, "t0"), mem(0x24, 1, 16, "t0"), mem(0x25, 2, 24, "t0")],
  f"t0={DATA + 0x60:x},m4:{DATA + 0x60:x}=4080,m8:{DATA + 0x68:x}=4010",
  f"f1=4010000000000000,f2=4010000000000000,m4:{DATA + 0x70:x}=4080,m8:{DATA + 0x78:x}=4010")
# ---- VAX arithmetic (G-layout registers): 1.0 + 2.0, 1.5 * 2.0 (F), compares, conversions ----
T("vax_addg_mulf_cmpglt", [fp(0x15, 0x0a0, 1, 2, 3), fp(0x15, 0x082, 4, 2, 5), fp(0x15, 0x0a6, 1, 2, 6)],
  "f1=4010000000000000,f2=4020000000000000,f4=4018000000000000",
  "f3=4028000000000000,f5=4028000000000000,f6=4000000000000000")
T("vax_ties", [fp(0x15, 0x0a0, 1, 2, 3), fp(0x15, 0x020, 1, 2, 4), fp(0x15, 0x080, 1, 5, 6)],
  "f1=4010000000000000,f2=3cc0000000000000,f5=3e90000000000000",
  "f3=4010000000000001,f4=4010000000000000,f6=4010000020000000")
  # 1 + 2^-53 (G) and 1 + 2^-24 (F) are exact halfway cases: VAX rounds them away from zero; /C chops
T("vax_cvtgq_round", [fp(0x15, 0x0af, 31, 1, 2), fp(0x15, 0x02f, 31, 1, 3), fp(0x15, 0x0af, 31, 4, 5)],
  "f1=4024000000000000,f4=c024000000000000",
  "f2=3,f3=2,f5=fffffffffffffffd")       # 2.5 -> 3 (VAX rounds ties away), /C -> 2; -2.5 -> -3
T("vax_cvtdg_cvtgd", [fp(0x15, 0x09e, 31, 1, 2), fp(0x15, 0x0ad, 31, 2, 3)],
  "f1=4080000000000000", "f2=4010000000000000,f3=4080000000000000")   # D 1.0 <-> G 1.0
T("vax_negg_zero", [fp(0x15, 0x0a1, 31, 1, 2), fp(0x15, 0x0a1, 31, 3, 4)],
  "f1=0,f3=4010000000000000", "f2=0,f4=c010000000000000")   # -(0) stays a true zero
# ---- IEEE rounding modes ----
T("divt_rounding", [fp(0x16, 0x0a3, 1, 2, 3), fp(0x16, 0x023, 1, 2, 4), fp(0x16, 0x063, 1, 2, 5),
                    fp(0x17, 0x024, 6, 6, 6), fp(0x16, 0x0e3, 7, 2, 8)],
  "f1=bff0000000000000,f2=4008000000000000,f6=0c00000000000000,f7=3ff0000000000000",
  "f3=bfd5555555555555,f4=bfd5555555555555,f5=bfd5555555555556,f8=3fd5555555555556")
  # -1/3 normal and /C: ...555; /M: toward -inf ...556; 1/3 with FPCR DYN=+inf (/D): ...556
T("adds_rounding", [fp(0x16, 0x000, 1, 2, 3), fp(0x17, 0x024, 6, 6, 6), fp(0x16, 0x0c0, 1, 2, 4)],
  "f1=3ff0000000000000,f2=3e10000000000000,f6=0c00000000000000",
  "f3=3ff0000000000000,f4=3ff0000020000000")   # 1 + 2^-30 in single: /C -> 1.0, +inf -> 1 + 2^-23
T("cvttq_rounding", [fp(0x16, 0x0af, 31, 1, 2), fp(0x16, 0x0af, 31, 3, 4), fp(0x16, 0x06f, 31, 5, 6),
                     fp(0x16, 0x02f, 31, 5, 7)],
  "f1=4004000000000000,f3=400c000000000000,f5=c004000000000000",
  "f2=2,f4=4,f6=fffffffffffffffd,f7=fffffffffffffffe")   # 2.5 -> 2, 3.5 -> 4 (even); -2.5 /M -> -3, /C -> -2
T("cvtqt_rounding", [fp(0x16, 0x0be, 31, 1, 2), fp(0x17, 0x024, 6, 6, 6), fp(0x16, 0x0fe, 31, 1, 3)],
  "f1=20000000000001,f6=0c00000000000000",
  "f2=4340000000000000,f3=4340000000000001")   # 2^53 + 1: nearest even 2^53, +inf 2^53 + 2
T("mt_mf_fpcr", [fp(0x17, 0x024, 1, 1, 1), fp(0x17, 0x025, 2, 2, 2)],
  "f1=0800000000000000", "f2=0800000000000000,FPCR=0800000000000000")
# ---- floating branches test register bits ----
T("fblt_nan", [bra(0x32, 1, 1), ADDQi("t1", 1, "t1"), NOP], "f1=fff8000000000000,t1=0", "t1=0")   # sign set, not zero: taken

def main():
    out = sys.argv[1]
    image = bytearray(0x10000)
    pc = 0
    lines = []
    for name, words, init, expect in tests:
        start = pc
        for w in words:
            struct.pack_into("<I", image, pc, w & 0xffffffff)
            pc += 4
        stop = pc
        # relocate absolute code targets (jsr_reg/jmp_same_reg give offsets within the test)
        if name == "jsr_reg":
            init = init.replace("pv=c", f"pv={start + 0xc:x}")
            expect = expect.replace("ra=4", f"ra={start + 4:x}")
        if name == "jmp_same_reg":
            init = init.replace("t0=8", f"t0={start + 8:x}")
            expect = expect.replace("t0=4", f"t0={start + 4:x}")
            stop = start + 8
        if name in ("bsr_ret",):
            expect = expect.replace("ra=4", f"ra={start + 4:x}")
            stop = start + 5 * 4
        if name == "br_link":
            expect = expect.replace("t3=4", f"t3={start + 4:x}")
            stop = start + 8
        lines.append(f"{name} {start:x} {stop:x} {init} {expect}")
        struct.pack_into("<I", image, pc, NOP)   # separator
        pc += 4
    assert pc < DATA
    open(f"{out}/emu.bin", "wb").write(image)
    open(f"{out}/emu.txt", "w").write("\n".join(lines) + "\n")
    print(f"{len(tests)} emulator tests")

if __name__ == "__main__":
    main()
