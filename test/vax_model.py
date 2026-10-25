#!/usr/bin/env python3
"""Reference model of the Alpha VAX floating-point instructions, written from the Alpha
Architecture Handbook (register formats 2.2.6, VAX instruction descriptions 4.10), using exact
rational arithmetic. QEMU cannot be the oracle for these: its VAX helpers drop the fraction of
F results and mask the wrong bits in LDF/ITOFF (target/alpha/vax_helper.c, QEMU 10.1).

Register layout of F and G values: sign <63>, exponent <62:52> (excess 1024), fraction <51:0>
(F uses the top 23 fraction bits); value = 0.1f x 2^(exp - 1024); exponent 0 is zero.
D: sign <63>, exponent <62:55> (excess 128), fraction <54:0>.
Normal VAX rounding rounds exact halfway cases away from zero; /C chops.
"""
from fractions import Fraction
from math import isqrt

SIGN = 1 << 63

def g_val(b):
    e = (b >> 52) & 0x7ff
    if e == 0:
        return Fraction(0)
    v = Fraction((1 << 52) | (b & ((1 << 52) - 1)), 1 << 53) * Fraction(2) ** (e - 1024)
    return -v if b & SIGN else v

def d_val(b):
    e = (b >> 55) & 0xff
    if e == 0:
        return Fraction(0)
    v = Fraction((1 << 55) | (b & ((1 << 55) - 1)), 1 << 56) * Fraction(2) ** (e - 128)
    return -v if b & SIGN else v

def round_int(v, chopped):
    """round a non-negative Fraction to an integer"""
    q, r = divmod(v.numerator, v.denominator)
    if not chopped and 2 * r >= v.denominator:
        q += 1
    return q

def to_vax(v, bits, chopped, exact_sqrt_sticky=None):
    """Fraction -> G-layout register bits with a <bits>-bit significand (53 G, 24 F)"""
    if v == 0:
        return 0
    s = SIGN if v < 0 else 0
    a = abs(v)
    k = a.numerator.bit_length() - a.denominator.bit_length()   # 2^(k-1) <= a < 2^(k+1)
    while Fraction(2) ** k <= a:
        k += 1
    while Fraction(2) ** (k - 1) > a:
        k -= 1
    # a = m x 2^k, 0.5 <= m < 1
    m = a / Fraction(2) ** k
    q = round_int(m * (1 << bits), chopped)
    if q == 1 << bits:
        q >>= 1
        k += 1
    e = k + 1024
    if e <= 0:
        return 0                     # underflow: zero (no /U trap)
    frac = (q - (1 << (bits - 1))) << (53 - bits)
    return s | (e << 52) | frac

def sqrt_frac(v):
    """sqrt of a positive Fraction to 120 fraction bits plus a sticky bit (enough for rounding)"""
    n = v.numerator << 260
    d = v.denominator
    x = isqrt(n // d)
    exact = x * x * d == n
    return Fraction(2 * x + (0 if exact else 1), 2 << 130)

def f_to_g_layout(x):
    """F memory/integer-register longword -> G-layout register (LDF, ITOFF)"""
    e = (x >> 7) & 0xff
    hi = (x >> 14) & 1
    m3 = 0 if e == 0 or hi else 7
    return ((x >> 15) & 1) << 63 | hi << 62 | m3 << 59 | (x & 0x3fff) << 45 | (x >> 16) << 29

def model(name, a, b, ia):
    """result bits of <name> (with qualifier) for operand bits a (Fa), b (Fb), ia (Ra)"""
    base, _, q = name.partition("/")
    chopped = "c" in q
    if base in ("addf", "subf", "mulf", "divf", "addg", "subg", "mulg", "divg"):
        x, y = g_val(a), g_val(b)
        op = base[:3]
        r = x + y if op == "add" else x - y if op == "sub" else x * y if op == "mul" else x / y
        return to_vax(r, 24 if base[3] == "f" else 53, chopped)
    if base in ("sqrtf", "sqrtg"):
        return to_vax(sqrt_frac(g_val(b)), 24 if base == "sqrtf" else 53, chopped)
    if base == "cvtgf":
        return to_vax(g_val(b), 24, chopped)
    if base == "cvtgq":
        v = g_val(b)
        r = round_int(abs(v), chopped)
        return (-r if v < 0 else r) & ((1 << 64) - 1)
    if base in ("cvtqf", "cvtqg"):
        i = b - (1 << 64) if b >> 63 else b
        return to_vax(Fraction(i), 24 if base == "cvtqf" else 53, chopped)
    if base in ("cmpgeq", "cmpglt", "cmpgle"):
        x, y = g_val(a), g_val(b)
        t = {"cmpgeq": x == y, "cmpglt": x < y, "cmpgle": x <= y}[base]
        return 0x4000000000000000 if t else 0
    if base in ("negf", "negg"):
        return 0 if (b >> 52) & 0x7ff == 0 else b ^ SIGN
    if base == "itoff":
        return f_to_g_layout(ia & 0xffffffff)
    raise KeyError(name)
