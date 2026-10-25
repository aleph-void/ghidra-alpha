# DEC Alpha processor module for Ghidra

SLEIGH processor module for the DEC/Compaq Alpha (AXP): disassembly, p-code semantics,
implementation-specific PALcode instructions, per-OS register names and CALL_PAL functions,
ELF loading with relocations. Target: **Ghidra 12.1.4** (also builds for 12.1.3 and 12.2).

This is the community module [kkaempf/ghidra-alpha](https://github.com/kkaempf/ghidra-alpha)
by Klaus Kämpf and Matt Turner (Apache-2.0), verified and fixed by Ghidra-Rare. See
[CREDITS.md](CREDITS.md) for provenance and the full list of changes.

## Languages

Fifteen languages: five CPU generations times three operating-system conventions.

| Language ID | CPU | PALcode format |
|---|---|---|
| `21064:LE:64:{unix,vms,nt}` | 21064/21066/21068 (EV4, EV45, LCA) | EV4 |
| `21164:LE:64:{unix,vms,nt}` | 21164/21164A/21164PC (EV5, EV56, PCA56) | EV5 |
| `21264:LE:64:{unix,vms,nt}` | 21264 (EV6, EV67, EV68) **ELF default** | EV6 |
| `21364:LE:64:{unix,vms,nt}` | 21364 (EV7) | EV6 |
| `21464:LE:64:{unix,vms,nt}` | 21464 (EV8) | EV6 |

User-mode code decodes identically in all of them; every language accepts the BWX, FIX, CIX
and MVI extensions. The CPU matters for PALcode (HW_MFPR/HW_MTPR, HW_LD/HW_ST, HW_REI/HW_RET
encodings) and IMPLVER. The OS selects register names (`unix`: v0, t0, ..., pv, GP, SP;
`nt`: t12, gp, sp; `vms`: R0..R28, AI, RA, PV, FP), the calling convention and the named
CALL_PAL functions (CALLSYS/RDUNIQ/... for OSF/1 and Linux, the NT and OpenVMS lists).

Loading:

- **ELF.** `EM_ALPHA` 0x9026 (what GNU toolchains write) and 41 load as `21264:LE:64:unix`.
  The relocation handler applies the dynamic and data relocations (RELATIVE, REFQUAD, GLOB_DAT,
  JMP_SLOT, REFLONG, SREL*, BRADDR, HINT). In relocatable objects it also applies the
  gp-relative ones: LITERAL entries go into an artificial `%got` block, and gp is 0x8000 past
  the lowest of that block and the small-data sections. It handles GPDISP, LITERAL,
  GPREL16/32, GPRELHIGH/GPRELLOW and BRSGP.
- **Windows NT (PE, IMAGE_FILE_MACHINE_ALPHA).** These load as `21264:LE:64:nt`. Functions
  come from the exception directory (`.pdata`). Import-table entries are 32-bit pointers, and
  the `ldah/ldl/jmp` import stubs are thunks of the imported functions. NT uses 32-bit
  pointers.
- **OpenVMS.** Ghidra has no loader for OpenVMS Alpha images. Import the image sections raw
  with a `:vms` language, at their virtual addresses (`objdump -h` lists them;
  `test/vms_flat.py` lays them out). The gp analyzer finds the procedure descriptors and seeds
  `PV` (R27) at each procedure entry, so linkage-section references resolve.

Analysis:

- **gp.** The gp analyzer seeds `pv` at every function entry and `gp` at the post-`ldgp` entry.
  After a call, `ra` holds the return address, so gcc's `ldgp gp,0(ra)` folds to the constant
  gp, and gp-relative globals and jump tables resolve.
- **ldgp prologues.** gcc gives each procedure a second entry point after its two-instruction
  `ldgp` prologue (`foo..ng`). The prologue becomes an 8-byte thunk of that body (`foo` →
  `foo..ng`), so each procedure is one function.
- **PALcode.** `ghidra_scripts/AlphaPALcodeEntries.java` marks the PALcode vectors and CALL_PAL
  entry points, which nothing branches to.

## Semantics

Everything is p-code except state that is outside the program. These are pcodeops:

- The cycle counter (RPCC).
- AMASK, whose result depends on the exact chip; one language covers several chips.
- Cache and prefetch hints, and memory barriers.
- PALcode internal processor registers.
- The PALcode behind CALL_PAL.

Floating point:

- **Register formats.** S and F values live in the registers in T and G layout. LDS/STS,
  ITOFS/FTOIS, LDF/STF/ITOFF and LDG/STG map the bits as the architecture does, so denormals,
  NaN payloads and VAX values move exactly.
- **IEEE rounding.** Instructions without a rounding qualifier are plain float p-code. /C
  (chopped), /M (minus infinity) and /D (dynamic, from FPCR<59:58>) are exact: the
  round-to-nearest result is moved by one unit when the exact result is on the other side.
  Error-free transformations give the sign of that error. FPCR is a register, so MT_FPCR and
  MF_FPCR move it. The pspec tracks FPCR's start value (normal rounding), so the decompiler
  folds /D code.
- **Signed zero.** Exact zero sums are -0 when rounding toward minus infinity.
- **VAX F/G/D.** These convert exactly to IEEE double, are computed there and convert back.
  F results round to 24 bits and G to 53. Normal VAX rounding sends exact ties away from zero;
  /C chops. CVTDG/CVTGD convert D format. VAX compares, NEGF/NEGG, CVTGQ, CVTQF/CVTQG and
  SQRTF/SQRTG are included.
- **FP branches and FCMOVxx.** These test the register bits, as the architecture defines them,
  so the same test works for IEEE and VAX operands.
- **MVI.** MINxB8/MINxW4/MAXxB8/MAXxW4 and PERR are per-element p-code.

## Results

| Check | Result |
|---|---|
| SLEIGH | 15/15 specs compile on Ghidra 12.1.3, 12.1.4 and 12.2. Each `.sla` is 38-42 KB |
| Decode vs GNU objdump 2.45, every opcode-table entry (16 words each, 16,000 words) | 21264, 21364 and 21464: 100% exact+semantic. 21064: 99.78%, plus 34 words of a confirmed objdump bug. 21164: 77.05%, plus 3,554 words of a confirmed objdump bug. 0 unexplained differences; 0 words decoded by only one side |
| Decode, 50,000 random words | 21264 and later: 100.00% (99.16% exact). 21064: 99.87%, plus 46 objdump-bug words. 21164: 98.23%, plus 611 objdump-bug words. 0 words differ; 0 one-sided |
| Every-entry test (all 16 words of each applicable table entry decode and agree) | EV4 716/716, EV5 880/880, EV6 670/670 |
| CALL_PAL names vs MAME `unidasm` (0x00-0x3f, 0x80-0xbf) | UNIX, NT, VMS: 128/128 each |
| Upstream's own `tests/*.hex` (`test/upstream-tests.sh`) | 36/36 (12 files on 21064 VMS, 21164 UNIX and 21264 NT) |
| Emulator, hand-computed | 53/53. These include MVI, the S/F/G bit mappings, VAX arithmetic, ties and conversions, the IEEE rounding modes and FP branches on NaN |
| Emulator vs `qemu-alpha -cpu ev67` (VAX instructions vs an exact reference model) | 40,000/40,000 random tests (two seeds), 206 mnemonics, 0 differences. Covers: MVI; every IEEE rounding mode, with /D under a random FPCR rounding mode; ITOFS/FTOIS on random bit patterns; VAX F/G with and without /C |
| Relocations in a relocatable object (`test/reloc-check.sh`) | 24 applied, 0 failed. Checked by formula (GPDISP gives gp; LITERAL loads a GOT entry holding S; GPREL16, GPRELHIGH/LOW and GPREL32 give S + A; .eh_frame SREL32 gives S + A - P): 16/16 sites. 88 other bytes are identical to GNU ld's link |
| Debian alpha `libz.so.1.3.2`, `ls`, `sort`, `libc.so.6.1`, `busybox` (static) | The opinion picks the language for all. 822,959 instructions, 100% agree with objdump at the same addresses. 0 bad-instruction and 0 error bookmarks. 1,703 relocations applied; 15 TLS TPREL64 reported. 0 decompile failures, 0 timeouts |
| QEMU EV6 PALcode `palcode-clipper` | 3,703 instructions, 100% agree with `objdump -m alpha:ev6`. 0 decompile failures |
| Windows NT PE: MiKTeX 1.07 `miktex.dll`, `dvips.exe`, `bibtex.exe`, `makeindex.exe`, Info-ZIP `unzip.exe` | The opinion picks `21264:LE:64:nt`. 125,022 instructions, 100% agree with objdump: binutils has no Alpha PE support, so the code sections are compared with `objdump -b binary` at their addresses. 0 bad-instruction and 0 error bookmarks. 829 functions decompile with 0 failures; their functions come from `.pdata`. Imports resolve through the 32-bit IAT and the import-stub thunks. The only lost jump tables are in two `unzip.exe` functions; every other occurrence is the stub's own `jmp` when the thunk itself is decompiled. One `dvips.exe` function decompiles a path into data (`halt_baddata`) |
| OpenVMS: Info-ZIP UnZip 5.12 for VMS AXP (`unz512x-axp.exe`, raw import) | 13,899 instructions, 100% agree with `objdump -d` (vms-alpha). 141 functions, all decompile. Procedure descriptors give `PV`, so linkage-section calls resolve |

Before these fixes, the same Linux samples produced:

- Two overlapping functions for every `ldgp` procedure (135 pairs in `ls`, 1,448 in libc, 2,744
  in busybox).
- 102 distinct lost switch tables. Now 47 remain: libz 1 → 0, ls 5 → 2, sort 5 → 3,
  libc 45 → 14, busybox 44 → 26.
- 413 libc functions with `in_r` inputs. Now 119.

The upstream module as imported scored 94-95% on random words and 586-591 of 670-880 table
entries. It had no ELF opinion, so Debian binaries did not import.

Semantic agreement covers objdump's alternative spellings: `or`/`andnot`/`jcr` for the
architecture's BIS/BIC/JSR_COROUTINE, objdump pseudo-ops (`negq`, `fmov`, `sextl`, `negt/su`,
...) that the module prints in full, and OS-named CALL_PAL functions.

### Confirmed GNU objdump 2.45 bugs

- **EV5 HW_LD/HW_ST bit 10** (load LOCK, store COND) is never decoded: `EV5HWMEM_MASK` is
  `OP_MASK | 0xF800`, so the table's `hw_ldl/l`, `hw_ldq_l`, `hw_stl/c` ... entries never match
  and objdump prints the plain form. The module decodes the bit (21164 HRM).
- **EV4 HW_ST, mode 0xE**: `alpha-opc.c` names both `EV4HWMEM(0x1F,0xE)` and `0xF`
  `hw_stq/par`. 0xE is the longword form `hw_stl/par` (the generic `hw_st/par` entry
  agrees).

### Confirmed QEMU bugs (why VAX instructions are checked against a model)

QEMU 10.1's VAX floating-point helpers (`target/alpha/vax_helper.c`) are wrong, and the
source says so ("either implement VAX arithmetic properly or just signal invalid opcode"):

- `float32_to_f` drops the fraction of every F result.
- `helper_memory_to_f` (LDF, ITOFF) masks `0x003fffff` instead of `0x3fff` and sets the
  exponent extension for a zero exponent.
- CVTDG and CVTGD raise an illegal-instruction fault.

`test/vax_model.py` implements the VAX instructions from the Alpha Architecture Handbook with
exact rational arithmetic, and the differential compares Ghidra with it.

## Testing

```sh
export GHIDRA_INSTALL_DIR=/path/to/scratch/ghidra_12.1.4_PUBLIC   # module gets symlinked in
export ALPHA_LD=/path/to/alpha-linux-gnu-ld                       # optional: relocation check
test/run-tests.sh /tmp/alpha-tests          # SLEIGH, decode, every-entry, emulator, QEMU diff, relocations
test/upstream-tests.sh /tmp/alpha-upstream  # upstream's tests/*.hex
test/fetch-real-samples.sh samples          # Debian, QEMU palcode, NT and VMS samples, pinned SHA-256
test/real-binaries.sh samples /tmp/alpha-real
```

Needs:

- GNU binutils with the alpha target (`OBJDUMP`), plus `BINUTILS_SRC`, `BINUTILS_LIB` and
  `LIBIBERTY` to dump its opcode table (see `test/build-dumpopc.sh`).
- MAME `unidasm`.
- `qemu-alpha` (optional).
- binutils configured `--target=alpha-linux-gnu` (optional, for the relocation check).
- A JDK with `javac` for `lib/Alpha.jar`.

Ghidra rejects project paths that contain a dot-directory; set `PROJ_DIR` when `TMPDIR` is
under one. `test/elf/relocs.s` is the relocation test object's source, and `test/elf/build.sh`
reassembles it.

## Known gaps

Fixed in this round (they were listed here before):

- MVI MIN/MAX/PERR are p-code.
- LDS/STS/ITOFS/FTOIS (and LDF/STF/LDG/STG/ITOFF) are bit-exact.
- The /C, /M and /D rounding modes are modelled exactly.
- VAX F/G/D arithmetic is real VAX arithmetic.
- FPCR is a register.
- gp-relative relocations in relocatable objects are applied.
- The `ldgp` double entry is fixed (thunk plus body).
- 55 of 102 lost switch tables were recovered, through `ra` after calls.
- Floating-point arguments share the six argument slots with the integer registers (cspec
  `<group>`).
- NT and VMS use 32-bit pointers.
- The VMS cspec has a stack argument area and float output types.
- The NT cspec names the `__cdecl`/`__fastcall` conventions.
- NT and VMS were checked on real, freely licensed binaries.

Remaining, with the reason each cannot be fixed in the module:

- **Readability cost of bit-exact S format.** A single-precision value loaded from memory
  decompiles as the bit mapping, not as `(double)f`: 30 sites in `ls` and `sort`, 23 in libc.
  Ghidra's decompiler cannot express Alpha's S-to-T register mapping as a conversion. Before,
  LDS used `float2float`, which reads well but changed the bits of denormals and NaNs.
- **Trap qualifiers (/U, /V, /S, /I) and FPCR exception bits.** These are hardware exception
  state; arithmetic traps are not modelled. VAX overflow (results past the G/F range) is not
  modelled either. The hardware traps there.
- **47 switch tables still not recovered.** The table base or index reaches the jump through a
  merge of several values, which the decompiler does not separate. Examples: a callee-saved
  register reused on other paths (busybox `FUN_12004acf8`), or a byte compared through a
  masked copy (`ls` 0x12001858c: the guard tests `t0 & 0xff` and the index is `t0`). The
  decompiler's jump-table recovery does no path-sensitive constant propagation.
- **Pcodeops.** RPCC, AMASK, cache hints, barriers and IPR accesses read or change hardware
  state the program does not hold.
- **TLS relocations in relocatable objects.** Ghidra's ELF loader rejects every relocation
  against a thread-local (STT_TLS) symbol before the processor's handler runs
  (ElfRelocationContext.processRelocation). The dynamic ones have values only at run time.
- **OpenVMS loading.** There is no Ghidra loader for OpenVMS Alpha images, so they are imported
  raw. A loader is outside a processor module's scope.
- **21064/21164 PALcode formats.** These were checked against objdump and MAME only: there is
  no freely licensed EV4/EV5 PALcode image.
