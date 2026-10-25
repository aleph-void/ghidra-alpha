/* ###
 * IP: Apache License 2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.NotFoundException;

/**
 * ELF relocation handler for DEC Alpha (EM_ALPHA: 0x9026 as used by every GNU toolchain, and
 * the official 41).
 * <p>
 * Semantics follow binutils bfd/elf64-alpha.c and glibc sysdeps/alpha/dl-machine.h:
 * <ul>
 * <li>Dynamic: RELATIVE = B + A; REFQUAD, GLOB_DAT and JMP_SLOT = S + A (one quadword). With
 * the secure PLT (DT_ALPHA_PLTRO) JMP_SLOT addresses a .got entry; old-style PLTs are patched
 * by the dynamic linker at run time and are left alone here.</li>
 * <li>Static data and branch fields of relocatable objects: REFLONG, SREL16/32/64, BRADDR,
 * HINT.</li>
 * <li>GP-relative relocations of relocatable objects: there is no linker-built GOT, so LITERAL
 * entries go into an artificial {@code %got} block, and gp is 0x8000 past the lowest of that
 * block and the small-data sections ({@link Alpha_ElfRelocationContext}). GPDISP rewrites the
 * ldah/lda pair that computes gp, GPREL16/GPRELHIGH/GPRELLOW/GPREL32 are S + A - gp, and BRSGP
 * branches past the target's ldgp prologue when it has one (STO_ALPHA_STD_GPLOAD).</li>
 * </ul>
 * TLS relocations are reported: their values depend on the thread pointer and on module IDs and
 * offsets that only the dynamic linker assigns.
 */
public class Alpha_ElfRelocationHandler
		extends AbstractElfRelocationHandler<Alpha_ElfRelocationType, Alpha_ElfRelocationContext> {

	public static final int EM_ALPHA = 0x9026;
	public static final int EM_ALPHA_OFFICIAL = 41;

	public Alpha_ElfRelocationHandler() {
		super(Alpha_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == (short) EM_ALPHA || elf.e_machine() == EM_ALPHA_OFFICIAL;
	}

	@Override
	public Alpha_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new Alpha_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	/** st_other: the symbol's entry starts with the standard two-instruction ldgp */
	private static final int STO_ALPHA_STD_GPLOAD = 0x88;
	private static final int STO_ALPHA_MASK = 0x88;

	private static long gp(Alpha_ElfRelocationContext ctx) throws NotFoundException {
		return ctx.getGp();
	}

	/** high half for an ldah whose lda/ldq partner adds the sign-extended low half */
	private static int hi16(long v) {
		return (int) (((v >> 16) + ((v >> 15) & 1)) & 0xffff);
	}

	private static void setDisp16(Memory mem, Address a, long v) throws MemoryAccessException {
		int insn = mem.getInt(a);
		mem.setInt(a, (insn & 0xffff0000) | (int) (v & 0xffff));
	}

	@Override
	public int getRelrRelocationType() {
		return Alpha_ElfRelocationType.R_ALPHA_RELATIVE.typeId;
	}

	@Override
	protected RelocationResult relocate(Alpha_ElfRelocationContext ctx, ElfRelocation relocation,
			Alpha_ElfRelocationType type, Address relocationAddress, ElfSymbol elfSymbol,
			Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory mem = program.getMemory();
		long addend = relocation.getAddend();
		long P = relocationAddress.getOffset();
		int symIndex = relocation.getSymbolIndex();

		switch (type) {
			case R_ALPHA_NONE:
			case R_ALPHA_LITUSE: // marks uses of a LITERAL load for linker relaxation
				return RelocationResult.SKIPPED;

			case R_ALPHA_RELATIVE:
				mem.setLong(relocationAddress, ctx.getImageBaseWordAdjustmentOffset() + addend);
				return new RelocationResult(Status.APPLIED, 8);

			case R_ALPHA_DTPMOD64: // module ID: assigned by the dynamic linker
				return RelocationResult.SKIPPED;

			case R_ALPHA_GPDISP: {
				// ldah at P and lda at P + addend compute gp from the register they use (pv at a
				// procedure entry, ra after a call, both holding P's address); their fields
				// receive gp - P plus the offset already assembled into them.
				try {
					Address ldaAddr = relocationAddress.add(addend);
					int ldah = mem.getInt(relocationAddress);
					int lda = mem.getInt(ldaAddr);
					long old = ((long) (short) (ldah & 0xffff) << 16) + (short) (lda & 0xffff);
					long disp = gp(ctx) - P + old;
					mem.setInt(relocationAddress, (ldah & 0xffff0000) | hi16(disp));
					mem.setInt(ldaAddr, (lda & 0xffff0000) | (int) (disp & 0xffff));
					return new RelocationResult(Status.APPLIED, 4);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						"GOT allocation failure", ctx.getLog());
					return RelocationResult.FAILURE;
				}
			}

			default:
				break;
		}

		if (handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		long S = symbolValue;
		switch (type) {
			case R_ALPHA_REFQUAD:
			case R_ALPHA_GLOB_DAT:
			case R_ALPHA_JMP_SLOT:
				mem.setLong(relocationAddress, S + addend);
				return new RelocationResult(Status.APPLIED, 8);

			case R_ALPHA_REFLONG:
				mem.setInt(relocationAddress, (int) (S + addend));
				return new RelocationResult(Status.APPLIED, 4);

			case R_ALPHA_SREL16:
				mem.setShort(relocationAddress, (short) (S + addend - P));
				return new RelocationResult(Status.APPLIED, 2);

			case R_ALPHA_SREL32:
				mem.setInt(relocationAddress, (int) (S + addend - P));
				return new RelocationResult(Status.APPLIED, 4);

			case R_ALPHA_SREL64:
				mem.setLong(relocationAddress, S + addend - P);
				return new RelocationResult(Status.APPLIED, 8);

			case R_ALPHA_BRADDR: { // 21-bit branch displacement in instructions
				int insn = mem.getInt(relocationAddress);
				long disp = (S + addend - (P + 4)) >> 2;
				mem.setInt(relocationAddress, (insn & 0xffe00000) | (int) (disp & 0x1fffff));
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_ALPHA_HINT: { // 14-bit JMP/JSR branch-prediction hint
				int insn = mem.getInt(relocationAddress);
				long disp = (S + addend - (P + 4)) >> 2;
				mem.setInt(relocationAddress, (insn & 0xffffc000) | (int) (disp & 0x3fff));
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_ALPHA_LITERAL: { // ldq Rx, got_entry(gp): the GOT entry holds S + A
				if (addend != 0) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						"LITERAL with addend not supported", ctx.getLog());
					return RelocationResult.FAILURE;
				}
				try {
					long gpv = gp(ctx);
					Address got = ctx.getGotEntryAddress(elfSymbol);
					if (got == null) {
						throw new NotFoundException();
					}
					long disp = got.getOffset() - gpv;
					if (disp < -0x8000 || disp > 0x7fff) {
						markAsError(program, relocationAddress, type, symbolName, symIndex,
							"GOT entry out of 16-bit range of gp", ctx.getLog());
						return RelocationResult.FAILURE;
					}
					setDisp16(mem, relocationAddress, disp);
					return new RelocationResult(Status.APPLIED, 4);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						"GOT allocation failure", ctx.getLog());
					return RelocationResult.FAILURE;
				}
			}

			case R_ALPHA_GPREL16:
			case R_ALPHA_GPRELHIGH:
			case R_ALPHA_GPRELLOW:
			case R_ALPHA_GPREL32: {
				long v;
				try {
					v = S + addend - gp(ctx);
				}
				catch (NotFoundException e) {
					markAsError(program, relocationAddress, type, symbolName, symIndex,
						"GOT allocation failure", ctx.getLog());
					return RelocationResult.FAILURE;
				}
				if (type == Alpha_ElfRelocationType.R_ALPHA_GPREL32) {
					if (v != (int) v) {
						markAsError(program, relocationAddress, type, symbolName, symIndex,
							"value out of 32-bit range of gp", ctx.getLog());
						return RelocationResult.FAILURE;
					}
					mem.setInt(relocationAddress, (int) v);
					return new RelocationResult(Status.APPLIED, 4);
				}
				if (type == Alpha_ElfRelocationType.R_ALPHA_GPRELHIGH) {
					if (((v >> 16) + ((v >> 15) & 1)) != (short) hi16(v)) {
						markAsError(program, relocationAddress, type, symbolName, symIndex,
							"value out of 32-bit range of gp", ctx.getLog());
						return RelocationResult.FAILURE;
					}
					setDisp16(mem, relocationAddress, hi16(v));
				}
				else {
					if (type == Alpha_ElfRelocationType.R_ALPHA_GPREL16 && v != (short) v) {
						markAsError(program, relocationAddress, type, symbolName, symIndex,
							"value out of 16-bit range of gp", ctx.getLog());
						return RelocationResult.FAILURE;
					}
					setDisp16(mem, relocationAddress, v);
				}
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_ALPHA_BRSGP: { // bsr to a same-gp procedure: skip its ldgp prologue
				long target = S + addend;
				if (elfSymbol != null && (elfSymbol.getOther() & STO_ALPHA_MASK) == STO_ALPHA_STD_GPLOAD) {
					target += 8;
				}
				int insn = mem.getInt(relocationAddress);
				long disp = (target - (P + 4)) >> 2;
				mem.setInt(relocationAddress, (insn & 0xffe00000) | (int) (disp & 0x1fffff));
				return new RelocationResult(Status.APPLIED, 4);
			}

			case R_ALPHA_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName, symIndex,
					elfSymbol.getSize(), ctx.getLog());
				return RelocationResult.UNSUPPORTED;

			case R_ALPHA_TLSGD:
			case R_ALPHA_TLSLDM:
			case R_ALPHA_GOTDTPREL:
			case R_ALPHA_DTPREL64:
			case R_ALPHA_DTPRELHI:
			case R_ALPHA_DTPRELLO:
			case R_ALPHA_DTPREL16:
			case R_ALPHA_GOTTPREL:
			case R_ALPHA_TPREL64:
			case R_ALPHA_TPRELHI:
			case R_ALPHA_TPRELLO:
			case R_ALPHA_TPREL16:
				markAsWarning(program, relocationAddress, type, symbolName, symIndex,
					"Thread Local Symbol relocation not supported", ctx.getLog());
				return RelocationResult.UNSUPPORTED;

			default:
				markAsUnhandled(program, relocationAddress, type, symIndex, symbolName,
					ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
	}
}
