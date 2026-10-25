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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.NotFoundException;

/**
 * Relocation context for DEC Alpha. Relocatable objects have no GOT; LITERAL relocations get
 * entries in an artificial {@code %got} block. gp is 0x8000 past the lowest of that block and
 * the small-data sections (.sdata, .sbss, .lit4, .lit8, .lita), as GNU ld places gp 0x8000 into
 * the GOT and small-data area it builds, so 16-bit gp displacements reach both.
 */
class Alpha_ElfRelocationContext extends ElfGotRelocationContext<Alpha_ElfRelocationHandler> {

	/** gp is this far into the GOT, so signed 16-bit displacements reach 64 KB of it */
	static final long GP_BIAS = 0x8000;

	Alpha_ElfRelocationContext(Alpha_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	private static final String[] SMALL_DATA = { ".sdata", ".sbss", ".lit4", ".lit8", ".lita" };
	private Long gp;

	/** gp for gp-relative relocations of a relocatable object */
	long getGp() throws NotFoundException {
		if (gp == null) {
			long low = getGOTValue();
			for (String n : SMALL_DATA) {
				MemoryBlock b = getProgram().getMemory().getBlock(n);
				if (b != null) {
					low = Math.min(low, b.getStart().getOffset());
				}
			}
			gp = low + GP_BIAS;
		}
		return gp;
	}

	@Override
	protected boolean requiresGotEntry(ElfRelocation r) {
		return r.getType() == Alpha_ElfRelocationType.R_ALPHA_LITERAL.typeId;
	}
}
