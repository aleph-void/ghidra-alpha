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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Alpha NT import stubs, {@code ldah t12,hi(zero); ldl t12,lo(t12); jmp (t12)}, jump through a
 * 32-bit import address table entry. Ghidra's thunk detection does not follow the sign-extended
 * 32-bit load, so each such stub becomes a thunk of the external function its IAT entry
 * references.
 */
public class AlphaNtImportThunkAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Alpha NT Import Thunks";
	private static final String DESCRIPTION =
		"Makes Alpha NT import stubs (ldah/ldl/jmp through the IAT) thunks of the imported functions.";

	public AlphaNtImportThunkAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("Alpha")) &&
			PeLoader.PE_NAME.equals(program.getExecutableFormat());
	}

	/** the IAT entry a stub at entry jumps through, or null */
	static Address stubTarget(Program program, Address entry) {
		try {
			int ldah = program.getMemory().getInt(entry);
			int ldl = program.getMemory().getInt(entry.add(4));
			int jmp = program.getMemory().getInt(entry.add(8));
			int r = (ldah >> 21) & 31;
			if ((ldah >>> 26) != 0x09 || ((ldah >> 16) & 31) != 31 || (ldl >>> 26) != 0x28 ||
				((ldl >> 21) & 31) != r || ((ldl >> 16) & 31) != r || (jmp >>> 26) != 0x1a ||
				((jmp >> 14) & 3) != 0 || ((jmp >> 16) & 31) != r) {
				return null;
			}
			long a = ((long) (short) (ldah & 0xffff) << 16) + (short) (ldl & 0xffff);
			return entry.getNewAddress(a & 0xffffffffL);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		makeThunks(program, program.getFunctionManager().getFunctions(set, true), monitor, log);
		return true;
	}

	/** turn every import stub among functions into a thunk of its import */
	static void makeThunks(Program program, Iterable<Function> functions, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		ReferenceManager rm = program.getReferenceManager();
		for (Function f : functions) {
			monitor.checkCancelled();
			if (f.isThunk()) {
				continue;
			}
			Address iat = stubTarget(program, f.getEntryPoint());
			if (iat == null) {
				continue;
			}
			for (Reference r : rm.getReferencesFrom(iat)) {
				if (!(r instanceof ExternalReference er)) {
					continue;
				}
				ExternalLocation loc = er.getExternalLocation();
				Function ext = loc.getFunction();
				if (ext == null) {
					ext = loc.createFunction();
				}
				try {
					f.setBody(new AddressSet(f.getEntryPoint(), f.getEntryPoint().add(11)));
					f.setThunkedFunction(ext);
				}
				catch (Exception e) {
					log.appendMsg(NAME, "could not make " + f.getName() + " a thunk: " + e.getMessage());
				}
				break;
			}
		}
	}
}
