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

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Windows NT for Alpha (PE images, IMAGE_FILE_MACHINE_ALPHA):
 * <ul>
 * <li>Ghidra's PE loader does not read the Alpha exception directory ({@code .pdata}). Its
 * entries (ALPHA_RUNTIME_FUNCTION: begin, end, exception handler, handler data, prologue end;
 * absolute 32-bit addresses) list every procedure, so each begin address becomes a function.</li>
 * <li>Alpha NT is a 32-bit-pointer system on a 64-bit CPU: import address table entries are
 * 32 bits. They are typed as 32-bit pointers (keeping their external references), so the
 * import thunks ({@code ldah t12; ldl t12; jmp (t12)}) resolve to the imported functions.</li>
 * </ul>
 */
public class AlphaPeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Alpha NT PE Functions and Imports";
	private static final String DESCRIPTION = "Creates functions from the Alpha exception " +
		"directory (.pdata) and types import address table entries as 32-bit pointers.";

	public AlphaPeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
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

	private static StructureDataType runtimeFunction(DataTypeManager dtm) {
		StructureDataType s = new StructureDataType("ALPHA_RUNTIME_FUNCTION", 0, dtm);
		DataType p32 = new PointerDataType(DataType.DEFAULT, 4, dtm);
		s.add(p32, "BeginAddress", null);
		s.add(p32, "EndAddress", null);
		s.add(p32, "ExceptionHandler", null);
		s.add(p32, "HandlerData", null);
		s.add(p32, "PrologEndAddress", null);
		return s;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		fixImportPointers(program, monitor, log);
		MemoryBlock pdata = program.getMemory().getBlock(".pdata");
		if (pdata == null || !pdata.isInitialized()) {
			return true;
		}
		Memory mem = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		DataType rf = program.getDataTypeManager()
				.addDataType(runtimeFunction(program.getDataTypeManager()),
					DataTypeConflictHandler.DEFAULT_HANDLER);
		AddressSet starts = new AddressSet();
		long n = pdata.getSize() / 20;
		for (long i = 0; i < n; i++) {
			monitor.checkCancelled();
			Address entry = pdata.getStart().add(i * 20);
			long begin, end;
			try {
				begin = mem.getInt(entry) & 0xffffffffL;
				end = mem.getInt(entry.add(4)) & 0xffffffffL;
			}
			catch (MemoryAccessException e) {
				break;
			}
			if (begin == 0 && end == 0) {
				break; // padding at the end of the table
			}
			Address b = space.getAddress(begin);
			MemoryBlock blk = mem.getBlock(b);
			if (blk == null || !blk.isExecute() || end <= begin) {
				continue;
			}
			try {
				DataUtilities.createData(program, entry, rf, 20, false,
					DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			catch (CodeUnitInsertionException e) {
				// leave existing markup alone
			}
			starts.add(b);
		}
		if (starts.isEmpty()) {
			return true;
		}
		new DisassembleCommand(starts, null, true).applyTo(program, monitor);
		for (AddressRange r : starts) {
			Address a = r.getMinAddress();
			if (program.getFunctionManager().getFunctionAt(a) == null) {
				new CreateFunctionCmd(a).applyTo(program, monitor);
			}
		}
		return true;
	}

	/** retype 64-bit pointers that carry an external (import) reference as 32-bit pointers */
	private static void fixImportPointers(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		DataType p32 = new PointerDataType(DataType.DEFAULT, 4, program.getDataTypeManager());
		AddressIterator it = rm.getReferenceSourceIterator(program.getMemory(), true);
		java.util.List<Address> sources = new java.util.ArrayList<>();
		while (it.hasNext()) {
			monitor.checkCancelled();
			Address a = it.next();
			for (Reference r : rm.getReferencesFrom(a)) {
				if (r.isExternalReference()) {
					sources.add(a);
					break;
				}
			}
		}
		java.util.Map<Address, Reference[]> saved = new java.util.HashMap<>();
		for (Address a : sources) {
			saved.put(a, rm.getReferencesFrom(a));
		}
		for (Address a : sources) {
			// import address table entries are 32 bits whatever type the loader gave them
			// (8-byte pointers, or undefined8 for data imports such as _iob)
			Data d = listing.getDataContaining(a);
			if (d != null && d.getLength() == 4 && d.getAddress().equals(a)) {
				continue;
			}
			if (d != null && !d.isPointer() && d.getLength() != 8) {
				continue; // inside some other data: leave it alone
			}
			try {
				if (d != null) {
					listing.clearCodeUnits(d.getAddress(), d.getMaxAddress(), false);
				}
				listing.createData(a, p32);
			}
			catch (Exception e) {
				log.appendMsg(NAME, "could not retype import pointer at " + a + ": " + e.getMessage());
			}
		}
		for (Address a : sources) {
			for (Reference r : saved.get(a)) {
				if (!(r instanceof ExternalReference er)) {
					continue;
				}
				boolean present = false;
				for (Reference cur : rm.getReferencesFrom(a)) {
					present |= cur.isExternalReference();
				}
				if (present) {
					continue;
				}
				try {
					ExternalLocation loc = er.getExternalLocation();
					rm.addExternalReference(a, loc.getLibraryName(), loc.getLabel(),
						loc.getAddress(), er.getSource(), er.getOperandIndex(), er.getReferenceType());
				}
				catch (Exception e) {
					log.appendMsg(NAME, "could not restore import reference at " + a);
				}
			}
		}
	}
}
