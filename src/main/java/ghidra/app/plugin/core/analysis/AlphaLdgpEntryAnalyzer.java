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

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * gcc (and the Tru64/OpenVMS calling standards' "standard gp load") start a procedure with
 * {@code ldah gp,hi(pv); lda gp,lo(gp)} and give it a second entry point just after those two
 * instructions, which callers in the same module enter with {@code bsr} and the caller's gp
 * ({@code foo..ng} in gcc's symbol table). Without help Ghidra makes two overlapping functions
 * with the same body.
 * <p>
 * This analyzer turns the first entry into an 8-byte thunk of the second: callers through
 * {@code jsr} reach the real body (and its prototype) through the thunk, and the body is
 * decompiled once, at the second entry, where the gp analyzer seeds gp with the value the
 * prologue computes.
 */
public class AlphaLdgpEntryAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Alpha ldgp Entry Points";
	private static final String DESCRIPTION = "Makes a procedure's ldgp prologue a thunk of its " +
		"second (post-ldgp) entry point, so each procedure has one function body.";

	public AlphaLdgpEntryAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("Alpha"));
	}

	/** true when the two instructions at entry are ldah $29,x($27); lda $29,y($29) */
	static boolean isLdgpPrologue(Program program, Address entry) {
		try {
			int ldah = program.getMemory().getInt(entry);
			int lda = program.getMemory().getInt(entry.add(4));
			return (ldah >>> 26) == 0x09 && ((ldah >> 21) & 31) == 29 && ((ldah >> 16) & 31) == 27 &&
				(lda >>> 26) == 0x08 && ((lda >> 21) & 31) == 29 && ((lda >> 16) & 31) == 29;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return false;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FunctionManager fm = program.getFunctionManager();
		Listing listing = program.getListing();
		for (Function f : fm.getFunctions(set, true)) {
			monitor.checkCancelled();
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			Address entry = f.getEntryPoint();
			if (!isLdgpPrologue(program, entry)) {
				continue;
			}
			Address second;
			try {
				second = entry.add(8);
			}
			catch (AddressOutOfBoundsException e) {
				continue;
			}
			// the prologue must flow into the body: both instructions and the one after them
			// disassembled (the body may already be a function of its own, from a bsr)
			Instruction i1 = listing.getInstructionAt(entry.add(4));
			if (listing.getInstructionAt(entry) == null || i1 == null ||
				listing.getInstructionAt(second) == null || !second.equals(i1.getFallThrough())) {
				continue;
			}
			try {
				f.setBody(new AddressSet(entry, entry.add(7)));
			}
			catch (Exception e) {
				log.appendMsg(NAME, "could not shrink " + f.getName() + ": " + e.getMessage());
				continue;
			}
			Function body = fm.getFunctionAt(second);
			if (body == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(second);
				cmd.applyTo(program, monitor);
				body = fm.getFunctionAt(second);
			}
			if (body == null) {
				log.appendMsg(NAME, "could not create the body function at " + second);
				continue;
			}
			try {
				f.setThunkedFunction(body);
				if (body.getSymbol().getSource() == SourceType.DEFAULT &&
					f.getSymbol().getSource() != SourceType.DEFAULT) {
					body.setName(f.getName() + "..ng", SourceType.ANALYSIS);
				}
			}
			catch (Exception e) {
				log.appendMsg(NAME, "could not make " + f.getName() + " a thunk: " + e.getMessage());
			}
		}
		return true;
	}
}
