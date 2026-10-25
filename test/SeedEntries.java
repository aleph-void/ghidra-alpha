// Pre-analysis script for raw images: disassemble at each given address, make it a function
// and an external entry point, so auto-analysis has somewhere to start. Arguments of the form
// code=<start>-<end> (hex, inclusive) list the code ranges: the image's memory block is split
// at their boundaries and only they stay executable, so data next to code is not disassembled.
// Script args: [code=<start>-<end> ...] <address-hex> ...
//@category Testing

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class SeedEntries extends GhidraScript {

	@Override
	protected void run() throws Exception {
		List<Address> seeds = new ArrayList<>();
		AddressSet code = new AddressSet();
		for (String s : getScriptArgs()) {
			if (s.startsWith("code=")) {
				String[] r = s.substring(5).split("-");
				code.add(toAddr(Long.decode(r[0])), toAddr(Long.decode(r[1])));
			}
			else {
				seeds.add(toAddr(Long.decode(s)));
			}
		}
		if (!code.isEmpty()) {
			Memory mem = currentProgram.getMemory();
			for (var r : code) {
				for (Address cut : new Address[] { r.getMinAddress(), r.getMaxAddress().next() }) {
					MemoryBlock b = cut == null ? null : mem.getBlock(cut);
					if (b != null && !b.getStart().equals(cut)) {
						mem.split(b, cut);
					}
				}
			}
			for (MemoryBlock b : mem.getBlocks()) {
				b.setExecute(code.contains(b.getStart()));
			}
		}
		for (Address a : seeds) {
			disassemble(a);
			createFunction(a, null);
			currentProgram.getSymbolTable().addExternalEntryPoint(a);
		}
	}
}
