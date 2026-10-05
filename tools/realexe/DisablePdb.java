// Ghidra headless preScript: turn off PDB loading before auto-analysis.
//
// Gosleigh does not consume PDB symbols, so a golden decompiled with PDB names
// and types can never match byte-for-byte. The parity golden is therefore the
// no-PDB analysis. Note the PDB analyzers would otherwise find the PDB through
// the absolute path recorded in the PE debug directory even when the .pdb is
// not next to the imported file.
//
// @category Gosleigh

import ghidra.app.script.GhidraScript;

public class DisablePdb extends GhidraScript {

	@Override
	public void run() throws Exception {
		setAnalysisOption(currentProgram, "PDB Universal", "false");
		setAnalysisOption(currentProgram, "PDB MSDIA", "false");
		println("DisablePdb: PDB analyzers disabled");
	}
}
