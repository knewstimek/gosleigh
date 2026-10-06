// Ghidra headless postScript: write decompiler debug captures (savefile XML)
// for selected functions of an analyzed program.
//
//   analyzeHeadless <projDir> <projName> -process <file> -noanalysis -readOnly \
//       -scriptPath tools/realexe -postScript GenCapture.java <outDir> <entry> [<entry>...]
//
// DecompInterface.enableDebug records everything the Java side hands the C++
// core for one decompilation (program bytes, symbols, callee prototypes, the
// eval models). Fed to tools/decomp_dbg.exe ("restore <file>"), the C++ core
// can be stepped and inspected in the exact real-binary environment the golden
// came from. Entries are decimal or 0x-prefixed offsets in the default space.
//
// @category Gosleigh

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;

import java.io.File;

public class GenCapture extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir = new File(args[0]);
		outDir.mkdirs();
		for (int i = 1; i < args.length; i++) {
			long off = args[i].startsWith("0x") ? Long.parseLong(args[i].substring(2), 16)
					: Long.parseLong(args[i]);
			Function f = getFunctionAt(toAddr(off));
			if (f == null) {
				println("GenCapture: no function at " + args[i]);
				continue;
			}
			File out = new File(outDir, String.format("%08x.xml", off));
			DecompInterface iface = new DecompInterface();
			// No setOptions: openProgram then installs the program's options
			// (grabFromProgram), as for the goldens -- e.g. protoeval is the
			// cspec eval_current_prototype, not "default".
			// Some saved projects carry no decompiler options, leaving the
			// interface without any (enableDebug then fails on encode): load
			// them from the program explicitly, which is what openProgram does
			// when they exist.
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			iface.setOptions(opts);
			iface.enableDebug(out);
			if (!iface.openProgram(currentProgram)) {
				println("GenCapture: openProgram failed for " + args[i] + ": " + iface.getLastMessage());
				iface.dispose();
				continue;
			}
			iface.decompileFunction(f, 60, monitor);
			iface.dispose();
			println("GenCapture: wrote " + out);
		}
	}
}
