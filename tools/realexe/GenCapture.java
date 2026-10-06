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

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.TypeDef;

import java.io.File;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class GenCapture extends GhidraScript {

	// The savefile lists data-types in dependency order, but the C++ core
	// issues type warnings (an enum with duplicate values) in the order it
	// decoded them, i.e. the order it queried Java. DecompileDebug keeps that
	// order in its private dtypes list; write the warned enums in that order
	// beside the capture (<entry>.typeorder).
	private void writeTypeOrder(DecompInterface iface, File out) {
		try {
			// decompileFunction drops the interface's own reference after the
			// dump; the callback still holds the DecompileDebug.
			Field cf = DecompInterface.class.getDeclaredField("decompCallback");
			cf.setAccessible(true);
			Object cb = cf.get(iface);
			if (cb == null) {
				return;
			}
			Field df = cb.getClass().getDeclaredField("debug");
			df.setAccessible(true);
			Object debug = df.get(cb);
			if (debug == null) {
				return;
			}
			Field tf = debug.getClass().getDeclaredField("dtypes");
			tf.setAccessible(true);
			List<?> dtypes = (List<?>) tf.get(debug);
			// Only enums the core warns about: two names with one value
			// (TypeEnum::decode "Some values do not have unique names").
			try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
				for (Object o : dtypes) {
					if (o instanceof TypeDef) {
						o = ((TypeDef) o).getBaseDataType();
					}
					if (!(o instanceof Enum)) {
						continue;
					}
					Enum en = (Enum) o;
					Set<Long> seen = new HashSet<>();
					for (String nm : en.getNames()) {
						if (!seen.add(en.getValue(nm))) {
							w.println(en.getName());
							break;
						}
					}
				}
			}
		}
		catch (Exception e) {
			println("GenCapture: no type order: " + e);
		}
	}

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
			writeTypeOrder(iface, new File(outDir, String.format("%08x.typeorder", off)));
			iface.dispose();
			println("GenCapture: wrote " + out);
		}
	}
}
