// Ghidra headless postScript (Java -- works without PyGhidra).
// Dumps every function's name, entry offset, body bytes (hex), and decompiled
// C to a JSON file given as the first script argument.
//
//   analyzeHeadless <proj> <name> -import corpus.obj \
//       -scriptPath testdata/x64_corpus -postScript GenGoldens.java <out.json>
//
// @category Gosleigh

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;

import java.io.FileWriter;

public class GenGoldens extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outPath = (args.length > 0) ? args[0] : "x64_goldens.json";

		DecompInterface iface = new DecompInterface();
		iface.openProgram(currentProgram);
		FunctionManager fm = currentProgram.getFunctionManager();

		StringBuilder sb = new StringBuilder();
		sb.append("{\n  \"functions\": [\n");
		boolean first = true;
		for (Function func : fm.getFunctions(true)) {
			if (func.isThunk()) {
				continue;
			}
			String name = func.getName();
			long entry = func.getEntryPoint().getOffset();
			String c = decompile(iface, func);
			String bytesHex = bodyHex(func);
			if (!first) {
				sb.append(",\n");
			}
			first = false;
			sb.append("    {\n");
			sb.append("      \"name\": ").append(jsonStr(name)).append(",\n");
			sb.append("      \"entry\": ").append(entry).append(",\n");
			sb.append("      \"bytes\": ").append(jsonStr(bytesHex)).append(",\n");
			sb.append("      \"c\": ").append(jsonStr(c)).append("\n");
			sb.append("    }");
			println("dumped " + name + " @0x" + Long.toHexString(entry)
					+ " (" + (bytesHex.length() / 2) + " bytes)");
		}
		sb.append("\n  ]\n}\n");

		FileWriter w = new FileWriter(outPath);
		try {
			w.write(sb.toString());
		} finally {
			w.close();
		}
		println("wrote functions to " + outPath);
	}

	private String decompile(DecompInterface iface, Function func) {
		DecompileResults res = iface.decompileFunction(func, 60, monitor);
		if (res == null || !res.decompileCompleted()) {
			return "";
		}
		DecompiledFunction d = res.getDecompiledFunction();
		return (d == null) ? "" : d.getC();
	}

	private String bodyHex(Function func) throws Exception {
		// Read the whole function image contiguously from the body's minimum
		// to maximum address, NOT range-by-range. func.getBody() is an
		// AddressSetView that excludes unreachable dead-code islands (e.g. the
		// redundant "jmp epilogue" fillers MSVC /Od emits after each early
		// return in an if-else-if ladder); concatenating its disjoint ranges
		// drops those bytes and corrupts every relative branch displacement
		// that spans a dropped island -- the resulting slice disassembles with
		// jl/jmp targets landing mid-instruction or past the end. Emitting the
		// full [min,max] span preserves the real on-disk byte layout so the
		// slice decodes identically to the original binary.
		AddressSetView body = func.getBody();
		Address min = body.getMinAddress();
		Address max = body.getMaxAddress();
		Memory mem = currentProgram.getMemory();
		int n = (int) (max.subtract(min) + 1);
		byte[] buf = new byte[n];
		mem.getBytes(min, buf);
		StringBuilder hex = new StringBuilder();
		for (byte b : buf) {
			hex.append(String.format("%02x", b & 0xff));
		}
		return hex.toString();
	}

	private String jsonStr(String s) {
		StringBuilder b = new StringBuilder();
		b.append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"': b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default:
					if (c < 0x20) {
						b.append(String.format("\\u%04x", (int) c));
					} else {
						b.append(c);
					}
			}
		}
		b.append('"');
		return b.toString();
	}
}
