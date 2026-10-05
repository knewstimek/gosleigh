// Ghidra headless postScript: dump a deterministic, size-stratified sample of
// functions from an already-analyzed program as a golden JSON.
//
//   analyzeHeadless <projDir> <projName> -process <file> -noanalysis \
//       -scriptPath tools/realexe -postScript GenSample.java <out.json> <n> <seed> <maxBytes>
//
// Schema matches testdata/x64_auto/GenGoldens.java (name/entry/bytes/c) plus
// "size". entry is the absolute VMA, so the Gosleigh side must map the image
// at its linked addresses (cmd/goldengap -pe) rather than base-0 bytes.
//
// Sampling: candidates (non-thunk, non-external, body span <= maxBytes) are
// sorted by span and one function is drawn at a random position inside each of
// n equal-count quantile slices. This keeps small leaf functions from
// dominating the sample while staying reproducible for a given seed.
//
// @category Gosleigh

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

public class GenSample extends GhidraScript {

	private static final ghidra.program.model.symbol.NameTransformer DISPLAY_NT =
		new ghidra.program.model.symbol.IllegalCharCppTransformer();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outPath = arg(args, 0, "sample_goldens.json");
		int n = Integer.parseInt(arg(args, 1, "200"));
		long seed = Long.parseLong(arg(args, 2, "1"));
		long maxBytes = Long.parseLong(arg(args, 3, "4096"));

		List<Function> cands = new ArrayList<>();
		int total = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			total++;
			if (f.isThunk() || f.isExternal()) {
				continue;
			}
			long span = span(f);
			if (span <= 0 || span > maxBytes) {
				continue;
			}
			cands.add(f);
		}
		cands.sort(Comparator.comparingLong(GenSample::span)
				.thenComparing(f -> f.getEntryPoint().getOffset()));
		println("GenSample: " + total + " functions, " + cands.size() + " candidates");

		List<Function> picked = new ArrayList<>();
		Random rnd = new Random(seed);
		int m = Math.min(n, cands.size());
		for (int i = 0; i < m; i++) {
			int lo = (int) ((long) i * cands.size() / m);
			int hi = (int) ((long) (i + 1) * cands.size() / m);
			picked.add(cands.get(lo + rnd.nextInt(Math.max(1, hi - lo))));
		}

		DecompInterface iface = new DecompInterface();
		iface.openProgram(currentProgram);
		StringBuilder sb = new StringBuilder();
		sb.append("{\n  \"total_functions\": ").append(total);
		sb.append(",\n  \"candidates\": ").append(cands.size());
		sb.append(",\n  \"seed\": ").append(seed);
		sb.append(",\n  \"functions\": [\n");
		for (int i = 0; i < picked.size(); i++) {
			Function f = picked.get(i);
			if (i > 0) {
				sb.append(",\n");
			}
			sb.append("    {\n");
			sb.append("      \"name\": ").append(jsonStr(f.getName())).append(",\n");
			// The name the core prints for the function itself: transformed
			// like every symbol name DecompileCallback sends, namespace-qualified.
			String ns = nsPath(f.getParentNamespace(), DISPLAY_NT);
			String disp = DISPLAY_NT.simplify(f.getName());
			sb.append("      \"display\": ").append(jsonStr(ns.isEmpty() ? disp : ns + "::" + disp)).append(",\n");
			sb.append("      \"entry\": ").append(f.getEntryPoint().getOffset()).append(",\n");
			sb.append("      \"size\": ").append(span(f)).append(",\n");
			sb.append("      \"proto\": ").append(protoJson(f)).append(",\n");
			sb.append("      \"locals\": ").append(localsJson(f)).append(",\n");
			sb.append("      \"bytes\": ").append(jsonStr(bodyHex(f))).append(",\n");
			sb.append("      \"c\": ").append(jsonStr(decompile(iface, f))).append("\n");
			sb.append("    }");
		}
		sb.append("\n  ]\n}\n");
		iface.dispose();

		try (FileWriter w = new FileWriter(outPath)) {
			w.write(sb.toString());
		}
		println("GenSample: wrote " + picked.size() + " functions to " + outPath);
		writeSymbols(new java.io.File(new java.io.File(outPath).getAbsoluteFile().getParentFile(), "symbols.json"));
	}

	// The host symbol table the decompiler core queries through the Java
	// layer (ScopeGhidra): every function entry with its name. Gosleigh's
	// harness serves it back as the HostScope.
	// Names pass through the decompiler's own NameTransformer (the default
	// DecompileOptions one, as DecompInterface installs it), and namespaces are
	// the transformed parent path below the global namespace -- exactly what
	// DecompileCallback hands the core.
	private void writeSymbols(java.io.File path) throws Exception {
		ghidra.program.model.symbol.NameTransformer nt =
			new ghidra.program.model.symbol.IllegalCharCppTransformer();
		StringBuilder sb = new StringBuilder("{\n  \"functions\": [\n");
		boolean first = true;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!first) {
				sb.append(",\n");
			}
			first = false;
			// extrapop exactly as FunctionPrototype.grabFromFunction computes it
			// for the core: purge + model stackshift, else the model's extrapop.
			ghidra.program.model.lang.PrototypeModel pm = f.getCallingConvention();
			if (pm == null) {
				pm = currentProgram.getCompilerSpec().getDefaultCallingConvention();
			}
			int purge = f.getStackPurgeSize();
			int extrapop = (purge == Function.INVALID_STACK_DEPTH_CHANGE ||
				purge == Function.UNKNOWN_STACK_DEPTH_CHANGE) ? pm.getExtrapop()
						: purge + pm.getStackshift();
			String cc = f.getCallingConventionName();
			sb.append("    {\"entry\": ").append(f.getEntryPoint().getOffset())
				.append(", \"name\": ").append(jsonStr(nt.simplify(f.getName())))
				.append(", \"namespace\": ").append(jsonStr(nsPath(f.getParentNamespace(), nt)))
				.append(", \"cc\": ").append(jsonStr(cc == null ? "" : cc))
				.append(", \"extrapop\": ").append(extrapop == ghidra.program.model.lang.PrototypeModel.UNKNOWN_EXTRAPOP ? "null" : String.valueOf(extrapop))
				.append(", \"sigsrc\": ").append(jsonStr(f.getSignatureSource().toString()))
				.append(", \"thunk\": ").append(f.isThunk()).append("}");
		}
		sb.append("\n  ],\n  \"externals\": [\n");
		first = true;
		ghidra.program.model.symbol.ReferenceIterator it =
			currentProgram.getReferenceManager().getExternalReferences();
		while (it.hasNext()) {
			ghidra.program.model.symbol.Reference r = it.next();
			if (!(r instanceof ghidra.program.model.symbol.ExternalReference)) {
				continue;
			}
			ghidra.program.model.symbol.ExternalLocation loc =
				((ghidra.program.model.symbol.ExternalReference) r).getExternalLocation();
			if (!first) {
				sb.append(",\n");
			}
			first = false;
			sb.append("    {\"addr\": ").append(r.getFromAddress().getOffset())
				.append(", \"name\": ").append(jsonStr(nt.simplify(loc.getLabel()))).append("}");
		}
		sb.append("\n  ]\n}\n");
		try (FileWriter w = new FileWriter(path)) {
			w.write(sb.toString());
		}
		println("GenSample: wrote symbols to " + path);
	}

	private static String nsPath(ghidra.program.model.symbol.Namespace ns,
			ghidra.program.model.symbol.NameTransformer nt) {
		if (ns == null || ns.isGlobal()) {
			return "";
		}
		String parent = nsPath(ns.getParentNamespace(), nt);
		String name = nt.simplify(ns.getName());
		return parent.isEmpty() ? name : parent + "::" + name;
	}

	private static String arg(String[] a, int i, String def) {
		return (a.length > i) ? a[i] : def;
	}

	// Contiguous [min,max] span of the body; see GenGoldens.bodyHex for why
	// the span (not the range-by-range body) is the faithful byte image.
	private static long span(Function f) {
		AddressSetView body = f.getBody();
		if (body.isEmpty()) {
			return 0;
		}
		return body.getMaxAddress().subtract(body.getMinAddress()) + 1;
	}

	// The prototype committed in the program database is an input to the
	// decompiler core (FuncProto decode), not something the core derives. A
	// non-DEFAULT signature source means analysis (e.g. Decompiler Parameter
	// ID) locked it, so a standalone harness must inject it to be comparable.
	private static String protoJson(Function f) {
		StringBuilder b = new StringBuilder("{");
		b.append("\"cc\": ").append(jsonStr(String.valueOf(f.getCallingConventionName())));
		b.append(", \"source\": ").append(jsonStr(f.getSignatureSource().toString()));
		b.append(", \"custom_storage\": ").append(f.hasCustomVariableStorage());
		Parameter ret = f.getReturn();
		b.append(", \"ret\": ").append(varJson(ret.getName(), ret.getDataType().getName(), ret.getVariableStorage().toString()));
		b.append(", \"params\": [");
		Parameter[] ps = f.getParameters();
		for (int i = 0; i < ps.length; i++) {
			if (i > 0) {
				b.append(", ");
			}
			b.append(varJson(ps[i].getName(), ps[i].getDataType().getName(), ps[i].getVariableStorage().toString()));
		}
		return b.append("]}").toString();
	}

	// The function's own stack-frame locals, which DecompileCallback hands the
	// core as the name-locked symbols of its local scope (localdb).
	private static String localsJson(Function f) {
		StringBuilder b = new StringBuilder("[");
		ghidra.program.model.listing.Variable[] vars = f.getStackFrame().getLocals();
		for (int i = 0; i < vars.length; i++) {
			if (i > 0) {
				b.append(", ");
			}
			b.append("{\"offset\": ").append(vars[i].getStackOffset())
				.append(", \"name\": ").append(jsonStr(vars[i].getName()))
				.append(", \"size\": ").append(vars[i].getLength()).append("}");
		}
		return b.append("]").toString();
	}

	private static String varJson(String name, String type, String storage) {
		return "{\"name\": " + jsonStr(name) + ", \"type\": " + jsonStr(type) + ", \"storage\": " + jsonStr(storage) + "}";
	}

	private String decompile(DecompInterface iface, Function f) {
		DecompileResults res = iface.decompileFunction(f, 60, monitor);
		if (res == null || !res.decompileCompleted()) {
			return "";
		}
		DecompiledFunction d = res.getDecompiledFunction();
		return (d == null) ? "" : d.getC();
	}

	private String bodyHex(Function f) throws Exception {
		AddressSetView body = f.getBody();
		Address min = body.getMinAddress();
		byte[] buf = new byte[(int) span(f)];
		currentProgram.getMemory().getBytes(min, buf);
		StringBuilder hex = new StringBuilder();
		for (byte b : buf) {
			hex.append(String.format("%02x", b & 0xff));
		}
		return hex.toString();
	}

	private static String jsonStr(String s) {
		StringBuilder b = new StringBuilder("\"");
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
		return b.append('"').toString();
	}
}
