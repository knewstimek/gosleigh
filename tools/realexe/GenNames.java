// Ghidra headless postScript: write the name-collision table of selected
// functions beside their decompiler captures (<entry>.names).
//
//   analyzeHeadless <projDir> <projName> -process <file> -noanalysis -readOnly \
//       -scriptPath tools/realexe -postScript GenNames.java <outDir> <entry> [<entry>...]
//
// When printing a global symbol, the C++ core asks Java whether its name is
// used by a namespace between the function and the symbol's scope
// (DecompileCallback.isNameUsed); a collision adds a scope qualifier
// ("::FloatOne"). The debug capture does not record these answers, so this
// script records what isNameUsed reads: every symbol name of each namespace
// on the function's path, as "<name>\t<depth>" (depth 0 = outermost namespace
// below global), and "<name>\t*" for the capture's names carried by more than
// MAX_SYMBOL_COUNT symbols (isNameUsed then answers true). Run after
// GenCapture: the capture's names are read from <outDir>/<entry>.xml.
//
// @category Gosleigh

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GenNames extends GhidraScript {

	// DecompileCallback.MAX_SYMBOL_COUNT
	private static final int MAX_SYMBOL_COUNT = 16;

	private static final Pattern NAME_ATTR = Pattern.compile("\\bname=\"([^\"]*)\"");

	private static String unescape(String s) {
		return s.replace("&apos;", "'").replace("&quot;", "\"").replace("&lt;", "<")
				.replace("&gt;", ">").replace("&amp;", "&");
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir = new File(args[0]);
		SymbolTable st = currentProgram.getSymbolTable();
		for (int i = 1; i < args.length; i++) {
			long off = args[i].startsWith("0x") ? Long.parseLong(args[i].substring(2), 16)
					: Long.parseLong(args[i]);
			Function f = getFunctionAt(toAddr(off));
			if (f == null) {
				println("GenNames: no function at " + args[i]);
				continue;
			}
			// The namespace path DecompileCallback.isNameUsed walks, innermost
			// first, stopping at global (or a namespace collapsed to it).
			List<Namespace> path = new ArrayList<>();
			Namespace ns = f.getParentNamespace();
			while (ns != null && ns.getID() != Namespace.GLOBAL_NAMESPACE_ID &&
				!HighFunction.collapseToGlobal(ns)) {
				path.add(ns);
				ns = ns.getParentNamespace();
			}
			Set<String> lines = new LinkedHashSet<>();
			int n = path.size();
			for (int j = 0; j < n; j++) {
				SymbolIterator it = st.getSymbols(path.get(j));
				while (it.hasNext()) {
					lines.add(it.next().getName() + "\t" + (n - 1 - j));
				}
			}
			File cap = new File(outDir, String.format("%08x.xml", off));
			if (n > 0 && cap.exists()) {
				String xml = new String(Files.readAllBytes(cap.toPath()), StandardCharsets.UTF_8);
				Set<String> seen = new LinkedHashSet<>();
				Matcher m = NAME_ATTR.matcher(xml);
				while (m.find()) {
					String nm = unescape(m.group(1));
					if (nm.isEmpty() || !seen.add(nm)) {
						continue;
					}
					int count = 0;
					for (Symbol s : st.getSymbols(nm)) {
						if (++count > MAX_SYMBOL_COUNT) {
							lines.add(nm + "\t*");
							break;
						}
					}
				}
			}
			File out = new File(outDir, String.format("%08x.names", off));
			try (PrintWriter w = new PrintWriter(out, "UTF-8")) {
				for (String ln : lines) {
					w.println(ln);
				}
			}
		}
		println("GenNames: done");
	}
}
