// Ghidra GhidraScript: dump HighFunction internals.
// Invoked via analyzeHeadless -postScript GhidraGcdDump.java <out.json> <entry>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Iterator;

public class GhidraGcdDump extends GhidraScript {

    private StringBuilder out = new StringBuilder();

    private String jstr(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder();
        b.append('"');
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') { b.append('\\').append(c); }
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        b.append('"');
        return b.toString();
    }

    private String vnDesc(Varnode vn) {
        if (vn == null) return "null";
        StringBuilder b = new StringBuilder();
        b.append("{");
        b.append("\"space\":").append(jstr(vn.getAddress().getAddressSpace().getName()));
        b.append(",\"offset_hex\":").append(jstr(Long.toHexString(vn.getOffset())));
        b.append(",\"offset\":").append(vn.getOffset());
        b.append(",\"size\":").append(vn.getSize());
        b.append(",\"is_input\":").append(vn.isInput());
        b.append(",\"is_constant\":").append(vn.isConstant());
        b.append(",\"is_addrtied\":").append(vn.isAddrTied());
        HighVariable hv = null;
        try { hv = vn.getHigh(); } catch (Exception e) {}
        if (hv != null) {
            b.append(",\"hv_name\":").append(jstr(hv.getName()));
            b.append(",\"hv_class\":").append(jstr(hv.getClass().getSimpleName()));
            try {
                HighSymbol sym = hv.getSymbol();
                if (sym != null) {
                    b.append(",\"hv_symbol\":").append(jstr(sym.getName()));
                }
            } catch (Exception e) {}
        }
        b.append("}");
        return b.toString();
    }

    private String opDesc(PcodeOp op) {
        StringBuilder b = new StringBuilder();
        b.append("{");
        b.append("\"seq\":").append(jstr(op.getSeqnum().toString()));
        b.append(",\"opcode\":").append(jstr(op.getMnemonic()));
        b.append(",\"opcode_int\":").append(op.getOpcode());
        b.append(",\"output\":").append(vnDesc(op.getOutput()));
        b.append(",\"inputs\":[");
        for (int i = 0; i < op.getNumInputs(); i++) {
            if (i > 0) b.append(",");
            b.append(vnDesc(op.getInput(i)));
        }
        b.append("]");
        if (op.getParent() != null) {
            b.append(",\"parent_idx\":").append(op.getParent().getIndex());
        }
        b.append("}");
        return b.toString();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new RuntimeException("expected output path");
        String outputPath = args[0];
        long entryOffset = 0;
        if (args.length > 1) {
            String s = args[1];
            if (s.startsWith("0x") || s.startsWith("0X")) entryOffset = Long.parseLong(s.substring(2), 16);
            else entryOffset = Long.parseLong(s);
        }
        Address entryAddr = toAddr(entryOffset);
        Listing listing = currentProgram.getListing();
        Function function = listing.getFunctionAt(entryAddr);
        if (function == null) {
            createFunction(entryAddr, "entry");
            function = listing.getFunctionAt(entryAddr);
        }
        if (function == null) throw new RuntimeException("no function at " + entryAddr);

        DecompInterface iface = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        iface.setOptions(opts);
        iface.openProgram(currentProgram);
        DecompileResults res = iface.decompileFunction(function, 120, monitor);
        if (!res.decompileCompleted()) {
            throw new RuntimeException("decompile failed: " + res.getErrorMessage());
        }
        HighFunction hf = res.getHighFunction();
        if (hf == null) throw new RuntimeException("no high function");

        StringBuilder json = new StringBuilder();
        json.append("{\"blocks\":[");
        ArrayList<PcodeBlockBasic> blocks = hf.getBasicBlocks();
        for (int bi = 0; bi < blocks.size(); bi++) {
            PcodeBlockBasic b = blocks.get(bi);
            if (bi > 0) json.append(",");
            json.append("{");
            json.append("\"index\":").append(b.getIndex());
            json.append(",\"start\":").append(jstr(b.getStart().toString()));
            json.append(",\"stop\":").append(jstr(b.getStop().toString()));
            json.append(",\"in_edges\":[");
            for (int i = 0; i < b.getInSize(); i++) {
                if (i > 0) json.append(",");
                json.append(b.getIn(i).getIndex());
            }
            json.append("],\"out_edges\":[");
            for (int i = 0; i < b.getOutSize(); i++) {
                if (i > 0) json.append(",");
                json.append(b.getOut(i).getIndex());
            }
            json.append("],\"ops\":[");
            Iterator<PcodeOp> it = b.getIterator();
            int opi = 0;
            while (it.hasNext()) {
                PcodeOp op = it.next();
                if (opi > 0) json.append(",");
                json.append(opDesc(op));
                opi++;
            }
            json.append("]}");
        }
        json.append("]");
        if (res.getDecompiledFunction() != null) {
            json.append(",\"c\":").append(jstr(res.getDecompiledFunction().getC()));
        }
        json.append("}");

        FileWriter fw = new FileWriter(outputPath);
        try { fw.write(json.toString()); } finally { fw.close(); }
        println("wrote dump to " + outputPath);
    }
}
