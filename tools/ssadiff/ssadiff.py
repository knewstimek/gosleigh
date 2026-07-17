"""ssadiff.py -- op-by-op SSA p-code comparator: Gosleigh vs. Ghidra C++ core.

Main entry point of tools/ssadiff/. For one function drawn from a
GenGoldens-schema golden JSON file (testdata/x64_corpus/x64_goldens.json and
friends):

  1. Runs the Gosleigh production decompile pipeline via `go run ./cmd/ssadump`
     and captures its pkg/pcode.DumpSSA text.
  2. Builds an unlocked-prototype decomp_dbg savefile (capture.py) and drives
     tools/decomp_dbg.exe's `print raw` console command (run_cpp.py) to get
     the C++ core's ground-truth SSA text -- or, if decomp_dbg isn't
     available, reads a pre-captured raw-text file instead (--cpp-raw-file).
  3. Parses both dumps into per-op records, normalizes away
     implementation-private numbering (creation-order "uniq" ids, unique-space
     temp offsets, structuring block indices -- see normalize_rest below),
     aligns them by instruction address, and prints a side-by-side diff plus
     summary match-rate statistics.

Usage:
    py -3 tools/ssadiff/ssadiff.py --golden testdata/x64_corpus/x64_goldens.json \
        --func sum_to_n --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe

    py -3 tools/ssadiff/ssadiff.py --golden testdata/x64_corpus2/x64_goldens.json \
        --func umulhi --decomp-dbg D:/News/Business/Gosleigh/tools/decomp_dbg.exe

    # No decomp_dbg available: compare against a pre-captured raw dump file
    # (see run_cpp.py output, or tools/captures/*.txt) instead of running it live.
    py -3 tools/ssadiff/ssadiff.py --golden testdata/x64_corpus/x64_goldens.json \
        --func sum_to_n --cpp-raw-file /tmp/sum_to_n_cpp_raw.txt

Must be run from the repository root (the --sla/--pspec/--cspec/--golden
defaults, and the `go run ./cmd/ssadump` invocation, are relative to it).
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capture  # noqa: E402
import run_cpp  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_BLOCK_HEADER_RE = re.compile(r"^Basic Block (\d+)(?: (\S+)-(\S+))?")
_IMPLIED_GOTO_RE = re.compile(r"^(\S+):\s*\t\[ goto (.+) \]$")
_OP_LINE_RE = re.compile(r"^([^\s:]+):([0-9a-fA-F]+):\t(.*)$")

_DEF_ANNOTATION_RE = re.compile(r"\((0x[0-9a-fA-F]+):[0-9a-fA-F]+\)")
_UNIQUE_TEMP_RE = re.compile(r"u0x[0-9a-fA-F]+")
_BLOCK_LABEL_RE = re.compile(r"Block_\d+:")


class OpRecord(object):
    """One parsed p-code op line: its own instruction address, the
    implementation-private "uniq" creation-order id (kept only for display,
    never compared), the raw operator text, and which basic block (by print
    order, 0-based) it appeared in."""

    __slots__ = ("addr", "uniq", "rest", "block")

    def __init__(self, addr, uniq, rest, block):
        self.addr = addr
        self.uniq = uniq
        self.rest = rest
        self.block = block


def parse_dump(text):
    """Parse a DumpSSA / decomp_dbg `print raw` text into a list of OpRecord,
    in original print order. Block header and implied-goto marker lines are
    consumed to track the current block index but do not produce OpRecords
    (the implied-goto marker has no "uniq", so it isn't directly comparable
    the same way; it is rare enough in practice to skip without losing much
    signal -- see README "Known limitations")."""
    records = []
    block = -1
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = _BLOCK_HEADER_RE.match(line)
        if m:
            block = int(m.group(1))
            continue
        if _IMPLIED_GOTO_RE.match(line):
            continue
        m = _OP_LINE_RE.match(line)
        if m:
            records.append(OpRecord(m.group(1), m.group(2), m.group(3), block))
    return records


def normalize_rest(rest, fuzzy=False):
    """Strip implementation-private numbering from an op's operator text so
    two independently-allocated SSA builds can be compared structurally:

      - varnode def-annotations "(<addr>:<uniq>)" keep the address (which is
        shared ground truth -- both sides decode the same bytes at the same
        base) but drop the per-implementation creation-order uniq: "(DEF)"
        becomes "(<addr>)". In --fuzzy mode the address is dropped too (see
        below).
      - unique-space temporary identifiers ("u0x...") are pure allocation
        artifacts (Gosleigh and the C++ core allocate unique-space ids in
        totally different orders/pools even for byte-identical semantics) --
        collapsed to a single "uTMP" placeholder.
      - structuring block index labels ("Block_10:0xADDR" in goto/switch
        targets) keep the target address but mask the RPO index, since the
        two implementations' block numbering can legitimately differ even
        when the underlying CFG structuring agrees.

    fuzzy=True additionally drops the address inside def-annotations
    entirely ("(DEF)" instead of "(<addr>)"). This is needed for one
    calibration finding (see README "Known limitations"): Gosleigh's
    ActionHeritage currently stamps a newly-created MULTIEQUAL (phi) op's own
    SeqNum address with the *defined varnode's storage address* (e.g. a
    stack offset) instead of the block's entry instruction address that the
    C++ core uses -- so every downstream reference to that phi output has a
    genuinely different, but not wrong, address on the two sides. Fuzzy mode
    trades away the ability to catch a wrong def *target* in exchange for not
    drowning every other real signal under that one known, narrow gap.
    """
    if fuzzy:
        rest = _DEF_ANNOTATION_RE.sub("(DEF)", rest)
    else:
        rest = _DEF_ANNOTATION_RE.sub(r"(\1)", rest)
    rest = _UNIQUE_TEMP_RE.sub("uTMP", rest)
    rest = _BLOCK_LABEL_RE.sub("Block_N:", rest)
    return rest


def _addr_key(addr):
    try:
        return int(addr, 16)
    except ValueError:
        return addr


def align(gosleigh_ops, cpp_ops):
    """Bucket both op lists by instruction address (the one field genuinely
    shared between the two implementations by construction: same bytes, same
    base -- see capture.py), then zip same-address buckets positionally.
    Returns a list of (gosleigh_op_or_None, cpp_op_or_None) pairs in
    address-sorted order; within a shared address, original relative order is
    preserved (multiple p-code ops per instruction)."""
    from collections import defaultdict

    g_by_addr = defaultdict(list)
    for op in gosleigh_ops:
        g_by_addr[op.addr].append(op)
    c_by_addr = defaultdict(list)
    for op in cpp_ops:
        c_by_addr[op.addr].append(op)

    all_addrs = sorted(set(g_by_addr) | set(c_by_addr), key=_addr_key)

    pairs = []
    for addr in all_addrs:
        gs = g_by_addr.get(addr, [])
        cs = c_by_addr.get(addr, [])
        for i in range(max(len(gs), len(cs))):
            pairs.append((gs[i] if i < len(gs) else None, cs[i] if i < len(cs) else None))
    return pairs


def run_gosleigh_dump(golden_path, func_name, sla, pspec, cspec, max_instructions):
    """Invoke `go run ./cmd/ssadump` and return its stdout (the DumpSSA text)."""
    cmd = [
        "go", "run", "./cmd/ssadump",
        "--golden", golden_path,
        "--func", func_name,
        "--sla", sla,
        "--pspec", pspec,
        "--cspec", cspec,
        "--max-instructions", str(max_instructions),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError("cmd/ssadump failed:\n%s\n%s" % (proc.stdout, proc.stderr))
    return proc.stdout


def get_cpp_dump(args):
    """Return the C++ core's raw p-code dump text, either from a
    pre-captured file (--cpp-raw-file) or by generating a savefile and
    driving decomp_dbg.exe live."""
    if args.cpp_raw_file:
        with open(args.cpp_raw_file, "r", encoding="utf-8") as f:
            return f.read()

    if not args.decomp_dbg:
        raise RuntimeError(
            "either --decomp-dbg (to run tools/decomp_dbg.exe live) or --cpp-raw-file "
            "(a pre-captured `print raw` dump) is required"
        )

    savefile_path = args.savefile
    tmp_savefile = None
    if not savefile_path:
        entry = capture.load_golden_entry(args.golden, args.func)
        if entry is None:
            raise RuntimeError("function %r not found in %s" % (args.func, args.golden))
        xml_text = capture.build_savefile(entry["name"], entry["bytes"])
        fd, tmp_savefile = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        with open(tmp_savefile, "w", encoding="utf-8") as f:
            f.write(xml_text)
        savefile_path = tmp_savefile

    try:
        _full, raw_section = run_cpp.run_print_raw(
            args.decomp_dbg, savefile_path, args.func, args.sleighhome
        )
        return raw_section
    finally:
        if tmp_savefile:
            try:
                os.remove(tmp_savefile)
            except OSError:
                pass


def render_side_by_side(pairs, width=60, fuzzy=False):
    """Render an aligned op-pair list as a two-column text report, marking
    each row MATCH / MISMATCH / GOSLEIGH-ONLY / CPP-ONLY."""
    lines = []
    header = "%-6s %-*s | %s" % ("", width, "GOSLEIGH", "CPP")
    lines.append(header)
    lines.append("-" * len(header))
    for g, c in pairs:
        g_text = "%s:%s: %s" % (g.addr, g.uniq, g.rest) if g else ""
        c_text = "%s:%s: %s" % (c.addr, c.uniq, c.rest) if c else ""
        if g is None:
            status = "GOSL-"
        elif c is None:
            status = "CPP--"
        elif normalize_rest(g.rest, fuzzy) == normalize_rest(c.rest, fuzzy):
            status = "MATCH"
        else:
            status = "DIFF!"
        g_display = g_text if len(g_text) <= width else g_text[: width - 3] + "..."
        lines.append("%-6s %-*s | %s" % (status, width, g_display, c_text))
    return "\n".join(lines)


def summarize(pairs, fuzzy=False):
    matched = mismatched = gosleigh_only = cpp_only = 0
    for g, c in pairs:
        if g is None:
            gosleigh_only += 1
        elif c is None:
            cpp_only += 1
        elif normalize_rest(g.rest, fuzzy) == normalize_rest(c.rest, fuzzy):
            matched += 1
        else:
            mismatched += 1
    total = len(pairs)
    rate = (100.0 * matched / total) if total else 0.0
    return {
        "total": total,
        "matched": matched,
        "mismatched": mismatched,
        "gosleigh_only": gosleigh_only,
        "cpp_only": cpp_only,
        "match_rate_pct": rate,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--golden", required=True, help="path to a GenGoldens-schema golden JSON file")
    ap.add_argument("--func", required=True, help="function name to compare")
    ap.add_argument("--sla", default="pkg/sla/testdata/x86-64-packed.sla")
    ap.add_argument("--pspec", default="testdata/sla/x86-64.pspec")
    ap.add_argument("--cspec", default="testdata/sla/x86-64-win.cspec")
    ap.add_argument("--max-instructions", type=int, default=200)
    ap.add_argument("--decomp-dbg", default="", help="path to tools/decomp_dbg.exe (main repo, absolute)")
    ap.add_argument("--savefile", default="", help="use this savefile XML instead of auto-generating one via capture.py")
    ap.add_argument("--sleighhome", default=os.environ.get("SLEIGHHOME", ""))
    ap.add_argument("--cpp-raw-file", default="", help="skip decomp_dbg entirely; read a pre-captured `print raw` dump from this file")
    ap.add_argument("--format", choices=["side-by-side", "unified"], default="side-by-side")
    ap.add_argument("--width", type=int, default=60, help="column width for --format side-by-side")
    ap.add_argument("--fuzzy", action="store_true", help="also drop def-annotation addresses (see normalize_rest doc)")
    args = ap.parse_args(argv)

    gosleigh_text = run_gosleigh_dump(args.golden, args.func, args.sla, args.pspec, args.cspec, args.max_instructions)
    cpp_text = get_cpp_dump(args)

    gosleigh_ops = parse_dump(gosleigh_text)
    cpp_ops = parse_dump(cpp_text)
    pairs = align(gosleigh_ops, cpp_ops)
    stats = summarize(pairs, fuzzy=args.fuzzy)

    if args.format == "side-by-side":
        print(render_side_by_side(pairs, width=args.width, fuzzy=args.fuzzy))
    else:
        for g, c in pairs:
            if g is None:
                print("+CPP  %s:%s: %s" % (c.addr, c.uniq, c.rest))
            elif c is None:
                print("+GOSL %s:%s: %s" % (g.addr, g.uniq, g.rest))
            elif normalize_rest(g.rest, args.fuzzy) == normalize_rest(c.rest, args.fuzzy):
                print(" MATCH %s: %s" % (g.addr, g.rest))
            else:
                print("!GOSL %s:%s: %s" % (g.addr, g.uniq, g.rest))
                print("!CPP  %s:%s: %s" % (c.addr, c.uniq, c.rest))

    print()
    print(
        "SSADIFF SUMMARY: %(matched)d/%(total)d matched (%(match_rate_pct).1f%%), "
        "%(mismatched)d mismatched, %(gosleigh_only)d gosleigh-only, %(cpp_only)d cpp-only"
        % stats
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
