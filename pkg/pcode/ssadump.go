// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import (
	"fmt"
	"sort"
	"strings"

	"gosleigh/pkg/address"
)

// DumpSSA renders the final SSA p-code of fd in the same textual convention as
// C++ Ghidra's console `print raw` command, so a Gosleigh dump can be diffed
// op-by-op against a tools/decomp_dbg.exe capture. See tools/ssadiff/ for the
// comparison harness that consumes this output.
//
// C++ parity: funcdata.cc Funcdata::printRaw (line 209) -> block.cc
// BlockGraph::printRaw (1300) -> BlockBasic::printHeader/printRaw (2665/2672) ->
// op.hh PcodeOp::printRaw (243, forwards to TypeOp::printRaw) -> typeop.cc
// per-opcode TypeOpXxx::printRaw overrides, and varnode.cc Varnode::printRaw
// (741) / printRawNoMarkup (711).
//
// This is a diagnostic dump, not a decompiler-parity code path: it is not
// exercised by any production decompile flow and does not need to be
// byte-identical to the C++ text. Known, deliberate simplifications vs. the
// C++ original (documented at each helper below and in tools/ssadiff/README.md):
//   - Register-name resolution is an exact "space:offset:size" map lookup
//     (Engine.RegisterNamesByLocation), not the C++ prefix/overlap search that
//     also resolves partial-register reads (e.g. AL inside EAX) to the
//     containing register name with a nonzero remainder offset.
//   - Basic block start/stop "header" addresses are approximated from the
//     block's first/last op address, not the C++ BlockBasic start/stop range
//     (which can extend past the last op to the end of its machine
//     instruction).
//   - AddrSpace shortcut characters are approximated (const='#', unique='u',
//     stack='s', else first letter of the space name lowercased) since Go's
//     address.Space does not carry the .sla-declared shortcut char.
//   - Only the per-opcode print forms actually observed in the project's
//     debug captures (tools/captures/*.txt) or read directly from
//     ghidra-ref typeop.cc are special-cased below (arithmetic/logical/
//     comparison binary and unary ops, CAST, LOAD/STORE, BRANCH/CBRANCH/
//     BRANCHIND, CALL, RETURN, MULTIEQUAL, INDIRECT, COPY, and the
//     size-suffixed ZEXT/SEXT/PIECE/SUBPIECE names). Anything else
//     (CALLOTHER, PTRADD/PTRSUB, NEW, POPCOUNT/LZCOUNT, SEGMENT, ...) falls
//     back to a generic "OUT = OPCODE(in0,in1,...)" functional form using the
//     canonical CPUI opcode name -- still comparable op-by-op, just not
//     textually identical to whatever custom form the C++ side prints.
func DumpSSA(fd *Funcdata, regNames map[string]string) string {
	if fd == nil {
		return ""
	}
	ctx := &ssaDumpContext{regNames: regNames, defaultSize: ssaDefaultSize(fd)}

	graph := fd.Graph()
	if graph == nil || graph.GetSize() == 0 {
		return ctx.dumpRawOpList(fd)
	}
	return ctx.dumpBlockGraph(graph)
}

// ssaDumpContext carries the formatting inputs (register-name map, default
// varnode size) through the dump so per-op/per-varnode helpers stay free
// functions of a receiver rather than threading two extra parameters
// everywhere.
type ssaDumpContext struct {
	regNames    map[string]string
	defaultSize int32
}

// ssaDefaultSize approximates C++ Translate::getDefaultSize() -- the
// architecture's default value size (used as Varnode::printRawNoMarkup's
// "expect" size for any varnode that isn't a resolved register) -- from the
// address size of fd's own (code/ram) space. This is the space
// fd.BaseAddr() lives in, which is always available post-Build and avoids
// needing a separate Translate/Engine handle here.
func ssaDefaultSize(fd *Funcdata) int32 {
	sp := fd.BaseAddr().Space
	if sp == nil || sp.AddrSize == 0 {
		return 4
	}
	return int32(sp.AddrSize)
}

// dumpRawOpList mirrors the Funcdata::printRaw fallback path taken when no
// basic blocks have been built yet (bblocks.getSize()==0): a flat "Raw
// operations:" listing of every op in the op bank, ordered by (address,
// creation time) to approximate the PcodeOpTree's SeqNum ordering. Not
// expected to be exercised once a full decompile has run (Decompile always
// leaves fd.Graph() populated), kept only for completeness/robustness.
func (ctx *ssaDumpContext) dumpRawOpList(fd *Funcdata) string {
	ops := fd.GetPcodeOpBank().AllOps()
	if len(ops) == 0 {
		return "Raw operations: \n"
	}
	sort.Slice(ops, func(i, j int) bool {
		ai, aj := ops[i].Addr(), ops[j].Addr()
		if ai.Offset != aj.Offset {
			return ai.Offset < aj.Offset
		}
		return ops[i].Seq().Time < ops[j].Seq().Time
	})
	var sb strings.Builder
	sb.WriteString("Raw operations: \n")
	for _, op := range ops {
		sb.WriteString(ctx.opPrefix(op))
		sb.WriteString(ctx.opBody(op))
		sb.WriteString("\n")
	}
	return sb.String()
}

// dumpBlockGraph mirrors BlockGraph::printRaw (block.cc:1300): print each
// basic block in graph order, inserting a bracketed implied-goto line
// (BlockBasic::printRawImpliedGoto, block.cc:2688) between two blocks that
// are adjacent in print order but not connected by a fallthrough edge.
func (ctx *ssaDumpContext) dumpBlockGraph(graph *BlockGraph) string {
	var sb strings.Builder
	n := graph.GetSize()
	for i := 0; i < n; i++ {
		bb := asBasic(graph.GetBlock(i))
		if bb == nil {
			continue
		}
		sb.WriteString(ctx.blockHeader(bb))
		sb.WriteString("\n")
		for _, op := range bb.Ops() {
			sb.WriteString(ctx.opPrefix(op))
			sb.WriteString(ctx.opBody(op))
			sb.WriteString("\n")
		}
		if i+1 < n {
			next := asBasic(graph.GetBlock(i + 1))
			if line := ctx.impliedGoto(bb, next); line != "" {
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
	}
	return sb.String()
}

// blockHeader mirrors BlockBasic::printHeader (block.cc:2665): "Basic Block
// <index> <start>-<stop>". start/stop are approximated from the block's
// first/last op address (see DumpSSA doc comment).
func (ctx *ssaDumpContext) blockHeader(bb *BlockBasic) string {
	first, last := bb.FirstOp(), bb.LastOp()
	if first == nil || last == nil {
		return fmt.Sprintf("Basic Block %d <empty>", bb.Index())
	}
	return fmt.Sprintf("Basic Block %d %s-%s",
		bb.Index(), ctx.formatAddr(first.Addr()), ctx.formatAddr(last.Addr()))
}

// impliedGoto mirrors BlockBasic::printRawImpliedGoto (block.cc:2688): when
// a block falls out of print order into a non-adjacent block without an
// explicit branch op, print a bracketed "[ goto Block_N:addr ]" marker using
// the block's own stop address.
func (ctx *ssaDumpContext) impliedGoto(bb, next *BlockBasic) string {
	if bb.FlowBlock.SizeOut() != 1 {
		return ""
	}
	target := bb.FlowBlock.OutEdge(0).Point
	if next != nil && target == &next.FlowBlock {
		return "" // falls through to the next printed block; no marker needed
	}
	if last := bb.LastOp(); last != nil && last.IsBranch() {
		return "" // block already ends in an explicit branch op
	}
	stop := bb.LastOp()
	stopAddr := "?"
	if stop != nil {
		stopAddr = ctx.formatAddr(stop.Addr())
	}
	return fmt.Sprintf("%s:   \t[ goto %s ]", stopAddr, ctx.blockShortHeader(target))
}

// blockShortHeader mirrors FlowBlock::printShortHeader (block.cc:643):
// "Block_<index>:<start-addr>".
func (ctx *ssaDumpContext) blockShortHeader(b *FlowBlock) string {
	bb := asBasic(b)
	if bb == nil {
		return fmt.Sprintf("Block_%d", b.Index())
	}
	first := bb.FirstOp()
	if first == nil {
		return fmt.Sprintf("Block_%d", bb.Index())
	}
	return fmt.Sprintf("Block_%d:%s", bb.Index(), ctx.formatAddr(first.Addr()))
}

// opPrefix mirrors the "<seqnum>:\t" label BlockBasic::printRaw (and the
// Funcdata::printRaw fallback) prints before every op: SeqNum's own
// operator<< (address.cc:32) prints "<addr>:<uniq-hex>", and the caller
// appends a further ":\t".
func (ctx *ssaDumpContext) opPrefix(op *PcodeOp) string {
	return fmt.Sprintf("%s:%x:\t", ctx.formatAddr(op.Addr()), op.Seq().Time)
}

// formatAddr mirrors Address::printRaw (address.hh:336), which forwards to
// AddrSpace::printRaw(offset) with no space-name/shortcut prefix.
func (ctx *ssaDumpContext) formatAddr(a address.Address) string {
	return ctx.formatSpaceOffset(a.Space, a.Offset)
}

// formatSpaceOffset mirrors the generic AddrSpace::printRaw(ostream&,uintb)
// (space.cc:206): "0x" + zero-padded hex, where the padding width is the
// space's address size in bytes (halved to 4 or 6 bytes when the high bits
// of the offset are zero, so 64-bit code addresses that fit in 32 or 48
// bits print without a wall of leading zeros).
func (ctx *ssaDumpContext) formatSpaceOffset(sp *address.Space, offset uint64) string {
	sz := 4
	if sp != nil && sp.AddrSize != 0 {
		sz = int(sp.AddrSize)
	}
	if sz > 4 {
		if offset>>32 == 0 {
			sz = 4
		} else if offset>>48 == 0 {
			sz = 6
		}
	}
	return fmt.Sprintf("0x%0*x", 2*sz, offset)
}

// spaceShortcut approximates the .sla-declared per-space shortcut character
// used by Varnode::printRawNoMarkup (varnode.cc:711) when a varnode's
// location isn't a named register. Go's address.Space has no Shortcut field,
// so this is a best-effort convention: '#' for constant and 'u' for unique
// match Ghidra's universal convention; other spaces fall back to the first
// letter of the space name (documented simplification, see DumpSSA doc).
func spaceShortcut(sp *address.Space) byte {
	if sp == nil {
		return '?'
	}
	switch sp.Kind {
	case address.SpaceKindConstant:
		return '#'
	case address.SpaceKindUnique:
		return 'u'
	case address.SpaceKindStack:
		return 's'
	}
	if len(sp.Name) > 0 {
		c := sp.Name[0]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		return c
	}
	return '?'
}

// varnodeToken mirrors Varnode::printRaw (varnode.cc:741) and
// printRawNoMarkup (varnode.cc:711): a register name (or shortcut+offset)
// identifier, followed by a ":<size>" suffix when the size differs from the
// "expected" size for that identifier, an "(i)" marker for input varnodes,
// and a "(<def-addr>:<def-uniq-hex>)" marker for varnodes with a defining op.
func (ctx *ssaDumpContext) varnodeToken(vn *Varnode) string {
	if vn == nil {
		return "<null>"
	}
	sp := vn.Space()

	var base string
	var expect int32
	if sp != nil && sp.Kind == address.SpaceKindConstant {
		// ConstantSpace::printRaw (space.cc:372): plain unpadded hex, no
		// zero-fill -- constants aren't addresses.
		base = fmt.Sprintf("#0x%x", vn.Offset())
		expect = ctx.defaultSize
	} else if name, ok := ctx.registerName(vn); ok {
		base = name
		expect = vn.Size() // exact map hit: key already encodes size (see doc comment)
	} else {
		base = fmt.Sprintf("%c%s", spaceShortcut(sp), ctx.formatSpaceOffset(sp, vn.Offset()))
		expect = ctx.defaultSize
	}

	var sb strings.Builder
	sb.WriteString(base)
	if vn.Size() != expect {
		fmt.Fprintf(&sb, ":%d", vn.Size())
	}
	if vn.IsInput() {
		sb.WriteString("(i)")
	}
	if vn.IsWritten() {
		def := vn.Def()
		fmt.Fprintf(&sb, "(%s:%x)", ctx.formatAddr(def.Addr()), def.Seq().Time)
	}
	return sb.String()
}

// registerName looks up vn's register name via the "spaceIdx:offset:size"
// convention shared with PrintC.SetRegisterNames (printc.go) /
// Engine.RegisterNamesByLocation (sla/engine.go).
func (ctx *ssaDumpContext) registerName(vn *Varnode) (string, bool) {
	if len(ctx.regNames) == 0 || vn.Space() == nil {
		return "", false
	}
	key := fmt.Sprintf("%d:%d:%d", vn.Space().Index, vn.Offset(), vn.Size())
	name, ok := ctx.regNames[key]
	return name, ok
}

// ---------------------------------------------------------------------------
// Per-opcode raw forms -- C++ parity: typeop.cc TypeOpXxx::printRaw overrides.
// ---------------------------------------------------------------------------

// binaryInfixSymbol maps an opcode to its infix operator token for the
// TypeOpBinary::printRaw form "out = in0 <sym> in1" (typeop.cc:336).
// CPUI_INT_SRIGHT is deliberately excluded: it has its own printRaw override
// (typeop.cc:1577) using the literal token " s>> " instead of getOperatorName.
var binaryInfixSymbol = map[OpCode]string{
	CPUI_INT_EQUAL:       "==",
	CPUI_INT_NOTEQUAL:    "!=",
	CPUI_INT_SLESS:       "<",
	CPUI_INT_SLESSEQUAL:  "<=",
	CPUI_INT_LESS:        "<",
	CPUI_INT_LESSEQUAL:   "<=",
	CPUI_INT_ADD:         "+",
	CPUI_INT_SUB:         "-",
	CPUI_INT_XOR:         "^",
	CPUI_INT_AND:         "&",
	CPUI_INT_OR:          "|",
	CPUI_INT_LEFT:        "<<",
	CPUI_INT_RIGHT:       ">>",
	CPUI_INT_MULT:        "*",
	CPUI_INT_DIV:         "/",
	CPUI_INT_SDIV:        "/",
	CPUI_INT_REM:         "%",
	CPUI_INT_SREM:        "%",
	CPUI_BOOL_XOR:        "^^",
	CPUI_BOOL_AND:        "&&",
	CPUI_BOOL_OR:         "||",
	CPUI_FLOAT_EQUAL:     "==",
	CPUI_FLOAT_NOTEQUAL:  "!=",
	CPUI_FLOAT_LESS:      "<",
	CPUI_FLOAT_LESSEQUAL: "<=",
	CPUI_FLOAT_ADD:       "+",
	CPUI_FLOAT_SUB:       "-",
	CPUI_FLOAT_MULT:      "*",
	CPUI_FLOAT_DIV:       "/",
}

// unaryPrefixSymbol maps an opcode to its prefix token for the
// TypeOpUnary::printRaw form "out = <sym> in0" (typeop.cc:358). CPUI_CAST is
// included here: TypeOpUnary-shaped output ("out = (cast) in0") matches the
// literal token measured in tools/captures/op_switch_cpp_measured.txt.
var unaryPrefixSymbol = map[OpCode]string{
	CPUI_INT_2COMP:   "-",
	CPUI_INT_NEGATE:  "~",
	CPUI_BOOL_NEGATE: "!",
	CPUI_FLOAT_NEG:   "-",
	CPUI_CAST:        "(cast)",
}

// opBody renders the operator-specific part of a raw op line (everything
// after the "<seqnum>:\t" prefix from opPrefix). Dispatches by opcode,
// falling back to a generic functional form for anything not specially
// handled (see the DumpSSA doc comment for the exact coverage list).
func (ctx *ssaDumpContext) opBody(op *PcodeOp) string {
	code := op.Code()

	if sym, ok := binaryInfixSymbol[code]; ok && op.NumInput() == 2 {
		return fmt.Sprintf("%s = %s %s %s",
			ctx.varnodeToken(op.Output()), ctx.varnodeToken(op.Input(0)), sym, ctx.varnodeToken(op.Input(1)))
	}
	if code == CPUI_INT_SRIGHT && op.NumInput() == 2 {
		return fmt.Sprintf("%s = %s s>> %s",
			ctx.varnodeToken(op.Output()), ctx.varnodeToken(op.Input(0)), ctx.varnodeToken(op.Input(1)))
	}
	if sym, ok := unaryPrefixSymbol[code]; ok && op.NumInput() == 1 {
		return fmt.Sprintf("%s = %s %s", ctx.varnodeToken(op.Output()), sym, ctx.varnodeToken(op.Input(0)))
	}

	switch code {
	case CPUI_COPY:
		// TypeOpCopy::printRaw (typeop.cc:426): no operator token at all.
		return fmt.Sprintf("%s = %s", ctx.varnodeToken(op.Output()), ctx.varnodeToken(op.Input(0)))

	case CPUI_INT_ZEXT, CPUI_INT_SEXT:
		// typeop.cc:1124/1150: name + insize + outsize, e.g. "ZEXT14".
		name := code.String()[len("INT_"):] // "ZEXT" / "SEXT"
		return ctx.funcForm(op, fmt.Sprintf("%s%d%d", name, op.Input(0).Size(), op.Output().Size()))

	case CPUI_PIECE:
		// typeop.cc:2050: name + in0size + in1size.
		return ctx.funcForm(op, fmt.Sprintf("PIECE%d%d", op.Input(0).Size(), op.Input(1).Size()))

	case CPUI_SUBPIECE:
		// typeop.cc:2129: name + in0size + outsize, e.g. "SUB41".
		return ctx.funcForm(op, fmt.Sprintf("SUB%d%d", op.Input(0).Size(), op.Output().Size()))

	case CPUI_LOAD:
		// TypeOpLoad::printRaw (typeop.cc:503): "out = *(spacename,in1)".
		spc := ctx.constSpaceName(op.Input(0))
		return fmt.Sprintf("%s = *(%s,%s)", ctx.varnodeToken(op.Output()), spc, ctx.varnodeToken(op.Input(1)))

	case CPUI_STORE:
		// TypeOpStore::printRaw (typeop.cc:574): "*(spacename,in1) = in2".
		spc := ctx.constSpaceName(op.Input(0))
		return fmt.Sprintf("*(%s,%s) = %s", spc, ctx.varnodeToken(op.Input(1)), ctx.varnodeToken(op.Input(2)))

	case CPUI_BRANCH:
		return "goto " + ctx.branchTarget(op)

	case CPUI_CBRANCH:
		return ctx.cbranchForm(op)

	case CPUI_BRANCHIND:
		// TypeOpBranchind::printRaw (typeop.cc:655): "switch in0".
		return "switch " + ctx.varnodeToken(op.Input(0))

	case CPUI_CALL, CPUI_CALLIND:
		return ctx.callForm(op)

	case CPUI_RETURN:
		return ctx.returnForm(op)

	case CPUI_MULTIEQUAL:
		return ctx.multiequalForm(op)

	case CPUI_INDIRECT:
		return ctx.indirectForm(op)
	}

	// Generic fallback: TypeOpFunc::printRaw shape (typeop.cc:378) using the
	// canonical CPUI opcode name. Not textually identical to whatever custom
	// getOperatorName/printRaw the C++ side uses for these rarer opcodes
	// (CALLOTHER, PTRADD/PTRSUB, NEW, POPCOUNT/LZCOUNT, SEGMENT, ...), but
	// still comparable op-by-op (see DumpSSA doc comment).
	return ctx.funcForm(op, code.String())
}

// funcForm renders the TypeOpFunc::printRaw shape (typeop.cc:378):
// "[out = ]name(in0,in1,...)".
func (ctx *ssaDumpContext) funcForm(op *PcodeOp, name string) string {
	var sb strings.Builder
	if out := op.Output(); out != nil {
		sb.WriteString(ctx.varnodeToken(out))
		sb.WriteString(" = ")
	}
	sb.WriteString(name)
	sb.WriteString("(")
	for i := 0; i < op.NumInput(); i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(ctx.varnodeToken(op.Input(i)))
	}
	sb.WriteString(")")
	return sb.String()
}

// constSpaceName resolves the AddrSpace named by a LOAD/STORE's first input
// (a constant encoding the space id -- op.getIn(0)->getSpaceFromConst() in
// C++). Gosleigh's LOAD/STORE first input is the space's own constant
// varnode; its Space() field IS that addressed space per the Go pcode model.
func (ctx *ssaDumpContext) constSpaceName(spaceVn *Varnode) string {
	if spaceVn == nil {
		return "?"
	}
	if sp := spaceVn.Space(); sp != nil {
		return sp.Name
	}
	return "?"
}

// branchTarget mirrors TypeOpBranch::printRaw (typeop.cc:592): the parent
// block's sole out-edge target (short header) if unambiguous, else the raw
// input-0 varnode (an indirect/relative code-address encoding).
func (ctx *ssaDumpContext) branchTarget(op *PcodeOp) string {
	if parent := op.Parent(); parent != nil && parent.FlowBlock.SizeOut() == 1 {
		return ctx.blockShortHeader(parent.FlowBlock.OutEdge(0).Point)
	}
	if op.NumInput() > 0 {
		return ctx.varnodeToken(op.Input(0))
	}
	return "?"
}

// cbranchForm mirrors TypeOpCbranch::printRaw (typeop.cc:623):
// "goto <trueOut|in0> if (in1 [==|!=] 0)[ else <falseOut>]".
func (ctx *ssaDumpContext) cbranchForm(op *PcodeOp) string {
	var sb strings.Builder
	sb.WriteString("goto ")

	var falseOut *FlowBlock
	if parent := op.Parent(); parent != nil && parent.FlowBlock.SizeOut() == 2 {
		sb.WriteString(ctx.blockShortHeader(parent.FlowBlock.TrueOut()))
		falseOut = parent.FlowBlock.FalseOut()
	} else if op.NumInput() > 0 {
		sb.WriteString(ctx.varnodeToken(op.Input(0)))
	}

	sb.WriteString(" if (")
	if op.NumInput() > 1 {
		sb.WriteString(ctx.varnodeToken(op.Input(1)))
	}
	if op.HasFlag(PcodeOpBooleanFlip) {
		sb.WriteString(" == 0)")
	} else {
		sb.WriteString(" != 0)")
	}
	if falseOut != nil {
		sb.WriteString(" else ")
		sb.WriteString(ctx.blockShortHeader(falseOut))
	}
	return sb.String()
}

// callForm mirrors TypeOpCall::printRaw (typeop.cc:669):
// "[out = ]call in0(in1,in2,...)".
func (ctx *ssaDumpContext) callForm(op *PcodeOp) string {
	var sb strings.Builder
	if out := op.Output(); out != nil {
		sb.WriteString(ctx.varnodeToken(out))
		sb.WriteString(" = ")
	}
	sb.WriteString("call ")
	if op.NumInput() > 0 {
		sb.WriteString(ctx.varnodeToken(op.Input(0)))
	}
	if op.NumInput() > 1 {
		sb.WriteString("(")
		for i := 1; i < op.NumInput(); i++ {
			if i > 1 {
				sb.WriteString(",")
			}
			sb.WriteString(ctx.varnodeToken(op.Input(i)))
		}
		sb.WriteString(")")
	}
	return sb.String()
}

// returnForm mirrors TypeOpReturn::printRaw (typeop.cc:884):
// "return(in0) [in1,in2,...]".
func (ctx *ssaDumpContext) returnForm(op *PcodeOp) string {
	var sb strings.Builder
	sb.WriteString("return")
	if op.NumInput() >= 1 {
		sb.WriteString("(")
		sb.WriteString(ctx.varnodeToken(op.Input(0)))
		sb.WriteString(")")
	}
	if op.NumInput() > 1 {
		sb.WriteString(" ")
		for i := 1; i < op.NumInput(); i++ {
			if i > 1 {
				sb.WriteString(",")
			}
			sb.WriteString(ctx.varnodeToken(op.Input(i)))
		}
	}
	return sb.String()
}

// multiequalForm mirrors TypeOpMulti::printRaw (typeop.cc:1969): a phi node
// prints as "out = in0 ? in1 ? in2 ..." -- no opcode name, just "?" joiners.
func (ctx *ssaDumpContext) multiequalForm(op *PcodeOp) string {
	var sb strings.Builder
	sb.WriteString(ctx.varnodeToken(op.Output()))
	sb.WriteString(" = ")
	if op.NumInput() > 0 {
		sb.WriteString(ctx.varnodeToken(op.Input(0)))
	}
	if op.NumInput() == 1 {
		sb.WriteString(" ?") // rare single-input MULTIEQUAL edge case
	}
	for i := 1; i < op.NumInput(); i++ {
		sb.WriteString(" ? ")
		sb.WriteString(ctx.varnodeToken(op.Input(i)))
	}
	return sb.String()
}

// indirectForm mirrors TypeOpIndirect::printRaw (typeop.cc:2024):
// "out = [create] in1" for an indirect-creation marker, else
// "out = in0 [] in1" (the literal "[]" is CPUI_INDIRECT's TypeOp name --
// C++ doesn't override getOperatorName for it either).
func (ctx *ssaDumpContext) indirectForm(op *PcodeOp) string {
	out := ctx.varnodeToken(op.Output())
	if op.IsIndirectCreation() {
		if op.NumInput() > 1 {
			return fmt.Sprintf("%s = [create] %s", out, ctx.varnodeToken(op.Input(1)))
		}
		return fmt.Sprintf("%s = [create]", out)
	}
	if op.NumInput() > 1 {
		return fmt.Sprintf("%s = %s [] %s", out, ctx.varnodeToken(op.Input(0)), ctx.varnodeToken(op.Input(1)))
	}
	if op.NumInput() > 0 {
		return fmt.Sprintf("%s = %s []", out, ctx.varnodeToken(op.Input(0)))
	}
	return out + " = []"
}
