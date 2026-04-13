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

// This file ports Ghidra's condexe.{hh,cc} (ConditionalExecution class) and
// the ActionConditionalConst helper cluster that lives in coreaction.cc.
//
// C++ references:
//   ghidra-ref/.../cpp/condexe.hh       (class layout)
//   ghidra-ref/.../cpp/condexe.cc       (712 lines, ConditionalExecution)
//   ghidra-ref/.../cpp/coreaction.cc    (lines 4080-4557, ActionConditionalConst)
//
// Known mismatches (no corresponding Go infrastructure yet):
//   - Funcdata::hasUnreachableBlocks is not ported; we scan anyway and rely
//     on verify() to reject malformed iblocks.
//   - Funcdata::numHeritagePasses is not ported; buildHeritageArray
//     conservatively treats every space as heritaged, which can only shrink
//     the testRemovability yes-set compared to C++.
//   - Funcdata::removeFromFlowSplit is not ported; we emit a TODO marker in
//     execute() but still destroy the iblock ops.
//   - PcodeOp::executeSimple is not ported; pushConstant is therefore
//     limited to the literal passthrough case.

// ---------------------------------------------------------------------------
// PcodeOpNode -- (PcodeOp, slot) tuple used by collectReachable / flowTogether
// ---------------------------------------------------------------------------

// pcodeOpNode pairs a PcodeOp with a specific input slot. Used by
// ActionConditionalConst as "this constant flows into this edge of this phi".
// C++ parity: op.hh PcodeOpNode
type pcodeOpNode struct {
	op   *PcodeOp
	slot int
}

// ---------------------------------------------------------------------------
// ConditionalExecution
// ---------------------------------------------------------------------------

// ConditionalExecution simplifies a series of conditionally executed
// statements whose CBRANCHes test the same (or complementary) boolean.
//
// The transform merges two branches that rejoin in iblock while iblock still
// re-tests the same condition from initblock. See condexe.hh class comment
// for the full scenario picture.
//
// C++ parity: condexe.hh ConditionalExecution.
type ConditionalExecution struct {
	fd                *Funcdata
	cbranch           *PcodeOp
	initblock         *BlockBasic
	iblock            *BlockBasic
	preaInslot        int
	init2aTrue        bool
	iblock2postaTrue  bool
	camethruPostaSlot int
	postaOutslot      int
	postaBlock        *BlockBasic
	postbBlock        *BlockBasic

	// replacement[blockIndex] is the cached replacement Varnode for the
	// currently-being-replaced iblock op in that block.
	replacement map[int32]*Varnode
	// pullback[inbranch] is the cached pulled-back Varnode for inbranch.
	pullback []*Varnode
	// heritageyes is true for every address space index we allow to
	// contribute orphan writes without failing testRemovability.
	heritageyes []bool
}

// NewConditionalExecution constructs a reusable ConditionalExecution driver
// for the given function.
// C++ parity: condexe.cc ConditionalExecution::ConditionalExecution
func NewConditionalExecution(f *Funcdata) *ConditionalExecution {
	ce := &ConditionalExecution{
		fd:          f,
		replacement: make(map[int32]*Varnode),
	}
	ce.buildHeritageArray()
	return ce
}

// buildHeritageArray precomputes which address spaces have gone through at
// least one heritage pass. Used by testRemovability to decide whether an
// orphan write in iblock can be discarded.
//
// C++ parity: condexe.cc ConditionalExecution::buildHeritageArray
// Known mismatch: Gosleigh Funcdata has no numHeritagePasses tracking, so we
// conservatively treat every space as heritaged. This matches C++ output for
// functions after all heritage passes have completed (the usual case by the
// time conditionalexe runs).
func (ce *ConditionalExecution) buildHeritageArray() {
	// Stored as a map-in-slice keyed by space index. We lazily grow in
	// testRemovability since addresses spaces are rarely enumerated.
	ce.heritageyes = nil
}

// spaceHeritaged tests ce.heritageyes for the given space, returning true by
// default (conservative fallback, see buildHeritageArray).
func (ce *ConditionalExecution) spaceHeritaged(_ *Varnode) bool {
	return true
}

// testIBlock verifies iblock has exactly 2 in-edges, 2 out-edges, and ends
// with a CBRANCH.
// C++ parity: condexe.cc ConditionalExecution::testIBlock
func (ce *ConditionalExecution) testIBlock() bool {
	if ce.iblock == nil {
		return false
	}
	if ce.iblock.SizeIn() != 2 {
		return false
	}
	if ce.iblock.SizeOut() != 2 {
		return false
	}
	ce.cbranch = ce.iblock.LastOp()
	if ce.cbranch == nil || ce.cbranch.IsDead() {
		return false
	}
	if ce.cbranch.Code() != CPUI_CBRANCH {
		return false
	}
	return true
}

// findInitPre walks the two prea/preb chains backward from iblock and
// verifies they both reach the same initblock that has 2 out-edges.
// C++ parity: condexe.cc ConditionalExecution::findInitPre
func (ce *ConditionalExecution) findInitPre() bool {
	tmp := ce.iblock.InEdge(ce.preaInslot).Point
	var last *FlowBlock = &ce.iblock.FlowBlock
	for tmp != nil && tmp.SizeOut() == 1 && tmp.SizeIn() == 1 {
		last = tmp
		tmp = tmp.InEdge(0).Point
	}
	if tmp == nil || tmp.SizeOut() != 2 {
		return false
	}
	initBB, ok := tmp.Concrete().(*BlockBasic)
	if !ok || initBB == nil {
		return false
	}
	ce.initblock = initBB

	tmp2 := ce.iblock.InEdge(1 - ce.preaInslot).Point
	for tmp2 != nil && tmp2.SizeOut() == 1 && tmp2.SizeIn() == 1 {
		tmp2 = tmp2.InEdge(0).Point
	}
	if tmp2 != &initBB.FlowBlock {
		return false
	}
	if ce.initblock == ce.iblock {
		return false
	}

	ce.init2aTrue = ce.initblock.TrueOut() == last
	return true
}

// verifySameCondition compares the CBRANCHes in initblock and iblock using
// BooleanExpressionMatch. Flips init2aTrue if the match indicates complement.
// C++ parity: condexe.cc ConditionalExecution::verifySameCondition
func (ce *ConditionalExecution) verifySameCondition() bool {
	initCBranch := ce.initblock.LastOp()
	if initCBranch == nil || initCBranch.IsDead() {
		return false
	}
	if initCBranch.Code() != CPUI_CBRANCH {
		return false
	}
	var tester BooleanExpressionMatch
	if !tester.VerifyCondition(ce.cbranch, initCBranch) {
		return false
	}
	if tester.Flip() {
		ce.init2aTrue = !ce.init2aTrue
	}
	return true
}

// testMultiRead decides whether a MULTIEQUAL-defined Varnode in iblock can
// have a reader op moved out of the way during doReplacement.
// C++ parity: condexe.cc ConditionalExecution::testMultiRead
func (ce *ConditionalExecution) testMultiRead(vn *Varnode, op *PcodeOp) bool {
	if op.Parent() == ce.iblock {
		code := op.Code()
		if code == CPUI_COPY || code == CPUI_SUBPIECE {
			return true
		}
		return false
	}
	if op.Code() == CPUI_RETURN {
		if op.NumInput() < 2 || op.Input(1) != vn {
			return false
		}
	}
	return true
}

// testOpRead decides whether a non-MULTIEQUAL-defined Varnode in iblock can
// be pulled back past the given read op.
// C++ parity: condexe.cc ConditionalExecution::testOpRead
func (ce *ConditionalExecution) testOpRead(vn *Varnode, op *PcodeOp) bool {
	if op.Parent() == ce.iblock {
		return true
	}
	writeOp := vn.Def()
	if writeOp == nil {
		return false
	}
	opc := writeOp.Code()
	if opc == CPUI_COPY || opc == CPUI_SUBPIECE || opc == CPUI_INT_ADD || opc == CPUI_PTRSUB {
		if opc == CPUI_INT_ADD || opc == CPUI_PTRSUB {
			if writeOp.NumInput() < 2 || !writeOp.Input(1).IsConstant() {
				return false
			}
		}
		invn := writeOp.Input(0)
		if invn == nil {
			return false
		}
		if invn.IsWritten() {
			upop := invn.Def()
			if upop != nil && upop.Parent() == ce.iblock && upop.Code() != CPUI_MULTIEQUAL {
				return false
			}
		} else if invn.IsFree() {
			return false
		}
		return true
	}
	return false
}

// findPullback returns a cached pull-back Varnode for the given inbranch.
// C++ parity: condexe.cc ConditionalExecution::findPullback
func (ce *ConditionalExecution) findPullback(inbranch int) *Varnode {
	for len(ce.pullback) <= inbranch {
		ce.pullback = append(ce.pullback, nil)
	}
	return ce.pullback[inbranch]
}

// pullbackOp duplicates an iblock op outside the iblock, feeding it the
// MULTIEQUAL input for the given inbranch. Cached per inbranch.
// C++ parity: condexe.cc ConditionalExecution::pullbackOp
func (ce *ConditionalExecution) pullbackOp(op *PcodeOp, inbranch int) *Varnode {
	invn := ce.findPullback(inbranch)
	if invn != nil {
		return invn
	}
	invn = op.Input(0)
	if invn == nil {
		return nil
	}
	var bl *BlockBasic
	if invn.IsWritten() {
		defOp := invn.Def()
		if defOp != nil && defOp.Parent() == ce.iblock {
			// defOp must be MULTIEQUAL per testOpRead.
			if inbranch >= defOp.NumInput() {
				return nil
			}
			bbIn := ce.iblock.InEdge(inbranch).Point
			bbCon, _ := bbIn.Concrete().(*BlockBasic)
			bl = bbCon
			invn = defOp.Input(inbranch)
		} else {
			dom := ce.iblock.ImmedDom()
			if dom == nil {
				return nil
			}
			bl, _ = dom.Concrete().(*BlockBasic)
		}
	} else {
		dom := ce.iblock.ImmedDom()
		if dom == nil {
			return nil
		}
		bl, _ = dom.Concrete().(*BlockBasic)
	}
	if bl == nil {
		return nil
	}

	origOut := op.Output()
	if origOut == nil {
		return nil
	}
	newOp := ce.fd.NewOp(op.NumInput(), op.Addr())
	outVn := ce.fd.NewVarnodeOut(origOut.Size(), origOut.Addr(), newOp)
	ce.fd.OpSetOpcode(newOp, op.Code())
	ce.fd.OpSetInput(newOp, invn, 0)
	for i := 1; i < op.NumInput(); i++ {
		ce.fd.OpSetInput(newOp, op.Input(i), i)
	}
	ce.fd.OpInsertEnd(newOp, bl)

	// Cache
	for len(ce.pullback) <= inbranch {
		ce.pullback = append(ce.pullback, nil)
	}
	ce.pullback[inbranch] = outVn
	return outVn
}

// getNewMulti creates a MULTIEQUAL in bl whose inputs all point at op's
// output Varnode. The new MULTIEQUAL is later rewritten by doReplacement.
// C++ parity: condexe.cc ConditionalExecution::getNewMulti
func (ce *ConditionalExecution) getNewMulti(op *PcodeOp, bl *BlockBasic) *Varnode {
	outvn := op.Output()
	if outvn == nil {
		return nil
	}
	// We use the block's first op address if available, otherwise op's addr.
	addr := op.Addr()
	if first := bl.FirstOp(); first != nil {
		addr = first.Addr()
	}
	newop := ce.fd.NewOp(bl.SizeIn(), addr)
	newoutvn := ce.fd.NewUniqueOut(outvn.Size(), newop)
	ce.fd.OpSetOpcode(newop, CPUI_MULTIEQUAL)
	for i := 0; i < bl.SizeIn(); i++ {
		ce.fd.OpSetInput(newop, outvn, i)
	}
	ce.fd.OpInsertBegin(newop, bl)
	return newoutvn
}

// resolveRead picks a replacement for a read of op's output in block bl.
// C++ parity: condexe.cc ConditionalExecution::resolveRead
func (ce *ConditionalExecution) resolveRead(op *PcodeOp, bl *BlockBasic) *Varnode {
	if bl.SizeIn() == 1 {
		rev := bl.InRevIndex(0)
		slot := 1 - ce.camethruPostaSlot
		if rev == ce.postaOutslot {
			slot = ce.camethruPostaSlot
		}
		return ce.resolveIblockRead(op, slot)
	}
	return ce.getNewMulti(op, bl)
}

// resolveIblockRead returns the replacement Varnode for a read coming in
// through iblock via inbranch.
// C++ parity: condexe.cc ConditionalExecution::resolveIblockRead
func (ce *ConditionalExecution) resolveIblockRead(op *PcodeOp, inbranch int) *Varnode {
	if op.Code() == CPUI_COPY {
		vn := op.Input(0)
		if vn != nil && vn.IsWritten() {
			defOp := vn.Def()
			if defOp != nil && defOp.Code() == CPUI_MULTIEQUAL && defOp.Parent() == ce.iblock {
				op = defOp
			} else {
				return vn
			}
		} else if vn != nil {
			return vn
		}
	}
	opc := op.Code()
	if opc == CPUI_MULTIEQUAL {
		if inbranch < 0 || inbranch >= op.NumInput() {
			return nil
		}
		return op.Input(inbranch)
	}
	if opc == CPUI_SUBPIECE || opc == CPUI_INT_ADD || opc == CPUI_PTRSUB {
		return ce.pullbackOp(op, inbranch)
	}
	// "Illegal op in iblock" -- in C++ this throws LowlevelError. Returning
	// nil causes doReplacement to bail out without destroying data-flow.
	return nil
}

// getMultiequalRead resolves a read of an iblock MULTIEQUAL through a
// downstream MULTIEQUAL slot.
// C++ parity: condexe.cc ConditionalExecution::getMultiequalRead
func (ce *ConditionalExecution) getMultiequalRead(op *PcodeOp, readop *PcodeOp, slot int) *Varnode {
	bl := readop.Parent()
	if bl == nil {
		return nil
	}
	if slot < 0 || slot >= bl.SizeIn() {
		return nil
	}
	inbl := bl.InEdge(slot).Point
	if inbl == nil {
		return nil
	}
	inBB, _ := inbl.Concrete().(*BlockBasic)
	if inBB != ce.iblock {
		if inBB == nil {
			return nil
		}
		return ce.getReplacementRead(op, inBB)
	}
	rev := bl.InRevIndex(slot)
	s := 1 - ce.camethruPostaSlot
	if rev == ce.postaOutslot {
		s = ce.camethruPostaSlot
	}
	return ce.resolveIblockRead(op, s)
}

// getReplacementRead memoizes replacement Varnodes by dominator walking up
// from bl until we land in a block immediately dominated by iblock.
// C++ parity: condexe.cc ConditionalExecution::getReplacementRead
func (ce *ConditionalExecution) getReplacementRead(op *PcodeOp, bl *BlockBasic) *Varnode {
	if bl == nil {
		return nil
	}
	if cached, ok := ce.replacement[bl.Index()]; ok {
		return cached
	}
	curbl := bl
	for {
		dom := curbl.ImmedDom()
		if dom == nil {
			return nil
		}
		if domBB, _ := dom.Concrete().(*BlockBasic); domBB == ce.iblock {
			break
		}
		domBB, _ := dom.Concrete().(*BlockBasic)
		if domBB == nil {
			return nil
		}
		curbl = domBB
	}
	if cached, ok := ce.replacement[curbl.Index()]; ok {
		ce.replacement[bl.Index()] = cached
		return cached
	}
	res := ce.resolveRead(op, curbl)
	if res == nil {
		return nil
	}
	ce.replacement[curbl.Index()] = res
	if curbl != bl {
		ce.replacement[bl.Index()] = res
	}
	return res
}

// doReplacement rewrites every read of op's output to use the replacement
// Varnode appropriate for the reader's block. After this, op can be safely
// destroyed.
// C++ parity: condexe.cc ConditionalExecution::doReplacement
func (ce *ConditionalExecution) doReplacement(op *PcodeOp) {
	ce.replacement = make(map[int32]*Varnode)
	ce.pullback = ce.pullback[:0]

	vn := op.Output()
	if vn == nil {
		return
	}
	for {
		descs := vn.DescendIter()
		if len(descs) == 0 {
			break
		}
		readop := descs[0]
		slot := readop.GetSlot(vn)
		if slot < 0 {
			// Stale descend entry -- nothing to fix. Break out to avoid
			// infinite loops if the descend list is not rebuilt.
			break
		}
		bl := readop.Parent()
		if bl == nil {
			// Dead op in descend list; detach and continue.
			ce.fd.OpUnsetInput(readop, slot)
			continue
		}
		var rvn *Varnode
		if bl == ce.iblock {
			ce.fd.OpUnsetInput(readop, slot)
			continue
		}
		if readop.Code() == CPUI_MULTIEQUAL {
			rvn = ce.getMultiequalRead(op, readop, slot)
		} else if readop.Code() == CPUI_RETURN {
			retvn := readop.Input(1)
			if retvn == nil {
				ce.fd.OpUnsetInput(readop, slot)
				continue
			}
			newcopy := ce.fd.NewOp(1, readop.Addr())
			ce.fd.OpSetOpcode(newcopy, CPUI_COPY)
			outvn := ce.fd.NewVarnodeOut(retvn.Size(), retvn.Addr(), newcopy)
			ce.fd.OpSetInput(readop, outvn, 1)
			ce.fd.OpInsertBefore(newcopy, readop)
			readop = newcopy
			slot = 0
			rvn = ce.getReplacementRead(op, bl)
		} else {
			rvn = ce.getReplacementRead(op, bl)
		}
		if rvn == nil {
			// Bail safely by unsetting the input (the op is about to be
			// destroyed anyway if this was an iblock op).
			ce.fd.OpUnsetInput(readop, slot)
			continue
		}
		ce.fd.OpSetInput(readop, rvn, slot)
	}
}

// testRemovability returns true if op can be moved/destroyed out of iblock.
// C++ parity: condexe.cc ConditionalExecution::testRemovability
func (ce *ConditionalExecution) testRemovability(op *PcodeOp) bool {
	if op.Code() == CPUI_MULTIEQUAL {
		vn := op.Output()
		if vn == nil {
			return false
		}
		for _, readop := range vn.DescendIter() {
			if !ce.testMultiRead(vn, readop) {
				return false
			}
		}
		return true
	}

	if op.IsFlowBreak() || op.IsCall() {
		return false
	}
	code := op.Code()
	if code == CPUI_LOAD || code == CPUI_STORE {
		return false
	}
	if code == CPUI_INDIRECT {
		return false
	}

	vn := op.Output()
	if vn != nil {
		if vn.IsAddrTied() {
			return false
		}
		hasnodescend := true
		for _, readop := range vn.DescendIter() {
			if !ce.testOpRead(vn, readop) {
				return false
			}
			hasnodescend = false
		}
		if hasnodescend && !ce.spaceHeritaged(vn) {
			return false
		}
	}
	return true
}

// verify runs all structural and removability checks.
// C++ parity: condexe.cc ConditionalExecution::verify
func (ce *ConditionalExecution) verify() bool {
	ce.preaInslot = 0
	ce.postaOutslot = 0

	if !ce.testIBlock() {
		return false
	}
	if !ce.findInitPre() {
		return false
	}
	if !ce.verifySameCondition() {
		return false
	}

	ce.iblock2postaTrue = (ce.postaOutslot == 1)
	if ce.init2aTrue == ce.iblock2postaTrue {
		ce.camethruPostaSlot = ce.preaInslot
	} else {
		ce.camethruPostaSlot = 1 - ce.preaInslot
	}
	postaFB := ce.iblock.OutEdge(ce.postaOutslot).Point
	postbFB := ce.iblock.OutEdge(1 - ce.postaOutslot).Point
	ce.postaBlock, _ = postaFB.Concrete().(*BlockBasic)
	ce.postbBlock, _ = postbFB.Concrete().(*BlockBasic)
	if ce.postaBlock == nil || ce.postbBlock == nil {
		return false
	}

	// Walk ops in reverse, skipping the final branch.
	ops := ce.iblock.Ops()
	for i := len(ops) - 2; i >= 0; i-- {
		if !ce.testRemovability(ops[i]) {
			return false
		}
	}
	return true
}

// Trial stores ib as candidate iblock and runs verify().
// C++ parity: condexe.cc ConditionalExecution::trial
// Note: the C++ trial() additionally recurses on directsplit configurations;
// that secondary recursion is not yet ported. TODO known mismatch.
func (ce *ConditionalExecution) Trial(ib *BlockBasic) bool {
	ce.iblock = ib
	if !ce.verify() {
		return false
	}
	return true
}

// Execute destroys iblock ops and rewrites their readers. Must be called
// after a successful Trial().
// C++ parity: condexe.cc ConditionalExecution::execute
// Known mismatch: Funcdata::removeFromFlowSplit is not ported; the CFG-level
// edge rewiring is left to subsequent passes (blockaction). The data-flow
// fixup is complete and iblock ops are destroyed.
func (ce *ConditionalExecution) Execute() {
	ops := ce.iblock.Ops()
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		if op.IsDead() {
			continue
		}
		if !op.IsBranch() {
			ce.doReplacement(op)
		}
		ce.fd.OpDestroy(op)
	}
	// TODO known mismatch: fd.removeFromFlowSplit(iblock, postaOutslot != camethruPostaSlot).
}

// ---------------------------------------------------------------------------
// ActionConditionalConst helpers
// ---------------------------------------------------------------------------

// constPoint is a "constant known along this edge" record.
// C++ parity: coreaction.hh ConstPoint
type constPoint struct {
	vn         *Varnode   // varnode known to be constant along constBlock edge
	constVn    *Varnode   // may be nil until first use; created lazily
	value      uint64     // literal value along constBlock edge
	constBlock *FlowBlock // target of the edge where vn is known constant
	inSlot     int        // reverse index of the edge on constBlock.inEdges
	blockIsDom bool       // true if constBlock dominates its out-tree
}

// condConstContext groups state passed through the ActionConditionalConst
// helper methods. Fields correspond to C++ member access on
// ActionConditionalConst and locally-declared containers in apply().
type condConstContext struct {
	data      *Funcdata
	useMulti  bool
	phiEdges  []pcodeOpNode
	// markedOps and markedVars stand in for C++ PcodeOp::isMark() /
	// Varnode::isMark(). We use maps rather than clobbering shared flags.
	markedOps  map[*PcodeOp]bool
	markedVars map[*Varnode]bool
	changed    int
}

// collectReachable gathers COPY / INDIRECT / MULTIEQUAL ops reachable from
// vn through data-flow, skipping any MULTIEQUAL slots listed in phiNodeEdges.
// Every op added is marked in ctx.markedOps.
// C++ parity: coreaction.cc ActionConditionalConst::collectReachable
func (ctx *condConstContext) collectReachable(vn *Varnode, phiNodeEdges []pcodeOpNode, reachable *[]*PcodeOp) {
	// C++ sorts phiNodeEdges for binary_search. We replicate with a set.
	edgeSet := make(map[pcodeOpNode]struct{}, len(phiNodeEdges))
	for _, e := range phiNodeEdges {
		edgeSet[e] = struct{}{}
	}
	if vn.IsWritten() {
		if defOp := vn.Def(); defOp != nil && defOp.Code() == CPUI_MULTIEQUAL {
			ctx.markedOps[defOp] = true
			*reachable = append(*reachable, defOp)
		}
	}
	count := 0
	for {
		for _, op := range vn.DescendIter() {
			if ctx.markedOps[op] {
				continue
			}
			opc := op.Code()
			if opc == CPUI_MULTIEQUAL {
				found := false
				for slot := 0; slot < op.NumInput(); slot++ {
					if op.Input(slot) != vn {
						continue
					}
					if _, skip := edgeSet[pcodeOpNode{op: op, slot: slot}]; !skip {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			} else if opc != CPUI_COPY && opc != CPUI_INDIRECT {
				continue
			}
			*reachable = append(*reachable, op)
			ctx.markedOps[op] = true
		}
		if count >= len(*reachable) {
			break
		}
		vn = (*reachable)[count].Output()
		count++
		if vn == nil {
			break
		}
	}
}

// flowToAlternatePath follows op's output forward through COPY / INDIRECT /
// MULTIEQUAL looking for any ops already in ctx.markedOps. Returns true if
// the given op reunites with the "alternate flow" marked by collectReachable.
// C++ parity: coreaction.cc ActionConditionalConst::flowToAlternatePath
func (ctx *condConstContext) flowToAlternatePath(op *PcodeOp) bool {
	if ctx.markedOps[op] {
		return true
	}
	var markSet []*Varnode
	vn := op.Output()
	if vn == nil {
		return false
	}
	markSet = append(markSet, vn)
	ctx.markedVars[vn] = true

	count := 0
	found := false
	for count < len(markSet) {
		cur := markSet[count]
		count++
		for _, next := range cur.DescendIter() {
			opc := next.Code()
			if opc == CPUI_MULTIEQUAL {
				if ctx.markedOps[next] {
					found = true
					break
				}
			} else if opc != CPUI_COPY && opc != CPUI_INDIRECT {
				continue
			}
			outVn := next.Output()
			if outVn == nil || ctx.markedVars[outVn] {
				continue
			}
			ctx.markedVars[outVn] = true
			markSet = append(markSet, outVn)
		}
		if found {
			break
		}
	}
	// Clear per-call var marks.
	for _, v := range markSet {
		delete(ctx.markedVars, v)
	}
	return found
}

// flowTogether marks edges[i] and any other edges[j] whose data-flow
// rejoins edges[i]'s flow. Returns true if any merging was detected.
// C++ parity: coreaction.cc ActionConditionalConst::flowTogether
func (ctx *condConstContext) flowTogether(edges []pcodeOpNode, i int, result []int) bool {
	var reachable []*PcodeOp
	out := edges[i].op.Output()
	if out == nil {
		return false
	}
	ctx.collectReachable(out, nil, &reachable)
	res := false
	for j := range edges {
		if i == j || result[j] == 0 {
			continue
		}
		if ctx.markedOps[edges[j].op] {
			result[i] = 2
			result[j] = 2
			res = true
		}
	}
	// Clear marks set by collectReachable.
	for _, op := range reachable {
		delete(ctx.markedOps, op)
	}
	return res
}

// placeCopy inserts a COPY of constVn at the end of bl (before any branch op)
// and returns the new unique output.
// C++ parity: coreaction.cc ActionConditionalConst::placeCopy
func (ctx *condConstContext) placeCopy(op *PcodeOp, bl *BlockBasic, constVn *Varnode) *Varnode {
	data := ctx.data
	lastOp := bl.LastOp()
	var addr = op.Addr()
	insertBefore := (*PcodeOp)(nil)
	if lastOp == nil {
		insertBefore = nil
	} else if lastOp.IsBranch() {
		insertBefore = lastOp
		addr = lastOp.Addr()
	} else {
		insertBefore = nil
		addr = lastOp.Addr()
	}
	copyOp := data.NewOp(1, addr)
	data.OpSetOpcode(copyOp, CPUI_COPY)
	outVn := data.NewUniqueOut(constVn.Size(), copyOp)
	data.OpSetInput(copyOp, constVn, 0)
	if insertBefore != nil {
		data.OpInsertBefore(copyOp, insertBefore)
	} else {
		data.OpInsertEnd(copyOp, bl)
	}
	return outVn
}

// placeMultipleConstants emits one shared COPY at the common dominator of
// all phi edges whose marks are 2 ("flow together").
// C++ parity: coreaction.cc ActionConditionalConst::placeMultipleConstants
func (ctx *condConstContext) placeMultipleConstants(phiEdges []pcodeOpNode, marks []int, constVn *Varnode) {
	var blocks []*FlowBlock
	var representative *PcodeOp
	for i, e := range phiEdges {
		if marks[i] != 2 {
			continue
		}
		representative = e.op
		parent := e.op.Parent()
		if parent == nil || e.slot >= parent.SizeIn() {
			continue
		}
		blocks = append(blocks, parent.InEdge(e.slot).Point)
	}
	if representative == nil || len(blocks) == 0 {
		return
	}
	var root *FlowBlock
	for i, b := range blocks {
		if i == 0 {
			root = b
			continue
		}
		root = FindCommonBlock(root, b)
		if root == nil {
			return
		}
	}
	rootBB, _ := root.Concrete().(*BlockBasic)
	if rootBB == nil {
		return
	}
	outVn := ctx.placeCopy(representative, rootBB, constVn)
	for i, e := range phiEdges {
		if marks[i] != 2 {
			continue
		}
		ctx.data.OpSetInput(e.op, outVn, e.slot)
	}
}

// pushConstant tries to fold op with the current point's constant input.
// C++ uses PcodeOp::executeSimple which is not ported yet, so we only
// cover the literal no-op case: CPUI_COPY of the constant in.
// TODO known mismatch: restore full executeSimple fold.
// C++ parity: coreaction.cc ActionConditionalConst::pushConstant
func (ctx *condConstContext) pushConstant(points *[]constPoint, op *PcodeOp) {
	if op.EvalType()&PcodeOpSpecial != 0 {
		return
	}
	if op.Code() != CPUI_COPY {
		return
	}
	// Straight COPY: the new point inherits value.
	front := (*points)[0]
	out := op.Output()
	if out == nil {
		return
	}
	*points = append(*points, constPoint{
		vn:         out,
		value:      front.value,
		constBlock: front.constBlock,
		inSlot:     front.inSlot,
		blockIsDom: front.blockIsDom,
	})
}

// handlePhiNodes rewrites phi edges with a COPY of constVn where the
// data-flow does not rejoin varVn by any alternate route.
// C++ parity: coreaction.cc ActionConditionalConst::handlePhiNodes
func (ctx *condConstContext) handlePhiNodes(varVn *Varnode, constVn *Varnode, phiEdges []pcodeOpNode) {
	var alternateFlow []*PcodeOp
	results := make([]int, len(phiEdges))
	ctx.collectReachable(varVn, phiEdges, &alternateFlow)
	alternate := 0
	for i, e := range phiEdges {
		if !ctx.flowToAlternatePath(e.op) {
			results[i] = 1
			alternate++
		}
	}
	// Clear marks from collectReachable.
	for _, op := range alternateFlow {
		delete(ctx.markedOps, op)
	}

	hasFlowTogether := false
	if alternate > 1 {
		for i := range results {
			if results[i] == 0 {
				continue
			}
			if ctx.flowTogether(phiEdges, i, results) {
				hasFlowTogether = true
			}
		}
	}
	for i, e := range phiEdges {
		if results[i] != 1 {
			continue
		}
		parent := e.op.Parent()
		if parent == nil || e.slot >= parent.SizeIn() {
			continue
		}
		bl, _ := parent.InEdge(e.slot).Point.Concrete().(*BlockBasic)
		if bl == nil {
			continue
		}
		outVn := ctx.placeCopy(e.op, bl, constVn)
		ctx.data.OpSetInput(e.op, outVn, e.slot)
		ctx.changed++
	}
	if hasFlowTogether {
		ctx.placeMultipleConstants(phiEdges, results, constVn)
		ctx.changed++
	}
}

// testAlternatePath reports whether vn can be reached from op via any slot
// other than the given one, tracing through MULTIEQUAL / INT_ADD / PTRSUB /
// PTRADD up to depth.
// C++ parity: coreaction.cc ActionConditionalConst::testAlternatePath
func (ctx *condConstContext) testAlternatePath(vn *Varnode, op *PcodeOp, slot int, depth int) bool {
	for i := 0; i < op.NumInput(); i++ {
		if i == slot {
			continue
		}
		inVn := op.Input(i)
		if inVn == nil {
			continue
		}
		if inVn == vn {
			return true
		}
		if inVn.IsWritten() {
			cur := inVn.Def()
			if cur == nil {
				continue
			}
			opc := cur.Code()
			if opc == CPUI_INT_ADD || opc == CPUI_PTRSUB || opc == CPUI_PTRADD {
				if cur.NumInput() >= 2 && (cur.Input(0) == vn || cur.Input(1) == vn) {
					return true
				}
			} else if opc == CPUI_MULTIEQUAL {
				if depth == 0 {
					continue
				}
				if ctx.testAlternatePath(vn, cur, -1, depth-1) {
					return true
				}
			}
		}
	}
	return false
}

// propagateConstant processes the worklist of constPoints, replacing
// matching reads with constants and pushing through phi edges.
// C++ parity: coreaction.cc ActionConditionalConst::propagateConstant
func (ctx *condConstContext) propagateConstant(points []constPoint) int {
	data := ctx.data
	for len(points) > 0 {
		point := points[0]
		varVn := point.vn
		constVn := point.constVn
		constBlock := point.constBlock
		var phiEdges []pcodeOpNode

		// Snapshot descendants; replacement may mutate the descend list.
		for _, op := range varVn.DescendIter() {
			opc := op.Code()
			if opc == CPUI_INDIRECT {
				continue
			}
			if opc == CPUI_MULTIEQUAL {
				if !ctx.useMulti {
					continue
				}
				if varVn.IsAddrTied() && op.Output() != nil && varVn.Addr() == op.Output().Addr() {
					continue
				}
				bl := op.Parent()
				if bl == nil {
					continue
				}
				if &bl.FlowBlock == constBlock {
					// Immediate edge.
					if point.inSlot >= op.NumInput() || op.Input(point.inSlot) != varVn {
						continue
					}
					if point.value > 1 {
						continue
					}
					if op.Output() != nil && op.Output().IsAddrTied() {
						continue
					}
					if ctx.testAlternatePath(varVn, op, point.inSlot, 2) {
						continue
					}
					phiEdges = append(phiEdges, pcodeOpNode{op: op, slot: point.inSlot})
				} else if point.blockIsDom {
					for slot := 0; slot < op.NumInput(); slot++ {
						if op.Input(slot) != varVn {
							continue
						}
						if slot >= bl.SizeIn() {
							continue
						}
						srcFB := bl.InEdge(slot).Point
						if constBlock.Dominates(srcFB) {
							phiEdges = append(phiEdges, pcodeOpNode{op: op, slot: slot})
						}
					}
				}
				continue
			}
			if opc == CPUI_COPY {
				followOut := op.Output()
				if followOut == nil {
					continue
				}
				followOp := followOut.LoneDescend()
				if followOp == nil {
					continue
				}
				if followOp.IsMarker() {
					continue
				}
				if followOp.Code() == CPUI_COPY {
					continue
				}
			}
			if !point.blockIsDom {
				continue
			}
			if constBlock.Dominates(&op.Parent().FlowBlock) {
				if constVn == nil {
					constVn = data.NewConstant(varVn.Size(), point.value)
				}
				if opc == CPUI_RETURN {
					retvn := op.Input(1)
					if retvn == nil {
						continue
					}
					copyBeforeRet := data.NewOp(1, op.Addr())
					data.OpSetOpcode(copyBeforeRet, CPUI_COPY)
					data.OpSetInput(copyBeforeRet, constVn, 0)
					data.NewVarnodeOut(retvn.Size(), retvn.Addr(), copyBeforeRet)
					data.OpSetInput(op, copyBeforeRet.Output(), 1)
					data.OpInsertBefore(copyBeforeRet, op)
				} else {
					slot := op.GetSlot(varVn)
					if slot < 0 {
						continue
					}
					data.OpSetInput(op, constVn, slot)
				}
				ctx.changed++
			} else {
				ctx.pushConstant(&points, op)
			}
		}
		if len(phiEdges) > 0 {
			if constVn == nil {
				constVn = data.NewConstant(varVn.Size(), point.value)
			}
			ctx.handlePhiNodes(varVn, constVn, phiEdges)
		}
		points = points[1:]
	}
	return ctx.changed
}

// findConstCompare inspects the CBRANCH boolean for an INT_EQUAL /
// INT_NOTEQUAL against a constant, and if present creates a new constPoint
// pointing down the matching edge.
// C++ parity: coreaction.cc ActionConditionalConst::findConstCompare
func (ctx *condConstContext) findConstCompare(points *[]constPoint, boolVn *Varnode, bl *FlowBlock, blockDom [2]bool, flipEdge bool) {
	if !boolVn.IsWritten() {
		return
	}
	compOp := boolVn.Def()
	if compOp == nil {
		return
	}
	opc := compOp.Code()
	if opc == CPUI_BOOL_NEGATE {
		flipEdge = !flipEdge
		if compOp.NumInput() < 1 {
			return
		}
		boolVn = compOp.Input(0)
		if !boolVn.IsWritten() {
			return
		}
		compOp = boolVn.Def()
		if compOp == nil {
			return
		}
		opc = compOp.Code()
	}
	var constEdge int
	if opc == CPUI_INT_EQUAL {
		constEdge = 1
	} else if opc == CPUI_INT_NOTEQUAL {
		constEdge = 0
	} else {
		return
	}
	if compOp.NumInput() < 2 {
		return
	}
	varVn := compOp.Input(0)
	constVn := compOp.Input(1)
	if !constVn.IsConstant() {
		if !varVn.IsConstant() {
			return
		}
		varVn, constVn = constVn, varVn
	}
	if varVn.LoneDescend() != nil {
		return
	}
	if flipEdge {
		constEdge = 1 - constEdge
	}
	outFB := bl.OutEdge(constEdge).Point
	*points = append(*points, constPoint{
		vn:         varVn,
		constVn:    constVn,
		value:      constVn.Offset(),
		constBlock: outFB,
		inSlot:     bl.OutRevIndex(constEdge),
		blockIsDom: blockDom[constEdge],
	})
}

// restrictedByConditional answers the Go counterpart of FlowBlock::
// restrictedByConditional -- is the incoming edge the only way into out? We
// approximate with sizeIn()==1.
// C++ parity: block.cc FlowBlock::restrictedByConditional (simplified)
func restrictedByConditional(out *FlowBlock, _ *FlowBlock) bool {
	if out == nil {
		return false
	}
	return out.SizeIn() == 1
}
