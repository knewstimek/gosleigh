package pcode

// ActionForLoops converts BlockWhileDo blocks to for-loops where possible.
//
// Detection mirrors BlockWhileDo::finalTransform in block.cc:
//   - The loop body's tail basic-block has a last op (the iterate statement)
//     whose output feeds a MULTIEQUAL at the loop head that also flows into
//     the CBRANCH condition.
//   - A preceding block may supply the MULTIEQUAL's other input as the
//     initialize statement.
//
// C++ parity: BlockWhileDo::finalTransform (block.cc ~3356)
type ActionForLoops struct {
	ActionBase
}

// NewActionForLoops constructs an ActionForLoops in the given group.
func NewActionForLoops(group string) *ActionForLoops {
	a := &ActionForLoops{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "forloops", group)
	return a
}

// Clone implements Action.
func (a *ActionForLoops) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionForLoops(a.GetGroup())
}

// Apply walks every structured block recursively and attempts to convert
// BlockWhileDo nodes to for-loops.
//
// The structured graph's top-level blocks are accessed via BlockGraph.GetBlock(i)
// rather than FlowBlock.StructuredChildren() because the BlockGraph root itself
// is a container whose StructuredChildren are empty; the real top-level blocks
// live in BlockGraph.blocks (accessed via GetBlock).
//
// C++ parity: BlockWhileDo::finalTransform is called from the block graph
// traversal in Funcdata::finalizePrinting; here we do it explicitly.
func (a *ActionForLoops) Apply(data *Funcdata) int {
	graph := data.getStructure()
	if graph == nil || graph.GetSize() == 0 {
		return 0
	}
	// Walk top-level blocks in the structured graph.
	for i := 0; i < graph.GetSize(); i++ {
		applyForLoopsRecursive(data, graph.GetBlock(i))
	}
	return 0
}

// applyForLoopsRecursive walks the structured block tree and marks any
// BlockWhileDo that qualifies as a for-loop.
func applyForLoopsRecursive(data *Funcdata, bl *FlowBlock) {
	if bl == nil {
		return
	}
	if bl.Type() == BlockWhileDoType {
		if wdo, ok := bl.Concrete().(*BlockWhileDo); ok {
			tryMarkForLoop(data, wdo)
		}
	}
	// Recurse into structured children.
	for _, child := range bl.StructuredChildren() {
		applyForLoopsRecursive(data, child)
	}
}

// tryMarkForLoop tries to identify a for-loop structure within a BlockWhileDo.
//
// The pattern (C++ parity: BlockWhileDo::finalTransform / findLoopVariable):
//
//	children[0] = condition block (contains CBRANCH)
//	children[1] = body block (may itself be a list/graph)
//
// The tail basic-block of the body must have a last non-branch op whose
// output is the loop variable that feeds back into the condition via a
// MULTIEQUAL at the loop head.
//
// NOTE: structured children FlowBlock pointers may refer to "wrapper"
// BlockBasic instances whose ops slice is shared from the real BlockBasic
// that owns those ops. To obtain the authoritative *BlockBasic for parent
// comparisons we use op.Parent() (cbranch.Parent() for head, lastOp.Parent()
// for tail) rather than firstBasicBlock/lastBasicBlock.
//
// C++ parity: block.cc BlockWhileDo::finalTransform, findLoopVariable,
// findInitializer
func tryMarkForLoop(data *Funcdata, wdo *BlockWhileDo) {
	if wdo.HasOverflowSyntax() {
		return // overflow (while(true)) loops are not converted
	}
	children := wdo.StructuredChildren()
	if len(children) < 2 {
		return
	}
	condBl := children[0]
	bodyBl := children[1]

	// Locate the CBRANCH that guards the loop.
	// lastBasicBlock(condBl) returns a BlockBasic; we use its ops but trust
	// cbranch.Parent() as the authoritative head pointer.
	condBasic := lastBasicBlock(condBl)
	if condBasic == nil {
		return
	}
	cbranch := condBasic.LastOp()
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
		return
	}

	// The head block is the real BlockBasic that contains the CBRANCH.
	// Using cbranch.Parent() avoids the wrapper-BlockBasic pointer mismatch
	// that arises when structured children FlowBlocks share their ops slice
	// with the original BasicBlocks but have different *BlockBasic addresses.
	headBasic := cbranch.Parent()
	if headBasic == nil {
		return
	}

	// Locate the tail block: last basic-block in the body.
	// Same wrapper issue applies; use lastOp.Parent() as the authoritative pointer.
	tailWrapper := lastBasicBlock(bodyBl)
	if tailWrapper == nil {
		return
	}
	lastOp := lastNonBranchOp(tailWrapper)
	if lastOp == nil {
		return
	}
	tailBasic := lastOp.Parent()

	iterateOp, loopDef, tailSlot := findLoopVariable(cbranch, headBasic, tailBasic, lastOp)
	if iterateOp == nil {
		return
	}

	// testTerminal check: the varnode that loopDef reads from the tail slot must
	// be explicit. If it is implied (single-use temp), the iterate statement
	// cannot stand as a for-loop iterator clause.
	// C++ parity: BlockWhileDo::testTerminal (block.cc:3271)
	if tailSlot >= 0 && loopDef != nil {
		tailVn := loopDef.Input(tailSlot)
		if tailVn != nil && !tailVn.IsExplicit() {
			return
		}
	}

	// testIterateForm: the loop variable must appear as an input in the
	// iterator statement's input tree. If a pure cross-variable COPY got
	// through as the "iterator", this check rejects it and the while-do
	// stays a while-do. C++ parity: block.cc BlockWhileDo::testIterateForm
	// (~3287), invoked from finalizePrinting after all merging is done.
	if loopDef != nil && !testIterateForm(iterateOp, loopDef) {
		return
	}

	// Mark iterateOp as NonPrinting so emitOps skips it in the body.
	// C++ parity: Funcdata::opMarkNonPrinting(iterateOp)
	iterateOp.SetFlag(PcodeOpNonPrinting)

	// Try to find an initializer op in the block that flows into the loop head.
	// tailSlot is passed so findInitializerOp can compute entrySlot = 1 - tailSlot.
	// C++ parity: BlockWhileDo::findInitializer
	initOp := findInitializerOp(wdo, loopDef, headBasic, tailSlot)
	if initOp != nil {
		initOp.SetFlag(PcodeOpNonPrinting)
	}

	wdo.SetForLoop(iterateOp, initOp)
}

// testIterateForm verifies that the iterator statement's input tree reaches
// the loop variable HighVariable. Starts a depth-first walk from iterateOp;
// returns true if any reachable input varnode shares the HighVariable of
// loopDef.Output. Stops at annotations, explicit varnodes (no further walk),
// and unwritten inputs.
//
// C++ parity: block.cc BlockWhileDo::testIterateForm (~3287-3314).
func testIterateForm(iterateOp, loopDef *PcodeOp) bool {
	if iterateOp == nil || loopDef == nil {
		return false
	}
	targetVn := loopDef.Output()
	if targetVn == nil {
		return false
	}
	high := targetVn.High()
	if high == nil {
		return false
	}

	// Reject cross-variable COPY ops that are within-HV phi snapshots.
	//
	// In Gosleigh, when mergeAddrTied / snipReads inserts a COPY for a phi-input
	// varnode (e.g. "tmp = COPY(param_4)" where param_4 is already in the loop HV),
	// both the COPY input and the MULTIEQUAL output end up in the same HighVariable.
	// testIterateForm's DFS would find vn.High() == high on the very first step and
	// return true, incorrectly accepting this snapshot COPY as the iterator op.
	//
	// C++ avoids this via testTerminal (block.cc:3264): it checks finalOp->notPrinted()
	// (i.e. the COPY is a NonPrinting same-HV copy) and, when notPrinted, looks one
	// level deeper for the actual computation. Gosleigh's testTerminal is not yet fully
	// ported (it only checks isExplicit on the MULTIEQUAL slot input), so we add the
	// equivalent guard here: if iterateOp is a COPY whose input already belongs to the
	// loop variable HV, it is a within-HV snapshot and must be rejected.
	//
	// Exception: CountedLoop-style chains where iterateOp is a COPY with an input
	// from a DIFFERENT HV are still valid (the COPY bridges from a register temp to
	// the stack-backed loop variable). Those have inVn.High() != high and fall through
	// to the DFS walk below.
	if iterateOp.Code() == CPUI_COPY {
		inVn := iterateOp.Input(0)
		if inVn != nil && inVn.High() == high {
			// Input already in the loop HV: this is a within-HV phi snapshot COPY, not
			// a real loop update. Reject so the while-do stays a while-do.
			return false
		}
	}

	type frame struct {
		op   *PcodeOp
		slot int
	}
	// Path-like DFS; depth here is bounded by the number of implied (non-explicit)
	// defs in the chain. 16 is plenty and avoids pathological walks.
	path := make([]frame, 0, 16)
	path = append(path, frame{op: iterateOp, slot: 0})
	for len(path) > 0 {
		top := &path[len(path)-1]
		if top.slot >= top.op.NumInput() {
			path = path[:len(path)-1]
			continue
		}
		vn := top.op.Input(top.slot)
		top.slot++
		if vn == nil || vn.IsAnnotation() {
			continue
		}
		if vn.High() == high {
			return true
		}
		if vn.IsExplicit() {
			// C++ truncates at explicit. Go's ActionMergeCopy and
			// ActionMarkExplicit do not fully merge transient register
			// holders into the stack-storage HV the way C++ does, so a
			// legitimate iterator's chain (e.g. CountedLoop:
			//   unique = COPY(register) where register = INT_ADD(phi, 1))
			// dead-ends at the single-use register even though the INT_ADD
			// one step further has the loop variable as input. To recover
			// parity without rerunning MergeCopy, walk through explicit
			// varnodes only when they are single-use transient holders
			// (NumDescend == 1 and not addrTied). Multi-use and addrTied
			// explicit varnodes (e.g. gcd: register:0x4 used by both the
			// body-end COPY and INT_SREM) still truncate.
			if vn.NumDescend() > 1 || vn.IsAddrTied() {
				continue
			}
		}
		if !vn.IsWritten() {
			continue
		}
		defOp := vn.Def()
		if defOp == nil {
			continue
		}
		if len(path) >= cap(path) {
			continue // safety cap
		}
		path = append(path, frame{op: defOp, slot: 0})
	}
	return false
}

// findLoopVariable searches the tail block for an op whose output feeds back
// into the CBRANCH condition via a MULTIEQUAL at the head block.
//
// Unlike C++ which uses tail->getOutRevIndex(0) to find the MULTIEQUAL slot,
// we scan all MULTIEQUAL inputs because the structured-graph in-edge order
// may differ from the SSA phi slot order set during Heritage.
//
// Returns (iterateOp, loopDef MULTIEQUAL, tailSlot) or (nil, nil, -1).
// tailSlot is the MULTIEQUAL input slot from which the iterate op was found;
// findInitializerOp uses (1 - tailSlot) to find the entry/init slot.
//
// C++ parity: BlockWhileDo::findLoopVariable (block.cc ~3164)
func findLoopVariable(cbranch *PcodeOp, head, tail *BlockBasic, lastOp *PcodeOp) (*PcodeOp, *PcodeOp, int) {
	if cbranch.NumInput() < 2 {
		return nil, nil, -1
	}
	condVn := cbranch.Input(1)
	if condVn == nil || !condVn.IsWritten() {
		return nil, nil, -1
	}

	condDef := condVn.Def()

	// Breadth-limited search (depth 4 like C++) from cbranch condition upward.
	type frame struct {
		op   *PcodeOp
		slot int
	}
	stack := [4]frame{}
	stack[0] = frame{op: condDef, slot: 0}
	depth := 0

	for depth >= 0 {
		cur := &stack[depth]

		if cur.slot >= cur.op.NumInput() {
			depth--
			continue
		}
		inputVn := cur.op.Input(cur.slot)
		cur.slot++

		if inputVn == nil || !inputVn.IsWritten() {
			continue
		}
		defOp := inputVn.Def()

		// C++ parity: BlockWhileDo::finalTransform (block.cc:3356) runs inside
		// ActionStructureTransform, which precedes ActionSetCasts in the C++
		// action pipeline, so the def-chain findLoopVariable walks contains no
		// CPUI_CAST ops. Gosleigh runs ActionForLoops after ActionSetCasts (see
		// action.go), so an inserted CAST would otherwise consume one level of
		// this depth-4 breadth search that C++ never spent, hiding the loop-head
		// MULTIEQUAL (e.g. strlen_style's condition chain
		// LOAD -> CAST -> INT_ADD -> SEXT48 -> MULTIEQUAL is depth 5 with the
		// cast but depth 4 in C++'s pre-cast graph). A CPUI_CAST is a pure value
		// pass-through, so see through it to reproduce C++'s pre-cast reach.
		for defOp != nil && defOp.Code() == CPUI_CAST {
			castIn := defOp.Input(0)
			if castIn == nil || !castIn.IsWritten() {
				defOp = nil
				break
			}
			defOp = castIn.Def()
		}
		if defOp == nil {
			continue
		}

		if defOp.Code() == CPUI_MULTIEQUAL && defOp.Parent() == head {
			// Found a MULTIEQUAL at the head. Scan all its inputs for one
			// that is defined in the tail block.
			for s := 0; s < defOp.NumInput(); s++ {
				tailInputVn := defOp.Input(s)
				if tailInputVn == nil || !tailInputVn.IsWritten() {
					continue
				}
				possibleIter := tailInputVn.Def()
				if possibleIter.Parent() != tail {
					continue
				}
				if possibleIter.IsMarker() {
					continue
				}
				if isMoveable(possibleIter, lastOp) {
					return possibleIter, defOp, s
				}
			}
			continue // don't recurse into MULTIEQUAL inputs
		}

		if defOp.IsCall() || defOp.IsMarker() {
			continue
		}
		if depth >= 3 {
			continue // depth limit
		}
		depth++
		stack[depth] = frame{op: defOp, slot: 0}
	}
	return nil, nil, -1
}

// isMoveable reports whether op can be moved to occur immediately after point
// within the same basic block while preserving equivalent data flow. The order
// of operations may be rearranged as long as reads of op's output and any
// address-tied storage are not violated. This is a faithful port of the C++
// data-flow test, not the earlier "all intervening ops are branches" heuristic
// (which wrongly rejected e.g. the popcount iterator move past a non-conflicting
// counter increment).
//
// C++ parity: PcodeOp::isMoveable (op.cc:178).
func isMoveable(op, point *PcodeOp) bool {
	if op == point {
		return true // No movement necessary
	}
	movingLoad := false
	if op.EvalType() == PcodeOpSpecial {
		if op.Code() == CPUI_LOAD {
			movingLoad = true // Allow LOAD to be moved with additional restrictions
		} else {
			return false // Don't move special ops
		}
	}
	parent := op.Parent()
	if parent == nil || parent != point.Parent() {
		return false // Not in the same block
	}
	ops := parent.Ops()
	orderOf := func(target *PcodeOp) int {
		for i, o := range ops {
			if o == target {
				return i
			}
		}
		return -1
	}
	opIdx := orderOf(op)
	pointIdx := orderOf(point)
	if opIdx < 0 || pointIdx < 0 || opIdx > pointIdx {
		// The forward walk below assumes op precedes point; callers guarantee
		// this (point is the block's last non-branch op).
		return false
	}

	out := op.Output()
	if out != nil {
		// Output cannot be moved past an op that reads it: reject if any
		// same-block reader is ordered at or before point.
		for _, readOp := range out.DescendIter() {
			if readOp.Parent() != parent {
				continue
			}
			if orderOf(readOp) <= pointIdx {
				return false
			}
		}
	}

	// Only allow this op to be moved across a CALL in very restrictive
	// circumstances: a normal op whose inputs and output are not address tied.
	crossCalls := false
	if op.EvalType() != PcodeOpSpecial {
		if out != nil && !out.IsAddrTied() && !out.IsPersist() {
			i := 0
			for ; i < op.NumInput(); i++ {
				vn := op.Input(i)
				if vn != nil && (vn.IsAddrTied() || vn.IsPersist()) {
					break
				}
			}
			if i == op.NumInput() {
				crossCalls = true
			}
		}
	}

	var tiedList []*Varnode
	for i := 0; i < op.NumInput(); i++ {
		vn := op.Input(i)
		if vn != nil && vn.IsAddrTied() {
			tiedList = append(tiedList, vn)
		}
	}

	// Walk from the op immediately after op through point (inclusive),
	// rejecting any intervening op that conflicts with the move.
	for i := opIdx + 1; i <= pointIdx; i++ {
		cur := ops[i]
		if cur.EvalType() == PcodeOpSpecial {
			switch cur.Code() {
			case CPUI_LOAD:
				if out != nil && out.IsAddrTied() {
					return false
				}
			case CPUI_STORE:
				if movingLoad {
					return false
				}
				if len(tiedList) != 0 {
					return false
				}
				if out != nil && out.IsAddrTied() {
					return false
				}
			case CPUI_INDIRECT, CPUI_SEGMENTOP, CPUI_CPOOLREF:
				// Let thru; INDIRECTed storage is handled separately.
			case CPUI_CALL, CPUI_CALLIND, CPUI_NEW:
				if !crossCalls {
					return false
				}
			default:
				return false
			}
		}
		if curOut := cur.Output(); curOut != nil {
			if movingLoad && curOut.IsAddrTied() {
				return false
			}
			for _, vn := range tiedList {
				if vn.Overlap(curOut) >= 0 {
					return false
				}
				if curOut.Overlap(vn) >= 0 {
					return false
				}
			}
		}
	}
	return true
}

// findInitializerOp looks for an initializer op in the block that immediately
// precedes the while-do loop.
//
// headBasic must be the authoritative BlockBasic (cbranch.Parent()) with correct
// in-edge information. tailSlot is the MULTIEQUAL input slot from which the
// iterate op was found; the entry slot is computed as (1 - tailSlot).
//
// C++ parity: BlockWhileDo::findInitializer (block.cc ~3223)
// C++ signature: findInitializer(BlockBasic *head, int4 slot)
// where slot is the tail slot; entry slot = 1 - slot.
func findInitializerOp(wdo *BlockWhileDo, loopDef *PcodeOp, headBasic *BlockBasic, tailSlot int) *PcodeOp {
	if loopDef == nil || headBasic == nil {
		return nil
	}
	if headBasic.FlowBlock.SizeIn() != 2 {
		return nil // need exactly entry + back-edge
	}
	if tailSlot < 0 || loopDef.NumInput() != 2 {
		return nil // only handle 2-input MULTIEQUAL like C++
	}

	// C++ parity: slot = 1 - slot (flip tail slot to get entry slot)
	entrySlot := 1 - tailSlot

	initVn := loopDef.Input(entrySlot)
	if initVn == nil || !initVn.IsWritten() {
		return nil
	}
	initOp := initVn.Def()
	if initOp.IsMarker() {
		return nil
	}
	initBlock := initOp.Parent()
	if initBlock == nil {
		return nil
	}

	// C++ parity: if (initialBlock != head->getIn(slot)) return null
	// head->getIn(entrySlot) is the predecessor block at in-edge entrySlot.
	if entrySlot >= headBasic.FlowBlock.SizeIn() {
		return nil
	}
	expectedPred := headBasic.FlowBlock.InEdge(entrySlot).Point
	if expectedPred == nil || &initBlock.FlowBlock != expectedPred {
		return nil
	}

	// C++ parity: if (initialBlock->sizeOut() != 1) return null
	// Initializer block must flow only into the loop head.
	if initBlock.FlowBlock.SizeOut() != 1 {
		return nil
	}
	return initOp
}

// lastBasicBlock finds the last (deepest rightmost) basic block in a
// potentially nested structured block.
// C++ parity: getBlock(1)->lastOp()->getParent() in BlockWhileDo::finalTransform
func lastBasicBlock(bl *FlowBlock) *BlockBasic {
	if bl == nil {
		return nil
	}
	if bb := toBasic(bl); bb != nil {
		return bb
	}
	// Try the last structured child recursively.
	children := bl.StructuredChildren()
	for i := len(children) - 1; i >= 0; i-- {
		if bb := lastBasicBlock(children[i]); bb != nil {
			return bb
		}
	}
	return nil
}

// firstBasicBlock finds the first basic block in a potentially nested structured block.
// C++ parity: getFrontLeaf()->subBlock(0)
func firstBasicBlock(bl *FlowBlock) *BlockBasic {
	if bl == nil {
		return nil
	}
	if bb := toBasic(bl); bb != nil {
		return bb
	}
	children := bl.StructuredChildren()
	for _, child := range children {
		if bb := firstBasicBlock(child); bb != nil {
			return bb
		}
	}
	return nil
}

// lastNonBranchOp returns the last op in bb that is not a BRANCH/CBRANCH.
// C++ parity: "if (lastOp->isBranch()) lastOp = lastOp->previousOp()"
func lastNonBranchOp(bb *BlockBasic) *PcodeOp {
	ops := bb.Ops()
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		if op == nil || op.IsDead() {
			continue
		}
		if op.IsBranch() {
			continue
		}
		return op
	}
	return nil
}
