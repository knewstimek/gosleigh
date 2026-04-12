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
				if isOpMoveableToLast(possibleIter, tail, lastOp) {
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

// isOpMoveableToLast reports whether op can be considered the "last" statement
// in its block (ignoring trailing BRANCH ops).
// C++ parity: PcodeOp::isMoveable(lastOp) -- simplified: true if op == lastOp
// or all ops between op and lastOp are branches or dead.
func isOpMoveableToLast(op *PcodeOp, bb *BlockBasic, lastOp *PcodeOp) bool {
	if op == lastOp {
		return true
	}
	ops := bb.Ops()
	opIdx := -1
	lastIdx := -1
	for i, o := range ops {
		if o == op {
			opIdx = i
		}
		if o == lastOp {
			lastIdx = i
		}
	}
	if opIdx < 0 || lastIdx < 0 || opIdx > lastIdx {
		return false
	}
	// All ops between opIdx+1 and lastIdx must be branches or dead.
	for i := opIdx + 1; i <= lastIdx; i++ {
		o := ops[i]
		if o == nil || o.IsDead() {
			continue
		}
		if o.IsBranch() {
			continue
		}
		return false
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
