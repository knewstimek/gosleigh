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

// tryMarkForLoop finishes the for-loop that BlockWhileDo.finalTransform set
// up before merging: the iterator (and initializer) must still be explicit,
// printed statements ending their blocks, and the iterator must read the loop
// variable. Otherwise the loop prints as a while-do.
// C++ parity: BlockWhileDo::finalizePrinting.
func tryMarkForLoop(data *Funcdata, wdo *BlockWhileDo) {
	if wdo.iterateOp == nil || wdo.loopDef == nil {
		return // For-loop printing not enabled
	}
	slot := wdo.iterateOp.Parent().OutRevIndex(0)
	iterateOp := forLoopTerminal(data, wdo.loopDef, slot) // Iterator statement must be explicit
	if iterateOp == nil || !testIterateForm(iterateOp, wdo.loopDef) {
		wdo.SetForLoop(nil, nil)
		return
	}
	initOp := wdo.initializeOp
	if initOp == nil { // Last chance initializer
		initOp, _ = whileDoFindInitializer(wdo.loopDef, wdo.loopDef.Parent(), slot)
	}
	if initOp != nil {
		initOp = forLoopTerminal(data, wdo.loopDef, 1-slot) // Initializer must be explicit
	}
	iterateOp.SetFlag(PcodeOpNonPrinting)
	if initOp != nil {
		initOp.SetFlag(PcodeOpNonPrinting)
	}
	wdo.SetForLoop(iterateOp, initOp)
}

// forLoopTerminal returns the statement that produces the loop variable along
// the given MULTIEQUAL slot, looking through a non-printed COPY, or nil when
// that statement is not explicit and printed or cannot become the last
// statement of its block. The move stays even when the loop is not printed
// as a for-loop in the end.
// C++ parity: BlockWhileDo::testTerminal.
func forLoopTerminal(data *Funcdata, loopDef *PcodeOp, slot int) *PcodeOp {
	if loopDef == nil || slot < 0 || slot >= loopDef.NumInput() {
		return nil
	}
	vn := loopDef.Input(slot)
	if !vn.IsWritten() {
		return nil
	}
	finalOp := vn.Def()
	resOp := finalOp
	if finalOp.Code() == CPUI_COPY && finalOp.NotPrinted() {
		vn = finalOp.Input(0)
		if !vn.IsWritten() {
			return nil
		}
		resOp = vn.Def()
		if &resOp.Parent().FlowBlock != loopDef.Parent().getIn(slot) {
			return nil
		}
	}
	if !vn.IsExplicit() || resOp.NotPrinted() {
		return nil
	}
	// finalOp must be the last op in the basic block (except for the branch)
	lastOp := finalOp.Parent().LastOp()
	if lastOp.IsBranch() {
		lastOp = lastOp.PreviousOp()
	}
	if !data.moveRespectingCover(finalOp, lastOp) {
		return nil
	}
	return resOp
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
			continue // truncate at explicit
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
