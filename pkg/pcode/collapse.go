package pcode

import (
	"fmt"
	"sort"
	"sync"
)

type FloatingEdge struct {
	top    *FlowBlock
	bottom *FlowBlock
}

func NewFloatingEdge(top, bottom *FlowBlock) FloatingEdge {
	return FloatingEdge{top: top, bottom: bottom}
}

func (e *FloatingEdge) GetTop() *FlowBlock {
	return e.top
}

func (e *FloatingEdge) GetBottom() *FlowBlock {
	return e.bottom
}

func (e *FloatingEdge) GetCurrentEdge(graph *FlowBlock) (*FlowBlock, int) {
	if e.top == nil || e.bottom == nil {
		return nil, -1
	}
	for e.top.Parent() != graph && e.top.Parent() != nil {
		e.top = e.top.Parent()
	}
	for e.bottom.Parent() != graph && e.bottom.Parent() != nil {
		e.bottom = e.bottom.Parent()
	}
	outedge := e.top.GetOutIndex(e.bottom)
	if outedge < 0 {
		return nil, -1
	}
	return e.top, outedge
}

type blockStructInfo struct {
	children       []*FlowBlock
	gotoEdge       int
	gotoTarget     *FlowBlock
	gotoType       uint32
	overflowSyntax bool
}

var blockStructState = struct {
	sync.Mutex
	byBlock map[*FlowBlock]*blockStructInfo
}{
	byBlock: make(map[*FlowBlock]*blockStructInfo),
}

func getBlockStructInfo(bl *FlowBlock) *blockStructInfo {
	blockStructState.Lock()
	defer blockStructState.Unlock()
	info := blockStructState.byBlock[bl]
	if info == nil {
		info = &blockStructInfo{gotoEdge: -1}
		blockStructState.byBlock[bl] = info
	}
	return info
}

func (b *FlowBlock) StructuredChildren() []*FlowBlock {
	info := getBlockStructInfo(b)
	res := make([]*FlowBlock, len(info.children))
	copy(res, info.children)
	return res
}

func (b *FlowBlock) setStructuredChildren(children []*FlowBlock) {
	info := getBlockStructInfo(b)
	info.children = append(info.children[:0], children...)
}

func (b *FlowBlock) GotoEdgeIndex() int {
	return getBlockStructInfo(b).gotoEdge
}

func (b *FlowBlock) setGotoEdgeIndex(idx int) {
	getBlockStructInfo(b).gotoEdge = idx
}

// GotoTargetBlock returns the stored goto target for a BlockGoto/BlockIf-goto
// whose goto edge was removed from the structure graph, or nil.
// C++ parity: BlockGoto::getGotoTarget / BlockIf::getGotoTarget.
func (b *FlowBlock) GotoTargetBlock() *FlowBlock {
	return getBlockStructInfo(b).gotoTarget
}

func (b *FlowBlock) setGotoTargetBlock(tgt *FlowBlock) {
	getBlockStructInfo(b).gotoTarget = tgt
}

// GotoType returns the unstructured-branch flavor of a BlockGoto/BlockIf-goto:
// one of BlockFlagGotoGoto (plain goto), BlockFlagBreakGoto (break;) or
// BlockFlagContinueGoto (continue;). Assigned by scopeBreak.
// C++ parity: BlockGoto::getGotoType / BlockIf::getGotoType.
func (b *FlowBlock) GotoType() uint32 {
	return getBlockStructInfo(b).gotoType
}

func (b *FlowBlock) setGotoType(t uint32) {
	getBlockStructInfo(b).gotoType = t
}

func (b *FlowBlock) HasOverflowSyntax() bool {
	return getBlockStructInfo(b).overflowSyntax
}

func (b *FlowBlock) setOverflowSyntax(val bool) {
	getBlockStructInfo(b).overflowSyntax = val
}

func (b *FlowBlock) getIn(i int) *FlowBlock {
	return b.InEdge(i).Point
}

func (b *FlowBlock) getOut(i int) *FlowBlock {
	return b.OutEdge(i).Point
}

func (b *FlowBlock) isMark() bool {
	return b.HasFlag(BlockFlagMark)
}

func (b *FlowBlock) setMark() {
	b.SetFlag(BlockFlagMark)
}

func (b *FlowBlock) clearMark() {
	b.ClearFlag(BlockFlagMark)
}

func (b *FlowBlock) isGotoIn(i int) bool {
	return b.IsGotoIn(i)
}

func (b *FlowBlock) isGotoOut(i int) bool {
	return b.IsGotoOut(i)
}

func (b *FlowBlock) isBackEdgeIn(i int) bool {
	return b.InEdge(i).Label&EdgeFlagBack != 0
}

func (b *FlowBlock) isBackEdgeOut(i int) bool {
	return b.OutEdge(i).Label&EdgeFlagBack != 0
}

func (b *FlowBlock) isLoopIn(i int) bool {
	return b.IsLoopIn(i)
}

func (b *FlowBlock) isLoopOut(i int) bool {
	return b.IsLoopOut(i)
}

func (b *FlowBlock) isLoopExitOut(i int) bool {
	return b.OutEdge(i).Label&EdgeFlagLoopExit != 0
}

func (b *FlowBlock) setLoopExit(i int) {
	b.SetOutEdgeFlag(i, EdgeFlagLoopExit)
}

func (b *FlowBlock) clearLoopExit(i int) {
	b.ClearOutEdgeFlag(i, EdgeFlagLoopExit)
}

func (b *FlowBlock) setGotoBranch(i int) {
	b.SetOutEdgeFlag(i, EdgeFlagGoto)
	b.SetFlag(BlockFlagGotoGoto)
	if i >= 0 && i < b.SizeOut() {
		tgt := b.getOut(i)
		tgt.SetFlag(BlockFlagUnstructuredTarg)
		if tgt.Parent() == b.Parent() {
			b.SetFlag(BlockFlagInteriorGotoOut)
			tgt.SetFlag(BlockFlagInteriorGotoIn)
		}
	}
}

func (b *FlowBlock) isDecisionOut(i int) bool {
	if i < 0 || i >= b.SizeOut() {
		return false
	}
	if b.isGotoOut(i) {
		return false
	}
	if b.isBackEdgeOut(i) || b.isLoopOut(i) || b.isLoopExitOut(i) {
		return false
	}
	return true
}

func (b *FlowBlock) isLoopDAGOut(i int) bool {
	if i < 0 || i >= b.SizeOut() {
		return false
	}
	if b.isGotoOut(i) {
		return false
	}
	if b.isBackEdgeOut(i) || b.isLoopOut(i) || b.isLoopExitOut(i) {
		return false
	}
	return true
}

func (b *FlowBlock) isLoopDAGIn(i int) bool {
	if i < 0 || i >= b.SizeIn() {
		return false
	}
	if b.isGotoIn(i) {
		return false
	}
	if b.isBackEdgeIn(i) || b.isLoopIn(i) {
		return false
	}
	return true
}

func (b *FlowBlock) isSwitchOut() bool {
	return b.HasFlag(BlockFlagSwitchOut) || b.Type() == BlockSwitchType || b.Type() == BlockMultiGotoType
}

func (b *FlowBlock) isInteriorGotoTarget() bool {
	if b.HasFlag(BlockFlagInteriorGotoIn) {
		return true
	}
	for i := 0; i < b.SizeIn(); i++ {
		if b.isGotoIn(i) {
			return true
		}
	}
	return false
}

// isComplex reports whether this block is too complex to be emitted as a single
// conditional clause. The base FlowBlock is always complex; only leaf blocks and
// boolean-condition chains can be simple. C++ parity:
//   - FlowBlock::isComplex (block.hh:250)      -> true
//   - BlockBasic::isComplex (block.cc:2388)    -> statement count
//   - BlockCopy::isComplex (block.hh:536)      -> copy->isComplex()
//   - BlockCondition::isComplex (block.hh:635) -> getBlock(0)->isComplex()
// In Gosleigh the structure-graph leaf is a *BlockBasic carrying srcDelegate, so
// the BlockCopy case is folded into the *BlockBasic branch.
func (b *FlowBlock) isComplex() bool {
	switch b.Concrete().(type) {
	case *BlockBasic:
		// KNOWN GAP: BlockBasic::isComplex faithfully counts statements, but at
		// CollapseStructure time Gosleigh's basic blocks still carry ops that Ghidra
		// has already removed via ActionDeadCode / marked implied via
		// ActionMarkImplied (Gosleigh defers that cleanup to print time). Counting
		// those inflates the statement total and wrongly forces overflow syntax on
		// simple loops. Until the pre-structure SSA state is faithful, a leaf block
		// is treated as non-complex (matching prior behavior).
		return false
	case *BlockCondition:
		// BlockCondition::isComplex -> getBlock(0)->isComplex().
		children := b.StructuredChildren()
		if len(children) > 0 {
			return children[0].isComplex()
		}
		return true
	default:
		return true
	}
}

func (b *FlowBlock) preferComplement(*Funcdata) bool {
	return false
}

func (b *FlowBlock) negateCondition(top bool) bool {
	if bb, ok := b.Concrete().(*BlockBasic); ok {
		bb.NegateCondition(top)
		return true
	}
	if bc, ok := b.Concrete().(*BlockCondition); ok {
		// C++ parity: BlockCondition::negateCondition (block.cc:3023).
		// Distribute the NOT to both children, flip the boolean opcode, then flip
		// the order of this block's outgoing edges via FlowBlock::negateCondition.
		children := b.StructuredChildren()
		res1, res2 := false, false
		if len(children) > 0 {
			res1 = children[0].negateCondition(false)
		}
		if len(children) > 1 {
			res2 = children[1].negateCondition(false)
		}
		if bc.opc == CPUI_BOOL_AND {
			bc.opc = CPUI_BOOL_OR
		} else {
			bc.opc = CPUI_BOOL_AND
		}
		// FlowBlock::negateCondition(top): swap outgoing edges only at top/bottom.
		if top && b.SizeOut() == 2 {
			b.SwapEdges()
		}
		return res1 || res2
	}
	for _, child := range b.StructuredChildren() {
		if child.negateCondition(top) {
			return true
		}
	}
	return false
}

// BlockWhileDo is a while-do structured loop block.
// When iterateOp is non-nil the block prints as a for-loop.
// C++ parity: block.hh BlockWhileDo -- iterateOp / initializeOp fields
type BlockWhileDo struct {
	FlowBlock
	// iterateOp is the increment op extracted from the loop tail.
	// When non-nil the block renders as "for(init; cond; iter)".
	// C++ parity: BlockWhileDo::iterateOp
	iterateOp *PcodeOp
	// initializeOp is the initializer op extracted from the block preceding the loop.
	// May be nil (produces "for(; cond; iter)").
	// C++ parity: BlockWhileDo::initializeOp
	initializeOp *PcodeOp
}

// SetOverflowSyntax marks this while-do as requiring overflow (while(true)) syntax.
func (b *BlockWhileDo) SetOverflowSyntax() {
	b.FlowBlock.SetFlag(BlockFlagWhileDoOverflow)
	b.FlowBlock.setOverflowSyntax(true)
}

// IterateOp returns the for-loop increment op, or nil for a plain while loop.
// C++ parity: BlockWhileDo::getIterateOp
func (b *BlockWhileDo) IterateOp() *PcodeOp { return b.iterateOp }

// InitializeOp returns the for-loop initializer op, or nil if absent.
// C++ parity: BlockWhileDo::getInitializeOp
func (b *BlockWhileDo) InitializeOp() *PcodeOp { return b.initializeOp }

// SetForLoop sets the iterate and initialize ops, converting this block to a for-loop.
// C++ parity: BlockWhileDo::finalTransform sets iterateOp / initializeOp
func (b *BlockWhileDo) SetForLoop(iterateOp, initializeOp *PcodeOp) {
	b.iterateOp = iterateOp
	b.initializeOp = initializeOp
}

// BlockCondition is a compound short-circuit condition: two conditional
// sub-blocks glued together with a boolean AND/OR. The opc field carries the
// boolean operation, used both to render "&&"/"||" and to flip under negation.
// C++ parity: block.hh BlockCondition -- OpCode opc, getOpcode, negateCondition.
type BlockCondition struct {
	FlowBlock
	// opc is the boolean operation. newBlockCondition seeds it with the INTEGER
	// opcode (CPUI_INT_AND/OR); negateCondition normalizes it to the BOOLEAN
	// opcode (CPUI_BOOL_AND/OR), which is what the emitter tests to choose the
	// "&&"/"||" joiner. A never-negated condition therefore renders as "||",
	// matching PrintC::emitBlockCondition's getOpcode()==CPUI_BOOL_AND test.
	// C++ parity: BlockCondition::opc
	opc OpCode
}

// Opcode returns the boolean operation of the condition block.
// C++ parity: BlockCondition::getOpcode
func (b *BlockCondition) Opcode() OpCode { return b.opc }

type edgeRecord struct {
	other *FlowBlock
	node  *FlowBlock
	label uint32
}

func collapseEdgeLabel(label uint32) uint32 {
	return label & (EdgeFlagGoto | EdgeFlagLoop | EdgeFlagDefaultSwitch | EdgeFlagIrreducible | EdgeFlagLoopExit)
}

func newStructuredFlowBlock(tp BlockType) *FlowBlock {
	switch tp {
	case BlockWhileDoType:
		bl := &BlockWhileDo{}
		bl.FlowBlock.SetType(tp)
		bl.FlowBlock.SetConcrete(bl)
		return &bl.FlowBlock
	case BlockConditionType:
		bl := &BlockCondition{}
		bl.FlowBlock.SetType(tp)
		bl.FlowBlock.SetConcrete(bl)
		return &bl.FlowBlock
	default:
		bl := &FlowBlock{}
		bl.SetType(tp)
		bl.SetConcrete(bl)
		return bl
	}
}

func collectRegionSet(nodes []*FlowBlock) map[*FlowBlock]struct{} {
	res := make(map[*FlowBlock]struct{}, len(nodes))
	for _, node := range nodes {
		res[node] = struct{}{}
	}
	return res
}

func (bg *BlockGraph) collapseRegion(nodes []*FlowBlock, tp BlockType) *FlowBlock {
	if len(nodes) == 0 {
		return nil
	}
	region := collectRegionSet(nodes)
	newBlock := newStructuredFlowBlock(tp)
	newBlock.SetParent(&bg.FlowBlock)
	newBlock.setStructuredChildren(nodes)
	if tp == BlockSwitchType || tp == BlockMultiGotoType {
		newBlock.SetFlag(BlockFlagSwitchOut)
	}

	// Collect incoming edges from outside the region. These will be redirected
	// to newBlock in-place (preserving outEdge position in the source block).
	// C++ parity: BlockGraph::replaceNode -- in-place target replacement so that
	// the source block's TrueOut/FalseOut ordering is not disturbed.
	incomingRaw := make([]edgeRecord, 0, 4)
	outgoingRaw := make([]edgeRecord, 0, 4)
	for _, node := range nodes {
		for i := 0; i < node.SizeIn(); i++ {
			src := node.getIn(i)
			if _, ok := region[src]; ok {
				continue
			}
			incomingRaw = append(incomingRaw, edgeRecord{other: src, node: node, label: collapseEdgeLabel(node.InEdge(i).Label)})
		}
		for i := 0; i < node.SizeOut(); i++ {
			dst := node.getOut(i)
			if _, ok := region[dst]; ok {
				continue
			}
			outgoingRaw = append(outgoingRaw, edgeRecord{other: dst, node: node, label: collapseEdgeLabel(node.OutEdge(i).Label)})
		}
	}

	outgoing := make([]edgeRecord, 0, len(outgoingRaw))
	outgoingSeen := make(map[string]struct{})
	for _, edge := range outgoingRaw {
		key := fmt.Sprintf("%p:%d", edge.other, edge.label)
		if _, ok := outgoingSeen[key]; ok {
			continue
		}
		outgoingSeen[key] = struct{}{}
		outgoing = append(outgoing, edge)
	}

	selfLabels := make([]uint32, 0, 1)
	if tp == BlockListType {
		selfSeen := make(map[uint32]struct{})
		entry := nodes[0]
		for _, node := range nodes {
			for i := 0; i < node.SizeOut(); i++ {
				if node.getOut(i) != entry {
					continue
				}
				if _, ok := region[entry]; !ok || node == entry {
					continue
				}
				// A goto-marked edge back to the entry is an unstructured interior
				// jump, not a structural loop back-edge. C++ selfIdentify keeps such
				// an edge internal to the collapsed sub-structure; it must NOT become
				// a self-loop out-edge on the new block. Otherwise the self-loop
				// detector (LoopBody.Update) re-selects the already-goto'd self-edge
				// forever, since ruleBlockGoto cannot collapse a >2-out block.
				if node.OutEdge(i).Label&EdgeFlagGoto != 0 {
					continue
				}
				label := collapseEdgeLabel(node.OutEdge(i).Label)
				if _, ok := selfSeen[label]; ok {
					continue
				}
				selfSeen[label] = struct{}{}
				selfLabels = append(selfLabels, label)
			}
		}
	}

	// Redirect incoming edges in-place: replace the old region-node target with
	// newBlock without changing the slot in the source's outEdges. This preserves
	// TrueOut/FalseOut (outEdges[1]/outEdges[0]) ordering for conditional blocks.
	// If the same source has multiple edges into the region, each is handled once
	// (GetOutIndex returns -1 after the first replacement).
	for _, edge := range incomingRaw {
		outIdx := edge.other.GetOutIndex(edge.node)
		if outIdx < 0 {
			continue // already replaced (duplicate source)
		}
		edge.other.ReplaceOutEdge(outIdx, newBlock)
	}
	for _, edge := range outgoingRaw {
		idx := edge.node.GetOutIndex(edge.other)
		if idx >= 0 {
			edge.node.RemoveOutEdge(idx)
		}
	}

	for _, node := range nodes {
		node.SetParent(newBlock)
	}

	firstIndex := len(bg.blocks)
	filtered := make([]*FlowBlock, 0, len(bg.blocks)-len(nodes)+1)
	for idx, block := range bg.blocks {
		if _, ok := region[block]; ok {
			if firstIndex == len(bg.blocks) {
				firstIndex = idx
			}
			continue
		}
		filtered = append(filtered, block)
	}
	if firstIndex > len(filtered) {
		firstIndex = len(filtered)
	}
	filtered = append(filtered, nil)
	copy(filtered[firstIndex+1:], filtered[firstIndex:])
	filtered[firstIndex] = newBlock
	bg.blocks = filtered

	for _, edge := range outgoing {
		bg.AddEdge(newBlock, edge.other, edge.label)
	}
	for _, label := range selfLabels {
		bg.AddEdge(newBlock, newBlock, label)
	}
	return newBlock
}

func (bg *BlockGraph) newBlockList(nodes []*FlowBlock) *FlowBlock {
	return bg.collapseRegion(nodes, BlockListType)
}

func (bg *BlockGraph) newBlockCondition(left, right *FlowBlock) *FlowBlock {
	// C++ parity: BlockGraph::newBlockCondition (block.cc:1780).
	// opc = (b1->getFalseOut()==b2) ? CPUI_INT_OR : CPUI_INT_AND. Computed from
	// left's original false edge before collapse; collapseRegion's in-place edge
	// redirection preserves the 2-output false/true ordering that C++ pins with
	// forceOutputNum(2)/forceFalseEdge(out0).
	opc := CPUI_INT_AND
	if left.FalseOut() == right {
		opc = CPUI_INT_OR
	}
	// out0 = b2->getOut(0), captured before collapse so forceFalseEdge can pin
	// the condition's false out to it (preserving the condition ordering).
	out0 := right.getOut(0)
	res := bg.collapseRegion([]*FlowBlock{left, right}, BlockConditionType)
	if bc, ok := res.Concrete().(*BlockCondition); ok {
		bc.opc = opc
	}
	// C++ forceOutputNum(2) is a no-op for a real binary condition (already 2
	// outs); forceFalseEdge(out0) pins outEdges[0] to b2's original out(0).
	res.ForceFalseEdge(out0)
	return res
}

func (bg *BlockGraph) newBlockIf(cond, clause *FlowBlock) *FlowBlock {
	return bg.collapseRegion([]*FlowBlock{cond, clause}, BlockIfType)
}

func (bg *BlockGraph) newBlockIfElse(cond, trueClause, falseClause *FlowBlock) *FlowBlock {
	return bg.collapseRegion([]*FlowBlock{cond, trueClause, falseClause}, BlockIfType)
}

// newBlockGoto collapses bl into an unconditional BlockGoto. The goto edge is
// stored as the block's goto target and then removed from the structure graph,
// leaving the BlockGoto with no outgoing edges. Keeping the edge would inflate
// SizeOut and prevent later ruleBlockCat/ruleBlockProperIf collapses.
// C++ parity: BlockGraph::newBlockGoto (block.cc:1702) -- forceOutputNum(1)
// followed by removeEdge(ret, ret->getOut(0)).
func (bg *BlockGraph) newBlockGoto(bl *FlowBlock) *FlowBlock {
	target := bl.getOut(0)
	res := bg.collapseRegion([]*FlowBlock{bl}, BlockGotoType)
	res.setGotoTargetBlock(target)
	res.setGotoType(BlockFlagGotoGoto)
	res.setGotoEdgeIndex(0)
	if idx := res.GetOutIndex(target); idx >= 0 {
		res.RemoveOutEdge(idx)
	} else if res.SizeOut() > 0 {
		res.RemoveOutEdge(0)
	}
	return res
}

// newBlockIfGoto collapses a 2-out conditional bl (goto on the true/out1 edge)
// into a BlockIf whose true branch is stored as the goto target and removed from
// the graph, leaving a single false/fall-through out edge. This lets the if-goto
// participate in later ruleBlockCat/ruleBlockProperIf collapses.
// C++ parity: BlockGraph::newBlockIfGoto (block.cc:1799) -- BlockIf with
// setGotoTarget(getOut(1)), forceFalseEdge(getOut(0)), removeEdge(getTrueOut()).
func (bg *BlockGraph) newBlockIfGoto(bl *FlowBlock) *FlowBlock {
	out0 := bl.getOut(0)   // false / fall-through, preserved by forceFalseEdge
	target := bl.getOut(1) // true branch is the goto target
	res := bg.collapseRegion([]*FlowBlock{bl}, BlockIfType)
	res.setGotoTargetBlock(target)
	res.setGotoType(BlockFlagGotoGoto)
	res.setGotoEdgeIndex(1)
	res.ForceFalseEdge(out0)
	if idx := res.GetOutIndex(target); idx >= 0 {
		res.RemoveOutEdge(idx)
	}
	return res
}

func (bg *BlockGraph) newBlockMultiGoto(bl *FlowBlock, idx int) *FlowBlock {
	res := bg.collapseRegion([]*FlowBlock{bl}, BlockMultiGotoType)
	res.setGotoEdgeIndex(idx)
	res.SetFlag(BlockFlagSwitchOut)
	return res
}

func (bg *BlockGraph) newBlockWhileDo(cond, clause *FlowBlock) *BlockWhileDo {
	res := bg.collapseRegion([]*FlowBlock{cond, clause}, BlockWhileDoType)
	if typed, ok := res.Concrete().(*BlockWhileDo); ok {
		return typed
	}
	return nil
}

func (bg *BlockGraph) newBlockDoWhile(bl *FlowBlock) *FlowBlock {
	return bg.collapseRegion([]*FlowBlock{bl}, BlockDoWhileType)
}

func (bg *BlockGraph) newBlockInfLoop(bl *FlowBlock) *FlowBlock {
	return bg.collapseRegion([]*FlowBlock{bl}, BlockInfLoopType)
}

func (bg *BlockGraph) newBlockSwitch(cases []*FlowBlock, hasExit bool) *FlowBlock {
	res := bg.collapseRegion(cases, BlockSwitchType)
	res.SetFlag(BlockFlagSwitchOut)
	_ = hasExit
	return res
}

func (bg *BlockGraph) finalizePrinting(*Funcdata) {}

// scopeBreak walks the top-level structured list, assigning a fall-through exit
// to each block (the next sibling, or the enclosing curexit for the last one),
// then recurses. curloopexit is the innermost loop's exit block (nil at top).
// C++ parity: block.cc BlockGraph::scopeBreak (block.cc:1270). Pointers replace
// C++ int4 indices: the stored goto target and the loop-exit sibling are the
// same structure-graph FlowBlock object, so identity is equivalent to index
// equality without depending on post-collapse index reassignment.
func (bg *BlockGraph) scopeBreak(curexit, curloopexit *FlowBlock) {
	blocks := bg.blocks
	for i, curbl := range blocks {
		var ind *FlowBlock
		if i+1 < len(blocks) {
			ind = blocks[i+1]
		} else {
			ind = curexit
		}
		curbl.scopeBreak(ind, curloopexit)
	}
}

// scopeBreak recurses through the structured hierarchy, converting a goto whose
// target is the current loop exit into a break;. Dispatch mirrors the per-class
// C++ overrides; a BlockList reuses the sibling-chaining BlockGraph logic.
// C++ parity: block.cc {BlockGoto,BlockIf,BlockCondition,BlockWhileDo,
// BlockDoWhile,BlockInfLoop,BlockSwitch,BlockMultiGoto}::scopeBreak.
func (b *FlowBlock) scopeBreak(curexit, curloopexit *FlowBlock) {
	children := b.StructuredChildren()
	switch b.Type() {
	case BlockListType, BlockGraphType:
		// BlockGraph::scopeBreak: each child exits to the next sibling.
		for i, c := range children {
			var ind *FlowBlock
			if i+1 < len(children) {
				ind = children[i+1]
			} else {
				ind = curexit
			}
			c.scopeBreak(ind, curloopexit)
		}
	case BlockGotoType:
		// BlockGoto::scopeBreak (block.cc:2866).
		if len(children) > 0 {
			children[0].scopeBreak(b.GotoTargetBlock(), curloopexit)
		}
		if tgt := b.GotoTargetBlock(); tgt != nil && tgt == curloopexit {
			b.setGotoType(BlockFlagBreakGoto)
		}
	case BlockIfType:
		// BlockIf::scopeBreak (block.cc:3075): condition (child 0) has multiple
		// exits; the body clauses (1..) share the same exit.
		if len(children) > 0 {
			children[0].scopeBreak(nil, curloopexit)
		}
		for i := 1; i < len(children); i++ {
			children[i].scopeBreak(curexit, curloopexit)
		}
		if tgt := b.GotoTargetBlock(); tgt != nil && tgt == curloopexit {
			b.setGotoType(BlockFlagBreakGoto)
		}
	case BlockConditionType:
		// BlockCondition::scopeBreak (block.cc:3034): no fixed exit for either half.
		for _, c := range children {
			c.scopeBreak(nil, curloopexit)
		}
	case BlockWhileDoType:
		// BlockWhileDo::scopeBreak (block.cc:3324): new loop scope; the loop's own
		// exit (curexit passed in) becomes the loop-exit for the body.
		if len(children) > 0 {
			children[0].scopeBreak(nil, curexit)
		}
		if len(children) > 1 {
			children[1].scopeBreak(children[0], curexit)
		}
	case BlockDoWhileType:
		// BlockDoWhile::scopeBreak (block.cc:3434).
		if len(children) > 0 {
			children[0].scopeBreak(nil, curexit)
		}
	case BlockInfLoopType:
		// BlockInfLoop::scopeBreak (block.cc:3462): exits into itself.
		if len(children) > 0 {
			children[0].scopeBreak(children[0], curexit)
		}
	case BlockSwitchType:
		// BlockSwitch::scopeBreak (block.cc:3613): the case gototype -> break
		// assignment is intentionally omitted; Gosleigh's emitSwitchBlock renders
		// per-case break; from the terminal BRANCH (caseExits), independent of the
		// gototype mechanism. Recurse so nested loops/gotos inside cases are still
		// scoped.
		if len(children) > 0 {
			children[0].scopeBreak(nil, curexit)
		}
		for i := 1; i < len(children); i++ {
			children[i].scopeBreak(curexit, curexit)
		}
	case BlockMultiGotoType:
		// BlockMultiGoto::scopeBreak (block.cc:2918).
		if len(children) > 0 {
			children[0].scopeBreak(nil, curloopexit)
		}
	}
}

func (bg *BlockGraph) markUnstructured() {}

func (bg *BlockGraph) markLabelBumpUp(bool) {}

type CollapseStructure struct {
	finaltrace          bool
	likelylistfull      bool
	likelygoto          []FloatingEdge
	likelyIndex         int
	loopbody            []LoopBody
	loopbodyIndex       int
	graph               *BlockGraph
	dataflowChangeCount int
}

func NewCollapseStructure(g *BlockGraph) *CollapseStructure {
	return &CollapseStructure{graph: g}
}

func (c *CollapseStructure) GetChangeCount() int {
	return c.dataflowChangeCount
}

func (c *CollapseStructure) onlyReachableFromRoot(root *FlowBlock, body *[]*FlowBlock) {
	trial := make([]*FlowBlock, 0)
	i := 0
	root.setMark()
	*body = append(*body, root)
	for i < len(*body) {
		bl := (*body)[i]
		i++
		for j := 0; j < bl.SizeOut(); j++ {
			cur := bl.getOut(j)
			if cur.isMark() {
				continue
			}
			count := cur.VisitCount()
			if count == 0 {
				trial = append(trial, cur)
			}
			count++
			cur.SetVisitCount(count)
			if int(count) == cur.SizeIn() {
				cur.setMark()
				*body = append(*body, cur)
			}
		}
	}
	for _, block := range trial {
		block.SetVisitCount(0)
	}
}

func (c *CollapseStructure) markExitsAsGotos(body []*FlowBlock) int {
	changeCount := 0
	for _, bl := range body {
		for j := 0; j < bl.SizeOut(); j++ {
			cur := bl.getOut(j)
			if !cur.isMark() {
				bl.setGotoBranch(j)
				changeCount++
			}
		}
	}
	return changeCount
}

func (c *CollapseStructure) clipExtraRoots() bool {
	for i := 1; i < c.graph.GetSize(); i++ {
		bl := c.graph.GetBlock(i)
		if bl.SizeIn() != 0 {
			continue
		}
		body := make([]*FlowBlock, 0)
		c.onlyReachableFromRoot(bl, &body)
		count := c.markExitsAsGotos(body)
		ClearMarks(body)
		if count != 0 {
			return true
		}
	}
	return false
}

func (c *CollapseStructure) labelLoops(looporder *[]*LoopBody) {
	for i := 0; i < c.graph.GetSize(); i++ {
		bl := c.graph.GetBlock(i)
		for j := 0; j < bl.SizeIn(); j++ {
			if bl.isBackEdgeIn(j) {
				body := NewLoopBody(bl)
				body.AddTail(bl.getIn(j))
				c.loopbody = append(c.loopbody, *body)
				*looporder = append(*looporder, &c.loopbody[len(c.loopbody)-1])
			}
		}
	}
	sort.Slice(*looporder, func(i, j int) bool {
		return CompareLoopEnds((*looporder)[i], (*looporder)[j])
	})
}

func (c *CollapseStructure) orderLoopBodies() {
	looporder := make([]*LoopBody, 0)
	c.labelLoops(&looporder)
	if len(c.loopbody) == 0 {
		c.likelylistfull = false
		c.loopbodyIndex = 0
		return
	}
	oldSize := len(looporder)
	looporder = MergeIdenticalHeads(looporder)
	if oldSize != len(looporder) {
		filtered := c.loopbody[:0]
		for _, body := range c.loopbody {
			if body.GetHead() != nil {
				filtered = append(filtered, body)
			}
		}
		c.loopbody = filtered
		looporder = make([]*LoopBody, 0, len(c.loopbody))
		for i := range c.loopbody {
			looporder = append(looporder, &c.loopbody[i])
		}
		sort.Slice(looporder, func(i, j int) bool {
			return CompareLoopEnds(looporder[i], looporder[j])
		})
	}
	for i := range c.loopbody {
		body := make([]*FlowBlock, 0)
		c.loopbody[i].FindBase(&body)
		c.loopbody[i].LabelContainments(body, looporder)
		ClearMarks(body)
	}
	SortLoopBodiesByDepth(c.loopbody)
	for i := range c.loopbody {
		body := make([]*FlowBlock, 0)
		c.loopbody[i].FindBase(&body)
		c.loopbody[i].FindExit(body)
		c.loopbody[i].OrderTails()
		c.loopbody[i].Extend(&body)
		c.loopbody[i].LabelExitEdges(body)
		ClearMarks(body)
	}
	c.likelylistfull = false
	c.loopbodyIndex = 0
}

func (c *CollapseStructure) updateLoopBody() bool {
	if c.finaltrace {
		return false
	}
	var loopbottom *FlowBlock
	var looptop *FlowBlock
	for c.loopbodyIndex < len(c.loopbody) {
		curBody := &c.loopbody[c.loopbodyIndex]
		loopbottom = curBody.Update(&c.graph.FlowBlock)
		if loopbottom != nil {
			looptop = curBody.GetHead()
			if loopbottom == looptop {
				c.likelygoto = []FloatingEdge{NewFloatingEdge(looptop, looptop)}
				c.likelyIndex = 0
				c.likelylistfull = true
				return true
			}
			if !c.likelylistfull || c.likelyIndex < len(c.likelygoto) {
				break
			}
		}
		c.loopbodyIndex++
		c.likelylistfull = false
		loopbottom = nil
	}
	if c.likelylistfull && c.likelyIndex < len(c.likelygoto) {
		return true
	}

	c.likelygoto = c.likelygoto[:0]
	tracer := NewTraceDAG(&c.likelygoto)
	if loopbottom != nil {
		tracer.AddRoot(looptop)
		tracer.SetFinishBlock(loopbottom)
		c.loopbody[c.loopbodyIndex].SetExitMarks(&c.graph.FlowBlock)
	} else {
		for i := 0; i < c.graph.GetSize(); i++ {
			bl := c.graph.GetBlock(i)
			if bl.SizeIn() == 0 {
				tracer.AddRoot(bl)
			}
		}
	}
	tracer.Initialize()
	tracer.PushBranches()
	c.likelylistfull = true
	if loopbottom != nil {
		c.loopbody[c.loopbodyIndex].EmitLikelyEdges(&c.likelygoto, &c.graph.FlowBlock)
		c.loopbody[c.loopbodyIndex].ClearExitMarks(&c.graph.FlowBlock)
	} else if len(c.likelygoto) == 0 {
		c.finaltrace = true
		return false
	}
	c.likelyIndex = 0
	return true
}

func (c *CollapseStructure) selectGoto() *FlowBlock {
	for c.updateLoopBody() {
		for c.likelyIndex < len(c.likelygoto) {
			start, outedge := c.likelygoto[c.likelyIndex].GetCurrentEdge(&c.graph.FlowBlock)
			c.likelyIndex++
			if start != nil {
				start.setGotoBranch(outedge)
				return start
			}
		}
	}
	if !c.clipExtraRoots() {
		return nil
	}
	return nil
}

func (c *CollapseStructure) ruleBlockCat(bl *FlowBlock) bool {
	if bl.SizeOut() != 1 {
		return false
	}
	if bl.isSwitchOut() {
		return false
	}
	if bl.SizeIn() == 1 && bl.getIn(0).SizeOut() == 1 {
		return false
	}
	outblock := bl.getOut(0)
	if outblock == bl {
		return false
	}
	if outblock.SizeIn() != 1 {
		return false
	}
	if !bl.isDecisionOut(0) {
		return false
	}
	if outblock.isSwitchOut() {
		return false
	}

	nodes := []*FlowBlock{bl, outblock}
	for outblock.SizeOut() == 1 {
		outbl2 := outblock.getOut(0)
		if outbl2 == bl {
			break
		}
		if outbl2.SizeIn() != 1 {
			break
		}
		if !outblock.isDecisionOut(0) {
			break
		}
		if outbl2.isSwitchOut() {
			break
		}
		outblock = outbl2
		nodes = append(nodes, outblock)
	}

	c.graph.newBlockList(nodes)
	return true
}

func (c *CollapseStructure) ruleBlockOr(bl *FlowBlock) bool {
	if bl.SizeOut() != 2 {
		return false
	}
	if bl.isGotoOut(0) || bl.isGotoOut(1) || bl.isSwitchOut() {
		return false
	}
	for i := 0; i < 2; i++ {
		orblock := bl.getOut(i)
		if orblock == bl {
			continue
		}
		if orblock.SizeIn() != 1 || orblock.SizeOut() != 2 {
			continue
		}
		if orblock.isInteriorGotoTarget() || orblock.isSwitchOut() {
			continue
		}
		if bl.isBackEdgeOut(i) || orblock.isComplex() {
			continue
		}
		clauseblock := bl.getOut(1 - i)
		if clauseblock == bl || clauseblock == orblock {
			continue
		}
		match := -1
		for j := 0; j < 2; j++ {
			if clauseblock == orblock.getOut(j) {
				match = j
				break
			}
		}
		if match < 0 || orblock.getOut(1-match) == bl {
			continue
		}
		if i == 1 {
			if bl.negateCondition(true) {
				c.dataflowChangeCount++
			}
		}
		if match == 0 {
			if orblock.negateCondition(true) {
				c.dataflowChangeCount++
			}
		}
		c.graph.newBlockCondition(bl, orblock)
		return true
	}
	return false
}

func (c *CollapseStructure) ruleBlockProperIf(bl *FlowBlock) bool {
	if bl.SizeOut() != 2 || bl.isSwitchOut() {
		return false
	}
	if bl.getOut(0) == bl || bl.getOut(1) == bl {
		return false
	}
	if bl.isGotoOut(0) || bl.isGotoOut(1) {
		return false
	}
	for i := 0; i < 2; i++ {
		clause := bl.getOut(i)
		if clause.SizeIn() != 1 || clause.SizeOut() != 1 || clause.isSwitchOut() {
			continue
		}
		if !bl.isDecisionOut(i) || clause.isGotoOut(0) {
			continue
		}
		outblock := clause.getOut(0)
		if outblock != bl.getOut(1-i) {
			continue
		}
		if i == 0 && bl.negateCondition(true) {
			c.dataflowChangeCount++
		}
		c.graph.newBlockIf(bl, clause)
		return true
	}
	return false
}

func (c *CollapseStructure) ruleBlockIfElse(bl *FlowBlock) bool {
	if bl.SizeOut() != 2 || bl.isSwitchOut() {
		return false
	}
	if !bl.isDecisionOut(0) || !bl.isDecisionOut(1) {
		return false
	}
	tc := bl.TrueOut()
	fc := bl.FalseOut()
	if tc.SizeIn() != 1 || fc.SizeIn() != 1 {
		return false
	}
	if tc.SizeOut() != 1 || fc.SizeOut() != 1 {
		return false
	}
	outblock := tc.getOut(0)
	if outblock == bl || outblock != fc.getOut(0) {
		return false
	}
	if tc.isSwitchOut() || fc.isSwitchOut() {
		return false
	}
	if tc.isGotoOut(0) || fc.isGotoOut(0) {
		return false
	}
	c.graph.newBlockIfElse(bl, tc, fc)
	return true
}

func (c *CollapseStructure) ruleBlockGoto(bl *FlowBlock) bool {
	if bl.Type() == BlockGotoType || bl.Type() == BlockMultiGotoType {
		return false
	}
	for i := 0; i < bl.SizeOut(); i++ {
		if !bl.isGotoOut(i) {
			continue
		}
		if bl.isSwitchOut() {
			c.graph.newBlockMultiGoto(bl, i)
			return true
		}
		if bl.SizeOut() == 2 {
			if !bl.isGotoOut(1) && bl.negateCondition(true) {
				c.dataflowChangeCount++
			}
			c.graph.newBlockIfGoto(bl)
			return true
		}
		if bl.SizeOut() == 1 {
			c.graph.newBlockGoto(bl)
			return true
		}
	}
	return false
}

func (c *CollapseStructure) ruleBlockIfNoExit(bl *FlowBlock) bool {
	if bl.SizeOut() != 2 || bl.isSwitchOut() {
		return false
	}
	if bl.getOut(0) == bl || bl.getOut(1) == bl {
		return false
	}
	if bl.isGotoOut(0) || bl.isGotoOut(1) {
		return false
	}
	for i := 0; i < 2; i++ {
		clause := bl.getOut(i)
		if clause.SizeIn() != 1 || clause.SizeOut() != 0 || clause.isSwitchOut() {
			continue
		}
		if !bl.isDecisionOut(i) {
			continue
		}
		if i == 0 && bl.negateCondition(true) {
			c.dataflowChangeCount++
		}
		c.graph.newBlockIf(bl, clause)
		return true
	}
	return false
}

func (c *CollapseStructure) ruleBlockWhileDo(bl *FlowBlock) bool {
	if bl.SizeOut() != 2 || bl.isSwitchOut() {
		return false
	}
	if bl.getOut(0) == bl || bl.getOut(1) == bl {
		return false
	}
	if bl.isInteriorGotoTarget() || bl.isGotoOut(0) || bl.isGotoOut(1) {
		return false
	}
	for i := 0; i < 2; i++ {
		clause := bl.getOut(i)
		if clause.SizeIn() != 1 || clause.SizeOut() != 1 || clause.isSwitchOut() {
			continue
		}
		if clause.getOut(0) != bl {
			continue
		}
		overflow := bl.isComplex()
		if (i == 0) != overflow {
			if bl.negateCondition(true) {
				c.dataflowChangeCount++
			}
		}
		newbl := c.graph.newBlockWhileDo(bl, clause)
		if overflow && newbl != nil {
			newbl.SetOverflowSyntax()
		}
		return true
	}
	return false
}

func (c *CollapseStructure) ruleBlockDoWhile(bl *FlowBlock) bool {
	if bl.Type() == BlockDoWhileType {
		return false
	}
	if bl.SizeOut() != 2 || bl.isSwitchOut() {
		return false
	}
	if bl.isGotoOut(0) || bl.isGotoOut(1) {
		return false
	}
	for i := 0; i < 2; i++ {
		if bl.getOut(i) != bl {
			continue
		}
		if i == 0 && bl.negateCondition(true) {
			c.dataflowChangeCount++
		}
		c.graph.newBlockDoWhile(bl)
		return true
	}
	return false
}

func (c *CollapseStructure) ruleBlockInfLoop(bl *FlowBlock) bool {
	if bl.Type() == BlockInfLoopType {
		return false
	}
	if bl.SizeOut() != 1 {
		return false
	}
	if bl.isGotoOut(0) || bl.getOut(0) != bl {
		return false
	}
	c.graph.newBlockInfLoop(bl)
	return true
}

func (c *CollapseStructure) checkSwitchSkips(switchbl, exitblock *FlowBlock) bool {
	if exitblock == nil {
		return true
	}
	defaultNotToExit := false
	anySkipToExit := false
	for i := 0; i < switchbl.SizeOut(); i++ {
		if switchbl.getOut(i) == exitblock {
			if switchbl.OutEdge(i).Label&EdgeFlagDefaultSwitch == 0 {
				anySkipToExit = true
			}
		} else if switchbl.OutEdge(i).Label&EdgeFlagDefaultSwitch != 0 {
			defaultNotToExit = true
		}
	}
	if !anySkipToExit || !defaultNotToExit {
		return true
	}
	for i := 0; i < switchbl.SizeOut(); i++ {
		if switchbl.getOut(i) == exitblock && switchbl.OutEdge(i).Label&EdgeFlagDefaultSwitch == 0 {
			switchbl.setGotoBranch(i)
		}
	}
	return false
}

func (c *CollapseStructure) ruleBlockSwitch(bl *FlowBlock) bool {
	if bl.Type() == BlockSwitchType {
		return false
	}
	if !bl.isSwitchOut() {
		return false
	}
	var exitblock *FlowBlock
	for i := 0; i < bl.SizeOut(); i++ {
		cur := bl.getOut(i)
		if cur == bl || cur.SizeOut() > 1 || cur.SizeIn() > 1 {
			exitblock = cur
			break
		}
	}
	if exitblock == nil {
		for i := 0; i < bl.SizeOut(); i++ {
			cur := bl.getOut(i)
			if cur.SizeIn() == 0 || cur.isSwitchOut() {
				return false
			}
			if cur.isGotoIn(0) {
				return false
			}
			if cur.SizeOut() == 1 {
				if cur.isGotoOut(0) {
					return false
				}
				if exitblock != nil {
					if exitblock != cur.getOut(0) {
						return false
					}
				} else {
					exitblock = cur.getOut(0)
				}
			}
		}
	} else {
		for i := 0; i < exitblock.SizeIn(); i++ {
			if exitblock.isGotoIn(i) {
				return false
			}
		}
		for i := 0; i < exitblock.SizeOut(); i++ {
			if exitblock.isGotoOut(i) {
				return false
			}
		}
		for i := 0; i < bl.SizeOut(); i++ {
			cur := bl.getOut(i)
			if cur == exitblock {
				continue
			}
			if cur.SizeIn() > 1 || cur.isGotoIn(0) || cur.SizeOut() > 1 || cur.isSwitchOut() {
				return false
			}
			if cur.SizeOut() == 1 {
				if cur.isGotoOut(0) || cur.getOut(0) != exitblock {
					return false
				}
			}
		}
	}

	if !c.checkSwitchSkips(bl, exitblock) {
		return true
	}

	cases := []*FlowBlock{bl}
	for i := 0; i < bl.SizeOut(); i++ {
		cur := bl.getOut(i)
		if cur == exitblock {
			continue
		}
		cases = append(cases, cur)
	}
	c.graph.newBlockSwitch(cases, exitblock != nil)
	return true
}

func (c *CollapseStructure) ruleCaseFallthru(bl *FlowBlock) bool {
	if !bl.isSwitchOut() {
		return false
	}
	nonFallthrough := 0
	caseFallthroughs := make([]*FlowBlock, 0)
	for i := 0; i < bl.SizeOut(); i++ {
		cur := bl.getOut(i)
		if cur == bl {
			return false
		}
		if cur.SizeIn() > 2 || cur.SizeOut() > 1 {
			nonFallthrough++
		} else if cur.SizeOut() == 1 {
			target := cur.getOut(0)
			if target.SizeIn() == 2 && target.SizeOut() <= 1 {
				inSlot := cur.OutRevIndex(0)
				if target.getIn(1-inSlot) == bl {
					caseFallthroughs = append(caseFallthroughs, cur)
				}
			}
		}
		if nonFallthrough > 1 {
			return false
		}
	}
	if len(caseFallthroughs) == 0 {
		return false
	}
	for _, cur := range caseFallthroughs {
		cur.setGotoBranch(0)
	}
	return true
}

func (c *CollapseStructure) collapseInternal(targetbl *FlowBlock) int {
	var isolatedCount int
	for {
		change := false
		isolatedCount = 0
		index := 0
		for index < c.graph.GetSize() {
			var bl *FlowBlock
			if targetbl == nil {
				bl = c.graph.GetBlock(index)
				index++
			} else {
				bl = targetbl
				change = true
				targetbl = nil
				index = c.graph.GetSize()
			}
			if bl.SizeIn() == 0 && bl.SizeOut() == 0 {
				isolatedCount++
				continue
			}
			if c.ruleBlockGoto(bl) || c.ruleBlockCat(bl) || c.ruleBlockProperIf(bl) ||
				c.ruleBlockIfElse(bl) || c.ruleBlockWhileDo(bl) || c.ruleBlockDoWhile(bl) ||
				c.ruleBlockInfLoop(bl) || c.ruleBlockSwitch(bl) {
				change = true
				continue
			}
		}
		if change {
			continue
		}
		fullChange := false
		for i := 0; i < c.graph.GetSize(); i++ {
			bl := c.graph.GetBlock(i)
			if c.ruleBlockIfNoExit(bl) || c.ruleCaseFallthru(bl) {
				fullChange = true
				break
			}
		}
		if !fullChange {
			break
		}
	}
	return isolatedCount
}

func (c *CollapseStructure) collapseConditions() {
	for {
		change := false
		for i := 0; i < c.graph.GetSize(); i++ {
			if c.ruleBlockOr(c.graph.GetBlock(i)) {
				change = true
			}
		}
		if !change {
			return
		}
	}
}

func (c *CollapseStructure) CollapseAll() {
	c.finaltrace = false
	c.graph.ClearVisitCount()
	c.graph.StructureLoops()
	c.orderLoopBodies()
	c.collapseConditions()
	isolatedCount := c.collapseInternal(nil)
	for isolatedCount < c.graph.GetSize() {
		target := c.selectGoto()
		if target == nil && !c.clipExtraRoots() {
			break
		}
		isolatedCount = c.collapseInternal(target)
	}
}

func ClearMarks(body []*FlowBlock) {
	for _, block := range body {
		block.clearMark()
	}
}
