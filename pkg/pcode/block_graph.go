package pcode

import "sort"

// BlockGraph is a container of FlowBlocks forming a control flow graph.
// C++ parity: block.hh BlockGraph
type BlockGraph struct {
	FlowBlock // embedded
	blocks    []*FlowBlock
}

// NewBlockGraph creates a new BlockGraph with BlockGraphType set.
func NewBlockGraph() *BlockGraph {
	bg := &BlockGraph{}
	bg.blockType = BlockGraphType
	return bg
}

// Type returns BlockGraphType (overrides FlowBlock.Type).
func (bg *BlockGraph) Type() BlockType { return BlockGraphType }

// AddBlock adds a block to this graph and sets its parent.
func (bg *BlockGraph) AddBlock(bl *FlowBlock) {
	bl.parent = &bg.FlowBlock
	bg.blocks = append(bg.blocks, bl)
}

// GetSize returns the number of blocks in this graph.
func (bg *BlockGraph) GetSize() int { return len(bg.blocks) }

// GetBlock returns the i-th block.
func (bg *BlockGraph) GetBlock(i int) *FlowBlock { return bg.blocks[i] }

// AddEdge adds a directed edge from begin to end with the given label.
// C++ parity: block.cc BlockGraph::addEdge
func (bg *BlockGraph) AddEdge(begin, end *FlowBlock, label uint32) {
	end.AddInEdge(begin, label)
}

// RemoveEdge removes the edge from begin to end.
// C++ parity: block.cc BlockGraph::removeEdge
func (bg *BlockGraph) RemoveEdge(begin, end *FlowBlock) {
	for i, e := range end.inEdges {
		if e.Point == begin {
			end.RemoveInEdge(i)
			return
		}
	}
}

// RemoveBlock removes bl from the graph, removing all its edges first.
// C++ parity: block.cc BlockGraph::removeBlock
func (bg *BlockGraph) RemoveBlock(bl *FlowBlock) {
	// Remove all out-edges (iterate backwards to avoid index issues).
	for bl.SizeOut() > 0 {
		bl.RemoveOutEdge(bl.SizeOut() - 1)
	}
	// Remove all in-edges.
	for bl.SizeIn() > 0 {
		bl.RemoveInEdge(bl.SizeIn() - 1)
	}
	// Remove from blocks slice.
	for i, b := range bg.blocks {
		if b == bl {
			bg.blocks = append(bg.blocks[:i], bg.blocks[i+1:]...)
			break
		}
	}
	bl.parent = nil
}

// removeFromFlow removes bl from the flow of the graph, rewiring each of bl's
// predecessors' edges (that pointed at bl) to bl's successor. Intended for a
// block with at most one out-edge (do-nothing / unreachable removal). Loop-edge
// information is not preserved. bl's own edges are all severed.
// C++ parity: block.cc BlockGraph::removeFromFlow (block.cc:1545)
func (bg *BlockGraph) removeFromFlow(bl *FlowBlock) {
	for bl.SizeOut() > 0 {
		bbout := bl.OutEdge(bl.SizeOut() - 1).Point
		bl.RemoveOutEdge(bl.SizeOut() - 1)
		for bl.SizeIn() > 0 {
			bbin := bl.InEdge(0).Point
			// bl->intothis[0].reverse_index: the predecessor's out-edge slot
			// that currently targets bl. Retarget it to bbout, which severs
			// bl's in-edge 0 (advancing the loop).
			revIdx := bl.InEdge(0).ReverseIndex
			bbin.ReplaceOutEdge(revIdx, bbout)
		}
	}
}

// SpliceBlock removes bl from the graph, connecting bl's single predecessor
// directly to bl's single successor. bl must have exactly one in-edge and
// one out-edge (i.e. it is a passthrough block).
// C++ parity: block.cc BlockGraph::spliceBlock
func (bg *BlockGraph) SpliceBlock(bl *FlowBlock) {
	if bl.SizeIn() != 1 || bl.SizeOut() != 1 {
		return
	}
	pred := bl.inEdges[0].Point
	succ := bl.outEdges[0].Point
	label := bl.outEdges[0].Label

	// Remove edges: pred -> bl -> succ.
	bl.RemoveInEdge(0)
	bl.RemoveOutEdge(0)

	// Connect pred directly to succ.
	succ.AddInEdge(pred, label)

	// Remove bl from graph.
	for i, b := range bg.blocks {
		if b == bl {
			bg.blocks = append(bg.blocks[:i], bg.blocks[i+1:]...)
			break
		}
	}
	bl.parent = nil
}

// Clear removes all blocks from the graph.
func (bg *BlockGraph) Clear() {
	bg.blocks = nil
}

// NewBlockBasicInGraph creates a new BlockBasic and adds it to the graph.
// The returned *BlockBasic owns the FlowBlock stored in the blocks slice.
func (bg *BlockGraph) NewBlockBasicInGraph() *BlockBasic {
	bb := NewBlockBasic()
	bb.FlowBlock.parent = &bg.FlowBlock
	bg.blocks = append(bg.blocks, &bb.FlowBlock)
	return bb
}

// ClearVisitCount sets visitCount=0 on all blocks.
func (bg *BlockGraph) ClearVisitCount() {
	for _, bl := range bg.blocks {
		bl.visitCount = 0
	}
}

// FindSpanningTree labels the edges of a depth-first spanning tree and puts
// the blocks in reverse post-order. Every block without in-edges is a root,
// and so is any block left unvisited; the entry block is traversed last so it
// gets index 0. Returns the roots, entry first.
// C++ parity: block.cc BlockGraph::findSpanningTree. Irreducible edges are not
// modelled, and only the spanning-tree and loop labels are cleared (C++
// clears every edge flag).
func (bg *BlockGraph) FindSpanningTree() []*FlowBlock {
	n := len(bg.blocks)
	if n == 0 {
		return nil
	}
	reset := func() {
		for _, bl := range bg.blocks {
			bl.index = -1
			bl.visitCount = -1
		}
	}
	reset()
	var rootlist []*FlowBlock
	for _, bl := range bg.blocks {
		if bl.SizeIn() == 0 {
			rootlist = append(rootlist, bl)
		}
	}
	if len(rootlist) > 1 { // visit the original head last
		last := len(rootlist) - 1
		rootlist[0], rootlist[last] = rootlist[last], rootlist[0]
	} else if len(rootlist) == 0 {
		rootlist = append(rootlist, bg.blocks[0]) // assume the first block is the entry
	}
	origrootpos := len(rootlist) - 1

	rpostorder := make([]*FlowBlock, n)
	type frame struct {
		bl   *FlowBlock
		edge int
	}
	const spanFlags = EdgeFlagTree | EdgeFlagForward | EdgeFlagCross | EdgeFlagBack | EdgeFlagLoop
	for repeat := 0; repeat < 2; repeat++ {
		extraroots := false
		rpostcount := n
		rootindex := 0
		preorder := 0
		for _, bl := range bg.blocks {
			for i := range bl.outEdges {
				bl.outEdges[i].Label &^= spanFlags
			}
			for i := range bl.inEdges {
				bl.inEdges[i].Label &^= spanFlags
			}
		}
		for preorder < n {
			var startbl *FlowBlock
			for rootindex < len(rootlist) {
				startbl = rootlist[rootindex]
				rootindex++
				if startbl.visitCount == -1 {
					break
				}
				// Not really a root any more (a root from the previous pass).
				rootlist = append(rootlist[:rootindex-1], rootlist[rootindex:]...)
				rootindex--
				startbl = nil
			}
			if startbl == nil { // no obvious root left: take the next unvisited block
				extraroots = true
				for _, bl := range bg.blocks {
					if bl.visitCount == -1 {
						startbl = bl
						break
					}
				}
				rootlist = append(rootlist, startbl)
				rootindex++
			}
			startbl.visitCount = int32(preorder)
			preorder++
			startbl.numDesc = 1
			stack := []frame{{bl: startbl}}
			for len(stack) > 0 {
				top := &stack[len(stack)-1]
				cur := top.bl
				if top.edge >= cur.SizeOut() { // all children visited
					stack = stack[:len(stack)-1]
					rpostcount--
					cur.index = int32(rpostcount)
					rpostorder[rpostcount] = cur
					if len(stack) > 0 {
						stack[len(stack)-1].bl.numDesc += cur.numDesc
					}
					continue
				}
				edge := top.edge
				top.edge++
				child := cur.outEdges[edge].Point
				switch {
				case child.visitCount == -1:
					cur.SetOutEdgeFlag(edge, EdgeFlagTree)
					child.visitCount = int32(preorder)
					preorder++
					child.numDesc = 1
					stack = append(stack, frame{bl: child})
				case child.index == -1: // child is on the stack
					cur.SetOutEdgeFlag(edge, EdgeFlagBack|EdgeFlagLoop)
				case cur.visitCount < child.visitCount:
					cur.SetOutEdgeFlag(edge, EdgeFlagForward)
				default:
					cur.SetOutEdgeFlag(edge, EdgeFlagCross)
				}
			}
		}
		if !extraroots || repeat == 1 {
			break
		}
		// Extra roots appeared: redo the order so the entry block comes first.
		last := len(rootlist) - 1
		rootlist[last], rootlist[origrootpos] = rootlist[origrootpos], rootlist[last]
		reset()
	}
	if len(rootlist) > 1 { // the original head goes to the front of the list
		last := len(rootlist) - 1
		rootlist[0], rootlist[last] = rootlist[last], rootlist[0]
	}
	bg.blocks = rpostorder
	return rootlist
}

// CalcForwardDominator computes immediate dominators with the
// Cooper-Harvey-Kennedy iteration over the reverse post-order. Several roots
// hang off a virtual root, which is dropped again afterward; roots end with a
// nil dominator.
// C++ parity: block.cc BlockGraph::calcForwardDominator.
func (bg *BlockGraph) CalcForwardDominator(rootlist []*FlowBlock) {
	n := len(bg.blocks)
	if n == 0 {
		return
	}
	numnodes := n - 1
	postorder := make([]*FlowBlock, n, n+1)
	for i, bl := range bg.blocks {
		bl.immedDom = nil
		postorder[numnodes-i] = bl
	}
	// The virtual root keeps the zero index of a fresh C++ FlowBlock, which
	// the finger walk below relies on.
	var virtualroot *FlowBlock
	if len(rootlist) > 1 {
		virtualroot = &FlowBlock{}
		postorder = append(postorder, virtualroot)
	}
	b := postorder[len(postorder)-1]
	if b.SizeIn() != 0 { // the root must have no in-edges
		virtualroot = &FlowBlock{}
		postorder = append(postorder, virtualroot)
		b = virtualroot
	}
	// preds lists the in-edges of x plus the virtual root's edge into each
	// root (C++ createVirtualRoot appends it with addInEdge).
	preds := func(x *FlowBlock) []*FlowBlock {
		res := make([]*FlowBlock, 0, x.SizeIn()+1)
		for _, e := range x.inEdges {
			res = append(res, e.Point)
		}
		if virtualroot != nil {
			for _, r := range rootlist {
				if r == x {
					res = append(res, virtualroot)
				}
			}
		}
		return res
	}
	b.immedDom = b
	if b == virtualroot {
		for _, r := range rootlist {
			r.immedDom = b
		}
	} else {
		for _, e := range b.outEdges {
			e.Point.immedDom = b
		}
	}
	top := b
	for changed := true; changed; {
		changed = false
		for i := len(postorder) - 2; i >= 0; i-- {
			b := postorder[i]
			if b.immedDom == top {
				continue
			}
			in := preds(b)
			var newIdom *FlowBlock
			j := 0
			for ; j < len(in); j++ { // first processed predecessor
				newIdom = in[j]
				if newIdom.immedDom != nil {
					break
				}
			}
			for j++; j < len(in); j++ {
				rho := in[j]
				if rho.immedDom == nil {
					continue
				}
				f1, f2 := numnodes-int(rho.index), numnodes-int(newIdom.index)
				for f1 != f2 {
					for f1 < f2 {
						f1 = numnodes - int(postorder[f1].immedDom.index)
					}
					for f2 < f1 {
						f2 = numnodes - int(postorder[f2].immedDom.index)
					}
				}
				newIdom = postorder[f1]
			}
			if b.immedDom != newIdom {
				b.immedDom = newIdom
				changed = true
			}
		}
	}
	if virtualroot != nil {
		for _, bl := range bg.blocks {
			if bl.immedDom == virtualroot {
				bl.immedDom = nil
			}
		}
	} else {
		top.immedDom = nil
	}
}

// StructureLoops builds the spanning tree and dominators and returns the
// roots of the graph, entry first.
// C++ parity: block.cc BlockGraph::structureLoops (irreducible-edge
// detection is not ported) followed by calcForwardDominator.
func (bg *BlockGraph) StructureLoops() []*FlowBlock {
	rootlist := bg.FindSpanningTree()
	bg.CalcForwardDominator(rootlist)
	return rootlist
}

// OrderBlocks sorts the blocks into their final printing order.
// C++ parity: BlockGraph::orderBlocks.
func (bg *BlockGraph) OrderBlocks() {
	if len(bg.blocks) == 1 {
		return
	}
	sort.Slice(bg.blocks, func(i, j int) bool {
		return compareFinalOrder(bg.blocks[i], bg.blocks[j])
	})
}

// compareFinalOrder puts the entry block first and return blocks last;
// otherwise blocks keep index order.
// C++ parity: FlowBlock::compareFinalOrder.
func compareFinalOrder(bl1, bl2 *FlowBlock) bool {
	if bl1.index == 0 {
		return true
	}
	if bl2.index == 0 {
		return false
	}
	op1, op2 := bl1.finalLastOp(), bl2.finalLastOp()
	if op1 != nil {
		if op2 != nil {
			if op1.Code() == CPUI_RETURN && op2.Code() != CPUI_RETURN {
				return false
			} else if op1.Code() != CPUI_RETURN && op2.Code() == CPUI_RETURN {
				return true
			}
		}
		if op1.Code() == CPUI_RETURN {
			return false
		}
	} else if op2 != nil && op2.Code() == CPUI_RETURN {
		return true
	}
	return bl1.index < bl2.index
}

// finalLastOp is the op that ends control flow out of b, or nil.
// C++ parity: FlowBlock::lastOp and its BlockBasic/BlockCopy/BlockList/
// BlockCondition/BlockIf/BlockGoto/BlockMultiGoto overrides.
func (b *FlowBlock) finalLastOp() *PcodeOp {
	if bb, ok := b.Concrete().(*BlockBasic); ok {
		if bb.EmptyOp() {
			return nil
		}
		return bb.LastOp()
	}
	children := b.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	switch b.Type() {
	case BlockListType:
		return children[len(children)-1].finalLastOp()
	case BlockConditionType:
		if len(children) > 1 {
			return children[1].finalLastOp()
		}
	case BlockIfType:
		if len(children) == 1 {
			return children[0].finalLastOp()
		}
	case BlockGotoType, BlockMultiGotoType:
		return children[0].finalLastOp()
	}
	return nil
}

// MoveOutEdge retargets blold's out-edge at slot to point to blnew instead.
// The target block (blold.getOut(slot)) has its corresponding in-edge source
// changed from blold to blnew.
// C++ parity: block.cc BlockGraph::moveOutEdge
func (bg *BlockGraph) MoveOutEdge(blold *FlowBlock, slot int, blnew *FlowBlock) {
	outbl := blold.outEdges[slot].Point
	i := blold.outEdges[slot].ReverseIndex
	outbl.ReplaceInEdge(i, blnew)
}

// FinalTransform gives each control-flow structure a final chance to transform.
// C++ parity: blockaction.cc ActionStructureTransform::apply / BlockGraph::finalTransform
func (bg *BlockGraph) FinalTransform(data *Funcdata) {
	for _, bl := range bg.blocks {
		bl.finalTransform(data)
	}
}

// collectReachable lists the blocks reachable from bl, or with un set every
// block that is not.
// C++ parity: block.cc BlockGraph::collectReachable.
func (bg *BlockGraph) collectReachable(bl *FlowBlock, un bool) []*FlowBlock {
	bl.SetFlag(BlockFlagMark)
	res := []*FlowBlock{bl}
	for total := 0; total < len(res); total++ {
		for _, e := range res[total].outEdges {
			if e.Point.HasFlag(BlockFlagMark) {
				continue
			}
			e.Point.SetFlag(BlockFlagMark)
			res = append(res, e.Point)
		}
	}
	if !un {
		for _, b := range res {
			b.ClearFlag(BlockFlagMark)
		}
		return res
	}
	res = res[:0]
	for _, b := range bg.blocks {
		if b.HasFlag(BlockFlagMark) {
			b.ClearFlag(BlockFlagMark)
		} else {
			res = append(res, b)
		}
	}
	return res
}
