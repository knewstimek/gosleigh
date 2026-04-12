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

// FindSpanningTree performs a DFS from blocks[0] and assigns RPO indices.
// Edges are labeled as tree, forward, cross, or back.
// C++ parity: block.cc BlockGraph::findSpanningTree
func (bg *BlockGraph) FindSpanningTree() {
	if len(bg.blocks) == 0 {
		return
	}

	n := len(bg.blocks)
	// Clear all visit counts and edge labels.
	for _, bl := range bg.blocks {
		bl.visitCount = 0
		bl.index = -1
		for i := range bl.outEdges {
			bl.outEdges[i].Label &^= (EdgeFlagTree | EdgeFlagForward | EdgeFlagCross | EdgeFlagBack)
		}
		for i := range bl.inEdges {
			bl.inEdges[i].Label &^= (EdgeFlagTree | EdgeFlagForward | EdgeFlagCross | EdgeFlagBack)
		}
	}

	var timestamp int32 = 1
	rpoCounter := int32(n - 1)

	// finished[block] = true when DFS post-visit is done.
	type stackEntry struct {
		block   *FlowBlock
		edgeIdx int // next outEdge to visit
	}

	stack := []stackEntry{{block: bg.blocks[0], edgeIdx: 0}}
	bg.blocks[0].visitCount = timestamp
	timestamp++

	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		bl := top.block

		if top.edgeIdx >= bl.SizeOut() {
			// Post-visit: assign RPO index.
			bl.index = rpoCounter
			rpoCounter--
			stack = stack[:len(stack)-1]
			continue
		}

		edgeIdx := top.edgeIdx
		top.edgeIdx++
		target := bl.outEdges[edgeIdx].Point

		if target.visitCount == 0 {
			// Tree edge.
			bl.SetOutEdgeFlag(edgeIdx, EdgeFlagTree)
			target.visitCount = timestamp
			timestamp++
			stack = append(stack, stackEntry{block: target, edgeIdx: 0})
		} else if target.index == -1 {
			// Target is on stack (ancestor) -- back edge.
			bl.SetOutEdgeFlag(edgeIdx, EdgeFlagBack)
		} else if target.visitCount > bl.visitCount {
			// Target was discovered after bl -- forward edge.
			bl.SetOutEdgeFlag(edgeIdx, EdgeFlagForward)
		} else {
			// Cross edge.
			bl.SetOutEdgeFlag(edgeIdx, EdgeFlagCross)
		}
	}

	// Re-order bg.blocks to match RPO indices, mirroring C++ findSpanningTree's
	// "list = rpostorder" assignment. This ensures GetBlock(i) returns the block
	// with RPO index i, which Heritage and CalcForwardDominator rely on.
	// Unreachable blocks (index == -1) are placed at the end.
	// C++ parity: block.cc BlockGraph::findSpanningTree (list = rpostorder, line 1135)
	rpostorder := make([]*FlowBlock, n)
	for _, bl := range bg.blocks {
		if bl.index >= 0 && int(bl.index) < n {
			rpostorder[bl.index] = bl
		}
	}
	// Compact: put nil slots (unreachable) after reachable blocks.
	j := 0
	for _, bl := range rpostorder {
		if bl != nil {
			rpostorder[j] = bl
			j++
		}
	}
	// Append unreachable blocks at the end.
	for _, bl := range bg.blocks {
		if bl.index < 0 {
			rpostorder[j] = bl
			j++
		}
	}
	bg.blocks = rpostorder
}

// CalcForwardDominator computes immediate dominators using the
// Cooper-Harvey-Kennedy iterative algorithm. Blocks must have RPO indices
// set (from FindSpanningTree).
// C++ parity: block.cc BlockGraph::calcForwardDominator
func (bg *BlockGraph) CalcForwardDominator() {
	if len(bg.blocks) == 0 {
		return
	}

	// Sort blocks by RPO index for iteration.
	sorted := make([]*FlowBlock, len(bg.blocks))
	copy(sorted, bg.blocks)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].index < sorted[j].index
	})

	start := sorted[0]
	start.immedDom = start

	changed := true
	for changed {
		changed = false
		for _, bl := range sorted {
			if bl == start {
				continue
			}
			var newIdom *FlowBlock
			for i := 0; i < bl.SizeIn(); i++ {
				pred := bl.inEdges[i].Point
				if pred.immedDom == nil {
					continue
				}
				if newIdom == nil {
					newIdom = pred
				} else {
					newIdom = intersectDom(newIdom, pred)
				}
			}
			if newIdom != nil && bl.immedDom != newIdom {
				bl.immedDom = newIdom
				changed = true
			}
		}
	}
}

// intersectDom walks both sides toward the root using RPO index comparison.
func intersectDom(b1, b2 *FlowBlock) *FlowBlock {
	for b1 != b2 {
		for b1.index > b2.index {
			b1 = b1.immedDom
		}
		for b2.index > b1.index {
			b2 = b2.immedDom
		}
	}
	return b1
}

// StructureLoops calls FindSpanningTree then CalcForwardDominator.
// C++ parity: block.cc BlockGraph::structureLoops
func (bg *BlockGraph) StructureLoops() {
	bg.FindSpanningTree()
	bg.CalcForwardDominator()
}

// OrderBlocks sorts the blocks slice by RPO index.
func (bg *BlockGraph) OrderBlocks() {
	sort.Slice(bg.blocks, func(i, j int) bool {
		return bg.blocks[i].index < bg.blocks[j].index
	})
}
