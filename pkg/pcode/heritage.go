package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// Heritage performs SSA construction on a Funcdata.
// Implements the Bilardi-Pingali algorithm for phi-node placement
// and Cytron et al. renaming.
// C++ parity: heritage.hh Heritage
type Heritage struct {
	fd             *Funcdata
	spaces         []*address.Space // available address spaces
	globalDisjoint LocationMap
	disjoint       TaskList
	domChild       [][]int32 // domChild[blockIndex] = child block indices
	augment        [][]int32 // augment[blockIndex] = augmented edge target indices
	heritageFlags  []uint32  // per-block flags
	depth          []int32   // dominator depth per block
	maxDepth       int32     // -1 means needs rebuild
	pass           int32
	pq             PriorityQueue
	mergeBlocks    []int32 // block indices needing phi-nodes
	infoList       []HeritageInfo
	loadGuards     []LoadGuard
	storeGuards    []LoadGuard
}

const (
	heritageBoundaryNode uint32 = 1
	heritageMarkNode     uint32 = 2
	heritageMergedNode   uint32 = 4
)

// NewHeritage creates a Heritage engine for the given Funcdata.
// spaces is the list of address spaces that may need heritage processing.
// C++ parity: heritage.cc Heritage::Heritage
func NewHeritage(fd *Funcdata, spaces []*address.Space) *Heritage {
	return &Heritage{
		fd:       fd,
		spaces:   spaces,
		maxDepth: -1,
	}
}

// ForceRestructure marks the ADT as needing rebuild.
func (h *Heritage) ForceRestructure() { h.maxDepth = -1 }

// GetPass returns the current pass number.
func (h *Heritage) GetPass() int32 { return h.pass }

// Clear resets all heritage state.
func (h *Heritage) Clear() {
	h.globalDisjoint.Clear()
	h.disjoint.Clear()
	h.domChild = nil
	h.augment = nil
	h.heritageFlags = nil
	h.depth = nil
	h.maxDepth = -1
	h.pass = 0
	h.mergeBlocks = nil
	h.infoList = nil
	h.loadGuards = nil
	h.storeGuards = nil
}

// BuildInfoList initializes per-space heritage info.
// C++ parity: heritage.cc Heritage::buildInfoList
func (h *Heritage) BuildInfoList() {
	if len(h.infoList) > 0 {
		return
	}
	for _, spc := range h.spaces {
		h.infoList = append(h.infoList, NewHeritageInfo(spc))
	}
}

// toBasic recovers the *BlockBasic from a *FlowBlock using the concrete
// back-pointer. Returns nil if the block is not a BlockBasic.
func toBasic(bl *FlowBlock) *BlockBasic {
	if bl == nil || bl.Type() != BlockBasicType {
		return nil
	}
	if bb, ok := bl.Concrete().(*BlockBasic); ok {
		return bb
	}
	return nil
}

// ---------------------------------------------------------------------------
// BuildADT -- Build Augmented Dominator Tree (Bilardi-Pingali algorithm)
// Prerequisites: graph must have RPO indices and dominator tree set.
// C++ parity: heritage.cc Heritage::buildADT
// ---------------------------------------------------------------------------

// BuildADT builds the Augmented Dominator Tree from the CFG.
func (h *Heritage) BuildADT(graph *BlockGraph) {
	n := graph.GetSize()
	if n == 0 {
		return
	}

	// 1. Build domChild from dominator tree
	h.domChild = make([][]int32, n)
	for i := 0; i < n; i++ {
		bl := graph.GetBlock(i)
		idom := bl.ImmedDom()
		if idom != nil && idom != bl {
			pidx := idom.Index()
			h.domChild[pidx] = append(h.domChild[pidx], bl.Index())
		}
	}

	// 2. Compute dominator depths via BFS from root (index 0)
	h.depth = make([]int32, n)
	for i := range h.depth {
		h.depth[i] = -1
	}
	h.depth[0] = 0
	h.maxDepth = 0
	queue := []int32{0}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := h.depth[cur] + 1
		for _, child := range h.domChild[cur] {
			h.depth[child] = d
			if d > h.maxDepth {
				h.maxDepth = d
			}
			queue = append(queue, child)
		}
	}

	// 3. Collect up-edges: for each block v, for each predecessor u,
	// if u != v.immedDom, the edge u->v is an up-edge.
	type upEdge struct {
		from, to int32
	}
	var upEdges []upEdge
	for i := 0; i < n; i++ {
		bl := graph.GetBlock(i)
		idom := bl.ImmedDom()
		for j := 0; j < bl.SizeIn(); j++ {
			pred := bl.InEdge(j).Point
			if pred != idom {
				upEdges = append(upEdges, upEdge{from: pred.Index(), to: bl.Index()})
			}
		}
	}

	// 4. Initialize flags and augment arrays
	h.heritageFlags = make([]uint32, n)
	h.augment = make([][]int32, n)

	if len(upEdges) == 0 {
		// No up-edges means no merge points needed
		return
	}

	// Build augment edges: for each up-edge (u -> v), add v to the
	// augment list of v's immediate dominator. This is a simplified
	// version of the Bilardi-Pingali algorithm sufficient for Phase 3.
	// The augment edge from idom(v) to v means "if there is a definition
	// reaching idom(v), then v needs a phi node".
	for _, ue := range upEdges {
		v := ue.to
		bl := graph.GetBlock(int(v))
		idom := bl.ImmedDom()
		if idom == nil || idom == bl {
			continue
		}
		idomIdx := idom.Index()
		h.augment[idomIdx] = append(h.augment[idomIdx], v)
	}

	// Sort and deduplicate augment edges, sort by depth (descending)
	for i := range h.augment {
		if len(h.augment[i]) > 0 {
			sort.Slice(h.augment[i], func(a, b int) bool {
				return h.depth[h.augment[i][a]] > h.depth[h.augment[i][b]]
			})
			h.augment[i] = dedupInt32(h.augment[i])
		}
	}

	// Mark boundary nodes
	for i := 0; i < n; i++ {
		if len(h.augment[i]) > 0 {
			h.heritageFlags[i] |= heritageBoundaryNode
		}
	}
}

// dedupInt32 removes adjacent duplicates from a sorted slice.
func dedupInt32(s []int32) []int32 {
	if len(s) <= 1 {
		return s
	}
	out := s[:1]
	for i := 1; i < len(s); i++ {
		if s[i] != out[len(out)-1] {
			out = append(out, s[i])
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CalcMultiequals -- determine which blocks need phi-nodes.
// C++ parity: heritage.cc Heritage::calcMultiequals
// ---------------------------------------------------------------------------

// CalcMultiequals determines which blocks need MULTIEQUAL (phi) nodes
// for the given set of write varnodes.
func (h *Heritage) CalcMultiequals(graph *BlockGraph, writes []*Varnode) {
	if h.maxDepth < 0 {
		return
	}
	h.pq.Reset(h.maxDepth)
	h.mergeBlocks = h.mergeBlocks[:0]

	// Clear mark and merged flags
	for i := range h.heritageFlags {
		h.heritageFlags[i] &^= (heritageMarkNode | heritageMergedNode)
	}

	// Seed PQ with blocks containing writes
	for _, vn := range writes {
		if vn.Def() == nil || vn.Def().Parent() == nil {
			// Input varnodes (no def) -- seed start block
			continue
		}
		bidx := vn.Def().Parent().Index()
		if bidx < 0 || int(bidx) >= len(h.depth) {
			continue
		}
		// Skip blocks unreachable from the dominator root (depth == -1).
		// C++ heritage never visits these; the ADT BFS left their depth unset.
		if h.depth[bidx] < 0 {
			continue
		}
		if h.heritageFlags[bidx]&heritageMarkNode == 0 {
			h.heritageFlags[bidx] |= heritageMarkNode
			h.pq.Insert(bidx, h.depth[bidx])
		}
	}

	// Also seed with the start block (index 0) to handle input varnodes
	if len(h.heritageFlags) > 0 && h.heritageFlags[0]&heritageMarkNode == 0 {
		h.heritageFlags[0] |= heritageMarkNode
		h.pq.Insert(0, h.depth[0])
	}

	// Process priority queue
	for !h.pq.Empty() {
		qnodeIdx := h.pq.Extract()
		h.visitIncr(qnodeIdx, qnodeIdx)
	}
}

// visitIncr recursively traverses the ADT for phi-node placement.
// C++ parity: heritage.cc Heritage::visitIncr
func (h *Heritage) visitIncr(qnodeIdx, vnodeIdx int32) {
	// Process augment edges for this node
	for _, v := range h.augment[vnodeIdx] {
		// Augment targets are sorted by depth (descending).
		if h.depth[v] <= h.depth[qnodeIdx] {
			break
		}
		if h.heritageFlags[v]&heritageMergedNode == 0 {
			h.heritageFlags[v] |= heritageMergedNode
			h.mergeBlocks = append(h.mergeBlocks, v)
		}
		if h.heritageFlags[v]&heritageMarkNode == 0 {
			h.heritageFlags[v] |= heritageMarkNode
			h.pq.Insert(v, h.depth[v])
		}
	}

	// If not a boundary node, recurse into dominator children
	if h.heritageFlags[vnodeIdx]&heritageBoundaryNode == 0 {
		for _, child := range h.domChild[vnodeIdx] {
			if h.heritageFlags[child]&heritageMarkNode == 0 {
				h.visitIncr(qnodeIdx, child)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Collect -- gather varnodes in a given address range.
// C++ parity: heritage.cc Heritage::collect (simplified)
// ---------------------------------------------------------------------------

// Collect gathers varnodes overlapping [addr, addr+size) and partitions
// them into reads (free), writes (written), and inputs.
func (h *Heritage) Collect(addr address.Address, size int32) (reads, writes, inputs []*Varnode) {
	vns := h.fd.VarnodesByRange(addr, size)
	for _, vn := range vns {
		if vn.IsInput() {
			inputs = append(inputs, vn)
		} else if vn.IsWritten() {
			writes = append(writes, vn)
		} else {
			reads = append(reads, vn)
		}
	}
	return
}

// ---------------------------------------------------------------------------
// PlaceMultiequals -- insert MULTIEQUAL ops at merge blocks.
// C++ parity: heritage.cc Heritage::placeMultiequals (inner loop)
// ---------------------------------------------------------------------------

// placeMultiequals inserts MULTIEQUAL (phi) ops for a single address range.
func (h *Heritage) placeMultiequals(graph *BlockGraph, addr address.Address, size int32,
	reads, writes, inputs []*Varnode) {

	// Set VarnodeActiveHeritage on all participants
	for _, vn := range reads {
		vn.SetActiveHeritage()
	}
	for _, vn := range writes {
		vn.SetActiveHeritage()
	}
	for _, vn := range inputs {
		vn.SetActiveHeritage()
	}

	// Determine merge blocks
	allWrites := make([]*Varnode, 0, len(writes)+len(inputs))
	allWrites = append(allWrites, writes...)
	allWrites = append(allWrites, inputs...)
	h.CalcMultiequals(graph, allWrites)

	// Insert MULTIEQUAL ops at each merge block
	for _, bidx := range h.mergeBlocks {
		bl := graph.GetBlock(int(bidx))
		bb := toBasic(bl)
		if bb == nil {
			continue
		}

		numPreds := bl.SizeIn()
		if numPreds < 2 {
			continue
		}

		// Create MULTIEQUAL op with numPreds inputs
		op := h.fd.NewOp(numPreds, addr)
		h.fd.OpSetOpcode(op, CPUI_MULTIEQUAL)

		// Create output varnode
		h.fd.NewVarnodeOut(size, addr, op)

		// Insert at beginning of block
		h.fd.OpInsertBegin(op, bb)
	}
}

// ---------------------------------------------------------------------------
// Rename -- SSA variable renaming (Cytron et al.)
// C++ parity: heritage.cc Heritage::rename
// ---------------------------------------------------------------------------

// Rename performs SSA renaming for the address range [addr, addr+size)
// starting from the graph's root block.
func (h *Heritage) Rename(graph *BlockGraph, addr address.Address, size int32) {
	if graph.GetSize() == 0 {
		return
	}

	varStack := make(map[addressKey][]*Varnode)
	startBl := graph.GetBlock(0)
	bb := toBasic(startBl)
	if bb == nil {
		return
	}
	h.renameRecurse(bb, graph, varStack, addr, size)
}

// renameRecurse performs recursive SSA renaming on a single basic block
// and its dominator children.
// C++ parity: heritage.cc Heritage::renameRecurse
func (h *Heritage) renameRecurse(bl *BlockBasic, graph *BlockGraph,
	varStack map[addressKey][]*Varnode, addr address.Address, size int32) {

	endOff := addr.Offset + uint64(size)

	// Track writes made in this block for stack restoration on exit
	type stackRecord struct {
		key     addressKey
		prevLen int
	}
	var writeList []stackRecord

	// Phase 1: Process ops in this block
	for _, op := range bl.Ops() {
		if op.Code() != CPUI_MULTIEQUAL {
			// For non-MULTIEQUAL ops: replace active heritage inputs
			for slot := 0; slot < op.NumInput(); slot++ {
				inp := op.Input(slot)
				if inp == nil || !inp.IsActiveHeritage() {
					continue
				}
				inp.ClearActiveHeritage()

				key := makeAddressKey(inp.Addr())
				stk := varStack[key]
				if len(stk) == 0 {
					// No reaching definition -- create input varnode
					newVn := h.fd.NewVarnode(inp.Size(), inp.Addr())
					h.fd.SetInputVarnode(newVn)
					varStack[key] = append(varStack[key], newVn)
					stk = varStack[key]
				}
				top := stk[len(stk)-1]
				if top != inp {
					// Replace input with top of stack
					h.fd.OpUnsetInput(op, slot)
					h.fd.OpSetInput(op, top, slot)
				}
			}
		}

		// Process output
		out := op.Output()
		if out != nil && out.IsActiveHeritage() {
			out.ClearActiveHeritage()
			key := makeAddressKey(out.Addr())
			// Only track within our address range
			if out.Space() == addr.Space &&
				out.Offset() >= addr.Offset && out.Offset() < endOff {
				writeList = append(writeList, stackRecord{
					key:     key,
					prevLen: len(varStack[key]),
				})
				varStack[key] = append(varStack[key], out)
			}
		}
	}

	// Phase 2: Fill MULTIEQUAL inputs in successor blocks
	fb := &bl.FlowBlock
	for i := 0; i < fb.SizeOut(); i++ {
		succBl := fb.OutEdge(i).Point
		succBB := toBasic(succBl)
		if succBB == nil {
			continue
		}
		// Find which input slot we correspond to in the successor
		revIdx := fb.OutRevIndex(i)

		for _, op := range succBB.Ops() {
			if op.Code() != CPUI_MULTIEQUAL {
				break // MULTIEQUALs are at the start
			}
			out := op.Output()
			if out == nil {
				continue
			}
			if out.Space() != addr.Space {
				continue
			}
			if out.Offset() < addr.Offset || out.Offset() >= endOff {
				continue
			}

			key := makeAddressKey(out.Addr())
			stk := varStack[key]
			if len(stk) == 0 {
				// No reaching definition -- create input varnode
				newVn := h.fd.NewVarnode(out.Size(), out.Addr())
				h.fd.SetInputVarnode(newVn)
				varStack[key] = append(varStack[key], newVn)
				stk = varStack[key]
			}
			top := stk[len(stk)-1]
			if revIdx < op.NumInput() {
				h.fd.OpSetInput(op, top, revIdx)
			}
		}
	}

	// Phase 3: Recurse into dominator children
	blIdx := fb.Index()
	for _, childIdx := range h.domChild[blIdx] {
		childBl := graph.GetBlock(int(childIdx))
		childBB := toBasic(childBl)
		if childBB != nil {
			h.renameRecurse(childBB, graph, varStack, addr, size)
		}
	}

	// Phase 4: Pop this block's writes from stacks
	for i := len(writeList) - 1; i >= 0; i-- {
		rec := writeList[i]
		varStack[rec.key] = varStack[rec.key][:rec.prevLen]
	}
}

// ---------------------------------------------------------------------------
// Heritage -- main entry point for SSA construction.
// C++ parity: heritage.cc Heritage::heritage (simplified for Phase 3)
// ---------------------------------------------------------------------------

// Heritage performs one pass of SSA construction on the given CFG.
// This is the main entry point.
func (h *Heritage) Heritage(graph *BlockGraph) {
	h.BuildInfoList()

	// Rebuild ADT if needed
	if h.maxDepth == -1 {
		h.BuildADT(graph)
	}

	// For each heritaged space
	for _, info := range h.infoList {
		if !info.IsHeritaged() {
			continue
		}
		if h.pass < info.Delay {
			continue
		}

		// Scan all varnodes in this space
		vns := h.fd.VarnodesBySpace(info.Space)
		if len(vns) == 0 {
			continue
		}

		// Build task list: group varnodes into address ranges
		h.disjoint.Clear()
		for _, vn := range vns {
			flags := uint32(0)
			_, code := h.globalDisjoint.Add(vn.Addr(), vn.Size(), h.pass)
			switch code {
			case 0:
				flags = MemRangeNewAddresses
			case 1:
				flags = MemRangeNewAddresses | MemRangeOldAddresses
			case 2:
				flags = MemRangeOldAddresses
			}
			h.disjoint.Add(vn.Addr(), vn.Size(), flags)
		}

		// Place multiequals and rename for each range
		for i := 0; i < h.disjoint.Len(); i++ {
			task := h.disjoint.Get(i)
			reads, writes, inputs := h.Collect(task.Addr, task.Size)
			if len(reads) == 0 && len(writes) == 0 && len(inputs) == 0 {
				continue
			}
			h.placeMultiequals(graph, task.Addr, task.Size, reads, writes, inputs)
			h.Rename(graph, task.Addr, task.Size)
		}
	}

	h.disjoint.Clear()
	h.pass++
}
