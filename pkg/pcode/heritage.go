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
	// proto is the optional calling-convention model for CALL-site INDIRECT guard
	// insertion.  nil means no guardCalls pass (leaf-function safe default).
	// C++ parity: Heritage uses fd->getFuncProto()->getModel() for guardCalls.
	proto   *ProtoModel
	guarded map[callGuardKey]bool // deduplicate (callOp, addr) guard insertions
}

// callGuardKey uniquely identifies a guarded (callOp, register-offset, size) triple.
type callGuardKey struct {
	callOp *PcodeOp
	offset uint64
	size   int32
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

// WithProtoModel attaches a calling-convention model so that Heritage inserts
// INDIRECT ops at CALL sites during SSA construction (guardCalls pass).
// Returns h for chaining.  Passing nil is safe and disables guardCalls.
// C++ parity: Heritage stores fd->getFuncProto()->getModel() internally;
// we accept it explicitly to avoid coupling Heritage to FuncProto.
func (h *Heritage) WithProtoModel(pm *ProtoModel) *Heritage {
	h.proto = pm
	return h
}

// guardCalls inserts INDIRECT (or INDIRECT_CREATION) ops immediately before
// each CALL/CALLIND op to model the call-site side-effect on the register
// range (sp, offset, size).  Only register-space ranges are guarded; stack
// and other spaces are ignored (stack side effects are handled separately).
//
// Effect classification uses h.proto.EffectOnRegister:
//   - EffectKilledByCall  -> newIndirectCreation  (caller-saved: EAX/ECX/EDX)
//   - EffectUnaffected    -> no INDIRECT           (callee-saved: EBX/ESI/EDI/EBP)
//   - EffectUnknown       -> newIndirectOp         (unknown: model conservatively)
//
// h.guarded deduplicates (callOp, offset, size) across multiple Heritage()
// calls so the same INDIRECT is not inserted twice.
//
// C++ parity: heritage.cc Heritage::guardCalls (register-space subset of lines 1443-1527)
func (h *Heritage) guardCalls(sp *address.Space, offset uint64, size int32) {
	if h.proto == nil {
		return
	}
	// Only register space is guarded here; stack side-effects handled elsewhere.
	if sp.Kind != address.SpaceKindProcessor || sp.Name != "register" {
		return
	}
	if h.guarded == nil {
		h.guarded = make(map[callGuardKey]bool)
	}
	for _, op := range h.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() != CPUI_CALL && op.Code() != CPUI_CALLIND {
			continue
		}
		key := callGuardKey{callOp: op, offset: offset, size: size}
		if h.guarded[key] {
			continue
		}
		h.guarded[key] = true
		switch h.proto.EffectOnRegister(offset) {
		case EffectUnaffected:
			// Callee-saved register: no INDIRECT needed; pre-call value flows through.
		case EffectKilledByCall:
			// Caller-saved register (e.g. EAX, ECX, EDX): call overwrites it.
			h.fd.NewIndirectCreation(op, sp, offset, size)
		default: // EffectUnknown
			// Conservative: call may or may not modify; model as read-modify.
			h.fd.NewIndirectOp(op, sp, offset, size)
		}
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

		// Create output varnode and mark it for heritage tracking.
		// The output must be ActiveHeritage so that renameRecurse pushes it
		// onto varStack when visiting this MULTIEQUAL, allowing subsequent
		// ops in the same block to receive the phi output as their renamed input.
		// C++ parity: Heritage::placeMultiequals sets activeHeritage on the new vn.
		out := h.fd.NewVarnodeOut(size, addr, op)
		out.SetActiveHeritage()

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
			// For non-MULTIEQUAL ops: replace inputs in our address range with the
			// current reaching definition from varStack.
			for slot := 0; slot < op.NumInput(); slot++ {
				inp := op.Input(slot)
				if inp == nil {
					continue
				}
				// Only process inputs in our address range.
				// Multiple HeritageRange passes run sequentially over different slots;
				// this range check keeps each pass scoped to its own slot.
				// C++ parity: Ghidra runs a single rename over all disjoint ranges at once;
				// we approximate by scoping each HeritageRange pass to its own address range.
				if inp.Space() != addr.Space ||
					inp.Offset() < addr.Offset || inp.Offset() >= endOff {
					continue
				}
				// Skip varnodes that are already SSA-renamed definitions (IsWritten).
				// A written varnode is the output of a COPY/MULTIEQUAL in this pass --
				// it is already on varStack and does not need renaming as a use.
				// C++ parity: isHeritageKnown() filters out insert/constant/annotation varnodes
				// from the free set before Heritage processes them.
				if inp.IsWritten() {
					continue
				}
				// Clear ActiveHeritage flag to avoid double-processing if this varnode
				// is shared across multiple ops (e.g. multiple LOADs with same fresh input vn).
				// We do NOT require IsActiveHeritage() here -- for shared input varnodes only
				// the first use has the flag set; subsequent uses have it cleared but still
				// need renaming. The address range check above ensures we only touch our slot.
				if inp.IsActiveHeritage() {
					inp.ClearActiveHeritage()
				}

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
// refinedSubTaskSize computes the sub-task granularity for a merged address range.
// Returns the max varnode size that starts exactly at addr.Offset; if that max is
// smaller than size, the caller should split the task into sub-tasks of that size.
// If all varnodes at addr.Offset already fill the full range (max >= size), returns
// size unchanged (no split needed).
// C++ parity: heritage.cc Heritage::refinement -- condition max_vn < task.size.
func refinedSubTaskSize(reads, writes, inputs []*Varnode, addr address.Address, size int32) int32 {
	maxSz := int32(0)
	for _, vn := range reads {
		if vn.Offset() == addr.Offset && vn.Size() > maxSz {
			maxSz = vn.Size()
		}
	}
	for _, vn := range writes {
		if vn.Offset() == addr.Offset && vn.Size() > maxSz {
			maxSz = vn.Size()
		}
	}
	for _, vn := range inputs {
		if vn.Offset() == addr.Offset && vn.Size() > maxSz {
			maxSz = vn.Size()
		}
	}
	if maxSz == 0 || maxSz >= size {
		return size
	}
	return maxSz
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

		// Place multiequals and rename for each range.
		// Simplified Heritage::refinement(): when the max varnode size at the task
		// start offset is smaller than the task size (caused by adjacent-register
		// merging in TaskList.Add), split the task into sub-tasks so each register
		// gets its own correctly-sized phi.  Without splitting, renameRecurse would
		// rename a 4-byte EAX read to a 12-byte phi -- wrong size for downstream ops
		// (RuleSignForm, IDIV, etc.) and causes incorrect copy propagation.
		// C++ parity: heritage.cc Heritage::refinement (simplified -- no PIECE/SUBPIECE
		// physical splits; x86 register varnodes don't straddle sub-task boundaries).
		for i := 0; i < h.disjoint.Len(); i++ {
			task := h.disjoint.Get(i)
			// Insert INDIRECT guards for call-site side-effects on this range BEFORE
			// Collect so the INDIRECT output varnodes appear as written SSA definitions.
			// C++ parity: heritage.cc Heritage::heritage -> guard -> guardCalls
			h.guardCalls(info.Space, task.Addr.Offset, task.Size)
			reads, writes, inputs := h.Collect(task.Addr, task.Size)
			if len(reads) == 0 && len(writes) == 0 && len(inputs) == 0 {
				continue
			}
			subSize := refinedSubTaskSize(reads, writes, inputs, task.Addr, task.Size)
			if subSize < task.Size {
				for off := int32(0); off < task.Size; off += subSize {
					subAddr := task.Addr
					subAddr.Offset += uint64(off)
					curSize := subSize
					if off+curSize > task.Size {
						curSize = task.Size - off
					}
					subR, subW, subI := h.Collect(subAddr, curSize)
					if len(subR)+len(subW)+len(subI) == 0 {
						continue
					}
					h.placeMultiequals(graph, subAddr, curSize, subR, subW, subI)
					h.Rename(graph, subAddr, curSize)
				}
			} else {
				h.placeMultiequals(graph, task.Addr, task.Size, reads, writes, inputs)
				h.Rename(graph, task.Addr, task.Size)
			}
		}
	}

	h.disjoint.Clear()
	h.pass++
	h.AnnotateFloatTypes()
}

// HeritageRange performs SSA construction for a single explicit address range
// [addr, addr+size). This is used by callers (e.g. ActionStackPtrFlow) that need
// to run Heritage on individual stack slots without merging adjacent ranges.
//
// Unlike Heritage(), this method:
//   - Builds the ADT if not already built (requires the graph to have RPO + idoms set).
//   - Processes exactly one range, bypassing the TaskList merging logic.
//   - Does NOT increment the pass counter or run AnnotateFloatTypes.
//
// The caller is responsible for calling this once per distinct stack slot.
// C++ parity: approximates Heritage::heritage() restricted to one slot; Ghidra
// avoids this problem by running ActionStackPtrFlow before the first Heritage pass.
func (h *Heritage) HeritageRange(graph *BlockGraph, addr address.Address, size int32) {
	if h.maxDepth == -1 {
		h.BuildADT(graph)
	}
	// Guard call sites for this range before Collect picks up SSA definitions.
	// C++ parity: heritage.cc Heritage::heritage -> guard -> guardCalls
	h.guardCalls(addr.Space, addr.Offset, size)
	reads, writes, inputs := h.Collect(addr, size)
	if len(reads) == 0 && len(writes) == 0 && len(inputs) == 0 {
		return
	}
	h.placeMultiequals(graph, addr, size, reads, writes, inputs)
	h.Rename(graph, addr, size)
}

// AnnotateFloatTypes marks output varnodes of FLOAT_* ops with float type.
// This is a post-Heritage additive pass -- it does not change SSA placement or renaming.
// C++ parity: heritage.cc Heritage::analyzeNewVarnodes (simplified float subset)
func (h *Heritage) AnnotateFloatTypes() {
	for _, op := range h.fd.GetPcodeOpBank().AllOps() {
		if op.IsDead() {
			continue
		}
		if !isFloatOpcode(op.Code()) {
			continue
		}
		out := op.Output()
		if out == nil {
			continue
		}
		// Determine float size from output varnode size.
		// Comparison ops (FLOAT_EQUAL etc.) produce size-1 boolean outputs --
		// those fall through the default case and are intentionally skipped.
		sz := out.Size()
		var dt Datatype
		switch sz {
		case 4:
			dt = NewBase(4, TYPE_FLOAT, "float")
		case 8:
			dt = NewBase(8, TYPE_FLOAT, "double")
		default:
			continue // unusual float size or boolean comparison result, skip
		}
		SetVarnodeType(out, dt)
	}
}

// ---------------------------------------------------------------------------
// Heritage::guard / protectFreeStores / buildRefinement / heritageTree wrappers
// Ported from heritage.cc to give ActionHeritage a stable API surface.
// These wrappers keep parity with the C++ entry points without rewriting the
// internal pipeline (which already lives in Heritage()/HeritageRange()).
// ---------------------------------------------------------------------------

// Guard inserts INDIRECT/INDIRECT_CREATION ops at CALL sites and marks the
// reads/writes of the given address range with ActiveHeritage.  This is the
// outer entry that C++ Heritage::placeMultiequals calls before constructing
// MULTIEQUAL nodes.
//
// The current Go pipeline performs the call-site guard (guardCalls) and the
// ActiveHeritage marking inline inside placeMultiequals; Guard exposes the
// same effect as a separate callable for code paths (ActionHeritage,
// stack-pointer flow refinement) that need to pre-guard a slot.
//
// addIndirects mirrors the C++ flag of the same name -- when false, only the
// read/write flag bookkeeping runs.
//
// C++ parity: heritage.cc Heritage::guard (lines 1156-1199)
func (h *Heritage) Guard(addr address.Address, size int32, addIndirects bool,
	reads, writes, inputs []*Varnode) {

	for _, vn := range reads {
		vn.SetActiveHeritage()
	}
	for _, vn := range writes {
		vn.SetActiveHeritage()
	}
	for _, vn := range inputs {
		vn.SetActiveHeritage()
	}
	if !addIndirects {
		return
	}
	// Only the call-site guard is wired in Go; guardStores/guardLoads/
	// guardReturns are not yet ported (see heritage.cc lines 1538-1652).
	// TODO C++ parity: port Heritage::guardStores, guardLoads, guardReturns.
	h.guardCalls(addr.Space, addr.Offset, size)
}

// ProtectFreeStores walks all CPUI_STORE ops whose pointer ultimately resolves
// to a free Varnode in the given space and marks them as spacebase STOREs so
// that subsequent SSA construction treats them as aliasing the stack/global
// slot rather than as opaque memory writes.
//
// The returned slice contains the STOREs that were marked; the second return
// value is true when at least one new STORE was added (matches the C++ bool
// return that signals "rerun heritage").
//
// C++ parity: heritage.cc Heritage::protectFreeStores (lines 944-972)
func (h *Heritage) ProtectFreeStores(spc *address.Space) ([]*PcodeOp, bool) {
	var freeStores []*PcodeOp
	hasNew := false
	for _, op := range h.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() != CPUI_STORE {
			continue
		}
		if op.NumInput() < 2 {
			continue
		}
		vn := op.Input(1)
		// Walk through trivial COPY / INT_ADD-with-constant chains to find the
		// underlying base.  This mirrors the inner while-loop in C++.
		for vn != nil && vn.IsWritten() {
			defOp := vn.Def()
			if defOp == nil {
				break
			}
			code := defOp.Code()
			if code == CPUI_COPY {
				vn = defOp.Input(0)
				continue
			}
			if code == CPUI_INT_ADD && defOp.NumInput() == 2 &&
				defOp.Input(1) != nil && defOp.Input(1).IsConstant() {
				vn = defOp.Input(0)
				continue
			}
			break
		}
		if vn == nil {
			continue
		}
		if vn.IsFree() && vn.Space() == spc {
			// Mark op as spacebase STORE.  Funcdata.opMarkSpacebasePtr is not
			// yet ported as a public method; until then we set the flag bit
			// directly via the op's helper.  The flag value matches the C++
			// PcodeOp::spacebase_ptr constant.
			// TODO C++ parity: add Funcdata.OpMarkSpacebasePtr wrapper.
			op.SetFlag(PcodeOpSpacebasePtr)
			freeStores = append(freeStores, op)
			hasNew = true
		}
	}
	return freeStores, hasNew
}

// BuildRefinement returns a per-byte refinement array for the given address
// range and varnode list.  Each non-zero entry refine[i] indicates the start
// of a sub-element of size (refine[i+0..]) inside the range -- callers split
// the merged range into these sub-tasks before placing MULTIEQUAL ops.
//
// The output array has length size+1 (the C++ code allocates size+1 entries
// to make the boundary at the end terminate the final element cleanly).
//
// C++ parity: heritage.cc Heritage::buildRefinement (lines 1704-1714)
func (h *Heritage) BuildRefinement(addr address.Address, size int32, vnlist []*Varnode) []int32 {
	refine := make([]int32, size+1)
	for _, vn := range vnlist {
		if vn == nil {
			continue
		}
		curaddr := vn.Addr()
		if curaddr.Space != addr.Space {
			continue
		}
		if curaddr.Offset < addr.Offset {
			continue
		}
		diff := int32(curaddr.Offset - addr.Offset)
		sz := vn.Size()
		if diff < 0 || diff+sz > size {
			continue
		}
		refine[diff] = 1
		refine[diff+sz] = 1
	}
	return refine
}

// HeritageTree is the public alias for the SSA tree-building pass.  It
// matches the C++ method name Heritage::heritage; the existing Heritage()
// method on this type is kept for callers that already use it.
//
// C++ parity: heritage.cc Heritage::heritage (lines 2663-2778)
func (h *Heritage) HeritageTree(graph *BlockGraph) {
	h.Heritage(graph)
}

// PlaceMultiEquals exposes the C++ Heritage::placeMultiequals entry point.
// The Go pipeline already invokes the equivalent logic from inside
// Heritage(); this wrapper lets ActionHeritage call it directly when it
// only needs the MULTIEQUAL placement step for an explicit address range.
//
// C++ parity: heritage.cc Heritage::placeMultiequals (lines 2599-2645)
func (h *Heritage) PlaceMultiEquals(graph *BlockGraph, addr address.Address, size int32,
	reads, writes, inputs []*Varnode) {
	h.placeMultiequals(graph, addr, size, reads, writes, inputs)
}

// isFloatOpcode returns true for opcodes that compute floating-point results.
func isFloatOpcode(code OpCode) bool {
	switch code {
	case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS,
		CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB,
		CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT,
		CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT,
		CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
		return true
	}
	return false
}
