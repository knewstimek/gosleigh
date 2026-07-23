package pcode

import (
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
	idomIdx        []int32   // idomIdx[blockIndex] = immediate dominator index (-1 for root)
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
		// Skip guarding a range the call already assigns as its output: once
		// return-value recovery (ActionActiveReturn) has moved the return register
		// to be the CALL op's output, re-heritage must not re-guard that same range
		// with an INDIRECT -- doing so shadows the call output and drops the
		// RETURN's reference to it. C++ parity: heritage.cc Heritage::guardCalls
		// (the isAssignment guard, lines 1453-1456).
		if out := op.Output(); out != nil && out.Addr().Space == sp &&
			out.Addr().Offset == offset && out.Size() == size {
			continue
		}
		// Register an output (return-value) trial when the call is recovering its
		// output and this range fits its return storage. This runs independently of
		// the INDIRECT dedup below (guarded by whichTrial) so the trial is picked up
		// even on a re-heritage pass after the INDIRECT-creation already exists --
		// ActionActiveReturn matches trials to those INDIRECT ops by cause-op, not
		// by insertion order. C++ parity: heritage.cc Heritage::guardCalls
		// (isOutputActive block, lines 1469-1485; contained_by overlap guard unported).
		if fc := h.fd.callSpecsForOp(op); fc != nil && fc.IsOutputActive() {
			active := fc.GetActiveOutput()
			addr := address.Address{Space: sp, Offset: offset}
			switch fc.CharacterizeAsOutput(addr, size) {
			case retOutNoContainment:
				// No overlap with the return register; not an output candidate.
			case retOutContainedBy:
				// TODO known mismatch: tryOutputOverlapGuard (range larger than the
				// output register) is not ported; the exact-size register-output
				// path below covers the current call-return-carrier corpus.
			default: // retOutOther: range fits the return storage
				if active != nil && active.WhichTrial(addr, size) < 0 {
					active.RegisterTrial(addr, size)
				}
			}
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

	// Cache immediate-dominator indices for visitIncr's ancestor test.
	h.idomIdx = make([]int32, n)
	for i := 0; i < n; i++ {
		idom := graph.GetBlock(i).ImmedDom()
		if idom == nil || idom == graph.GetBlock(i) {
			h.idomIdx[i] = -1
		} else {
			h.idomIdx[i] = idom.Index()
		}
	}

	h.heritageFlags = make([]uint32, n)
	h.augment = make([][]int32, n)

	// 3. Collect up-edges and the b[]/t[] counters of the Bilardi-Pingali ADT.
	// An edge u->v is an up-edge when u is not the immediate dominator of v.
	// b[u] counts up-edges leaving u; t[x] counts up-edges whose target is a
	// dominator-tree child of x. C++ parity: heritage.cc Heritage::buildADT
	// (2339-2353) -- do NOT simplify to "augment at idom(v)": that misses phis
	// at merge blocks whose idom is an intermediate (non-entry, non-write) block.
	a := make([]int32, n)
	b := make([]int32, n)
	t := make([]int32, n)
	z := make([]int32, n)
	var upstart, upend []int32
	for i := 0; i < n; i++ {
		for _, vIdx := range h.domChild[i] {
			v := graph.GetBlock(int(vIdx))
			for k := 0; k < v.SizeIn(); k++ {
				u := v.InEdge(k).Point
				if u != v.ImmedDom() {
					upstart = append(upstart, u.Index())
					upend = append(upend, vIdx)
					b[u.Index()]++
					t[i]++
				}
			}
		}
	}

	// 4. Compute a[], z[] and boundary nodes bottom-up over the dominator tree.
	// A node is a boundary node when it is a leaf or z[i] > a[i]+1. Children have
	// larger RPO indices than their idom, so a high-to-low sweep visits children
	// first. C++ parity: heritage.cc Heritage::buildADT (2354-2367).
	for i := n - 1; i >= 0; i-- {
		var k, l int32
		for _, c := range h.domChild[i] {
			k += a[c]
			l += z[c]
		}
		a[i] = b[i] - t[i] + k
		z[i] = 1 + l
		if len(h.domChild[i]) == 0 || z[i] > a[i]+1 {
			h.heritageFlags[i] |= heritageBoundaryNode
			z[i] = 1
		}
	}

	// 5. Re-purpose z[] as the "next boundary ancestor" skip pointer used to walk
	// augment edges up the dominator tree. C++ parity: buildADT (2368-2375).
	z[0] = -1
	for i := 1; i < n; i++ {
		j := h.idomIdx[i]
		if j >= 0 && h.heritageFlags[j]&heritageBoundaryNode != 0 {
			z[i] = j
		} else if j >= 0 {
			z[i] = z[j]
		} else {
			z[i] = -1
		}
	}

	// 6. Attach each up-edge target v to augment[k] for every k on the z-chain
	// from the up-edge source up to (but not including) idom(v). This is the
	// step the previous simplification dropped. C++ parity: buildADT (2376-2384).
	for e := range upstart {
		v := upend[e]
		j := h.idomIdx[v]
		k := upstart[e]
		for j < k {
			h.augment[k] = append(h.augment[k], v)
			k = z[k]
			if k < 0 {
				break
			}
		}
	}
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
	// Process augment edges for this node. An augment target v yields a phi only
	// when idom(v) is a strict ancestor of qnode; augment[] is built in ascending
	// idom-index order so we can stop at the first non-qualifying entry.
	// C++ parity: heritage.cc Heritage::visitIncr (2405-2419) -- the test is on the
	// idom index, not dominator depth (equal-depth siblings would be mis-skipped).
	for _, v := range h.augment[vnodeIdx] {
		if h.idomIdx[v] >= qnodeIdx {
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
		// Skip write-masked Varnodes: these are the small original reads/writes
		// that normalizeReadSize/normalizeWriteSize replaced with full-range pieces.
		// C++ parity: heritage.cc Heritage::collect (the !vn->isWriteMask() guard).
		if vn.HasAddlFlags(VarnodeWriteMask) {
			continue
		}
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

// normalizeReadSize replaces a read Varnode smaller than the heritage range with a
// SUBPIECE of a new full-range Varnode. The original (small) read keeps its reading
// op but is redefined as SUBPIECE(big, overlap) and write-masked; the returned
// full-size Varnode is the new free read that participates in renaming. This keeps
// every read in a range at the range size so SSA renaming (offset-keyed) does not
// collide a sub-register read (EAX) with its containing super-register def (RAX).
// C++ parity: heritage.cc Heritage::normalizeReadSize.
func (h *Heritage) normalizeReadSize(vn *Varnode, op *PcodeOp, addr address.Address, size int32) *Varnode {
	newop := h.fd.NewOp(2, op.Addr())
	h.fd.OpSetOpcode(newop, CPUI_SUBPIECE)
	vn1 := h.fd.NewVarnode(size, addr)
	overlap := vn.OverlapAddr(addr, size)
	if overlap < 0 {
		overlap = 0
	}
	vn2 := h.fd.NewConstant(int32(addr.Space.AddrSize), uint64(overlap))
	h.fd.OpSetInput(newop, vn1, 0)
	h.fd.OpSetInput(newop, vn2, 1)
	h.fd.OpSetOutput(newop, vn) // old vn is no longer a free read
	vn.SetAddlFlags(VarnodeWriteMask)
	h.fd.OpInsertBefore(newop, op)
	return vn1 // new free read of uniform size
}

// normalizeWriteSize replaces a written Varnode smaller than the heritage range with
// a full-range Varnode built by concatenating (CPUI_PIECE) the original value with
// freshly read pieces covering the rest of the range. The original (small) write
// keeps its defining op but is write-masked; the returned full-size Varnode is the
// new write that participates in renaming. C++ parity: heritage.cc
// Heritage::normalizeWriteSize (CALL-effect newIndirectCreation path unported --
// callers skip CALL-defined writes).
func (h *Heritage) normalizeWriteSize(vn *Varnode, addr address.Address, size int32) *Varnode {
	def := vn.Def()
	overlap := vn.OverlapAddr(addr, size)
	if overlap < 0 {
		overlap = 0
	}
	mostsigsize := size - (int32(overlap) + vn.Size())
	addrSize := int32(addr.Space.AddrSize)
	bigEndian := addr.Space.BigEndian

	var mostvn, leastvn, midvn, bigout *Varnode

	if mostsigsize != 0 {
		pieceaddr := addr
		if !bigEndian {
			pieceaddr.Offset += uint64(int32(overlap) + vn.Size())
		}
		newop := h.fd.NewOp(2, def.Addr())
		mostvn = h.fd.NewVarnodeOut(mostsigsize, pieceaddr, newop)
		big := h.fd.NewVarnode(size, addr) // new full-range read for the missing piece
		big.SetActiveHeritage()
		h.fd.OpSetOpcode(newop, CPUI_SUBPIECE)
		h.fd.OpSetInput(newop, big, 0)
		h.fd.OpSetInput(newop, h.fd.NewConstant(addrSize, uint64(int32(overlap)+vn.Size())), 1)
		h.fd.OpInsertBefore(newop, def)
	}
	if overlap != 0 {
		pieceaddr := addr
		if bigEndian {
			pieceaddr.Offset += uint64(size - int32(overlap))
		}
		newop := h.fd.NewOp(2, def.Addr())
		leastvn = h.fd.NewVarnodeOut(int32(overlap), pieceaddr, newop)
		big := h.fd.NewVarnode(size, addr)
		big.SetActiveHeritage()
		h.fd.OpSetOpcode(newop, CPUI_SUBPIECE)
		h.fd.OpSetInput(newop, big, 0)
		h.fd.OpSetInput(newop, h.fd.NewConstant(addrSize, 0), 1)
		h.fd.OpInsertBefore(newop, def)
	}
	if overlap != 0 {
		newop := h.fd.NewOp(2, def.Addr())
		midAddr := addr
		if bigEndian {
			midAddr = vn.Addr()
		}
		midvn = h.fd.NewVarnodeOut(int32(overlap)+vn.Size(), midAddr, newop)
		h.fd.OpSetOpcode(newop, CPUI_PIECE)
		h.fd.OpSetInput(newop, vn, 0)      // most significant part
		h.fd.OpSetInput(newop, leastvn, 1) // least significant
		h.fd.OpInsertAfter(newop, def)
	} else {
		midvn = vn
	}
	if mostsigsize != 0 {
		newop := h.fd.NewOp(2, def.Addr())
		bigout = h.fd.NewVarnodeOut(size, addr, newop)
		h.fd.OpSetOpcode(newop, CPUI_PIECE)
		h.fd.OpSetInput(newop, mostvn, 0)
		h.fd.OpSetInput(newop, midvn, 1)
		h.fd.OpInsertAfter(newop, midvn.Def())
	} else {
		bigout = midvn
	}
	vn.SetAddlFlags(VarnodeWriteMask)
	return bigout // replace small write with full-range write
}

// normalizeRange brings every sub-range read/write in [addr,addr+size) up to the
// range size (via SUBPIECE/PIECE), so SSA renaming sees uniform-size participants.
// Returns the updated read/write lists with small Varnodes replaced by their
// full-range pieces. C++ parity: the read/write normalization loops in
// Heritage::guard (heritage.cc 1164-1182).
func (h *Heritage) normalizeRange(addr address.Address, size int32, reads, writes []*Varnode) ([]*Varnode, []*Varnode) {
	needNorm := false
	for _, vn := range reads {
		if vn.Size() < size {
			needNorm = true
			break
		}
	}
	if !needNorm {
		for _, vn := range writes {
			if vn.Size() < size {
				needNorm = true
				break
			}
		}
	}
	if !needNorm {
		return reads, writes
	}
	newReads := make([]*Varnode, 0, len(reads))
	for _, vn := range reads {
		if vn.Size() < size {
			op := vn.LoneDescend()
			if op == nil {
				newReads = append(newReads, vn)
				continue
			}
			vn = h.normalizeReadSize(vn, op, addr, size)
		}
		newReads = append(newReads, vn)
	}
	newWrites := make([]*Varnode, 0, len(writes))
	for _, vn := range writes {
		if vn.Size() < size {
			if def := vn.Def(); def == nil || def.IsCall() {
				// CALL-effect newIndirectCreation path is not ported; leave as-is.
				newWrites = append(newWrites, vn)
				continue
			}
			vn = h.normalizeWriteSize(vn, addr, size)
		}
		newWrites = append(newWrites, vn)
	}
	return newReads, newWrites
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
					// No reaching definition: reuse an existing input if one was already
					// created by a prior HeritageRange call for an overlapping slot.
					// C++ parity: VarnodeBank::xref deduplicates by replacing new varnodes
					// with pre-existing ones at the same (addr, size); Gosleigh lacks that
					// deduplication, so we check explicitly before creating a new input.
					if existing := h.fd.FindVarnodeInput(inp.Size(), inp.Addr()); existing != nil {
						varStack[key] = append(varStack[key], existing)
					} else {
						newVn := h.fd.NewVarnode(inp.Size(), inp.Addr())
						h.fd.SetInputVarnode(newVn)
						varStack[key] = append(varStack[key], newVn)
					}
					stk = varStack[key]
				}
				top := stk[len(stk)-1]
				// INDIRECTs and their cause op really happen AT THE SAME TIME: if the
				// top of the stack is the output of an INDIRECT whose input(1) refers
				// back to the op we are currently visiting, that INDIRECT models an
				// effect that has not "happened" yet from op's own point of view (e.g.
				// a CALLIND reading its own target register, where the INDIRECT for
				// that register's post-call value is inserted just before the call).
				// Skip past it to the value beneath it on the stack, synthesizing a
				// fresh input if the INDIRECT's output is all there is.
				// C++ parity: heritage.cc Heritage::renameRecurse lines 2506-2517.
				if top.IsWritten() && top.Def() != nil && top.Def().Code() == CPUI_INDIRECT &&
					top.Def().NumInput() >= 2 {
					if cause := top.Def().Input(1).GetIndirectCause(); cause == op {
						if len(stk) == 1 {
							fresh := h.fd.NewVarnode(inp.Size(), inp.Addr())
							fresh = h.fd.SetInputVarnode(fresh)
							stk = append([]*Varnode{fresh}, stk...)
							varStack[key] = stk
							top = fresh
						} else {
							top = stk[len(stk)-2]
						}
					}
				}
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
				// No reaching definition: reuse pre-existing input if present (same
				// dedup logic as the read-slot path above).
				if existing := h.fd.FindVarnodeInput(out.Size(), out.Addr()); existing != nil {
					varStack[key] = append(varStack[key], existing)
				} else {
					newVn := h.fd.NewVarnode(out.Size(), out.Addr())
					h.fd.SetInputVarnode(newVn)
					varStack[key] = append(varStack[key], newVn)
				}
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
// Refinement -- split an address range along the boundaries shared by every
// Varnode overlapping it, so SSA renaming only ever sees participants of one
// uniform size.  Without this, a range holding e.g. two 4-byte writes and one
// 8-byte read renames the 8-byte read to the 4-byte definition sitting at the
// same start offset (the rename varStack is keyed by address, not size).
// C++ parity: heritage.cc Heritage::refinement (1890-1940) and its helpers
// buildRefinement (1704), splitByRefinement (1733), refineRead (1772),
// refineWrite (1806), refineInput (1836), remove13Refinement (1857), plus
// concatPieces (507) and splitPieces (563).
// ---------------------------------------------------------------------------

// maxWriteSize returns the largest written-Varnode size in the list. This is the
// value C++ Heritage::collect returns; placeMultiequals compares it against the
// task size to decide whether the range needs refining.
// C++ parity: heritage.cc Heritage::collect (lines 336-337).
func maxWriteSize(writes []*Varnode) int32 {
	m := int32(0)
	for _, vn := range writes {
		if vn.Size() > m {
			m = vn.Size()
		}
	}
	return m
}

// startBasicBlock returns the entry BlockBasic of the graph, or nil.
// C++ parity: fd->getBasicBlocks().getStartBlock().
func startBasicBlock(graph *BlockGraph) *BlockBasic {
	if graph == nil || graph.GetSize() == 0 {
		return nil
	}
	return toBasic(graph.GetBlock(0))
}

// concatPieces builds a chain of PIECE ops reconstructing one value out of
// vnlist (given in increasing address order) and makes finalvn the result.
// insertop is the op the expression is inserted before; nil inserts at the
// beginning of the entry block. Returns the unified Varnode.
// C++ parity: heritage.cc Heritage::concatPieces (507-550).
func (h *Heritage) concatPieces(graph *BlockGraph, vnlist []*Varnode, insertop *PcodeOp, finalvn *Varnode) *Varnode {
	if len(vnlist) < 2 {
		return finalvn
	}
	preexist := vnlist[0]
	bigEndian := preexist.Addr().Space.BigEndian
	opaddr := h.fd.BaseAddr()
	if insertop != nil {
		opaddr = insertop.Addr()
	}
	var prev *PcodeOp
	for i := 1; i < len(vnlist); i++ {
		vn := vnlist[i]
		newop := h.fd.NewOp(2, opaddr)
		h.fd.OpSetOpcode(newop, CPUI_PIECE)
		var newvn *Varnode
		if i == len(vnlist)-1 {
			newvn = finalvn
			h.fd.OpSetOutput(newop, newvn)
		} else {
			newvn = h.fd.NewUniqueOut(preexist.Size()+vn.Size(), newop)
		}
		if bigEndian {
			h.fd.OpSetInput(newop, preexist, 0) // most significant part
			h.fd.OpSetInput(newop, vn, 1)       // least significant part
		} else {
			h.fd.OpSetInput(newop, vn, 0)
			h.fd.OpSetInput(newop, preexist, 1)
		}
		// C++ holds one insert iterator and never advances it, so the ops land in
		// creation order at that point. OpInsertBefore reproduces that directly;
		// the entry-block case has to chain after the first op to keep the order.
		switch {
		case insertop != nil:
			h.fd.OpInsertBefore(newop, insertop)
		case prev != nil:
			h.fd.OpInsertAfter(newop, prev)
		default:
			bb := startBasicBlock(graph)
			if bb == nil {
				return finalvn
			}
			h.fd.OpInsertBegin(newop, bb)
		}
		prev = newop
		preexist = newvn
	}
	return preexist
}

// splitPieces defines each Varnode in vnlist as a SUBPIECE of startvn, where
// [addr,addr+size) is the whole range startvn covers. insertop is the defining op
// the SUBPIECEs are inserted after; nil inserts at the beginning of the entry
// block. C++ parity: heritage.cc Heritage::splitPieces (563-604).
func (h *Heritage) splitPieces(graph *BlockGraph, vnlist []*Varnode, insertop *PcodeOp,
	addr address.Address, size int32, startvn *Varnode) {

	bigEndian := addr.Space.BigEndian
	baseoff := addr.Offset
	if bigEndian {
		baseoff = addr.Offset + uint64(size)
	}
	opaddr := h.fd.BaseAddr()
	if insertop != nil {
		opaddr = insertop.Addr()
	}
	prev := insertop
	for _, vn := range vnlist {
		newop := h.fd.NewOp(2, opaddr)
		h.fd.OpSetOpcode(newop, CPUI_SUBPIECE)
		var diff uint64
		if bigEndian {
			diff = baseoff - (vn.Offset() + uint64(vn.Size()))
		} else {
			diff = vn.Offset() - baseoff
		}
		h.fd.OpSetInput(newop, startvn, 0)
		h.fd.OpSetInput(newop, h.fd.NewConstant(4, diff), 1)
		h.fd.OpSetOutput(newop, vn)
		if prev != nil {
			// C++ advances the iterator past the write once, then inserts each op
			// at that fixed point; chaining after the previous op is equivalent.
			h.fd.OpInsertAfter(newop, prev)
		} else {
			bb := startBasicBlock(graph)
			if bb == nil {
				return
			}
			h.fd.OpInsertBegin(newop, bb)
		}
		prev = newop
	}
}

// buildRefinement marks the start and end byte of every Varnode in vnlist inside
// the refinement array for [addr,addr+size). refine has size+1 entries (the extra
// slot is the fencepost for the range end).
// C++ parity: heritage.cc Heritage::buildRefinement (1704-1714). C++ collect only
// ever yields Varnodes fully inside the range, so the bounds tests below are
// guards for Gosleigh's overlap-based Collect, not extra behavior.
func buildRefinement(refine []int32, addr address.Address, size int32, vnlist []*Varnode) {
	for _, vn := range vnlist {
		if vn.Offset() < addr.Offset {
			continue
		}
		diff := int64(vn.Offset() - addr.Offset)
		if diff+int64(vn.Size()) > int64(size) {
			continue
		}
		refine[diff] = 1
		refine[diff+int64(vn.Size())] = 1
	}
}

// splitByRefinement returns a disjoint cover of vn built from fresh Varnodes whose
// boundaries follow the refinement partition. Returns nil when vn already fits one
// partition element (nothing to do).
// C++ parity: heritage.cc Heritage::splitByRefinement (1733-1753). The wrapOffset
// call is dropped: heritage ranges never wrap the space here.
func (h *Heritage) splitByRefinement(vn *Varnode, addr address.Address, refine []int32) []*Varnode {
	curaddr := vn.Addr()
	if curaddr.Offset < addr.Offset {
		return nil
	}
	diff := int64(curaddr.Offset - addr.Offset)
	if diff >= int64(len(refine)) {
		return nil
	}
	sz := vn.Size()
	cutsz := refine[diff]
	if cutsz <= 0 || sz <= cutsz {
		return nil // already refined
	}
	split := []*Varnode{h.fd.NewVarnode(cutsz, curaddr)}
	sz -= cutsz
	for sz > 0 {
		curaddr.Offset += uint64(cutsz)
		diff = int64(curaddr.Offset - addr.Offset)
		if diff >= int64(len(refine)) || refine[diff] <= 0 {
			break // partition does not cover the rest; leave the tail alone
		}
		cutsz = refine[diff]
		if cutsz > sz {
			cutsz = sz // final piece
		}
		split = append(split, h.fd.NewVarnode(cutsz, curaddr))
		sz -= cutsz
	}
	return split
}

// refineRead replaces a free read straddling the refinement with a concatenation
// of partition-sized reads. C++ parity: heritage.cc Heritage::refineRead (1772-1787).
func (h *Heritage) refineRead(graph *BlockGraph, vn *Varnode, addr address.Address, refine []int32) {
	newvn := h.splitByRefinement(vn, addr, refine)
	if len(newvn) == 0 {
		return
	}
	// C++ takes loneDescend unconditionally (a free read has exactly one). Gosleigh's
	// Collect also classifies descendant-less Varnodes as reads, so bail out instead
	// of rewriting an op that does not exist.
	op := vn.LoneDescend()
	if op == nil {
		for _, piece := range newvn {
			h.fd.DeleteVarnode(piece)
		}
		return
	}
	slot := op.GetSlot(vn)
	if slot < 0 {
		for _, piece := range newvn {
			h.fd.DeleteVarnode(piece)
		}
		return
	}
	replacevn := h.fd.NewUnique(vn.Size())
	h.concatPieces(graph, newvn, op, replacevn)
	h.fd.OpSetInput(op, replacevn, slot)
	if vn.HasNoDescend() {
		h.fd.DeleteVarnode(vn)
	}
}

// refineWrite replaces a written Varnode straddling the refinement with
// partition-sized pieces, each defined by a SUBPIECE of the original definition.
// C++ parity: heritage.cc Heritage::refineWrite (1806-1818).
func (h *Heritage) refineWrite(graph *BlockGraph, vn *Varnode, addr address.Address, refine []int32) {
	def := vn.Def()
	if def == nil {
		return
	}
	newvn := h.splitByRefinement(vn, addr, refine)
	if len(newvn) == 0 {
		return
	}
	replacevn := h.fd.NewUnique(vn.Size())
	h.fd.OpSetOutput(def, replacevn)
	h.splitPieces(graph, newvn, def, vn.Addr(), vn.Size(), replacevn)
	h.fd.TotalReplace(vn, replacevn)
	h.fd.DeleteVarnode(vn)
}

// refineInput splits a known input Varnode into partition-sized pieces defined by
// SUBPIECEs of the input, and write-masks the original.
// C++ parity: heritage.cc Heritage::refineInput (1836-1844).
func (h *Heritage) refineInput(graph *BlockGraph, vn *Varnode, addr address.Address, refine []int32) {
	newvn := h.splitByRefinement(vn, addr, refine)
	if len(newvn) == 0 {
		return
	}
	h.splitPieces(graph, newvn, nil, vn.Addr(), vn.Size(), vn)
	vn.SetAddlFlags(VarnodeWriteMask)
}

// remove13Refinement rewrites a 1-3 or 3-1 partition pair as a single 4, since
// such a cover of a 4-byte range is almost certainly artificial.
// C++ parity: heritage.cc Heritage::remove13Refinement (1857-1880).
func remove13Refinement(refine []int32) {
	if len(refine) == 0 {
		return
	}
	pos := int32(0)
	lastsize := refine[pos]
	if lastsize <= 0 {
		return
	}
	pos += lastsize
	for pos < int32(len(refine)) {
		cursize := refine[pos]
		if cursize == 0 {
			break
		}
		if (lastsize == 1 && cursize == 3) || (lastsize == 3 && cursize == 1) {
			refine[pos-lastsize] = 4
			lastsize = 4
			pos += cursize
		} else {
			lastsize = cursize
			pos += lastsize
		}
	}
}

// refinement finds the common refinement of every read/write/input overlapping the
// disjoint task at index idx, splits those Varnodes to match it, and replaces the
// task (and its globalDisjoint entry) with one entry per partition element.
// Returns true when a non-trivial refinement was applied; the first partition
// element then occupies index idx, so the caller re-collects at idx and the
// remaining elements are picked up by later iterations of the task loop -- exactly
// how C++ resumes from the iterator refinement() hands back.
// C++ parity: heritage.cc Heritage::refinement (1890-1940).
func (h *Heritage) refinement(graph *BlockGraph, idx int, readvars, writevars, inputvars []*Varnode) bool {
	task := h.disjoint.Get(idx)
	size := task.Size
	if size > 1024 {
		return false
	}
	addr := task.Addr
	refine := make([]int32, size+1) // extra "fencepost" slot for the size position
	buildRefinement(refine, addr, size, readvars)
	buildRefinement(refine, addr, size, writevars)
	buildRefinement(refine, addr, size, inputvars)
	refine = refine[:size] // remove the fencepost
	lastpos := int32(0)
	for curpos := int32(1); curpos < size; curpos++ { // boundary points -> partition sizes
		if refine[curpos] != 0 {
			refine[lastpos] = curpos - lastpos
			lastpos = curpos
		}
	}
	if lastpos == 0 {
		return false // no non-trivial refinement
	}
	refine[lastpos] = size - lastpos
	remove13Refinement(refine)
	for _, vn := range readvars {
		h.refineRead(graph, vn, addr, refine)
	}
	for _, vn := range writevars {
		h.refineWrite(graph, vn, addr, refine)
	}
	for _, vn := range inputvars {
		h.refineInput(graph, vn, addr, refine)
	}

	// Alter the disjoint cover (both locally and globally) to reflect the refinement.
	flags := task.Flags
	curPass := h.globalDisjoint.FindPass(addr)
	if curPass < 0 {
		curPass = h.pass
	}
	if gi := h.globalDisjoint.Find(addr); gi >= 0 {
		h.globalDisjoint.RemoveAt(gi)
	}
	parts := make([]MemRange, 0, 2)
	partAddr := addr
	for cut := int32(0); cut < size; {
		sz := refine[cut]
		if sz <= 0 {
			break
		}
		parts = append(parts, MemRange{Addr: partAddr, Size: sz, Flags: flags})
		h.globalDisjoint.Add(partAddr, sz, curPass)
		cut += sz
		partAddr.Offset += uint64(sz)
	}
	if len(parts) == 0 {
		return false
	}
	h.disjoint.ReplaceAt(idx, parts)
	return true
}

// RemoveAt drops the entry at index idx.
// C++ parity: heritage.cc Heritage::refinement -> globaldisjoint.erase(iter).
func (lm *LocationMap) RemoveAt(idx int) {
	if idx < 0 || idx >= len(lm.entries) {
		return
	}
	lm.entries = append(lm.entries[:idx], lm.entries[idx+1:]...)
}

// ReplaceAt substitutes the task at index idx with the given ranges, preserving
// list order. C++ parity: heritage.cc Heritage::refinement -> disjoint.erase +
// repeated disjoint.insert at the erased position.
func (tl *TaskList) ReplaceAt(idx int, ranges []MemRange) {
	if idx < 0 || idx >= len(tl.tasks) {
		return
	}
	tail := append([]MemRange(nil), tl.tasks[idx+1:]...)
	tl.tasks = append(tl.tasks[:idx], ranges...)
	tl.tasks = append(tl.tasks, tail...)
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

		// Build task list: group varnodes into address ranges. Incremental across
		// passes -- only ranges containing newly freed varnodes are reprocessed, so
		// re-running Heritage() on later mainloop iterations does not re-place phis
		// for already-resolved (heritage-known) varnodes.
		// C++ parity: heritage.cc Heritage::heritage (2702-2732).
		h.disjoint.Clear()
		for _, vn := range vns {
			// Skip dead free varnodes (no def, no uses, not unaffected, not input):
			// they carry no data-flow to heritage. C++ parity: heritage.cc:2704.
			if !vn.IsWritten() && vn.HasNoDescend() && !vn.IsUnaffected() && !vn.IsInput() {
				continue
			}
			_, code := h.globalDisjoint.Add(vn.Addr(), vn.Size(), h.pass)
			switch code {
			case 0:
				// All-new location (first time heritaged, or intersecting new).
				h.disjoint.Add(vn.Addr(), vn.Size(), MemRangeNewAddresses)
			case 2:
				// Completely contained in a previous-pass range. Skip if already in
				// SSA (heritage-known) or dead -- this is the incremental key that
				// stops the second pass from re-placing phis over old ranges.
				// C++ parity: heritage.cc:2711-2719.
				if vn.IsHeritageKnown() {
					continue
				}
				if vn.HasNoDescend() {
					continue
				}
				h.disjoint.Add(vn.Addr(), vn.Size(), MemRangeOldAddresses)
			default:
				// case 1: partially contained in an old range but may contain new
				// addresses; always reprocess. C++ parity: heritage.cc:2721-2722.
				h.disjoint.Add(vn.Addr(), vn.Size(), MemRangeOldAddresses|MemRangeNewAddresses)
			}
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
			// A range wider than 4 bytes whose largest write does not fill it is
			// split along the common refinement of everything overlapping it. This
			// runs before guardCalls so the guard (like C++ Heritage::guard, which
			// placeMultiequals calls after refinement) sees the refined range.
			// C++ parity: heritage.cc Heritage::placeMultiequals (2609-2616).
			reads, writes, inputs := h.Collect(task.Addr, task.Size)
			if task.Size > 4 && maxWriteSize(writes) < task.Size {
				if h.refinement(graph, i, reads, writes, inputs) {
					task = h.disjoint.Get(i)
				}
			}
			// Insert INDIRECT guards for call-site side-effects on this range BEFORE
			// Collect so the INDIRECT output varnodes appear as written SSA definitions.
			// C++ parity: heritage.cc Heritage::heritage -> guard -> guardCalls
			h.guardCalls(info.Space, task.Addr.Offset, task.Size)
			reads, writes, inputs = h.Collect(task.Addr, task.Size)
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
					subR, subW = h.normalizeRange(subAddr, curSize, subR, subW)
					h.placeMultiequals(graph, subAddr, curSize, subR, subW, subI)
					h.Rename(graph, subAddr, curSize)
				}
			} else {
				// Bring sub-register reads/writes (EAX inside RAX) up to the range size
				// so renaming does not collide them on their shared start offset.
				reads, writes = h.normalizeRange(task.Addr, task.Size, reads, writes)
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
// Dormant: no live caller. Stack slots used to be driven through here one at a
// time; they now go through Heritage() like every other space (see
// Funcdata.registerStackHeritageSpace), which is what gives them refinement and
// guard normalization. Kept for harnesses that need to heritage one explicit range.
// C++ parity: approximates Heritage::heritage() restricted to one range; it skips
// both refinement and normalizeRange, so callers must supply a range whose
// reads/writes are already uniform in size.
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
	// C++ parity: heritage.cc Heritage::guard (lines 1188-1197). guardStores/
	// guardLoads remain unported; guardReturns is ported below. fl is 0 for
	// register ranges (the register return value is never persistent).
	h.guardCalls(addr.Space, addr.Offset, size)
	h.guardReturns(0, addr, size)
}

// Return-output containment classes for guardReturns, the register-space subset
// of the ParamEntry containment outcomes that FuncProto::characterizeAsOutput
// reports. Gosleigh has not ported the ParamEntry output model, so only the
// single configured integer return register participates.
const (
	retOutNoContainment = iota // no overlap with the return register
	retOutContainedBy          // query range properly contains the return register
	retOutOther                // exact match, query inside output, or partial overlap
)

// characterizeReturnOutput classifies how the heritaged range [addr,addr+size)
// relates to the function's single integer return register (ProtoModel.ReturnReg*).
// C++ parity: fspec.cc FuncProto::characterizeAsOutput (register subset).
func (h *Heritage) characterizeReturnOutput(addr address.Address, size int32) int {
	if h.proto == nil || h.proto.ReturnRegSpaceIndex < 0 || h.proto.ReturnRegSize == 0 {
		return retOutNoContainment
	}
	if addr.Space == nil || int(addr.Space.Index) != h.proto.ReturnRegSpaceIndex {
		return retOutNoContainment
	}
	qStart := addr.Offset
	qEnd := addr.Offset + uint64(size)
	oStart := h.proto.ReturnRegOffset
	oEnd := h.proto.ReturnRegOffset + uint64(h.proto.ReturnRegSize)
	if qEnd <= oStart || oEnd <= qStart {
		return retOutNoContainment
	}
	if qStart <= oStart && oEnd <= qEnd && size > h.proto.ReturnRegSize {
		return retOutContainedBy
	}
	return retOutOther
}

// guardReturns prepopulates data-flow for the given register range at every
// CPUI_RETURN op so that, on a re-heritage pass, the return value reaches the
// function exit. When an active return trial exists, a fresh Varnode at the
// range is appended as a new input to each RETURN (or a truncating SUBPIECE is
// inserted when the range properly contains the return storage). SSA renaming on
// the subsequent pass then connects that fresh Varnode to the dominating
// definition of the return register.
//
// This is the faithful replacement for the anchorReturnReg SeqNum heuristic
// (funcproto.go): the fresh RETURN input plus dominance-based renaming reproduces
// "the value live at the return site" exactly, where anchorReturnReg approximates
// it by picking the latest-SeqNum write at the return-register location.
//
// Dormant: invoked only from Guard(), which currently has no live callers. Live
// wiring requires installing the active output (ActionActiveReturn) and a second
// heritage pass over the register range so the appended Varnodes get renamed.
//
// C++ parity: heritage.cc Heritage::guardReturns (lines 1652-1692). The persist
// branch (Varnode::persist -> address-forced COPY) is intentionally omitted: it
// applies to persistent memory ranges, never to the register return value, and
// depends on markReturnCopy/setAddrForce which are not ported.
func (h *Heritage) guardReturns(fl uint32, addr address.Address, size int32) {
	fp := h.fd.GetFuncProto()
	if fp == nil {
		return
	}
	active := fp.GetActiveOutput()
	if active != nil {
		switch h.characterizeReturnOutput(addr, size) {
		case retOutContainedBy:
			h.guardReturnsOverlapping(addr, size)
		case retOutNoContainment:
			// No overlap with the return register; nothing to guard.
		default:
			active.RegisterTrial(addr, size)
			for _, op := range h.fd.GetPcodeOpBank().AllOps() {
				if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
					continue
				}
				if op.HaltType() != 0 { // special halt points cannot take return values
					continue
				}
				invn := h.fd.NewVarnode(size, addr)
				invn.SetActiveHeritage()
				h.fd.OpInsertInput(op, invn, op.NumInput())
			}
		}
	}
	// C++ persist branch omitted (see doc comment). fl is accepted to keep the
	// signature aligned with Heritage::guardReturns.
	_ = fl
}

// guardReturnsOverlapping handles the case where the heritaged range properly
// contains the return storage: a SUBPIECE truncates the oversized range down to
// the return register before the result is appended to each RETURN op.
// C++ parity: heritage.cc Heritage::guardReturnsOverlapping (lines 1609-1638).
func (h *Heritage) guardReturnsOverlapping(addr address.Address, size int32) {
	retSize := h.proto.ReturnRegSize
	truncAddr := address.Address{Space: addr.Space, Offset: h.proto.ReturnRegOffset}
	active := h.fd.GetFuncProto().GetActiveOutput()
	active.RegisterTrial(truncAddr, retSize)
	// Number of least significant bytes to truncate.
	offset := int32(h.proto.ReturnRegOffset - addr.Offset)
	if addr.Space != nil && addr.Space.BigEndian {
		offset = (size - retSize) - offset
	}
	for _, op := range h.fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		if op.HaltType() != 0 {
			continue
		}
		invn := h.fd.NewVarnode(size, addr)
		subOp := h.fd.NewOp(2, op.Addr())
		h.fd.OpSetOpcode(subOp, CPUI_SUBPIECE)
		h.fd.OpSetInput(subOp, invn, 0)
		h.fd.OpSetInput(subOp, h.fd.NewConstant(4, uint64(uint32(offset))), 1)
		h.fd.OpInsertBefore(subOp, op)
		retVal := h.fd.NewVarnodeOut(retSize, truncAddr, subOp)
		invn.SetActiveHeritage()
		h.fd.OpInsertInput(op, retVal, op.NumInput())
	}
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
