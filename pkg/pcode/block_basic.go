package pcode

// BlockBasic is a basic block containing PcodeOps.
// C++ parity: block.hh BlockBasic
//
// Structure-graph delegation: when ActionBlockStructure clones the basic-block
// graph into a separate structure graph (see cloneFlowBlock), the clone shares
// its underlying op list with the source basic block through the srcDelegate
// field. This mirrors C++ Ghidra's BlockCopy wrapper that holds a pointer to
// the original FlowBlock. Without this delegation, trim COPYs inserted by
// Merge::trimOpInput after ActionBlockStructure land in the original basic
// block and never appear in the cloned structure graph, so PrintC (which walks
// the structure graph) cannot render them.
// C++ parity: block.hh BlockCopy wraps a FlowBlock* rather than copying ops.
type BlockBasic struct {
	FlowBlock // embedded
	ops       []*PcodeOp
	// srcDelegate, when non-nil, redirects all op reads/writes to this source
	// block. Set by cloneFlowBlock when creating a structure-graph clone.
	srcDelegate *BlockBasic
}

// asBasic recovers the BlockBasic that owns a FlowBlock. In the basic-block
// graph every FlowBlock is embedded in a BlockBasic (concrete back-pointer set
// by NewBlockBasic). This is a Go-embedding stand-in for the C++ upcast
// (BlockBasic *)flowblock. Returns nil if the block is not a BlockBasic.
func asBasic(b *FlowBlock) *BlockBasic {
	if b == nil {
		return nil
	}
	bb, _ := b.concrete.(*BlockBasic)
	return bb
}

// NewBlockBasic creates a new BlockBasic with BlockBasicType set.
func NewBlockBasic() *BlockBasic {
	bb := &BlockBasic{}
	bb.blockType = BlockBasicType
	bb.concrete = bb // back-pointer for FlowBlock -> BlockBasic recovery
	return bb
}

// Type returns BlockBasicType (overrides FlowBlock.Type).
func (bb *BlockBasic) Type() BlockType { return BlockBasicType }

// opSlice returns the authoritative op slice: either this block's own ops, or
// the delegated source block's ops when this is a structure-graph clone.
// C++ parity: BlockCopy::firstOp / BlockCopy::lastOp forward to the wrapped block.
func (bb *BlockBasic) opSlice() []*PcodeOp {
	if bb.srcDelegate != nil {
		return bb.srcDelegate.opSlice()
	}
	return bb.ops
}

// AddOp appends an op to this basic block.
func (bb *BlockBasic) AddOp(op *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.AddOp(op)
		return
	}
	bb.ops = append(bb.ops, op)
}

// RemoveOp finds and removes op from this basic block.
func (bb *BlockBasic) RemoveOp(op *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.RemoveOp(op)
		return
	}
	for i, o := range bb.ops {
		if o == op {
			bb.ops = append(bb.ops[:i], bb.ops[i+1:]...)
			return
		}
	}
}

// InsertOpBefore inserts op before follow in the ops slice.
func (bb *BlockBasic) InsertOpBefore(op, follow *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.InsertOpBefore(op, follow)
		return
	}
	for i, o := range bb.ops {
		if o == follow {
			bb.ops = append(bb.ops, nil)
			copy(bb.ops[i+1:], bb.ops[i:])
			bb.ops[i] = op
			return
		}
	}
	// If follow not found, append.
	bb.ops = append(bb.ops, op)
}

// InsertOpAfter inserts op after prev in the ops slice.
func (bb *BlockBasic) InsertOpAfter(op, prev *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.InsertOpAfter(op, prev)
		return
	}
	for i, o := range bb.ops {
		if o == prev {
			pos := i + 1
			bb.ops = append(bb.ops, nil)
			copy(bb.ops[pos+1:], bb.ops[pos:])
			bb.ops[pos] = op
			return
		}
	}
	bb.ops = append(bb.ops, op)
}

// InsertOpBegin prepends op to the ops slice.
func (bb *BlockBasic) InsertOpBegin(op *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.InsertOpBegin(op)
		return
	}
	bb.ops = append([]*PcodeOp{op}, bb.ops...)
}

// InsertOpEnd appends op to the ops slice.
func (bb *BlockBasic) InsertOpEnd(op *PcodeOp) {
	if bb.srcDelegate != nil {
		bb.srcDelegate.InsertOpEnd(op)
		return
	}
	bb.ops = append(bb.ops, op)
}

// FirstOp returns the first op, or nil if empty.
func (bb *BlockBasic) FirstOp() *PcodeOp {
	s := bb.opSlice()
	if len(s) == 0 {
		return nil
	}
	return s[0]
}

// LastOp returns the last op, or nil if empty.
func (bb *BlockBasic) LastOp() *PcodeOp {
	s := bb.opSlice()
	if len(s) == 0 {
		return nil
	}
	return s[len(s)-1]
}

// EmptyOp returns true if there are no ops.
func (bb *BlockBasic) EmptyOp() bool { return len(bb.opSlice()) == 0 }

// NumOps returns the number of ops.
func (bb *BlockBasic) NumOps() int { return len(bb.opSlice()) }

// Ops returns a copy of the ops slice.
func (bb *BlockBasic) Ops() []*PcodeOp {
	s := bb.opSlice()
	out := make([]*PcodeOp, len(s))
	copy(out, s)
	return out
}

// EarliestUse finds the earliest op in bb that uses (reads) vn.
// Returns nil if no op in bb reads vn.
// C++ parity: block.cc BlockBasic::earliestUse
func (bb *BlockBasic) EarliestUse(vn *Varnode) *PcodeOp {
	if vn == nil {
		return nil
	}
	for _, op := range bb.opSlice() {
		for i := 0; i < op.NumInput(); i++ {
			if op.Input(i) == vn {
				return op
			}
		}
	}
	return nil
}

// HasOnlyMarkers reports whether this block contains nothing but marker ops
// (MULTIEQUAL, INDIRECT) and branch ops -- i.e. no substantive computation.
// C++ parity: block.cc BlockBasic::hasOnlyMarkers (block.cc:2578)
func (bb *BlockBasic) HasOnlyMarkers() bool {
	for _, bop := range bb.opSlice() {
		if bop.IsMarker() {
			continue
		}
		if bop.IsBranch() {
			continue
		}
		return false
	}
	return true
}

// IsDoNothing reports whether this block does nothing useful and is a candidate
// for removal. It must have exactly one out-edge, at least one in-edge, must not
// be a switch target that still propagates a unique value into a join, must not
// end in an indirect jump, and must contain only marker/branch ops.
// C++ parity: block.cc BlockBasic::isDoNothing (block.cc:2596)
func (bb *BlockBasic) IsDoNothing() bool {
	if bb.SizeOut() != 1 {
		return false // no return / cbranch: exactly one out
	}
	if bb.SizeIn() == 0 {
		return false // starting block may hold global-var placeholders
	}
	for i := 0; i < bb.SizeIn(); i++ {
		switchbl := bb.InEdge(i).Point
		if !switchbl.IsSwitchOut() {
			continue
		}
		if switchbl.SizeOut() > 1 {
			// This block is a switch target; a switch edge may still be
			// propagating a unique value into a multi-edge join.
			if bb.OutEdge(0).Point.SizeIn() > 1 {
				return false
			}
		}
	}
	lastop := bb.LastOp()
	if lastop != nil && lastop.Code() == CPUI_BRANCHIND {
		return false // don't remove single-out indirect jumps
	}
	return bb.HasOnlyMarkers()
}

// UnblockedMulti reports whether removing this block (collapsing it to its
// out-block at outslot) leaves no implied COPY hidden in a MULTIEQUAL. A hidden
// implied COPY means the block is doing real work and must not be removed.
// C++ parity: block.cc BlockBasic::unblockedMulti (block.cc:2534)
func (bb *BlockBasic) UnblockedMulti(outslot int) bool {
	blout := asBasic(bb.OutEdge(outslot).Point)
	// Build the list of blocks that would have redundant branches into blout.
	var redundlist []*FlowBlock
	for i := 0; i < bb.SizeIn(); i++ {
		bl := bb.InEdge(i).Point
		for j := 0; j < bl.SizeOut(); j++ {
			if bl.OutEdge(j).Point == &blout.FlowBlock {
				redundlist = append(redundlist, bl)
			}
		}
	}
	if len(redundlist) == 0 {
		return true
	}
	for _, multiop := range blout.opSlice() {
		if multiop.Code() != CPUI_MULTIEQUAL {
			continue
		}
		for _, bl := range redundlist {
			vnredund := multiop.Input(blout.GetInIndex(bl))       // a redundant varnode
			vnremove := multiop.Input(blout.GetInIndex(&bb.FlowBlock))
			if vnremove.IsWritten() {
				othermulti := vnremove.Def()
				if othermulti.Code() == CPUI_MULTIEQUAL && othermulti.Parent() == bb {
					vnremove = othermulti.Input(bb.GetInIndex(bl))
				}
			}
			if vnremove != vnredund {
				return false // redundant branches must be identical
			}
		}
	}
	return true
}

// NegateCondition flips PcodeOpBooleanFlip and PcodeOpFallthruTrue on the
// CBRANCH (last) op, then swaps the two outgoing edges if present.
// C++ parity: block.cc BlockBasic::negateCondition -- always uses op.back()
// regardless of the top parameter, then calls FlowBlock::negateCondition(true)
// which swaps edges.
func (bb *BlockBasic) NegateCondition(top bool) {
	s := bb.opSlice()
	if len(s) == 0 {
		return
	}
	// C++ always flips the last op (CBRANCH), ignoring the top parameter.
	target := s[len(s)-1]
	target.FlipFlag(PcodeOpBooleanFlip)
	target.FlipFlag(PcodeOpFallthruTrue)
	// C++ FlowBlock::negateCondition(true) -> swapEdges(); only valid with 2 edges.
	if bb.FlowBlock.SizeOut() == 2 {
		bb.FlowBlock.SwapEdges()
	}
	// C++ BlockCopy::negateCondition (block.hh:534) forwards copy->negateCondition()
	// to the WRAPPED basic block, which swaps the source block's out-edges too (a real
	// data-flow change), in addition to swapping the copy's edges. When this BlockBasic
	// is a structure-graph clone (srcDelegate != nil), the loop above only swapped the
	// clone's edges; mirror C++ by swapping the source's edges as well. Without this,
	// the source basic block keeps its original branch order, so later basic-block
	// passes (ActionNodeJoin/ConditionalJoin.match) see a stale, unaligned edge order
	// and a do-while loop never rotates to the canonical while head+body form.
	if bb.srcDelegate != nil && bb.srcDelegate.FlowBlock.SizeOut() == 2 {
		bb.srcDelegate.FlowBlock.SwapEdges()
	}
}
