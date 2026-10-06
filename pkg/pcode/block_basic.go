package pcode

import "gosleigh/pkg/address"

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

	// cover is the set of instruction address ranges the block was built
	// from; it survives op removal. C++ parity: BlockBasic::cover.
	cover []blockRange
}

// blockRange is one [first,last] instruction address range of a block.
type blockRange struct {
	space       *address.Space
	first, last uint64
}

// SetInitialRange sets the block's address cover to [beg,end].
// C++ parity: BlockBasic::setInitialRange.
func (bb *BlockBasic) SetInitialRange(beg, end address.Address) {
	bb.cover = []blockRange{{space: beg.Space, first: beg.Offset, last: end.Offset}}
}

// SetInitialRangeFromOps covers the block's ops: from the first op's address
// to the highest op address. C++ parity: FlowInfo::splitBasic.
func (bb *BlockBasic) SetInitialRangeFromOps() {
	ops := bb.opSlice()
	if len(ops) == 0 {
		return
	}
	start := ops[0].Addr()
	stop := start
	for _, op := range ops[1:] {
		if a := op.Addr(); a.Space == stop.Space && a.Offset > stop.Offset {
			stop = a
		}
	}
	bb.SetInitialRange(start, stop)
}

// SetInitialRanges covers every basic block of a freshly built graph by its
// ops. C++ parity: FlowInfo::splitBasic (setBasicBlockRange per block).
func (bg *BlockGraph) SetInitialRanges() {
	for _, b := range bg.blocks {
		if bb := asBasic(b); bb != nil {
			bb.SetInitialRangeFromOps()
		}
	}
}

// copyRange copies another block's cover. C++ parity: BlockBasic::copyRange.
func (bb *BlockBasic) copyRange(o *BlockBasic) {
	bb.cover = append([]blockRange(nil), o.cover...)
}

// mergeRange adds another block's ranges to the cover, joining any that
// overlap or touch. C++ parity: BlockBasic::mergeRange (RangeList::merge).
func (bb *BlockBasic) mergeRange(o *BlockBasic) {
	for _, r := range o.cover {
		bb.insertRange(r)
	}
}

// insertRange is RangeList::insertRange: the new range absorbs every range
// of the same space it overlaps, and the list stays sorted.
func (bb *BlockBasic) insertRange(r blockRange) {
	out := bb.cover[:0:0]
	for _, c := range bb.cover {
		if c.space == r.space && c.first <= r.last && r.first <= c.last {
			r.first = min(r.first, c.first)
			r.last = max64(r.last, c.last)
			continue
		}
		out = append(out, c)
	}
	at := len(out)
	for i, c := range out {
		if spaceOrder(r.space) < spaceOrder(c.space) || (c.space == r.space && r.first < c.first) {
			at = i
			break
		}
	}
	out = append(out, blockRange{})
	copy(out[at+1:], out[at:])
	out[at] = r
	bb.cover = out
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
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
// entryAddr is the address of the block's original entry instruction: the
// start of its cover when that is a single range, else the start of the
// range holding the first op. C++ parity: BlockBasic::getEntryAddr.
func (bb *BlockBasic) entryAddr() address.Address {
	if bb.srcDelegate != nil {
		return bb.srcDelegate.entryAddr()
	}
	first := bb.FirstOp()
	if len(bb.cover) == 1 {
		return address.Address{Space: bb.cover[0].space, Offset: bb.cover[0].first}
	}
	if first == nil {
		return address.Address{}
	}
	a := first.Addr()
	for _, r := range bb.cover {
		if r.space == a.Space && a.Offset >= r.first && a.Offset <= r.last {
			return address.Address{Space: r.space, Offset: r.first}
		}
	}
	return a
}

// startAddr is the start of the block's first address range.
// C++ parity: BlockBasic::getStart. A block built without a cover falls back
// to its first non-MULTIEQUAL op's address.
func (bb *BlockBasic) startAddr() address.Address {
	if bb.srcDelegate != nil {
		return bb.srcDelegate.startAddr()
	}
	if len(bb.cover) != 0 {
		return address.Address{Space: bb.cover[0].space, Offset: bb.cover[0].first}
	}
	ops := bb.opSlice()
	for _, op := range ops {
		if op.Code() != CPUI_MULTIEQUAL {
			return op.Addr()
		}
	}
	if len(ops) != 0 {
		return ops[0].Addr()
	}
	return address.Address{}
}

func (bb *BlockBasic) EmptyOp() bool { return len(bb.opSlice()) == 0 }

// NoInterveningStatement reports whether this block creates no value usable
// outside the block. Computing a value for a BRANCHIND/CBRANCH and copying
// values is allowed; any value used outside the block, a write to an
// addressable location, or a CALL/STORE causes it to return false. Used by
// foldInOneGuard to confirm the switch block is safe to fold a guard into.
// C++ parity: block.cc BlockBasic::noInterveningStatement (block.cc:2712).
func (bb *BlockBasic) NoInterveningStatement() bool {
	for _, bop := range bb.opSlice() {
		if bop.IsMarker() {
			continue
		}
		if bop.IsBranch() {
			continue
		}
		if bop.EvalType()&PcodeOpSpecial != 0 {
			if bop.IsCall() {
				return false
			}
			opc := bop.Code()
			if opc == CPUI_STORE || opc == CPUI_NEW {
				return false
			}
		} else {
			opc := bop.Code()
			if opc == CPUI_COPY || opc == CPUI_SUBPIECE {
				continue
			}
		}
		outvn := bop.Output()
		if outvn == nil {
			continue
		}
		if outvn.IsAddrTied() {
			return false
		}
		for _, op := range outvn.DescendIter() {
			if op.Parent() != bb {
				return false
			}
		}
	}
	return true
}

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
			vnredund := multiop.Input(blout.GetInIndex(bl)) // a redundant varnode
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
