package pcode

// BlockType identifies the kind of FlowBlock.
// C++ parity: block.hh block_type
type BlockType int

const (
	BlockPlain         BlockType = iota // t_plain
	BlockBasicType                      // t_basic
	BlockGraphType                      // t_graph
	BlockCopyType                       // t_copy
	BlockGotoType                       // t_goto
	BlockMultiGotoType                  // t_multigoto
	BlockListType                       // t_ls
	BlockConditionType                  // t_condition
	BlockIfType                         // t_if
	BlockWhileDoType                    // t_whiledo
	BlockDoWhileType                    // t_dowhile
	BlockSwitchType                     // t_switch
	BlockInfLoopType                    // t_infloop
)

// Block flags -- uint32 bitmask
// C++ parity: block.hh block_flags
const (
	BlockFlagGotoGoto         uint32 = 0x001
	BlockFlagBreakGoto        uint32 = 0x002
	BlockFlagContinueGoto     uint32 = 0x004
	BlockFlagSwitchOut        uint32 = 0x010
	BlockFlagUnstructuredTarg uint32 = 0x020
	BlockFlagMark             uint32 = 0x080
	BlockFlagMark2            uint32 = 0x100
	BlockFlagEntryPoint       uint32 = 0x200
	BlockFlagInteriorGotoOut  uint32 = 0x400
	BlockFlagInteriorGotoIn   uint32 = 0x800
	BlockFlagLabelBumpUp      uint32 = 0x1000
	BlockFlagDoNothingLoop    uint32 = 0x2000
	BlockFlagDead             uint32 = 0x4000
	BlockFlagWhileDoOverflow  uint32 = 0x8000
	BlockFlagFlipPath         uint32 = 0x10000
	BlockFlagJoinedBlock      uint32 = 0x20000
	BlockFlagDuplicateBlock   uint32 = 0x40000
)

// Edge flags -- uint32 bitmask
// C++ parity: block.hh edge_flags
const (
	EdgeFlagGoto          uint32 = 0x001
	EdgeFlagLoop          uint32 = 0x002
	EdgeFlagDefaultSwitch uint32 = 0x004
	EdgeFlagIrreducible   uint32 = 0x008
	EdgeFlagTree          uint32 = 0x010
	EdgeFlagForward       uint32 = 0x020
	EdgeFlagCross         uint32 = 0x040
	EdgeFlagBack          uint32 = 0x080
	EdgeFlagLoopExit      uint32 = 0x100
)

// BlockEdge is one half of a bidirectional CFG edge.
// C++ parity: block.hh BlockEdge
type BlockEdge struct {
	Label        uint32
	Point        *FlowBlock
	ReverseIndex int // index in the opposite direction's edge list
}

// FlowBlock is the base type for all control flow blocks.
// C++ parity: block.hh FlowBlock
type FlowBlock struct {
	blockType  BlockType
	flags      uint32
	parent     *FlowBlock
	immedDom   *FlowBlock
	index      int32
	visitCount int32
	numDesc    int32
	inEdges    []BlockEdge
	outEdges   []BlockEdge
	// concrete points back to the embedding struct (e.g. *BlockBasic).
	// Set by NewBlockBasic()/NewBlockGraph(). Used by heritage to
	// recover the concrete block type without unsafe pointer math.
	// Not part of C++ parity -- Go embedding workaround.
	concrete interface{}
}

// Concrete returns the concrete block that owns this FlowBlock, or nil.
func (b *FlowBlock) Concrete() interface{} { return b.concrete }

// SetConcrete sets the concrete back-pointer.
func (b *FlowBlock) SetConcrete(c interface{}) { b.concrete = c }

// Type returns the block type.
func (b *FlowBlock) Type() BlockType { return b.blockType }

// SetType sets the block type.
func (b *FlowBlock) SetType(t BlockType) { b.blockType = t }

// Index returns the block index (RPO order after spanning tree).
func (b *FlowBlock) Index() int32 { return b.index }

// SetIndex sets the block index.
func (b *FlowBlock) SetIndex(i int32) { b.index = i }

// Flags returns the block flags.
func (b *FlowBlock) Flags() uint32 { return b.flags }

// SetFlag sets the given flag bits.
func (b *FlowBlock) SetFlag(f uint32) { b.flags |= f }

// ClearFlag clears the given flag bits.
func (b *FlowBlock) ClearFlag(f uint32) { b.flags &^= f }

// HasFlag returns true if all bits in f are set.
func (b *FlowBlock) HasFlag(f uint32) bool { return b.flags&f == f }

// IsSwitchOut reports whether this block heads a switch (BRANCHIND) region.
// C++ parity: block.hh FlowBlock::isSwitchOut
func (b *FlowBlock) IsSwitchOut() bool { return b.flags&BlockFlagSwitchOut != 0 }

// IsEntryPoint reports whether this block is the function entry.
// C++ parity: block.hh FlowBlock::isEntryPoint
func (b *FlowBlock) IsEntryPoint() bool { return b.flags&BlockFlagEntryPoint != 0 }

// IsDead reports whether this block has been marked dead (pending removal).
// C++ parity: block.hh FlowBlock::isDead
func (b *FlowBlock) IsDead() bool { return b.flags&BlockFlagDead != 0 }

// SetDead marks this block dead.
// C++ parity: block.hh FlowBlock::setDead
func (b *FlowBlock) SetDead() { b.flags |= BlockFlagDead }

// IsDonothingLoop reports whether this block is a flagged do-nothing infinite loop.
// C++ parity: block.hh FlowBlock::isDonothingLoop
func (b *FlowBlock) IsDonothingLoop() bool { return b.flags&BlockFlagDoNothingLoop != 0 }

// SetDonothingLoop flags this block as a do-nothing infinite loop.
// C++ parity: block.hh FlowBlock::setDonothingLoop
func (b *FlowBlock) SetDonothingLoop() { b.flags |= BlockFlagDoNothingLoop }

// Parent returns the parent block.
func (b *FlowBlock) Parent() *FlowBlock { return b.parent }

// SetParent sets the parent block.
func (b *FlowBlock) SetParent(p *FlowBlock) { b.parent = p }

// ImmedDom returns the immediate dominator.
func (b *FlowBlock) ImmedDom() *FlowBlock { return b.immedDom }

// SetImmedDom sets the immediate dominator.
func (b *FlowBlock) SetImmedDom(d *FlowBlock) { b.immedDom = d }

// VisitCount returns the visit count (used during DFS).
func (b *FlowBlock) VisitCount() int32 { return b.visitCount }

// SetVisitCount sets the visit count.
func (b *FlowBlock) SetVisitCount(c int32) { b.visitCount = c }

// NumDesc returns the number of descendants.
func (b *FlowBlock) NumDesc() int32 { return b.numDesc }

// SetNumDesc sets the number of descendants.
func (b *FlowBlock) SetNumDesc(n int32) { b.numDesc = n }

// SizeIn returns the number of incoming edges.
func (b *FlowBlock) SizeIn() int { return len(b.inEdges) }

// SizeOut returns the number of outgoing edges.
func (b *FlowBlock) SizeOut() int { return len(b.outEdges) }

// InEdge returns the i-th incoming edge.
func (b *FlowBlock) InEdge(i int) BlockEdge { return b.inEdges[i] }

// OutEdge returns the i-th outgoing edge.
func (b *FlowBlock) OutEdge(i int) BlockEdge { return b.outEdges[i] }

// InRevIndex returns the reverse index for the i-th incoming edge.
func (b *FlowBlock) InRevIndex(i int) int { return b.inEdges[i].ReverseIndex }

// OutRevIndex returns the reverse index for the i-th outgoing edge.
func (b *FlowBlock) OutRevIndex(i int) int { return b.outEdges[i].ReverseIndex }

// GetInIndex returns the index of bl in this block's inEdges, or -1 if not found.
func (b *FlowBlock) GetInIndex(bl *FlowBlock) int {
	for i, e := range b.inEdges {
		if e.Point == bl {
			return i
		}
	}
	return -1
}

// GetOutIndex returns the index of bl in this block's outEdges, or -1 if not found.
func (b *FlowBlock) GetOutIndex(bl *FlowBlock) int {
	for i, e := range b.outEdges {
		if e.Point == bl {
			return i
		}
	}
	return -1
}

// FalseOut returns the false branch target (outEdges[0]).
func (b *FlowBlock) FalseOut() *FlowBlock { return b.outEdges[0].Point }

// TrueOut returns the true branch target (outEdges[1]).
func (b *FlowBlock) TrueOut() *FlowBlock { return b.outEdges[1].Point }

// C++ parity: block.cc FlowBlock::findCondition
func (b *FlowBlock) FindCondition(bl1 *FlowBlock, edge1 int, bl2 *FlowBlock, edge2 int) (*FlowBlock, int) {
	if b == nil || bl1 == nil || bl2 == nil || edge1 < 0 || edge2 < 0 || edge1 >= bl1.SizeIn() || edge2 >= bl2.SizeIn() {
		return nil, -1
	}
	cond := bl1.InEdge(edge1).Point
	for cond != nil && cond.SizeOut() != 2 {
		if cond.SizeOut() != 1 {
			return nil, -1
		}
		bl1 = cond
		edge1 = 0
		if bl1.SizeIn() == 0 {
			return nil, -1
		}
		cond = bl1.InEdge(0).Point
	}
	for cond != nil && bl2.InEdge(edge2).Point != cond {
		bl2 = bl2.InEdge(edge2).Point
		if bl2 == nil || bl2.SizeOut() != 1 {
			return nil, -1
		}
		edge2 = 0
	}
	if cond == nil {
		return nil, -1
	}
	return cond, bl1.InRevIndex(edge1)
}

// AddInEdge adds a bidirectional edge: b <- source.
// The new edge is appended to b.inEdges and source.outEdges with
// cross-referencing ReverseIndex values.
// C++ parity: block.cc FlowBlock::addInEdge
func (b *FlowBlock) AddInEdge(source *FlowBlock, label uint32) {
	inIdx := len(b.inEdges)
	outIdx := len(source.outEdges)
	b.inEdges = append(b.inEdges, BlockEdge{
		Label:        label,
		Point:        source,
		ReverseIndex: outIdx,
	})
	source.outEdges = append(source.outEdges, BlockEdge{
		Label:        label,
		Point:        b,
		ReverseIndex: inIdx,
	})
}

// halfDeleteInEdge removes inEdges[slot], sliding the subsequent edges down to
// preserve order (NOT a swap-with-last). Order preservation is required so the
// in-edge list stays in lockstep with a merge block's MULTIEQUAL inputs, which
// PcodeOp.RemoveInput / Funcdata.OpRemoveInput also slide down. A swap-with-last
// here would desync the two: removing a block's edge would leave the MULTIEQUAL
// input order (shifted) inconsistent with the in-edge order (swapped), permuting
// which predecessor feeds which phi slot.
// C++ parity: block.cc FlowBlock::halfDeleteInEdge (100).
func (b *FlowBlock) halfDeleteInEdge(slot int) {
	for slot < len(b.inEdges)-1 {
		b.inEdges[slot] = b.inEdges[slot+1] // slide the edge entry over
		// The moved edge came from slot+1; its mirror out-edge's ReverseIndex
		// pointed there, so decrement it to track the new position.
		moved := &b.inEdges[slot]
		moved.Point.outEdges[moved.ReverseIndex].ReverseIndex--
		slot++
	}
	b.inEdges = b.inEdges[:len(b.inEdges)-1]
}

// halfDeleteOutEdge removes outEdges[slot], sliding subsequent edges down to
// preserve order (mirror of halfDeleteInEdge).
// C++ parity: block.cc FlowBlock::halfDeleteOutEdge (115).
func (b *FlowBlock) halfDeleteOutEdge(slot int) {
	for slot < len(b.outEdges)-1 {
		b.outEdges[slot] = b.outEdges[slot+1] // slide the edge entry over
		moved := &b.outEdges[slot]
		moved.Point.inEdges[moved.ReverseIndex].ReverseIndex--
		slot++
	}
	b.outEdges = b.outEdges[:len(b.outEdges)-1]
}

// RemoveInEdge removes the bidirectional edge at inEdges[slot].
// C++ parity: block.cc FlowBlock::removeInEdge
func (b *FlowBlock) RemoveInEdge(slot int) {
	// Find the mirror outEdge on the source block.
	srcBlock := b.inEdges[slot].Point
	outSlot := b.inEdges[slot].ReverseIndex
	// Delete from source's outEdges first (may swap-move).
	srcBlock.halfDeleteOutEdge(outSlot)
	// If the source's halfDelete moved an edge into outSlot, that moved edge's
	// target block needs its inEdge ReverseIndex updated -- halfDeleteOutEdge
	// already did that. But our own inEdge[slot].ReverseIndex may now be stale
	// if the edge that was swapped in was NOT slot's edge. However, since we're
	// about to delete inEdge[slot] too, we only need to worry if slot's
	// ReverseIndex changed. Actually halfDeleteOutEdge already fixed any
	// moved edge's mirror. Now delete from our inEdges.
	b.halfDeleteInEdge(slot)
}

// RemoveOutEdge removes the bidirectional edge at outEdges[slot].
// C++ parity: block.cc FlowBlock::removeOutEdge
func (b *FlowBlock) RemoveOutEdge(slot int) {
	tgtBlock := b.outEdges[slot].Point
	inSlot := b.outEdges[slot].ReverseIndex
	tgtBlock.halfDeleteInEdge(inSlot)
	b.halfDeleteOutEdge(slot)
}

// ReplaceInEdge replaces the source block of inEdges[slot].
// C++ parity: block.cc FlowBlock::replaceInEdge
func (b *FlowBlock) ReplaceInEdge(slot int, newSrc *FlowBlock) {
	oldSrc := b.inEdges[slot].Point
	outSlot := b.inEdges[slot].ReverseIndex

	// Remove mirror from old source.
	oldSrc.halfDeleteOutEdge(outSlot)

	// Add new outEdge on newSrc.
	newOutIdx := len(newSrc.outEdges)
	newSrc.outEdges = append(newSrc.outEdges, BlockEdge{
		Label:        b.inEdges[slot].Label,
		Point:        b,
		ReverseIndex: slot,
	})
	b.inEdges[slot].Point = newSrc
	b.inEdges[slot].ReverseIndex = newOutIdx
}

// ReplaceOutEdge replaces the target block of outEdges[slot].
// C++ parity: block.cc FlowBlock::replaceOutEdge
func (b *FlowBlock) ReplaceOutEdge(slot int, newTgt *FlowBlock) {
	oldTgt := b.outEdges[slot].Point
	inSlot := b.outEdges[slot].ReverseIndex

	// Remove mirror from old target.
	oldTgt.halfDeleteInEdge(inSlot)

	// Add new inEdge on newTgt.
	newInIdx := len(newTgt.inEdges)
	newTgt.inEdges = append(newTgt.inEdges, BlockEdge{
		Label:        b.outEdges[slot].Label,
		Point:        b,
		ReverseIndex: slot,
	})
	b.outEdges[slot].Point = newTgt
	b.outEdges[slot].ReverseIndex = newInIdx
}

// SwapEdges swaps outEdges[0] and outEdges[1], fixing ReverseIndex on both
// sides, and toggles BlockFlagFlipPath.
// C++ parity: block.cc FlowBlock::swapEdges
func (b *FlowBlock) SwapEdges() {
	b.outEdges[0], b.outEdges[1] = b.outEdges[1], b.outEdges[0]

	// Fix ReverseIndex on the target's inEdges for both swapped edges.
	b.outEdges[0].Point.inEdges[b.outEdges[0].ReverseIndex].ReverseIndex = 0
	b.outEdges[1].Point.inEdges[b.outEdges[1].ReverseIndex].ReverseIndex = 1

	b.flags ^= BlockFlagFlipPath
}

// ForceFalseEdge pins outEdges[0] (the false out) to out0, swapping the two
// outgoing edges if necessary. Used when collapsing a binary condition so the
// false/true ordering is preserved, which later structuring rules rely on to
// decide whether to negate. A self-loop target (out0 collapsed into this block)
// is redirected to this block, matching C++.
// C++ parity: block.cc BlockGraph::forceFalseEdge
func (b *FlowBlock) ForceFalseEdge(out0 *FlowBlock) {
	if len(b.outEdges) != 2 {
		return // can only preserve a binary condition
	}
	if out0 != nil && out0.parent == b {
		out0 = b // allow for loops to self
	}
	if b.outEdges[0].Point != out0 {
		b.SwapEdges()
	}
}

// SetOutEdgeFlag sets flag bits on outEdges[i] and the mirror inEdge.
// C++ parity: block.cc FlowBlock::setOutEdgeFlag
func (b *FlowBlock) SetOutEdgeFlag(i int, lab uint32) {
	b.outEdges[i].Label |= lab
	tgt := b.outEdges[i].Point
	revIdx := b.outEdges[i].ReverseIndex
	tgt.inEdges[revIdx].Label |= lab
}

// ClearOutEdgeFlag clears flag bits on outEdges[i] and the mirror inEdge.
// C++ parity: block.cc FlowBlock::clearOutEdgeFlag
func (b *FlowBlock) ClearOutEdgeFlag(i int, lab uint32) {
	b.outEdges[i].Label &^= lab
	tgt := b.outEdges[i].Point
	revIdx := b.outEdges[i].ReverseIndex
	tgt.inEdges[revIdx].Label &^= lab
}

// SetDefaultSwitch marks out-edge pos as the switch default edge, clearing any
// edge that was previously flagged as the default (a switch has exactly one).
// C++ parity: block.cc FlowBlock::setDefaultSwitch
func (b *FlowBlock) SetDefaultSwitch(pos int) {
	for i := 0; i < len(b.outEdges); i++ {
		if b.outEdges[i].Label&EdgeFlagDefaultSwitch != 0 {
			b.ClearOutEdgeFlag(i, EdgeFlagDefaultSwitch)
		}
	}
	b.SetOutEdgeFlag(pos, EdgeFlagDefaultSwitch)
}

// HasLoopIn returns true if any incoming edge has EdgeFlagLoop.
func (b *FlowBlock) HasLoopIn() bool {
	for _, e := range b.inEdges {
		if e.Label&EdgeFlagLoop != 0 {
			return true
		}
	}
	return false
}

// HasLoopOut returns true if any outgoing edge has EdgeFlagLoop.
func (b *FlowBlock) HasLoopOut() bool {
	for _, e := range b.outEdges {
		if e.Label&EdgeFlagLoop != 0 {
			return true
		}
	}
	return false
}

// IsLoopIn returns true if inEdges[i] has EdgeFlagLoop.
func (b *FlowBlock) IsLoopIn(i int) bool { return b.inEdges[i].Label&EdgeFlagLoop != 0 }

// IsLoopOut returns true if outEdges[i] has EdgeFlagLoop.
func (b *FlowBlock) IsLoopOut(i int) bool { return b.outEdges[i].Label&EdgeFlagLoop != 0 }

// IsGotoIn returns true if inEdges[i] has EdgeFlagGoto.
func (b *FlowBlock) IsGotoIn(i int) bool { return b.inEdges[i].Label&EdgeFlagGoto != 0 }

// IsGotoOut returns true if outEdges[i] has EdgeFlagGoto.
func (b *FlowBlock) IsGotoOut(i int) bool { return b.outEdges[i].Label&EdgeFlagGoto != 0 }

// Dominates returns true if b dominates sub by walking the immedDom chain.
// C++ parity: block.cc FlowBlock::dominates
func (b *FlowBlock) Dominates(sub *FlowBlock) bool {
	cur := sub
	for cur != nil {
		if cur == b {
			return true
		}
		if cur.immedDom == cur {
			// Reached the root without finding b.
			return false
		}
		cur = cur.immedDom
	}
	return false
}

// FindCommonBlock finds the lowest common ancestor of bl1 and bl2 in the
// dominator tree using BlockFlagMark to detect intersection.
// C++ parity: block.cc FlowBlock::findCommonBlock
func FindCommonBlock(bl1, bl2 *FlowBlock) *FlowBlock {
	if bl1 == nil {
		return bl2
	}
	if bl2 == nil {
		return bl1
	}

	// Mark all ancestors of bl1.
	cur := bl1
	for cur != nil {
		cur.SetFlag(BlockFlagMark)
		if cur.immedDom == cur {
			break
		}
		cur = cur.immedDom
	}

	// Walk ancestors of bl2 until we find a marked block.
	var result *FlowBlock
	cur = bl2
	for cur != nil {
		if cur.HasFlag(BlockFlagMark) {
			result = cur
			break
		}
		if cur.immedDom == cur {
			break
		}
		cur = cur.immedDom
	}

	// Clear marks.
	cur = bl1
	for cur != nil {
		cur.ClearFlag(BlockFlagMark)
		if cur.immedDom == cur {
			break
		}
		cur = cur.immedDom
	}

	return result
}
