package pcode

// This file ports the structure-graph flow helpers that ActionReturnSplit's
// gatherReturnGotos relies on to decide whether a BlockGoto actually prints a
// goto statement (and therefore whether its in-edge to a RETURN block should be
// split). C++ dispatches nextFlowAfter virtually per block type; Gosleigh's
// FlowBlock is a single struct, so the dispatch is a switch on Type().

// getFrontLeaf descends the structured hierarchy taking the first child until a
// leaf (a block with no structured children, i.e. a BlockCopy/basic leaf) is
// reached -- the first FlowBlock that would execute.
// C++ parity: FlowBlock::getFrontLeaf (block.cc:354). C++ stops at t_copy; the
// Gosleigh structure leaves carry no children, which is the same stopping point.
func (b *FlowBlock) getFrontLeaf() *FlowBlock {
	bl := b
	for len(bl.StructuredChildren()) > 0 {
		bl = bl.StructuredChildren()[0]
		if bl == nil {
			return bl
		}
	}
	return bl
}

// nextFlowAfter returns the structure-graph leaf that executes immediately after
// child bl within b's printed flow, or nil when flow is not statically known.
// C++ parity: block.cc <BlockType>::nextFlowAfter (virtual).
func (b *FlowBlock) nextFlowAfter(bl *FlowBlock) *FlowBlock {
	switch b.Type() {
	case BlockGotoType:
		// BlockGoto::nextFlowAfter (block.cc:2899).
		if tgt := b.GotoTargetBlock(); tgt != nil {
			return tgt.getFrontLeaf()
		}
		return nil
	case BlockMultiGotoType, BlockConditionType, BlockDoWhileType:
		// nextFlowAfter returns null for these (block.cc:2931/3053/3448).
		return nil
	case BlockIfType:
		// BlockIf::nextFlowAfter (block.cc:3127).
		children := b.StructuredChildren()
		if len(children) > 0 && children[0] == bl {
			return nil // Do not know where flow goes
		}
		if b.Parent() == nil {
			return nil
		}
		return b.Parent().nextFlowAfter(b)
	case BlockWhileDoType:
		// BlockWhileDo::nextFlowAfter (block.cc:3341).
		children := b.StructuredChildren()
		if len(children) > 0 && children[0] == bl {
			return nil
		}
		if len(children) > 0 {
			return children[0].getFrontLeaf()
		}
		return nil
	case BlockInfLoopType:
		// BlockInfLoop::nextFlowAfter (block.cc:3476).
		children := b.StructuredChildren()
		if len(children) > 0 {
			return children[0].getFrontLeaf()
		}
		return nil
	case BlockSwitchType:
		return b.switchNextFlowAfter(bl)
	default:
		// BlockList / BlockGraph base (block.cc:1335).
		return b.listNextFlowAfter(bl)
	}
}

// listNextFlowAfter implements the BlockGraph base nextFlowAfter: the sibling
// after bl in the child list (its front leaf), else recurse to the parent.
// C++ parity: BlockGraph::nextFlowAfter (block.cc:1335).
func (b *FlowBlock) listNextFlowAfter(bl *FlowBlock) *FlowBlock {
	children := b.StructuredChildren()
	idx := -1
	for i, c := range children {
		if c == bl {
			idx = i
			break
		}
	}
	next := idx + 1
	if idx < 0 || next >= len(children) {
		if b.Parent() == nil {
			return nil
		}
		return b.Parent().nextFlowAfter(b)
	}
	nextbl := children[next]
	if nextbl != nil {
		nextbl = nextbl.getFrontLeaf()
	}
	return nextbl
}

// switchNextFlowAfter implements BlockSwitch::nextFlowAfter: fall-through from
// one case block (a t_goto) to the next case in print order, else the switch
// exit. Child 0 is the switch head; children[1:] are the case blocks in
// fall-through print order.
// C++ parity: BlockSwitch::nextFlowAfter (block.cc:3639).
func (b *FlowBlock) switchNextFlowAfter(bl *FlowBlock) *FlowBlock {
	children := b.StructuredChildren()
	if len(children) > 0 && children[0] == bl {
		return nil // Do not know where flow goes
	}
	// Fall-through must be a goto block; otherwise a break statement is in flow.
	if bl.Type() != BlockGotoType {
		return nil
	}
	for i := 1; i < len(children); i++ {
		if children[i] != bl {
			continue
		}
		if i+1 < len(children) {
			return children[i+1].getFrontLeaf()
		}
		if b.Parent() == nil {
			return nil
		}
		return b.Parent().nextFlowAfter(b)
	}
	return nil
}

// gotoPrints reports whether a BlockGoto emits a formal goto statement: it does
// unless its target's front leaf is exactly the block that flows next anyway.
// C++ parity: BlockGoto::gotoPrints (block.cc:2881).
func (b *FlowBlock) gotoPrints() bool {
	if b.Parent() == nil {
		return false
	}
	nextbl := b.Parent().nextFlowAfter(b)
	tgt := b.GotoTargetBlock()
	if tgt == nil {
		return false
	}
	return tgt.getFrontLeaf() != nextbl
}

// structuredGotoTargetBasic descends a goto target to its leaf and unwraps the
// structure clone to the original basic block it delegates to, so the identity
// comparison against op.Parent() (an original BlockBasic) in gatherReturnGotos
// matches. C++ descends subBlock(0) until t_basic, where BlockCopy::subBlock
// returns the wrapped original block; Gosleigh's leaves are BlockBasic clones
// that reach the original via srcDelegate.
// C++ parity: the while-descent + compare in ActionReturnSplit::gatherReturnGotos
// (blockaction.cc:2223).
func structuredGotoTargetBasic(ret *FlowBlock) *FlowBlock {
	for len(ret.StructuredChildren()) > 0 {
		ret = ret.StructuredChildren()[0]
		if ret == nil {
			return nil
		}
	}
	if bb := asBasic(ret); bb != nil && bb.srcDelegate != nil {
		return &bb.srcDelegate.FlowBlock
	}
	return ret
}
