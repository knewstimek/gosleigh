package pcode

// BlockBasic is a basic block containing PcodeOps.
// C++ parity: block.hh BlockBasic
type BlockBasic struct {
	FlowBlock // embedded
	ops       []*PcodeOp
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

// AddOp appends an op to this basic block.
func (bb *BlockBasic) AddOp(op *PcodeOp) {
	bb.ops = append(bb.ops, op)
}

// RemoveOp finds and removes op from this basic block.
func (bb *BlockBasic) RemoveOp(op *PcodeOp) {
	for i, o := range bb.ops {
		if o == op {
			bb.ops = append(bb.ops[:i], bb.ops[i+1:]...)
			return
		}
	}
}

// InsertOpBefore inserts op before follow in the ops slice.
func (bb *BlockBasic) InsertOpBefore(op, follow *PcodeOp) {
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
	bb.ops = append([]*PcodeOp{op}, bb.ops...)
}

// InsertOpEnd appends op to the ops slice.
func (bb *BlockBasic) InsertOpEnd(op *PcodeOp) {
	bb.ops = append(bb.ops, op)
}

// FirstOp returns the first op, or nil if empty.
func (bb *BlockBasic) FirstOp() *PcodeOp {
	if len(bb.ops) == 0 {
		return nil
	}
	return bb.ops[0]
}

// LastOp returns the last op, or nil if empty.
func (bb *BlockBasic) LastOp() *PcodeOp {
	if len(bb.ops) == 0 {
		return nil
	}
	return bb.ops[len(bb.ops)-1]
}

// EmptyOp returns true if there are no ops.
func (bb *BlockBasic) EmptyOp() bool { return len(bb.ops) == 0 }

// NumOps returns the number of ops.
func (bb *BlockBasic) NumOps() int { return len(bb.ops) }

// Ops returns a copy of the ops slice.
func (bb *BlockBasic) Ops() []*PcodeOp {
	out := make([]*PcodeOp, len(bb.ops))
	copy(out, bb.ops)
	return out
}

// NegateCondition flips PcodeOpBooleanFlip and PcodeOpFallthruTrue on the
// CBRANCH (last) op, then swaps the two outgoing edges if present.
// C++ parity: block.cc BlockBasic::negateCondition -- always uses op.back()
// regardless of the top parameter, then calls FlowBlock::negateCondition(true)
// which swaps edges.
func (bb *BlockBasic) NegateCondition(top bool) {
	if len(bb.ops) == 0 {
		return
	}
	// C++ always flips the last op (CBRANCH), ignoring the top parameter.
	target := bb.ops[len(bb.ops)-1]
	target.FlipFlag(PcodeOpBooleanFlip)
	target.FlipFlag(PcodeOpFallthruTrue)
	// C++ FlowBlock::negateCondition(true) -> swapEdges(); only valid with 2 edges.
	if bb.FlowBlock.SizeOut() == 2 {
		bb.FlowBlock.SwapEdges()
	}
}
