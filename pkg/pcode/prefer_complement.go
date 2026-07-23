package pcode

// prefer_complement.go -- ActionPreferComplement and supporting helpers.
//
// C++ parity:
//   Funcdata::opFlipInPlaceTest / opFlipInPlaceExecute / replaceLessequal
//   BlockBasic::flipInPlaceTest / flipInPlaceExecute / getSplitPoint
//   BlockIf::preferComplement
//   ActionPreferComplement::apply

// getBooleanFlipOpcode returns the complement opcode for a comparison op and
// whether the operands must be swapped (reorder).
// Returns CPUI_MAX if op cannot be complemented by opcode change alone.
// CPUI_COPY is a sentinel meaning "remove the op entirely" (for BOOL_NEGATE).
// C++ parity: opcodes.cc get_booleanflip
func getBooleanFlipOpcode(opc OpCode) (flip OpCode, reorder bool, ok bool) {
	switch opc {
	case CPUI_INT_EQUAL:
		return CPUI_INT_NOTEQUAL, false, true
	case CPUI_INT_NOTEQUAL:
		return CPUI_INT_EQUAL, false, true
	case CPUI_INT_SLESS:
		return CPUI_INT_SLESSEQUAL, true, true
	case CPUI_INT_SLESSEQUAL:
		return CPUI_INT_SLESS, true, true
	case CPUI_INT_LESS:
		return CPUI_INT_LESSEQUAL, true, true
	case CPUI_INT_LESSEQUAL:
		return CPUI_INT_LESS, true, true
	case CPUI_BOOL_NEGATE:
		// Sentinel: remove the op by propagating input[0] directly.
		return CPUI_COPY, false, true
	case CPUI_BOOL_AND, CPUI_BOOL_OR:
		// Sentinel CPUI_MAX (with ok=true) routes opFlipInPlaceExecute to its
		// De Morgan branch, which swaps BOOL_AND<->BOOL_OR. opFlipInPlaceTest
		// already recurses into both operands so they are flipped too; without
		// this case the op was skipped (ok=false), flipping the operands but NOT
		// the connective -- e.g. negating (a!=0 && a>=0) wrongly yielded
		// (a==0 && a<0) instead of (a==0 || a<0). C++ parity: funcdata_op.cc
		// Funcdata::opFlipInPlaceExecute handles CPUI_BOOL_AND/CPUI_BOOL_OR.
		return CPUI_MAX, false, true
	case CPUI_FLOAT_EQUAL:
		return CPUI_FLOAT_NOTEQUAL, false, true
	case CPUI_FLOAT_NOTEQUAL:
		return CPUI_FLOAT_EQUAL, false, true
	case CPUI_FLOAT_LESS:
		return CPUI_FLOAT_LESSEQUAL, true, true
	case CPUI_FLOAT_LESSEQUAL:
		return CPUI_FLOAT_LESS, true, true
	}
	return CPUI_MAX, false, false
}

// replaceLessequal converts "c <= x" to "c-1 < x" or "x <= c" to "x < c+1"
// in-place on op using fd to allocate the adjusted constant varnode.
// Changes the opcode to INT_SLESS or INT_LESS.
// Returns false if the constant adjustment would overflow.
// C++ parity: funcdata_op.cc Funcdata::replaceLessequal
func replaceLessequal(fd *Funcdata, op *PcodeOp) bool {
	if op == nil || op.NumInput() < 2 {
		return false
	}

	in0 := op.Input(0)
	in1 := op.Input(1)
	isSigned := (op.Code() == CPUI_INT_SLESSEQUAL)

	var constIdx int
	var diff int64
	var vn *Varnode
	if in0 != nil && in0.IsConstant() {
		constIdx = 0
		diff = -1
		vn = in0
	} else if in1 != nil && in1.IsConstant() {
		constIdx = 1
		diff = 1
		vn = in1
	} else {
		return false
	}

	val := int64(vn.Offset())
	sz := vn.Size()

	if isSigned {
		minVal := int64(-1) << (uint(sz)*8 - 1)
		maxVal := (int64(1) << (uint(sz)*8 - 1)) - 1
		if diff == -1 && val == minVal {
			return false
		}
		if diff == 1 && val == maxVal {
			return false
		}
		// C++ parity: res = (val+diff) & calc_mask(size). NewConstant does not
		// mask, so mask here or a -1 result is stored as full-width 0xff..ff in
		// an undersized varnode and the printer mis-renders it.
		newVn := fd.NewConstant(sz, uint64(val+diff)&maskForSize(sz))
		op.SetInput(newVn, constIdx)
		fd.OpSetOpcode(op, CPUI_INT_SLESS)
	} else {
		var maxUnsigned uint64
		if sz >= 8 {
			maxUnsigned = ^uint64(0)
		} else {
			maxUnsigned = (uint64(1) << (uint(sz) * 8)) - 1
		}
		uval := vn.Offset()
		if diff == -1 && uval == 0 {
			return false
		}
		if diff == 1 && uval == maxUnsigned {
			return false
		}
		// C++ parity: res = (val+diff) & calc_mask(size). See signed branch note.
		newVn := fd.NewConstant(sz, uint64(int64(uval)+diff)&maskForSize(sz))
		op.SetInput(newVn, constIdx)
		fd.OpSetOpcode(op, CPUI_INT_LESS)
	}
	return true
}

// opFlipInPlaceTest recursively checks whether the boolean output of op can be
// flipped by changing opcodes in-place (no new ops inserted).
// Returns 0 (normalizes), 1 (ambivalent), 2 (not possible).
// Appends ops that need opcode changes to *fliplist.
// C++ parity: funcdata_op.cc Funcdata::opFlipInPlaceTest
func opFlipInPlaceTest(op *PcodeOp, fliplist *[]*PcodeOp) int {
	if op == nil {
		return 2
	}
	switch op.Code() {
	case CPUI_CBRANCH:
		if op.NumInput() < 2 {
			return 2
		}
		vn := op.Input(1)
		if vn == nil || !vn.IsWritten() || vn.NumDescend() != 1 {
			return 2
		}
		return opFlipInPlaceTest(vn.Def(), fliplist)

	case CPUI_INT_EQUAL, CPUI_FLOAT_EQUAL:
		*fliplist = append(*fliplist, op)
		return 1

	case CPUI_BOOL_NEGATE, CPUI_INT_NOTEQUAL, CPUI_FLOAT_NOTEQUAL:
		*fliplist = append(*fliplist, op)
		return 0

	case CPUI_INT_SLESS, CPUI_INT_LESS:
		*fliplist = append(*fliplist, op)
		if op.NumInput() > 0 && op.Input(0) != nil && op.Input(0).IsConstant() {
			return 0
		}
		return 1

	case CPUI_INT_SLESSEQUAL, CPUI_INT_LESSEQUAL:
		*fliplist = append(*fliplist, op)
		if op.NumInput() > 1 && op.Input(1) != nil && op.Input(1).IsConstant() {
			return 1
		}
		return 0

	case CPUI_BOOL_OR, CPUI_BOOL_AND:
		if op.NumInput() < 2 {
			return 2
		}
		vn0 := op.Input(0)
		if vn0 == nil || !vn0.IsWritten() || vn0.NumDescend() != 1 {
			return 2
		}
		vn1 := op.Input(1)
		if vn1 == nil || !vn1.IsWritten() || vn1.NumDescend() != 1 {
			return 2
		}
		sub0 := opFlipInPlaceTest(vn0.Def(), fliplist)
		if sub0 == 2 {
			return 2
		}
		sub1 := opFlipInPlaceTest(vn1.Def(), fliplist)
		if sub1 == 2 {
			return 2
		}
		*fliplist = append(*fliplist, op)
		return sub0
	}
	return 2
}

// opFlipInPlaceExecute applies in-place opcode changes to flip a boolean value.
// The fliplist was built by opFlipInPlaceTest.
// fd is needed to allocate adjusted constant varnodes in replaceLessequal.
// C++ parity: funcdata_op.cc Funcdata::opFlipInPlaceExecute
func opFlipInPlaceExecute(fd *Funcdata, fliplist []*PcodeOp) {
	for _, op := range fliplist {
		if op == nil || op.IsDead() {
			continue
		}
		flipOpc, reorder, ok := getBooleanFlipOpcode(op.Code())
		if !ok {
			continue
		}
		switch {
		case flipOpc == CPUI_COPY:
			// BOOL_NEGATE removal: propagate input[0] to the lone consumer slot.
			if op.NumInput() == 0 || op.Output() == nil {
				continue
			}
			src := op.Input(0)
			out := op.Output()
			if out.NumDescend() != 1 {
				continue
			}
			var consumer *PcodeOp
			for _, c := range out.DescendIter() {
				consumer = c
				break
			}
			if consumer == nil {
				continue
			}
			slot := -1
			for i := 0; i < consumer.NumInput(); i++ {
				if consumer.Input(i) == out {
					slot = i
					break
				}
			}
			if slot < 0 {
				continue
			}
			consumer.SetInput(src, slot)
			op.SetFlag(PcodeOpDead)

		case flipOpc == CPUI_MAX:
			// BOOL_AND <-> BOOL_OR swap.
			if op.Code() == CPUI_BOOL_AND {
				fd.OpSetOpcode(op, CPUI_BOOL_OR)
			} else if op.Code() == CPUI_BOOL_OR {
				fd.OpSetOpcode(op, CPUI_BOOL_AND)
			}

		default:
			fd.OpSetOpcode(op, flipOpc)
			if reorder && op.NumInput() >= 2 {
				in0 := op.Input(0)
				in1 := op.Input(1)
				op.SetInput(in1, 0)
				op.SetInput(in0, 1)
				// After reordering LESS(EQUAL), apply c+/-1 constant adjustment.
				if flipOpc == CPUI_INT_LESSEQUAL || flipOpc == CPUI_INT_SLESSEQUAL {
					replaceLessequal(fd, op)
				}
			}
		}
	}
}

// getSplitPoint returns the deepest component FlowBlock that performs the
// conditional split -- the component able to run flipInPlaceTest /
// flipInPlaceExecute -- or nil when b does not end in a conditional branch.
//
// C++ parity (the virtual overrides, in dispatch order):
//   - FlowBlock::getSplitPoint      (block.hh:845) -> nil (BlockGoto, BlockIf,
//     BlockWhileDo, BlockSwitch, ... all inherit this)
//   - BlockBasic::getSplitPoint     (block.cc:2361) -> this when sizeOut()==2
//   - BlockCopy::getSplitPoint      (block.hh:535)  -> copy->getSplitPoint()
//   - BlockList::getSplitPoint      (block.cc:2976) -> last child's split point
//   - BlockCondition::getSplitPoint (block.hh:631)  -> this
//
// Gosleigh's structure-graph leaf is a *BlockBasic carrying srcDelegate, so the
// BlockCopy case folds into the *BlockBasic branch. The BlockCondition case is
// what lets ActionPreferComplement reach a compound &&/|| condition: without
// it, a condition block fell into the generic "recurse into the last child"
// path and reported a leaf of its right half as the split point, so the De
// Morgan flip was tested against half the expression and never applied.
func (b *FlowBlock) getSplitPoint() *FlowBlock {
	if b == nil {
		return nil
	}
	switch c := b.Concrete().(type) {
	case *BlockBasic:
		// A structure-graph leaf is Gosleigh's stand-in for BlockCopy: it carries
		// srcDelegate to the source basic block. Collapse moves a leaf's external
		// out-edges up to the enclosing structured block, so a leaf inside a
		// BlockCondition ends up with SizeOut()==1 and would fail the sizeOut()==2
		// test -- but C++ tests the WRAPPED block, whose edges collapse never
		// touches. C++ parity: BlockCopy::getSplitPoint -> copy->getSplitPoint().
		if c.srcDelegate != nil {
			return c.srcDelegate.FlowBlock.getSplitPoint()
		}
		if b.SizeOut() != 2 {
			return nil
		}
		return b
	case *BlockCondition:
		return b
	}
	if b.Type() == BlockListType {
		children := b.StructuredChildren()
		if len(children) == 0 {
			return nil
		}
		return children[len(children)-1].getSplitPoint()
	}
	return nil
}

// flipInPlaceTestBlock tests whether the condition computed by split point b can
// be negated purely by in-place opcode changes, appending the ops that need
// changing to fliplist. Returns 0 when the flip normalizes the condition, 1 when
// it is neutral, 2 when it is impossible.
//
// C++ parity: FlowBlock::flipInPlaceTest (block.hh:862, default 2),
// BlockBasic::flipInPlaceTest (block.cc:2368),
// BlockCondition::flipInPlaceTest (block.cc:2990).
func flipInPlaceTestBlock(b *FlowBlock, fliplist *[]*PcodeOp) int {
	if b == nil {
		return 2
	}
	switch c := b.Concrete().(type) {
	case *BlockBasic:
		if c.EmptyOp() {
			return 2
		}
		lastOp := c.LastOp()
		if lastOp == nil || lastOp.Code() != CPUI_CBRANCH {
			return 2
		}
		return opFlipInPlaceTest(lastOp, fliplist)
	case *BlockCondition:
		// Both halves must be flippable; the result of the FRONT half decides
		// whether the whole flip normalizes ("Front of AND/OR must be
		// normalizing", funcdata_op.cc:1270 makes the same choice for the
		// BOOL_AND/BOOL_OR p-code form of this shape).
		children := b.StructuredChildren()
		if len(children) != 2 {
			return 2
		}
		split1 := children[0].getSplitPoint()
		if split1 == nil {
			return 2
		}
		split2 := children[1].getSplitPoint()
		if split2 == nil {
			return 2
		}
		sub1 := flipInPlaceTestBlock(split1, fliplist)
		if sub1 == 2 {
			return 2
		}
		if sub2 := flipInPlaceTestBlock(split2, fliplist); sub2 == 2 {
			return 2
		}
		return sub1
	}
	return 2
}

// flipInPlaceExecuteBlock performs the flip that flipInPlaceTestBlock validated.
// For a basic block it flips the fall-thru sense of the CBRANCH and swaps the
// outgoing edges, without touching the BooleanFlip flag (the opcode change
// already inverts the logical sense). For a condition block it applies De
// Morgan: swap the connective and push the negation into both halves. A
// condition block does not reorder its own outgoing edges -- only the leaf
// basic blocks do.
//
// C++ parity: BlockBasic::flipInPlaceExecute (block.cc:2378),
// BlockCondition::flipInPlaceExecute (block.cc:3008).
func flipInPlaceExecuteBlock(b *FlowBlock) {
	if b == nil {
		return
	}
	switch c := b.Concrete().(type) {
	case *BlockBasic:
		if c.EmptyOp() {
			return
		}
		lastOp := c.LastOp()
		if lastOp == nil {
			return
		}
		lastOp.FlipFlag(PcodeOpFallthruTrue)
		if b.SizeOut() == 2 {
			b.SwapEdges()
		}
	case *BlockCondition:
		if c.opc == CPUI_BOOL_AND {
			c.opc = CPUI_BOOL_OR
		} else {
			c.opc = CPUI_BOOL_AND
		}
		children := b.StructuredChildren()
		if len(children) > 0 {
			flipInPlaceExecuteBlock(children[0].getSplitPoint())
		}
		if len(children) > 1 {
			flipInPlaceExecuteBlock(children[1].getSplitPoint())
		}
	}
}

// preferComplementBlockIf applies the complement transform to an if-else block.
// It flips the condition so the "normalizing" form is used (e.g. "x < 1" over
// "0 < x") and swaps the then/else child blocks accordingly.
// Returns true if a change was made.
// C++ parity: block.cc BlockIf::preferComplement
func preferComplementBlockIf(fd *Funcdata, bl *FlowBlock) bool {
	if bl == nil || bl.Type() != BlockIfType {
		return false
	}
	children := bl.StructuredChildren()
	if len(children) != 3 {
		return false
	}
	split := children[0].getSplitPoint()
	if split == nil {
		return false
	}
	var fliplist []*PcodeOp
	if flipInPlaceTestBlock(split, &fliplist) != 0 {
		// Only apply when flip normalizes (result==0). Ghidra skips ambivalent cases.
		return false
	}
	// C++ order (block.cc:3105): flipInPlaceExecute first, then opFlipInPlaceExecute.
	flipInPlaceExecuteBlock(split)
	opFlipInPlaceExecute(fd, fliplist)
	// Swap then-clause (children[1]) and else-clause (children[2]).
	bl.setStructuredChildren([]*FlowBlock{children[0], children[2], children[1]})
	return true
}

// ActionPreferComplement post-processes the structured graph, applying
// preferComplementBlockIf to every if-else (BlockIf with 3 children) node.
// This normalizes conditions like "0 < x" to "x < 1".
// C++ parity: blockaction.cc ActionPreferComplement::apply
type ActionPreferComplement struct {
	ActionBase
}

func NewActionPreferComplement(group string) *ActionPreferComplement {
	act := &ActionPreferComplement{}
	act.ActionBase = NewActionBase(act, 0, "prefercomplement", group)
	return act
}

func (a *ActionPreferComplement) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionPreferComplement(a.GetGroup())
}

// applyPreferComplement recursively walks structured FlowBlock children and
// applies preferComplementBlockIf to every BlockIfType node encountered.
func (a *ActionPreferComplement) applyPreferComplement(fd *Funcdata, bl *FlowBlock) {
	if bl == nil {
		return
	}
	if bl.Type() == BlockIfType {
		if preferComplementBlockIf(fd, bl) {
			a.count++
		}
	}
	// Always recurse into structured children regardless of type.
	for _, ch := range bl.StructuredChildren() {
		a.applyPreferComplement(fd, ch)
	}
}

// Apply walks the structured graph and applies preferComplementBlockIf to
// every BlockIf node in the structured CFG.
// C++ parity: ActionPreferComplement::apply
func (a *ActionPreferComplement) Apply(data *Funcdata) int {
	graph := data.getStructure()
	if graph == nil || graph.GetSize() == 0 {
		return 0
	}
	for i := 0; i < graph.GetSize(); i++ {
		a.applyPreferComplement(data, graph.GetBlock(i))
	}
	return 0
}
