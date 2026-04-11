package pcode

type RulePiece2Zext struct{ batchRule }

func NewRulePiece2Zext(group string) *RulePiece2Zext {
	r := &RulePiece2Zext{}
	r.batchRule = newBatchRule(group, "piece2zext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRulePiece2Zext(g) })
	return r
}

func (r *RulePiece2Zext) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(0)) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, op.Input(1))
	return 1
}

type RulePiece2Sext struct{ batchRule }

func NewRulePiece2Sext(group string) *RulePiece2Sext {
	r := &RulePiece2Sext{}
	r.batchRule = newBatchRule(group, "piece2sext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRulePiece2Sext(g) })
	return r
}

func (r *RulePiece2Sext) apply(op *PcodeOp, data *Funcdata) int {
	shift := definedBy(op.Input(0), CPUI_INT_SRIGHT)
	if shift == nil || !sameValue(shift.Input(0), op.Input(1)) {
		return 0
	}
	val, ok := constantValue(shift.Input(1))
	if !ok || val != uint64(op.Input(1).Size()*8-1) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_SEXT, op.Input(1))
	return 1
}

type RuleZextEliminate struct{ batchRule }

func NewRuleZextEliminate(group string) *RuleZextEliminate {
	r := &RuleZextEliminate{}
	r.batchRule = newBatchRule(group, "zexteliminate", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleZextEliminate(g) })
	return r
}

func (r *RuleZextEliminate) apply(op *PcodeOp, data *Funcdata) int {
	in := op.Input(0)
	if in.Size() == outputOrInputSize(op) {
		return rewriteToCopy(data, op, in)
	}
	if val, ok := constantValue(in); ok {
		return rewriteToCopy(data, op, data.NewConstant(outputOrInputSize(op), val))
	}
	return 0
}

type RuleSlessToLess struct{ batchRule }

func NewRuleSlessToLess(group string) *RuleSlessToLess {
	r := &RuleSlessToLess{}
	r.batchRule = newBatchRule(group, "slesstoless", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleSlessToLess(g) })
	return r
}

func (r *RuleSlessToLess) apply(op *PcodeOp, data *Funcdata) int {
	left := definedBy(op.Input(0), CPUI_INT_ZEXT)
	right := definedBy(op.Input(1), CPUI_INT_ZEXT)
	if left == nil || right == nil {
		return 0
	}
	if left.Input(0).Size() != right.Input(0).Size() {
		return 0
	}
	if op.Code() == CPUI_INT_SLESS {
		rewriteOp(data, op, CPUI_INT_LESS, left.Input(0), right.Input(0))
	} else {
		rewriteOp(data, op, CPUI_INT_LESSEQUAL, left.Input(0), right.Input(0))
	}
	return 1
}

type RuleZextSless struct{ batchRule }

func NewRuleZextSless(group string) *RuleZextSless {
	r := &RuleZextSless{}
	r.batchRule = newBatchRule(group, "zextsless", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleZextSless(g) })
	return r
}

func (r *RuleZextSless) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val != 0 {
		return 0
	}
	ext := definedBy(lhs, CPUI_INT_ZEXT)
	if ext == nil {
		return 0
	}
	if op.Code() == CPUI_INT_SLESS {
		return rewriteToConst(data, op, 0)
	}
	rewriteOp(data, op, CPUI_INT_EQUAL, ext.Input(0), data.NewConstant(ext.Input(0).Size(), 0))
	return 1
}

type RuleConcatZext struct{ batchRule }

func NewRuleConcatZext(group string) *RuleConcatZext {
	r := &RuleConcatZext{}
	r.batchRule = newBatchRule(group, "concatzext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatZext(g) })
	return r
}

func (r *RuleConcatZext) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(0)) {
		return 0
	}
	ext := definedBy(op.Input(1), CPUI_INT_ZEXT)
	if ext == nil {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, ext.Input(0))
	return 1
}

type RuleZextCommute struct{ batchRule }

func NewRuleZextCommute(group string) *RuleZextCommute {
	r := &RuleZextCommute{}
	r.batchRule = newBatchRule(group, "zextcommute", []OpCode{CPUI_INT_ZEXT, CPUI_INT_SEXT}, r.apply, func(g string) Rule { return NewRuleZextCommute(g) })
	return r
}

func (r *RuleZextCommute) apply(op *PcodeOp, data *Funcdata) int {
	copyop := definedBy(op.Input(0), CPUI_COPY)
	if copyop == nil {
		return 0
	}
	rewriteOp(data, op, op.Code(), copyop.Input(0))
	return 1
}

type RuleZextShiftZext struct{ batchRule }

func NewRuleZextShiftZext(group string) *RuleZextShiftZext {
	r := &RuleZextShiftZext{}
	r.batchRule = newBatchRule(group, "zextshiftzext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleZextShiftZext(g) })
	return r
}

func (r *RuleZextShiftZext) apply(op *PcodeOp, data *Funcdata) int {
	inner := definedBy(op.Input(0), CPUI_INT_ZEXT)
	if inner == nil {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, inner.Input(0))
	return 1
}

type RuleSubZext struct{ batchRule }

func NewRuleSubZext(group string) *RuleSubZext {
	r := &RuleSubZext{}
	r.batchRule = newBatchRule(group, "subzext", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubZext(g) })
	return r
}

func (r *RuleSubZext) apply(op *PcodeOp, data *Funcdata) int {
	ext := definedBy(op.Input(0), CPUI_INT_ZEXT)
	if ext == nil || !isZeroConst(op.Input(1)) || outputSize(op) != ext.Input(0).Size() {
		return 0
	}
	return rewriteToCopy(data, op, ext.Input(0))
}

type RuleSubExtComm struct{ batchRule }

func NewRuleSubExtComm(group string) *RuleSubExtComm {
	r := &RuleSubExtComm{}
	r.batchRule = newBatchRule(group, "subextcomm", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubExtComm(g) })
	return r
}

func (r *RuleSubExtComm) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(1)) {
		return 0
	}
	for _, opc := range []OpCode{CPUI_INT_ZEXT, CPUI_INT_SEXT} {
		ext := definedBy(op.Input(0), opc)
		if ext == nil {
			continue
		}
		base := ext.Input(0)
		if outputSize(op) == base.Size() {
			return rewriteToCopy(data, op, base)
		}
		if outputSize(op) < base.Size() {
			rewriteOp(data, op, CPUI_SUBPIECE, base, data.NewConstant(op.Input(1).Size(), 0))
			return 1
		}
	}
	return 0
}

// RuleSubCommute pushes SUBPIECE earlier into arithmetic/bitwise expressions,
// commuting it past INT_MULT, INT_ADD, INT_XOR, INT_AND, INT_OR, INT_NEGATE.
// Only the low-part (offset==0) truncation commutes with INT_MULT and INT_ADD.
// After commuting, RuleSubExtComm or constant folding can cancel the SEXT/ZEXT.
// C++ parity: RuleSubCommute::applyOp in ruleaction.cc
type RuleSubCommute struct{ batchRule }

func NewRuleSubCommute(group string) *RuleSubCommute {
	r := &RuleSubCommute{}
	r.batchRule = newBatchRule(group, "subcommute", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubCommute(g) })
	return r
}

func (r *RuleSubCommute) apply(op *PcodeOp, data *Funcdata) int {
	base := op.Input(0)
	if base == nil || !base.IsWritten() {
		return 0
	}
	offset, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	// Precis lo/hi varnodes are managed by PIECE reconstruction -- do not disturb.
	if outvn.IsPrecisLo() || outvn.IsPrecisHi() {
		return 0
	}
	longform := base.Def()
	if longform == nil {
		return 0
	}
	// Determine whether SUBPIECE commutes through this opcode.
	// INT_MULT and INT_ADD only commute when truncating the low part (offset==0).
	// Bitwise ops commute regardless of offset.
	switch longform.Code() {
	case CPUI_INT_MULT, CPUI_INT_ADD:
		if offset != 0 {
			return 0
		}
		// Deconflict INT_ADD with RulePtrArith: skip if input 0 is spacebase.
		if longform.Code() == CPUI_INT_ADD && longform.Input(0) != nil && longform.Input(0).IsSpaceBase() {
			return 0
		}
	case CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR:
		// commutes for any offset
	default:
		return 0
	}

	// base must be consumed only by this SUBPIECE.
	if base.LoneDescend() != op {
		return 0
	}

	// Overlap check with RuleSubZext: if the sole consumer of outvn is an INT_ZEXT
	// that restores the original size, let RuleSubZext handle it instead.
	if offset == 0 {
		next := outvn.LoneDescend()
		if next != nil && next.Code() == CPUI_INT_ZEXT && next.Output() != nil &&
			next.Output().Size() == int32(base.Size()) {
			return 0
		}
	}

	// Push SUBPIECE through each input of longform.
	// Track the last input varnode so we can reuse the same SUBPIECE op when
	// both inputs are the same varnode (INT_MULT x,x corner case).
	var lastIn *Varnode
	var newVn *Varnode
	outSize := outvn.Size()
	for i := 0; i < longform.NumInput(); i++ {
		vn := longform.Input(i)
		if vn == nil {
			return 0
		}
		if lastIn != vn || newVn == nil {
			newsub := data.NewOp(2, op.Seq().Address)
			data.OpSetOpcode(newsub, CPUI_SUBPIECE)
			newVn = data.NewUniqueOut(outSize, newsub)
			// Set the new varnode as the ith input of longform before wiring newsub
			// inputs, because vn may still be free (not yet in the bank).
			data.OpSetInput(longform, newVn, i)
			data.OpSetInput(newsub, vn, 0)
			data.OpSetInput(newsub, data.NewConstant(4, offset), 1)
			data.OpInsertBefore(newsub, longform)
		} else {
			// Same varnode -- reuse the already-created SUBPIECE output.
			data.OpSetInput(longform, newVn, i)
		}
		lastIn = vn
	}
	// Redirect longform's output to reuse outvn (which is the SUBPIECE output).
	data.OpUnsetOutput(longform)
	data.OpSetOutput(longform, outvn)
	// Destroy the now-redundant SUBPIECE.
	data.OpDestroy(op)
	return 1
}

type RuleBoolZext struct{ batchRule }

func NewRuleBoolZext(group string) *RuleBoolZext {
	r := &RuleBoolZext{}
	r.batchRule = newBatchRule(group, "boolzext", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleBoolZext(g) })
	return r
}

func (r *RuleBoolZext) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val > 1 {
		return 0
	}
	ext := definedBy(lhs, CPUI_INT_ZEXT)
	if ext == nil || !isBoolLike(ext.Input(0)) {
		return 0
	}
	negate := op.Code() == CPUI_INT_NOTEQUAL
	if val == 0 {
		negate = !negate
	}
	if negate {
		rewriteOp(data, op, CPUI_BOOL_NEGATE, ext.Input(0))
		return 1
	}
	return rewriteToCopy(data, op, ext.Input(0))
}
