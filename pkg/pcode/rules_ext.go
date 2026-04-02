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
