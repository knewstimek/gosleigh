package pcode

type RuleBxor2NotEqual struct{ batchRule }

func NewRuleBxor2NotEqual(group string) *RuleBxor2NotEqual {
	r := &RuleBxor2NotEqual{}
	r.batchRule = newBatchRule(group, "bxor2notequal", []OpCode{CPUI_BOOL_XOR}, r.apply, func(g string) Rule { return NewRuleBxor2NotEqual(g) })
	return r
}

func (r *RuleBxor2NotEqual) apply(op *PcodeOp, data *Funcdata) int {
	rewriteOp(data, op, CPUI_INT_NOTEQUAL, op.Input(0), op.Input(1))
	return 1
}

type RuleOrMask struct{ batchRule }

func NewRuleOrMask(group string) *RuleOrMask {
	r := &RuleOrMask{}
	r.batchRule = newBatchRule(group, "ormask", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleOrMask(g) })
	return r
}

func (r *RuleOrMask) apply(op *PcodeOp, data *Funcdata) int {
	if isAllOnesConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isAllOnesConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	return 0
}

type RuleAndMask struct{ batchRule }

func NewRuleAndMask(group string) *RuleAndMask {
	r := &RuleAndMask{}
	r.batchRule = newBatchRule(group, "andmask", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndMask(g) })
	return r
}

func (r *RuleAndMask) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(0)) || isZeroConst(op.Input(1)) {
		return rewriteToConst(data, op, 0)
	}
	if isAllOnesConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isAllOnesConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleOrCollapse struct{ batchRule }

func NewRuleOrCollapse(group string) *RuleOrCollapse {
	r := &RuleOrCollapse{}
	r.batchRule = newBatchRule(group, "orcollapse", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleOrCollapse(g) })
	return r
}

func (r *RuleOrCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if sameValue(op.Input(0), op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isZeroConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleAndOrLump struct{ batchRule }

func NewRuleAndOrLump(group string) *RuleAndOrLump {
	r := &RuleAndOrLump{}
	r.batchRule = newBatchRule(group, "andorlump", []OpCode{CPUI_INT_OR, CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndOrLump(g) })
	return r
}

func (r *RuleAndOrLump) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		other := op.Input(1 - slot)
		if def := op.Input(slot).Def(); def != nil {
			if op.Code() == CPUI_INT_OR && def.Code() == CPUI_INT_AND {
				if sameValue(def.Input(0), other) || sameValue(def.Input(1), other) {
					return rewriteToCopy(data, op, other)
				}
			}
			if op.Code() == CPUI_INT_AND && def.Code() == CPUI_INT_OR {
				if sameValue(def.Input(0), other) || sameValue(def.Input(1), other) {
					return rewriteToCopy(data, op, other)
				}
			}
		}
	}
	return 0
}

type RuleNegateIdentity struct{ batchRule }

func NewRuleNegateIdentity(group string) *RuleNegateIdentity {
	r := &RuleNegateIdentity{}
	r.batchRule = newBatchRule(group, "negateidentity", []OpCode{CPUI_INT_AND, CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleNegateIdentity(g) })
	return r
}

func (r *RuleNegateIdentity) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		neg := definedBy(op.Input(slot), CPUI_INT_NEGATE)
		if neg == nil || !sameValue(neg.Input(0), op.Input(1-slot)) {
			continue
		}
		if op.Code() == CPUI_INT_AND {
			return rewriteToConst(data, op, 0)
		}
		return rewriteToConst(data, op, maskForSize(outputOrInputSize(op)))
	}
	return 0
}

type RuleShiftBitops struct{ batchRule }

func NewRuleShiftBitops(group string) *RuleShiftBitops {
	r := &RuleShiftBitops{}
	r.batchRule = newBatchRule(group, "shiftbitops", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleShiftBitops(g) })
	return r
}

func (r *RuleShiftBitops) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleRightShiftAnd struct{ batchRule }

func NewRuleRightShiftAnd(group string) *RuleRightShiftAnd {
	r := &RuleRightShiftAnd{}
	r.batchRule = newBatchRule(group, "rightshiftand", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleRightShiftAnd(g) })
	return r
}

func (r *RuleRightShiftAnd) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		shiftop := definedBy(op.Input(slot), CPUI_INT_RIGHT)
		if shiftop == nil {
			continue
		}
		shift, ok := constantValue(shiftop.Input(1))
		maskVal, maskOK := constantValue(op.Input(1 - slot))
		if !ok || !maskOK || shift >= uint64(outputOrInputSize(op)*8) {
			continue
		}
		expected := lowMask(uint64(outputOrInputSize(op)*8) - shift)
		if maskVal == truncateToSize(expected, outputOrInputSize(op)) {
			return rewriteToCopy(data, op, op.Input(slot))
		}
	}
	return 0
}

type RuleAndCommute struct{ batchRule }

func NewRuleAndCommute(group string) *RuleAndCommute {
	r := &RuleAndCommute{}
	r.batchRule = newBatchRule(group, "andcommute", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndCommute(g) })
	return r
}

func (r *RuleAndCommute) apply(op *PcodeOp, data *Funcdata) int {
	if op.Input(0) != nil && op.Input(0).IsConstant() && (op.Input(1) == nil || !op.Input(1).IsConstant()) {
		return swapInputs(data, op)
	}
	return 0
}

type RuleAndPiece struct{ batchRule }

func NewRuleAndPiece(group string) *RuleAndPiece {
	r := &RuleAndPiece{}
	r.batchRule = newBatchRule(group, "andpiece", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndPiece(g) })
	return r
}

func (r *RuleAndPiece) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		piece := definedBy(op.Input(slot), CPUI_PIECE)
		if piece == nil {
			continue
		}
		maskVal, ok := constantValue(op.Input(1 - slot))
		if !ok {
			continue
		}
		lo := piece.Input(1)
		if maskVal == maskForSize(lo.Size()) {
			rewriteOp(data, op, CPUI_INT_ZEXT, lo)
			return 1
		}
	}
	return 0
}

type RuleAndZext struct{ batchRule }

func NewRuleAndZext(group string) *RuleAndZext {
	r := &RuleAndZext{}
	r.batchRule = newBatchRule(group, "andzext", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndZext(g) })
	return r
}

func (r *RuleAndZext) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		ext := definedBy(op.Input(slot), CPUI_INT_ZEXT)
		if ext == nil {
			continue
		}
		maskVal, ok := constantValue(op.Input(1 - slot))
		if !ok {
			continue
		}
		if maskVal == maskForSize(ext.Input(0).Size()) {
			return rewriteToCopy(data, op, op.Input(slot))
		}
	}
	return 0
}

type RuleXorCollapse struct{ batchRule }

func NewRuleXorCollapse(group string) *RuleXorCollapse {
	r := &RuleXorCollapse{}
	r.batchRule = newBatchRule(group, "xorcollapse", []OpCode{CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleXorCollapse(g) })
	return r
}

func (r *RuleXorCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isAllOnesConst(op.Input(0)) {
		rewriteOp(data, op, CPUI_INT_NEGATE, op.Input(1))
		return 1
	}
	if isAllOnesConst(op.Input(1)) {
		rewriteOp(data, op, CPUI_INT_NEGATE, op.Input(0))
		return 1
	}
	return 0
}
