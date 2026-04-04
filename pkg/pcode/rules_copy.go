package pcode

type RulePropagateCopy struct{ batchRule }

func NewRulePropagateCopy(group string) *RulePropagateCopy {
	r := &RulePropagateCopy{}
	r.batchRule = newBatchRule(group, "propagatecopy", nil, r.apply, func(g string) Rule { return NewRulePropagateCopy(g) })
	return r
}

func (r *RulePropagateCopy) apply(op *PcodeOp, data *Funcdata) int {
	changed := 0
	for i := 0; i < op.NumInput(); i++ {
		copyop := definedBy(op.Input(i), CPUI_COPY)
		if copyop == nil || copyop.Input(0) == nil {
			continue
		}
		if copyop.Input(0) == op.Input(i) {
			continue
		}
		data.OpUnsetInput(op, i)
		data.OpSetInput(op, copyop.Input(0), i)
		changed = 1
	}
	return changed
}

type RuleConcatCommute struct{ batchRule }

func NewRuleConcatCommute(group string) *RuleConcatCommute {
	r := &RuleConcatCommute{}
	r.batchRule = newBatchRule(group, "concatcommute", []OpCode{CPUI_PIECE, CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleConcatCommute(g) })
	return r
}

func (r *RuleConcatCommute) apply(op *PcodeOp, data *Funcdata) int {
	changed := 0
	for i := 0; i < op.NumInput(); i++ {
		if i == 1 && op.Code() == CPUI_SUBPIECE && op.Input(i).IsConstant() {
			continue
		}
		copyop := definedBy(op.Input(i), CPUI_COPY)
		if copyop == nil {
			continue
		}
		data.OpUnsetInput(op, i)
		data.OpSetInput(op, copyop.Input(0), i)
		changed = 1
	}
	return changed
}

type RuleSubCancel struct{ batchRule }

func NewRuleSubCancel(group string) *RuleSubCancel {
	r := &RuleSubCancel{}
	r.batchRule = newBatchRule(group, "subcancel", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubCancel(g) })
	return r
}

func (r *RuleSubCancel) apply(op *PcodeOp, data *Funcdata) int {
	piece := definedBy(op.Input(0), CPUI_PIECE)
	if piece == nil {
		return 0
	}
	offset, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	lo := piece.Input(1)
	hi := piece.Input(0)
	if offset == 0 && outputSize(op) == lo.Size() {
		return rewriteToCopy(data, op, lo)
	}
	if offset == uint64(lo.Size()) && outputSize(op) == hi.Size() {
		return rewriteToCopy(data, op, hi)
	}
	return 0
}

type RuleSubNormal struct{ batchRule }

func NewRuleSubNormal(group string) *RuleSubNormal {
	r := &RuleSubNormal{}
	r.batchRule = newBatchRule(group, "subnormal", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubNormal(g) })
	return r
}

func (r *RuleSubNormal) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(1)) && outputSize(op) == op.Input(0).Size() {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleMultiCollapse struct{ batchRule }

func NewRuleMultiCollapse(group string) *RuleMultiCollapse {
	r := &RuleMultiCollapse{}
	r.batchRule = newBatchRule(group, "multicollapse", []OpCode{CPUI_MULTIEQUAL}, r.apply, func(g string) Rule { return NewRuleMultiCollapse(g) })
	return r
}

func (r *RuleMultiCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() == 0 {
		return 0
	}
	base := op.Input(0)
	for i := 1; i < op.NumInput(); i++ {
		if !sameValue(base, op.Input(i)) {
			return 0
		}
	}
	return rewriteToCopy(data, op, base)
}

type RuleHumptyOr struct{ batchRule }

func NewRuleHumptyOr(group string) *RuleHumptyOr {
	r := &RuleHumptyOr{}
	r.batchRule = newBatchRule(group, "humptyor", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleHumptyOr(g) })
	return r
}

func (r *RuleHumptyOr) apply(op *PcodeOp, data *Funcdata) int {
	hi := definedBy(op.Input(0), CPUI_SUBPIECE)
	lo := definedBy(op.Input(1), CPUI_SUBPIECE)
	if hi == nil || lo == nil || !sameValue(hi.Input(0), lo.Input(0)) {
		return 0
	}
	hiOff, hiOK := constantValue(hi.Input(1))
	loOff, loOK := constantValue(lo.Input(1))
	root := hi.Input(0)
	if !hiOK || !loOK || loOff != 0 || hiOff != uint64(outputSize(op.Input(1).Def())) {
		_ = root
	}
	if !hiOK || !loOK || loOff != 0 || hiOff != uint64(op.Input(1).Size()) {
		return 0
	}
	if root.Size() != outputSize(op) {
		return 0
	}
	return rewriteToCopy(data, op, root)
}

type batchARuleFactory func(string) Rule

var batchARuleFactories = []batchARuleFactory{
	func(group string) Rule { return NewRulePiece2Zext(group) },
	func(group string) Rule { return NewRulePiece2Sext(group) },
	func(group string) Rule { return NewRuleBxor2NotEqual(group) },
	func(group string) Rule { return NewRuleOrMask(group) },
	func(group string) Rule { return NewRuleAndMask(group) },
	func(group string) Rule { return NewRuleOrCollapse(group) },
	func(group string) Rule { return NewRuleAndOrLump(group) },
	func(group string) Rule { return NewRuleNegateIdentity(group) },
	func(group string) Rule { return NewRuleShiftBitops(group) },
	func(group string) Rule { return NewRuleRightShiftAnd(group) },
	func(group string) Rule { return NewRuleTrivialArith(group) },
	func(group string) Rule { return NewRuleEquality(group) },
	func(group string) Rule { return NewRuleTrivialBool(group) },
	func(group string) Rule { return NewRuleZextEliminate(group) },
	func(group string) Rule { return NewRuleSlessToLess(group) },
	func(group string) Rule { return NewRuleZextSless(group) },
	func(group string) Rule { return NewRuleBooleanDedup(group) },
	func(group string) Rule { return NewRuleBooleanNegate(group) },
	func(group string) Rule { return NewRuleBoolZext(group) },
	func(group string) Rule { return NewRuleLogic2Bool(group) },
	func(group string) Rule { return NewRuleMultiCollapse(group) },
	func(group string) Rule { return NewRuleAddUnsigned(group) },
	func(group string) Rule { return NewRule2Comp2Sub(group) },
	func(group string) Rule { return NewRuleSubRight(group) },
	func(group string) Rule { return NewRulePropagateCopy(group) },
	func(group string) Rule { return NewRuleAndCommute(group) },
	func(group string) Rule { return NewRuleAndPiece(group) },
	func(group string) Rule { return NewRuleAndZext(group) },
	func(group string) Rule { return NewRuleShift2Mult(group) },
	func(group string) Rule { return NewRuleConcatCommute(group) },
	func(group string) Rule { return NewRule2Comp2Mult(group) },
	func(group string) Rule { return NewRuleSub2Add(group) },
	func(group string) Rule { return NewRuleXorCollapse(group) },
	func(group string) Rule { return NewRuleAddMultCollapse(group) },
	func(group string) Rule { return NewRuleSubExtComm(group) },
	func(group string) Rule { return NewRuleConcatZext(group) },
	func(group string) Rule { return NewRuleZextCommute(group) },
	func(group string) Rule { return NewRuleZextShiftZext(group) },
	func(group string) Rule { return NewRuleSubZext(group) },
	func(group string) Rule { return NewRuleSubCancel(group) },
	func(group string) Rule { return NewRuleHumptyOr(group) },
	func(group string) Rule { return NewRuleBoolNegate(group) },
	func(group string) Rule { return NewRuleCondNegate(group) },
	func(group string) Rule { return NewRuleLess2Zero(group) },
	func(group string) Rule { return NewRuleLessEqual2Zero(group) },
	func(group string) Rule { return NewRuleSLess2Zero(group) },
	func(group string) Rule { return NewRuleEqual2Zero(group) },
	func(group string) Rule { return NewRuleEqual2Constant(group) },
	func(group string) Rule { return NewRuleMultNegOne(group) },
	func(group string) Rule { return NewRuleNegateNegate(group) },
	func(group string) Rule { return NewRuleSubNormal(group) },
	func(group string) Rule { return NewRuleSborrow(group) },
}

func BatchARules(group string) []Rule {
	rules := make([]Rule, 0, len(batchARuleFactories))
	for _, factory := range batchARuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchARules(pool *ActionPool, group string) int {
	count := 0
	for _, rule := range BatchARules(group) {
		pool.AddRule(rule)
		count++
	}
	return count
}

func NewBatchAActionPool(name string, group string) *ActionPool {
	pool := NewActionPool(0, name)
	AddBatchARules(pool, group)
	return pool
}
