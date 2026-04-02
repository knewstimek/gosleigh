package pcode

func normalizeCompareConst(op *PcodeOp) (*Varnode, *Varnode, uint64, bool) {
	if val, ok := constantValue(op.Input(1)); ok {
		return op.Input(0), op.Input(1), val, true
	}
	if val, ok := constantValue(op.Input(0)); ok {
		return op.Input(1), op.Input(0), val, true
	}
	return nil, nil, 0, false
}

func boolFlipOpcode(opc OpCode) (OpCode, bool, bool) {
	switch opc {
	case CPUI_INT_EQUAL:
		return CPUI_INT_NOTEQUAL, false, true
	case CPUI_INT_NOTEQUAL:
		return CPUI_INT_EQUAL, false, true
	case CPUI_INT_LESS:
		return CPUI_INT_LESSEQUAL, true, true
	case CPUI_INT_LESSEQUAL:
		return CPUI_INT_LESS, true, true
	case CPUI_INT_SLESS:
		return CPUI_INT_SLESSEQUAL, true, true
	case CPUI_INT_SLESSEQUAL:
		return CPUI_INT_SLESS, true, true
	default:
		return CPUI_MAX, false, false
	}
}

func isNegatedBoolPair(a *Varnode, b *Varnode) bool {
	if neg := definedBy(a, CPUI_BOOL_NEGATE); neg != nil && sameValue(neg.Input(0), b) {
		return true
	}
	if neg := definedBy(b, CPUI_BOOL_NEGATE); neg != nil && sameValue(neg.Input(0), a) {
		return true
	}
	return false
}

type RuleTrivialBool struct{ batchRule }

func NewRuleTrivialBool(group string) *RuleTrivialBool {
	r := &RuleTrivialBool{}
	r.batchRule = newBatchRule(group, "trivialbool", []OpCode{CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_BOOL_XOR}, r.apply, func(g string) Rule { return NewRuleTrivialBool(g) })
	return r
}

func (r *RuleTrivialBool) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val > 1 {
		return 0
	}
	switch op.Code() {
	case CPUI_BOOL_AND:
		if val == 0 {
			return rewriteToConst(data, op, 0)
		}
		return rewriteToCopy(data, op, lhs)
	case CPUI_BOOL_OR:
		if val == 0 {
			return rewriteToCopy(data, op, lhs)
		}
		return rewriteToConst(data, op, 1)
	case CPUI_BOOL_XOR:
		if val == 0 {
			return rewriteToCopy(data, op, lhs)
		}
		rewriteOp(data, op, CPUI_BOOL_NEGATE, lhs)
		return 1
	default:
		return 0
	}
}

type RuleEquality struct{ batchRule }

func NewRuleEquality(group string) *RuleEquality {
	r := &RuleEquality{}
	r.batchRule = newBatchRule(group, "equality", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleEquality(g) })
	return r
}

func (r *RuleEquality) apply(op *PcodeOp, data *Funcdata) int {
	if sameValue(op.Input(0), op.Input(1)) {
		if op.Code() == CPUI_INT_EQUAL {
			return rewriteToConst(data, op, 1)
		}
		return rewriteToConst(data, op, 0)
	}
	lhs, rhs, lval, lok := op.Input(0), op.Input(1), uint64(0), false
	lval, lok = constantValue(lhs)
	rval, rok := constantValue(rhs)
	if lok && rok {
		want := uint64(0)
		if (op.Code() == CPUI_INT_EQUAL && lval == rval) || (op.Code() == CPUI_INT_NOTEQUAL && lval != rval) {
			want = 1
		}
		return rewriteToConst(data, op, want)
	}
	return 0
}

type RuleBoolNegate struct{ batchRule }

func NewRuleBoolNegate(group string) *RuleBoolNegate {
	r := &RuleBoolNegate{}
	r.batchRule = newBatchRule(group, "boolnegate", []OpCode{CPUI_BOOL_NEGATE}, r.apply, func(g string) Rule { return NewRuleBoolNegate(g) })
	return r
}

func (r *RuleBoolNegate) apply(op *PcodeOp, data *Funcdata) int {
	in := op.Input(0)
	if neg := definedBy(in, CPUI_BOOL_NEGATE); neg != nil {
		return rewriteToCopy(data, op, neg.Input(0))
	}
	def := in.Def()
	if def == nil {
		return 0
	}
	flip, swap, ok := boolFlipOpcode(def.Code())
	if !ok {
		return 0
	}
	if swap {
		rewriteOp(data, op, flip, def.Input(1), def.Input(0))
	} else {
		rewriteOp(data, op, flip, def.Input(0), def.Input(1))
	}
	return 1
}

type RuleBooleanNegate struct{ batchRule }

func NewRuleBooleanNegate(group string) *RuleBooleanNegate {
	r := &RuleBooleanNegate{}
	r.batchRule = newBatchRule(group, "booleannegate", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleBooleanNegate(g) })
	return r
}

func (r *RuleBooleanNegate) apply(op *PcodeOp, data *Funcdata) int {
	subbool, _, val, ok := normalizeCompareConst(op)
	if !ok || val > 1 || !isBoolLike(subbool) {
		return 0
	}
	negate := op.Code() == CPUI_INT_NOTEQUAL
	if val == 0 {
		negate = !negate
	}
	if negate {
		rewriteOp(data, op, CPUI_BOOL_NEGATE, subbool)
		return 1
	}
	return rewriteToCopy(data, op, subbool)
}

type RuleBooleanDedup struct{ batchRule }

func NewRuleBooleanDedup(group string) *RuleBooleanDedup {
	r := &RuleBooleanDedup{}
	r.batchRule = newBatchRule(group, "booleandedup", []OpCode{CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_BOOL_XOR}, r.apply, func(g string) Rule { return NewRuleBooleanDedup(g) })
	return r
}

func (r *RuleBooleanDedup) apply(op *PcodeOp, data *Funcdata) int {
	if !isNegatedBoolPair(op.Input(0), op.Input(1)) {
		return 0
	}
	if op.Code() == CPUI_BOOL_AND {
		return rewriteToConst(data, op, 0)
	}
	return rewriteToConst(data, op, 1)
}

type RuleLogic2Bool struct{ batchRule }

func NewRuleLogic2Bool(group string) *RuleLogic2Bool {
	r := &RuleLogic2Bool{}
	r.batchRule = newBatchRule(group, "logic2bool", []OpCode{CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleLogic2Bool(g) })
	return r
}

func (r *RuleLogic2Bool) apply(op *PcodeOp, data *Funcdata) int {
	if outputOrInputSize(op) != 1 || !isBoolLike(op.Input(0)) || !isBoolLike(op.Input(1)) {
		return 0
	}
	switch op.Code() {
	case CPUI_INT_AND:
		rewriteOp(data, op, CPUI_BOOL_AND, op.Input(0), op.Input(1))
	case CPUI_INT_OR:
		rewriteOp(data, op, CPUI_BOOL_OR, op.Input(0), op.Input(1))
	case CPUI_INT_XOR:
		rewriteOp(data, op, CPUI_BOOL_XOR, op.Input(0), op.Input(1))
	default:
		return 0
	}
	return 1
}

type RuleCondNegate struct{ batchRule }

func NewRuleCondNegate(group string) *RuleCondNegate {
	r := &RuleCondNegate{}
	r.batchRule = newBatchRule(group, "condnegate", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleCondNegate(g) })
	return r
}

func (r *RuleCondNegate) apply(op *PcodeOp, data *Funcdata) int {
	left := definedBy(op.Input(0), CPUI_BOOL_NEGATE)
	right := definedBy(op.Input(1), CPUI_BOOL_NEGATE)
	if left == nil || right == nil {
		return 0
	}
	rewriteOp(data, op, op.Code(), left.Input(0), right.Input(0))
	return 1
}

type RuleLess2Zero struct{ batchRule }

func NewRuleLess2Zero(group string) *RuleLess2Zero {
	r := &RuleLess2Zero{}
	r.batchRule = newBatchRule(group, "less2zero", []OpCode{CPUI_INT_LESS}, r.apply, func(g string) Rule { return NewRuleLess2Zero(g) })
	return r
}

func (r *RuleLess2Zero) apply(op *PcodeOp, data *Funcdata) int {
	_, _, val, ok := normalizeCompareConst(op)
	if ok && val == 0 {
		return rewriteToConst(data, op, 0)
	}
	return 0
}

type RuleLessEqual2Zero struct{ batchRule }

func NewRuleLessEqual2Zero(group string) *RuleLessEqual2Zero {
	r := &RuleLessEqual2Zero{}
	r.batchRule = newBatchRule(group, "lessequal2zero", []OpCode{CPUI_INT_LESSEQUAL}, r.apply, func(g string) Rule { return NewRuleLessEqual2Zero(g) })
	return r
}

func (r *RuleLessEqual2Zero) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val != 0 {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_EQUAL, lhs, data.NewConstant(lhs.Size(), 0))
	return 1
}

type RuleSLess2Zero struct{ batchRule }

func NewRuleSLess2Zero(group string) *RuleSLess2Zero {
	r := &RuleSLess2Zero{}
	r.batchRule = newBatchRule(group, "sless2zero", []OpCode{CPUI_INT_SLESS}, r.apply, func(g string) Rule { return NewRuleSLess2Zero(g) })
	return r
}

func (r *RuleSLess2Zero) apply(op *PcodeOp, data *Funcdata) int {
	lval, lok := constantValue(op.Input(0))
	rval, rok := constantValue(op.Input(1))
	if !lok || !rok {
		return 0
	}
	bits := uint(op.Input(0).Size() * 8)
	if bits == 0 {
		return 0
	}
	var lhs, rhs int64
	if bits >= 64 {
		lhs = int64(lval)
		rhs = int64(rval)
	} else {
		shift := 64 - bits
		lhs = int64(lval<<shift) >> shift
		rhs = int64(rval<<shift) >> shift
	}
	if lhs < rhs {
		return rewriteToConst(data, op, 1)
	}
	return rewriteToConst(data, op, 0)
}

type RuleEqual2Zero struct{ batchRule }

func NewRuleEqual2Zero(group string) *RuleEqual2Zero {
	r := &RuleEqual2Zero{}
	r.batchRule = newBatchRule(group, "equal2zero", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleEqual2Zero(g) })
	return r
}

func (r *RuleEqual2Zero) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val != 0 {
		return 0
	}
	xor := definedBy(lhs, CPUI_INT_XOR)
	if xor == nil {
		return 0
	}
	for slot := 0; slot < 2; slot++ {
		cval, cok := constantValue(xor.Input(slot))
		if !cok {
			continue
		}
		other := xor.Input(1 - slot)
		rewriteOp(data, op, op.Code(), other, data.NewConstant(other.Size(), cval))
		return 1
	}
	return 0
}

type RuleEqual2Constant struct{ batchRule }

func NewRuleEqual2Constant(group string) *RuleEqual2Constant {
	r := &RuleEqual2Constant{}
	r.batchRule = newBatchRule(group, "equal2constant", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleEqual2Constant(g) })
	return r
}

func (r *RuleEqual2Constant) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok {
		return 0
	}
	add := definedBy(lhs, CPUI_INT_ADD)
	if add == nil {
		return 0
	}
	for slot := 0; slot < 2; slot++ {
		cval, cok := constantValue(add.Input(slot))
		if !cok || cval != val {
			continue
		}
		other := add.Input(1 - slot)
		rewriteOp(data, op, op.Code(), other, data.NewConstant(other.Size(), 0))
		return 1
	}
	return 0
}
