package pcode

type batchRule struct {
	RuleBase
	opcodes []OpCode
	applyFn func(*PcodeOp, *Funcdata) int
	cloneFn func(string) Rule
}

func newBatchRule(group string, name string, opcodes []OpCode, applyFn func(*PcodeOp, *Funcdata) int, cloneFn func(string) Rule) batchRule {
	return batchRule{
		RuleBase: NewRuleBase(group, 0, name),
		opcodes:  append([]OpCode(nil), opcodes...),
		applyFn:  applyFn,
		cloneFn:  cloneFn,
	}
}

func (r *batchRule) GetOpList() []OpCode {
	if len(r.opcodes) == 0 {
		return r.RuleBase.GetOpList()
	}
	return append([]OpCode(nil), r.opcodes...)
}

func (r *batchRule) ApplyOp(op *PcodeOp, data *Funcdata) int {
	if r.applyFn == nil {
		return 0
	}
	return r.applyFn(op, data)
}

func (r *batchRule) Clone(groups ActionGroupList) Rule {
	if !r.CloneAllowed(groups) || r.cloneFn == nil {
		return nil
	}
	return r.cloneFn(r.GetGroup())
}

func maskForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	if size >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (uint(size) * 8)) - 1
}

func signBitForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return uint64(1) << 63
	}
	return uint64(1) << (bits - 1)
}

func truncateToSize(val uint64, size int32) uint64 {
	return val & maskForSize(size)
}

func lowMask(bits uint64) uint64 {
	if bits == 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func outputSize(op *PcodeOp) int32 {
	if op == nil || op.Output() == nil {
		return 0
	}
	return op.Output().Size()
}

func outputOrInputSize(op *PcodeOp) int32 {
	if size := outputSize(op); size != 0 {
		return size
	}
	if op != nil && op.NumInput() > 0 && op.Input(0) != nil {
		return op.Input(0).Size()
	}
	return 0
}

func constantValue(vn *Varnode) (uint64, bool) {
	if vn == nil || !vn.IsConstant() {
		return 0, false
	}
	return truncateToSize(vn.Offset(), vn.Size()), true
}

func isConstantValue(vn *Varnode, want uint64) bool {
	val, ok := constantValue(vn)
	return ok && val == truncateToSize(want, vn.Size())
}

func isZeroConst(vn *Varnode) bool {
	return isConstantValue(vn, 0)
}

func isOneConst(vn *Varnode) bool {
	return isConstantValue(vn, 1)
}

func isAllOnesConst(vn *Varnode) bool {
	val, ok := constantValue(vn)
	return ok && val == maskForSize(vn.Size())
}

func boolConst(vn *Varnode) (bool, bool) {
	val, ok := constantValue(vn)
	if !ok || val > 1 {
		return false, false
	}
	return val != 0, true
}

func sameValue(a *Varnode, b *Varnode) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil || a.Size() != b.Size() {
		return false
	}
	aval, aok := constantValue(a)
	bval, bok := constantValue(b)
	return aok && bok && aval == bval
}

func definedBy(vn *Varnode, opcode OpCode) *PcodeOp {
	if vn == nil || !vn.IsWritten() {
		return nil
	}
	def := vn.Def()
	if def == nil || def.Code() != opcode {
		return nil
	}
	return def
}

func isBoolLike(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	if _, ok := boolConst(vn); ok {
		return true
	}
	def := vn.Def()
	return def != nil && def.IsBoolOutput()
}

func replaceInputs(data *Funcdata, op *PcodeOp, inputs ...*Varnode) {
	for i := op.NumInput() - 1; i >= 0; i-- {
		data.OpUnsetInput(op, i)
	}
	op.SetNumInputs(len(inputs))
	for i, vn := range inputs {
		data.OpSetInput(op, vn, i)
	}
}

func rewriteOp(data *Funcdata, op *PcodeOp, opcode OpCode, inputs ...*Varnode) {
	data.OpSetOpcode(op, opcode)
	replaceInputs(data, op, inputs...)
}

func rewriteToCopy(data *Funcdata, op *PcodeOp, vn *Varnode) int {
	rewriteOp(data, op, CPUI_COPY, vn)
	return 1
}

func rewriteToConst(data *Funcdata, op *PcodeOp, val uint64) int {
	size := outputOrInputSize(op)
	if size == 0 {
		size = 1
	}
	return rewriteToCopy(data, op, data.NewConstant(size, truncateToSize(val, size)))
}

func swapInputs(data *Funcdata, op *PcodeOp) int {
	if op.NumInput() < 2 {
		return 0
	}
	replaceInputs(data, op, op.Input(1), op.Input(0))
	return 1
}

func negateConstForSize(val uint64, size int32) uint64 {
	return truncateToSize(^val+1, size)
}

type RuleTrivialArith struct{ batchRule }

func NewRuleTrivialArith(group string) *RuleTrivialArith {
	r := &RuleTrivialArith{}
	r.batchRule = newBatchRule(group, "trivialarith", []OpCode{
		CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_LESS,
		CPUI_INT_EQUAL, CPUI_INT_SLESSEQUAL, CPUI_INT_LESSEQUAL,
		CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL,
	}, r.apply, func(g string) Rule { return NewRuleTrivialArith(g) })
	return r
}

func (r *RuleTrivialArith) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 || !sameValue(op.Input(0), op.Input(1)) {
		return 0
	}
	switch op.Code() {
	case CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_LESS, CPUI_BOOL_XOR, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS:
		return rewriteToConst(data, op, 0)
	case CPUI_INT_EQUAL, CPUI_INT_SLESSEQUAL, CPUI_INT_LESSEQUAL, CPUI_FLOAT_EQUAL, CPUI_FLOAT_LESSEQUAL:
		return rewriteToConst(data, op, 1)
	case CPUI_INT_XOR:
		return rewriteToConst(data, op, 0)
	case CPUI_INT_AND, CPUI_INT_OR, CPUI_BOOL_AND, CPUI_BOOL_OR:
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleAddUnsigned struct{ batchRule }

func NewRuleAddUnsigned(group string) *RuleAddUnsigned {
	r := &RuleAddUnsigned{}
	r.batchRule = newBatchRule(group, "addunsigned", []OpCode{CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRuleAddUnsigned(g) })
	return r
}

func (r *RuleAddUnsigned) apply(op *PcodeOp, data *Funcdata) int {
	size := outputOrInputSize(op)
	for slot := 0; slot < 2; slot++ {
		val, ok := constantValue(op.Input(slot))
		if !ok || val == 0 || isAllOnesConst(op.Input(slot)) {
			continue
		}
		if val&signBitForSize(size) == 0 {
			continue
		}
		other := op.Input(1 - slot)
		rewriteOp(data, op, CPUI_INT_SUB, other, data.NewConstant(size, negateConstForSize(val, size)))
		return 1
	}
	return 0
}

type Rule2Comp2Sub struct{ batchRule }

func NewRule2Comp2Sub(group string) *Rule2Comp2Sub {
	r := &Rule2Comp2Sub{}
	r.batchRule = newBatchRule(group, "2comp2sub", []OpCode{CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRule2Comp2Sub(g) })
	return r
}

func (r *Rule2Comp2Sub) apply(op *PcodeOp, data *Funcdata) int {
	if neg := definedBy(op.Input(0), CPUI_INT_2COMP); neg != nil {
		rewriteOp(data, op, CPUI_INT_SUB, op.Input(1), neg.Input(0))
		return 1
	}
	if neg := definedBy(op.Input(1), CPUI_INT_2COMP); neg != nil {
		rewriteOp(data, op, CPUI_INT_SUB, op.Input(0), neg.Input(0))
		return 1
	}
	return 0
}

type RuleSub2Add struct{ batchRule }

func NewRuleSub2Add(group string) *RuleSub2Add {
	r := &RuleSub2Add{}
	r.batchRule = newBatchRule(group, "sub2add", []OpCode{CPUI_INT_SUB}, r.apply, func(g string) Rule { return NewRuleSub2Add(g) })
	return r
}

func (r *RuleSub2Add) apply(op *PcodeOp, data *Funcdata) int {
	// C++ parity: RuleSub2Add::applyOp (ruleaction.cc)
	// V - W  =>  V + (W * -1)
	// Must NOT fold to V + (-const) directly: a raw negative constant would
	// re-trigger RuleAddUnsigned on the resulting INT_ADD, causing an infinite
	// rewrite cycle. Instead, introduce a CPUI_INT_MULT op so the result is a
	// non-constant varnode from RuleAddUnsigned's perspective.
	vn := op.Input(1)
	if vn == nil {
		return 0
	}
	size := vn.Size()
	if size == 0 {
		size = outputOrInputSize(op)
	}
	allOnes := truncateToSize(^uint64(0), size)
	mulOp := data.NewOpBefore(op, CPUI_INT_MULT, vn, data.NewConstant(size, allOnes))
	newvn := data.NewUniqueOut(size, mulOp)
	// Insert mulOp into the same block as op, immediately before it.
	// C++ uses opInsertBefore which places the new op in the instruction stream.
	if blk := op.Parent(); blk != nil {
		mulOp.SetParent(blk)
		blk.InsertOpBefore(mulOp, op)
	}
	data.OpSetInput(op, newvn, 1)
	data.OpSetOpcode(op, CPUI_INT_ADD)
	return 1
}

type Rule2Comp2Mult struct{ batchRule }

func NewRule2Comp2Mult(group string) *Rule2Comp2Mult {
	r := &Rule2Comp2Mult{}
	r.batchRule = newBatchRule(group, "2comp2mult", []OpCode{CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRule2Comp2Mult(g) })
	return r
}

func (r *Rule2Comp2Mult) apply(op *PcodeOp, data *Funcdata) int {
	size := outputOrInputSize(op)
	if neg := definedBy(op.Input(0), CPUI_INT_2COMP); neg != nil {
		if val, ok := constantValue(op.Input(1)); ok {
			rewriteOp(data, op, CPUI_INT_MULT, neg.Input(0), data.NewConstant(size, negateConstForSize(val, size)))
			return 1
		}
	}
	if neg := definedBy(op.Input(1), CPUI_INT_2COMP); neg != nil {
		if val, ok := constantValue(op.Input(0)); ok {
			rewriteOp(data, op, CPUI_INT_MULT, neg.Input(0), data.NewConstant(size, negateConstForSize(val, size)))
			return 1
		}
	}
	return 0
}

type RuleMultNegOne struct{ batchRule }

func NewRuleMultNegOne(group string) *RuleMultNegOne {
	r := &RuleMultNegOne{}
	r.batchRule = newBatchRule(group, "multnegone", []OpCode{CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRuleMultNegOne(g) })
	return r
}

func (r *RuleMultNegOne) apply(op *PcodeOp, data *Funcdata) int {
	if isAllOnesConst(op.Input(0)) {
		rewriteOp(data, op, CPUI_INT_2COMP, op.Input(1))
		return 1
	}
	if isAllOnesConst(op.Input(1)) {
		rewriteOp(data, op, CPUI_INT_2COMP, op.Input(0))
		return 1
	}
	return 0
}

type RuleShift2Mult struct{ batchRule }

func NewRuleShift2Mult(group string) *RuleShift2Mult {
	r := &RuleShift2Mult{}
	r.batchRule = newBatchRule(group, "shift2mult", []OpCode{CPUI_INT_LEFT}, r.apply, func(g string) Rule { return NewRuleShift2Mult(g) })
	return r
}

func (r *RuleShift2Mult) apply(op *PcodeOp, data *Funcdata) int {
	shift, ok := constantValue(op.Input(1))
	if !ok || shift == 0 || shift >= 63 {
		return 0
	}
	size := outputOrInputSize(op)
	if shift >= uint64(size*8) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_MULT, op.Input(0), data.NewConstant(size, uint64(1)<<shift))
	return 1
}

type RuleAddMultCollapse struct{ batchRule }

func NewRuleAddMultCollapse(group string) *RuleAddMultCollapse {
	r := &RuleAddMultCollapse{}
	r.batchRule = newBatchRule(group, "addmultcollapse", []OpCode{CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRuleAddMultCollapse(g) })
	return r
}

func (r *RuleAddMultCollapse) apply(op *PcodeOp, data *Funcdata) int {
	size := outputOrInputSize(op)
	if sameValue(op.Input(0), op.Input(1)) {
		rewriteOp(data, op, CPUI_INT_MULT, op.Input(0), data.NewConstant(size, 2))
		return 1
	}
	for slot := 0; slot < 2; slot++ {
		mul := definedBy(op.Input(slot), CPUI_INT_MULT)
		if mul == nil {
			continue
		}
		other := op.Input(1 - slot)
		for cslot := 0; cslot < 2; cslot++ {
			cval, ok := constantValue(mul.Input(cslot))
			if !ok {
				continue
			}
			base := mul.Input(1 - cslot)
			if !sameValue(base, other) {
				continue
			}
			rewriteOp(data, op, CPUI_INT_MULT, base, data.NewConstant(size, truncateToSize(cval+1, size)))
			return 1
		}
	}
	return 0
}

type RuleSubRight struct{ batchRule }

func NewRuleSubRight(group string) *RuleSubRight {
	r := &RuleSubRight{}
	r.batchRule = newBatchRule(group, "subright", []OpCode{CPUI_INT_SUB}, r.apply, func(g string) Rule { return NewRuleSubRight(g) })
	return r
}

func (r *RuleSubRight) apply(op *PcodeOp, data *Funcdata) int {
	if sameValue(op.Input(0), op.Input(1)) {
		return rewriteToConst(data, op, 0)
	}
	if neg := definedBy(op.Input(1), CPUI_INT_2COMP); neg != nil {
		rewriteOp(data, op, CPUI_INT_ADD, op.Input(0), neg.Input(0))
		return 1
	}
	return 0
}

type RuleNegateNegate struct{ batchRule }

func NewRuleNegateNegate(group string) *RuleNegateNegate {
	r := &RuleNegateNegate{}
	r.batchRule = newBatchRule(group, "negatenegate", []OpCode{CPUI_INT_NEGATE}, r.apply, func(g string) Rule { return NewRuleNegateNegate(g) })
	return r
}

func (r *RuleNegateNegate) apply(op *PcodeOp, data *Funcdata) int {
	if neg := definedBy(op.Input(0), CPUI_INT_NEGATE); neg != nil {
		return rewriteToCopy(data, op, neg.Input(0))
	}
	if val, ok := constantValue(op.Input(0)); ok {
		return rewriteToConst(data, op, ^val)
	}
	return 0
}
