package pcode

import "github.com/knewstimek/gosleigh/pkg/address"

type RuleFloatCast struct{ batchRule }

func NewRuleFloatCast(group string) *RuleFloatCast {
	r := &RuleFloatCast{}
	r.batchRule = newBatchRule(group, "floatcast", []OpCode{CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC}, r.apply, func(g string) Rule {
		return NewRuleFloatCast(g)
	})
	return r
}

func (r *RuleFloatCast) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 1 {
		return 0
	}
	castOp := op.Input(0).Def()
	if castOp == nil {
		return 0
	}
	opc2 := castOp.Code()
	if opc2 != CPUI_FLOAT_FLOAT2FLOAT && opc2 != CPUI_FLOAT_INT2FLOAT {
		return 0
	}
	vn2 := castOp.Input(0)
	if vn2.IsFree() {
		return 0
	}
	insize1 := op.Input(0).Size()
	insize2 := vn2.Size()
	outsize := outputSize(op)
	switch {
	case opc2 == CPUI_FLOAT_FLOAT2FLOAT && op.Code() == CPUI_FLOAT_FLOAT2FLOAT:
		if insize1 > outsize {
			data.OpSetInput(op, vn2, 0)
			if outsize == insize2 {
				data.OpSetOpcode(op, CPUI_COPY)
			}
			return 1
		}
		if insize2 < insize1 {
			data.OpSetInput(op, vn2, 0)
			return 1
		}
	case opc2 == CPUI_FLOAT_INT2FLOAT && op.Code() == CPUI_FLOAT_FLOAT2FLOAT:
		data.OpSetInput(op, vn2, 0)
		data.OpSetOpcode(op, CPUI_FLOAT_INT2FLOAT)
		return 1
	case opc2 == CPUI_FLOAT_FLOAT2FLOAT && op.Code() == CPUI_FLOAT_TRUNC:
		data.OpSetInput(op, vn2, 0)
		return 1
	}
	return 0
}

type RuleIgnoreNan struct{ batchRule }

func NewRuleIgnoreNan(group string) *RuleIgnoreNan {
	r := &RuleIgnoreNan{}
	r.batchRule = newBatchRule(group, "ignorenan", []OpCode{CPUI_FLOAT_NAN}, r.apply, func(g string) Rule { return NewRuleIgnoreNan(g) })
	return r
}

// apply removes NaN tests guarding a floating-point comparison of the same
// value, following the NaN result through up to three boolean combinations.
// C++ parity: RuleIgnoreNan::applyOp (nan_ignore_all off: the default
// "compare" setting).
func (r *RuleIgnoreNan) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 1 || op.Output() == nil || op.Input(0).IsFree() {
		return 0
	}
	floatVar := op.Input(0)
	out1 := op.Output()
	count := 0
	for _, boolRead1 := range append([]*PcodeOp(nil), out1.DescendIter()...) {
		var out2 *Varnode
		matchCode := CPUI_BOOL_OR
		if boolRead1.Code() == CPUI_BOOL_NEGATE {
			matchCode = CPUI_BOOL_AND
			out2 = boolRead1.Output()
		} else {
			out2 = nanTestForComparison(floatVar, boolRead1, boolRead1.GetSlot(out1), matchCode, &count, data)
		}
		if out2 == nil {
			continue
		}
		for _, boolRead2 := range append([]*PcodeOp(nil), out2.DescendIter()...) {
			out3 := nanTestForComparison(floatVar, boolRead2, boolRead2.GetSlot(out2), matchCode, &count, data)
			if out3 == nil {
				continue
			}
			for _, boolRead3 := range append([]*PcodeOp(nil), out3.DescendIter()...) {
				nanTestForComparison(floatVar, boolRead3, boolRead3.GetSlot(out3), matchCode, &count, data)
			}
		}
	}
	if count > 0 {
		return 1
	}
	return 0
}

type RuleUnsigned2Float struct{ batchRule }

func NewRuleUnsigned2Float(group string) *RuleUnsigned2Float {
	r := &RuleUnsigned2Float{}
	r.batchRule = newBatchRule(group, "unsigned2float", []OpCode{CPUI_FLOAT_INT2FLOAT}, r.apply, func(g string) Rule { return NewRuleUnsigned2Float(g) })
	return r
}

func (r *RuleUnsigned2Float) apply(op *PcodeOp, data *Funcdata) int {
	orOp := definedBy(op.Input(0), CPUI_INT_OR)
	if orOp == nil || !orOp.Input(0).IsWritten() || !orOp.Input(1).IsWritten() || op.Output() == nil {
		return 0
	}
	shiftOp := definedBy(orOp.Input(0), CPUI_INT_RIGHT)
	andOp := orOp.Input(1).Def()
	if shiftOp == nil {
		shiftOp = definedBy(orOp.Input(1), CPUI_INT_RIGHT)
		andOp = orOp.Input(0).Def()
	}
	if shiftOp == nil || andOp == nil || !isOneConst(shiftOp.Input(1)) {
		return 0
	}
	base := shiftOp.Input(0)
	if base.IsFree() {
		return 0
	}
	if andOp.Code() == CPUI_INT_ZEXT {
		andOp = definedBy(andOp.Input(0), CPUI_INT_AND)
		if andOp == nil {
			return 0
		}
	}
	if andOp.Code() != CPUI_INT_AND || !isOneConst(andOp.Input(1)) {
		return 0
	}
	vn := andOp.Input(0)
	if vn != base {
		subOp := definedBy(vn, CPUI_SUBPIECE)
		if subOp == nil || !isZeroConst(subOp.Input(1)) || subOp.Input(0) != base {
			return 0
		}
	}
	for _, addOp := range op.Output().DescendIter() {
		if addOp.Code() != CPUI_FLOAT_ADD || addOp.Input(0) != op.Output() || addOp.Input(1) != op.Output() {
			continue
		}
		zextOp := newAuxUnaryOp(data, addOp.Addr(), CPUI_INT_ZEXT, preferredUnsignedFloatSize(base.Size()), base)
		data.OpSetOpcode(addOp, CPUI_FLOAT_INT2FLOAT)
		data.OpRemoveInput(addOp, 1)
		data.OpSetInput(addOp, zextOp.Output(), 0)
		return 1
	}
	return 0
}

// C++ parity: ruleaction.cc RuleInt2FloatCollapse
type RuleInt2FloatCollapse struct{ batchRule }

// C++ parity: ruleaction.cc RuleInt2FloatCollapse
func NewRuleInt2FloatCollapse(group string) *RuleInt2FloatCollapse {
	r := &RuleInt2FloatCollapse{}
	r.batchRule = newBatchRule(group, "int2floatcollapse", []OpCode{CPUI_FLOAT_INT2FLOAT}, r.apply, func(g string) Rule {
		return NewRuleInt2FloatCollapse(g)
	})
	return r
}

// C++ parity: ruleaction.cc RuleInt2FloatCollapse::applyOp
func (r *RuleInt2FloatCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if op.Input(0) == nil || !op.Input(0).IsWritten() {
		return 0
	}
	zextop := op.Input(0).Def()
	if zextop == nil || zextop.Code() != CPUI_INT_ZEXT {
		return 0
	}
	basevn := zextop.Input(0)
	if basevn == nil || basevn.IsFree() {
		return 0
	}
	out := op.Output()
	if out == nil {
		return 0
	}
	multiop := out.LoneDescend()
	if multiop == nil || multiop.Code() != CPUI_MULTIEQUAL || multiop.NumInput() != 2 {
		return 0
	}
	slot := multiop.GetSlot(out)
	if slot < 0 {
		return 0
	}
	otherout := multiop.Input(1 - slot)
	if otherout == nil || !otherout.IsWritten() {
		return 0
	}
	op2 := otherout.Def()
	if op2 == nil || op2.Code() != CPUI_FLOAT_INT2FLOAT || op2.Input(0) != basevn {
		return 0
	}
	parent := multiop.Parent()
	if parent == nil {
		return 0
	}
	cond, dir2unsigned := parent.FlowBlock.FindCondition(&parent.FlowBlock, slot, &parent.FlowBlock, 1-slot)
	if cond == nil {
		return 0
	}
	condBasic, ok := cond.Concrete().(*BlockBasic)
	if !ok || condBasic == nil {
		return 0
	}
	cbranch := condBasic.LastOp()
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH || cbranch.Input(1) == nil || !cbranch.Input(1).IsWritten() || cbranch.HasFlag(PcodeOpBooleanFlip) {
		return 0
	}
	compare := cbranch.Input(1).Def()
	if compare == nil || compare.Code() != CPUI_INT_SLESS || compare.NumInput() != 2 {
		return 0
	}
	switch {
	case compare.Input(1) != nil && isZeroConst(compare.Input(1)):
		if compare.Input(0) != basevn || dir2unsigned != 1 {
			return 0
		}
	case compare.Input(0) != nil && compare.Input(0).IsConstant() && compare.Input(0).Offset() == maskForSize(basevn.Size()):
		if compare.Input(1) != basevn || dir2unsigned == 1 {
			return 0
		}
	default:
		return 0
	}
	outbl := multiop.Parent()
	data.OpUninsert(multiop)
	data.OpSetOpcode(multiop, CPUI_FLOAT_INT2FLOAT)
	data.OpRemoveInput(multiop, 0)
	multiop.SetNumInputs(1)
	newzext := data.NewOp(1, multiop.Addr())
	data.OpSetOpcode(newzext, CPUI_INT_ZEXT)
	newout := data.NewUniqueOut(int32(preferredZextSizeFloatInt2Float(int(basevn.Size()))), newzext)
	data.OpSetInput(newzext, basevn, 0)
	data.OpSetInput(multiop, newout, 0)
	data.OpInsertBegin(multiop, outbl)
	data.OpInsertBefore(newzext, multiop)
	return 1
}

type RuleFloatSign struct{ batchRule }

func NewRuleFloatSign(group string) *RuleFloatSign {
	r := &RuleFloatSign{}
	r.batchRule = newBatchRule(group, "floatsign", []OpCode{
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
		CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_TRUNC,
	}, r.apply, func(g string) Rule { return NewRuleFloatSign(g) })
	return r
}

func (r *RuleFloatSign) apply(op *PcodeOp, data *Funcdata) int {
	res := 0
	if op.Code() != CPUI_FLOAT_INT2FLOAT {
		if rewriteFloatSignInput(op, 0, data) {
			res = 1
		}
		if op.NumInput() == 2 && rewriteFloatSignInput(op, 1, data) {
			res = 1
		}
	}
	if op.IsBoolOutput() || op.Code() == CPUI_FLOAT_TRUNC || op.Output() == nil {
		return res
	}
	for _, readOp := range op.Output().DescendIter() {
		if rewriteFloatSignOp(readOp, data) {
			res = 1
		}
	}
	return res
}

type RuleFloatSignCleanup struct{ batchRule }

func NewRuleFloatSignCleanup(group string) *RuleFloatSignCleanup {
	r := &RuleFloatSignCleanup{}
	r.batchRule = newBatchRule(group, "floatsigncleanup", []OpCode{CPUI_INT_AND, CPUI_INT_XOR}, r.apply, func(g string) Rule {
		return NewRuleFloatSignCleanup(g)
	})
	return r
}

func (r *RuleFloatSignCleanup) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil {
		return 0
	}
	dt := op.Output().TypeReadFacing(op)
	if dt == nil || dt.Metatype() != TYPE_FLOAT {
		return 0
	}
	if !rewriteFloatSignOp(op, data) {
		return 0
	}
	return 1
}

// nanTestForComparison removes the NaN input of op (reading it at slot) when
// op combines it with a floating-point comparison of floatVar, through
// matchCode, INT_EQUAL/INT_NOTEQUAL, or a CBRANCH guarding a CBRANCH on the
// comparison. It returns op's output when op combines it with another NaN.
// C++ parity: RuleIgnoreNan::testForComparison.
func nanTestForComparison(floatVar *Varnode, op *PcodeOp, slot int, matchCode OpCode, count *int, data *Funcdata) *Varnode {
	if slot < 0 {
		return nil
	}
	switch opc := op.Code(); {
	case opc == matchCode:
		vn := op.Input(1 - slot)
		if nanCheckBackForCompare(floatVar, vn) {
			data.OpSetOpcode(op, CPUI_COPY)
			data.OpRemoveInput(op, 1)
			data.OpSetInput(op, vn, 0)
			*count++
		} else if nanIsAnotherNan(vn) {
			return op.Output()
		}
	case opc == CPUI_INT_EQUAL || opc == CPUI_INT_NOTEQUAL:
		vn := op.Input(1 - slot)
		if nanCheckBackForCompare(floatVar, vn) {
			val := uint64(1)
			if matchCode == CPUI_BOOL_OR {
				val = 0
			}
			data.OpSetInput(op, data.NewConstant(1, val), slot)
			*count++
		}
	case opc == CPUI_CBRANCH:
		parent := op.Parent()
		outDir := 1
		if matchCode == CPUI_BOOL_OR {
			outDir = 0
		}
		if op.HasFlag(PcodeOpBooleanFlip) {
			outDir = 1 - outDir
		}
		if parent == nil || parent.SizeOut() != 2 {
			return nil
		}
		outBranch := parent.OutEdge(outDir).Point
		bb, ok := outBranch.Concrete().(*BlockBasic)
		if !ok {
			return nil
		}
		lastOp := bb.LastOp()
		if lastOp != nil && lastOp.Code() == CPUI_CBRANCH && outBranch.SizeOut() == 2 {
			otherBranch := parent.OutEdge(1 - outDir).Point
			if outBranch.OutEdge(0).Point == otherBranch || outBranch.OutEdge(1).Point == otherBranch {
				if nanCheckBackForCompare(floatVar, lastOp.Input(1)) {
					val := uint64(1)
					if matchCode == CPUI_BOOL_OR {
						val = 0
					}
					data.OpSetInput(op, data.NewConstant(1, val), 1)
					*count++
				}
			}
		}
	}
	return nil
}

// nanCheckBackForCompare reports a boolean root produced by (or combining
// through BOOL_AND/BOOL_OR) a floating-point comparison of floatVar.
// C++ parity: RuleIgnoreNan::checkBackForCompare.
func nanCheckBackForCompare(floatVar, root *Varnode) bool {
	if !root.IsWritten() {
		return false
	}
	def1 := root.Def()
	if !def1.IsBoolOutput() {
		return false
	}
	if def1.Code() == CPUI_BOOL_NEGATE {
		vn := def1.Input(0)
		if !vn.IsWritten() {
			return false
		}
		def1 = vn.Def()
	}
	if isFloatingPointOpcode(def1.Code()) {
		if def1.NumInput() != 2 {
			return false
		}
		return functionalEquality(floatVar, def1.Input(0)) || functionalEquality(floatVar, def1.Input(1))
	}
	if opc := def1.Code(); opc != CPUI_BOOL_AND && opc != CPUI_BOOL_OR {
		return false
	}
	for i := 0; i < 2; i++ {
		vn := def1.Input(i)
		if !vn.IsWritten() {
			continue
		}
		def2 := vn.Def()
		if !def2.IsBoolOutput() || !isFloatingPointOpcode(def2.Code()) || def2.NumInput() != 2 {
			continue
		}
		if functionalEquality(floatVar, def2.Input(0)) || functionalEquality(floatVar, def2.Input(1)) {
			return true
		}
	}
	return false
}

// nanIsAnotherNan reports vn as the direct or negated output of a NaN.
// C++ parity: RuleIgnoreNan::isAnotherNan.
func nanIsAnotherNan(vn *Varnode) bool {
	if !vn.IsWritten() {
		return false
	}
	op := vn.Def()
	if op.Code() == CPUI_BOOL_NEGATE {
		vn = op.Input(0)
		if !vn.IsWritten() {
			return false
		}
		op = vn.Def()
	}
	return op.Code() == CPUI_FLOAT_NAN
}

// isFloatingPointOpcode is TypeOp::isFloatingPointOp (floatingpoint_op).
func isFloatingPointOpcode(opc OpCode) bool {
	switch opc {
	case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL,
		CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
		return true
	}
	return false
}

func rewriteFloatSignInput(op *PcodeOp, slot int, data *Funcdata) bool {
	if slot >= op.NumInput() {
		return false
	}
	signOp := op.Input(slot).Def()
	return rewriteFloatSignOp(signOp, data)
}

func rewriteFloatSignOp(op *PcodeOp, data *Funcdata) bool {
	resCode, constSlot := floatSignManipulation(op)
	if resCode == CPUI_MAX {
		return false
	}
	data.OpRemoveInput(op, constSlot)
	data.OpSetOpcode(op, resCode)
	return true
}

func floatSignManipulation(op *PcodeOp) (OpCode, int) {
	if op == nil || op.NumInput() != 2 {
		return CPUI_MAX, -1
	}
	for slot := 0; slot < 2; slot++ {
		val, ok := constantValue(op.Input(slot))
		if !ok {
			continue
		}
		size := op.Input(1 - slot).Size()
		switch op.Code() {
		case CPUI_INT_AND:
			if val == lowMask(uint64(size*8-1)) {
				return CPUI_FLOAT_ABS, slot
			}
		case CPUI_INT_XOR:
			if val == signBitForSize(size) {
				return CPUI_FLOAT_NEG, slot
			}
		}
	}
	return CPUI_MAX, -1
}

func preferredUnsignedFloatSize(size int32) int32 {
	if size < 4 {
		return 4
	}
	if size > 8 {
		return 8
	}
	return size
}

func newAuxUnaryOp(data *Funcdata, addr address.Address, opcode OpCode, outSize int32, in *Varnode) *PcodeOp {
	op := data.NewOp(1, addr)
	data.OpSetOpcode(op, opcode)
	data.NewUniqueOut(outSize, op)
	data.OpSetInput(op, in, 0)
	data.OpMarkAlive(op)
	return op
}

type batchCFloatRuleFactory func(string) Rule

var batchCFloatRuleFactories = []batchCFloatRuleFactory{
	func(group string) Rule { return NewRuleFloatCast(group) },
	func(group string) Rule { return NewRuleIgnoreNan(group) },
	func(group string) Rule { return NewRuleUnsigned2Float(group) },
	func(group string) Rule { return NewRuleFloatSign(group) },
	func(group string) Rule { return NewRuleFloatSignCleanup(group) },
}

func BatchCFloatRules(group string) []Rule {
	rules := make([]Rule, 0, len(batchCFloatRuleFactories))
	for _, factory := range batchCFloatRuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchCFloatRules(pool *ActionPool, group string) int {
	if pool == nil {
		return 0
	}
	rules := BatchCFloatRules(group)
	for _, rule := range rules {
		pool.AddRule(rule)
	}
	return len(rules)
}
