package pcode

import "math/bits"

func newKnownMismatchBatchRule(group string, name string, opcodes []OpCode, cloneFn func(string) Rule) batchRule {
	return newBatchRule(group, name, opcodes, nil, cloneFn)
}

type RuleCollectTerms struct{ batchRule }

func NewRuleCollectTerms(group string) *RuleCollectTerms {
	r := &RuleCollectTerms{}
	// RuleCollectTerms::applyOp -- ruleaction.cc.
	// known mismatch: TermOrder/AdditiveEdge/distributeIntMultAdd are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "collect_terms", []OpCode{CPUI_INT_ADD}, func(g string) Rule { return NewRuleCollectTerms(g) })
	return r
}

type RuleTermOrder struct{ batchRule }

func NewRuleTermOrder(group string) *RuleTermOrder {
	r := &RuleTermOrder{}
	r.batchRule = newBatchRule(group, "termorder", []OpCode{
		CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_ADD, CPUI_INT_CARRY,
		CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		CPUI_INT_MULT, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_ADD,
		CPUI_FLOAT_MULT,
	}, r.apply, func(g string) Rule { return NewRuleTermOrder(g) })
	return r
}

// RuleTermOrder::applyOp -- ruleaction.cc.
func (r *RuleTermOrder) apply(op *PcodeOp, data *Funcdata) int {
	in0 := op.Input(0)
	in1 := op.Input(1)
	if in0 == nil || in1 == nil {
		return 0
	}
	if in0.IsConstant() && !in1.IsConstant() {
		return swapInputs(data, op)
	}
	return 0
}

type RuleSelectCse struct{ batchRule }

func NewRuleSelectCse(group string) *RuleSelectCse {
	r := &RuleSelectCse{}
	// RuleSelectCse::applyOp -- ruleaction.cc.
	// known mismatch: getCseHash/cseEliminateList are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "selectcse", []OpCode{CPUI_SUBPIECE, CPUI_INT_SRIGHT}, func(g string) Rule { return NewRuleSelectCse(g) })
	return r
}

type RuleEarlyRemoval struct{ batchRule }

func NewRuleEarlyRemoval(group string) *RuleEarlyRemoval {
	r := &RuleEarlyRemoval{}
	// RuleEarlyRemoval::applyOp -- ruleaction.cc.
	// known mismatch: doesDeadcode/deadRemovalAllowedSeen space policy is not modeled.
	r.batchRule = newKnownMismatchBatchRule(group, "earlyremoval", nil, func(g string) Rule { return NewRuleEarlyRemoval(g) })
	return r
}

type RuleCollapseConstants struct{ batchRule }

func NewRuleCollapseConstants(group string) *RuleCollapseConstants {
	r := &RuleCollapseConstants{}
	// RuleCollapseConstants::applyOp -- ruleaction.cc.
	// known mismatch: op::collapse, architecture constant-space folding, and constant-symbol propagation are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "collapseconstants", nil, func(g string) Rule { return NewRuleCollapseConstants(g) })
	return r
}

type RuleCarryElim struct{ batchRule }

func NewRuleCarryElim(group string) *RuleCarryElim {
	r := &RuleCarryElim{}
	r.batchRule = newBatchRule(group, "carryelim", []OpCode{CPUI_INT_CARRY}, r.apply, func(g string) Rule { return NewRuleCarryElim(g) })
	return r
}

// RuleCarryElim::applyOp -- ruleaction.cc.
func (r *RuleCarryElim) apply(op *PcodeOp, data *Funcdata) int {
	vn2 := op.Input(1)
	if !vn2.IsConstant() {
		return 0
	}
	vn1 := op.Input(0)
	if vn1.IsFree() {
		return 0
	}
	off := truncateToSize(vn2.Offset(), vn2.Size())
	if off == 0 {
		rewriteOp(data, op, CPUI_COPY, data.NewConstant(1, 0))
		return 1
	}
	off = negateConstForSize(off, vn2.Size())
	rewriteOp(data, op, CPUI_INT_LESSEQUAL, data.NewConstant(vn1.Size(), off), vn1)
	return 1
}

type RuleScarry struct{ batchRule }

func NewRuleScarry(group string) *RuleScarry {
	r := &RuleScarry{}
	// RuleScarry::applyOp -- ruleaction.cc.
	// known mismatch: AddExpression equivalence matching is not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "scarry", []OpCode{CPUI_INT_SCARRY}, func(g string) Rule { return NewRuleScarry(g) })
	return r
}

type RuleTrivialShift struct{ batchRule }

func NewRuleTrivialShift(group string) *RuleTrivialShift {
	r := &RuleTrivialShift{}
	r.batchRule = newBatchRule(group, "trivialshift", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleTrivialShift(g) })
	return r
}

// RuleTrivialShift::applyOp -- ruleaction.cc.
func (r *RuleTrivialShift) apply(op *PcodeOp, data *Funcdata) int {
	constvn := op.Input(1)
	if constvn == nil || !constvn.IsConstant() {
		return 0
	}
	val := truncateToSize(constvn.Offset(), constvn.Size())
	if val != 0 {
		if val < uint64(op.Input(0).Size()*8) {
			return 0
		}
		if op.Code() == CPUI_INT_SRIGHT {
			return 0
		}
		replaceInputSlot(data, op, 0, data.NewConstant(op.Input(0).Size(), 0))
	}
	rewriteOp(data, op, CPUI_COPY, op.Input(0))
	return 1
}

type RuleSignShift struct{ batchRule }

func NewRuleSignShift(group string) *RuleSignShift {
	r := &RuleSignShift{}
	r.batchRule = newBatchRule(group, "signshift", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleSignShift(g) })
	return r
}

// RuleSignShift::applyOp -- ruleaction.cc.
func (r *RuleSignShift) apply(op *PcodeOp, data *Funcdata) int {
	constVn := op.Input(1)
	if !constVn.IsConstant() {
		return 0
	}
	inVn := op.Input(0)
	if truncateToSize(constVn.Offset(), constVn.Size()) != uint64(inVn.Size()*8-1) {
		return 0
	}
	if inVn.IsFree() {
		return 0
	}
	doConversion := false
	for _, arithOp := range op.Output().DescendIter() {
		switch arithOp.Code() {
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			if arithOp.Input(1).IsConstant() {
				doConversion = true
			}
		case CPUI_INT_ADD, CPUI_INT_MULT:
			doConversion = true
		}
		if doConversion {
			break
		}
	}
	if !doConversion {
		return 0
	}
	shiftOp := data.NewOp(2, op.Addr())
	data.OpSetOpcode(shiftOp, CPUI_INT_SRIGHT)
	uniqueVn := data.NewUniqueOut(inVn.Size(), shiftOp)
	data.OpSetInput(shiftOp, inVn, 0)
	data.OpSetInput(shiftOp, constVn, 1)
	data.OpInsertBefore(shiftOp, op)
	rewriteOp(data, op, CPUI_INT_MULT, uniqueVn, data.NewConstant(inVn.Size(), maskForSize(inVn.Size())))
	return 1
}

type RuleTestSign struct{ batchRule }

func NewRuleTestSign(group string) *RuleTestSign {
	r := &RuleTestSign{}
	r.batchRule = newBatchRule(group, "testsign", []OpCode{CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleTestSign(g) })
	return r
}

func (r *RuleTestSign) findComparisons(vn *Varnode) []*PcodeOp {
	res := make([]*PcodeOp, 0)
	for _, op := range vn.DescendIter() {
		if (op.Code() == CPUI_INT_EQUAL || op.Code() == CPUI_INT_NOTEQUAL) && op.Input(1).IsConstant() {
			res = append(res, op)
		}
	}
	return res
}

// RuleTestSign::applyOp -- ruleaction.cc.
func (r *RuleTestSign) apply(op *PcodeOp, data *Funcdata) int {
	constVn := op.Input(1)
	if !constVn.IsConstant() {
		return 0
	}
	inVn := op.Input(0)
	if truncateToSize(constVn.Offset(), constVn.Size()) != uint64(inVn.Size()*8-1) {
		return 0
	}
	if inVn.IsFree() {
		return 0
	}
	compareOps := r.findComparisons(op.Output())
	resultCode := 0
	for _, compareOp := range compareOps {
		compVn := compareOp.Input(0)
		compSize := compVn.Size()
		offset := truncateToSize(compareOp.Input(1).Offset(), compareOp.Input(1).Size())
		sgn := 0
		if offset == 0 {
			sgn = 1
		} else if offset == maskForSize(compSize) {
			sgn = -1
		} else {
			continue
		}
		if compareOp.Code() == CPUI_INT_NOTEQUAL {
			sgn = -sgn
		}
		zeroVn := data.NewConstant(inVn.Size(), 0)
		if sgn == 1 {
			rewriteOp(data, compareOp, CPUI_INT_SLESSEQUAL, zeroVn, inVn)
		} else {
			rewriteOp(data, compareOp, CPUI_INT_SLESS, inVn, zeroVn)
		}
		resultCode = 1
	}
	return resultCode
}

type RuleOrConsume struct{ batchRule }

func NewRuleOrConsume(group string) *RuleOrConsume {
	r := &RuleOrConsume{}
	r.batchRule = newBatchRule(group, "orconsume", []OpCode{CPUI_INT_OR, CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleOrConsume(g) })
	return r
}

// RuleOrConsume::applyOp -- ruleaction.cc.
func (r *RuleOrConsume) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil || outvn.Size() > 8 {
		return 0
	}
	consume := outvn.Consumed()
	if consume&op.Input(0).NZMask() == 0 {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if consume&op.Input(1).NZMask() == 0 {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleIntLessEqual struct{ batchRule }

func NewRuleIntLessEqual(group string) *RuleIntLessEqual {
	r := &RuleIntLessEqual{}
	r.batchRule = newBatchRule(group, "intlessequal", []OpCode{CPUI_INT_LESSEQUAL, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleIntLessEqual(g) })
	return r
}

// RuleIntLessEqual::applyOp -- ruleaction.cc.
// C++ parity note: C++ converts both constant-left (c <= V => c-1 < V) and
// constant-right (V <= c => V < c+1) forms. We skip constant-on-left here
// because that form with PcodeOpBooleanFlip=true (set by ActionBlockStructure
// on while-loop CBRANCHes) renders as V <= c-1 instead of V < c, diverging
// from golden. C++ avoids this via ActionNormalizeBranches (not yet ported)
// which re-normalizes c-1 < V back to V < c after structuring.
func (r *RuleIntLessEqual) apply(op *PcodeOp, data *Funcdata) int {
	// Skip constant-on-left: requires ActionNormalizeBranches to fix rendering.
	if op.NumInput() < 1 || op.Input(0) == nil || op.Input(0).IsConstant() {
		return 0
	}
	if replaceLessequal(data, op) {
		return 1
	}
	return 0
}

type RuleBitUndistribute struct{ batchRule }

func NewRuleBitUndistribute(group string) *RuleBitUndistribute {
	r := &RuleBitUndistribute{}
	// RuleBitUndistribute::applyOp -- ruleaction.cc.
	// known mismatch: exact extension/shift undistribution depends on heritage-known and additional IR rewrite helpers not yet ported.
	r.batchRule = newKnownMismatchBatchRule(group, "bitundistribute", []OpCode{CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR}, func(g string) Rule { return NewRuleBitUndistribute(g) })
	return r
}

type RuleBooleanUndistribute struct{ batchRule }

func NewRuleBooleanUndistribute(group string) *RuleBooleanUndistribute {
	r := &RuleBooleanUndistribute{}
	// RuleBooleanUndistribute::applyOp -- ruleaction.cc.
	// known mismatch: BooleanMatch/opBoolNegate are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "booleanundistribute", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, func(g string) Rule { return NewRuleBooleanUndistribute(g) })
	return r
}

type RuleShiftAnd struct{ batchRule }

func NewRuleShiftAnd(group string) *RuleShiftAnd {
	r := &RuleShiftAnd{}
	r.batchRule = newBatchRule(group, "shiftand", []OpCode{CPUI_INT_RIGHT, CPUI_INT_LEFT, CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRuleShiftAnd(g) })
	return r
}

// RuleShiftAnd::applyOp -- ruleaction.cc.
func (r *RuleShiftAnd) apply(op *PcodeOp, data *Funcdata) int {
	cvn := op.Input(1)
	if !cvn.IsConstant() {
		return 0
	}
	shiftin := op.Input(0)
	if !shiftin.IsWritten() {
		return 0
	}
	andop := shiftin.Def()
	if andop.Code() != CPUI_INT_AND {
		return 0
	}
	maskvn := andop.Input(1)
	if !maskvn.IsConstant() {
		return 0
	}
	mask := truncateToSize(maskvn.Offset(), maskvn.Size())
	invn := andop.Input(0)
	if invn.IsFree() {
		return 0
	}
	opc := op.Code()
	sa := 0
	if opc == CPUI_INT_RIGHT || opc == CPUI_INT_LEFT {
		sa = int(truncateToSize(cvn.Offset(), cvn.Size()))
	} else {
		val := truncateToSize(cvn.Offset(), cvn.Size())
		if val == 0 || val&(val-1) != 0 {
			return 0
		}
		sa = bits.TrailingZeros64(val)
		if sa <= 0 {
			return 0
		}
		opc = CPUI_INT_LEFT
	}
	nzm := invn.NZMask()
	fullmask := maskForSize(invn.Size())
	if opc == CPUI_INT_RIGHT {
		nzm >>= sa
		mask >>= sa
	} else {
		nzm = (nzm << sa) & fullmask
		mask = (mask << sa) & fullmask
	}
	if mask&nzm != nzm {
		return 0
	}
	replaceInputSlot(data, op, 0, invn)
	return 1
}

type RuleConcatZero struct{ batchRule }

func NewRuleConcatZero(group string) *RuleConcatZero {
	r := &RuleConcatZero{}
	r.batchRule = newBatchRule(group, "concatzero", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatZero(g) })
	return r
}

// RuleConcatZero::applyOp -- ruleaction.cc.
func (r *RuleConcatZero) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(1)) {
		return 0
	}
	sa := uint64(8 * op.Input(1).Size())
	highvn := op.Input(0)
	newop := data.NewOp(1, op.Addr())
	data.OpSetOpcode(newop, CPUI_INT_ZEXT)
	outvn := data.NewUniqueOut(outputSize(op), newop)
	data.OpSetInput(newop, highvn, 0)
	data.OpInsertBefore(newop, op)
	rewriteOp(data, op, CPUI_INT_LEFT, outvn, data.NewConstant(4, sa))
	return 1
}

type RuleHumptyDumpty struct{ batchRule }

func NewRuleHumptyDumpty(group string) *RuleHumptyDumpty {
	r := &RuleHumptyDumpty{}
	r.batchRule = newBatchRule(group, "humptydumpty", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleHumptyDumpty(g) })
	return r
}

// RuleHumptyDumpty::applyOp -- ruleaction.cc.
func (r *RuleHumptyDumpty) apply(op *PcodeOp, data *Funcdata) int {
	vn1 := op.Input(0)
	if !vn1.IsWritten() {
		return 0
	}
	sub1 := vn1.Def()
	if sub1.Code() != CPUI_SUBPIECE {
		return 0
	}
	vn2 := op.Input(1)
	if !vn2.IsWritten() {
		return 0
	}
	sub2 := vn2.Def()
	if sub2.Code() != CPUI_SUBPIECE {
		return 0
	}
	root := sub1.Input(0)
	if root != sub2.Input(0) {
		return 0
	}
	pos1, ok1 := constantValue(sub1.Input(1))
	pos2, ok2 := constantValue(sub2.Input(1))
	if !ok1 || !ok2 {
		return 0
	}
	size1 := vn1.Size()
	size2 := vn2.Size()
	if pos1 != pos2+uint64(size2) {
		return 0
	}
	if pos2 == 0 && size1+size2 == root.Size() {
		return rewriteToCopy(data, op, root)
	}
	rewriteOp(data, op, CPUI_SUBPIECE, root, data.NewConstant(sub2.Input(1).Size(), pos2))
	return 1
}

type RuleDumptyHump struct{ batchRule }

func NewRuleDumptyHump(group string) *RuleDumptyHump {
	r := &RuleDumptyHump{}
	r.batchRule = newBatchRule(group, "dumptyhump", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleDumptyHump(g) })
	return r
}

// RuleDumptyHump::applyOp -- ruleaction.cc.
func (r *RuleDumptyHump) apply(op *PcodeOp, data *Funcdata) int {
	base := op.Input(0)
	if base == nil || !base.IsWritten() {
		return 0
	}
	pieceop := base.Def()
	if pieceop.Code() != CPUI_PIECE {
		return 0
	}
	offset, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	outsize := outputSize(op)
	vn1 := pieceop.Input(0)
	vn2 := pieceop.Input(1)
	vn := vn2
	if offset < uint64(vn2.Size()) {
		if offset+uint64(outsize) > uint64(vn2.Size()) {
			return 0
		}
	} else {
		vn = vn1
		offset -= uint64(vn2.Size())
	}
	if vn.IsFree() && !vn.IsConstant() {
		return 0
	}
	if offset == 0 && outsize == vn.Size() {
		return rewriteToCopy(data, op, vn)
	}
	replaceInputSlot(data, op, 0, vn)
	replaceInputSlot(data, op, 1, data.NewConstant(4, offset))
	return 1
}

type RuleIndirectCollapse struct{ batchRule }

func NewRuleIndirectCollapse(group string) *RuleIndirectCollapse {
	r := &RuleIndirectCollapse{}
	// RuleIndirectCollapse::applyOp -- ruleaction.cc.
	// known mismatch: IOP-space op references, totalReplace, and guarded STORE resolution are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "indirectcollapse", []OpCode{CPUI_INDIRECT}, func(g string) Rule { return NewRuleIndirectCollapse(g) })
	return r
}

type RuleDivTermAdd struct{ batchRule }

func NewRuleDivTermAdd(group string) *RuleDivTermAdd {
	r := &RuleDivTermAdd{}
	// RuleDivTermAdd::applyOp -- ruleaction.cc.
	// known mismatch: extended-constant arithmetic and findSubshift/division-form helpers are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "divtermadd", []OpCode{CPUI_SUBPIECE, CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, func(g string) Rule { return NewRuleDivTermAdd(g) })
	return r
}

type RuleDivTermAdd2 struct{ batchRule }

func NewRuleDivTermAdd2(group string) *RuleDivTermAdd2 {
	r := &RuleDivTermAdd2{}
	// RuleDivTermAdd2::applyOp -- ruleaction.cc.
	// known mismatch: extended-constant arithmetic and optimized division form matching are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "divtermadd2", []OpCode{CPUI_INT_RIGHT}, func(g string) Rule { return NewRuleDivTermAdd2(g) })
	return r
}

type RuleSignNearMult struct{ batchRule }

func NewRuleSignNearMult(group string) *RuleSignNearMult {
	r := &RuleSignNearMult{}
	r.batchRule = newBatchRule(group, "signnearmult", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleSignNearMult(g) })
	return r
}

// RuleSignNearMult::applyOp -- ruleaction.cc.
func (r *RuleSignNearMult) apply(op *PcodeOp, data *Funcdata) int {
	if !op.Input(1).IsConstant() || !op.Input(0).IsWritten() {
		return 0
	}
	addop := op.Input(0).Def()
	if addop.Code() != CPUI_INT_ADD {
		return 0
	}
	var shiftvn *Varnode
	var unshiftop *PcodeOp
	slot := -1
	for i := 0; i < 2; i++ {
		shiftvn = addop.Input(i)
		if !shiftvn.IsWritten() {
			continue
		}
		unshiftop = shiftvn.Def()
		if unshiftop.Code() == CPUI_INT_RIGHT && unshiftop.Input(1).IsConstant() {
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0
	}
	x := addop.Input(1 - slot)
	if x.IsFree() {
		return 0
	}
	n := int(truncateToSize(unshiftop.Input(1).Offset(), unshiftop.Input(1).Size()))
	if n <= 0 {
		return 0
	}
	n = int(shiftvn.Size()*8) - n
	if n <= 0 || n >= 64 {
		return 0
	}
	mask := maskForSize(shiftvn.Size())
	mask = (mask << n) & mask
	if mask != truncateToSize(op.Input(1).Offset(), op.Input(1).Size()) {
		return 0
	}
	sgnvn := unshiftop.Input(0)
	if !sgnvn.IsWritten() {
		return 0
	}
	sshiftop := sgnvn.Def()
	if sshiftop.Code() != CPUI_INT_SRIGHT || !sshiftop.Input(1).IsConstant() {
		return 0
	}
	if sshiftop.Input(0) != x {
		return 0
	}
	val := truncateToSize(sshiftop.Input(1).Offset(), sshiftop.Input(1).Size())
	if val != uint64(8*x.Size()-1) {
		return 0
	}
	pow := uint64(1) << n
	newdiv := data.NewOp(2, op.Addr())
	data.OpSetOpcode(newdiv, CPUI_INT_SDIV)
	divvn := data.NewUniqueOut(x.Size(), newdiv)
	data.OpSetInput(newdiv, x, 0)
	data.OpSetInput(newdiv, data.NewConstant(x.Size(), pow), 1)
	data.OpInsertBefore(newdiv, op)
	rewriteOp(data, op, CPUI_INT_MULT, divvn, data.NewConstant(x.Size(), pow))
	return 1
}

type RuleRangeMeld struct{ batchRule }

func NewRuleRangeMeld(group string) *RuleRangeMeld {
	r := &RuleRangeMeld{}
	// RuleRangeMeld::applyOp -- ruleaction.cc.
	// known mismatch: CircleRange pullBack/intersect/union translation is not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "rangemeld", []OpCode{CPUI_BOOL_OR, CPUI_BOOL_AND}, func(g string) Rule { return NewRuleRangeMeld(g) })
	return r
}

type RuleFloatRange struct{ batchRule }

func NewRuleFloatRange(group string) *RuleFloatRange {
	r := &RuleFloatRange{}
	r.batchRule = newBatchRule(group, "floatrange", []OpCode{CPUI_BOOL_OR, CPUI_BOOL_AND}, r.apply, func(g string) Rule { return NewRuleFloatRange(g) })
	return r
}

// RuleFloatRange::applyOp -- ruleaction.cc.
func (r *RuleFloatRange) apply(op *PcodeOp, data *Funcdata) int {
	vn1 := op.Input(0)
	if !vn1.IsWritten() {
		return 0
	}
	vn2 := op.Input(1)
	if !vn2.IsWritten() {
		return 0
	}
	cmp1 := vn1.Def()
	cmp2 := vn2.Def()
	opccmp1 := cmp1.Code()
	if opccmp1 != CPUI_FLOAT_LESS && opccmp1 != CPUI_FLOAT_LESSEQUAL {
		cmp1, cmp2 = cmp2, cmp1
		opccmp1 = cmp1.Code()
	}
	resultopc := CPUI_MAX
	if opccmp1 == CPUI_FLOAT_LESS {
		if cmp2.Code() == CPUI_FLOAT_EQUAL && op.Code() == CPUI_BOOL_OR {
			resultopc = CPUI_FLOAT_LESSEQUAL
		}
	} else if opccmp1 == CPUI_FLOAT_LESSEQUAL {
		if cmp2.Code() == CPUI_FLOAT_NOTEQUAL && op.Code() == CPUI_BOOL_AND {
			resultopc = CPUI_FLOAT_LESS
		}
	}
	if resultopc == CPUI_MAX {
		return 0
	}
	slot1 := 0
	nvn1 := cmp1.Input(slot1)
	if nvn1.IsConstant() {
		slot1 = 1
		nvn1 = cmp1.Input(slot1)
		if nvn1.IsConstant() {
			return 0
		}
	}
	if nvn1.IsFree() {
		return 0
	}
	cvn1 := cmp1.Input(1 - slot1)
	slot2 := -1
	if sameValue(nvn1, cmp2.Input(0)) {
		slot2 = 0
	} else if sameValue(nvn1, cmp2.Input(1)) {
		slot2 = 1
	} else {
		return 0
	}
	matchvn := cmp2.Input(1 - slot2)
	if cvn1.IsConstant() {
		if !matchvn.IsConstant() || !sameValue(cvn1, matchvn) {
			return 0
		}
	} else if cvn1 != matchvn || cvn1.IsFree() {
		return 0
	}
	rhs := cvn1
	if cvn1.IsConstant() {
		rhs = data.NewConstant(cvn1.Size(), truncateToSize(cvn1.Offset(), cvn1.Size()))
	}
	if slot1 == 0 {
		rewriteOp(data, op, resultopc, nvn1, rhs)
	} else {
		rewriteOp(data, op, resultopc, rhs, nvn1)
	}
	return 1
}

type RulePopcountBoolXor struct{ batchRule }

func NewRulePopcountBoolXor(group string) *RulePopcountBoolXor {
	r := &RulePopcountBoolXor{}
	// RulePopcountBoolXor::applyOp -- ruleaction.cc.
	// known mismatch: getBooleanResult boolean-bit extraction is not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "popcountboolxor", []OpCode{CPUI_POPCOUNT}, func(g string) Rule { return NewRulePopcountBoolXor(g) })
	return r
}

type RuleExtensionPush struct{ batchRule }

func NewRuleExtensionPush(group string) *RuleExtensionPush {
	r := &RuleExtensionPush{}
	// RuleExtensionPush::applyOp -- ruleaction.cc.
	// known mismatch: duplicateNeed/RulePushPtr-driven extension duplication is not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "extensionpush", []OpCode{CPUI_INT_ZEXT, CPUI_INT_SEXT}, func(g string) Rule { return NewRuleExtensionPush(g) })
	return r
}

type RulePieceStructure struct{ batchRule }

func NewRulePieceStructure(group string) *RulePieceStructure {
	r := &RulePieceStructure{}
	// RulePieceStructure::applyOp -- ruleaction.cc.
	// known mismatch: structured-type discovery, PieceNode traversal, and symbol splitting are not ported.
	r.batchRule = newKnownMismatchBatchRule(group, "piecestructure", []OpCode{CPUI_PIECE, CPUI_INT_ZEXT}, func(g string) Rule { return NewRulePieceStructure(g) })
	return r
}
