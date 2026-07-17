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
	// RuleCollapseConstants::applyOp -- ruleaction.cc:3874. In C++ this rule
	// "applies to all opcodes" (ruleaction.hh) and is gated at runtime by
	// PcodeOp::isCollapsible (all inputs constant, assignment, out size <= 8).
	// Go dispatches rules by opcode, so we register the full set evalConstOp can
	// evaluate -- the Go stand-in for op->collapse -> behave->evaluate. Running
	// in the fixpoint pool (not just the once-per-func ActionConstantFold pass)
	// is what folds constants materialized late, e.g. the SUB(const,0) and shift
	// masks in switch/jump-table case bodies.
	r.batchRule = newBatchRule(group, "collapseconstants", constFoldableOpcodes, r.apply, func(g string) Rule { return NewRuleCollapseConstants(g) })
	return r
}

// RuleCollapseConstants::applyOp -- ruleaction.cc:3874.
// evalConstOp performs the op->collapse role: it succeeds only when every input
// resolves to a constant. The result is masked to the output size, mirroring
// data.getArch()->getConstant on the collapsed value.
func (r *RuleCollapseConstants) apply(op *PcodeOp, data *Funcdata) int {
	out := op.Output()
	if out == nil {
		return 0
	}
	res, ok := evalConstOp(op)
	if !ok {
		return 0
	}
	newConst := data.NewConstant(out.Size(), truncateToSize(res, out.Size()))
	return rewriteToCopy(data, op, newConst)
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

// RuleIntLessEqual::applyOp -- ruleaction.cc:611.
// Faithful port: unconditionally delegate to replaceLessequal, which handles
// both constant-left (c <= V => c-1 < V) and constant-right (V <= c => V < c+1)
// forms. ActionNormalizeBranches (blockaction.cc:2117, ported in
// action_nodejoin.go) re-normalizes CBRANCH conditions after structuring, so
// the constant-left form no longer needs to be skipped here.
func (r *RuleIntLessEqual) apply(op *PcodeOp, data *Funcdata) int {
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
	r.batchRule = newKnownMismatchBatchRule(group, "booleanundistribute", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, func(g string) Rule { return NewRuleBooleanUndistribute(g) })
	return r
}

// C++ parity: condexe.cc RuleOrPredicate::MultiPredicate.
type orPredicateMulti struct {
	op             *PcodeOp
	zeroSlot       int
	zeroBlock      *FlowBlock
	condBlock      *FlowBlock
	cbranch        *PcodeOp
	otherVn        *Varnode
	zeroPathIsTrue bool
}

// C++ parity: condexe.cc RuleOrPredicate::MultiPredicate::discoverZeroSlot.
func (m *orPredicateMulti) discoverZeroSlot(vn *Varnode) bool {
	if vn == nil || !vn.IsWritten() {
		return false
	}
	m.op = vn.Def()
	if m.op.Code() != CPUI_MULTIEQUAL || m.op.NumInput() != 2 {
		return false
	}
	for m.zeroSlot = 0; m.zeroSlot < 2; m.zeroSlot++ {
		tmpvn := m.op.Input(m.zeroSlot)
		if tmpvn == nil || !tmpvn.IsWritten() {
			continue
		}
		copyop := tmpvn.Def()
		if copyop.Code() != CPUI_COPY {
			continue
		}
		zerovn := copyop.Input(0)
		if zerovn == nil || !zerovn.IsConstant() || zerovn.Offset() != 0 {
			continue
		}
		m.otherVn = m.op.Input(1 - m.zeroSlot)
		if m.otherVn.IsFree() {
			return false
		}
		return true
	}
	return false
}

// C++ parity: condexe.cc RuleOrPredicate::MultiPredicate::discoverCbranch.
func (m *orPredicateMulti) discoverCbranch() bool {
	baseBlock := m.op.Parent()
	if baseBlock == nil {
		return false
	}
	if m.zeroSlot < 0 || m.zeroSlot >= baseBlock.SizeIn() {
		return false
	}
	m.zeroBlock = baseBlock.InEdge(m.zeroSlot).Point
	otherBlock := baseBlock.InEdge(1 - m.zeroSlot).Point
	if m.zeroBlock.SizeOut() == 1 {
		if m.zeroBlock.SizeIn() != 1 {
			return false
		}
		m.condBlock = m.zeroBlock.InEdge(0).Point
	} else if m.zeroBlock.SizeOut() == 2 {
		m.condBlock = m.zeroBlock
	} else {
		return false
	}
	if m.condBlock.SizeOut() != 2 {
		return false
	}
	if otherBlock.SizeOut() == 1 {
		if otherBlock.SizeIn() != 1 {
			return false
		}
		if m.condBlock != otherBlock.InEdge(0).Point {
			return false
		}
	} else if otherBlock.SizeOut() == 2 {
		if m.condBlock != otherBlock {
			return false
		}
	} else {
		return false
	}
	condBasic, ok := m.condBlock.Concrete().(*BlockBasic)
	if !ok {
		return false
	}
	m.cbranch = condBasic.LastOp()
	if m.cbranch == nil || m.cbranch.Code() != CPUI_CBRANCH {
		return false
	}
	return true
}

// C++ parity: condexe.cc RuleOrPredicate::MultiPredicate::discoverPathIsTrue.
func (m *orPredicateMulti) discoverPathIsTrue() {
	if m.condBlock.TrueOut() == m.zeroBlock {
		m.zeroPathIsTrue = true
	} else if m.condBlock.FalseOut() == m.zeroBlock {
		m.zeroPathIsTrue = false
	} else {
		m.zeroPathIsTrue = m.condBlock.TrueOut() == &m.op.Parent().FlowBlock
	}
}

// C++ parity: condexe.cc RuleOrPredicate::MultiPredicate::discoverConditionalZero.
func (m *orPredicateMulti) discoverConditionalZero(vn *Varnode) bool {
	boolvn := m.cbranch.Input(1)
	if boolvn == nil || !boolvn.IsWritten() {
		return false
	}
	compareop := boolvn.Def()
	opc := compareop.Code()
	if opc == CPUI_INT_NOTEQUAL {
		m.zeroPathIsTrue = !m.zeroPathIsTrue
	} else if opc != CPUI_INT_EQUAL {
		return false
	}
	a1 := compareop.Input(0)
	a2 := compareop.Input(1)
	var zerovn *Varnode
	if a1 == vn {
		zerovn = a2
	} else if a2 == vn {
		zerovn = a1
	} else {
		return false
	}
	if zerovn == nil || !zerovn.IsConstant() || zerovn.Offset() != 0 {
		return false
	}
	if m.cbranch.HasFlag(PcodeOpBooleanFlip) {
		m.zeroPathIsTrue = !m.zeroPathIsTrue
	}
	return true
}

// C++ parity: condexe.cc RuleOrPredicate.
type RuleOrPredicate struct{ batchRule }

// C++ parity: condexe.cc RuleOrPredicate.
func NewRuleOrPredicate(group string) *RuleOrPredicate {
	r := &RuleOrPredicate{}
	r.batchRule = newBatchRule(group, "orpredicate", []OpCode{CPUI_INT_OR, CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleOrPredicate(g) })
	return r
}

// C++ parity: condexe.cc RuleOrPredicate::getOpList.
func (r *RuleOrPredicate) getOpList() []OpCode {
	return []OpCode{CPUI_INT_OR, CPUI_INT_XOR}
}

// C++ parity: condexe.cc RuleOrPredicate::checkSingle.
func (r *RuleOrPredicate) checkSingle(vn *Varnode, branch orPredicateMulti, op *PcodeOp, data *Funcdata) int {
	if vn == nil || vn.IsFree() {
		return 0
	}
	if !branch.discoverCbranch() {
		return 0
	}
	if branch.op.Output() == nil || branch.op.Output().LoneDescend() != op {
		return 0
	}
	branch.discoverPathIsTrue()
	if !branch.discoverConditionalZero(vn) {
		return 0
	}
	if branch.zeroPathIsTrue {
		return 0
	}
	data.OpSetInput(branch.op, vn, branch.zeroSlot)
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpSetInput(op, branch.op.Output(), 0)
	return 1
}

// C++ parity: condexe.cc RuleOrPredicate::applyOp.
func (r *RuleOrPredicate) apply(op *PcodeOp, data *Funcdata) int {
	branch0 := orPredicateMulti{}
	branch1 := orPredicateMulti{}
	test0 := branch0.discoverZeroSlot(op.Input(0))
	test1 := branch1.discoverZeroSlot(op.Input(1))
	if !test0 && !test1 {
		return 0
	}
	if !test0 {
		return r.checkSingle(op.Input(0), branch1, op, data)
	}
	if !test1 {
		return r.checkSingle(op.Input(1), branch0, op, data)
	}
	if !branch0.discoverCbranch() {
		return 0
	}
	if !branch1.discoverCbranch() {
		return 0
	}
	if branch0.condBlock == branch1.condBlock {
		if branch0.zeroBlock == branch1.zeroBlock {
			return 0
		}
	} else {
		var condmarker BooleanExpressionMatch
		if !condmarker.VerifyCondition(branch0.cbranch, branch1.cbranch) {
			return 0
		}
		if condmarker.MultiSlot() != -1 {
			return 0
		}
		branch0.discoverPathIsTrue()
		branch1.discoverPathIsTrue()
		finalBool := branch0.zeroPathIsTrue == branch1.zeroPathIsTrue
		if condmarker.Flip() {
			finalBool = !finalBool
		}
		if finalBool {
			return 0
		}
	}
	order := 0
	if SeqNumLess(branch0.op.Seq(), branch1.op.Seq()) {
		order = -1
	} else if SeqNumLess(branch1.op.Seq(), branch0.op.Seq()) {
		order = 1
	}
	if order == 0 {
		return 0
	}
	var finalBlock *BlockBasic
	slot0SetsBranch0 := false
	if order < 0 {
		finalBlock = branch1.op.Parent()
		slot0SetsBranch0 = branch1.zeroSlot == 0
	} else {
		finalBlock = branch0.op.Parent()
		slot0SetsBranch0 = branch0.zeroSlot == 1
	}
	insertAddr := branch0.op.Addr()
	if finalBlock.FirstOp() != nil {
		insertAddr = finalBlock.FirstOp().Addr()
	}
	newMulti := data.NewOp(2, insertAddr)
	data.OpSetOpcode(newMulti, CPUI_MULTIEQUAL)
	if slot0SetsBranch0 {
		data.OpSetInput(newMulti, branch0.otherVn, 0)
		data.OpSetInput(newMulti, branch1.otherVn, 1)
	} else {
		data.OpSetInput(newMulti, branch1.otherVn, 0)
		data.OpSetInput(newMulti, branch0.otherVn, 1)
	}
	newvn := data.NewUniqueOut(branch0.otherVn.Size(), newMulti)
	data.OpInsertBegin(newMulti, finalBlock)
	data.OpRemoveInput(op, 1)
	data.OpSetInput(op, newvn, 0)
	data.OpSetOpcode(op, CPUI_COPY)
	return 1
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
	// RuleRangeMeld::applyOp -- ruleaction.cc:1357.
	r.batchRule = newBatchRule(group, "rangemeld", []OpCode{CPUI_BOOL_OR, CPUI_BOOL_AND}, r.apply, func(g string) Rule { return NewRuleRangeMeld(g) })
	return r
}

// RuleRangeMeld::applyOp -- ruleaction.cc:1357. Merge two same-variable range
// conditions (V==c, V!=c, V s< c, c s< V, ...) joined by BOOL_AND/BOOL_OR into a
// single comparison by intersecting/unioning their CircleRanges and translating
// the result back to one comparison op.
func (r *RuleRangeMeld) apply(op *PcodeOp, data *Funcdata) int {
	vn1 := op.Input(0)
	if !vn1.IsWritten() {
		return 0
	}
	vn2 := op.Input(1)
	if !vn2.IsWritten() {
		return 0
	}
	sub1 := vn1.Def()
	if !sub1.IsBoolOutput() {
		return 0
	}
	sub2 := vn2.Def()
	if !sub2.IsBoolOutput() {
		return 0
	}

	range1 := newCircleRangeBoolean(true)
	var markup *Varnode
	a1 := range1.pullBack(sub1, &markup, false)
	if a1 == nil {
		return 0
	}
	range2 := newCircleRangeBoolean(true)
	a2 := range2.pullBack(sub2, &markup, false)
	if a2 == nil {
		return 0
	}
	if sub1.Code() == CPUI_BOOL_NEGATE { // Extra pull-back if the last step is a '!'
		if !a1.IsWritten() {
			return 0
		}
		a1 = range1.pullBack(a1.Def(), &markup, false)
		if a1 == nil {
			return 0
		}
	}
	if sub2.Code() == CPUI_BOOL_NEGATE {
		if !a2.IsWritten() {
			return 0
		}
		a2 = range2.pullBack(a2.Def(), &markup, false)
		if a2 == nil {
			return 0
		}
	}
	if !functionalEquality(a1, a2) {
		if a2.Size() == a1.Size() {
			return 0
		}
		if a1.Size() < a2.Size() && a2.IsWritten() {
			a2 = range2.pullBack(a2.Def(), &markup, false)
		} else if a1.IsWritten() {
			a1 = range1.pullBack(a1.Def(), &markup, false)
		}
		if a1 != a2 {
			return 0
		}
	}
	if a1 == nil || !a1.IsHeritageKnown() {
		return 0
	}

	var restype int
	if op.Code() == CPUI_BOOL_AND {
		restype = range1.intersect(range2)
	} else {
		restype = range1.circleUnion(range2)
	}

	if restype == 0 {
		opc, resc, resslot, tr := range1.translate2Op()
		restype = tr
		if tr == 0 {
			newConst := data.NewConstant(a1.Size(), resc)
			data.OpSetOpcode(op, opc)
			data.OpSetInput(op, a1, 1-resslot)
			data.OpSetInput(op, newConst, resslot)
			return 1
		}
	}

	if restype == 2 {
		return 0 // Cannot represent
	}
	if restype == 1 { // Pieces cover everything, condition is always true
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpRemoveInput(op, 1)
		data.OpSetInput(op, data.NewConstant(1, 1), 0)
	} else if restype == 3 { // Nothing left in intersection, condition is always false
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpRemoveInput(op, 1)
		data.OpSetInput(op, data.NewConstant(1, 0), 0)
	}
	return 1
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
