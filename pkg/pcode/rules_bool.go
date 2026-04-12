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
	// All descendants of lhs must produce bool output; non-bool consumers
	// mean the expression value is used outside a comparison context.
	// C++ parity: RuleEqual2Zero::applyOp ruleaction.cc:5884-5887
	for _, desc := range lhs.DescendIter() {
		if !desc.IsBoolOutput() {
			return 0
		}
	}
	// Pattern: INT_ADD(a, INT_MULT(b, -1)) == 0  =>  a == b
	// This is the normal form produced by RuleSub2Add from INT_SUB(a,b).
	// Also: INT_ADD(a, c) == 0  =>  a == -c  (constant rhs).
	// C++ parity: RuleEqual2Zero::applyOp ruleaction.cc:5890-5923
	add := definedBy(lhs, CPUI_INT_ADD)
	if add != nil && add.Input(0) != nil && add.Input(1) != nil {
		a, b := add.Input(0), add.Input(1)
		if bval, bok := constantValue(b); bok {
			// INT_ADD(a, c) == 0  =>  a == -c
			sz := b.Size()
			negC := truncateToSize(^bval+1, sz)
			data.OpSetInput(op, a, 0)
			data.OpSetInput(op, data.NewConstant(sz, negC), 1)
			return 1
		}
		// Try: one operand is INT_MULT(x, -1) -- identifies the negated operand.
		for slot := 0; slot < 2; slot++ {
			negvn := add.Input(slot)
			posvn := add.Input(1 - slot)
			mult := definedBy(negvn, CPUI_INT_MULT)
			if mult == nil || mult.Input(0) == nil || mult.Input(1) == nil {
				continue
			}
			mval, mok := constantValue(mult.Input(1))
			if !mok {
				continue
			}
			allOnes := truncateToSize(^uint64(0), negvn.Size())
			if mval != allOnes {
				continue
			}
			unnegvn := mult.Input(0)
			data.OpSetInput(op, posvn, 0)
			data.OpSetInput(op, unnegvn, 1)
			return 1
		}
	}
	// Pattern: INT_SUB(a, b) == 0  =>  a == b (pre-Sub2Add form)
	sub := definedBy(lhs, CPUI_INT_SUB)
	if sub != nil && sub.Input(0) != nil && sub.Input(1) != nil {
		rewriteOp(data, op, op.Code(), sub.Input(0), sub.Input(1))
		return 1
	}
	// Pattern: INT_XOR(a, c) == 0  =>  a == c
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

// RuleSborrow simplifies INT_SBORROW expressions.
//
// Trivial case: sborrow(V, 0) => false (constant 0 of size 1).
//
// Full pattern (RuleSborrow::applyOp in ruleaction.cc lines 3381-3432):
//   sborrow(V,W) != (V + W*-1 s< 0)  =>  V s< W
//   sborrow(V,W) != (0 s< V + W*-1)  =>  W s< V
//   sborrow(V,W) == (0 s< V + W*-1)  =>  V s<= W
//   sborrow(V,W) == (V + W*-1 s< 0)  =>  W s<= V
//
// This fires on the SBORROW op itself: inspect consumers (INT_EQUAL /
// INT_NOTEQUAL) whose other operand is an INT_SLESS over the same
// add-expression, then replace the comparison with a direct signed compare.
type RuleSborrow struct{ batchRule }

func NewRuleSborrow(group string) *RuleSborrow {
	r := &RuleSborrow{}
	r.batchRule = newBatchRule(group, "sborrow", []OpCode{CPUI_INT_SBORROW},
		r.apply, func(g string) Rule { return NewRuleSborrow(g) })
	return r
}

func (r *RuleSborrow) apply(op *PcodeOp, data *Funcdata) int {
	bvn := op.Input(1)
	// Trivial case: sborrow(V, 0) => false
	// This covers the common pattern from compilers that emit SBORROW with 0
	// to detect signed overflow on subtraction from zero.
	if isZeroConst(bvn) {
		rewriteOp(data, op, CPUI_COPY, data.NewConstant(1, 0))
		return 1
	}

	// Full pattern: look for INT_EQUAL or INT_NOTEQUAL consumers of this
	// SBORROW output that compare against an INT_SLESS applied to the
	// add-expression (avn + bvn*-1). When matched, replace the comparison
	// with a direct signed comparison.
	// C++ parity: RuleSborrow::applyOp in ruleaction.cc lines 3381-3432.
	out := op.Output()
	if out == nil {
		return 0
	}
	avn := op.Input(0)

	changed := 0
	for _, cmp := range out.DescendIter() {
		if cmp == nil || cmp.IsDead() {
			continue
		}
		if cmp.Code() != CPUI_INT_EQUAL && cmp.Code() != CPUI_INT_NOTEQUAL {
			continue
		}
		// Find the other input (not the SBORROW output).
		var otherVn *Varnode
		if cmp.Input(0) == out {
			otherVn = cmp.Input(1)
		} else if cmp.Input(1) == out {
			otherVn = cmp.Input(0)
		} else {
			continue
		}
		if otherVn == nil {
			continue
		}
		// The other input must come from an INT_SLESS.
		sless := otherVn.Def()
		if sless == nil || sless.Code() != CPUI_INT_SLESS {
			continue
		}
		// Determine match variant. We expect one of:
		//   (avn + bvn*-1) s< 0   (sless.Input(1) is zero const)
		//   0 s< (avn + bvn*-1)   (sless.Input(0) is zero const)
		addExprVn, zeroSlot, ok := matchSborrowAddExpr(sless, avn, bvn)
		if !ok || addExprVn == nil {
			continue
		}
		// Determine the resulting comparison opcode.
		// C++ parity table:
		//   NEQ + (add s< 0) => V s< W  (zeroSlot==1)
		//   NEQ + (0 s< add) => W s< V  (zeroSlot==0)
		//   EQ  + (0 s< add) => V s<= W (zeroSlot==0)
		//   EQ  + (add s< 0) => W s<= V (zeroSlot==1)
		var resultOpc OpCode
		var lhsVn, rhsVn *Varnode
		isNeq := cmp.Code() == CPUI_INT_NOTEQUAL
		if isNeq && zeroSlot == 1 {
			// NEQ + (add s< 0) => V s< W
			resultOpc = CPUI_INT_SLESS
			lhsVn = avn
			rhsVn = bvn
		} else if isNeq && zeroSlot == 0 {
			// NEQ + (0 s< add) => W s< V
			resultOpc = CPUI_INT_SLESS
			lhsVn = bvn
			rhsVn = avn
		} else if !isNeq && zeroSlot == 0 {
			// EQ + (0 s< add) => V s<= W
			resultOpc = CPUI_INT_SLESSEQUAL
			lhsVn = avn
			rhsVn = bvn
		} else {
			// EQ + (add s< 0) => W s<= V
			resultOpc = CPUI_INT_SLESSEQUAL
			lhsVn = bvn
			rhsVn = avn
		}
		rewriteOp(data, cmp, resultOpc, lhsVn, rhsVn)
		changed = 1
	}
	return changed
}

// matchSborrowAddExpr checks whether the INT_SLESS op contains an add-expression
// matching (avn + bvn*-1) on one side and zero on the other.
// Returns the add-expression varnode, which slot (0 or 1) holds zero, and ok.
// C++ parity: AddExpression::gatherTwoTermsSubtract in ruleaction.cc.
func matchSborrowAddExpr(sless *PcodeOp, avn, bvn *Varnode) (*Varnode, int, bool) {
	for zeroSlot := 0; zeroSlot <= 1; zeroSlot++ {
		zeroVn := sless.Input(zeroSlot)
		addVn := sless.Input(1 - zeroSlot)
		if !isZeroConst(zeroVn) || addVn == nil {
			continue
		}
		addOp := addVn.Def()
		if addOp == nil || addOp.Code() != CPUI_INT_ADD {
			continue
		}
		if isAddExprMatch(addOp, avn, bvn) {
			return addVn, zeroSlot, true
		}
	}
	return nil, 0, false
}

// isAddExprMatch returns true if the INT_ADD op computes (avn + bvn*-1),
// i.e. one input is avn and the other is the negation of bvn.
// C++ parity: AddExpression::gatherTwoTermsSubtract.
func isAddExprMatch(addOp *PcodeOp, avn, bvn *Varnode) bool {
	for slot := 0; slot < 2; slot++ {
		if !sameValue(addOp.Input(slot), avn) {
			continue
		}
		neg := addOp.Input(1 - slot)
		if isNegatedVarnode(neg, bvn) {
			return true
		}
	}
	return false
}

// isNegatedVarnode returns true if neg represents (bvn * -1), i.e. the
// two's-complement negation of bvn. Handles three sub-cases:
//  1. bvn is a constant: neg is the constant equal to (-bvn) masked to size.
//  2. neg is an INT_2COMP of bvn.
//  3. neg is an INT_MULT of bvn by -1 constant.
func isNegatedVarnode(neg, bvn *Varnode) bool {
	if neg == nil || bvn == nil {
		return false
	}
	// Case 1: both constants.
	if neg.IsConstant() && bvn.IsConstant() {
		bits := uint(bvn.Size() * 8)
		var mask uint64
		if bits >= 64 {
			mask = ^uint64(0)
		} else {
			mask = (uint64(1) << bits) - 1
		}
		return ((-bvn.Offset()) & mask) == (neg.Offset() & mask)
	}
	// Case 2: INT_2COMP of bvn.
	if twocomp := neg.Def(); twocomp != nil && twocomp.Code() == CPUI_INT_2COMP {
		if sameValue(twocomp.Input(0), bvn) {
			return true
		}
	}
	// Case 3: INT_MULT of bvn by -1 constant.
	if mult := neg.Def(); mult != nil && mult.Code() == CPUI_INT_MULT {
		for slot := 0; slot < 2; slot++ {
			cv, ok := constantValue(mult.Input(slot))
			if !ok {
				continue
			}
			bits := uint(bvn.Size() * 8)
			var negOne uint64
			if bits >= 64 {
				negOne = ^uint64(0)
			} else {
				negOne = (uint64(1) << bits) - 1
			}
			if cv == negOne && sameValue(mult.Input(1-slot), bvn) {
				return true
			}
		}
	}
	return false
}

// RuleLessNotEqualBoolAnd simplifies BOOL_AND((S)LESSEQUAL(V,W), NOTEQUAL(V,W)) to (S)LESS(V,W).
//
// Pattern: (V <= W) && (V != W)  =>  V < W   (and signed variant s<= / s<)
// This arises from x86 JG pcode: ZF==0 && SF==OF compiles to
//   BOOL_AND(INT_NOTEQUAL(a,0), INT_SLESSEQUAL(0,a)) which simplifies to INT_SLESS(0,a).
//
// C++ parity: RuleLessNotEqual::applyOp in ruleaction.cc
type RuleLessNotEqualBoolAnd struct{ batchRule }

func NewRuleLessNotEqualBoolAnd(group string) *RuleLessNotEqualBoolAnd {
	r := &RuleLessNotEqualBoolAnd{}
	r.batchRule = newBatchRule(group, "lessnotequalbooland", []OpCode{CPUI_BOOL_AND}, r.apply, func(g string) Rule { return NewRuleLessNotEqualBoolAnd(g) })
	return r
}

func (r *RuleLessNotEqualBoolAnd) apply(op *PcodeOp, data *Funcdata) int {
	vn0 := op.Input(0)
	vn1 := op.Input(1)
	if vn0 == nil || vn1 == nil || !vn0.IsWritten() || !vn1.IsWritten() {
		return 0
	}
	opLess := vn0.Def()
	opNeq := vn1.Def()
	opc := opLess.Code()
	if opc != CPUI_INT_LESSEQUAL && opc != CPUI_INT_SLESSEQUAL {
		// Try with inputs swapped.
		opLess, opNeq = opNeq, opLess
		opc = opLess.Code()
		if opc != CPUI_INT_LESSEQUAL && opc != CPUI_INT_SLESSEQUAL {
			return 0
		}
	}
	if opNeq.Code() != CPUI_INT_NOTEQUAL {
		return 0
	}
	compvn1 := opLess.Input(0)
	compvn2 := opLess.Input(1)
	// C++ isHeritageKnown(): constant, written, or input varnodes have stable identities.
	heritageKnown := func(v *Varnode) bool {
		return v != nil && (v.IsConstant() || v.IsWritten() || v.IsInput())
	}
	if !heritageKnown(compvn1) || !heritageKnown(compvn2) {
		return 0
	}
	// Verify that NOTEQUAL compares the same two values (possibly reversed).
	eq0, eq1 := opNeq.Input(0), opNeq.Input(1)
	if !(sameValue(compvn1, eq0) && sameValue(compvn2, eq1)) &&
		!(sameValue(compvn1, eq1) && sameValue(compvn2, eq0)) {
		return 0
	}
	var result OpCode
	if opc == CPUI_INT_SLESSEQUAL {
		result = CPUI_INT_SLESS
	} else {
		result = CPUI_INT_LESS
	}
	rewriteOp(data, op, result, compvn1, compvn2)
	return 1
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
