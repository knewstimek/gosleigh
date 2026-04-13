package pcode

import (
	"fmt"
	"math/bits"

	"gosleigh/pkg/address"
)

type RuleSwitchSingle struct{ batchRule }

func NewRuleSwitchSingle(group string) *RuleSwitchSingle {
	r := &RuleSwitchSingle{}
	r.batchRule = newBatchRule(group, "switchsingle", []OpCode{CPUI_BRANCHIND}, r.apply, func(g string) Rule { return NewRuleSwitchSingle(g) })
	return r
}

func (r *RuleSwitchSingle) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 1 {
		return 0
	}
	phi := definedBy(op.Input(0), CPUI_MULTIEQUAL)
	if phi == nil || phi.NumInput() == 0 {
		return 0
	}
	base := phi.Input(0)
	for i := 1; i < phi.NumInput(); i++ {
		if !sameValue(base, phi.Input(i)) {
			return 0
		}
	}
	replaceInputSlot(data, op, 0, base)
	return 1
}

type RuleTransformCPool struct{ batchRule }

func NewRuleTransformCPool(group string) *RuleTransformCPool {
	r := &RuleTransformCPool{}
	r.batchRule = newBatchRule(group, "transformcpool", []OpCode{CPUI_CPOOLREF}, r.apply, func(g string) Rule { return NewRuleTransformCPool(g) })
	return r
}

func (r *RuleTransformCPool) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil || op.NumInput() != 1 || !op.Input(0).IsConstant() {
		return 0
	}
	return rewriteToCopy(data, op, op.Input(0))
}

type RulePiecePathology struct{ batchRule }

func NewRulePiecePathology(group string) *RulePiecePathology {
	r := &RulePiecePathology{}
	r.batchRule = newBatchRule(group, "piecepathology", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRulePiecePathology(g) })
	return r
}

func (r *RulePiecePathology) apply(op *PcodeOp, data *Funcdata) int {
	hi := definedBy(op.Input(0), CPUI_SUBPIECE)
	lo := definedBy(op.Input(1), CPUI_SUBPIECE)
	if hi == nil || lo == nil || !sameValue(hi.Input(0), lo.Input(0)) {
		return 0
	}
	hiOff, hiOK := constantValue(hi.Input(1))
	loOff, loOK := constantValue(lo.Input(1))
	if !hiOK || !loOK || loOff != 0 || hiOff != uint64(op.Input(1).Size()) {
		return 0
	}
	if hi.Input(0).Size() != outputSize(op) {
		return 0
	}
	return rewriteToCopy(data, op, hi.Input(0))
}

type RuleExpandLoad struct{ batchRule }

func NewRuleExpandLoad(group string) *RuleExpandLoad {
	r := &RuleExpandLoad{}
	r.batchRule = newBatchRule(group, "expandload", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleExpandLoad(g) })
	return r
}

func (r *RuleExpandLoad) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 2 {
		return 0
	}
	ptr := op.Input(1)
	if ptrsub := definedBy(ptr, CPUI_PTRSUB); ptrsub != nil && ptrsub.NumInput() >= 2 && isZeroConst(ptrsub.Input(1)) {
		replaceInputSlot(data, op, 1, ptrsub.Input(0))
		return 1
	}
	if ptradd := definedBy(ptr, CPUI_PTRADD); ptradd != nil && ptradd.NumInput() >= 2 && isZeroConst(ptradd.Input(1)) {
		replaceInputSlot(data, op, 1, ptradd.Input(0))
		return 1
	}
	if cast := definedBy(ptr, CPUI_CAST); cast != nil && cast.NumInput() == 1 && cast.Input(0).Size() == ptr.Size() {
		replaceInputSlot(data, op, 1, cast.Input(0))
		return 1
	}
	return 0
}

type RuleNotDistribute struct{ batchRule }

func NewRuleNotDistribute(group string) *RuleNotDistribute {
	r := &RuleNotDistribute{}
	r.batchRule = newBatchRule(group, "notdistribute", []OpCode{CPUI_INT_NEGATE}, r.apply, func(g string) Rule { return NewRuleNotDistribute(g) })
	return r
}

func (r *RuleNotDistribute) apply(op *PcodeOp, data *Funcdata) int {
	root := op.Input(0).Def()
	if root == nil || root.NumInput() != 2 {
		return 0
	}
	outSize := outputOrInputSize(op)
	switch root.Code() {
	case CPUI_INT_AND:
		neg0 := newAuxUnaryOp(data, op.Addr(), CPUI_INT_NEGATE, outSize, root.Input(0))
		neg1 := newAuxUnaryOp(data, op.Addr(), CPUI_INT_NEGATE, outSize, root.Input(1))
		rewriteOp(data, op, CPUI_INT_OR, neg0.Output(), neg1.Output())
		return 1
	case CPUI_INT_OR:
		neg0 := newAuxUnaryOp(data, op.Addr(), CPUI_INT_NEGATE, outSize, root.Input(0))
		neg1 := newAuxUnaryOp(data, op.Addr(), CPUI_INT_NEGATE, outSize, root.Input(1))
		rewriteOp(data, op, CPUI_INT_AND, neg0.Output(), neg1.Output())
		return 1
	}
	return 0
}

type RuleHighOrderAnd struct{ batchRule }

func NewRuleHighOrderAnd(group string) *RuleHighOrderAnd {
	r := &RuleHighOrderAnd{}
	r.batchRule = newBatchRule(group, "highorderand", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleHighOrderAnd(g) })
	return r
}

func (r *RuleHighOrderAnd) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		shift := definedBy(op.Input(slot), CPUI_INT_RIGHT)
		if shift == nil || shift.NumInput() != 2 {
			continue
		}
		amt, amtOK := constantValue(shift.Input(1))
		mask, maskOK := constantValue(op.Input(1 - slot))
		if !amtOK || !maskOK || amt%8 != 0 || mask != maskForSize(outputOrInputSize(op)) {
			continue
		}
		byteOff := amt / 8
		if byteOff+uint64(outputSize(op)) > uint64(shift.Input(0).Size()) {
			continue
		}
		rewriteOp(data, op, CPUI_SUBPIECE, shift.Input(0), data.NewConstant(4, byteOff))
		return 1
	}
	return 0
}

type RuleAndDistribute struct{ batchRule }

func NewRuleAndDistribute(group string) *RuleAndDistribute {
	r := &RuleAndDistribute{}
	r.batchRule = newBatchRule(group, "anddistribute", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndDistribute(g) })
	return r
}

func (r *RuleAndDistribute) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		orop := definedBy(op.Input(slot), CPUI_INT_OR)
		mask, ok := constantValue(op.Input(1 - slot))
		if orop == nil || !ok {
			continue
		}
		outSize := outputOrInputSize(op)
		masked0 := newAuxBinaryOp(data, op.Addr(), CPUI_INT_AND, outSize, orop.Input(0), data.NewConstant(outSize, mask))
		masked1 := newAuxBinaryOp(data, op.Addr(), CPUI_INT_AND, outSize, orop.Input(1), data.NewConstant(outSize, mask))
		rewriteOp(data, op, CPUI_INT_OR, masked0.Output(), masked1.Output())
		return 1
	}
	return 0
}

type RuleAndCompare struct{ batchRule }

func NewRuleAndCompare(group string) *RuleAndCompare {
	r := &RuleAndCompare{}
	r.batchRule = newBatchRule(group, "andcompare", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleAndCompare(g) })
	return r
}

func (r *RuleAndCompare) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		andop := definedBy(op.Input(slot), CPUI_INT_AND)
		c, cOK := constantValue(op.Input(1 - slot))
		if andop == nil || !cOK {
			continue
		}
		mask, maskOK := constantValue(andop.Input(1))
		if !maskOK || !isSingleBitMask(mask) || c != mask {
			continue
		}
		replaceInputSlot(data, op, 1-slot, data.NewConstant(op.Input(1-slot).Size(), 0))
		if op.Code() == CPUI_INT_EQUAL {
			data.OpSetOpcode(op, CPUI_INT_NOTEQUAL)
		} else {
			data.OpSetOpcode(op, CPUI_INT_EQUAL)
		}
		return 1
	}
	return 0
}

type RuleDoubleSub struct{ batchRule }

func NewRuleDoubleSub(group string) *RuleDoubleSub {
	r := &RuleDoubleSub{}
	r.batchRule = newBatchRule(group, "doublesub", []OpCode{CPUI_INT_SUB}, r.apply, func(g string) Rule { return NewRuleDoubleSub(g) })
	return r
}

func (r *RuleDoubleSub) apply(op *PcodeOp, data *Funcdata) int {
	inner := definedBy(op.Input(0), CPUI_INT_SUB)
	if inner == nil {
		return 0
	}
	c1, ok1 := constantValue(inner.Input(1))
	c2, ok2 := constantValue(op.Input(1))
	if !ok1 || !ok2 {
		return 0
	}
	size := outputOrInputSize(op)
	rewriteOp(data, op, CPUI_INT_SUB, inner.Input(0), data.NewConstant(size, truncateToSize(c1+c2, size)))
	return 1
}

type RuleDoubleShift struct{ batchRule }

func NewRuleDoubleShift(group string) *RuleDoubleShift {
	r := &RuleDoubleShift{}
	r.batchRule = newBatchRule(group, "doubleshift", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleDoubleShift(g) })
	return r
}

func (r *RuleDoubleShift) apply(op *PcodeOp, data *Funcdata) int {
	if op.Code() != CPUI_INT_LEFT && op.Code() != CPUI_INT_RIGHT {
		return 0
	}
	return combineNestedShift(op, data, op.Code())
}

type RuleDoubleArithShift struct{ batchRule }

func NewRuleDoubleArithShift(group string) *RuleDoubleArithShift {
	r := &RuleDoubleArithShift{}
	r.batchRule = newBatchRule(group, "doublearithshift", []OpCode{CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleDoubleArithShift(g) })
	return r
}

func (r *RuleDoubleArithShift) apply(op *PcodeOp, data *Funcdata) int {
	return combineNestedShift(op, data, CPUI_INT_SRIGHT)
}

type RuleConcatShift struct{ batchRule }

func NewRuleConcatShift(group string) *RuleConcatShift {
	r := &RuleConcatShift{}
	r.batchRule = newBatchRule(group, "concatshift", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleConcatShift(g) })
	return r
}

func (r *RuleConcatShift) apply(op *PcodeOp, data *Funcdata) int {
	if op.Code() != CPUI_INT_RIGHT {
		return 0
	}
	piece := definedBy(op.Input(0), CPUI_PIECE)
	if piece == nil {
		return 0
	}
	amt, ok := constantValue(op.Input(1))
	if !ok || amt != uint64(piece.Input(1).Size()*8) || outputSize(op) != piece.Input(0).Size() {
		return 0
	}
	return rewriteToCopy(data, op, piece.Input(0))
}

type RuleLeftRight struct{ batchRule }

func NewRuleLeftRight(group string) *RuleLeftRight {
	r := &RuleLeftRight{}
	r.batchRule = newBatchRule(group, "leftright", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleLeftRight(g) })
	return r
}

func (r *RuleLeftRight) apply(op *PcodeOp, data *Funcdata) int {
	left := definedBy(op.Input(0), CPUI_INT_LEFT)
	if left == nil {
		return 0
	}
	amt0, ok0 := constantValue(left.Input(1))
	amt1, ok1 := constantValue(op.Input(1))
	if !ok0 || !ok1 || amt0 != amt1 {
		return 0
	}
	width := uint64(outputOrInputSize(op) * 8)
	if amt0 >= width {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_AND, left.Input(0), data.NewConstant(outputOrInputSize(op), lowMask(width-amt0)))
	return 1
}

type RuleShiftCompare struct{ batchRule }

func NewRuleShiftCompare(group string) *RuleShiftCompare {
	r := &RuleShiftCompare{}
	r.batchRule = newBatchRule(group, "shiftcompare", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleShiftCompare(g) })
	return r
}

func (r *RuleShiftCompare) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		shift := op.Input(slot).Def()
		if shift == nil {
			continue
		}
		switch shift.Code() {
		case CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			if !isZeroConst(shift.Input(1)) {
				continue
			}
			replaceInputSlot(data, op, slot, shift.Input(0))
			return 1
		}
	}
	return 0
}

type RuleLessOne struct{ batchRule }

func NewRuleLessOne(group string) *RuleLessOne {
	r := &RuleLessOne{}
	r.batchRule = newBatchRule(group, "lessone", []OpCode{CPUI_INT_LESS}, r.apply, func(g string) Rule { return NewRuleLessOne(g) })
	return r
}

func (r *RuleLessOne) apply(op *PcodeOp, data *Funcdata) int {
	if !isOneConst(op.Input(1)) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_EQUAL, op.Input(0), data.NewConstant(op.Input(0).Size(), 0))
	return 1
}

type RuleLessEqual struct{ batchRule }

func NewRuleLessEqual(group string) *RuleLessEqual {
	r := &RuleLessEqual{}
	// C++ parity: RuleLessEqual fires on CPUI_BOOL_OR (ruleaction.cc:2256).
	// Pattern: BOOL_OR(INT_SLESS(a,b), INT_EQUAL(a,b)) -> INT_SLESSEQUAL(a,b)
	//          BOOL_OR(INT_LESS(a,b),  INT_EQUAL(a,b)) -> INT_LESSEQUAL(a,b)
	r.batchRule = newBatchRule(group, "lessequal", []OpCode{CPUI_BOOL_OR}, r.apply, func(g string) Rule { return NewRuleLessEqual(g) })
	return r
}

func (r *RuleLessEqual) apply(op *PcodeOp, data *Funcdata) int {
	vnout1 := op.Input(0)
	vnout2 := op.Input(1)
	if vnout1 == nil || vnout2 == nil {
		return 0
	}
	opLess := vnout1.Def()
	if opLess == nil {
		return 0
	}
	opc := opLess.Code()
	var opEqual *PcodeOp
	if opc != CPUI_INT_LESS && opc != CPUI_INT_SLESS {
		// Try swapping: maybe vnout2 is the less op.
		opEqual = opLess
		opLess = vnout2.Def()
		if opLess == nil {
			return 0
		}
		opc = opLess.Code()
		if opc != CPUI_INT_LESS && opc != CPUI_INT_SLESS {
			return 0
		}
	} else {
		opEqual = vnout2.Def()
	}
	if opEqual == nil {
		return 0
	}
	equalOpc := opEqual.Code()
	if equalOpc != CPUI_INT_EQUAL && equalOpc != CPUI_INT_NOTEQUAL {
		return 0
	}
	compvn1 := opLess.Input(0)
	compvn2 := opLess.Input(1)
	if compvn1 == nil || compvn2 == nil {
		return 0
	}
	eq0 := opEqual.Input(0)
	eq1 := opEqual.Input(1)
	if eq0 == nil || eq1 == nil {
		return 0
	}
	// Verify the equal op uses the same two operands (in either order).
	// C++ parity: ruleaction.cc:2291-2294
	match := (sameValue(compvn1, eq0) && sameValue(compvn2, eq1)) ||
		(sameValue(compvn1, eq1) && sameValue(compvn2, eq0))
	if !match {
		return 0
	}
	if equalOpc == CPUI_INT_NOTEQUAL {
		// BOOL_OR(less, notequal): notequal alone subsumes less.
		// Rewrite to COPY(notequal_out). C++ parity: ruleaction.cc:2296-2299.
		rewriteToCopy(data, op, opEqual.Output())
	} else {
		// Convert BOOL_OR -> INT_SLESSEQUAL or INT_LESSEQUAL.
		var newOpc OpCode
		if opc == CPUI_INT_SLESS {
			newOpc = CPUI_INT_SLESSEQUAL
		} else {
			newOpc = CPUI_INT_LESSEQUAL
		}
		rewriteOp(data, op, newOpc, compvn1, compvn2)
	}
	return 1
}

// RuleSLessEqual2Constant normalizes INT_SLESSEQUAL(x, C) -> INT_SLESS(x, C+1)
// when C+1 does not overflow the varnode size. This avoids the <= operator in
// C output and matches Ghidra's preference for strict-less comparisons.
// C++ parity: Ghidra normalizes SLESSEQUAL-with-constant during type/rule passes
// so that PrintC always emits < rather than <= for constant RHS comparisons.
type RuleSLessEqual2Constant struct{ batchRule }

func NewRuleSLessEqual2Constant(group string) *RuleSLessEqual2Constant {
	r := &RuleSLessEqual2Constant{}
	r.batchRule = newBatchRule(group, "slessequal2const", []OpCode{CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleSLessEqual2Constant(g) })
	return r
}

func (r *RuleSLessEqual2Constant) apply(op *PcodeOp, data *Funcdata) int {
	rhs := op.Input(1)
	if rhs == nil || !rhs.IsConstant() {
		return 0
	}
	c := rhs.Offset()
	sz := rhs.Size()
	// Max signed value for this size: (1 << (sz*8-1)) - 1.
	// If c equals the max signed value, C+1 would overflow (signed).
	maxSigned := uint64((1 << (uint(sz)*8 - 1)) - 1)
	if c == maxSigned {
		return 0
	}
	newConst := data.NewConstant(sz, c+1)
	data.OpUnsetInput(op, 1)
	data.OpSetInput(op, newConst, 1)
	data.OpSetOpcode(op, CPUI_INT_SLESS)
	return 1
}

type RuleLessNotEqual struct{ batchRule }

func NewRuleLessNotEqual(group string) *RuleLessNotEqual {
	r := &RuleLessNotEqual{}
	r.batchRule = newBatchRule(group, "lessnotequal", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleLessNotEqual(g) })
	return r
}

func (r *RuleLessNotEqual) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		flag, ok := boolConst(op.Input(1 - slot))
		if !ok || !isBoolLike(op.Input(slot)) {
			continue
		}
		switch {
		case op.Code() == CPUI_INT_NOTEQUAL && !flag:
			return rewriteToCopy(data, op, op.Input(slot))
		case op.Code() == CPUI_INT_EQUAL && flag:
			return rewriteToCopy(data, op, op.Input(slot))
		case op.Code() == CPUI_INT_NOTEQUAL && flag:
			rewriteOp(data, op, CPUI_BOOL_NEGATE, op.Input(slot))
			return 1
		case op.Code() == CPUI_INT_EQUAL && !flag:
			rewriteOp(data, op, CPUI_BOOL_NEGATE, op.Input(slot))
			return 1
		}
	}
	return 0
}

type RuleThreeWayCompare struct{ batchRule }

func NewRuleThreeWayCompare(group string) *RuleThreeWayCompare {
	r := &RuleThreeWayCompare{}
	r.batchRule = newBatchRule(group, "threewaycomp", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleThreeWayCompare(g) })
	return r
}

func (r *RuleThreeWayCompare) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		left, right, ok := detectThreeWayInputs(op.Input(slot))
		c, cOK := constantValue(op.Input(1 - slot))
		if !ok || !cOK {
			continue
		}
		size := op.Input(slot).Size()
		switch truncateToSize(c, size) {
		case 0:
			if op.Code() == CPUI_INT_EQUAL {
				rewriteOp(data, op, CPUI_INT_EQUAL, left, right)
				return 1
			}
			if op.Code() == CPUI_INT_NOTEQUAL {
				rewriteOp(data, op, CPUI_INT_NOTEQUAL, left, right)
				return 1
			}
		case maskForSize(size):
			if op.Code() == CPUI_INT_EQUAL {
				rewriteOp(data, op, CPUI_INT_LESS, left, right)
				return 1
			}
		case 1:
			if op.Code() == CPUI_INT_EQUAL {
				rewriteOp(data, op, CPUI_INT_LESS, right, left)
				return 1
			}
		}
	}
	return 0
}

type RuleXorSwap struct{ batchRule }

func NewRuleXorSwap(group string) *RuleXorSwap {
	r := &RuleXorSwap{}
	r.batchRule = newBatchRule(group, "xorswap", []OpCode{CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleXorSwap(g) })
	return r
}

func (r *RuleXorSwap) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		xorop := definedBy(op.Input(slot), CPUI_INT_XOR)
		if xorop == nil {
			continue
		}
		other := op.Input(1 - slot)
		if sameValue(xorop.Input(0), other) {
			return rewriteToCopy(data, op, xorop.Input(1))
		}
		if sameValue(xorop.Input(1), other) {
			return rewriteToCopy(data, op, xorop.Input(0))
		}
	}
	return 0
}

type RuleLzcountShiftBool struct{ batchRule }

func NewRuleLzcountShiftBool(group string) *RuleLzcountShiftBool {
	r := &RuleLzcountShiftBool{}
	r.batchRule = newBatchRule(group, "lzcountshiftbool", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleLzcountShiftBool(g) })
	return r
}

func (r *RuleLzcountShiftBool) apply(op *PcodeOp, data *Funcdata) int {
	if outputSize(op) != 1 {
		return 0
	}
	lzc := definedBy(op.Input(0), CPUI_LZCOUNT)
	if lzc == nil || lzc.NumInput() != 1 {
		return 0
	}
	amt, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	width := uint64(lzc.Input(0).Size() * 8)
	if width == 0 || width&(width-1) != 0 {
		return 0
	}
	if amt != uint64(bits.TrailingZeros64(width)) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_EQUAL, lzc.Input(0), data.NewConstant(lzc.Input(0).Size(), 0))
	return 1
}

type RuleOrCompare struct{ batchRule }

func NewRuleOrCompare(group string) *RuleOrCompare {
	r := &RuleOrCompare{}
	r.batchRule = newBatchRule(group, "orcompare", []OpCode{CPUI_BOOL_OR}, r.apply, func(g string) Rule { return NewRuleOrCompare(g) })
	return r
}

func (r *RuleOrCompare) apply(op *PcodeOp, data *Funcdata) int {
	left := op.Input(0).Def()
	right := op.Input(1).Def()
	if left == nil || right == nil {
		return 0
	}
	if left.Code() == CPUI_INT_LESS && right.Code() == CPUI_INT_EQUAL && sameCompareOperands(left, right) {
		rewriteOp(data, op, CPUI_INT_LESSEQUAL, left.Input(0), left.Input(1))
		return 1
	}
	if right.Code() == CPUI_INT_LESS && left.Code() == CPUI_INT_EQUAL && sameCompareOperands(left, right) {
		rewriteOp(data, op, CPUI_INT_LESSEQUAL, right.Input(0), right.Input(1))
		return 1
	}
	return 0
}

type RuleConditionalMove struct{ batchRule }

func NewRuleConditionalMove(group string) *RuleConditionalMove {
	r := &RuleConditionalMove{}
	r.batchRule = newBatchRule(group, "conditionalmove", []OpCode{CPUI_MULTIEQUAL}, r.apply, func(g string) Rule { return NewRuleConditionalMove(g) })
	return r
}

func (r *RuleConditionalMove) apply(op *PcodeOp, data *Funcdata) int {
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

type RuleFuncPtrEncoding struct{ batchRule }

func NewRuleFuncPtrEncoding(group string) *RuleFuncPtrEncoding {
	r := &RuleFuncPtrEncoding{}
	r.batchRule = newBatchRule(group, "funcptrencoding", []OpCode{CPUI_CALLIND}, r.apply, func(g string) Rule { return NewRuleFuncPtrEncoding(g) })
	return r
}

func (r *RuleFuncPtrEncoding) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 1 {
		return 0
	}
	base := op.Input(0)
	for {
		def := base.Def()
		if def == nil || def.NumInput() == 0 {
			break
		}
		switch def.Code() {
		case CPUI_INT_XOR, CPUI_INT_ADD, CPUI_PTRADD:
			if def.NumInput() >= 2 && isZeroConst(def.Input(1)) {
				base = def.Input(0)
				continue
			}
		}
		break
	}
	if base == op.Input(0) {
		return 0
	}
	replaceInputSlot(data, op, 0, base)
	return 1
}

type RulePullsubMulti struct{ batchRule }

func NewRulePullsubMulti(group string) *RulePullsubMulti {
	r := &RulePullsubMulti{}
	r.batchRule = newBatchRule(group, "pullsub_multi", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRulePullsubMulti(g) })
	return r
}

func (r *RulePullsubMulti) apply(op *PcodeOp, data *Funcdata) int {
	phi := definedBy(op.Input(0), CPUI_MULTIEQUAL)
	if phi == nil || phi.NumInput() == 0 {
		return 0
	}
	base := phi.Input(0)
	for i := 1; i < phi.NumInput(); i++ {
		if !sameValue(base, phi.Input(i)) {
			return 0
		}
	}
	replaceInputSlot(data, op, 0, base)
	return 1
}

type RulePullsubIndirect struct{ batchRule }

func NewRulePullsubIndirect(group string) *RulePullsubIndirect {
	r := &RulePullsubIndirect{}
	r.batchRule = newBatchRule(group, "pullsub_indirect", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRulePullsubIndirect(g) })
	return r
}

func (r *RulePullsubIndirect) apply(op *PcodeOp, data *Funcdata) int {
	ind := definedBy(op.Input(0), CPUI_INDIRECT)
	if ind == nil || ind.NumInput() == 0 {
		return 0
	}
	replaceInputSlot(data, op, 0, ind.Input(0))
	return 1
}

type RulePushMulti struct{ batchRule }

func NewRulePushMulti(group string) *RulePushMulti {
	r := &RulePushMulti{}
	r.batchRule = newBatchRule(group, "push_multi", []OpCode{CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRulePushMulti(g) })
	return r
}

func (r *RulePushMulti) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < op.NumInput(); slot++ {
		phi := definedBy(op.Input(slot), CPUI_MULTIEQUAL)
		if phi == nil || phi.NumInput() == 0 {
			continue
		}
		base := phi.Input(0)
		for i := 1; i < phi.NumInput(); i++ {
			if !sameValue(base, phi.Input(i)) {
				base = nil
				break
			}
		}
		if base == nil {
			continue
		}
		replaceInputSlot(data, op, slot, base)
		return 1
	}
	return 0
}

type RulePushPtr struct{ batchRule }

func NewRulePushPtr(group string) *RulePushPtr {
	r := &RulePushPtr{}
	r.batchRule = newBatchRule(group, "pushptr", []OpCode{CPUI_PTRADD, CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePushPtr(g) })
	return r
}

func (r *RulePushPtr) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 2 || !isZeroConst(op.Input(1)) {
		return 0
	}
	return rewriteToCopy(data, op, op.Input(0))
}

type RuleShiftPiece struct{ batchRule }

func NewRuleShiftPiece(group string) *RuleShiftPiece {
	r := &RuleShiftPiece{}
	r.batchRule = newBatchRule(group, "shiftpiece", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleShiftPiece(g) })
	return r
}

func (r *RuleShiftPiece) apply(op *PcodeOp, data *Funcdata) int {
	if op.Code() != CPUI_INT_RIGHT {
		return 0
	}
	piece := definedBy(op.Input(0), CPUI_PIECE)
	if piece == nil {
		return 0
	}
	amt, ok := constantValue(op.Input(1))
	if !ok || amt != uint64(piece.Input(1).Size()*8) || outputSize(op) != piece.Input(0).Size() {
		return 0
	}
	return rewriteToCopy(data, op, piece.Input(0))
}

type RuleConcatLeftShift struct{ batchRule }

func NewRuleConcatLeftShift(group string) *RuleConcatLeftShift {
	r := &RuleConcatLeftShift{}
	r.batchRule = newBatchRule(group, "concatleftshift", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatLeftShift(g) })
	return r
}

func (r *RuleConcatLeftShift) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(0)) {
		return 0
	}
	shift := definedBy(op.Input(1), CPUI_INT_LEFT)
	if shift == nil || shift.NumInput() != 2 {
		return 0
	}
	amt, ok := constantValue(shift.Input(1))
	if !ok {
		return 0
	}
	zext := newAuxUnaryOp(data, op.Addr(), CPUI_INT_ZEXT, outputSize(op), shift.Input(0))
	rewriteOp(data, op, CPUI_INT_LEFT, zext.Output(), data.NewConstant(outputSize(op), amt))
	return 1
}

type RuleShiftSub struct{ batchRule }

func NewRuleShiftSub(group string) *RuleShiftSub {
	r := &RuleShiftSub{}
	r.batchRule = newBatchRule(group, "shiftsub", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleShiftSub(g) })
	return r
}

func (r *RuleShiftSub) apply(op *PcodeOp, data *Funcdata) int {
	shift := definedBy(op.Input(0), CPUI_INT_RIGHT)
	if shift == nil || shift.NumInput() != 2 {
		return 0
	}
	shiftAmt, shiftOK := constantValue(shift.Input(1))
	subAmt, subOK := constantValue(op.Input(1))
	if !shiftOK || !subOK || shiftAmt%8 != 0 {
		return 0
	}
	byteOff := shiftAmt/8 + subAmt
	if byteOff+uint64(outputSize(op)) > uint64(shift.Input(0).Size()) {
		return 0
	}
	replaceInputSlot(data, op, 0, shift.Input(0))
	replaceInputSlot(data, op, 1, data.NewConstant(op.Input(1).Size(), byteOff))
	return 1
}

func combineNestedShift(op *PcodeOp, data *Funcdata, opcode OpCode) int {
	inner := definedBy(op.Input(0), opcode)
	if inner == nil || inner.NumInput() != 2 {
		return 0
	}
	amt0, ok0 := constantValue(inner.Input(1))
	amt1, ok1 := constantValue(op.Input(1))
	if !ok0 || !ok1 {
		return 0
	}
	width := uint64(outputOrInputSize(op) * 8)
	total := amt0 + amt1
	if total >= width {
		return 0
	}
	rewriteOp(data, op, opcode, inner.Input(0), data.NewConstant(op.Input(1).Size(), total))
	return 1
}

func replaceInputSlot(data *Funcdata, op *PcodeOp, slot int, vn *Varnode) {
	data.OpUnsetInput(op, slot)
	data.OpSetInput(op, vn, slot)
}

func sameCompareOperands(left *PcodeOp, right *PcodeOp) bool {
	if left == nil || right == nil || left.NumInput() != 2 || right.NumInput() != 2 {
		return false
	}
	return sameValue(left.Input(0), right.Input(0)) && sameValue(left.Input(1), right.Input(1))
}

func isSingleBitMask(val uint64) bool {
	return val != 0 && bits.OnesCount64(val) == 1
}

func detectThreeWayInputs(vn *Varnode) (*Varnode, *Varnode, bool) {
	sub := definedBy(vn, CPUI_INT_SUB)
	if sub == nil || sub.NumInput() != 2 {
		return nil, nil, false
	}
	za := definedBy(sub.Input(0), CPUI_INT_ZEXT)
	zb := definedBy(sub.Input(1), CPUI_INT_ZEXT)
	if za == nil || zb == nil {
		return nil, nil, false
	}
	ab := definedBy(za.Input(0), CPUI_INT_LESS)
	ba := definedBy(zb.Input(0), CPUI_INT_LESS)
	if ab == nil || ba == nil || ab.NumInput() != 2 || ba.NumInput() != 2 {
		return nil, nil, false
	}
	if !sameValue(ab.Input(0), ba.Input(1)) || !sameValue(ab.Input(1), ba.Input(0)) {
		return nil, nil, false
	}
	return ab.Input(0), ab.Input(1), true
}

// RulePushMultiME fires on 2-input MULTIEQUAL ops where both inputs are
// computed by functionally equivalent operations. It merges the computations
// into the MULTIEQUAL's block and eliminates one of them.
// COPY special case: uses findSubstituteForME to find an existing MULTIEQUAL
// that already merges the differing inputs.
// C++ parity: ruleaction.cc RulePushMulti::applyOp (lines 1074-1137)
type RulePushMultiME struct{ batchRule }

func NewRulePushMultiME(group string) *RulePushMultiME {
	r := &RulePushMultiME{}
	r.batchRule = newBatchRule(group, "push_multi_me", []OpCode{CPUI_MULTIEQUAL}, r.apply, func(g string) Rule { return NewRulePushMultiME(g) })
	return r
}

// findSubstituteForME searches for an existing MULTIEQUAL op in bl with inputs
// in1 and in2 (in order). If not found, tries via functionalEqualityLevel.
// C++ parity: ruleaction.cc RulePushMulti::findSubstitute (lines 1031-1059)
func findSubstituteForME(in1, in2 *Varnode, bl *BlockBasic, earliest *PcodeOp, fd *Funcdata) *PcodeOp {
	// Direct search: MULTIEQUAL in bl with in[0]==in1 and in[1]==in2.
	for _, op := range in1.DescendIter() {
		if op.Parent() != bl {
			continue
		}
		if op.Code() != CPUI_MULTIEQUAL {
			continue
		}
		if op.NumInput() < 2 {
			continue
		}
		if op.Input(0) != in1 {
			continue
		}
		if op.Input(1) != in2 {
			continue
		}
		return op
	}
	if in1 == in2 {
		return nil
	}
	var buf1, buf2 [2]*Varnode
	if functionalEqualityLevel(in1, in2, buf1[:], buf2[:]) != 0 {
		return nil
	}
	if !in1.IsWritten() {
		return nil
	}
	op1 := in1.Def()
	for i := 0; i < op1.NumInput(); i++ {
		vn := op1.Input(i)
		if vn.IsConstant() {
			continue
		}
		if in2.IsWritten() && vn == in2.Def().Input(i) {
			return fd.CseFindInBlock(op1, vn, bl, earliest)
		}
	}
	return nil
}

func (r *RulePushMultiME) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	in1 := op.Input(0)
	in2 := op.Input(1)
	if !in1.IsWritten() || !in2.IsWritten() {
		return 0
	}
	if in1.IsSpacebasePlaceholder() || in2.IsSpacebasePlaceholder() {
		return 0
	}

	var buf1, buf2 [2]*Varnode
	res := functionalEqualityLevel(in1, in2, buf1[:], buf2[:])
	if res < 0 || res > 1 {
		fmt.Printf("PUSHME skip: res=%d in1=%v in2=%v\n", res, in1, in2)
		return 0
	}
	op1 := in1.Def()
	if op1.Code() == CPUI_SUBPIECE {
		return 0
	}

	bl := op.Parent()
	earliest := bl.EarliestUse(op.Output())

	if op1.Code() == CPUI_COPY {
		if res == 0 {
			return 0
		}
		substitute := findSubstituteForME(buf1[0], buf2[0], bl, earliest, data)
		if substitute == nil {
			fmt.Printf("PUSHME COPY skip: no substitute in1=%v in2=%v buf1=%v buf2=%v\n", in1, in2, buf1[0], buf2[0])
			return 0
		}
		data.TotalReplace(op.Output(), substitute.Output())
		data.OpDestroy(op)
		return 1
	}

	op2 := in2.Def()
	if in1.LoneDescend() != op {
		fmt.Printf("PUSHME skip: in1 not lone descend, in1=%v op1=%v numDesc=%d\n", in1, op1.Code(), in1.NumDescend())
		for _, d := range in1.DescendIter() {
			fmt.Printf("  in1 desc: %v parent=%v\n", d.Code(), d.Parent())
		}
		return 0
	}
	if in2.LoneDescend() != op {
		fmt.Printf("PUSHME skip: in2 not lone descend, in2=%v op2=%v numDesc=%d\n", in2, op2.Code(), in2.NumDescend())
		for _, d := range in2.DescendIter() {
			fmt.Printf("  in2 desc: %v parent=%v\n", d.Code(), d.Parent())
		}
		return 0
	}
	fmt.Printf("PUSHME applying: op=%v in1=%v in2=%v res=%d buf1=%v buf2=%v\n", op.Code(), in1, in2, res, buf1[0], buf2[0])

	outvn := op.Output()
	data.OpSetOutput(op1, outvn)
	data.OpUninsert(op1)

	if res == 1 {
		slot1 := op1.GetSlot(buf1[0])
		substitute := findSubstituteForME(buf1[0], buf2[0], bl, earliest, data)
		if substitute == nil {
			substitute = data.NewOp(2, op.Addr())
			data.OpSetOpcode(substitute, CPUI_MULTIEQUAL)
			if buf1[0].Addr() == buf2[0].Addr() && !buf1[0].IsAddrTied() {
				data.NewVarnodeOut(buf1[0].Size(), buf1[0].Addr(), substitute)
			} else {
				data.NewUniqueOut(buf1[0].Size(), substitute)
			}
			data.OpSetInput(substitute, buf1[0], 0)
			data.OpSetInput(substitute, buf2[0], 1)
			data.OpInsertBegin(substitute, bl)
		}
		data.OpSetInput(op1, substitute.Output(), slot1)
		data.OpInsertAfter(op1, substitute)
	} else {
		data.OpInsertBegin(op1, bl)
	}

	data.OpDestroy(op)
	data.OpDestroy(op2)
	return 1
}

// RuleDumptyHumpLate::applyOp -- subflow.cc.
type RuleDumptyHumpLate struct{ batchRule }

// NewRuleDumptyHumpLate is the Go port of RuleDumptyHumpLate::RuleDumptyHumpLate in subflow.cc.
func NewRuleDumptyHumpLate(group string) *RuleDumptyHumpLate {
	r := &RuleDumptyHumpLate{}
	r.batchRule = newBatchRule(group, "dumptyhumplate", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleDumptyHumpLate(g) })
	return r
}

// RuleDumptyHumpLate::applyOp -- subflow.cc.
func (r *RuleDumptyHumpLate) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	if vn == nil || !vn.IsWritten() {
		return 0
	}
	pieceOp := vn.Def()
	if pieceOp == nil || pieceOp.Code() != CPUI_PIECE {
		return 0
	}
	out := op.Output()
	if out == nil {
		return 0
	}
	outSize := out.Size()
	trunc, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	for {
		trialVn := pieceOp.Input(1)
		trialTrunc := trunc
		if trunc >= uint64(trialVn.Size()) {
			trialTrunc -= uint64(trialVn.Size())
			trialVn = pieceOp.Input(0)
		}
		if uint64(outSize)+trialTrunc > uint64(trialVn.Size()) {
			return 0
		}
		vn = trialVn
		trunc = trialTrunc
		if vn.Size() == outSize {
			break
		}
		if !vn.IsWritten() {
			break
		}
		pieceOp = vn.Def()
		if pieceOp == nil || pieceOp.Code() != CPUI_PIECE {
			break
		}
	}
	if vn == op.Input(0) {
		return 0
	}
	if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_COPY {
		vn = vn.Def().Input(0)
	}
	var removeOp *PcodeOp
	if outSize != vn.Size() {
		removeOp = op.Input(0).Def()
		if op.Input(1).Offset() != trunc {
			data.OpSetInput(op, data.NewConstant(4, trunc), 1)
		}
		data.OpSetInput(op, vn, 0)
	} else if out.IsAutoLive() {
		removeOp = op.Input(0).Def()
		data.OpRemoveInput(op, 1)
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpSetInput(op, vn, 0)
	} else {
		removeOp = op
		data.TotalReplace(out, vn)
	}
	if removeOp != nil && removeOp.Output() != nil && removeOp.Output().HasNoDescend() && !removeOp.Output().IsAutoLive() {
		data.OpDestroyRecursive(removeOp)
	}
	return 1
}

type batchCMiscRuleFactory func(string) Rule

var batchCMiscRuleFactories = []batchCMiscRuleFactory{
	func(group string) Rule { return NewRuleSwitchSingle(group) },
	func(group string) Rule { return NewRuleTransformCPool(group) },
	func(group string) Rule { return NewRuleSegment(group) },
	func(group string) Rule { return NewRulePiecePathology(group) },
	func(group string) Rule { return NewRuleExpandLoad(group) },
	func(group string) Rule { return NewRuleNotDistribute(group) },
	func(group string) Rule { return NewRuleHighOrderAnd(group) },
	func(group string) Rule { return NewRuleAndDistribute(group) },
	func(group string) Rule { return NewRuleAndCompare(group) },
	func(group string) Rule { return NewRuleDoubleSub(group) },
	func(group string) Rule { return NewRuleDoubleShift(group) },
	func(group string) Rule { return NewRuleDoubleArithShift(group) },
	func(group string) Rule { return NewRuleConcatShift(group) },
	func(group string) Rule { return NewRuleLeftRight(group) },
	func(group string) Rule { return NewRuleShiftCompare(group) },
	func(group string) Rule { return NewRuleLessOne(group) },
	func(group string) Rule { return NewRuleLessEqual(group) },
	func(group string) Rule { return NewRuleLessNotEqual(group) },
	func(group string) Rule { return NewRuleThreeWayCompare(group) },
	func(group string) Rule { return NewRuleXorSwap(group) },
	func(group string) Rule { return NewRuleLzcountShiftBool(group) },
	func(group string) Rule { return NewRuleOrCompare(group) },
	func(group string) Rule { return NewRuleConditionalMove(group) },
	func(group string) Rule { return NewRuleFuncPtrEncoding(group) },
	func(group string) Rule { return NewRulePullsubMulti(group) },
	func(group string) Rule { return NewRulePullsubIndirect(group) },
	func(group string) Rule { return NewRulePushMulti(group) },
	func(group string) Rule { return NewRulePushPtr(group) },
	func(group string) Rule { return NewRuleShiftPiece(group) },
	func(group string) Rule { return NewRuleConcatLeftShift(group) },
	func(group string) Rule { return NewRuleShiftSub(group) },
}

func BatchCMiscRules(group string) []Rule {
	rules := make([]Rule, 0, len(batchCMiscRuleFactories))
	for _, factory := range batchCMiscRuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchCMiscRules(pool *ActionPool, group string) int {
	if pool == nil {
		return 0
	}
	rules := BatchCMiscRules(group)
	for _, rule := range rules {
		pool.AddRule(rule)
	}
	return len(rules)
}

// RuleSubvarAnd::applyOp -- subflow.cc.
type RuleSubvarAnd struct{ batchRule }

// NewRuleSubvarAnd is the Go port of RuleSubvarAnd::RuleSubvarAnd in subflow.cc.
func NewRuleSubvarAnd(group string) *RuleSubvarAnd {
	r := &RuleSubvarAnd{}
	r.batchRule = newBatchRule(group, "subvar_and", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleSubvarAnd(g) })
	return r
}

// RuleSubvarAnd::getOpList -- subflow.cc.
func (r *RuleSubvarAnd) getOpList() []OpCode {
	return []OpCode{CPUI_INT_AND}
}

// RuleSubvarAnd::applyOp -- subflow.cc.
func (r *RuleSubvarAnd) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil || !op.Input(1).IsConstant() {
		return 0
	}
	vn := op.Input(0)
	outvn := op.Output()
	if outvn.Consumed() != op.Input(1).Offset() {
		return 0
	}
	if (outvn.Consumed() & 1) == 0 {
		return 0
	}
	var cmask uint64
	if outvn.Consumed() == 1 {
		cmask = 1
	} else {
		cmask = maskForSize(vn.Size()) >> 8
		for cmask != 0 {
			if cmask == outvn.Consumed() {
				break
			}
			cmask >>= 8
		}
	}
	if cmask == 0 || outvn.HasNoDescend() {
		return 0
	}
	subflow := NewSubvariableFlow(data, vn, cmask, false, false, false)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarSubpiece::applyOp -- subflow.cc.
type RuleSubvarSubpiece struct{ batchRule }

// NewRuleSubvarSubpiece is the Go port of RuleSubvarSubpiece::RuleSubvarSubpiece in subflow.cc.
func NewRuleSubvarSubpiece(group string) *RuleSubvarSubpiece {
	r := &RuleSubvarSubpiece{}
	r.batchRule = newBatchRule(group, "subvar_subpiece", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubvarSubpiece(g) })
	return r
}

// RuleSubvarSubpiece::getOpList -- subflow.cc.
func (r *RuleSubvarSubpiece) getOpList() []OpCode {
	return []OpCode{CPUI_SUBPIECE}
}

// RuleSubvarSubpiece::applyOp -- subflow.cc.
func (r *RuleSubvarSubpiece) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	vn := op.Input(0)
	outvn := op.Output()
	flowsize := outvn.Size()
	sa := int32(op.Input(1).Offset())
	if flowsize+sa > 8 {
		return 0
	}
	mask := maskForSize(flowsize) << uint(8*sa)
	aggressive := outvn.HasPtrFlow()
	if !aggressive {
		if (vn.Consumed() & mask) != vn.Consumed() {
			return 0
		}
		if outvn.HasNoDescend() {
			return 0
		}
	}
	big := false
	if flowsize >= 8 && vn.IsInput() && vn.LoneDescend() == op {
		big = true
	}
	subflow := NewSubvariableFlow(data, vn, mask, aggressive, false, big)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarCompZero::applyOp -- subflow.cc.
type RuleSubvarCompZero struct{ batchRule }

// NewRuleSubvarCompZero is the Go port of RuleSubvarCompZero::RuleSubvarCompZero in subflow.cc.
func NewRuleSubvarCompZero(group string) *RuleSubvarCompZero {
	r := &RuleSubvarCompZero{}
	r.batchRule = newBatchRule(group, "subvar_compzero", []OpCode{CPUI_INT_NOTEQUAL, CPUI_INT_EQUAL}, r.apply, func(g string) Rule { return NewRuleSubvarCompZero(g) })
	return r
}

// RuleSubvarCompZero::getOpList -- subflow.cc.
func (r *RuleSubvarCompZero) getOpList() []OpCode {
	return []OpCode{CPUI_INT_NOTEQUAL, CPUI_INT_EQUAL}
}

// RuleSubvarCompZero::applyOp -- subflow.cc.
func (r *RuleSubvarCompZero) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil || !op.Input(1).IsConstant() {
		return 0
	}
	vn := op.Input(0)
	mask := vn.NZMask()
	bitnum := bits.TrailingZeros64(mask)
	if mask == 0 || (mask>>uint(bitnum)) != 1 {
		return 0
	}
	if op.Input(1).Offset() != mask && op.Input(1).Offset() != 0 {
		return 0
	}
	if op.Output().HasNoDescend() {
		return 0
	}
	if vn.IsWritten() && vn.Def() != nil {
		andop := vn.Def()
		if andop.NumInput() == 0 {
			return 0
		}
		vn0 := andop.Input(0)
		switch andop.Code() {
		case CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_RIGHT:
			if vn0.IsConstant() {
				return 0
			}
			mask0 := vn0.Consumed() & vn0.NZMask()
			wholemask := maskForSize(vn0.Size()) & mask0
			if (wholemask&0xff) == 0xff || (wholemask&0xff00) == 0xff00 {
				return 0
			}
		}
	}
	subflow := NewSubvariableFlow(data, vn, mask, false, false, false)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarShift::applyOp -- subflow.cc.
type RuleSubvarShift struct{ batchRule }

// NewRuleSubvarShift is the Go port of RuleSubvarShift::RuleSubvarShift in subflow.cc.
func NewRuleSubvarShift(group string) *RuleSubvarShift {
	r := &RuleSubvarShift{}
	r.batchRule = newBatchRule(group, "subvar_shift", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleSubvarShift(g) })
	return r
}

// RuleSubvarShift::getOpList -- subflow.cc.
func (r *RuleSubvarShift) getOpList() []OpCode {
	return []OpCode{CPUI_INT_RIGHT}
}

// RuleSubvarShift::applyOp -- subflow.cc.
func (r *RuleSubvarShift) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil || op.Input(0).Size() != 1 || !op.Input(1).IsConstant() {
		return 0
	}
	vn := op.Input(0)
	sa := int32(op.Input(1).Offset())
	mask := vn.NZMask()
	if (mask >> uint(sa)) != 1 {
		return 0
	}
	mask = (mask >> uint(sa)) << uint(sa)
	if op.Output().HasNoDescend() {
		return 0
	}
	subflow := NewSubvariableFlow(data, vn, mask, false, false, false)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarZext::applyOp -- subflow.cc.
type RuleSubvarZext struct{ batchRule }

// NewRuleSubvarZext is the Go port of RuleSubvarZext::RuleSubvarZext in subflow.cc.
func NewRuleSubvarZext(group string) *RuleSubvarZext {
	r := &RuleSubvarZext{}
	r.batchRule = newBatchRule(group, "subvar_zext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleSubvarZext(g) })
	return r
}

// RuleSubvarZext::getOpList -- subflow.cc.
func (r *RuleSubvarZext) getOpList() []OpCode {
	return []OpCode{CPUI_INT_ZEXT}
}

// RuleSubvarZext::applyOp -- subflow.cc.
func (r *RuleSubvarZext) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	vn := op.Output()
	invn := op.Input(0)
	mask := maskForSize(invn.Size())
	subflow := NewSubvariableFlow(data, vn, mask, invn.HasPtrFlow(), false, false)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarSext::applyOp -- subflow.cc.
type RuleSubvarSext struct {
	batchRule
	isaggressive bool
}

// NewRuleSubvarSext is the Go port of RuleSubvarSext::RuleSubvarSext in subflow.cc.
func NewRuleSubvarSext(group string) *RuleSubvarSext {
	r := &RuleSubvarSext{}
	r.batchRule = newBatchRule(group, "subvar_sext", []OpCode{CPUI_INT_SEXT}, r.apply, func(g string) Rule { return NewRuleSubvarSext(g) })
	return r
}

// RuleSubvarSext::getOpList -- subflow.cc.
func (r *RuleSubvarSext) getOpList() []OpCode {
	return []OpCode{CPUI_INT_SEXT}
}

// RuleSubvarSext::applyOp -- subflow.cc.
func (r *RuleSubvarSext) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	vn := op.Output()
	invn := op.Input(0)
	mask := maskForSize(invn.Size())
	subflow := NewSubvariableFlow(data, vn, mask, r.isaggressive, true, false)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.DoReplacement()
	return 1
}

// RuleSubvarSext::reset -- subflow.cc.
func (r *RuleSubvarSext) Reset(data *Funcdata) {
	// TODO known mismatch: the architecture-level aggressive_ext_trim flag is not yet
	// surfaced in Gosleigh, so this stays conservative.
	_ = data
	r.isaggressive = false
}

// RuleSplitFlow::applyOp -- subflow.cc.
type RuleSplitFlow struct{ batchRule }

// NewRuleSplitFlow is the Go port of RuleSplitFlow::RuleSplitFlow in subflow.cc.
func NewRuleSplitFlow(group string) *RuleSplitFlow {
	r := &RuleSplitFlow{}
	r.batchRule = newBatchRule(group, "splitflow", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSplitFlow(g) })
	return r
}

// RuleSplitFlow::applyOp -- subflow.cc.
func (r *RuleSplitFlow) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil || op.Input(1) == nil || !op.Input(1).IsConstant() {
		return 0
	}
	loSize := int32(op.Input(1).Offset())
	if loSize == 0 {
		return 0
	}
	vn := op.Input(0)
	if vn == nil || !vn.IsWritten() || vn.IsPrecisLo() || vn.IsPrecisHi() {
		return 0
	}
	if op.Output().Size()+loSize != vn.Size() {
		return 0
	}
	multiOp := vn.Def()
	if multiOp == nil {
		return 0
	}
	for multiOp.Code() == CPUI_INDIRECT {
		tmpvn := multiOp.Input(0)
		if tmpvn == nil || !tmpvn.IsWritten() {
			return 0
		}
		multiOp = tmpvn.Def()
		if multiOp == nil {
			return 0
		}
	}
	var concatOp *PcodeOp
	switch multiOp.Code() {
	case CPUI_PIECE:
		if vn.Def() != multiOp {
			concatOp = multiOp
		}
	case CPUI_MULTIEQUAL:
		for i := 0; i < multiOp.NumInput(); i++ {
			invn := multiOp.Input(i)
			if invn == nil || !invn.IsWritten() {
				continue
			}
			tmpOp := invn.Def()
			if tmpOp != nil && tmpOp.Code() == CPUI_PIECE {
				concatOp = tmpOp
				break
			}
		}
	}
	if concatOp == nil || concatOp.Input(1) == nil || concatOp.Input(1).Size() != loSize {
		return 0
	}
	splitFlow := NewSplitFlow(data, vn, loSize)
	if !splitFlow.DoTrace() {
		return 0
	}
	splitFlow.Apply()
	return 1
}

// RuleSplitCopy::applyOp -- subflow.cc.
type RuleSplitCopy struct{ batchRule }

// NewRuleSplitCopy is the Go port of RuleSplitCopy::RuleSplitCopy in subflow.cc.
func NewRuleSplitCopy(group string) *RuleSplitCopy {
	r := &RuleSplitCopy{}
	r.batchRule = newBatchRule(group, "splitcopy", []OpCode{CPUI_COPY}, r.apply, func(g string) Rule { return NewRuleSplitCopy(g) })
	return r
}

// RuleSplitCopy::applyOp -- subflow.cc.
func (r *RuleSplitCopy) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil || op.NumInput() == 0 {
		return 0
	}
	inType := op.Input(0).TypeReadFacing(op)
	outType := op.Output().TypeDefFacing()
	if inType == nil || outType == nil {
		return 0
	}
	if inType.Metatype() != TYPE_STRUCT && inType.Metatype() != TYPE_ARRAY && inType.Metatype() != TYPE_PARTIALSTRUCT &&
		outType.Metatype() != TYPE_STRUCT && outType.Metatype() != TYPE_ARRAY && outType.Metatype() != TYPE_PARTIALSTRUCT {
		return 0
	}
	splitter := NewSplitDatatype(data)
	if splitter.splitCopy(op, inType, outType) {
		return 1
	}
	return 0
}

// RuleSplitLoad::applyOp -- subflow.cc.
type RuleSplitLoad struct{ batchRule }

// NewRuleSplitLoad is the Go port of RuleSplitLoad::RuleSplitLoad in subflow.cc.
func NewRuleSplitLoad(group string) *RuleSplitLoad {
	r := &RuleSplitLoad{}
	r.batchRule = newBatchRule(group, "splitload", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleSplitLoad(g) })
	return r
}

// RuleSplitLoad::applyOp -- subflow.cc.
func (r *RuleSplitLoad) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	splitter := NewSplitDatatype(data)
	inType := splitter.getValueDatatype(op, op.Output().Size(), splitter.types)
	if inType == nil {
		return 0
	}
	if inType.Metatype() != TYPE_STRUCT && inType.Metatype() != TYPE_ARRAY && inType.Metatype() != TYPE_PARTIALSTRUCT {
		return 0
	}
	if splitter.splitLoad(op, inType) {
		return 1
	}
	return 0
}

// RuleSplitStore::applyOp -- subflow.cc.
type RuleSplitStore struct{ batchRule }

// NewRuleSplitStore is the Go port of RuleSplitStore::RuleSplitStore in subflow.cc.
func NewRuleSplitStore(group string) *RuleSplitStore {
	r := &RuleSplitStore{}
	r.batchRule = newBatchRule(group, "splitstore", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleSplitStore(g) })
	return r
}

// RuleSplitStore::applyOp -- subflow.cc.
func (r *RuleSplitStore) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 3 {
		return 0
	}
	splitter := NewSplitDatatype(data)
	outType := splitter.getValueDatatype(op, op.Input(2).Size(), splitter.types)
	if outType == nil {
		return 0
	}
	if outType.Metatype() != TYPE_STRUCT && outType.Metatype() != TYPE_ARRAY && outType.Metatype() != TYPE_PARTIALSTRUCT {
		return 0
	}
	if splitter.splitStore(op, outType) {
		return 1
	}
	return 0
}

// RuleSubfloatConvert::applyOp -- subflow.cc.
type RuleSubfloatConvert struct{ batchRule }

// NewRuleSubfloatConvert is the Go port of RuleSubfloatConvert::RuleSubfloatConvert in subflow.cc.
func NewRuleSubfloatConvert(group string) *RuleSubfloatConvert {
	r := &RuleSubfloatConvert{}
	r.batchRule = newBatchRule(group, "subfloat_convert", []OpCode{CPUI_FLOAT_FLOAT2FLOAT}, r.apply, func(g string) Rule {
		return NewRuleSubfloatConvert(g)
	})
	return r
}

// RuleSubfloatConvert::getOpList -- subflow.cc.
func (r *RuleSubfloatConvert) getOpList() []OpCode {
	return []OpCode{CPUI_FLOAT_FLOAT2FLOAT}
}

// RuleSubfloatConvert::applyOp -- subflow.cc.
func (r *RuleSubfloatConvert) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() != 1 || op.Output() == nil || op.Input(0) == nil {
		return 0
	}
	invn := op.Input(0)
	outvn := op.Output()
	insize := invn.Size()
	outsize := outvn.Size()
	if outsize > insize {
		subflow := NewSubfloatFlow(data, outvn, insize)
		if !subflow.DoTrace() {
			return 0
		}
		subflow.Apply()
		return 1
	}
	subflow := NewSubfloatFlow(data, invn, outsize)
	if !subflow.DoTrace() {
		return 0
	}
	subflow.Apply()
	return 1
}

// BitField rules -- real ports of RuleBitFieldStore/Load/Out/In, RulePullAbsorb
// and RuleInsertAbsorb. The rule-level dispatch follows the C++ control flow
// verbatim (see ghidra-ref/.../bitfield.cc lines 1655-2390). Each rule bails
// out at Datatype.HasBitfields() == false today, because the Go type model
// has no TypeBitField struct-member support yet; the constructors and dispatch
// are real so flipping HasBitfields() on in the type model will light them up.
// See TODO(bitfield-typemodel) in datatype.go.
// ----------------------------------------------------------------------------

// RuleBitFieldStore collapses a bitfield insertion terminating in a CPUI_STORE.
// C++ parity: class RuleBitFieldStore in bitfield.hh.
type RuleBitFieldStore struct{ batchRule }

// NewRuleBitFieldStore constructs the bitfield_store rule.
// C++ parity: RuleBitFieldStore::RuleBitFieldStore.
func NewRuleBitFieldStore(group string) *RuleBitFieldStore {
	r := &RuleBitFieldStore{}
	r.batchRule = newBatchRule(group, "bitfield_store", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleBitFieldStore(g) })
	return r
}

// apply mirrors RuleBitFieldStore::applyOp (bitfield.cc 1661).
func (r *RuleBitFieldStore) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 3 {
		return 0
	}
	ptrVn := op.Input(1)
	if ptrVn == nil {
		return 0
	}
	// C++: Datatype *ptr = op->getIn(1)->getTypeReadFacing(op);
	// Go equivalent pulls the inferred temp-type for the input.
	ptrType := ptrVn.GetTempType()
	dt, off := GetPtrInto(ptrType)
	if dt == nil {
		return 0
	}
	if !dt.HasBitfields() {
		return 0
	}
	vn := op.Input(2)
	if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_INSERT {
		return 0
	}
	transform := NewBitFieldInsertTransform(data, op, dt, off)
	if !transform.DoTrace() {
		return 0
	}
	transform.Apply()
	return 1
}

// RuleBitFieldOut collapses a bitfield insertion ending in a write to a mapped Varnode.
// C++ parity: class RuleBitFieldOut in bitfield.hh.
type RuleBitFieldOut struct{ batchRule }

// NewRuleBitFieldOut constructs the bitfield_out rule.
// C++ parity: RuleBitFieldOut::RuleBitFieldOut.
func NewRuleBitFieldOut(group string) *RuleBitFieldOut {
	r := &RuleBitFieldOut{}
	ops := []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD,
		CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT,
		CPUI_BOOL_NEGATE, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL,
		CPUI_FLOAT_NAN, CPUI_INDIRECT, CPUI_SUBPIECE,
	}
	r.batchRule = newBatchRule(group, "bitfield_out", ops, r.apply, func(g string) Rule { return NewRuleBitFieldOut(g) })
	return r
}

// apply mirrors RuleBitFieldOut::applyOp (bitfield.cc 1690).
func (r *RuleBitFieldOut) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	// C++: Datatype *dt = outvn->getTypeDefFacing();
	dt := outvn.GetTempType()
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	transform := NewBitFieldInsertTransform(data, op, dt, 0)
	if !transform.DoTrace() {
		return 0
	}
	transform.Apply()
	return 1
}

// RuleBitFieldLoad collapses a bitfield pull rooted at a CPUI_LOAD.
// C++ parity: class RuleBitFieldLoad in bitfield.hh.
type RuleBitFieldLoad struct{ batchRule }

// NewRuleBitFieldLoad constructs the bitfield_load rule.
// C++ parity: RuleBitFieldLoad::RuleBitFieldLoad.
func NewRuleBitFieldLoad(group string) *RuleBitFieldLoad {
	r := &RuleBitFieldLoad{}
	r.batchRule = newBatchRule(group, "bitfield_load", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleBitFieldLoad(g) })
	return r
}

// apply mirrors RuleBitFieldLoad::applyOp (bitfield.cc 1709).
func (r *RuleBitFieldLoad) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 2 {
		return 0
	}
	ptrVn := op.Input(1)
	if ptrVn == nil {
		return 0
	}
	ptrType := ptrVn.GetTempType()
	dt, off := GetPtrInto(ptrType)
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	// C++: if (op->notPrinted()) return 0;
	// TODO(bitfield-typemodel): no NotPrinted() yet; under the current
	// runtime LOAD visitation flags are not tracked, so we always proceed.
	out := op.Output()
	if out == nil {
		return 0
	}
	transform := NewBitFieldPullTransform(data, out, dt, off)
	if !transform.DoTrace() {
		return 0
	}
	transform.Apply()
	return 1
}

// RuleBitFieldIn collapses a bitfield pull rooted at a mapped Varnode read.
// C++ parity: class RuleBitFieldIn in bitfield.hh.
type RuleBitFieldIn struct{ batchRule }

// NewRuleBitFieldIn constructs the bitfield_in rule.
// C++ parity: RuleBitFieldIn::RuleBitFieldIn.
func NewRuleBitFieldIn(group string) *RuleBitFieldIn {
	r := &RuleBitFieldIn{}
	ops := []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT,
		CPUI_INT_ADD, CPUI_INT_NEGATE,
		CPUI_INT_AND, CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT,
		CPUI_SUBPIECE,
	}
	r.batchRule = newBatchRule(group, "bitfield_in", ops, r.apply, func(g string) Rule { return NewRuleBitFieldIn(g) })
	return r
}

// apply mirrors RuleBitFieldIn::applyOp (bitfield.cc 1737).
func (r *RuleBitFieldIn) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 1 {
		return 0
	}
	invn := op.Input(0)
	if invn == nil {
		return 0
	}
	dt := invn.GetTempType()
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	transform := NewBitFieldPullTransform(data, invn, dt, 0)
	if !transform.DoTrace() {
		return 0
	}
	transform.Apply()
	return 1
}

// RulePullAbsorb simplifies expressions explicitly using ZPULL and SPULL.
// C++ parity: class RulePullAbsorb in bitfield.hh.
type RulePullAbsorb struct{ batchRule }

// NewRulePullAbsorb constructs the pull_absorb rule.
// C++ parity: RulePullAbsorb::RulePullAbsorb.
func NewRulePullAbsorb(group string) *RulePullAbsorb {
	r := &RulePullAbsorb{}
	r.batchRule = newBatchRule(group, "pull_absorb", []OpCode{CPUI_ZPULL, CPUI_SPULL}, r.apply, func(g string) Rule { return NewRulePullAbsorb(g) })
	return r
}

// apply mirrors RulePullAbsorb::applyOp (bitfield.cc 2157) -- walks every
// descendant of the ZPULL/SPULL output and dispatches on the read op code.
func (r *RulePullAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		res := 0
		switch readOp.Code() {
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			res = r.absorbRight(data, readOp, op)
		case CPUI_INT_LEFT:
			res = r.absorbLeft(data, readOp, op)
		case CPUI_INT_AND:
			res = r.absorbAnd(data, readOp, op)
		case CPUI_INT_SLESS, CPUI_INT_LESS:
			res = r.absorbCompare(data, readOp, nil, op)
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			res = r.absorbExt(data, readOp, op)
		case CPUI_SUBPIECE:
			res = r.absorbSubpiece(data, readOp, op)
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			res = r.absorbCompZero(data, readOp, op)
		}
		if res != 0 {
			return res
		}
	}
	return 0
}

// absorbRight mirrors bitfield.cc RulePullAbsorb::absorbRight (1756).
// TODO(bitfield-runtime): needs Funcdata.DestroyVarnodeRecursive and
// Funcdata.OpInsertInput; returns 0 until those primitives land.
func (r *RulePullAbsorb) absorbRight(data *Funcdata, rightOp, pullOp *PcodeOp) int {
	_ = data
	_ = rightOp
	_ = pullOp
	return 0
}

// absorbLeft mirrors bitfield.cc RulePullAbsorb::absorbLeft (1819).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbLeft(data *Funcdata, leftOp, pullOp *PcodeOp) int {
	_ = data
	_ = leftOp
	_ = pullOp
	return 0
}

// absorbAnd mirrors bitfield.cc RulePullAbsorb::absorbAnd (1928).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbAnd(data *Funcdata, andOp, pullOp *PcodeOp) int {
	_ = data
	_ = andOp
	_ = pullOp
	return 0
}

// absorbCompare mirrors bitfield.cc RulePullAbsorb::absorbCompare (1979).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbCompare(data *Funcdata, compOp, leftOp, pullOp *PcodeOp) int {
	_ = data
	_ = compOp
	_ = leftOp
	_ = pullOp
	return 0
}

// absorbExt mirrors bitfield.cc RulePullAbsorb::absorbExt (2059).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbExt(data *Funcdata, extOp, pullOp *PcodeOp) int {
	_ = data
	_ = extOp
	_ = pullOp
	return 0
}

// absorbSubpiece mirrors bitfield.cc RulePullAbsorb::absorbSubpiece (2083).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbSubpiece(data *Funcdata, subOp, pullOp *PcodeOp) int {
	_ = data
	_ = subOp
	_ = pullOp
	return 0
}

// absorbCompZero mirrors bitfield.cc RulePullAbsorb::absorbCompZero (2109).
// TODO(bitfield-runtime): see absorbRight.
func (r *RulePullAbsorb) absorbCompZero(data *Funcdata, compOp, pullOp *PcodeOp) int {
	_ = data
	_ = compOp
	_ = pullOp
	return 0
}

// RuleInsertAbsorb simplifies expressions explicitly using CPUI_INSERT.
// C++ parity: class RuleInsertAbsorb in bitfield.hh.
type RuleInsertAbsorb struct{ batchRule }

// NewRuleInsertAbsorb constructs the insert_absorb rule.
// C++ parity: RuleInsertAbsorb::RuleInsertAbsorb.
func NewRuleInsertAbsorb(group string) *RuleInsertAbsorb {
	r := &RuleInsertAbsorb{}
	r.batchRule = newBatchRule(group, "insert_absorb", []OpCode{CPUI_INSERT}, r.apply, func(g string) Rule { return NewRuleInsertAbsorb(g) })
	return r
}

// apply mirrors RuleInsertAbsorb::applyOp (bitfield.cc 2352) -- dispatches on
// the op defining the INSERT value slot.
func (r *RuleInsertAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 4 {
		return 0
	}
	inVn := op.Input(1)
	if inVn == nil || !inVn.IsWritten() {
		return 0
	}
	inOp := inVn.Def()
	if inOp == nil {
		return 0
	}
	switch inOp.Code() {
	case CPUI_SUBPIECE:
		// INSERT( SUB(x,0), ... )  =>  INSERT( x, ... )
		// TODO(bitfield-runtime): needs Funcdata.DestroyVarnodeRecursive to
		// clean up the old SUBPIECE output; skipped until that lands.
		return 0
	case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		if inOp.NumInput() < 2 || !inOp.Input(1).IsConstant() {
			return 0
		}
		shiftedVn := inOp.Input(0)
		if !shiftedVn.IsWritten() {
			return 0
		}
		nextOp := shiftedVn.Def()
		if nextOp == nil {
			return 0
		}
		switch nextOp.Code() {
		case CPUI_INT_ADD:
			return r.absorbShiftAdd(data, inOp, nextOp, op)
		case CPUI_INT_LEFT, CPUI_SUBPIECE:
			return r.absorbRightLeft(data, nextOp, inOp, op)
		}
		return 0
	case CPUI_INT_AND:
		return r.absorbAnd(data, inOp, op)
	case CPUI_INT_ADD, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_MULT:
		return r.absorbNestedAnd(data, inOp, op)
	}
	return 0
}

// absorbAnd mirrors bitfield.cc RuleInsertAbsorb::absorbAnd (2230).
// TODO(bitfield-runtime): needs Funcdata.DestroyVarnodeRecursive.
func (r *RuleInsertAbsorb) absorbAnd(data *Funcdata, andOp, insertOp *PcodeOp) int {
	if andOp.NumInput() < 2 {
		return 0
	}
	cvn := andOp.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return 0
	}
	val := cvn.Offset()
	mask := insertExpressionLSBMask(insertOp)
	if (mask & val) != mask {
		return 0
	}
	// Real rewrite requires destroying andOp's output recursively once the
	// INSERT input is re-pointed; leaving the mutation to the follow-up port.
	_ = data
	return 0
}

// absorbRightLeft mirrors bitfield.cc RuleInsertAbsorb::absorbRightLeft (2246).
// TODO(bitfield-runtime): see absorbAnd.
func (r *RuleInsertAbsorb) absorbRightLeft(data *Funcdata, nextOp, rightOp, insertOp *PcodeOp) int {
	_ = data
	_ = nextOp
	_ = rightOp
	_ = insertOp
	return 0
}

// absorbShiftAdd mirrors bitfield.cc RuleInsertAbsorb::absorbShiftAdd (2284).
// TODO(bitfield-runtime): see absorbAnd.
func (r *RuleInsertAbsorb) absorbShiftAdd(data *Funcdata, rightOp, addOp, insertOp *PcodeOp) int {
	_ = data
	_ = rightOp
	_ = addOp
	_ = insertOp
	return 0
}

// absorbNestedAnd mirrors bitfield.cc RuleInsertAbsorb::absorbNestedAnd (2322).
// TODO(bitfield-runtime): see absorbAnd.
func (r *RuleInsertAbsorb) absorbNestedAnd(data *Funcdata, baseOp, insertOp *PcodeOp) int {
	_ = data
	_ = baseOp
	_ = insertOp
	return 0
}


// isDoublePrecisionArithOp classifies opcodes that the C++ decompiler treats
// as "acting on a logical whole" for the purpose of double-precision marking.
// C++ parity: TypeOp::isArithmeticOp / TypeOp::isFloatingPointOp checks in
// RuleDoubleIn::attemptMarking and RuleDoubleOut::attemptMarking.
func isDoublePrecisionArithOp(opc OpCode) bool {
	switch opc {
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_MULT, CPUI_INT_DIV, CPUI_INT_REM,
		CPUI_INT_SDIV, CPUI_INT_SREM,
		CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR,
		CPUI_INT_NEGATE, CPUI_INT_2COMP,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT,
		CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
		CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW,
		CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV,
		CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL,
		CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL,
		CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT,
		CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
		CPUI_FLOAT_NAN:
		return true
	}
	return false
}

// RuleDoubleIn matches a CPUI_SUBPIECE that extracts the least-significant
// half of a logical whole and tries to collapse associated double-precision
// ops into a single operation on the whole.
//
// C++ parity: class RuleDoubleIn in double.hh / double.cc:3198-3279.
type RuleDoubleIn struct{ batchRule }

// C++ parity: RuleDoubleIn::RuleDoubleIn
func NewRuleDoubleIn(group string) *RuleDoubleIn {
	r := &RuleDoubleIn{}
	r.batchRule = newBatchRule(group, "doublein", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleDoubleIn(g) })
	return r
}

// C++ parity: RuleDoubleIn::attemptMarking (double.cc:3218)
func (r *RuleDoubleIn) attemptMarking(vn *Varnode, subpieceOp *PcodeOp) int {
	whole := subpieceOp.Input(0)
	if whole == nil {
		return 0
	}
	// TODO(parity): skip when whole is type-locked to a non-primitive type
	// (Varnode::isTypeLock + Datatype::isPrimitiveWhole). Not yet plumbed.
	offset, ok := constantValue(subpieceOp.Input(1))
	if !ok {
		return 0
	}
	if int32(offset) != vn.Size() {
		return 0
	}
	if int32(offset)*2 != whole.Size() {
		return 0
	}
	if whole.IsInput() {
		if !whole.IsTypeLock() {
			return 0
		}
	} else if !whole.IsWritten() {
		return 0
	} else {
		if !isDoublePrecisionArithOp(whole.Def().Code()) {
			return 0
		}
	}
	var vnLo *Varnode
	for _, op := range whole.DescendIter() {
		if op.Code() != CPUI_SUBPIECE {
			continue
		}
		loff, ok := constantValue(op.Input(1))
		if !ok || loff != 0 {
			continue
		}
		if op.Output() != nil && op.Output().Size() == vn.Size() {
			vnLo = op.Output()
			break
		}
	}
	if vnLo == nil {
		return 0
	}
	vnLo.SetPrecisLo()
	vn.SetPrecisHi()
	return 1
}

// C++ parity: RuleDoubleIn::applyOp (double.cc:3259)
func (r *RuleDoubleIn) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	if !outvn.IsPrecisLo() {
		if outvn.IsPrecisHi() {
			return 0
		}
		return r.attemptMarking(outvn, op)
	}
	// The pieces are already marked: enumerate the split pairs off the whole
	// and try each double-precision form. applyRuleIn is currently a stub
	// until the Form classes are ported.
	var splitvec []SplitVarnode
	SplitVarnodeWholeList(op.Input(0), &splitvec)
	for i := range splitvec {
		if res := SplitVarnodeApplyRuleIn(&splitvec[i], data); res != 0 {
			return res
		}
	}
	return 0
}

// RuleDoubleOut matches a CPUI_PIECE whose two inputs are persistent input
// Varnodes forming a contiguous logical whole, and attempts to collapse them
// into a single input Varnode.
//
// C++ parity: class RuleDoubleOut in double.hh / double.cc:3281-3355.
type RuleDoubleOut struct{ batchRule }

// C++ parity: RuleDoubleOut::RuleDoubleOut
func NewRuleDoubleOut(group string) *RuleDoubleOut {
	r := &RuleDoubleOut{}
	r.batchRule = newBatchRule(group, "doubleout", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleDoubleOut(g) })
	return r
}

// C++ parity: RuleDoubleOut::attemptMarking (double.cc:3295)
func (r *RuleDoubleOut) attemptMarking(vnhi, vnlo *Varnode, pieceOp *PcodeOp) int {
	whole := pieceOp.Output()
	if whole == nil {
		return 0
	}
	// TODO(parity): skip non-primitive type-locked wholes.
	if vnhi.Size() != vnlo.Size() {
		return 0
	}
	// TODO(parity): symbol-entry compatibility check (double.cc:3306-3313).
	isWhole := false
	for _, use := range whole.DescendIter() {
		if isDoublePrecisionArithOp(use.Code()) {
			isWhole = true
			break
		}
	}
	if !isWhole {
		return 0
	}
	vnhi.SetPrecisHi()
	vnlo.SetPrecisLo()
	return 1
}

// C++ parity: RuleDoubleOut::applyOp (double.cc:3332)
func (r *RuleDoubleOut) apply(op *PcodeOp, data *Funcdata) int {
	vnhi := op.Input(0)
	vnlo := op.Input(1)
	if vnhi == nil || vnlo == nil {
		return 0
	}
	// The C++ rule only targets inputs-read-by-PIECE right now.
	if !vnhi.IsInput() || !vnlo.IsInput() {
		return 0
	}
	if !vnhi.IsPersist() || !vnlo.IsPersist() {
		return 0
	}
	if !vnhi.IsPrecisHi() || !vnlo.IsPrecisLo() {
		return r.attemptMarking(vnhi, vnlo, op)
	}
	// TODO(parity): Funcdata::combineInputVarnodes merges two adjacent input
	// Varnodes into a single one spanning both. Not yet implemented in
	// Gosleigh, so the final collapse is deferred.
	if _, ok := SplitVarnodeIsAddrTiedContiguous(vnlo, vnhi); !ok {
		return 0
	}
	_ = data
	return 0
}

// RuleDoubleLoad collapses two contiguous CPUI_LOADs that feed a CPUI_PIECE
// into a single wider load.
//
// C++ parity: class RuleDoubleLoad in double.hh / double.cc:3370-3505.
type RuleDoubleLoad struct{ batchRule }

// C++ parity: RuleDoubleLoad::RuleDoubleLoad
func NewRuleDoubleLoad(group string) *RuleDoubleLoad {
	r := &RuleDoubleLoad{}
	r.batchRule = newBatchRule(group, "doubleload", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleDoubleLoad(g) })
	return r
}

// doubleLoadNoWriteConflict ports RuleDoubleLoad::noWriteConflict. It scans
// the ops between op1 and op2 (within the same basic block) to make sure
// nothing writes the load/store space in between. When successful the later
// of the two ops is returned so callers can insert after it. Indirects whose
// affector is op1 or op2 are accumulated when the caller cares.
//
// C++ parity: double.cc:3370-3434. The affector-walk uses
// PcodeOp::getOpFromConst on the second input of an INDIRECT, which isn't
// plumbed in Gosleigh yet, so the indirect-range extension is skipped.
// TODO(parity): Funcdata::newVarnodeIop and PcodeOp::getOpFromConst.
func doubleLoadNoWriteConflict(op1, op2 *PcodeOp, spc *address.Space, indirects *[]*PcodeOp) *PcodeOp {
	bb := op1.Parent()
	if bb != op2.Parent() {
		return nil
	}
	if op2.Seq().Order < op1.Seq().Order {
		op1, op2 = op2, op1
	}
	for _, curop := range bb.Ops() {
		if curop.Seq().Order <= op1.Seq().Order {
			continue
		}
		if curop.Seq().Order >= op2.Seq().Order {
			break
		}
		switch curop.Code() {
		case CPUI_STORE:
			if curop.Input(0).GetSpaceFromConst() == spc {
				return nil
			}
		case CPUI_INDIRECT:
			// We cannot resolve affector from const iop yet, so we treat
			// every INDIRECT as potentially conflicting unless its output
			// lives in a different space.
			out := curop.Output()
			if out != nil && out.Space() == spc {
				return nil
			}
		case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER,
			CPUI_RETURN, CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND:
			return nil
		default:
			out := curop.Output()
			if out != nil && out.Space() == spc {
				return nil
			}
		}
		_ = indirects
	}
	return op2
}

// C++ parity: RuleDoubleLoad::applyOp (double.cc:3442)
func (r *RuleDoubleLoad) apply(op *PcodeOp, data *Funcdata) int {
	piece0 := op.Input(0)
	piece1 := op.Input(1)
	if piece0 == nil || piece1 == nil {
		return 0
	}
	if !piece0.IsWritten() || !piece1.IsWritten() {
		return 0
	}
	load1 := piece1.Def()
	if load1.Code() != CPUI_LOAD {
		return 0
	}
	load0 := piece0.Def()
	opc := load0.Code()
	offset := uint64(0)
	if opc == CPUI_SUBPIECE {
		loff, ok := constantValue(load0.Input(1))
		if !ok || loff != 0 {
			return 0
		}
		vn0 := load0.Input(0)
		if !vn0.IsWritten() {
			return 0
		}
		offset = uint64(vn0.Size() - piece0.Size())
		load0 = vn0.Def()
		opc = load0.Code()
	}
	if opc != CPUI_LOAD {
		return 0
	}
	loadlo, loadhi, spc, ok := SplitVarnodeTestContiguousPointers(load0, load1)
	if !ok {
		return 0
	}
	size := piece0.Size() + piece1.Size()
	latest := doubleLoadNoWriteConflict(loadlo, loadhi, spc, nil)
	if latest == nil {
		return 0
	}
	// Build a single wider LOAD.
	newload := data.NewOp(2, latest.Addr())
	vnout := data.NewUniqueOut(size, newload)
	spcvn := data.NewSpaceIDConst(spc)
	data.OpSetOpcode(newload, CPUI_LOAD)
	data.OpSetInput(newload, spcvn, 0)
	addrvn := loadlo.Input(1)
	if spc.BigEndian && offset != 0 {
		// The most-significant part of the big LOAD was discarded; bump the
		// pointer by the discard amount.
		newadd := data.NewOp(2, latest.Addr())
		addout := data.NewUniqueOut(addrvn.Size(), newadd)
		data.OpSetOpcode(newadd, CPUI_INT_ADD)
		data.OpSetInput(newadd, addrvn, 0)
		data.OpSetInput(newadd, data.NewConstant(addrvn.Size(), offset), 1)
		data.OpInsertAfter(newadd, latest)
		addrvn = addout
		latest = newadd
	}
	data.OpSetInput(newload, addrvn, 1)
	data.OpInsertAfter(newload, latest)

	// Convert the PIECE into a COPY of the wide load output.
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpSetInput(op, vnout, 0)
	return 1
}

// RuleDoubleStore collapses a CPUI_STORE of the low SUBPIECE plus a
// companion STORE of the high SUBPIECE into one wider store.
//
// C++ parity: class RuleDoubleStore in double.hh / double.cc:3507-3568.
type RuleDoubleStore struct{ batchRule }

// C++ parity: RuleDoubleStore::RuleDoubleStore
func NewRuleDoubleStore(group string) *RuleDoubleStore {
	r := &RuleDoubleStore{}
	r.batchRule = newBatchRule(group, "doublestore", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleDoubleStore(g) })
	return r
}

// C++ parity: RuleDoubleStore::applyOp (double.cc:3513)
func (r *RuleDoubleStore) apply(op *PcodeOp, data *Funcdata) int {
	vnlo := op.Input(2)
	if vnlo == nil || !vnlo.IsPrecisLo() {
		return 0
	}
	if !vnlo.IsWritten() {
		return 0
	}
	subpieceOpLo := vnlo.Def()
	if subpieceOpLo.Code() != CPUI_SUBPIECE {
		return 0
	}
	loff, ok := constantValue(subpieceOpLo.Input(1))
	if !ok || loff != 0 {
		return 0
	}
	whole := subpieceOpLo.Input(0)
	if whole == nil || whole.IsFree() {
		return 0
	}
	for _, subpieceOpHi := range whole.DescendIter() {
		if subpieceOpHi.Code() != CPUI_SUBPIECE {
			continue
		}
		if subpieceOpHi == subpieceOpLo {
			continue
		}
		hoff, ok := constantValue(subpieceOpHi.Input(1))
		if !ok {
			continue
		}
		if int32(hoff) != vnlo.Size() {
			continue
		}
		vnhi := subpieceOpHi.Output()
		if vnhi == nil || !vnhi.IsPrecisHi() {
			continue
		}
		if vnhi.Size() != whole.Size()-int32(hoff) {
			continue
		}
		for _, storeOp2 := range vnhi.DescendIter() {
			if storeOp2.Code() != CPUI_STORE {
				continue
			}
			if storeOp2.Input(2) != vnhi {
				continue
			}
			storelo, storehi, spc, ok := SplitVarnodeTestContiguousPointers(storeOp2, op)
			if !ok {
				continue
			}
			var indirects []*PcodeOp
			latest := doubleLoadNoWriteConflict(storelo, storehi, spc, &indirects)
			if latest == nil {
				continue
			}
			// TODO(parity): RuleDoubleStore::testIndirectUse and
			// reassignIndirects need Funcdata::newVarnodeIop. Until that is
			// ported we skip merges that carry any INDIRECTs to avoid losing
			// side-effect edges.
			if len(indirects) != 0 {
				continue
			}
			// Build the merged STORE.
			newstore := data.NewOp(3, latest.Addr())
			spcvn := data.NewSpaceIDConst(spc)
			data.OpSetOpcode(newstore, CPUI_STORE)
			data.OpSetInput(newstore, spcvn, 0)
			addrvn := storelo.Input(1)
			if addrvn.IsConstant() {
				addrvn = data.NewConstant(addrvn.Size(), addrvn.Offset())
			}
			data.OpSetInput(newstore, addrvn, 1)
			data.OpSetInput(newstore, whole, 2)
			data.OpInsertAfter(newstore, latest)
			data.OpDestroy(op)
			data.OpDestroy(storeOp2)
			return 1
		}
	}
	return 0
}

// RuleStringCopy rewrites a sequence of constant-char COPY ops into a single
// CALLOTHER representing strncpy/wcsncpy/memcpy.
// C++ parity: constseq.hh/constseq.cc class RuleStringCopy.
type RuleStringCopy struct{ batchRule }

// NewRuleStringCopy constructs the RuleStringCopy rule.
// C++ parity: RuleStringCopy::RuleStringCopy.
func NewRuleStringCopy(group string) *RuleStringCopy {
	r := &RuleStringCopy{}
	r.batchRule = newBatchRule(group, "stringcopy", []OpCode{CPUI_COPY}, r.apply, func(g string) Rule { return NewRuleStringCopy(g) })
	return r
}

// apply mirrors constseq.cc RuleStringCopy::applyOp.
// C++ parity: RuleStringCopy::applyOp.
func (r *RuleStringCopy) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || data == nil {
		return 0
	}
	if op.NumInput() == 0 || op.Input(0) == nil || !op.Input(0).IsConstant() {
		return 0
	}
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	ct := outvn.Type()
	if ct == nil || !isCharPrintLike(ct) {
		return 0
	}
	if isOpaqueStringLike(ct) {
		return 0
	}
	if !outvn.IsAddrTied() {
		return 0
	}
	// TODO: replace the stub with a real ScopeLocal.queryContainer lookup.
	entry := queryContainerStub(data, outvn.Addr(), outvn.Size())
	seq := newStringSequence(data, ct, entry, op, outvn.Addr())
	if !seq.isValid() {
		return 0
	}
	if !seq.transform() {
		return 0
	}
	return 1
}

// RuleStringStore rewrites a sequence of constant-char STORE ops into a single
// CALLOTHER representing strncpy/wcsncpy/memcpy.
// C++ parity: constseq.hh/constseq.cc class RuleStringStore.
type RuleStringStore struct{ batchRule }

// NewRuleStringStore constructs the RuleStringStore rule.
// C++ parity: RuleStringStore::RuleStringStore.
func NewRuleStringStore(group string) *RuleStringStore {
	r := &RuleStringStore{}
	r.batchRule = newBatchRule(group, "stringstore", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStringStore(g) })
	return r
}

// apply mirrors constseq.cc RuleStringStore::applyOp.
// C++ parity: RuleStringStore::applyOp.
func (r *RuleStringStore) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || data == nil {
		return 0
	}
	if op.NumInput() < 3 || op.Input(2) == nil || !op.Input(2).IsConstant() {
		return 0
	}
	ptrvn := op.Input(1)
	if ptrvn == nil {
		return 0
	}
	ct := ptrvn.TypeReadFacing(op)
	if ct == nil || ct.Metatype() != TYPE_PTR {
		return 0
	}
	ptrT, ok := ct.(*Pointer)
	if !ok {
		return 0
	}
	pointee := ptrT.Pointee()
	if pointee == nil || !isCharPrintLike(pointee) {
		return 0
	}
	if isOpaqueStringLike(pointee) {
		return 0
	}
	seq := newHeapSequence(data, pointee, op)
	if !seq.isValid() {
		return 0
	}
	if !seq.transform() {
		return 0
	}
	return 1
}
