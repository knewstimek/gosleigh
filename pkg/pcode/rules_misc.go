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
	func(group string) Rule { return NewRuleBitFieldStore(group) },
	func(group string) Rule { return NewRuleBitFieldOut(group) },
	func(group string) Rule { return NewRuleBitFieldLoad(group) },
	func(group string) Rule { return NewRuleBitFieldIn(group) },
	func(group string) Rule { return NewRulePullAbsorb(group) },
	func(group string) Rule { return NewRuleInsertAbsorb(group) },
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

// RuleBitFieldStore is the Go port of RuleBitFieldStore::RuleBitFieldStore in bitfield.cc.
type RuleBitFieldStore struct{ batchRule }

// NewRuleBitFieldStore is the Go port of RuleBitFieldStore::RuleBitFieldStore in bitfield.cc.
func NewRuleBitFieldStore(group string) *RuleBitFieldStore {
	r := &RuleBitFieldStore{}
	r.batchRule = newBatchRule(group, "bitfield_store", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule {
		return NewRuleBitFieldStore(g)
	})
	return r
}

// RuleBitFieldStore::getOpList -- bitfield.cc.
func (r *RuleBitFieldStore) getOpList() []OpCode {
	return []OpCode{CPUI_STORE}
}

// RuleBitFieldStore::applyOp -- bitfield.cc.
func (r *RuleBitFieldStore) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 3 || op.Input(1) == nil || op.Input(2) == nil {
		return 0
	}
	ptr := op.Input(1).TypeReadFacing(op)
	if ptr == nil {
		return 0
	}
	dt, off := bitfieldPtrInto(ptr, 0)
	if dt == nil || !bitfieldHasBitfields(dt) {
		return 0
	}
	_ = off
	vn := op.Input(2)
	if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_INSERT {
		return 0
	}
	// Gosleigh keeps the transform scaffold conservative until the bitfield
	// datatype metadata is wired in.
	_ = data
	return 0
}

// RuleBitFieldOut is the Go port of RuleBitFieldOut::RuleBitFieldOut in bitfield.cc.
type RuleBitFieldOut struct{ batchRule }

// NewRuleBitFieldOut is the Go port of RuleBitFieldOut::RuleBitFieldOut in bitfield.cc.
func NewRuleBitFieldOut(group string) *RuleBitFieldOut {
	r := &RuleBitFieldOut{}
	r.batchRule = newBatchRule(group, "bitfield_out", []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD,
		CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_BOOL_NEGATE,
		CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL,
		CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN, CPUI_INDIRECT, CPUI_SUBPIECE,
	}, r.apply, func(g string) Rule { return NewRuleBitFieldOut(g) })
	return r
}

// RuleBitFieldOut::getOpList -- bitfield.cc.
func (r *RuleBitFieldOut) getOpList() []OpCode {
	return []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD,
		CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR,
		CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_BOOL_NEGATE,
		CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL,
		CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN, CPUI_INDIRECT, CPUI_SUBPIECE,
	}
}

// RuleBitFieldOut::applyOp -- bitfield.cc.
func (r *RuleBitFieldOut) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	dt := op.Output().TypeDefFacing()
	if !bitfieldHasBitfields(dt) {
		return 0
	}
	_ = data
	return 0
}

// RuleBitFieldLoad is the Go port of RuleBitFieldLoad::RuleBitFieldLoad in bitfield.cc.
type RuleBitFieldLoad struct{ batchRule }

// NewRuleBitFieldLoad is the Go port of RuleBitFieldLoad::RuleBitFieldLoad in bitfield.cc.
func NewRuleBitFieldLoad(group string) *RuleBitFieldLoad {
	r := &RuleBitFieldLoad{}
	r.batchRule = newBatchRule(group, "bitfield_load", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule {
		return NewRuleBitFieldLoad(g)
	})
	return r
}

// RuleBitFieldLoad::getOpList -- bitfield.cc.
func (r *RuleBitFieldLoad) getOpList() []OpCode {
	return []OpCode{CPUI_LOAD}
}

// RuleBitFieldLoad::applyOp -- bitfield.cc.
func (r *RuleBitFieldLoad) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 2 || op.Input(1) == nil {
		return 0
	}
	ptr := op.Input(1).TypeReadFacing(op)
	if ptr == nil {
		return 0
	}
	dt, off := bitfieldPtrInto(ptr, 0)
	if dt == nil || !bitfieldHasBitfields(dt) {
		return 0
	}
	_ = off
	_ = data
	return 0
}

// RuleBitFieldIn is the Go port of RuleBitFieldIn::RuleBitFieldIn in bitfield.cc.
type RuleBitFieldIn struct{ batchRule }

// NewRuleBitFieldIn is the Go port of RuleBitFieldIn::RuleBitFieldIn in bitfield.cc.
func NewRuleBitFieldIn(group string) *RuleBitFieldIn {
	r := &RuleBitFieldIn{}
	r.batchRule = newBatchRule(group, "bitfield_in", []OpCode{CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL,
		CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT,
		CPUI_INT_SEXT, CPUI_INT_ADD, CPUI_INT_NEGATE, CPUI_INT_AND, CPUI_INT_LEFT, CPUI_INT_RIGHT,
		CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleBitFieldIn(g) })
	return r
}

// RuleBitFieldIn::getOpList -- bitfield.cc.
func (r *RuleBitFieldIn) getOpList() []OpCode {
	return []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD,
		CPUI_INT_NEGATE, CPUI_INT_AND, CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT,
		CPUI_INT_MULT, CPUI_SUBPIECE,
	}
}

// RuleBitFieldIn::applyOp -- bitfield.cc.
func (r *RuleBitFieldIn) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return 0
	}
	dt := op.Input(0).TypeReadFacing(op)
	if !bitfieldHasBitfields(dt) {
		return 0
	}
	_ = data
	return 0
}

// RulePullAbsorb is the Go port of RulePullAbsorb::RulePullAbsorb in bitfield.cc.
type RulePullAbsorb struct{ batchRule }

// NewRulePullAbsorb is the Go port of RulePullAbsorb::RulePullAbsorb in bitfield.cc.
func NewRulePullAbsorb(group string) *RulePullAbsorb {
	r := &RulePullAbsorb{}
	r.batchRule = newBatchRule(group, "pull_absorb", []OpCode{CPUI_ZPULL, CPUI_SPULL}, r.apply, func(g string) Rule {
		return NewRulePullAbsorb(g)
	})
	return r
}

// RulePullAbsorb::getOpList -- bitfield.cc.
func (r *RulePullAbsorb) getOpList() []OpCode {
	return []OpCode{CPUI_ZPULL, CPUI_SPULL}
}

// RulePullAbsorb::applyOp -- bitfield.cc.
func (r *RulePullAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	outvn := op.Output()
	destroyIfDead := func(dead *PcodeOp) {
		if dead == nil || dead.Output() == nil || !dead.Output().HasNoDescend() {
			return
		}
		data.OpDestroyRecursive(dead)
	}
	absorbExt := func(extOp *PcodeOp, pullOp *PcodeOp) int {
		if extOp == nil || pullOp == nil || extOp.NumInput() != 1 || extOp.Input(0) == nil {
			return 0
		}
		pullSigned := pullOp.Code() == CPUI_SPULL
		extSigned := extOp.Code() == CPUI_INT_SEXT
		if extSigned != pullSigned {
			return 0
		}
		vn := extOp.Input(0)
		if vn.LoneDescend() != extOp {
			return 0
		}
		extOp.SetNumInputs(3)
		data.OpSetOpcode(extOp, pullOp.Code())
		data.OpSetInput(extOp, pullOp.Input(0), 0)
		data.OpSetInput(extOp, pullOp.Input(1), 1)
		data.OpSetInput(extOp, pullOp.Input(2), 2)
		destroyIfDead(vn.Def())
		return 1
	}
	absorbSubpiece := func(subOp *PcodeOp, pullOp *PcodeOp) int {
		if subOp == nil || pullOp == nil || subOp.NumInput() < 2 || subOp.Input(1) == nil {
			return 0
		}
		if subOp.Input(1).Offset() != 0 {
			return 0
		}
		bitsize := int32(pullOp.Input(2).Offset())
		if bitsize > 8*subOp.Output().Size() {
			return 0
		}
		vn := subOp.Input(0)
		if vn.LoneDescend() != subOp {
			return 0
		}
		subOp.SetNumInputs(3)
		data.OpSetOpcode(subOp, pullOp.Code())
		data.OpSetInput(subOp, pullOp.Input(0), 0)
		data.OpSetInput(subOp, pullOp.Input(1), 1)
		data.OpSetInput(subOp, pullOp.Input(2), 2)
		destroyIfDead(vn.Def())
		return 1
	}
	absorbCompare := func(compOp *PcodeOp, leftOp *PcodeOp, pullOp *PcodeOp) int {
		if compOp == nil || pullOp == nil || compOp.NumInput() != 2 || compOp.Input(0) == nil || compOp.Input(1) == nil {
			return 0
		}
		sa := int32(0)
		if leftOp != nil {
			if leftOp.NumInput() < 2 || leftOp.Input(1) == nil || !leftOp.Input(1).IsConstant() {
				return 0
			}
			sa = int32(leftOp.Input(1).Offset())
		}
		numbits := int32(pullOp.Input(2).Offset())
		invn := pullOp.Input(0)
		if numbits+sa != invn.Size()*8 {
			return 0
		}
		inVn := pullOp.Output()
		if leftOp != nil {
			inVn = leftOp.Output()
		}
		lessVn0 := compOp.Input(0)
		lessVn1 := compOp.Input(1)
		if compOp.Code() == CPUI_INT_SLESS {
			if numbits == 1 && lessVn0 == inVn && lessVn1.IsConstant() && lessVn1.Offset() == 0 {
				rewriteToCopy(data, compOp, pullOp.Output())
				destroyIfDead(leftOp)
				return 1
			}
			if numbits == 1 && lessVn1 == inVn && lessVn0.IsConstant() && lessVn0.Offset() == maskForSize(inVn.Size()) {
				rewriteOp(data, compOp, CPUI_BOOL_NEGATE, pullOp.Output())
				destroyIfDead(leftOp)
				return 1
			}
		}
		mask := uint64(1)
		mask = (mask << uint(sa)) - 1
		if sa > 0 && sa < 64 && inVn == lessVn0 && lessVn1.IsConstant() {
			origVal := lessVn1.Offset()
			lowBits := mask & origVal
			if lowBits == 0 || lowBits == 1 {
				var newVal uint64
				if lowBits == 1 {
					newVal = (origVal - 1) >> uint(sa)
					newVal = (newVal + 1) & maskForSize(inVn.Size())
				} else {
					newVal = origVal >> uint(sa)
				}
				data.OpSetInput(compOp, pullOp.Output(), 0)
				data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 1)
				destroyIfDead(leftOp)
				return 1
			}
		}
		if sa > 0 && sa < 64 && inVn == lessVn1 && lessVn0.IsConstant() {
			origVal := lessVn0.Offset()
			lowBits := mask & origVal
			if lowBits == 0 || lowBits == mask {
				var newVal uint64
				if lowBits == mask {
					newVal = (origVal + 1) >> uint(sa)
					newVal = (newVal - 1) & maskForSize(inVn.Size())
				} else {
					newVal = origVal >> uint(sa)
				}
				data.OpSetInput(compOp, pullOp.Output(), 1)
				data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 0)
				destroyIfDead(leftOp)
				return 1
			}
		}
		return 0
	}
	absorbAnd := func(andOp *PcodeOp, pullOp *PcodeOp) int {
		if andOp == nil || pullOp == nil || andOp.NumInput() < 2 || andOp.Input(1) == nil || !andOp.Input(1).IsConstant() {
			return 0
		}
		if pullOp.Code() != CPUI_SPULL {
			return 0
		}
		bitsize := int32(pullOp.Input(2).Offset())
		if bitsize <= 0 {
			return 0
		}
		matchVal := uint64(1) << uint(bitsize-1)
		if matchVal != andOp.Input(1).Offset() {
			return 0
		}
		outvn := andOp.Output()
		if outvn == nil {
			return 0
		}
		for _, readOp := range outvn.DescendIter() {
			if readOp == nil || readOp.NumInput() < 2 || readOp.Input(1) == nil || !readOp.Input(1).IsConstant() {
				continue
			}
			switch readOp.Code() {
			case CPUI_INT_EQUAL:
				rewriteOp(data, readOp, CPUI_INT_LESSEQUAL, pullOp.Output(), data.NewConstant(pullOp.Output().Size(), 0))
				destroyIfDead(andOp)
				return 1
			case CPUI_INT_NOTEQUAL:
				rewriteOp(data, readOp, CPUI_INT_SLESS, pullOp.Output(), data.NewConstant(pullOp.Output().Size(), 0))
				destroyIfDead(andOp)
				return 1
			}
		}
		return 0
	}
	absorbRightAndCompZero := func(rightOp *PcodeOp, andOp *PcodeOp, pullOp *PcodeOp) int {
		if pullOp.Code() != CPUI_SPULL || rightOp == nil || andOp == nil {
			return 0
		}
		if rightOp.NumInput() < 2 || !rightOp.Input(1).IsConstant() || andOp.NumInput() < 2 || !andOp.Input(1).IsConstant() {
			return 0
		}
		if int32(pullOp.Input(2).Offset())-1 != int32(rightOp.Input(1).Offset()) {
			return 0
		}
		if andOp.Input(1).Offset() != 1 {
			return 0
		}
		outvn := andOp.Output()
		if outvn == nil {
			return 0
		}
		for _, readOp := range outvn.DescendIter() {
			if readOp == nil || readOp.NumInput() < 2 || readOp.Input(1) == nil || !readOp.Input(1).IsConstant() || readOp.Input(1).Offset() != 0 {
				continue
			}
			switch readOp.Code() {
			case CPUI_INT_EQUAL:
				rewriteOp(data, readOp, CPUI_INT_LESSEQUAL, pullOp.Output(), readOp.Input(1))
				destroyIfDead(andOp)
				return 1
			case CPUI_INT_NOTEQUAL:
				rewriteOp(data, readOp, CPUI_INT_SLESS, pullOp.Output(), readOp.Input(1))
				destroyIfDead(andOp)
				return 1
			}
		}
		return 0
	}
	absorbExtOrSubpiece := func(readOp *PcodeOp) int {
		switch readOp.Code() {
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			return absorbExt(readOp, op)
		case CPUI_SUBPIECE:
			return absorbSubpiece(readOp, op)
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			if readOp.NumInput() >= 2 && readOp.Input(1) != nil && readOp.Input(1).IsConstant() && readOp.Input(1).Offset() == 0 {
				if readOp.Code() == CPUI_INT_EQUAL {
					rewriteOp(data, readOp, CPUI_BOOL_NEGATE, op.Output())
				} else {
					rewriteToCopy(data, readOp, op.Output())
				}
				return 1
			}
		}
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		if readOp == nil {
			continue
		}
		switch readOp.Code() {
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			if readOp.Output() == nil || readOp.Output().LoneDescend() == nil {
				continue
			}
			if res := absorbRightAndCompZero(readOp, readOp.Output().LoneDescend(), op); res != 0 {
				return res
			}
		case CPUI_INT_LEFT:
			if readOp.Output() == nil {
				continue
			}
			for _, nextOp := range readOp.Output().DescendIter() {
				if nextOp == nil {
					continue
				}
				switch nextOp.Code() {
				case CPUI_INT_SLESS, CPUI_INT_LESS:
					if res := absorbCompare(nextOp, readOp, op); res != 0 {
						return res
					}
				case CPUI_INT_RIGHT:
					if res := absorbCompare(nextOp, readOp, op); res != 0 {
						return res
					}
				case CPUI_INT_AND:
					if res := absorbCompare(nextOp, readOp, op); res != 0 {
						return res
					}
				}
			}
		case CPUI_INT_AND:
			if res := absorbAnd(readOp, op); res != 0 {
				return res
			}
		case CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_SUBPIECE, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			if res := absorbExtOrSubpiece(readOp); res != 0 {
				return res
			}
		case CPUI_INT_SLESS, CPUI_INT_LESS:
			if res := absorbCompare(readOp, nil, op); res != 0 {
				return res
			}
		}
	}
	return 0
}

// RuleInsertAbsorb is the Go port of RuleInsertAbsorb::RuleInsertAbsorb in bitfield.cc.
type RuleInsertAbsorb struct{ batchRule }

// NewRuleInsertAbsorb is the Go port of RuleInsertAbsorb::RuleInsertAbsorb in bitfield.cc.
func NewRuleInsertAbsorb(group string) *RuleInsertAbsorb {
	r := &RuleInsertAbsorb{}
	r.batchRule = newBatchRule(group, "insert_absorb", []OpCode{CPUI_INSERT}, r.apply, func(g string) Rule {
		return NewRuleInsertAbsorb(g)
	})
	return r
}

// RuleInsertAbsorb::getOpList -- bitfield.cc.
func (r *RuleInsertAbsorb) getOpList() []OpCode {
	return []OpCode{CPUI_INSERT}
}

// RuleInsertAbsorb::applyOp -- bitfield.cc.
func (r *RuleInsertAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 2 || op.Input(1) == nil {
		return 0
	}
	leftShiftVarnode := func(vn *Varnode, sa int32) *Varnode {
		if vn == nil || !vn.IsWritten() || vn.Def() == nil || vn.Def().NumInput() < 2 || vn.Def().Input(1) == nil || !vn.Def().Input(1).IsConstant() {
			return nil
		}
		multOp := vn.Def()
		multVal := multOp.Input(1)
		var matchVal uint64
		switch multOp.Code() {
		case CPUI_INT_MULT:
			matchVal = uint64(1) << uint(sa)
		case CPUI_INT_LEFT:
			matchVal = uint64(sa)
		default:
			return nil
		}
		if multVal.Offset() != matchVal {
			return nil
		}
		return multOp.Input(0)
	}
	absorbAnd := func(andOp *PcodeOp, insertOp *PcodeOp) int {
		if andOp == nil || insertOp == nil || andOp.NumInput() < 2 || andOp.Input(1) == nil || !andOp.Input(1).IsConstant() || insertOp.NumInput() < 4 || insertOp.Input(3) == nil {
			return 0
		}
		mask := lowMask(insertOp.Input(3).Offset())
		if (mask & andOp.Input(1).Offset()) != mask {
			return 0
		}
		data.OpSetInput(insertOp, andOp.Input(0), 1)
		if andOp.Output() != nil && andOp.Output().HasNoDescend() {
			data.OpDestroyRecursive(andOp)
		}
		return 1
	}
	absorbRightLeft := func(nextOp *PcodeOp, rightOp *PcodeOp, insertOp *PcodeOp) int {
		if nextOp == nil || rightOp == nil || insertOp == nil || rightOp.NumInput() < 2 || rightOp.Input(1) == nil || !rightOp.Input(1).IsConstant() {
			return 0
		}
		var leftOp *PcodeOp
		switch nextOp.Code() {
		case CPUI_INT_LEFT:
			leftOp = nextOp
		case CPUI_SUBPIECE:
			if nextOp.NumInput() < 2 || nextOp.Input(1) == nil || nextOp.Input(1).Offset() != 0 {
				return 0
			}
			subin := nextOp.Input(0)
			if subin == nil || !subin.IsWritten() || subin.Def() == nil || subin.Def().Code() != CPUI_INT_LEFT {
				return 0
			}
			leftOp = subin.Def()
		default:
			return 0
		}
		if leftOp.NumInput() < 2 || leftOp.Input(1) == nil || !leftOp.Input(1).IsConstant() {
			return 0
		}
		lsa := int32(leftOp.Input(1).Offset())
		rsa := int32(rightOp.Input(1).Offset())
		if lsa != rsa {
			return 0
		}
		if insertOp.NumInput() < 4 || insertOp.Input(3) == nil {
			return 0
		}
		bitsize := int32(insertOp.Input(3).Offset())
		if bitsize > leftOp.Input(0).Size()*8-lsa {
			return 0
		}
		data.OpSetInput(insertOp, leftOp.Input(0), 1)
		if rightOp.Output() != nil && rightOp.Output().HasNoDescend() {
			data.OpDestroyRecursive(rightOp)
		}
		return 1
	}
	absorbShiftAdd := func(rightOp *PcodeOp, addOp *PcodeOp, insertOp *PcodeOp) int {
		if rightOp == nil || addOp == nil || insertOp == nil || rightOp.NumInput() < 2 || rightOp.Input(1) == nil || !rightOp.Input(1).IsConstant() {
			return 0
		}
		sa := int32(rightOp.Input(1).Offset())
		if sa <= 0 || sa >= 64 {
			return 0
		}
		vn0 := leftShiftVarnode(addOp.Input(0), sa)
		if vn0 == nil {
			return 0
		}
		var vn1 *Varnode
		addVn1 := addOp.Input(1)
		if addVn1 != nil && addVn1.IsConstant() {
			addVal := addVn1.Offset()
			addVal >>= uint(sa)
			if (addVal << uint(sa)) != addVn1.Offset() {
				return 0
			}
			vn1 = data.NewConstant(vn0.Size(), addVal)
			SetVarnodeType(vn1, addVn1.TypeReadFacing(addOp))
		} else {
			vn1 = leftShiftVarnode(addVn1, sa)
			if vn1 == nil {
				return 0
			}
		}
		if insertOp.NumInput() < 4 || insertOp.Input(3) == nil {
			return 0
		}
		bitsize := int32(insertOp.Input(3).Offset())
		if bitsize > vn0.Size()*8-sa {
			return 0
		}
		data.OpSetOpcode(rightOp, CPUI_INT_ADD)
		data.OpSetInput(rightOp, vn0, 0)
		data.OpSetInput(rightOp, vn1, 1)
		if addOp.Output() != nil && addOp.Output().HasNoDescend() {
			data.OpDestroyRecursive(addOp)
		}
		return 1
	}
	absorbNestedAnd := func(baseOp *PcodeOp, insertOp *PcodeOp) int {
		if baseOp == nil || insertOp == nil || baseOp.Output() == nil || baseOp.Output().LoneDescend() != insertOp || insertOp.NumInput() < 4 || insertOp.Input(3) == nil {
			return 0
		}
		for slot := 0; slot < 2; slot++ {
			vn := baseOp.Input(slot)
			if vn == nil || !vn.IsWritten() || vn.Def() == nil || vn.Def().Code() != CPUI_INT_AND || vn.Def().NumInput() < 2 || vn.Def().Input(1) == nil || !vn.Def().Input(1).IsConstant() {
				continue
			}
			mask := vn.Def().Input(1).Offset()
			cover := lowMask(uint64(bits.Len64(mask)))
			if cover != mask || (cover&1) == 0 {
				continue
			}
			count := bits.OnesCount64(mask)
			if uint64(count) < insertOp.Input(3).Offset() {
				continue
			}
			data.OpSetInput(baseOp, vn.Def().Input(0), slot)
			if vn.Def().Output() != nil && vn.Def().Output().HasNoDescend() {
				data.OpDestroyRecursive(vn.Def())
			}
			return 1
		}
		return 0
	}
	inVn := op.Input(1)
	if !inVn.IsWritten() || inVn.Def() == nil {
		return 0
	}
	inOp := inVn.Def()
	switch inOp.Code() {
	case CPUI_SUBPIECE:
		if inOp.NumInput() < 2 || inOp.Input(1) == nil || inOp.Input(1).Offset() != 0 {
			return 0
		}
		data.OpSetInput(op, inOp.Input(0), 1)
		if inOp.Output() != nil && inOp.Output().HasNoDescend() {
			data.OpDestroyRecursive(inOp)
		}
		return 1
	case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		if inOp.NumInput() < 2 || inOp.Input(1) == nil || !inOp.Input(1).IsConstant() {
			return 0
		}
		vn := inOp.Input(0)
		if vn == nil || !vn.IsWritten() || vn.Def() == nil {
			return 0
		}
		nextOp := vn.Def()
		switch nextOp.Code() {
		case CPUI_INT_ADD:
			return absorbShiftAdd(inOp, nextOp, op)
		case CPUI_INT_LEFT, CPUI_SUBPIECE:
			return absorbRightLeft(nextOp, inOp, op)
		}
	case CPUI_INT_AND:
		return absorbAnd(inOp, op)
	case CPUI_INT_ADD, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_MULT:
		return absorbNestedAnd(inOp, op)
	}
	return 0
}

// RuleDoubleIn is the Go port of RuleDoubleIn::RuleDoubleIn in double.cc.
type RuleDoubleIn struct{ batchRule }

// NewRuleDoubleIn is the Go port of RuleDoubleIn::RuleDoubleIn in double.cc.
func NewRuleDoubleIn(group string) *RuleDoubleIn {
	r := &RuleDoubleIn{}
	r.batchRule = newBatchRule(group, "doublein", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleDoubleIn(g) })
	return r
}

func (r *RuleDoubleIn) attemptMarking(vn *Varnode, subpieceOp *PcodeOp) int {
	if vn == nil || subpieceOp == nil || subpieceOp.NumInput() < 2 || subpieceOp.Input(0) == nil || subpieceOp.Input(1) == nil {
		return 0
	}
	whole := subpieceOp.Input(0)
	off := subpieceOp.Input(1).Offset()
	if off != uint64(vn.Size()) || whole.Size() != vn.Size()*2 {
		return 0
	}
	if whole.IsWritten() && whole.Def() != nil {
		switch whole.Def().Code() {
		case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_MULT,
			CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
			CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
			CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV,
			CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
		default:
			return 0
		}
	}
	for _, op := range whole.DescendIter() {
		if op == nil || op.Code() != CPUI_SUBPIECE || op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		if op.Input(1).Offset() != 0 || op.Output() == nil || op.Output().Size() != vn.Size() {
			continue
		}
		op.Output().SetPrecisLo()
		vn.SetPrecisHi()
		return 1
	}
	return 0
}

func (r *RuleDoubleIn) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.Output() == nil {
		return 0
	}
	outvn := op.Output()
	if !outvn.IsPrecisLo() && !outvn.IsPrecisHi() {
		return r.attemptMarking(outvn, op)
	}
	_ = data
	return 0
}

// RuleDoubleOut is the Go port of RuleDoubleOut::RuleDoubleOut in double.cc.
type RuleDoubleOut struct{ batchRule }

// NewRuleDoubleOut is the Go port of RuleDoubleOut::RuleDoubleOut in double.cc.
func NewRuleDoubleOut(group string) *RuleDoubleOut {
	r := &RuleDoubleOut{}
	r.batchRule = newBatchRule(group, "doubleout", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleDoubleOut(g) })
	return r
}

func (r *RuleDoubleOut) attemptMarking(vnhi *Varnode, vnlo *Varnode, pieceOp *PcodeOp) int {
	if vnhi == nil || vnlo == nil || pieceOp == nil || pieceOp.Output() == nil || vnhi.Size() != vnlo.Size() {
		return 0
	}
	whole := pieceOp.Output()
	for _, op := range whole.DescendIter() {
		if op == nil {
			continue
		}
		switch op.Code() {
		case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_MULT,
			CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
			CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
			CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV,
			CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
			vnhi.SetPrecisHi()
			vnlo.SetPrecisLo()
			return 1
		}
	}
	return 0
}

func (r *RuleDoubleOut) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 2 {
		return 0
	}
	vnhi := op.Input(0)
	vnlo := op.Input(1)
	if vnhi == nil || vnlo == nil {
		return 0
	}
	if !vnhi.IsInput() || !vnlo.IsInput() || !vnhi.IsPersist() || !vnlo.IsPersist() {
		return 0
	}
	if !vnhi.IsPrecisHi() || !vnlo.IsPrecisLo() {
		return r.attemptMarking(vnhi, vnlo, op)
	}
	_ = data
	return 0
}

// RuleDoubleLoad is the Go port of RuleDoubleLoad::RuleDoubleLoad in double.cc.
type RuleDoubleLoad struct{ batchRule }

// NewRuleDoubleLoad is the Go port of RuleDoubleLoad::RuleDoubleLoad in double.cc.
func NewRuleDoubleLoad(group string) *RuleDoubleLoad {
	r := &RuleDoubleLoad{}
	r.batchRule = newBatchRule(group, "doubleload", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleDoubleLoad(g) })
	return r
}

func (r *RuleDoubleLoad) noWriteConflict(op1 *PcodeOp, op2 *PcodeOp, spc *address.Space, indirects *[]*PcodeOp) *PcodeOp {
	_ = indirects
	if op1 == nil || op2 == nil || op1.Parent() != op2.Parent() {
		return nil
	}
	if op2.Seq().Order < op1.Seq().Order {
		op1, op2 = op2, op1
	}
	for _, curop := range op1.Parent().Ops() {
		if curop == nil || curop == op1 {
			continue
		}
		if curop.Seq().Order > op2.Seq().Order {
			break
		}
		switch curop.Code() {
		case CPUI_STORE:
			if curop.NumInput() > 0 && curop.Input(0) != nil && curop.Input(0).GetSpaceFromConst() == spc {
				return nil
			}
		case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER, CPUI_RETURN:
			return nil
		case CPUI_INDIRECT:
			if curop.Output() != nil && curop.Output().Space() == spc {
				return nil
			}
		default:
			if out := curop.Output(); out != nil && out.Space() == spc {
				return nil
			}
		}
	}
	return op2
}

func (r *RuleDoubleLoad) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 2 {
		return 0
	}
	piece0 := op.Input(0)
	piece1 := op.Input(1)
	if piece0 == nil || piece1 == nil || !piece0.IsWritten() || !piece1.IsWritten() {
		return 0
	}
	load0 := piece0.Def()
	load1 := piece1.Def()
	if load0 == nil || load1 == nil || load1.Code() != CPUI_LOAD {
		return 0
	}
	offset := 0
	if load0.Code() == CPUI_SUBPIECE {
		if load0.NumInput() < 2 || load0.Input(1) == nil || load0.Input(1).Offset() != 0 || load0.Input(0) == nil || !load0.Input(0).IsWritten() {
			return 0
		}
		offset = int(load0.Input(0).Size() - piece0.Size())
		load0 = load0.Input(0).Def()
		if load0 == nil || load0.Code() != CPUI_LOAD {
			return 0
		}
	}
	if load0.Code() != CPUI_LOAD {
		return 0
	}
	first, second, spc, ok := (&SplitVarnode{}).testContiguousPointers(load0, load1)
	if !ok || first == nil || second == nil || spc == nil {
		return 0
	}
	latest := r.noWriteConflict(first, second, spc, nil)
	if latest == nil {
		return 0
	}
	if offset != 0 && spc.BigEndian {
		return 0
	}
	newload := data.NewOp(2, latest.Addr())
	data.OpSetOpcode(newload, CPUI_LOAD)
	spcvn := data.NewConstant(4, 0)
	BindSpaceConstant(spcvn, spc)
	data.OpSetInput(newload, spcvn, 0)
	addrvn := first.Input(1)
	if offset != 0 {
		add := data.NewOp(2, latest.Addr())
		data.OpSetOpcode(add, CPUI_INT_ADD)
		data.OpSetInput(add, addrvn, 0)
		data.OpSetInput(add, data.NewConstant(addrvn.Size(), uint64(offset)), 1)
		data.OpInsertAfter(add, latest)
		addrvn = add.Output()
		latest = add
	}
	data.OpSetInput(newload, addrvn, 1)
	vnout := data.NewUniqueOut(piece0.Size()+piece1.Size(), newload)
	data.OpInsertAfter(newload, latest)
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpSetInput(op, vnout, 0)
	return 1
}

// RuleDoubleStore is the Go port of RuleDoubleStore::RuleDoubleStore in double.cc.
type RuleDoubleStore struct{ batchRule }

// NewRuleDoubleStore is the Go port of RuleDoubleStore::RuleDoubleStore in double.cc.
func NewRuleDoubleStore(group string) *RuleDoubleStore {
	r := &RuleDoubleStore{}
	r.batchRule = newBatchRule(group, "doublestore", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleDoubleStore(g) })
	return r
}

func (r *RuleDoubleStore) testIndirectUse(op1 *PcodeOp, op2 *PcodeOp, indirects []*PcodeOp) bool {
	_ = op1
	_ = op2
	_ = indirects
	return true
}

func (r *RuleDoubleStore) noWriteConflict(op1 *PcodeOp, op2 *PcodeOp, spc *address.Space, indirects *[]*PcodeOp) *PcodeOp {
	return (&RuleDoubleLoad{}).noWriteConflict(op1, op2, spc, indirects)
}

func (r *RuleDoubleStore) reassignIndirects(data *Funcdata, newStore *PcodeOp, indirects []*PcodeOp) {
	_ = data
	_ = newStore
	_ = indirects
}

func (r *RuleDoubleStore) apply(op *PcodeOp, data *Funcdata) int {
	if op == nil || op.NumInput() < 3 {
		return 0
	}
	vnlo := op.Input(2)
	if vnlo == nil || !vnlo.IsPrecisLo() || !vnlo.IsWritten() || vnlo.Def() == nil || vnlo.Def().Code() != CPUI_SUBPIECE || vnlo.Def().NumInput() < 2 || vnlo.Def().Input(1) == nil || vnlo.Def().Input(1).Offset() != 0 {
		return 0
	}
	whole := vnlo.Def().Input(0)
	if whole == nil {
		return 0
	}
	for _, subpieceOpHi := range whole.DescendIter() {
		if subpieceOpHi == nil || subpieceOpHi.Code() != CPUI_SUBPIECE || subpieceOpHi == vnlo.Def() || subpieceOpHi.NumInput() < 2 || subpieceOpHi.Input(1) == nil {
			continue
		}
		if subpieceOpHi.Input(1).Offset() != uint64(vnlo.Size()) {
			continue
		}
		vnhi := subpieceOpHi.Output()
		if vnhi == nil || !vnhi.IsPrecisHi() || vnhi.Size() != whole.Size()-int32(subpieceOpHi.Input(1).Offset()) {
			continue
		}
		for _, storeOp2 := range vnhi.DescendIter() {
			if storeOp2 == nil || storeOp2.Code() != CPUI_STORE || storeOp2.NumInput() < 3 || storeOp2.Input(2) != vnhi {
				continue
			}
			first, second, spc, ok := (&SplitVarnode{}).testContiguousPointers(storeOp2, op)
			if !ok || first == nil || second == nil || spc == nil {
				continue
			}
			latest := r.noWriteConflict(first, second, spc, nil)
			if latest == nil {
				continue
			}
			newstore := data.NewOp(3, latest.Addr())
			data.OpSetOpcode(newstore, CPUI_STORE)
			spcvn := data.NewConstant(4, 0)
			BindSpaceConstant(spcvn, spc)
			data.OpSetInput(newstore, spcvn, 0)
			addrvn := first.Input(1)
			if addrvn != nil && addrvn.IsConstant() {
				addrvn = data.NewConstant(addrvn.Size(), addrvn.Offset())
			}
			data.OpSetInput(newstore, addrvn, 1)
			data.OpSetInput(newstore, whole, 2)
			data.OpInsertAfter(newstore, latest)
			data.OpDestroy(op)
			data.OpDestroy(storeOp2)
			r.reassignIndirects(data, newstore, nil)
			return 1
		}
	}
	return 0
}
