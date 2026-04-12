package pcode

import "math/bits"

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
