package pcode

type RuleBxor2NotEqual struct{ batchRule }

func NewRuleBxor2NotEqual(group string) *RuleBxor2NotEqual {
	r := &RuleBxor2NotEqual{}
	r.batchRule = newBatchRule(group, "bxor2notequal", []OpCode{CPUI_BOOL_XOR}, r.apply, func(g string) Rule { return NewRuleBxor2NotEqual(g) })
	return r
}

func (r *RuleBxor2NotEqual) apply(op *PcodeOp, data *Funcdata) int {
	rewriteOp(data, op, CPUI_INT_NOTEQUAL, op.Input(0), op.Input(1))
	return 1
}

type RuleOrMask struct{ batchRule }

func NewRuleOrMask(group string) *RuleOrMask {
	r := &RuleOrMask{}
	r.batchRule = newBatchRule(group, "ormask", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleOrMask(g) })
	return r
}

func (r *RuleOrMask) apply(op *PcodeOp, data *Funcdata) int {
	if isAllOnesConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isAllOnesConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	return 0
}

type RuleAndMask struct{ batchRule }

func NewRuleAndMask(group string) *RuleAndMask {
	r := &RuleAndMask{}
	r.batchRule = newBatchRule(group, "andmask", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndMask(g) })
	return r
}

// apply is a faithful port of RuleAndMask::applyOp (ruleaction.cc:310), collapsing
// an unnecessary INT_AND via non-zero-bit (NZMask) and consume analysis.
//
// The all-ones algebraic shortcuts are kept ahead of the faithful path: they
// handle "all-ones & X => X" in either operand slot without depending on a prior
// commutative normalization moving the constant to slot 1, matching prior Go
// behavior exactly (a strict subset of what the NZMask logic below also removes).
func (r *RuleAndMask) apply(op *PcodeOp, data *Funcdata) int {
	if isAllOnesConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isAllOnesConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	out := op.Output()
	if out == nil {
		return 0
	}
	size := out.Size()
	if size > 8 { // C++: size > sizeof(uintb)
		return 0
	}
	mask1 := op.Input(0).NZMask()
	var andmask uint64
	if mask1 != 0 {
		andmask = mask1 & op.Input(1).NZMask()
	}
	var vn *Varnode
	switch {
	case andmask == 0: // result of AND is always zero
		vn = data.NewConstant(size, 0)
	case andmask&out.Consumed() == 0: // surviving bits are all consumed away
		vn = data.NewConstant(size, 0)
	case andmask == mask1: // AND keeps every possibly-nonzero bit of input(0)
		if !op.Input(1).IsConstant() {
			return 0
		}
		vn = op.Input(0)
	default:
		return 0
	}
	if !vn.IsHeritageKnown() {
		return 0
	}
	return rewriteToCopy(data, op, vn)
}

type RuleOrCollapse struct{ batchRule }

func NewRuleOrCollapse(group string) *RuleOrCollapse {
	r := &RuleOrCollapse{}
	r.batchRule = newBatchRule(group, "orcollapse", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleOrCollapse(g) })
	return r
}

func (r *RuleOrCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if sameValue(op.Input(0), op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isZeroConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleAndOrLump struct{ batchRule }

func NewRuleAndOrLump(group string) *RuleAndOrLump {
	r := &RuleAndOrLump{}
	r.batchRule = newBatchRule(group, "andorlump", []OpCode{CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleAndOrLump(g) })
	return r
}

// apply collapses constants in a chain of identical logical ops:
//
//	(V & c) & d  =>  V & (c & d)   (likewise for INT_OR, INT_XOR)
//
// This is what lets a shift-count mask chain such as
// ((byte)param_3 & 0x3f) & 0xff) & 0x1f collapse to (byte)param_3 & 0x1f.
// C++ parity: ruleaction.cc RuleAndOrLump::applyOp. The constant must sit in
// slot 1 (RuleAndCommute / commutative normalization guarantees this), the
// other input must be defined by the same opcode with its own slot-1 constant,
// and the innermost base must not be free.
func (r *RuleAndOrLump) apply(op *PcodeOp, data *Funcdata) int {
	opc := op.Code()
	if !op.Input(1).IsConstant() {
		return 0
	}
	vn1 := op.Input(0)
	if !vn1.IsWritten() {
		return 0
	}
	op2 := vn1.Def()
	if op2.Code() != opc { // must be the same op
		return 0
	}
	if !op2.Input(1).IsConstant() {
		return 0
	}
	basevn := op2.Input(0)
	if basevn.IsFree() {
		return 0
	}
	val := op.Input(1).Offset()
	val2 := op2.Input(1).Offset()
	switch opc {
	case CPUI_INT_AND:
		val &= val2
	case CPUI_INT_OR:
		val |= val2
	case CPUI_INT_XOR:
		val ^= val2
	}
	data.OpSetInput(op, basevn, 0)
	data.OpSetInput(op, data.NewConstant(basevn.Size(), val), 1)
	return 1
}

type RuleNegateIdentity struct{ batchRule }

func NewRuleNegateIdentity(group string) *RuleNegateIdentity {
	r := &RuleNegateIdentity{}
	r.batchRule = newBatchRule(group, "negateidentity", []OpCode{CPUI_INT_AND, CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleNegateIdentity(g) })
	return r
}

func (r *RuleNegateIdentity) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		neg := definedBy(op.Input(slot), CPUI_INT_NEGATE)
		if neg == nil || !sameValue(neg.Input(0), op.Input(1-slot)) {
			continue
		}
		if op.Code() == CPUI_INT_AND {
			return rewriteToConst(data, op, 0)
		}
		return rewriteToConst(data, op, maskForSize(outputOrInputSize(op)))
	}
	return 0
}

type RuleShiftBitops struct{ batchRule }

func NewRuleShiftBitops(group string) *RuleShiftBitops {
	r := &RuleShiftBitops{}
	r.batchRule = newBatchRule(group, "shiftbitops", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleShiftBitops(g) })
	return r
}

func (r *RuleShiftBitops) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleRightShiftAnd struct{ batchRule }

func NewRuleRightShiftAnd(group string) *RuleRightShiftAnd {
	r := &RuleRightShiftAnd{}
	r.batchRule = newBatchRule(group, "rightshiftand", []OpCode{CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleRightShiftAnd(g) })
	return r
}

// apply is a faithful port of RuleRightShiftAnd::applyOp (ruleaction.cc:580-599):
// drop an INT_AND mask that a following right shift makes redundant --
// (V & mask) >> sa => V >> sa, when the mask keeps exactly the bits that survive
// the shift (mask >> sa == fullMask(V) >> sa). Works for INT_RIGHT and INT_SRIGHT.
//
// The previous body under this name removed an *outer* AND over a shifted value
// ((V>>sa) & lowMask(w-sa) => V>>sa), which is the NZMask-coverage case of C++
// RuleAndMask (a mask covering every possibly-nonzero bit). It is dropped here as
// the name-collision fix; the empirical gate run confirmed no golden depends on it.
func (r *RuleRightShiftAnd) apply(op *PcodeOp, data *Funcdata) int {
	sa, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	andOp := definedBy(op.Input(0), CPUI_INT_AND)
	if andOp == nil {
		return 0
	}
	maskConst, maskOK := constantValue(andOp.Input(1))
	if !maskOK {
		return 0
	}
	rootVn := andOp.Input(0)
	if maskConst>>sa != maskForSize(rootVn.Size())>>sa {
		return 0
	}
	if rootVn.IsFree() {
		return 0
	}
	data.OpSetInput(op, rootVn, 0) // bypass the INT_AND
	return 1
}

type RuleAndCommute struct{ batchRule }

func NewRuleAndCommute(group string) *RuleAndCommute {
	r := &RuleAndCommute{}
	r.batchRule = newBatchRule(group, "andcommute", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndCommute(g) })
	return r
}

func (r *RuleAndCommute) apply(op *PcodeOp, data *Funcdata) int {
	if op.Input(0) != nil && op.Input(0).IsConstant() && (op.Input(1) == nil || !op.Input(1).IsConstant()) {
		return swapInputs(data, op)
	}
	return 0
}

type RuleAndPiece struct{ batchRule }

func NewRuleAndPiece(group string) *RuleAndPiece {
	r := &RuleAndPiece{}
	r.batchRule = newBatchRule(group, "andpiece", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndPiece(g) })
	return r
}

func (r *RuleAndPiece) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		piece := definedBy(op.Input(slot), CPUI_PIECE)
		if piece == nil {
			continue
		}
		maskVal, ok := constantValue(op.Input(1 - slot))
		if !ok {
			continue
		}
		lo := piece.Input(1)
		if maskVal == maskForSize(lo.Size()) {
			rewriteOp(data, op, CPUI_INT_ZEXT, lo)
			return 1
		}
	}
	return 0
}

type RuleAndZext struct{ batchRule }

func NewRuleAndZext(group string) *RuleAndZext {
	r := &RuleAndZext{}
	r.batchRule = newBatchRule(group, "andzext", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndZext(g) })
	return r
}

func (r *RuleAndZext) apply(op *PcodeOp, data *Funcdata) int {
	for slot := 0; slot < 2; slot++ {
		ext := definedBy(op.Input(slot), CPUI_INT_ZEXT)
		if ext == nil {
			continue
		}
		maskVal, ok := constantValue(op.Input(1 - slot))
		if !ok {
			continue
		}
		if maskVal == maskForSize(ext.Input(0).Size()) {
			return rewriteToCopy(data, op, op.Input(slot))
		}
	}
	return 0
}

// RuleXorIdentity folds the INT_XOR identity/complement elements,
// "V ^ 0 => V" and "V ^ -1 => ~V".
//
// No C++ rule of this shape exists. It used to live under the name
// "RuleXorCollapse", but that name belongs to a completely different C++ rule
// (see RuleXorCollapse below). The body is kept under its own name because
// unregistering it regresses output; the zero case overlaps C++ RuleIdentityEl
// (ruleaction.cc) except that this one also normalizes the commuted slot 0.
type RuleXorIdentity struct{ batchRule }

func NewRuleXorIdentity(group string) *RuleXorIdentity {
	r := &RuleXorIdentity{}
	r.batchRule = newBatchRule(group, "xoridentity", []OpCode{CPUI_INT_XOR}, r.apply, func(g string) Rule { return NewRuleXorIdentity(g) })
	return r
}

func (r *RuleXorIdentity) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(0)) {
		return rewriteToCopy(data, op, op.Input(1))
	}
	if isZeroConst(op.Input(1)) {
		return rewriteToCopy(data, op, op.Input(0))
	}
	if isAllOnesConst(op.Input(0)) {
		rewriteOp(data, op, CPUI_INT_NEGATE, op.Input(1))
		return 1
	}
	if isAllOnesConst(op.Input(1)) {
		rewriteOp(data, op, CPUI_INT_NEGATE, op.Input(0))
		return 1
	}
	return 0
}

type RuleXorCollapse struct{ batchRule }

func NewRuleXorCollapse(group string) *RuleXorCollapse {
	r := &RuleXorCollapse{}
	// RuleXorCollapse::applyOp -- ruleaction.cc:4058. Eliminate INT_XOR feeding a
	// comparison:
	//   (V ^ W) == 0  =>  V == W
	//   (V ^ c) == d  =>  V == (c^d)
	r.batchRule = newBatchRule(group, "xorcollapse", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleXorCollapse(g) })
	return r
}

func (r *RuleXorCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if !op.Input(1).IsConstant() {
		return 0
	}
	xorop := op.Input(0).Def()
	if xorop == nil || xorop.Code() != CPUI_INT_XOR {
		return 0
	}
	// Only rewrite when the XOR result has no other reader; otherwise the XOR
	// stays alive and the rewrite only adds an operation.
	if op.Input(0).LoneDescend() == nil {
		return 0
	}
	coeff1 := op.Input(1).Offset()
	xorvn := xorop.Input(1)
	if xorop.Input(0).IsFree() {
		return 0 // This will be propagated
	}
	if !xorvn.IsConstant() {
		if coeff1 != 0 {
			return 0
		}
		if xorvn.IsFree() {
			return 0
		}
		data.OpSetInput(op, xorvn, 1) // Move term to other side
		data.OpSetInput(op, xorop.Input(0), 0)
		return 1
	}
	coeff2 := xorvn.Offset()
	if coeff2 == 0 {
		return 0
	}
	// C++ also does constvn->copySymbolIfValid(xorvn) here; Varnode symbol markup
	// propagation is unported, so the equate/enum annotation is not carried over.
	constvn := data.NewConstant(op.Input(1).Size(), coeff1^coeff2)
	data.OpSetInput(op, constvn, 1)
	data.OpSetInput(op, xorop.Input(0), 0)
	return 1
}
