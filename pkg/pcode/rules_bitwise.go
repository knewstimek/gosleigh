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
// There is no all-ones shortcut: "X & 0xff" with an unconsumed result or a
// zero NZMask input must collapse to 0, not to X.
func (r *RuleAndMask) apply(op *PcodeOp, data *Funcdata) int {
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

// apply collapses V | c to c when c already covers every bit V can have.
// (V | V and V | 0 belong to RuleTrivialArith and RuleIdentityEl.)
// C++ parity: ruleaction.cc RuleOrCollapse::applyOp.
func (r *RuleOrCollapse) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(1)
	if !vn.IsConstant() {
		return 0
	}
	if op.Output().Size() > 8 {
		return 0
	}
	mask := op.Input(0).NZMask()
	val := vn.Offset()
	if mask|val != val {
		return 0 // first param may turn on other bits
	}
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpRemoveInput(op, 0)
	return 1
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
	r.batchRule = newBatchRule(group, "negateidentity", []OpCode{CPUI_INT_NEGATE}, r.apply, func(g string) Rule { return NewRuleNegateIdentity(g) })
	return r
}

// apply folds V & ~V to 0 and V | ~V, V ^ ~V to all ones.
// C++ parity: RuleNegateIdentity::applyOp (triggered on the INT_NEGATE).
func (r *RuleNegateIdentity) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	outVn := op.Output()
	for _, logicOp := range outVn.DescendIter() {
		opc := logicOp.Code()
		if opc != CPUI_INT_AND && opc != CPUI_INT_OR && opc != CPUI_INT_XOR {
			continue
		}
		slot := logicOp.GetSlot(outVn)
		if logicOp.Input(1-slot) != vn {
			continue
		}
		var value uint64
		if opc != CPUI_INT_AND {
			value = maskForSize(vn.Size())
		}
		data.OpSetInput(logicOp, data.NewConstant(vn.Size(), value), 0)
		data.OpRemoveInput(logicOp, 1)
		data.OpSetOpcode(logicOp, CPUI_COPY)
		return 1
	}
	return 0
}

type RuleShiftBitops struct{ batchRule }

func NewRuleShiftBitops(group string) *RuleShiftBitops {
	r := &RuleShiftBitops{}
	r.batchRule = newBatchRule(group, "shiftbitops", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_SUBPIECE, CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRuleShiftBitops(g) })
	return r
}

// apply drops an input of a bitwise op whose bits a following shift (or
// truncation, or multiply by a power of two) pushes out entirely:
// (V & 0xf000) << 4 => #0 << 4, (V + 0xf000) << 4 => V << 4.
// A shift by zero is RuleTrivialShift's.
// C++ parity: RuleShiftBitops::applyOp.
func (r *RuleShiftBitops) apply(op *PcodeOp, data *Funcdata) int {
	constvn := op.Input(1)
	if !constvn.IsConstant() {
		return 0 // Must be a constant shift
	}
	vn := op.Input(0)
	if !vn.IsWritten() || vn.Size() > 8 {
		return 0
	}
	var sa uint64
	leftshift := false
	switch op.Code() {
	case CPUI_INT_LEFT:
		sa, leftshift = constvn.Offset(), true
	case CPUI_INT_RIGHT:
		sa = constvn.Offset()
	case CPUI_SUBPIECE:
		sa = constvn.Offset() * 8
	case CPUI_INT_MULT:
		bit := leastSigBitSet(constvn.Offset())
		if bit == -1 {
			return 0
		}
		sa, leftshift = uint64(bit), true
	default:
		return 0
	}
	bitop := vn.Def()
	switch bitop.Code() {
	case CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR:
	case CPUI_INT_MULT, CPUI_INT_ADD:
		if !leftshift {
			return 0
		}
	default:
		return 0
	}
	mask := maskForSize(op.Output().Size())
	i := 0
	for ; i < bitop.NumInput(); i++ {
		nzm := bitop.Input(i).NZMask()
		if leftshift {
			nzm = pcodeLeft(nzm, sa)
		} else {
			nzm = pcodeRight(nzm, sa)
		}
		if nzm&mask == 0 {
			break
		}
	}
	if i == bitop.NumInput() {
		return 0
	}
	switch bitop.Code() {
	case CPUI_INT_MULT, CPUI_INT_AND:
		data.OpSetInput(op, data.NewConstant(vn.Size(), 0), 0) // Result will be zero
	case CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR:
		other := bitop.Input(1 - i)
		if !other.IsHeritageKnown() {
			return 0
		}
		data.OpSetInput(op, other, 0)
	}
	return 1
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

// apply commutes an AND with a shift when the shifted value is an OR or
// PIECE whose pieces the mask can then separate:
// (V << c) & W becomes (V & (W >> c)) << c.
// C++ parity: RuleAndCommute::applyOp.
func (r *RuleAndCommute) apply(op *PcodeOp, data *Funcdata) int {
	size := op.Output().Size()
	if size > 8 {
		return 0
	}
	fullmask := bitfieldSizeMask(size)
	var orvn, othervn, savn *Varnode
	opc := CPUI_INT_OR
	found := false
	for i := 0; i < 2 && !found; i++ {
		shiftvn := op.Input(i)
		shiftop := shiftvn.Def()
		if shiftop == nil {
			continue
		}
		opc = shiftop.Code()
		if opc != CPUI_INT_LEFT && opc != CPUI_INT_RIGHT {
			continue
		}
		savn = shiftop.Input(1)
		if !savn.IsConstant() {
			continue
		}
		sa := uint(savn.Offset())
		othervn = op.Input(1 - i)
		if !othervn.IsHeritageKnown() {
			continue
		}
		othermask := othervn.NZMask()
		// Skip an AND that only clears bits the shift already zeroed (andmask
		// handles it).
		if opc == CPUI_INT_RIGHT {
			if fullmask>>sa == othermask {
				continue
			}
			othermask <<= sa // the mask as it will be after the commute
		} else {
			// C++ tests ((fullmask<<sa) && fullmask), a logical AND that
			// yields 1; kept as is.
			if fullmask<<sa != 0 && fullmask != 0 && othermask == 1 {
				continue
			}
			othermask >>= sa
		}
		if othermask == 0 || othermask == fullmask {
			continue
		}
		orvn = shiftop.Input(0)
		if opc == CPUI_INT_LEFT && othervn.IsConstant() {
			// (v & #c) << #sa is preferred to (v << #sa) & #(c << sa): the
			// mask is least justified, a normalization.
			if shiftvn.LoneDescend() == op {
				found = true
				break
			}
		}
		if !orvn.IsWritten() {
			continue
		}
		orop := orvn.Def()
		switch orop.Code() {
		case CPUI_INT_OR:
			ormask1 := orop.Input(0).NZMask()
			ormask2 := orop.Input(1).NZMask()
			if ormask1&othermask == 0 || ormask2&othermask == 0 {
				found = true
			} else if othervn.IsConstant() && (ormask1&othermask == ormask1 || ormask2&othermask == ormask2) {
				found = true
			}
		case CPUI_PIECE:
			ormask1 := orop.Input(1).NZMask() // low part of the piece
			ormask2 := orop.Input(0).NZMask() << (uint(orop.Input(1).Size()) * 8)
			if ormask1&othermask == 0 || ormask2&othermask == 0 {
				found = true
			}
		}
	}
	if !found {
		return 0
	}
	newop1 := data.NewOp(2, op.Addr())
	newvn1 := data.NewUniqueOut(size, newop1)
	if opc == CPUI_INT_LEFT {
		data.OpSetOpcode(newop1, CPUI_INT_RIGHT)
	} else {
		data.OpSetOpcode(newop1, CPUI_INT_LEFT)
	}
	data.OpSetInput(newop1, othervn, 0)
	data.OpSetInput(newop1, savn, 1)
	data.OpInsertBefore(newop1, op)

	newop2 := data.NewOp(2, op.Addr())
	newvn2 := data.NewUniqueOut(size, newop2)
	data.OpSetOpcode(newop2, CPUI_INT_AND)
	data.OpSetInput(newop2, orvn, 0)
	data.OpSetInput(newop2, newvn1, 1)
	data.OpInsertBefore(newop2, op)

	data.OpSetInput(op, newvn2, 0)
	data.OpSetInput(op, savn, 1)
	data.OpSetOpcode(op, opc)
	return 1
}

type RuleAndPiece struct{ batchRule }

func NewRuleAndPiece(group string) *RuleAndPiece {
	r := &RuleAndPiece{}
	r.batchRule = newBatchRule(group, "andpiece", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndPiece(g) })
	return r
}

// apply simplifies a PIECE under an AND whose mask clears one half: the high
// half cleared gives ZEXT(lo), the low half cleared gives PIECE(hi, 0).
// C++ parity: RuleAndPiece::applyOp.
func (r *RuleAndPiece) apply(op *PcodeOp, data *Funcdata) int {
	size := op.Output().Size()
	var highvn, lowvn *Varnode
	opc := CPUI_PIECE
	i := 0
	for ; i < 2; i++ {
		piecevn := op.Input(i)
		if !piecevn.IsWritten() {
			continue
		}
		pieceop := piecevn.Def()
		if pieceop.Code() != CPUI_PIECE {
			continue
		}
		othermask := op.Input(1 - i).NZMask()
		if othermask == maskForSize(size) || othermask == 0 {
			continue // all bits kept, or handled by andmask
		}
		highvn = pieceop.Input(0)
		if !highvn.IsHeritageKnown() {
			continue
		}
		lowvn = pieceop.Input(1)
		if !lowvn.IsHeritageKnown() {
			continue
		}
		maskhigh := highvn.NZMask()
		masklow := lowvn.NZMask()
		if maskhigh&(othermask>>(uint(lowvn.Size())*8)) == 0 {
			if maskhigh == 0 && highvn.IsConstant() {
				continue // handled by piece2zext
			}
			opc = CPUI_INT_ZEXT
			break
		} else if masklow&othermask == 0 {
			if lowvn.IsConstant() {
				continue
			}
			opc = CPUI_PIECE
			break
		}
	}
	if i == 2 {
		return 0
	}
	var newop *PcodeOp
	if opc == CPUI_INT_ZEXT {
		newop = data.NewOp(1, op.Addr())
		data.OpSetOpcode(newop, opc)
		data.OpSetInput(newop, lowvn, 0)
	} else {
		newop = data.NewOp(2, op.Addr())
		data.OpSetOpcode(newop, opc)
		data.OpSetInput(newop, highvn, 0)
		data.OpSetInput(newop, data.NewConstant(lowvn.Size(), 0), 1)
	}
	newvn := data.NewUniqueOut(size, newop)
	data.OpInsertBefore(newop, op)
	data.OpSetInput(op, newvn, i)
	return 1
}

type RuleAndZext struct{ batchRule }

func NewRuleAndZext(group string) *RuleAndZext {
	r := &RuleAndZext{}
	r.batchRule = newBatchRule(group, "andzext", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleAndZext(g) })
	return r
}

// apply turns sext(V) & mask(V) or piece(H,V) & mask(V) into zext(V).
// C++ parity: RuleAndZext::applyOp.
func (r *RuleAndZext) apply(op *PcodeOp, data *Funcdata) int {
	cvn1 := op.Input(1)
	if !cvn1.IsConstant() || !op.Input(0).IsWritten() {
		return 0
	}
	otherop := op.Input(0).Def()
	var rootvn *Varnode
	switch otherop.Code() {
	case CPUI_INT_SEXT:
		rootvn = otherop.Input(0)
	case CPUI_PIECE:
		rootvn = otherop.Input(1)
	default:
		return 0
	}
	if maskForSize(rootvn.Size()) != cvn1.Offset() || rootvn.IsFree() || rootvn.Size() > 8 {
		return 0
	}
	data.OpSetOpcode(op, CPUI_INT_ZEXT)
	data.OpRemoveInput(op, 1)
	data.OpSetInput(op, rootvn, 0)
	return 1
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
