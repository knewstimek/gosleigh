package pcode

type RulePiece2Zext struct{ batchRule }

func NewRulePiece2Zext(group string) *RulePiece2Zext {
	r := &RulePiece2Zext{}
	r.batchRule = newBatchRule(group, "piece2zext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRulePiece2Zext(g) })
	return r
}

func (r *RulePiece2Zext) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(0)) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, op.Input(1))
	return 1
}

type RulePiece2Sext struct{ batchRule }

func NewRulePiece2Sext(group string) *RulePiece2Sext {
	r := &RulePiece2Sext{}
	r.batchRule = newBatchRule(group, "piece2sext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRulePiece2Sext(g) })
	return r
}

func (r *RulePiece2Sext) apply(op *PcodeOp, data *Funcdata) int {
	shift := definedBy(op.Input(0), CPUI_INT_SRIGHT)
	if shift == nil || !sameValue(shift.Input(0), op.Input(1)) {
		return 0
	}
	val, ok := constantValue(shift.Input(1))
	if !ok || val != uint64(op.Input(1).Size()*8-1) {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_SEXT, op.Input(1))
	return 1
}

// RuleZextIdentity folds an INT_ZEXT that extends nothing: a zext whose input
// already has the output size becomes a COPY, and a zext of a constant folds to
// the widened constant.
//
// No C++ rule of this shape exists. It used to live under the name
// "RuleZextEliminate", but that name belongs to a completely different C++ rule
// (see RuleZextEliminate below). The body is kept under its own name because
// unregistering it regresses output; the constant case overlaps C++
// RuleCollapseConstants, the same-size case has no C++ counterpart because C++
// never builds a width-preserving INT_ZEXT.
type RuleZextIdentity struct{ batchRule }

func NewRuleZextIdentity(group string) *RuleZextIdentity {
	r := &RuleZextIdentity{}
	r.batchRule = newBatchRule(group, "zextidentity", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleZextIdentity(g) })
	return r
}

func (r *RuleZextIdentity) apply(op *PcodeOp, data *Funcdata) int {
	in := op.Input(0)
	if in.Size() == outputOrInputSize(op) {
		return rewriteToCopy(data, op, in)
	}
	if val, ok := constantValue(in); ok {
		return rewriteToCopy(data, op, data.NewConstant(outputOrInputSize(op), val))
	}
	return 0
}

type RuleZextEliminate struct{ batchRule }

func NewRuleZextEliminate(group string) *RuleZextEliminate {
	r := &RuleZextEliminate{}
	// RuleZextEliminate::getOpList -- ruleaction.cc:2499. Eliminate INT_ZEXT in a
	// comparison against a constant that loses no non-zero bits when narrowed:
	//   zext(V) == c  =>  V == c   (likewise !=, <, <=)
	opcodes := []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL}
	r.batchRule = newBatchRule(group, "zexteliminate", opcodes, r.apply, func(g string) Rule { return NewRuleZextEliminate(g) })
	return r
}

// RuleZextEliminate::applyOp -- ruleaction.cc:2507.
func (r *RuleZextEliminate) apply(op *PcodeOp, data *Funcdata) int {
	// vn1 is the ZEXTed input, vn2 the other one.
	vn1 := op.Input(0)
	vn2 := op.Input(1)
	zextslot, otherslot := 0, 1
	if vn2.IsWritten() && vn2.Def().Code() == CPUI_INT_ZEXT {
		vn1, vn2 = vn2, op.Input(0)
		zextslot, otherslot = 1, 0
	} else if !vn1.IsWritten() || vn1.Def().Code() != CPUI_INT_ZEXT {
		return 0
	}
	if !vn2.IsConstant() {
		return 0
	}
	zext := vn1.Def()
	if !zext.Input(0).IsHeritageKnown() {
		return 0
	}
	if vn1.LoneDescend() != op {
		return 0 // Make sure extension is not used for anything else
	}
	smallsize := zext.Input(0).Size()
	val := vn2.Offset()
	// Is the zero extension unnecessary. C++ writes val>>(8*smallsize) on a
	// uintb; for smallsize>=8 that shift is undefined there, while Go defines it
	// as 0. The Go answer is the mathematically intended one (any 64-bit value
	// fits in 8+ bytes), and smallsize>=8 with a wider zext output is not
	// reachable on the supported architectures.
	if val>>(8*uint(smallsize)) == 0 {
		// C++ also does newvn->copySymbolIfValid(vn2) here; Varnode symbol markup
		// propagation is unported project-wide, so the equate/enum annotation is
		// not carried over.
		newvn := data.NewConstant(smallsize, val)
		data.OpSetInput(op, zext.Input(0), zextslot)
		data.OpSetInput(op, newvn, otherslot)
		return 1
	}
	// C++ notes an unimplemented else branch here (constant comparison folded on
	// the spot); not present in C++ either, so nothing to port.
	return 0
}

type RuleSlessToLess struct{ batchRule }

func NewRuleSlessToLess(group string) *RuleSlessToLess {
	r := &RuleSlessToLess{}
	r.batchRule = newBatchRule(group, "slesstoless", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleSlessToLess(g) })
	return r
}

// apply turns a signed comparison unsigned when neither side can have its
// sign bit set. C++ parity: RuleSlessToLess::applyOp.
func (r *RuleSlessToLess) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	sz := vn.Size()
	if signbitNegative(vn.NZMask(), sz) || signbitNegative(op.Input(1).NZMask(), sz) {
		return 0
	}
	if op.Code() == CPUI_INT_SLESS {
		data.OpSetOpcode(op, CPUI_INT_LESS)
	} else {
		data.OpSetOpcode(op, CPUI_INT_LESSEQUAL)
	}
	return 1
}

type RuleZextSless struct{ batchRule }

func NewRuleZextSless(group string) *RuleZextSless {
	r := &RuleZextSless{}
	r.batchRule = newBatchRule(group, "zextsless", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleZextSless(g) })
	return r
}

// apply drops a zero extension from a signed comparison against a constant
// whose sign bit is clear, turning it unsigned. C++ parity: RuleZextSless::applyOp.
func (r *RuleZextSless) apply(op *PcodeOp, data *Funcdata) int {
	vn1, vn2 := op.Input(0), op.Input(1)
	zextslot, otherslot := 0, 1
	if vn2.IsWritten() && vn2.Def().Code() == CPUI_INT_ZEXT {
		vn1, vn2 = vn2, op.Input(0)
		zextslot, otherslot = 1, 0
	} else if !vn1.IsWritten() || vn1.Def().Code() != CPUI_INT_ZEXT {
		return 0
	}
	if !vn2.IsConstant() {
		return 0
	}
	zext := vn1.Def()
	if !zext.Input(0).IsHeritageKnown() {
		return 0
	}
	smallsize := zext.Input(0).Size()
	val := vn2.Offset()
	if val>>(8*uint(smallsize)-1) != 0 {
		return 0 // the sign bit must also be 0
	}
	data.OpSetInput(op, zext.Input(0), zextslot)
	data.OpSetInput(op, data.NewConstant(smallsize, val), otherslot)
	if op.Code() == CPUI_INT_SLESS {
		data.OpSetOpcode(op, CPUI_INT_LESS)
	} else {
		data.OpSetOpcode(op, CPUI_INT_LESSEQUAL)
	}
	return 1
}

type RuleConcatZext struct{ batchRule }

func NewRuleConcatZext(group string) *RuleConcatZext {
	r := &RuleConcatZext{}
	r.batchRule = newBatchRule(group, "concatzext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatZext(g) })
	return r
}

// apply turns concat(zext(H), L) into zext(concat(H, L)).
// C++ parity: RuleConcatZext::applyOp.
func (r *RuleConcatZext) apply(op *PcodeOp, data *Funcdata) int {
	hi := op.Input(0)
	if !hi.IsWritten() {
		return 0
	}
	zextop := hi.Def()
	if zextop.Code() != CPUI_INT_ZEXT {
		return 0
	}
	hi = zextop.Input(0)
	lo := op.Input(1)
	if hi.IsFree() || lo.IsFree() {
		return 0
	}
	newconcat := data.NewOp(2, op.Addr())
	data.OpSetOpcode(newconcat, CPUI_PIECE)
	newvn := data.NewUniqueOut(hi.Size()+lo.Size(), newconcat)
	data.OpSetInput(newconcat, hi, 0)
	data.OpSetInput(newconcat, lo, 1)
	data.OpInsertBefore(newconcat, op)
	data.OpRemoveInput(op, 1)
	data.OpSetInput(op, newvn, 0)
	data.OpSetOpcode(op, CPUI_INT_ZEXT)
	return 1
}

type RuleZextCommute struct{ batchRule }

func NewRuleZextCommute(group string) *RuleZextCommute {
	r := &RuleZextCommute{}
	r.batchRule = newBatchRule(group, "zextcommute", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleZextCommute(g) })
	return r
}

// apply is a faithful port of RuleZextCommute::applyOp (ruleaction.cc:4852):
// zext(V) >> W => zext(V >> W), pushing the shift under the zero-extension.
//
// The prior body under this name bypassed a COPY under an extension
// (ext(COPY(V)) => ext(V)), which duplicates RulePropagateCopy (it inlines any
// COPY-defined input on every op), so replacing it loses no coverage.
func (r *RuleZextCommute) apply(op *PcodeOp, data *Funcdata) int {
	zextvn := op.Input(0)
	if zextvn == nil || !zextvn.IsWritten() {
		return 0
	}
	zextop := zextvn.Def()
	if zextop == nil || zextop.Code() != CPUI_INT_ZEXT {
		return 0
	}
	zextin := zextop.Input(0)
	if zextin.IsFree() {
		return 0
	}
	savn := op.Input(1)
	if !savn.IsConstant() && savn.IsFree() {
		return 0
	}
	newop := data.NewOpBefore(op, CPUI_INT_RIGHT, zextin, savn)
	data.NewUniqueOut(zextin.Size(), newop)
	data.OpRemoveInput(op, 1)
	data.OpSetInput(op, newop.Output(), 0)
	data.OpSetOpcode(op, CPUI_INT_ZEXT)
	return 1
}

type RuleZextShiftZext struct{ batchRule }

func NewRuleZextShiftZext(group string) *RuleZextShiftZext {
	r := &RuleZextShiftZext{}
	r.batchRule = newBatchRule(group, "zextshiftzext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleZextShiftZext(g) })
	return r
}

// apply removes a ZEXT of a ZEXT, or turns zext(zext(V) << n) into
// zext(V) << n when the shift loses no bits. C++ parity: RuleZextShiftZext::applyOp.
func (r *RuleZextShiftZext) apply(op *PcodeOp, data *Funcdata) int {
	invn := op.Input(0)
	if !invn.IsWritten() {
		return 0
	}
	shiftop := invn.Def()
	if shiftop.Code() == CPUI_INT_ZEXT {
		vn := shiftop.Input(0)
		if vn.IsFree() || invn.LoneDescend() != op {
			return 0
		}
		data.OpSetInput(op, vn, 0)
		return 1
	}
	if shiftop.Code() != CPUI_INT_LEFT || !shiftop.Input(1).IsConstant() || !shiftop.Input(0).IsWritten() {
		return 0
	}
	zext2op := shiftop.Input(0).Def()
	if zext2op.Code() != CPUI_INT_ZEXT {
		return 0
	}
	rootvn := zext2op.Input(0)
	if rootvn.IsFree() {
		return 0
	}
	sa := shiftop.Input(1).Offset()
	if sa > uint64(8*(zext2op.Output().Size()-rootvn.Size())) {
		return 0 // the shift might lose bits off the top
	}
	newop := data.NewOp(1, op.Addr())
	data.OpSetOpcode(newop, CPUI_INT_ZEXT)
	outvn := data.NewUniqueOut(op.Output().Size(), newop)
	data.OpSetInput(newop, rootvn, 0)
	data.OpSetOpcode(op, CPUI_INT_LEFT)
	data.OpSetInput(op, outvn, 0)
	data.OpInsertInput(op, data.NewConstant(4, sa), 1)
	data.OpInsertBefore(newop, op)
	return 1
}

type RuleSubZext struct{ batchRule }

func NewRuleSubZext(group string) *RuleSubZext {
	r := &RuleSubZext{}
	r.batchRule = newBatchRule(group, "subzext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleSubZext(g) })
	return r
}

// apply turns a zero extension of a truncation back to the same size into
// a mask: zext(sub(V,0)) => V & mask, zext(sub(V,c) >> d) => (V >> (8c+d)) & mask.
// C++ parity: RuleSubZext::applyOp.
func (r *RuleSubZext) apply(op *PcodeOp, data *Funcdata) int {
	subvn := op.Input(0)
	if !subvn.IsWritten() {
		return 0
	}
	subop := subvn.Def()
	switch subop.Code() {
	case CPUI_SUBPIECE:
		basevn := subop.Input(0)
		if basevn.IsFree() || basevn.Size() != op.Output().Size() || basevn.Size() > 8 {
			return 0
		}
		if subop.Input(1).Offset() != 0 { // truncating from the middle
			if subvn.LoneDescend() != op { // with no other use of the truncation
				return 0
			}
			newvn := data.NewUnique(basevn.Size())
			constvn := subop.Input(1)
			data.OpSetInput(op, newvn, 0)
			data.OpSetOpcode(subop, CPUI_INT_RIGHT) // the truncation becomes a shift
			data.OpSetInput(subop, data.NewConstant(constvn.Size(), constvn.Offset()*8), 1)
			data.OpSetOutput(subop, newvn)
		} else {
			data.OpSetInput(op, basevn, 0) // bypass the truncation
		}
		data.OpSetOpcode(op, CPUI_INT_AND)
		data.OpInsertInput(op, data.NewConstant(basevn.Size(), bitfieldSizeMask(subvn.Size())), 1)
		return 1
	case CPUI_INT_RIGHT:
		shiftop := subop
		if !shiftop.Input(1).IsConstant() {
			return 0
		}
		midvn := shiftop.Input(0)
		if !midvn.IsWritten() {
			return 0
		}
		subop = midvn.Def()
		if subop.Code() != CPUI_SUBPIECE {
			return 0
		}
		basevn := subop.Input(0)
		if basevn.IsFree() || basevn.Size() != op.Output().Size() {
			return 0
		}
		if midvn.LoneDescend() != shiftop || subvn.LoneDescend() != op {
			return 0
		}
		sa := shiftop.Input(1).Offset()
		val := bitfieldSizeMask(midvn.Size()) >> sa // the shift shrinks the mask further
		sa += subop.Input(1).Offset() * 8           // total shift: truncation + small shift
		newvn := data.NewUnique(basevn.Size())
		data.OpSetInput(op, newvn, 0)
		data.OpSetInput(shiftop, basevn, 0) // shift the full value
		data.OpSetInput(shiftop, data.NewConstant(shiftop.Input(1).Size(), sa), 1)
		data.OpSetOutput(shiftop, newvn)
		data.OpSetOpcode(op, CPUI_INT_AND)
		data.OpInsertInput(op, data.NewConstant(basevn.Size(), val), 1)
		return 1
	}
	return 0
}

type RuleSubExtComm struct{ batchRule }

func NewRuleSubExtComm(group string) *RuleSubExtComm {
	r := &RuleSubExtComm{}
	r.batchRule = newBatchRule(group, "subextcomm", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubExtComm(g) })
	return r
}

// apply commutes a SUBPIECE with the extension it truncates:
// sub(ext(V),c) => sub(V,c) when no extended bit survives, else ext(sub(V,c)).
// C++ parity: RuleSubExtComm::applyOp.
func (r *RuleSubExtComm) apply(op *PcodeOp, data *Funcdata) int {
	base := op.Input(0)
	if !base.IsWritten() {
		return 0
	}
	extop := base.Def()
	if extop.Code() != CPUI_INT_ZEXT && extop.Code() != CPUI_INT_SEXT {
		return 0
	}
	invn := extop.Input(0)
	if invn.IsFree() {
		return 0
	}
	subcut := int32(op.Input(1).Offset())
	if op.Output().Size()+subcut <= invn.Size() {
		// The SUBPIECE does not reach the extended bits.
		data.OpSetInput(op, invn, 0)
		if invn.Size() == op.Output().Size() {
			data.OpRemoveInput(op, 1)
			data.OpSetOpcode(op, CPUI_COPY)
		}
		return 1
	}
	if subcut >= invn.Size() {
		return 0
	}
	newvn := invn
	if subcut != 0 {
		newop := data.NewOp(2, op.Addr())
		data.OpSetOpcode(newop, CPUI_SUBPIECE)
		newvn = data.NewUniqueOut(invn.Size()-subcut, newop)
		data.OpSetInput(newop, data.NewConstant(op.Input(1).Size(), uint64(subcut)), 1)
		data.OpSetInput(newop, invn, 0)
		data.OpInsertBefore(newop, op)
	}
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, extop.Code())
	data.OpSetInput(op, newvn, 0)
	return 1
}

// RuleSubCommute pushes SUBPIECE earlier into arithmetic/bitwise expressions,
// commuting it past INT_MULT, INT_ADD, INT_XOR, INT_AND, INT_OR, INT_NEGATE.
// Only the low-part (offset==0) truncation commutes with INT_MULT and INT_ADD.
// After commuting, RuleSubExtComm or constant folding can cancel the SEXT/ZEXT.
// C++ parity: RuleSubCommute::applyOp in ruleaction.cc
type RuleSubCommute struct{ batchRule }

func NewRuleSubCommute(group string) *RuleSubCommute {
	r := &RuleSubCommute{}
	r.batchRule = newBatchRule(group, "subcommute", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubCommute(g) })
	return r
}

// apply pushes a SUBPIECE through the operation defining its input when the
// two commute. C++ parity: RuleSubCommute::applyOp.
func (r *RuleSubCommute) apply(op *PcodeOp, data *Funcdata) int {
	base := op.Input(0)
	if !base.IsWritten() {
		return 0
	}
	offset := op.Input(1).Offset()
	outvn := op.Output()
	if outvn.IsPrecisLo() || outvn.IsPrecisHi() {
		return 0
	}
	insize := base.Size()
	longform := base.Def()
	j := -1
	switch longform.Code() {
	case CPUI_INT_LEFT:
		j = 1 // the shift amount is not truncated
		if offset != 0 || !longform.Input(0).IsWritten() {
			return 0
		}
		if opc := longform.Input(0).Def().Code(); opc != CPUI_INT_ZEXT && opc != CPUI_PIECE {
			return 0
		}
	case CPUI_INT_REM, CPUI_INT_DIV, CPUI_INT_SREM, CPUI_INT_SDIV:
		// Commutes only if the inputs are zero (or sign) extended.
		ext := CPUI_INT_ZEXT
		if longform.Code() == CPUI_INT_SREM || longform.Code() == CPUI_INT_SDIV {
			ext = CPUI_INT_SEXT
		}
		if offset != 0 || !longform.Input(0).IsWritten() {
			return 0
		}
		ext0 := longform.Input(0).Def()
		if ext0.Code() != ext {
			return 0
		}
		ext0In := ext0.Input(0)
		if in1 := longform.Input(1); in1.IsWritten() {
			ext1 := in1.Def()
			if ext1.Code() != ext {
				return 0
			}
			ext1In := ext1.Input(0)
			if ext1In.Size() > outvn.Size() || ext0In.Size() > outvn.Size() {
				// Partial commute: the extensions cancel, the SUBPIECE stays.
				if subCommuteCancelExtensions(longform, op, ext0In, ext1In, data) {
					return 1
				}
				return 0
			}
		} else if in1.IsConstant() && ext0In.Size() <= outvn.Size() {
			val := in1.Offset()
			smallval := val & maskForSize(outvn.Size())
			if ext == CPUI_INT_SEXT {
				smallval = uint64(signExtendToInt64(smallval, outvn.Size())) & maskForSize(insize)
			}
			if val != smallval {
				return 0
			}
		} else {
			return 0
		}
	case CPUI_INT_ADD:
		if offset != 0 || longform.Input(0).IsSpaceBase() {
			return 0 // low piece only; deconflict with RulePtrArith
		}
	case CPUI_INT_MULT:
		if offset != 0 {
			return 0
		}
	case CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR:
	default:
		return 0
	}
	if base.LoneDescend() != op {
		return 0 // no other piece of base may be used
	}
	if offset == 0 { // overlap with RuleSubZext
		if next := outvn.LoneDescend(); next != nil && next.Code() == CPUI_INT_ZEXT && next.Output().Size() == insize {
			return 0
		}
	}
	var lastIn, newVn *Varnode
	for i := 0; i < longform.NumInput(); i++ {
		vn := longform.Input(i)
		if i != j {
			if lastIn != vn || newVn == nil {
				newsub := data.NewOp(2, op.Addr())
				data.OpSetOpcode(newsub, CPUI_SUBPIECE)
				newVn = data.NewUniqueOut(outvn.Size(), newsub)
				data.OpSetInput(longform, newVn, i)
				data.OpSetInput(newsub, vn, 0)
				data.OpSetInput(newsub, data.NewConstant(4, offset), 1)
				data.OpInsertBefore(newsub, longform)
			} else {
				data.OpSetInput(longform, newVn, i)
			}
		}
		lastIn = vn
	}
	// outvn moves to longform; op must not free it when destroyed.
	data.OpUnsetOutput(longform)
	data.OpSetOutput(longform, outvn)
	op.SetOutput(nil)
	data.OpDestroy(op)
	return 1
}

// subCommuteCancelExtensions rebuilds longform on its unextended inputs at the
// larger of their sizes, keeping the SUBPIECE. C++ parity:
// RuleSubCommute::cancelExtensions / shortenExtension.
func subCommuteCancelExtensions(longform, subOp *PcodeOp, ext0In, ext1In *Varnode, data *Funcdata) bool {
	if longform.Output().LoneDescend() != subOp {
		return false
	}
	shorten := func(extOp *PcodeOp, maxSize int32) *Varnode {
		orig := extOp.Output()
		addr := orig.Addr()
		if addr.Space != nil && addr.Space.BigEndian {
			addr.Offset += uint64(orig.Size() - maxSize)
		}
		data.OpUnsetOutput(extOp)
		return data.NewVarnodeOut(maxSize, addr, extOp)
	}
	var maxSize int32
	switch {
	case ext0In.Size() == ext1In.Size():
		maxSize = ext0In.Size()
		if ext0In.IsFree() || ext1In.IsFree() {
			return false
		}
	case ext0In.Size() < ext1In.Size():
		maxSize = ext1In.Size()
		if ext1In.IsFree() || longform.Input(0).LoneDescend() != longform {
			return false
		}
		ext0In = shorten(longform.Input(0).Def(), maxSize)
	default:
		maxSize = ext0In.Size()
		if ext0In.IsFree() || longform.Input(1).LoneDescend() != longform {
			return false
		}
		ext1In = shorten(longform.Input(1).Def(), maxSize)
	}
	data.OpUnsetOutput(longform)
	outvn := data.NewUniqueOut(maxSize, longform)
	data.OpSetInput(longform, ext0In, 0)
	data.OpSetInput(longform, ext1In, 1)
	data.OpSetInput(subOp, outvn, 0)
	return true
}

type RuleBoolZext struct{ batchRule }

func NewRuleBoolZext(group string) *RuleBoolZext {
	r := &RuleBoolZext{}
	r.batchRule = newBatchRule(group, "boolzext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleBoolZext(g) })
	return r
}

// RuleBoolZext::applyOp -- ruleaction.cc:3015. op is the INT_ZEXT.
func (r *RuleBoolZext) apply(op *PcodeOp, data *Funcdata) int {
	boolVn1 := op.Input(0)
	if !isBoolLike(boolVn1) {
		return 0
	}

	multop1 := op.Output().LoneDescend()
	if multop1 == nil || multop1.Code() != CPUI_INT_MULT {
		return 0
	}
	if !multop1.Input(1).IsConstant() {
		return 0
	}
	coeff := multop1.Input(1).Offset()
	if coeff != maskForSize(multop1.Input(1).Size()) {
		return 0
	}
	size := multop1.Output().Size()

	// If we reached here, we are multiplying extended boolean by -1.
	actionop := multop1.Output().LoneDescend()
	if actionop == nil {
		return 0
	}
	var opc OpCode
	switch actionop.Code() {
	case CPUI_INT_ADD:
		if !actionop.Input(1).IsConstant() {
			return 0
		}
		if actionop.Input(1).Offset() == 1 {
			newop := data.NewOp(1, op.Addr())
			data.OpSetOpcode(newop, CPUI_BOOL_NEGATE) // Negate the boolean
			vn := data.NewUniqueOut(1, newop)
			data.OpSetInput(newop, boolVn1, 0)
			data.OpInsertBefore(newop, op)
			data.OpSetInput(op, vn, 0)
			data.OpRemoveInput(actionop, 1) // eliminate the INT_ADD operator
			data.OpSetOpcode(actionop, CPUI_COPY)
			data.OpSetInput(actionop, op.Output(), 0) // propagate past the INT_MULT operator
			return 1
		}
		return 0
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
		if !actionop.Input(1).IsConstant() {
			return 0
		}
		val := actionop.Input(1).Offset()

		// Change comparison of extended boolean to 0 or -1
		// to comparison of unextended boolean to 0 or 1.
		if val == coeff {
			val = 1
		} else if val != 0 {
			return 0 // Not comparing with 0 or -1
		}

		data.OpSetInput(actionop, boolVn1, 0)
		data.OpSetInput(actionop, data.NewConstant(1, val), 1)
		return 1
	case CPUI_INT_AND:
		opc = CPUI_BOOL_AND
	case CPUI_INT_OR:
		opc = CPUI_BOOL_OR
	case CPUI_INT_XOR:
		opc = CPUI_BOOL_XOR
	default:
		return 0
	}

	// Apparently doing logical ops with extended boolean.

	// Check that the other side is also an extended boolean.
	var multop2 *PcodeOp
	if multop1 == actionop.Input(0).Def() {
		multop2 = actionop.Input(1).Def()
	} else {
		multop2 = actionop.Input(0).Def()
	}
	if multop2 == nil || multop2.Code() != CPUI_INT_MULT {
		return 0
	}
	if !multop2.Input(1).IsConstant() {
		return 0
	}
	coeff2 := multop2.Input(1).Offset()
	if coeff2 != maskForSize(size) {
		return 0
	}
	zextop2 := multop2.Input(0).Def()
	if zextop2 == nil || zextop2.Code() != CPUI_INT_ZEXT {
		return 0
	}
	boolVn2 := zextop2.Input(0)
	if !isBoolLike(boolVn2) {
		return 0
	}

	// Do the boolean calculation on unextended boolean values
	// and then extend the result.
	newop := data.NewOp(2, actionop.Addr())
	newres := data.NewUniqueOut(1, newop)
	data.OpSetOpcode(newop, opc)
	data.OpSetInput(newop, boolVn1, 0)
	data.OpSetInput(newop, boolVn2, 1)
	data.OpInsertBefore(newop, actionop)

	newzext := data.NewOp(1, actionop.Addr())
	newzout := data.NewUniqueOut(size, newzext)
	data.OpSetOpcode(newzext, CPUI_INT_ZEXT)
	data.OpSetInput(newzext, newres, 0)
	data.OpInsertBefore(newzext, actionop)

	data.OpSetOpcode(actionop, CPUI_INT_MULT)
	data.OpSetInput(actionop, newzout, 0)
	data.OpSetInput(actionop, data.NewConstant(size, coeff2), 1)
	return 1
}
