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

func (r *RuleSlessToLess) apply(op *PcodeOp, data *Funcdata) int {
	left := definedBy(op.Input(0), CPUI_INT_ZEXT)
	right := definedBy(op.Input(1), CPUI_INT_ZEXT)
	if left == nil || right == nil {
		return 0
	}
	if left.Input(0).Size() != right.Input(0).Size() {
		return 0
	}
	if op.Code() == CPUI_INT_SLESS {
		rewriteOp(data, op, CPUI_INT_LESS, left.Input(0), right.Input(0))
	} else {
		rewriteOp(data, op, CPUI_INT_LESSEQUAL, left.Input(0), right.Input(0))
	}
	return 1
}

type RuleZextSless struct{ batchRule }

func NewRuleZextSless(group string) *RuleZextSless {
	r := &RuleZextSless{}
	r.batchRule = newBatchRule(group, "zextsless", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL}, r.apply, func(g string) Rule { return NewRuleZextSless(g) })
	return r
}

func (r *RuleZextSless) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val != 0 {
		return 0
	}
	ext := definedBy(lhs, CPUI_INT_ZEXT)
	if ext == nil {
		return 0
	}
	if op.Code() == CPUI_INT_SLESS {
		return rewriteToConst(data, op, 0)
	}
	rewriteOp(data, op, CPUI_INT_EQUAL, ext.Input(0), data.NewConstant(ext.Input(0).Size(), 0))
	return 1
}

type RuleConcatZext struct{ batchRule }

func NewRuleConcatZext(group string) *RuleConcatZext {
	r := &RuleConcatZext{}
	r.batchRule = newBatchRule(group, "concatzext", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatZext(g) })
	return r
}

func (r *RuleConcatZext) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(0)) {
		return 0
	}
	ext := definedBy(op.Input(1), CPUI_INT_ZEXT)
	if ext == nil {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, ext.Input(0))
	return 1
}

type RuleZextCommute struct{ batchRule }

func NewRuleZextCommute(group string) *RuleZextCommute {
	r := &RuleZextCommute{}
	r.batchRule = newBatchRule(group, "zextcommute", []OpCode{CPUI_INT_ZEXT, CPUI_INT_SEXT}, r.apply, func(g string) Rule { return NewRuleZextCommute(g) })
	return r
}

func (r *RuleZextCommute) apply(op *PcodeOp, data *Funcdata) int {
	copyop := definedBy(op.Input(0), CPUI_COPY)
	if copyop == nil {
		return 0
	}
	rewriteOp(data, op, op.Code(), copyop.Input(0))
	return 1
}

type RuleZextShiftZext struct{ batchRule }

func NewRuleZextShiftZext(group string) *RuleZextShiftZext {
	r := &RuleZextShiftZext{}
	r.batchRule = newBatchRule(group, "zextshiftzext", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleZextShiftZext(g) })
	return r
}

func (r *RuleZextShiftZext) apply(op *PcodeOp, data *Funcdata) int {
	inner := definedBy(op.Input(0), CPUI_INT_ZEXT)
	if inner == nil {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_ZEXT, inner.Input(0))
	return 1
}

type RuleSubZext struct{ batchRule }

func NewRuleSubZext(group string) *RuleSubZext {
	r := &RuleSubZext{}
	r.batchRule = newBatchRule(group, "subzext", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubZext(g) })
	return r
}

func (r *RuleSubZext) apply(op *PcodeOp, data *Funcdata) int {
	ext := definedBy(op.Input(0), CPUI_INT_ZEXT)
	if ext == nil || !isZeroConst(op.Input(1)) || outputSize(op) != ext.Input(0).Size() {
		return 0
	}
	return rewriteToCopy(data, op, ext.Input(0))
}

// RuleSubZextMask simplifies INT_ZEXT applied to a SUBPIECE (optionally through an
// INT_RIGHT), turning the truncate-then-extend-to-same-size into an INT_AND mask:
//   - zext( sub(V,0) )       => V & mask
//   - zext( sub(V,c) )       => (V >> c*8) & mask
//   - zext( sub(V,c) >> d )  => (V >> (c*8+d)) & mask
// This keeps the full-width value V intact (e.g. a 64-bit INT_SDIV result stays
// 64-bit) and only masks the low logical bits, matching Ghidra's return-register
// rendering `x & 0xffffffff`. Because it is registered on INT_ZEXT ahead of
// RuleSubvarZext, it pre-empts the subvariable-flow narrowing that would otherwise
// remove the extension and let RuleSubCommute over-truncate a signed divide.
//
// The Go type is suffixed "Mask" only because the plain RuleSubZext identifier is
// already used by an unrelated SUBPIECE-cancel rule above; this is the faithful port.
// C++ parity: RuleSubZext::applyOp in ruleaction.cc (registered before
// RuleSubvarZext in coreaction.cc universalAction).
type RuleSubZextMask struct{ batchRule }

func NewRuleSubZextMask(group string) *RuleSubZextMask {
	r := &RuleSubZextMask{}
	r.batchRule = newBatchRule(group, "subzextmask", []OpCode{CPUI_INT_ZEXT}, r.apply, func(g string) Rule { return NewRuleSubZextMask(g) })
	return r
}

func (r *RuleSubZextMask) apply(op *PcodeOp, data *Funcdata) int {
	subvn := op.Input(0)
	if subvn == nil || !subvn.IsWritten() {
		return 0
	}
	subop := subvn.Def()
	switch subop.Code() {
	case CPUI_SUBPIECE:
		basevn := subop.Input(0)
		if basevn == nil || basevn.IsFree() {
			return 0
		}
		// Truncating then extending back to the same size.
		if basevn.Size() != outputSize(op) {
			return 0
		}
		if basevn.Size() > 8 {
			return 0
		}
		if subOffset, _ := constantValue(subop.Input(1)); subOffset != 0 {
			// Truncating from the middle: fold the byte offset into an INT_RIGHT
			// shift of the full value, but only when the truncated value has no
			// other use.
			if subvn.LoneDescend() != op {
				return 0
			}
			newvn := data.NewUnique(basevn.Size())
			constvn := subop.Input(1)
			rightVal := subOffset * 8
			data.OpSetInput(op, newvn, 0)
			data.OpSetOpcode(subop, CPUI_INT_RIGHT)
			data.OpSetInput(subop, data.NewConstant(constvn.Size(), rightVal), 1)
			data.OpSetOutput(subop, newvn)
		} else {
			// Bypass the truncation entirely.
			data.OpSetInput(op, basevn, 0)
		}
		val := maskForSize(subvn.Size())
		constvn := data.NewConstant(basevn.Size(), val)
		data.OpSetOpcode(op, CPUI_INT_AND)
		data.OpInsertInput(op, constvn, 1)
		return 1
	case CPUI_INT_RIGHT:
		shiftop := subop
		if !shiftop.Input(1).IsConstant() {
			return 0
		}
		midvn := shiftop.Input(0)
		if midvn == nil || !midvn.IsWritten() {
			return 0
		}
		innersub := midvn.Def()
		if innersub.Code() != CPUI_SUBPIECE {
			return 0
		}
		basevn := innersub.Input(0)
		if basevn == nil || basevn.IsFree() {
			return 0
		}
		if basevn.Size() != outputSize(op) {
			return 0
		}
		if midvn.LoneDescend() != shiftop || subvn.LoneDescend() != op {
			return 0
		}
		val := maskForSize(midvn.Size()) // mask based on truncated size
		sa, _ := constantValue(shiftop.Input(1))
		val >>= sa
		innerOff, _ := constantValue(innersub.Input(1))
		sa += innerOff * 8 // combined shift = truncation + small shift
		newvn := data.NewUnique(basevn.Size())
		data.OpSetInput(op, newvn, 0)
		data.OpSetInput(shiftop, basevn, 0)
		data.OpSetInput(shiftop, data.NewConstant(shiftop.Input(1).Size(), sa), 1)
		data.OpSetOutput(shiftop, newvn)
		constvn := data.NewConstant(basevn.Size(), val)
		data.OpSetOpcode(op, CPUI_INT_AND)
		data.OpInsertInput(op, constvn, 1)
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

func (r *RuleSubExtComm) apply(op *PcodeOp, data *Funcdata) int {
	if !isZeroConst(op.Input(1)) {
		return 0
	}
	for _, opc := range []OpCode{CPUI_INT_ZEXT, CPUI_INT_SEXT} {
		ext := definedBy(op.Input(0), opc)
		if ext == nil {
			continue
		}
		base := ext.Input(0)
		if outputSize(op) == base.Size() {
			return rewriteToCopy(data, op, base)
		}
		if outputSize(op) < base.Size() {
			rewriteOp(data, op, CPUI_SUBPIECE, base, data.NewConstant(op.Input(1).Size(), 0))
			return 1
		}
	}
	return 0
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

func (r *RuleSubCommute) apply(op *PcodeOp, data *Funcdata) int {
	base := op.Input(0)
	if base == nil || !base.IsWritten() {
		return 0
	}
	offset, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	// Precis lo/hi varnodes are managed by PIECE reconstruction -- do not disturb.
	if outvn.IsPrecisLo() || outvn.IsPrecisHi() {
		return 0
	}
	longform := base.Def()
	if longform == nil {
		return 0
	}
	// Determine whether SUBPIECE commutes through this opcode.
	// INT_MULT and INT_ADD only commute when truncating the low part (offset==0).
	// Bitwise ops commute regardless of offset.
	// INT_SDIV/INT_SREM/INT_DIV/INT_REM also commute at offset==0: used to
	// cancel the CDQ+IDIV pattern where SUBPIECE(INT_SREM(INT_SEXT(x), ...), 0, n)
	// is pushed through to INT_SREM(SUBPIECE(INT_SEXT(x), 0, n), ...) and then
	// RuleSubExtComm collapses SUBPIECE(INT_SEXT(x), 0, n) -> x.
	// C++ parity: RuleSubCommute::applyOp handles INT_SDIV/INT_SREM at lines
	// 4590-4621 in ruleaction.cc (Ghidra), pushing SUBPIECE through the op and
	// canceling the SEXT of each input when sizes match.
	switch longform.Code() {
	case CPUI_INT_MULT, CPUI_INT_ADD:
		if offset != 0 {
			return 0
		}
		// Deconflict INT_ADD with RulePtrArith: skip if input 0 is spacebase.
		if longform.Code() == CPUI_INT_ADD && longform.Input(0) != nil && longform.Input(0).IsSpaceBase() {
			return 0
		}
	case CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR:
		// commutes for any offset
	case CPUI_INT_SDIV, CPUI_INT_SREM, CPUI_INT_DIV, CPUI_INT_REM:
		if offset != 0 {
			return 0
		}
	default:
		return 0
	}

	// base must be consumed only by this SUBPIECE.
	if base.LoneDescend() != op {
		return 0
	}

	// Overlap check with RuleSubZext: if the sole consumer of outvn is an INT_ZEXT
	// that restores the original size, let RuleSubZext handle it instead.
	if offset == 0 {
		next := outvn.LoneDescend()
		if next != nil && next.Code() == CPUI_INT_ZEXT && next.Output() != nil &&
			next.Output().Size() == int32(base.Size()) {
			return 0
		}
	}

	// Push SUBPIECE through each input of longform.
	// Track the last input varnode so we can reuse the same SUBPIECE op when
	// both inputs are the same varnode (INT_MULT x,x corner case).
	var lastIn *Varnode
	var newVn *Varnode
	outSize := outvn.Size()
	for i := 0; i < longform.NumInput(); i++ {
		vn := longform.Input(i)
		if vn == nil {
			return 0
		}
		if lastIn != vn || newVn == nil {
			newsub := data.NewOp(2, op.Seq().Address)
			data.OpSetOpcode(newsub, CPUI_SUBPIECE)
			newVn = data.NewUniqueOut(outSize, newsub)
			// Set the new varnode as the ith input of longform before wiring newsub
			// inputs, because vn may still be free (not yet in the bank).
			data.OpSetInput(longform, newVn, i)
			data.OpSetInput(newsub, vn, 0)
			data.OpSetInput(newsub, data.NewConstant(4, offset), 1)
			data.OpInsertBefore(newsub, longform)
		} else {
			// Same varnode -- reuse the already-created SUBPIECE output.
			data.OpSetInput(longform, newVn, i)
		}
		lastIn = vn
	}
	// Redirect longform's output to reuse outvn (which is the SUBPIECE output).
	data.OpUnsetOutput(longform)
	data.OpSetOutput(longform, outvn)
	// Decouple op from outvn before destruction. OpDestroy calls OpUnsetOutput(op),
	// which would call MakeFree(outvn) and clear outvn.def -- even though outvn was
	// just assigned to longform above. Clearing op.output here prevents that.
	// C++ parity: after opSetOutput(longform, outvn), op->output is no longer the
	// canonical owner of outvn; destroying op must not touch outvn's bank entry.
	op.SetOutput(nil)
	// Destroy the now-redundant SUBPIECE.
	data.OpDestroy(op)
	return 1
}

// RuleOrSextForm collapses the OR-based sign-extension form back to INT_SEXT.
// This pattern appears in x86 CDQ+IDIV pcode where Gosleigh's packed .sla
// encodes the EDX:EAX 64-bit dividend as:
//
//	INT_OR(INT_LEFT(INT_ZEXT(INT_SRIGHT(x, n-1)), n), INT_ZEXT(x))
//
// which is semantically equivalent to INT_SEXT(x). After RuleSignForm converts
// CDQ's SUBPIECE(INT_SEXT(EAX), 4, 4) → INT_SRIGHT(EAX, 31), this rule
// collapses the full dividend expression, allowing RuleSubCommute to then push
// SUBPIECE through INT_SREM/INT_SDIV and cancel the SEXTs.
//
// C++ parity: Ghidra's x86 Sleigh emits PIECE(EDX, EAX) for IDIV which
// RulePiece2Sext handles. Gosleigh's packed .sla emits the INT_OR form;
// this rule provides an equivalent simplification path.
type RuleOrSextForm struct{ batchRule }

func NewRuleOrSextForm(group string) *RuleOrSextForm {
	r := &RuleOrSextForm{}
	r.batchRule = newBatchRule(group, "orsextform", []OpCode{CPUI_INT_OR}, r.apply,
		func(g string) Rule { return NewRuleOrSextForm(g) })
	return r
}

func (r *RuleOrSextForm) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	// Try both slot orders for INT_OR(shifted_sign, base) and INT_OR(base, shifted_sign).
	for slot := 0; slot < 2; slot++ {
		shifted := op.Input(slot)
		baseZext := op.Input(1 - slot)
		// The base side must be INT_ZEXT(x).
		zextBase := definedBy(baseZext, CPUI_INT_ZEXT)
		if zextBase == nil {
			continue
		}
		x := zextBase.Input(0)
		if x == nil || x.IsFree() {
			continue
		}
		n := uint64(x.Size()) * 8 // bit width of x
		// The shifted side must be INT_LEFT(..., n) or INT_MULT(..., 2^n).
		// RuleShift2Mult in BatchA may convert INT_LEFT to INT_MULT before this
		// rule sees the INT_OR op (ops are visited in instruction-address order),
		// so we must accept both forms.
		var signInput *Varnode
		if leftOp := definedBy(shifted, CPUI_INT_LEFT); leftOp != nil && leftOp.NumInput() >= 2 {
			shiftAmt, shiftOK := constantValue(leftOp.Input(1))
			if !shiftOK || shiftAmt != n {
				continue
			}
			signInput = leftOp.Input(0)
		} else if multOp := definedBy(shifted, CPUI_INT_MULT); multOp != nil && multOp.NumInput() >= 2 {
			multConst, multOK := constantValue(multOp.Input(1))
			if !multOK || multConst != uint64(1)<<n {
				continue
			}
			signInput = multOp.Input(0)
		} else {
			continue
		}
		// signInput must be INT_ZEXT(INT_SRIGHT(x, n-1)).
		zextSign := definedBy(signInput, CPUI_INT_ZEXT)
		if zextSign == nil {
			continue
		}
		sright := definedBy(zextSign.Input(0), CPUI_INT_SRIGHT)
		if sright == nil || sright.NumInput() < 2 {
			continue
		}
		if sright.Input(0) != x {
			continue
		}
		signShift, ok := constantValue(sright.Input(1))
		if !ok || signShift != n-1 {
			continue
		}
		// Pattern matched: collapse to INT_SEXT(x).
		rewriteOp(data, op, CPUI_INT_SEXT, x)
		return 1
	}
	return 0
}

type RuleBoolZext struct{ batchRule }

func NewRuleBoolZext(group string) *RuleBoolZext {
	r := &RuleBoolZext{}
	r.batchRule = newBatchRule(group, "boolzext", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleBoolZext(g) })
	return r
}

func (r *RuleBoolZext) apply(op *PcodeOp, data *Funcdata) int {
	lhs, _, val, ok := normalizeCompareConst(op)
	if !ok || val > 1 {
		return 0
	}
	ext := definedBy(lhs, CPUI_INT_ZEXT)
	if ext == nil || !isBoolLike(ext.Input(0)) {
		return 0
	}
	negate := op.Code() == CPUI_INT_NOTEQUAL
	if val == 0 {
		negate = !negate
	}
	if negate {
		rewriteOp(data, op, CPUI_BOOL_NEGATE, ext.Input(0))
		return 1
	}
	return rewriteToCopy(data, op, ext.Input(0))
}
