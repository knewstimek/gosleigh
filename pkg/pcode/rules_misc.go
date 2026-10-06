package pcode

import (
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
	if n := piecePathologyApply(op, data); n > 0 {
		return n
	}
	// Go-local: PIECE(SUBPIECE(x,k), SUBPIECE(x,0)) folds back to x. Not part
	// of the C++ rule; kept because the corpus goldens depend on it.
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
	// RuleNotDistribute::applyOp -- ruleaction.cc:1139. Boolean De Morgan:
	//   !(V && W)  =>  !V || !W
	// This is a BOOL_NEGATE rule. An earlier Gosleigh rule carrying the same name
	// distributed INT_NEGATE over INT_AND/INT_OR instead. That bitwise form has no
	// C++ counterpart and no inverse here (RuleBitUndistribute is still a stub), so
	// it was a one-way expansion that could leak `~a | ~b` into output; it is gone.
	r.batchRule = newBatchRule(group, "notdistribute", []OpCode{CPUI_BOOL_NEGATE}, r.apply, func(g string) Rule { return NewRuleNotDistribute(g) })
	return r
}

func (r *RuleNotDistribute) apply(op *PcodeOp, data *Funcdata) int {
	compop := op.Input(0).Def()
	if compop == nil {
		return 0
	}
	var opc OpCode
	switch compop.Code() {
	case CPUI_BOOL_AND:
		opc = CPUI_BOOL_OR
	case CPUI_BOOL_OR:
		opc = CPUI_BOOL_AND
	default:
		return 0
	}

	newneg1 := data.NewOp(1, op.Addr())
	newout1 := data.NewUniqueOut(1, newneg1)
	data.OpSetOpcode(newneg1, CPUI_BOOL_NEGATE)
	data.OpSetInput(newneg1, compop.Input(0), 0)
	data.OpInsertBefore(newneg1, op)

	newneg2 := data.NewOp(1, op.Addr())
	newout2 := data.NewUniqueOut(1, newneg2)
	data.OpSetOpcode(newneg2, CPUI_BOOL_NEGATE)
	data.OpSetInput(newneg2, compop.Input(1), 0)
	data.OpInsertBefore(newneg2, op)

	// op is unary BOOL_NEGATE; it grows to the binary opc, so slot 1 is inserted.
	data.OpSetOpcode(op, opc)
	data.OpSetInput(op, newout1, 0)
	data.OpInsertInput(op, newout2, 1)
	return 1
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

// apply is a faithful port of RuleAndDistribute::applyOp (ruleaction.cc:1260),
// distributing INT_AND through INT_OR -- (A|B) & other => (A&other) | (B&other) --
// but ONLY when the result is genuinely simpler.
//
// The prior Go body distributed on any constant mask with no benefit test, which
// is both a parity divergence (C++ never distributes unconditionally) and the
// source of a would-be oscillation with RuleHumptyOr (the reverse factoring). The
// guards below are what make the two mutually exclusive: distribute only if a side
// cancels under the mask ((ormask & othermask)==0) or, for a constant mask, a side
// is fully covered (trivial); skip othermask==0 (RuleAndMask's job) and
// othermask==fullmask (no gain). other may be non-constant (heritage-known), as in
// C++. New ANDs are spliced with NewOpBefore (proper block insertion).
func (r *RuleAndDistribute) apply(op *PcodeOp, data *Funcdata) int {
	out := op.Output()
	if out == nil {
		return 0
	}
	size := out.Size()
	if size > 8 { // C++: size > sizeof(uintb)
		return 0
	}
	fullmask := maskForSize(size)
	var orop *PcodeOp
	var othervn *Varnode
	found := false
	for i := 0; i < 2 && !found; i++ {
		othervn = op.Input(1 - i)
		if !othervn.IsHeritageKnown() {
			continue
		}
		orvn := op.Input(i)
		orop = orvn.Def()
		if orop == nil || orop.Code() != CPUI_INT_OR {
			continue
		}
		if !orop.Input(0).IsHeritageKnown() || !orop.Input(1).IsHeritageKnown() {
			continue
		}
		othermask := othervn.NZMask()
		if othermask == 0 { // this case picked up by RuleAndMask
			continue
		}
		if othermask == fullmask { // nothing useful from distributing
			continue
		}
		ormask1 := orop.Input(0).NZMask()
		if ormask1&othermask == 0 { // AND would cancel if distributed
			found = true
			break
		}
		ormask2 := orop.Input(1).NZMask()
		if ormask2&othermask == 0 { // AND would cancel if distributed
			found = true
			break
		}
		if othervn.IsConstant() {
			if ormask1&othermask == ormask1 { // AND is trivial if distributed
				found = true
				break
			}
			if ormask2&othermask == ormask2 {
				found = true
				break
			}
		}
	}
	if !found {
		return 0
	}
	newop1 := data.NewOpBefore(op, CPUI_INT_AND, orop.Input(0), othervn)
	newvn1 := data.NewUniqueOut(size, newop1)
	newop2 := data.NewOpBefore(op, CPUI_INT_AND, orop.Input(1), othervn)
	newvn2 := data.NewUniqueOut(size, newop2)
	rewriteOp(data, op, CPUI_INT_OR, newvn1, newvn2)
	return 1
}

type RuleAndCompare struct{ batchRule }

func NewRuleAndCompare(group string) *RuleAndCompare {
	r := &RuleAndCompare{}
	r.batchRule = newBatchRule(group, "andcompare", []OpCode{CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleAndCompare(g) })
	return r
}

// apply widens (sub(V) & c) == 0 or (zext(V) & c) == 0 into a test on V
// itself. C++ parity: RuleAndCompare::applyOp.
func (r *RuleAndCompare) apply(op *PcodeOp, data *Funcdata) int {
	if !op.Input(1).IsConstant() || op.Input(1).Offset() != 0 {
		return 0
	}
	andvn := op.Input(0)
	if !andvn.IsWritten() {
		return 0
	}
	andop := andvn.Def()
	if andop.Code() != CPUI_INT_AND || !andop.Input(1).IsConstant() {
		return 0
	}
	subvn := andop.Input(0)
	if !subvn.IsWritten() {
		return 0
	}
	subop := subvn.Def()
	var basevn *Varnode
	var andconst, baseconst uint64
	switch subop.Code() {
	case CPUI_SUBPIECE:
		basevn = subop.Input(0)
		if basevn.Size() > 8 {
			return 0
		}
		baseconst = andop.Input(1).Offset()
		andconst = baseconst << (subop.Input(1).Offset() * 8)
	case CPUI_INT_ZEXT:
		basevn = subop.Input(0)
		baseconst = andop.Input(1).Offset()
		andconst = baseconst & maskForSize(basevn.Size())
	default:
		return 0
	}
	if baseconst == maskForSize(andvn.Size()) {
		return 0 // degenerate AND
	}
	if basevn.IsFree() {
		return 0
	}
	constvn := data.NewConstant(basevn.Size(), andconst)
	if baseconst == andconst {
		constvn.copySymbol(andop.Input(1)) // keep any old symbol
	}
	newop := data.NewOp(2, andop.Addr())
	data.OpSetOpcode(newop, CPUI_INT_AND)
	newout := data.NewUniqueOut(basevn.Size(), newop)
	data.OpSetInput(newop, basevn, 0)
	data.OpSetInput(newop, constvn, 1)
	data.OpInsertBefore(newop, andop)
	data.OpSetInput(op, newout, 0)
	data.OpSetInput(op, data.NewConstant(basevn.Size(), 0), 1)
	return 1
}

type RuleDoubleSub struct{ batchRule }

func NewRuleDoubleSub(group string) *RuleDoubleSub {
	r := &RuleDoubleSub{}
	r.batchRule = newBatchRule(group, "doublesub", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleDoubleSub(g) })
	return r
}

// apply is a faithful port of RuleDoubleSub::applyOp (ruleaction.cc:1806-1823),
// collapsing chained SUBPIECE: sub(sub(V,c), d) => sub(V, c+d).
//
// The prior body under this name folded chained INT_SUB constants
// ((V-c1)-c2 => V-(c1+c2)), which is dead: RuleSub2Add rewrites every INT_SUB
// into V + (W * -1) before a second INT_SUB could stack, so that path never
// fired. The C++ core has no such INT_SUB rule; additive constants fold through
// RuleSub2Add + RuleCollectTerms instead.
//
// SUBPIECE's truncation operand is a constant by p-code invariant, so the
// offsets are read directly (matching C++, which does not gate on isConstant).
func (r *RuleDoubleSub) apply(op *PcodeOp, data *Funcdata) int {
	inner := definedBy(op.Input(0), CPUI_SUBPIECE)
	if inner == nil {
		return 0
	}
	offset1 := op.Input(1).Offset()
	offset2 := inner.Input(1).Offset()
	data.OpSetInput(op, inner.Input(0), 0) // skip middleman
	data.OpSetInput(op, data.NewConstant(4, offset1+offset2), 1)
	return 1
}

type RuleDoubleShift struct{ batchRule }

func NewRuleDoubleShift(group string) *RuleDoubleShift {
	r := &RuleDoubleShift{}
	r.batchRule = newBatchRule(group, "doubleshift", []OpCode{CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRuleDoubleShift(g) })
	return r
}

// apply simplifies chained INT_LEFT/INT_RIGHT shifts, treating a power-of-2
// INT_MULT as an INT_LEFT. Same-direction shifts combine (or zero out); opposite
// directions cancel into an INT_AND mask, possibly leaving a residual shift.
// C++ parity: ruleaction.cc RuleDoubleShift::applyOp (lines 1842-1930).
func (r *RuleDoubleShift) apply(op *PcodeOp, data *Funcdata) int {
	if !op.Input(1).IsConstant() {
		return 0
	}
	secvn := op.Input(0)
	if !secvn.IsWritten() {
		return 0
	}
	secop := secvn.Def()
	opc2 := secop.Code()
	if opc2 != CPUI_INT_LEFT && opc2 != CPUI_INT_RIGHT && opc2 != CPUI_INT_MULT {
		return 0
	}
	if !secop.Input(1).IsConstant() {
		return 0
	}
	opc1 := op.Code()
	size := secvn.Size()
	if !secop.Input(0).IsHeritageKnown() {
		return 0
	}

	var sa1, sa2 int
	if opc1 == CPUI_INT_MULT {
		val := op.Input(1).Offset()
		sa1 = leastSigBitSet(val)
		if (val >> uint(sa1)) != 1 { // Not multiplying by a power of 2
			return 0
		}
		opc1 = CPUI_INT_LEFT
	} else {
		sa1 = int(op.Input(1).Offset())
	}
	if opc2 == CPUI_INT_MULT {
		val := secop.Input(1).Offset()
		sa2 = leastSigBitSet(val)
		if (val >> uint(sa2)) != 1 { // Not multiplying by a power of 2
			return 0
		}
		opc2 = CPUI_INT_LEFT
	} else {
		sa2 = int(secop.Input(1).Offset())
	}

	if opc1 == opc2 { // Shifts in the same direction
		if sa1+sa2 < 8*int(size) {
			newvn := data.NewConstant(4, uint64(sa1+sa2))
			data.OpSetOpcode(op, opc1)
			data.OpSetInput(op, secop.Input(0), 0)
			data.OpSetInput(op, newvn, 1)
		} else {
			newvn := data.NewConstant(size, 0)
			data.OpSetOpcode(op, CPUI_COPY)
			data.OpSetInput(op, newvn, 0)
			data.OpRemoveInput(op, 1)
		}
	} else { // Shifts in opposite directions
		if int(size) > 8 { // FIXME: precision (sizeof(uintb))
			return 0
		}
		mask := maskForSize(size)
		var diffsa int // Bits (to the left) after cancellation
		if opc1 == CPUI_INT_LEFT {
			// The INT_LEFT is highly likely to be a multiply
			if secvn.LoneDescend() == nil {
				return 0
			}
			mask = (mask << uint(sa2)) & mask // Most significant bits remain after initial INT_RIGHT
			diffsa = sa1 - sa2
			if diffsa != 0 { // Don't collapse unless shift amounts are identical
				return 0
			}
		} else {
			mask = (mask >> uint(sa2)) & mask // Least significant bits remain after initial INT_LEFT
			diffsa = sa2 - sa1
		}
		if diffsa == 0 { // Opposite shifts exactly cancel
			newvn := data.NewConstant(size, mask)
			data.OpSetOpcode(op, CPUI_INT_AND)
			data.OpSetInput(op, secop.Input(0), 0)
			data.OpSetInput(op, newvn, 1)
		} else { // Shifts only partly cancel
			newAnd := data.NewOp(2, op.Addr())
			data.OpSetOpcode(newAnd, CPUI_INT_AND)
			data.OpSetInput(newAnd, secop.Input(0), 0)
			data.OpSetInput(newAnd, data.NewConstant(size, mask), 1)
			newOut := data.NewUniqueOut(size, newAnd)
			data.OpInsertBefore(newAnd, op)
			finalopc := CPUI_INT_LEFT
			if diffsa < 0 {
				finalopc = CPUI_INT_RIGHT
				diffsa = -diffsa
			}
			data.OpSetOpcode(op, finalopc)
			data.OpSetInput(op, newOut, 0)
			data.OpSetInput(op, data.NewConstant(4, uint64(diffsa)), 1)
		}
	}
	return 1
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

// apply moves a shift by a constant off one side of an (in)equality with a
// constant: (V << c) == d becomes V == d >> c when no bits are lost.
// C++ parity: RuleShiftCompare::applyOp.
func (r *RuleShiftCompare) apply(op *PcodeOp, data *Funcdata) int {
	shiftvn, constvn := op.Input(0), op.Input(1)
	if !constvn.IsConstant() || !shiftvn.IsWritten() {
		return 0
	}
	shiftop := shiftvn.Def()
	if shiftop.NumInput() != 2 { // none of the shift forms below
		return 0
	}
	savn := shiftop.Input(1)
	var sa int
	var isleft bool
	switch shiftop.Code() {
	case CPUI_INT_LEFT:
		if !savn.IsConstant() {
			return 0
		}
		isleft, sa = true, int(savn.Offset())
	case CPUI_INT_RIGHT:
		if !savn.IsConstant() {
			return 0
		}
		sa = int(savn.Offset())
		// A right shift likely extracts a bit field; only apply when the
		// shift variable goes away.
		if shiftvn.LoneDescend() != op {
			return 0
		}
	case CPUI_INT_MULT:
		if !savn.IsConstant() {
			return 0
		}
		val := savn.Offset()
		sa = leastSigBitSet(val)
		if val>>uint(sa) != 1 { // not a power of 2
			return 0
		}
		isleft = true
	case CPUI_INT_DIV:
		if !savn.IsConstant() {
			return 0
		}
		val := savn.Offset()
		sa = leastSigBitSet(val)
		if val>>uint(sa) != 1 || shiftvn.LoneDescend() != op {
			return 0
		}
	default:
		return 0
	}
	if sa == 0 {
		return 0
	}
	mainvn := shiftop.Input(0)
	if mainvn.IsFree() || mainvn.Size() > 8 {
		return 0
	}
	constval := constvn.Offset()
	nzmask := mainvn.NZMask()
	var newconst uint64
	if isleft {
		newconst = constval >> uint(sa)
		if newconst<<uint(sa) != constval { // information lost in constval
			return 0
		}
		tmp := (nzmask << uint(sa)) & bitfieldSizeMask(shiftvn.Size())
		if tmp>>uint(sa) != nzmask {
			// Information is lost in main: replace the LEFT with an AND
			// mask, which needs to be the lone use of the shift.
			if shiftvn.LoneDescend() != op {
				return 0
			}
			sa = 8*int(shiftvn.Size()) - sa
			newmask := data.NewConstant(constvn.Size(), uint64(1)<<uint(sa)-1)
			newop := data.NewOp(2, op.Addr())
			data.OpSetOpcode(newop, CPUI_INT_AND)
			newtmpvn := data.NewUniqueOut(constvn.Size(), newop)
			data.OpSetInput(newop, mainvn, 0)
			data.OpSetInput(newop, newmask, 1)
			data.OpInsertBefore(newop, shiftop)
			data.OpSetInput(op, newtmpvn, 0)
			data.OpSetInput(op, data.NewConstant(constvn.Size(), newconst), 1)
			return 1
		}
	} else {
		if (nzmask>>uint(sa))<<uint(sa) != nzmask { // information is lost
			return 0
		}
		newconst = (constval << uint(sa)) & bitfieldSizeMask(shiftvn.Size())
		if newconst>>uint(sa) != constval { // information lost in constval
			return 0
		}
	}
	data.OpSetInput(op, mainvn, 0)
	data.OpSetInput(op, data.NewConstant(constvn.Size(), newconst), 1)
	return 1
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

// RuleSLessEqual2Constant was an invented (non-C++) rule that rewrote
// INT_SLESSEQUAL(x, C) -> INT_SLESS(x, C+1) for a constant RHS only. It is now
// removed: RuleIntLessEqual (ruleaction.cc RuleIntLessEqual, via replaceLessequal)
// faithfully handles both constant-left and constant-right SLESSEQUAL/LESSEQUAL,
// making this special case redundant.

type RuleThreeWayCompare struct{ batchRule }

func NewRuleThreeWayCompare(group string) *RuleThreeWayCompare {
	r := &RuleThreeWayCompare{}
	r.batchRule = newBatchRule(group, "threewaycomp", []OpCode{CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL}, r.apply, func(g string) Rule { return NewRuleThreeWayCompare(g) })
	return r
}

// apply simplifies a comparison of a three-way compare
// zext(V < W) + zext(V <= W) - 1 against -1, 0, 1 or 2.
// C++ parity: RuleThreeWayCompare::applyOp.
func (r *RuleThreeWayCompare) apply(op *PcodeOp, data *Funcdata) int {
	constSlot := 0
	tmpvn := op.Input(constSlot)
	if !tmpvn.IsConstant() { // one input must be a constant
		constSlot = 1
		tmpvn = op.Input(constSlot)
		if !tmpvn.IsConstant() {
			return 0
		}
	}
	// Encode the constant (-1, 0, 1, 2) as the top bits of form.
	var form int
	switch val := tmpvn.Offset(); {
	case val <= 2:
		form = int(val) + 1
	case val == bitfieldSizeMask(tmpvn.Size()):
		form = 0
	default:
		return 0
	}
	tmpvn = op.Input(1 - constSlot)
	if !tmpvn.IsWritten() || tmpvn.Def().Code() != CPUI_INT_ADD {
		return 0
	}
	lessop, isPartial := detectThreeWay(tmpvn.Def())
	if lessop == nil {
		return 0
	}
	if isPartial { // complete the partial three-way by subtracting 1
		if form == 0 {
			return 0 // -1 is now out of range
		}
		form--
	}
	form <<= 1
	if constSlot == 1 {
		form++
	}
	lessform := lessop.Code() // INT_LESS, INT_SLESS or FLOAT_LESS
	form <<= 2
	switch op.Code() {
	case CPUI_INT_SLESSEQUAL:
		form++
	case CPUI_INT_EQUAL:
		form += 2
	case CPUI_INT_NOTEQUAL:
		form += 3
	}
	bvn := lessop.Input(0) // second parameter of the cmp3way function
	avn := lessop.Input(1) // first parameter
	if (!avn.IsConstant() && avn.IsFree()) || (!bvn.IsConstant() && bvn.IsFree()) {
		return 0
	}
	set := func(opc OpCode, in0, in1 *Varnode) {
		data.OpSetOpcode(op, opc)
		data.OpSetInput(op, in0, 0)
		data.OpSetInput(op, in1, 1)
	}
	switch form {
	case 1, 21: // -1 s<= threeway, threeway s<= 1: always true
		set(CPUI_INT_EQUAL, data.NewConstant(1, 0), data.NewConstant(1, 0))
	case 4, 16: // threeway s< -1, 1 s< threeway: always false
		set(CPUI_INT_NOTEQUAL, data.NewConstant(1, 0), data.NewConstant(1, 0))
	case 2, 5, 6, 12: // a < b
		set(lessform, avn, bvn)
	case 13, 19, 20, 23: // a <= b
		set(lessform+1, avn, bvn)
	case 8, 17, 18, 22: // a > b
		set(lessform, bvn, avn)
	case 0, 3, 7, 9: // a >= b
		set(lessform+1, bvn, avn)
	case 10, 14: // a == b
		if lessform == CPUI_FLOAT_LESS {
			set(CPUI_FLOAT_EQUAL, avn, bvn)
		} else {
			set(CPUI_INT_EQUAL, avn, bvn)
		}
	case 11, 15: // a != b
		if lessform == CPUI_FLOAT_LESS {
			set(CPUI_FLOAT_NOTEQUAL, avn, bvn)
		} else {
			set(CPUI_INT_NOTEQUAL, avn, bvn)
		}
	default:
		return 0
	}
	return 1
}

// detectThreeWay matches zext(V < W) + zext(V <= W) - 1 (in any of its
// association orders) at the INT_ADD op and returns the less-than op. A
// missing - 1 is reported as partial.
// C++ parity: RuleThreeWayCompare::detectThreeWay.
func detectThreeWay(op *PcodeOp) (*PcodeOp, bool) {
	isPartial := false
	defOf := func(vn *Varnode, opc OpCode) *PcodeOp {
		if !vn.IsWritten() || vn.Def().Code() != opc {
			return nil
		}
		return vn.Def()
	}
	isMinusOne := func(vn *Varnode) bool {
		return vn.IsConstant() && vn.Offset() == bitfieldSizeMask(vn.Size())
	}
	var zext1, zext2 *PcodeOp
	vn2 := op.Input(1)
	switch {
	case vn2.IsConstant(): // (z + z) - 1
		if !isMinusOne(vn2) {
			return nil, false
		}
		addop := defOf(op.Input(0), CPUI_INT_ADD)
		if addop == nil {
			return nil, false
		}
		zext1 = defOf(addop.Input(0), CPUI_INT_ZEXT)
		zext2 = defOf(addop.Input(1), CPUI_INT_ZEXT)
	case vn2.IsWritten():
		tmpop := vn2.Def()
		switch tmpop.Code() {
		case CPUI_INT_ZEXT: // (z - 1) + z
			zext2 = tmpop
			vn1 := op.Input(0)
			if !vn1.IsWritten() {
				return nil, false
			}
			addop := vn1.Def()
			if addop.Code() != CPUI_INT_ADD { // partial form: z + z
				if addop.Code() != CPUI_INT_ZEXT {
					return nil, false
				}
				zext1 = addop
				isPartial = true
			} else {
				if !isMinusOne(addop.Input(1)) {
					return nil, false
				}
				zext1 = defOf(addop.Input(0), CPUI_INT_ZEXT)
			}
		case CPUI_INT_ADD: // z + (z - 1)
			addop := tmpop
			zext1 = defOf(op.Input(0), CPUI_INT_ZEXT)
			if zext1 == nil || !isMinusOne(addop.Input(1)) {
				return nil, false
			}
			zext2 = defOf(addop.Input(0), CPUI_INT_ZEXT)
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	if zext1 == nil || zext2 == nil {
		return nil, false
	}
	vn1, vn2 := zext1.Input(0), zext2.Input(0)
	if !vn1.IsWritten() || !vn2.IsWritten() {
		return nil, false
	}
	lessop, lessequalop := vn1.Def(), vn2.Def()
	switch lessop.Code() {
	case CPUI_INT_LESS, CPUI_INT_SLESS, CPUI_FLOAT_LESS:
	default: // make sure the first zext is the less-than
		lessop, lessequalop = lessequalop, lessop
	}
	form := threeWayCompareEquivalence(lessop, lessequalop)
	if form < 0 {
		return nil, false
	}
	if form == 1 {
		lessop = lessequalop
	}
	return lessop, isPartial
}

// threeWayCompareEquivalence checks that the two comparisons of a three-way
// compare share their operands, allowing V < W+1 in place of V <= W.
// Returns -1 on no match, 0 on a match, 1 when the ops must be swapped.
// C++ parity: RuleThreeWayCompare::testCompareEquivalence.
func threeWayCompareEquivalence(lessop, lessequalop *PcodeOp) int {
	var twoLessThan bool
	switch lessop.Code() {
	case CPUI_INT_LESS:
		switch lessequalop.Code() {
		case CPUI_INT_LESSEQUAL:
		case CPUI_INT_LESS:
			twoLessThan = true
		default:
			return -1
		}
	case CPUI_INT_SLESS:
		switch lessequalop.Code() {
		case CPUI_INT_SLESSEQUAL:
		case CPUI_INT_SLESS:
			twoLessThan = true
		default:
			return -1
		}
	case CPUI_FLOAT_LESS:
		if lessequalop.Code() != CPUI_FLOAT_LESSEQUAL {
			return -1 // no partial form for floating-point
		}
	default:
		return -1
	}
	a1, a2 := lessop.Input(0), lessequalop.Input(0)
	b1, b2 := lessop.Input(1), lessequalop.Input(1)
	res := 0
	if a1 != a2 {
		if !a1.IsConstant() || !a2.IsConstant() {
			return -1
		}
		if a1.Offset() != a2.Offset() && twoLessThan {
			switch {
			case a2.Offset()+1 == a1.Offset(): // lessequalop is a LESSTHAN acting as LESSEQUAL
				twoLessThan = false
			case a1.Offset()+1 == a2.Offset(): // lessop is the LESSEQUAL: swap
				twoLessThan = false
				res = 1
			default:
				return -1
			}
		}
	}
	if b1 != b2 {
		if !b1.IsConstant() || !b2.IsConstant() {
			return -1
		}
		// C++ returns -1 here unless the constants differ under two
		// LESSTHANs, even when they are equal; kept as is.
		if b1.Offset() != b2.Offset() && twoLessThan {
			if b1.Offset()+1 == b2.Offset() {
				twoLessThan = false
			} else if b2.Offset()+1 == b1.Offset() {
				twoLessThan = false
				res = 1
			}
		} else {
			return -1
		}
	}
	if twoLessThan {
		return -1 // two LESSTHANs whose constants did not compensate
	}
	return res
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
	// C++ parity: RuleOrCompare fires on CPUI_INT_OR (ruleaction.cc:10805-10874).
	// `(V | W) == 0` => `(V==0) && (W==0)`
	// `(V | W) != 0` => `(V!=0) || (W!=0)`
	r.batchRule = newBatchRule(group, "orcompare", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleOrCompare(g) })
	return r
}

// apply is the faithful port of RuleOrCompare::applyOp (ruleaction.cc:10816-10874).
// The rule only fires when EVERY descendant of the INT_OR's output is an
// INT_EQUAL/INT_NOTEQUAL comparison against constant 0 -- a single
// non-matching descendant blocks the rule entirely (C++ early "return 0"
// inside the scan loop).
func (r *RuleOrCompare) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	// Snapshot descendants up front. The rewrite loop below reassigns each
	// comparison's inputs (data.OpSetInput), which detaches it from outvn's
	// live descend list mid-iteration -- C++ guards the same hazard by
	// advancing its list iterator before mutating; a snapshot slice is the
	// Go-idiomatic equivalent.
	descendants := outvn.DescendIter()

	hasCompares := false
	for _, compOp := range descendants {
		opc := compOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			return 0
		}
		if !isZeroConst(compOp.Input(1)) {
			return 0
		}
		hasCompares = true
	}
	if !hasCompares {
		return 0
	}

	v := op.Input(0)
	w := op.Input(1)
	// C++ parity: ruleaction.cc:10838-10839 -- V and W must be in SSA form.
	if v.IsFree() {
		return 0
	}
	if w.IsFree() {
		return 0
	}

	for _, equalOp := range descendants {
		opc := equalOp.Code()

		zeroV := data.NewConstant(v.Size(), 0)
		zeroW := data.NewConstant(w.Size(), 0)

		eqV := data.NewOp(2, equalOp.Addr())
		data.OpSetOpcode(eqV, opc)
		data.OpSetInput(eqV, v, 0)
		data.OpSetInput(eqV, zeroV, 1)

		eqW := data.NewOp(2, equalOp.Addr())
		data.OpSetOpcode(eqW, opc)
		data.OpSetInput(eqW, w, 0)
		data.OpSetInput(eqW, zeroW, 1)

		eqVOut := data.NewUniqueOut(1, eqV)
		eqWOut := data.NewUniqueOut(1, eqW)

		// Make sure the split comparisons are already defined before the
		// original op is rewired to consume them.
		data.OpInsertBefore(eqV, equalOp)
		data.OpInsertBefore(eqW, equalOp)

		// The original INT_EQUAL becomes BOOL_AND; INT_NOTEQUAL becomes BOOL_OR.
		joinOpc := CPUI_BOOL_AND
		if opc == CPUI_INT_NOTEQUAL {
			joinOpc = CPUI_BOOL_OR
		}
		data.OpSetOpcode(equalOp, joinOpc)
		data.OpSetInput(equalOp, eqVOut, 0)
		data.OpSetInput(equalOp, eqWOut, 1)
	}

	return 1
}

type RuleConditionalMove struct{ batchRule }

func NewRuleConditionalMove(group string) *RuleConditionalMove {
	r := &RuleConditionalMove{}
	r.batchRule = newBatchRule(group, "conditionalmove", []OpCode{CPUI_MULTIEQUAL}, r.apply, func(g string) Rule { return NewRuleConditionalMove(g) })
	return r
}

// condMoveCheckBoolean returns the root boolean Varnode feeding a MULTIEQUAL
// input, or nil if the input is not a boolean value. A value is boolean if its
// defining op has boolean output, or is a COPY of a 0/1 constant.
// C++ parity: RuleConditionalMove::checkBoolean (ruleaction.cc:9279).
func condMoveCheckBoolean(vn *Varnode) *Varnode {
	if !vn.IsWritten() {
		return nil
	}
	op := vn.Def()
	if op.IsBoolOutput() {
		return vn
	}
	if op.Code() == CPUI_COPY {
		in := op.Input(0)
		if in.IsConstant() {
			if (in.Offset() &^ uint64(1)) == 0 {
				return in
			}
		}
	}
	return nil
}

// apply ports the both-constant branch of RuleConditionalMove::applyOp
// (ruleaction.cc:9498-9524). A 2-input MULTIEQUAL whose inputs are both boolean
// constants is a conditional move (`if (c) x=1; else x=0;`) that collapses to a
// COPY / INT_ZEXT / BOOL_NEGATE of the controlling CBRANCH condition. The
// non-constant and single-constant branches (9449-9492, 9526-9549) require
// CloneBlockOps (gatherExpression/constructBool) which is not yet ported; those
// cases bail (return 0).
//
// The prior Go stub here only collapsed all-identical inputs to a COPY, which is
// redundant with the faithful RuleMultiCollapse (ruleaction.cc:3246, registered
// in action.go) that absorbs identical/functional-equal phis; the same-offset
// case below preserves that collapse for boolean constants.
func (r *RuleConditionalMove) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 { // MULTIEQUAL must have exactly 2 inputs
		return 0
	}
	bool0 := condMoveCheckBoolean(op.Input(0))
	if bool0 == nil {
		return 0
	}
	bool1 := condMoveCheckBoolean(op.Input(1))
	if bool1 == nil {
		return 0
	}
	// Only the both-constant case is ported; the other branches need CloneBlockOps.
	if !bool0.IsConstant() || !bool1.IsConstant() {
		return 0
	}

	// Discover the diamond: rootblock -> {inblock0, inblock1} -> bb.
	// Either inblock may be empty (a single-edge fall-through), in which case its
	// rootblock is its own predecessor. C++ parity: ruleaction.cc:9414-9429.
	bb := op.Parent()
	inblock0 := bb.InEdge(0).Point
	var rootblock0 *FlowBlock
	if inblock0.SizeOut() == 1 {
		if inblock0.SizeIn() != 1 {
			return 0
		}
		rootblock0 = inblock0.InEdge(0).Point
	} else {
		rootblock0 = inblock0
	}
	inblock1 := bb.InEdge(1).Point
	var rootblock1 *FlowBlock
	if inblock1.SizeOut() == 1 {
		if inblock1.SizeIn() != 1 {
			return 0
		}
		rootblock1 = inblock1.InEdge(0).Point
	} else {
		rootblock1 = inblock1
	}
	if rootblock0 != rootblock1 {
		return 0
	}

	// rootblock must end in CBRANCH; its condition drives the conditional move.
	// C++ parity: ruleaction.cc:9432-9434.
	rootBasic := asBasic(rootblock0)
	if rootBasic == nil {
		return 0
	}
	cbranch := rootBasic.LastOp()
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
		return 0
	}

	// gatherExpression is trivially true for constants (empty op list), so the
	// C++ calls at 9437-9439 are elided here.

	// C++ parity: ruleaction.cc:9441-9447.
	var path0istrue bool
	if rootblock0 != inblock0 {
		path0istrue = rootblock0.TrueOut() == inblock0
	} else {
		path0istrue = rootblock0.TrueOut() != inblock1
	}
	if cbranch.HasFlag(PcodeOpBooleanFlip) {
		path0istrue = !path0istrue
	}

	// From here a change is committed. C++ parity: ruleaction.cc:9496-9524.
	data.OpUninsert(op)
	sz := op.Output().Size()
	if bool0.Offset() == bool1.Offset() {
		data.OpRemoveInput(op, 1)
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpSetInput(op, data.NewConstant(sz, bool0.Offset()), 0)
		data.OpInsertBegin(op, bb)
	} else {
		data.OpRemoveInput(op, 1)
		boolvn := cbranch.Input(1)
		// needcomplement is true when the boolean sense of the condition is the
		// opposite of what selecting the '1' constant requires.
		needcomplement := (bool0.Offset() == 0) == path0istrue
		if sz == 1 {
			if needcomplement {
				data.OpSetOpcode(op, CPUI_BOOL_NEGATE)
			} else {
				data.OpSetOpcode(op, CPUI_COPY)
			}
			data.OpInsertBegin(op, bb)
			data.OpSetInput(op, boolvn, 0)
		} else {
			data.OpSetOpcode(op, CPUI_INT_ZEXT)
			data.OpInsertBegin(op, bb)
			if needcomplement {
				boolvn = data.OpBoolNegate(boolvn, op, false)
			}
			data.OpSetInput(op, boolvn, 0)
		}
	}
	return 1
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

// apply pulls a SUBPIECE of a MULTIEQUAL output back through the MULTIEQUAL,
// so the phi works on the smaller value.
// C++ parity: RulePullsubMulti::applyOp.
func (r *RulePullsubMulti) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	if !vn.IsWritten() {
		return 0
	}
	mult := vn.Def()
	if mult.Code() != CPUI_MULTIEQUAL {
		return 0
	}
	// Only pull up, never "down" to the bottom of a loop.
	if mult.Parent().HasLoopIn() {
		return 0
	}
	maxByte, minByte := pullsubMinMaxUse(vn)
	newSize := maxByte - minByte + 1
	if maxByte < minByte || newSize >= int(vn.Size()) {
		return 0 // all or none of vn is used
	}
	if !pullsubAcceptableSize(newSize) {
		return 0
	}
	if outvn := op.Output(); outvn.IsPrecisLo() || outvn.IsPrecisHi() {
		return 0 // don't pull apart a double precision object
	}
	// Don't add SUBPIECEs that will not cancel.
	if minByte > 8 {
		return 0
	}
	var consume uint64
	if minByte < 8 {
		consume = bitfieldSizeMask(int32(newSize)) << (8 * uint(minByte))
	}
	consume = ^consume // bits outside what gets truncated later
	branches := mult.NumInput()
	for i := 0; i < branches; i++ {
		inVn := mult.Input(i)
		if consume&inVn.Consumed() == 0 {
			continue
		}
		// An extension matching the truncation cancels anyway.
		if minByte == 0 && inVn.IsWritten() {
			if defOp := inVn.Def(); defOp.Code() == CPUI_INT_ZEXT || defOp.Code() == CPUI_INT_SEXT {
				if newSize == int(defOp.Input(0).Size()) {
					continue
				}
			}
		}
		return 0
	}
	smalladdr2 := pullsubPieceAddr(vn, minByte, maxByte)
	params := make([]*Varnode, 0, branches)
	for i := 0; i < branches; i++ {
		vnPiece := mult.Input(i)
		// Avoid exponential splitting: reuse a SUBPIECE already pulled.
		vnSub := pullsubFindSubpiece(vnPiece, newSize, minByte)
		if vnSub == nil {
			vnSub = pullsubBuildSubpiece(vnPiece, newSize, minByte, data)
		}
		params = append(params, vnSub)
	}
	newMulti := data.NewOp(len(params), mult.Addr())
	newVn := data.NewVarnodeOut(int32(newSize), smalladdr2, newMulti)
	data.OpSetOpcode(newMulti, CPUI_MULTIEQUAL)
	data.OpSetAllInput(newMulti, params)
	data.OpInsertBegin(newMulti, mult.Parent())
	pullsubReplaceDescendants(vn, newVn, maxByte, minByte, data)
	return 1
}

// apply pulls a SUBPIECE of an INDIRECT output back through the INDIRECT.
// C++ parity: RulePullsubIndirect::applyOp.
func (r *RulePullsubIndirect) apply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	if !vn.IsWritten() || vn.Size() > 8 {
		return 0
	}
	indir := vn.Def()
	if indir.Code() != CPUI_INDIRECT {
		return 0
	}
	targOp := indir.Input(1).GetIndirectCause()
	if targOp == nil || targOp.IsDead() || vn.IsAddrForce() {
		return 0
	}
	maxByte, minByte := pullsubMinMaxUse(vn)
	newSize := maxByte - minByte + 1
	if maxByte < minByte || newSize >= int(vn.Size()) {
		return 0
	}
	if !pullsubAcceptableSize(newSize) {
		return 0
	}
	if outvn := op.Output(); outvn.IsPrecisLo() || outvn.IsPrecisHi() {
		return 0
	}
	consume := ^(bitfieldSizeMask(int32(newSize)) << (8 * uint(minByte)))
	if consume&indir.Input(0).Consumed() != 0 {
		return 0
	}
	smalladdr2 := pullsubPieceAddr(vn, minByte, maxByte)
	var small2 *Varnode
	if indir.IsIndirectCreation() {
		possibleout := !indir.Input(0).IsIndirectZero()
		small2 = data.NewIndirectCreation(targOp, smalladdr2, int32(newSize), possibleout).Output()
	} else {
		basevn := indir.Input(0)
		small1 := pullsubFindSubpiece(basevn, newSize, int(op.Input(1).Offset()))
		if small1 == nil {
			small1 = pullsubBuildSubpiece(basevn, newSize, int(op.Input(1).Offset()), data)
		}
		// A new INDIRECT next to the original one.
		newInd := data.NewOp(2, indir.Addr())
		data.OpSetOpcode(newInd, CPUI_INDIRECT)
		small2 = data.NewVarnodeOut(int32(newSize), smalladdr2, newInd)
		data.OpSetInput(newInd, small1, 0)
		data.OpSetInput(newInd, data.NewVarnodeIop(targOp), 1)
		data.OpInsertBefore(newInd, indir)
	}
	pullsubReplaceDescendants(vn, small2, maxByte, minByte, data)
	return 1
}

// pullsubPieceAddr is the storage address of bytes minByte..maxByte of vn.
func pullsubPieceAddr(vn *Varnode, minByte, maxByte int) address.Address {
	a := vn.Addr()
	if a.Space != nil && a.Space.BigEndian {
		a.Offset += uint64(int(vn.Size()) - maxByte - 1)
	} else {
		a.Offset += uint64(minByte)
	}
	return a
}

// pullsubMinMaxUse returns the range of bytes of vn its readers use; any
// reader other than a SUBPIECE uses all of it.
// C++ parity: RulePullsubMulti::minMaxUse.
func pullsubMinMaxUse(vn *Varnode) (maxByte, minByte int) {
	inSize := int(vn.Size())
	maxByte, minByte = -1, inSize
	for _, op := range vn.DescendIter() {
		if op.Code() != CPUI_SUBPIECE {
			return inSize - 1, 0
		}
		lo := int(op.Input(1).Offset())
		hi := lo + int(op.Output().Size()) - 1
		if lo < minByte {
			minByte = lo
		}
		if hi > maxByte {
			maxByte = hi
		}
	}
	return maxByte, minByte
}

// pullsubReplaceDescendants points every SUBPIECE reading origVn at newVn
// (which holds bytes minByte..maxByte), fixing up the truncation amount.
// C++ parity: RulePullsubMulti::replaceDescendants.
func pullsubReplaceDescendants(origVn, newVn *Varnode, maxByte, minByte int, data *Funcdata) {
	for _, op := range origVn.DescendIter() {
		if op.Code() != CPUI_SUBPIECE {
			panic("Could not perform -replaceDescendants-")
		}
		truncAmount := int(op.Input(1).Offset())
		outSize := op.Output().Size()
		data.OpSetInput(op, newVn, 0)
		switch {
		case newVn.Size() == outSize:
			if truncAmount != minByte {
				panic("Could not perform -replaceDescendants-")
			}
			data.OpSetOpcode(op, CPUI_COPY)
			data.OpRemoveInput(op, 1)
		case newVn.Size() > outSize:
			newTrunc := truncAmount - minByte
			if newTrunc < 0 {
				panic("Could not perform -replaceDescendants-")
			}
			if newTrunc != truncAmount {
				data.OpSetInput(op, data.NewConstant(4, uint64(newTrunc)), 1)
			}
		default:
			panic("Could not perform -replaceDescendants-")
		}
	}
}

// pullsubAcceptableSize reports whether a pulled piece of this size is a
// natural size. C++ parity: RulePullsubMulti::acceptableSize.
func pullsubAcceptableSize(size int) bool {
	if size == 0 {
		return false
	}
	return size >= 8 || size == 1 || size == 2 || size == 4
}

// pullsubBuildSubpiece builds sub(basevn, shift) of outsize bytes next to the
// definition of basevn.
// C++ parity: RulePullsubMulti::buildSubpiece. A join-space base takes a
// unique output (join records are not modelled; C++ may find a piece).
func pullsubBuildSubpiece(basevn *Varnode, outsize, shift int, data *Funcdata) *Varnode {
	var newaddr address.Address
	if basevn.IsInput() {
		newaddr = asBasic(data.GetBasicBlocks().GetBlock(0)).startAddr()
	} else {
		if !basevn.IsWritten() {
			panic("Undefined pullsub")
		}
		newaddr = basevn.Def().Addr()
	}
	usetmp := basevn.Space() != nil && basevn.Space().Kind == address.SpaceKindJoin
	newOp := data.NewOp(2, newaddr)
	data.OpSetOpcode(newOp, CPUI_SUBPIECE)
	var outvn *Varnode
	if usetmp {
		outvn = data.NewUniqueOut(int32(outsize), newOp)
	} else {
		smalladdr1 := basevn.Addr()
		if smalladdr1.Space.BigEndian {
			smalladdr1.Offset += uint64(int(basevn.Size()) - (shift + outsize))
		} else {
			smalladdr1.Offset += uint64(shift)
		}
		outvn = data.NewVarnodeOut(int32(outsize), smalladdr1, newOp)
	}
	data.OpSetInput(newOp, basevn, 0)
	data.OpSetInput(newOp, data.NewConstant(4, uint64(shift)), 1)
	if basevn.IsInput() {
		data.OpInsertBegin(newOp, asBasic(data.GetBasicBlocks().GetBlock(0)))
	} else {
		data.OpInsertAfter(newOp, basevn.Def())
	}
	return outvn
}

// pullsubFindSubpiece finds an existing sub(basevn, shift) of outsize bytes
// in the block defining basevn.
// C++ parity: RulePullsubMulti::findSubpiece.
func pullsubFindSubpiece(basevn *Varnode, outsize, shift int) *Varnode {
	for _, prevop := range basevn.DescendIter() {
		if prevop.Code() != CPUI_SUBPIECE {
			continue
		}
		// The output must be defined in the same block as basevn.
		if basevn.IsInput() && prevop.Parent().Index() != 0 {
			continue
		}
		if !basevn.IsWritten() {
			continue
		}
		if basevn.Def().Parent() != prevop.Parent() {
			continue
		}
		if prevop.Input(0) == basevn && int(prevop.Output().Size()) == outsize && int(prevop.Input(1).Offset()) == shift {
			return prevop.Output()
		}
	}
	return nil
}

type RulePullsubIndirect struct{ batchRule }

func NewRulePullsubIndirect(group string) *RulePullsubIndirect {
	r := &RulePullsubIndirect{}
	r.batchRule = newBatchRule(group, "pullsub_indirect", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRulePullsubIndirect(g) })
	return r
}

// The C++ RulePushMulti (2-branch MULTIEQUAL phi CSE, coreaction.cc:1062) is
// faithfully ported as RulePushMultiME. A different Go-invented "push_multi"
// rule used to live here, substituting a redundant MULTIEQUAL (all inputs
// identical) into its arithmetic consumers; it was never registered in the
// production pool (action.go) and its effect is already covered by
// RuleConditionalMove (collapses the identical-input phi to a COPY) followed by
// RulePropagateCopy, so it was removed.

// RulePushPtr lives in rules_pointer.go (faithful port of C++ ruleaction.cc
// RulePushPtr). It used to be a PTRADD/PTRSUB zero-offset collapse here, which
// was unrelated to the C++ rule of the same name and never fired on any golden.

// RuleShiftPiece is a faithful port of RuleShiftPiece::applyOp
// (ruleaction.cc:3773-3870). It converts a "shift and add" back into a PIECE:
//
//	(zext(V) << 8*sizeof(W)) + zext(W)  =>  concat(V, W)
//
// The add carrier may be INT_ADD, INT_OR, or INT_XOR, and either operand order
// is handled by the shiftop/zextloop swap. A special CDQ/IDIV form, where the
// high half is the arithmetic sign extension of the low half, folds to a SEXT.
//
// The previous body under this name was a byte-for-byte duplicate of
// RuleConcatShift (INT_RIGHT canceling PIECE); that case is still covered by the
// separately registered RuleConcatShift, so replacing it here loses no coverage.
type RuleShiftPiece struct{ batchRule }

func NewRuleShiftPiece(group string) *RuleShiftPiece {
	r := &RuleShiftPiece{}
	r.batchRule = newBatchRule(group, "shiftpiece", []OpCode{CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRuleShiftPiece(g) })
	return r
}

func (r *RuleShiftPiece) apply(op *PcodeOp, data *Funcdata) int {
	in0 := op.Input(0)
	in1 := op.Input(1)
	if in0 == nil || !in0.IsWritten() || in1 == nil || !in1.IsWritten() {
		return 0
	}
	shiftop := in0.Def()
	zextloop := in1.Def()
	if shiftop == nil || zextloop == nil {
		return 0
	}
	// Normalize so shiftop is the INT_LEFT (the high, shifted piece).
	if shiftop.Code() != CPUI_INT_LEFT {
		if zextloop.Code() != CPUI_INT_LEFT {
			return 0
		}
		shiftop, zextloop = zextloop, shiftop
	}
	if !shiftop.Input(1).IsConstant() {
		return 0
	}
	shiftIn := shiftop.Input(0)
	if shiftIn == nil || !shiftIn.IsWritten() {
		return 0
	}
	zexthiop := shiftIn.Def()
	if zexthiop == nil || (zexthiop.Code() != CPUI_INT_ZEXT && zexthiop.Code() != CPUI_INT_SEXT) {
		return 0
	}
	hiVal := zexthiop.Input(0) // most significant piece (PIECE slot 0)
	if hiVal.IsConstant() {
		// Normally ZEXT of a constant collapses naturally; only intervene when
		// the constant is too wide for that to happen (C++: sizeof(uintb) == 8).
		if hiVal.Size() < 8 {
			return 0
		}
	} else if hiVal.IsFree() {
		return 0
	}
	sa := int32(shiftop.Input(1).Offset())
	concatsize := sa + 8*hiVal.Size()
	if op.Output().Size()*8 < concatsize {
		return 0
	}
	if zextloop.Code() != CPUI_INT_ZEXT {
		// Special case triggered by CDQ:IDIV -- the high half is the arithmetic
		// sign extension (INT_SRIGHT by width-1) of SUBPIECE(bigVn, 0). This
		// would fall to the base case but interacts with RuleSubZext.
		if !hiVal.IsWritten() {
			return 0
		}
		rShiftOp := hiVal.Def()
		if rShiftOp == nil || rShiftOp.Code() != CPUI_INT_SRIGHT || !rShiftOp.Input(1).IsConstant() {
			return 0
		}
		lowVn := rShiftOp.Input(0)
		if lowVn == nil || !lowVn.IsWritten() {
			return 0
		}
		subop := lowVn.Def()
		if subop == nil || subop.Code() != CPUI_SUBPIECE || subop.Input(1).Offset() != 0 {
			return 0
		}
		bigVn := zextloop.Output()
		if subop.Input(0) != bigVn { // verify link through SUBPIECE low part
			return 0
		}
		rsa := int32(rShiftOp.Input(1).Offset())
		if rsa != lowVn.Size()*8-1 { // shift must copy sign-bit through high part
			return 0
		}
		if (bigVn.NZMask() >> uint(sa)) != 0 { // original high bytes must be zero
			return 0
		}
		if sa != 8*lowVn.Size() {
			return 0
		}
		rewriteOp(data, op, CPUI_INT_SEXT, lowVn)
		return 1
	}
	lowVal := zextloop.Input(0) // least significant piece (PIECE slot 1)
	if lowVal.IsFree() {
		return 0
	}
	if sa != 8*lowVal.Size() {
		return 0
	}
	if concatsize == op.Output().Size()*8 {
		rewriteOp(data, op, CPUI_PIECE, hiVal, lowVal)
	} else {
		newop := data.NewOpBefore(op, CPUI_PIECE, hiVal, lowVal)
		data.NewUniqueOut(concatsize/8, newop)
		data.OpSetOpcode(op, zexthiop.Code())
		data.OpRemoveInput(op, 1)
		data.OpSetInput(op, newop.Output(), 0)
	}
	return 1
}

type RuleConcatLeftShift struct{ batchRule }

func NewRuleConcatLeftShift(group string) *RuleConcatLeftShift {
	r := &RuleConcatLeftShift{}
	r.batchRule = newBatchRule(group, "concatleftshift", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleConcatLeftShift(g) })
	return r
}

// apply rewrites concat(V, zext(W) << 8n), with W shifted to the most
// significant boundary, as concat(concat(V, W), 0).
// C++ parity: RuleConcatLeftShift::applyOp.
func (r *RuleConcatLeftShift) apply(op *PcodeOp, data *Funcdata) int {
	vn2 := op.Input(1)
	if !vn2.IsWritten() {
		return 0
	}
	shiftop := vn2.Def()
	if shiftop.Code() != CPUI_INT_LEFT || !shiftop.Input(1).IsConstant() {
		return 0
	}
	sa := int32(shiftop.Input(1).Offset())
	if sa&7 != 0 {
		return 0 // not a multiple of 8
	}
	tmpvn := shiftop.Input(0)
	if !tmpvn.IsWritten() {
		return 0
	}
	zextop := tmpvn.Def()
	if zextop.Code() != CPUI_INT_ZEXT {
		return 0
	}
	b := zextop.Input(0)
	if b.IsFree() {
		return 0
	}
	vn1 := op.Input(0)
	if vn1.IsFree() {
		return 0
	}
	sa /= 8
	if sa+b.Size() != tmpvn.Size() {
		return 0 // must shift to the most significant boundary
	}
	newop := data.NewOp(2, op.Addr())
	data.OpSetOpcode(newop, CPUI_PIECE)
	newout := data.NewUniqueOut(vn1.Size()+b.Size(), newop)
	data.OpSetInput(newop, vn1, 0)
	data.OpSetInput(newop, b, 1)
	data.OpInsertBefore(newop, op)
	data.OpSetInput(op, newout, 0)
	data.OpSetInput(op, data.NewConstant(op.Output().Size()-newout.Size(), 0), 1)
	return 1
}

type RuleShiftSub struct{ batchRule }

func NewRuleShiftSub(group string) *RuleShiftSub {
	r := &RuleShiftSub{}
	r.batchRule = newBatchRule(group, "shiftsub", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleShiftSub(g) })
	return r
}

// apply folds sub(V << 8n, c) into sub(V, c - n) when the result is a
// natural truncation of V. C++ parity: RuleShiftSub::applyOp.
func (r *RuleShiftSub) apply(op *PcodeOp, data *Funcdata) int {
	if !op.Input(0).IsWritten() {
		return 0
	}
	shiftop := op.Input(0).Def()
	if shiftop.Code() != CPUI_INT_LEFT {
		return 0
	}
	sa := shiftop.Input(1)
	if !sa.IsConstant() {
		return 0
	}
	n := int64(sa.Offset())
	if n&7 != 0 {
		return 0 // must shift by a multiple of 8 bits
	}
	c := int64(op.Input(1).Offset())
	vn := shiftop.Input(0)
	if vn.IsFree() {
		return 0
	}
	insize := int64(vn.Size())
	outsize := int64(op.Output().Size())
	c -= n / 8
	if c < 0 || c+outsize > insize {
		return 0 // not a natural truncation
	}
	data.OpSetInput(op, vn, 0)
	data.OpSetInput(op, data.NewConstant(op.Input(1).Size(), uint64(c)), 1)
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

func isSingleBitMask(val uint64) bool {
	return val != 0 && bits.OnesCount64(val) == 1
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
		return 0
	}
	op1 := in1.Def()
	if op1.Code() == CPUI_SUBPIECE {
		return 0
	}

	// Note: the cross-space guard that was here (b33f6a2) has been removed.
	// RulePushMultiME for gcd-style loops correctly merges stack and register
	// varnodes into a loop phi, matching Ghidra's SSA structure. The downstream
	// mergeMarker handles the merge via TrimOpOutput / snipReads.

	bl := op.Parent()
	earliest := bl.EarliestUse(op.Output())

	if op1.Code() == CPUI_COPY {
		if res == 0 {
			return 0
		}
		substitute := findSubstituteForME(buf1[0], buf2[0], bl, earliest, data)
		if substitute == nil {
			return 0
		}
		data.TotalReplace(op.Output(), substitute.Output())
		data.OpDestroy(op)
		return 1
	}

	op2 := in2.Def()
	if in1.LoneDescend() != op {
		return 0
	}
	if in2.LoneDescend() != op {
		return 0
	}

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
	func(group string) Rule { return NewRuleBooleanNegate(group) },
	func(group string) Rule { return NewRuleThreeWayCompare(group) },
	func(group string) Rule { return NewRuleXorSwap(group) },
	func(group string) Rule { return NewRuleLzcountShiftBool(group) },
	func(group string) Rule { return NewRuleOrCompare(group) },
	func(group string) Rule { return NewRuleConditionalMove(group) },
	func(group string) Rule { return NewRuleFuncPtrEncoding(group) },
	func(group string) Rule { return NewRulePullsubMulti(group) },
	func(group string) Rule { return NewRulePullsubIndirect(group) },
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

// bitfieldSizeMask returns the all-ones mask covering the given size in bytes.
// C++ parity: calc_mask(sz) in opbehavior.hh. Mirrors the helper RulePullAbsorb
// and RuleInsertAbsorb use to test whether a compare constant matches the
// full-width unsigned maximum of a Varnode.
func bitfieldSizeMask(sz int32) uint64 {
	if sz <= 0 {
		return 0
	}
	if sz >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(sz*8)) - 1
}

// absorbRight mirrors bitfield.cc RulePullAbsorb::absorbRight (L1756). It
// looks for `((sfield >> #n) & #1) == #0` / `!= #0` and rewrites them into a
// signed compare against zero, forwarding the PULL output into the compare.
func (r *RulePullAbsorb) absorbRight(data *Funcdata, rightOp, pullOp *PcodeOp) int {
	outvn := rightOp.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		if readOp.Code() == CPUI_INT_AND {
			res := r.absorbRightAndCompZero(data, rightOp, readOp, pullOp)
			if res != 0 {
				return res
			}
		}
	}
	return 0
}

// absorbRightAndCompZero mirrors bitfield.cc RulePullAbsorb::absorbRightAndCompZero
// (L1779). Transforms `((sfield >> #n) & #1) == #0` to `0 <= sfield` and the
// NOT_EQUAL variant to `sfield < 0`.
func (r *RulePullAbsorb) absorbRightAndCompZero(data *Funcdata, rightOp, andOp, pullOp *PcodeOp) int {
	if pullOp.Code() != CPUI_SPULL {
		return 0
	}
	cvn := rightOp.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return 0
	}
	sa := int64(cvn.Offset())
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	numbits := int64(pullOp.Input(2).Offset())
	if numbits-1 != sa {
		return 0
	}
	if andOp.NumInput() < 2 || andOp.Input(1) == nil || !andOp.Input(1).IsConstant() || andOp.Input(1).Offset() != 1 {
		return 0
	}
	outvn := andOp.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		if readOp.NumInput() < 2 || readOp.Input(1) == nil || !readOp.Input(1).IsConstant() || readOp.Input(1).Offset() != 0 {
			continue
		}
		vn := pullOp.Output()
		if vn == nil {
			continue
		}
		if opc == CPUI_INT_EQUAL {
			data.OpSetOpcode(readOp, CPUI_INT_LESSEQUAL)
			zvn := readOp.Input(1)
			data.OpSetInput(readOp, vn, 1)
			data.OpSetInput(readOp, zvn, 0)
		} else {
			data.OpSetOpcode(readOp, CPUI_INT_SLESS)
			data.OpSetInput(readOp, vn, 0)
		}
		data.DestroyVarnodeRecursive(outvn)
		return 1
	}
	return 0
}

// absorbLeft mirrors bitfield.cc RulePullAbsorb::absorbLeft (L1819). Dispatches
// left-shift descendants to the compare / right / and helpers.
func (r *RulePullAbsorb) absorbLeft(data *Funcdata, leftOp, pullOp *PcodeOp) int {
	outvn := leftOp.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		res := 0
		switch readOp.Code() {
		case CPUI_INT_SLESS:
			res = r.absorbCompare(data, readOp, leftOp, pullOp)
		case CPUI_INT_RIGHT:
			res = r.absorbLeftRight(data, readOp, leftOp, pullOp)
		case CPUI_INT_AND:
			res = r.absorbLeftAnd(data, readOp, leftOp, pullOp)
		}
		if res != 0 {
			return res
		}
	}
	return 0
}

// absorbLeftRight mirrors bitfield.cc RulePullAbsorb::absorbLeftRight (L1846).
// Collapses `(field << #c) >> #d` into `field >> (#d-#c)` or a left shift the
// other way when the right shift is smaller.
func (r *RulePullAbsorb) absorbLeftRight(data *Funcdata, rightOp, leftOp, pullOp *PcodeOp) int {
	if leftOp.NumInput() < 2 || rightOp.NumInput() < 2 {
		return 0
	}
	leftcvn := leftOp.Input(1)
	rightcvn := rightOp.Input(1)
	if leftcvn == nil || !leftcvn.IsConstant() || rightcvn == nil || !rightcvn.IsConstant() {
		return 0
	}
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	bitsize := int64(pullOp.Input(2).Offset())
	invn := pullOp.Input(0)
	if invn == nil {
		return 0
	}
	containerBits := int64(invn.Size()) * 8
	leftshift := int64(leftcvn.Offset())
	rightshift := int64(rightcvn.Offset())
	if leftshift+bitsize > containerBits {
		return 0
	}
	sa := rightshift - leftshift
	pullOut := pullOp.Output()
	leftOut := leftOp.Output()
	if pullOut == nil || leftOut == nil {
		return 0
	}
	if sa == 0 {
		data.TotalReplace(rightOp.Output(), pullOut)
		data.DestroyVarnodeRecursive(rightOp.Output())
	} else if sa > 0 {
		data.OpSetInput(rightOp, data.NewConstant(rightcvn.Size(), uint64(sa)), 1)
		data.OpSetInput(rightOp, pullOut, 0)
		data.DestroyVarnodeRecursive(leftOut)
	} else {
		data.OpSetOpcode(rightOp, CPUI_INT_LEFT)
		data.OpSetInput(rightOp, data.NewConstant(rightcvn.Size(), uint64(-sa)), 1)
		data.OpSetInput(rightOp, pullOut, 0)
		data.DestroyVarnodeRecursive(leftOut)
	}
	return 1
}

// absorbLeftAnd mirrors bitfield.cc RulePullAbsorb::absorbLeftAnd (L1885).
// Collapses `((field << #c) & #b) == #d` into `(field & #b>>c) == #d>>c`.
func (r *RulePullAbsorb) absorbLeftAnd(data *Funcdata, andOp, leftOp, pullOp *PcodeOp) int {
	_ = pullOp
	shiftAmount := leftOp.Input(1)
	if shiftAmount == nil || !shiftAmount.IsConstant() {
		return 0
	}
	sa := shiftAmount.Offset()
	if sa >= 64 {
		return 0
	}
	maskVn := andOp.Input(1)
	if maskVn == nil || !maskVn.IsConstant() {
		return 0
	}
	mask := maskVn.Offset()
	outvn := andOp.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		compVal := readOp.Input(1)
		if compVal == nil || !compVal.IsConstant() {
			continue
		}
		val := compVal.Offset() >> sa
		if val<<sa != compVal.Offset() {
			continue
		}
		newMask := mask >> sa
		newAnd := data.NewConstant(maskVn.Size(), newMask)
		data.OpSetInput(andOp, newAnd, 1)
		if val != compVal.Offset() {
			newVal := data.NewConstant(compVal.Size(), val)
			data.OpSetInput(readOp, newVal, 1)
		}
		data.OpSetInput(andOp, leftOp.Input(0), 0)
		data.DestroyVarnodeRecursive(leftOp.Output())
		return 1
	}
	return 0
}

// absorbAnd mirrors bitfield.cc RulePullAbsorb::absorbAnd (L1928). Rewrites
// `field & signbit == #0` into `field s<= 0` (and its != variant into signed
// less-than zero).
func (r *RulePullAbsorb) absorbAnd(data *Funcdata, andOp, pullOp *PcodeOp) int {
	maskVn := andOp.Input(1)
	if maskVn == nil || !maskVn.IsConstant() {
		return 0
	}
	vn := pullOp.Output()
	if vn == nil || pullOp.Code() != CPUI_SPULL {
		return 0
	}
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	bitsize := pullOp.Input(2).Offset()
	if bitsize == 0 {
		return 0
	}
	matchVal := uint64(1) << uint(bitsize-1)
	if matchVal != maskVn.Offset() {
		return 0
	}
	outvn := andOp.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		if readOp.Input(1) == nil || !readOp.Input(1).IsConstant() || readOp.Input(1).Offset() != 0 {
			continue
		}
		newZero := data.NewConstant(vn.Size(), 0)
		if opc == CPUI_INT_EQUAL {
			data.OpSetOpcode(readOp, CPUI_INT_SLESSEQUAL)
			data.OpSetInput(readOp, newZero, 0)
			data.OpSetInput(readOp, vn, 1)
		} else {
			data.OpSetOpcode(readOp, CPUI_INT_SLESS)
			data.OpSetInput(readOp, vn, 0)
			data.OpSetInput(readOp, newZero, 1)
		}
		data.DestroyVarnodeRecursive(outvn)
		return 1
	}
	return 0
}

// absorbCompare mirrors bitfield.cc RulePullAbsorb::absorbCompare (L1979). It
// rewrites INT_SLESS / INT_LESS ops fed either directly from the pull output or
// via a left shift, substituting the pull output for the shifted form.
func (r *RulePullAbsorb) absorbCompare(data *Funcdata, compOp, leftOp, pullOp *PcodeOp) int {
	sa := int64(0)
	if leftOp != nil {
		cvn := leftOp.Input(1)
		if cvn == nil || !cvn.IsConstant() {
			return 0
		}
		sa = int64(cvn.Offset())
	}
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	numbits := int64(pullOp.Input(2).Offset())
	invn := pullOp.Input(0)
	if invn == nil {
		return 0
	}
	sz := int64(invn.Size()) * 8
	if numbits+sa != sz {
		return 0
	}
	var inVn *Varnode
	if leftOp == nil {
		inVn = pullOp.Output()
	} else {
		inVn = leftOp.Output()
	}
	if inVn == nil {
		return 0
	}
	lessVn0 := compOp.Input(0)
	lessVn1 := compOp.Input(1)
	if lessVn0 == nil || lessVn1 == nil {
		return 0
	}
	pullOut := pullOp.Output()
	if pullOut == nil {
		return 0
	}
	if compOp.Code() == CPUI_INT_SLESS {
		if numbits == 1 && lessVn0 == inVn && lessVn1.IsConstant() && lessVn1.Offset() == 0 {
			oldVn := compOp.Output()
			if oldVn == nil {
				return 0
			}
			data.TotalReplace(oldVn, pullOut)
			data.DestroyVarnodeRecursive(oldVn)
			return 1
		}
		if numbits == 1 && lessVn1 == inVn && lessVn0.IsConstant() && lessVn0.Offset() == bitfieldSizeMask(inVn.Size()) {
			data.OpRemoveInput(compOp, 0)
			data.OpSetOpcode(compOp, CPUI_BOOL_NEGATE)
			data.OpSetInput(compOp, pullOut, 0)
			data.DestroyVarnodeRecursive(inVn)
			return 1
		}
	}
	var mask uint64
	if sa > 0 && sa < 64 {
		mask = (uint64(1) << uint(sa)) - 1
	}
	if sa > 0 && sa < 64 && inVn == lessVn0 && lessVn1.IsConstant() {
		origVal := lessVn1.Offset()
		lowBits := mask & origVal
		if lowBits == 0 || lowBits == 1 {
			var newVal uint64
			if lowBits == 1 {
				newVal = (origVal - 1) >> uint(sa)
				newVal = (newVal + 1) & bitfieldSizeMask(inVn.Size())
			} else {
				newVal = origVal >> uint(sa)
			}
			data.OpSetInput(compOp, pullOut, 0)
			data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 1)
			data.DestroyVarnodeRecursive(inVn)
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
				newVal = (newVal - 1) & bitfieldSizeMask(inVn.Size())
			} else {
				newVal = origVal >> uint(sa)
			}
			data.OpSetInput(compOp, pullOut, 1)
			data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 0)
			data.DestroyVarnodeRecursive(inVn)
			return 1
		}
	}
	return 0
}

// absorbExt mirrors bitfield.cc RulePullAbsorb::absorbExt (L2059). Rewrites
// `y = ZEXT(ZPULL(x))` into `y = ZPULL(x)` (same for signed extension / SPULL),
// so the extension op is itself turned into the PULL op.
func (r *RulePullAbsorb) absorbExt(data *Funcdata, extOp, pullOp *PcodeOp) int {
	pullSigned := pullOp.Code() == CPUI_SPULL
	extSigned := extOp.Code() == CPUI_INT_SEXT
	if extSigned != pullSigned {
		return 0
	}
	vn := extOp.Input(0)
	if vn == nil || vn.LoneDescend() != extOp {
		return 0
	}
	if pullOp.NumInput() < 3 {
		return 0
	}
	data.OpSetOpcode(extOp, pullOp.Code())
	data.OpSetInput(extOp, pullOp.Input(0), 0)
	posVn := pullOp.Input(1)
	numVn := pullOp.Input(2)
	data.OpInsertInput(extOp, posVn, 1)
	data.OpInsertInput(extOp, numVn, 2)
	data.DestroyVarnodeRecursive(vn)
	return 1
}

// absorbSubpiece mirrors bitfield.cc RulePullAbsorb::absorbSubpiece (L2083).
// Turns `y = SUB(PULL(x),0)` into `y = PULL(x)` when the subpiece slice covers
// at least the field width.
func (r *RulePullAbsorb) absorbSubpiece(data *Funcdata, subOp, pullOp *PcodeOp) int {
	if subOp.NumInput() < 2 || subOp.Input(1) == nil || !subOp.Input(1).IsConstant() || subOp.Input(1).Offset() != 0 {
		return 0
	}
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	bitsize := int64(pullOp.Input(2).Offset())
	outvn := subOp.Output()
	if outvn == nil || bitsize > int64(outvn.Size())*8 {
		return 0
	}
	vn := subOp.Input(0)
	if vn == nil || vn.LoneDescend() != subOp {
		return 0
	}
	data.OpSetOpcode(subOp, pullOp.Code())
	data.OpSetInput(subOp, pullOp.Input(0), 0)
	data.OpSetInput(subOp, pullOp.Input(1), 1)
	data.OpInsertInput(subOp, pullOp.Input(2), 2)
	data.DestroyVarnodeRecursive(vn)
	return 1
}

// absorbCompZero mirrors bitfield.cc RulePullAbsorb::absorbCompZero (L2109).
// Rewrites `ZPULL(x,#p,#1) != #0` into the bare ZPULL, and the == variant
// into a BOOL_NEGATE of the pull. We require a 1-bit field and conservatively
// drop the TypeBitField metatype check until the full type system lands.
func (r *RulePullAbsorb) absorbCompZero(data *Funcdata, compOp, pullOp *PcodeOp) int {
	zvn := compOp.Input(1)
	if zvn == nil || !zvn.IsConstant() || zvn.Offset() != 0 {
		return 0
	}
	if pullOp.NumInput() < 3 || pullOp.Input(2) == nil || !pullOp.Input(2).IsConstant() {
		return 0
	}
	bitsize := int64(pullOp.Input(2).Offset())
	if bitsize != 1 {
		return 0
	}
	vn := compOp.Input(0)
	if vn == nil || vn.LoneDescend() != compOp {
		return 0
	}
	if vn.IsAddrTied() {
		return 0
	}
	if pullOp.Code() == CPUI_SPULL {
		return 0
	}
	// TODO known mismatch: the C++ path additionally checks
	// BitFieldExpression::getPullField(pullOp)->type->getMetatype() == TYPE_BOOL
	// to avoid rewriting non-bool single-bit fields. Without the TypeBitField
	// trace machinery we accept any 1-bit ZPULL, which is strictly more
	// permissive than Ghidra.
	if compOp.Code() == CPUI_INT_EQUAL {
		// Simplified: replace the compare with BOOL_NEGATE(PULL). The C++
		// additionally rewires the PULL's output width to 1 when vn was wider,
		// which requires updating vn's storage; omitted here so we simply do
		// not handle the wider-vn case to stay sound.
		if vn.Size() != 1 {
			return 0
		}
		data.OpSetOpcode(compOp, CPUI_BOOL_NEGATE)
		data.OpRemoveInput(compOp, 1)
	} else {
		data.OpSetOpcode(compOp, pullOp.Code())
		data.OpSetInput(compOp, pullOp.Input(0), 0)
		data.OpSetInput(compOp, pullOp.Input(1), 1)
		data.OpInsertInput(compOp, pullOp.Input(2), 2)
		data.DestroyVarnodeRecursive(vn)
	}
	return 1
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

// apply mirrors RuleInsertAbsorb::applyOp (bitfield.cc L2352) -- dispatches on
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
		if inOp.NumInput() < 2 || inOp.Input(1) == nil || !inOp.Input(1).IsConstant() || inOp.Input(1).Offset() != 0 {
			return 0
		}
		data.OpSetInput(op, inOp.Input(0), 1)
		data.DestroyVarnodeRecursive(inVn)
		return 1
	case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		if inOp.NumInput() < 2 || !inOp.Input(1).IsConstant() {
			return 0
		}
		shiftedVn := inOp.Input(0)
		if shiftedVn == nil || !shiftedVn.IsWritten() {
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

// insertAbsorbLeftShiftVarnode mirrors bitfield.cc RuleInsertAbsorb::leftShiftVarnode
// (L2203). Returns the unshifted input when vn is the output of a left shift
// (either INT_LEFT or INT_MULT by a power-of-two) with shift amount sa.
func insertAbsorbLeftShiftVarnode(vn *Varnode, sa int) *Varnode {
	if vn == nil || !vn.IsWritten() {
		return nil
	}
	multOp := vn.Def()
	if multOp == nil || multOp.NumInput() < 2 {
		return nil
	}
	multVal := multOp.Input(1)
	if multVal == nil || !multVal.IsConstant() {
		return nil
	}
	var matchVal uint64
	switch multOp.Code() {
	case CPUI_INT_MULT:
		if sa < 0 || sa >= 64 {
			return nil
		}
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

// bitfieldPopcount returns the number of 1 bits in v.
// C++ parity: popcount helper in opbehavior.cc -- inlined here for the nested
// AND absorb test.
func bitfieldPopcount(v uint64) int {
	c := 0
	for v != 0 {
		v &= v - 1
		c++
	}
	return c
}

// bitfieldCoveringMask returns the smallest contiguous mask that covers v.
// C++ parity: coveringmask helper in opbehavior.cc.
func bitfieldCoveringMask(v uint64) uint64 {
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	return v
}

// absorbAnd mirrors bitfield.cc RuleInsertAbsorb::absorbAnd (L2230). Drops the
// redundant AND mask on the value flowing into an INSERT when the mask only
// touches the least significant bits that the INSERT slice preserves.
func (r *RuleInsertAbsorb) absorbAnd(data *Funcdata, andOp, insertOp *PcodeOp) int {
	cvn := andOp.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return 0
	}
	val := cvn.Offset()
	mask := insertExpressionLSBMask(insertOp)
	if (mask & val) != mask {
		return 0
	}
	data.OpSetInput(insertOp, andOp.Input(0), 1)
	data.DestroyVarnodeRecursive(andOp.Output())
	return 1
}

// absorbRightLeft mirrors bitfield.cc RuleInsertAbsorb::absorbRightLeft (L2246).
// Collapses `INSERT((x<<#c)>>#c,...)` (and the SUBPIECE variant) into
// `INSERT(x,...)` when the shift cancellation does not truncate field bits.
func (r *RuleInsertAbsorb) absorbRightLeft(data *Funcdata, nextOp, rightOp, insertOp *PcodeOp) int {
	var leftOp *PcodeOp
	switch nextOp.Code() {
	case CPUI_INT_LEFT:
		leftOp = nextOp
	case CPUI_SUBPIECE:
		if nextOp.Input(1) == nil || !nextOp.Input(1).IsConstant() || nextOp.Input(1).Offset() != 0 {
			return 0
		}
		subin := nextOp.Input(0)
		if subin == nil || !subin.IsWritten() {
			return 0
		}
		leftOp = subin.Def()
		if leftOp == nil || leftOp.Code() != CPUI_INT_LEFT {
			return 0
		}
	default:
		return 0
	}
	lvn := leftOp.Input(1)
	if lvn == nil || !lvn.IsConstant() {
		return 0
	}
	rvn := rightOp.Input(1)
	if rvn == nil || !rvn.IsConstant() {
		return 0
	}
	lsa := int64(lvn.Offset())
	rsa := int64(rvn.Offset())
	if lsa != rsa {
		return 0
	}
	if insertOp.NumInput() < 4 || insertOp.Input(3) == nil || !insertOp.Input(3).IsConstant() {
		return 0
	}
	bitsize := int64(insertOp.Input(3).Offset())
	containerBits := int64(insertOp.Input(1).Size())*8 - lsa
	if bitsize > containerBits {
		return 0
	}
	data.OpSetInput(insertOp, leftOp.Input(0), 1)
	data.DestroyVarnodeRecursive(rightOp.Output())
	return 1
}

// absorbShiftAdd mirrors bitfield.cc RuleInsertAbsorb::absorbShiftAdd (L2284).
// Turns `(a*#c + b*#c) >> #n` into `a + b` at the INSERT site.
func (r *RuleInsertAbsorb) absorbShiftAdd(data *Funcdata, rightOp, addOp, insertOp *PcodeOp) int {
	if rightOp.Input(1) == nil || !rightOp.Input(1).IsConstant() {
		return 0
	}
	sa := int(rightOp.Input(1).Offset())
	if sa <= 0 || sa >= 64 {
		return 0
	}
	vn0 := insertAbsorbLeftShiftVarnode(addOp.Input(0), sa)
	if vn0 == nil {
		return 0
	}
	var vn1 *Varnode
	addVn1 := addOp.Input(1)
	if addVn1 == nil {
		return 0
	}
	if addVn1.IsConstant() {
		addVal := addVn1.Offset() >> uint(sa)
		if (addVal << uint(sa)) != addVn1.Offset() {
			return 0
		}
		vn1 = data.NewConstant(vn0.Size(), addVal)
	} else {
		vn1 = insertAbsorbLeftShiftVarnode(addVn1, sa)
		if vn1 == nil {
			return 0
		}
	}
	if insertOp.NumInput() < 4 || insertOp.Input(3) == nil || !insertOp.Input(3).IsConstant() {
		return 0
	}
	bitsize := int64(insertOp.Input(3).Offset())
	if bitsize > int64(vn0.Size())*8-int64(sa) {
		return 0
	}
	data.OpSetOpcode(rightOp, CPUI_INT_ADD)
	data.OpSetInput(rightOp, vn0, 0)
	data.OpSetInput(rightOp, vn1, 1)
	data.DestroyVarnodeRecursive(addOp.Output())
	return 1
}

// absorbNestedAnd mirrors bitfield.cc RuleInsertAbsorb::absorbNestedAnd (L2322).
// Strips an `x & #mask` feeding an arithmetic op whose result is immediately
// absorbed by INSERT with a narrower slice.
func (r *RuleInsertAbsorb) absorbNestedAnd(data *Funcdata, baseOp, insertOp *PcodeOp) int {
	baseOut := baseOp.Output()
	if baseOut == nil || baseOut.LoneDescend() != insertOp {
		return 0
	}
	for slot := 0; slot < 2; slot++ {
		vn := baseOp.Input(slot)
		if vn == nil || !vn.IsWritten() {
			continue
		}
		andOp := vn.Def()
		if andOp == nil || andOp.Code() != CPUI_INT_AND {
			continue
		}
		cvn := andOp.Input(1)
		if cvn == nil || !cvn.IsConstant() {
			continue
		}
		mask := bitfieldCoveringMask(cvn.Offset())
		if mask != cvn.Offset() {
			continue
		}
		if (mask & 1) == 0 {
			continue
		}
		count := bitfieldPopcount(mask)
		if insertOp.NumInput() < 4 || insertOp.Input(3) == nil || !insertOp.Input(3).IsConstant() {
			continue
		}
		bitsize := int(insertOp.Input(3).Offset())
		if count < bitsize {
			continue
		}
		data.OpSetInput(baseOp, andOp.Input(0), slot)
		data.DestroyVarnodeRecursive(andOp.Output())
		return 1
	}
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
