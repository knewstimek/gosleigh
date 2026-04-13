/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pcode

import (
	"gosleigh/pkg/address"
)

// C++ parity: double.cc Form classes -- pattern-match and rewrite logic for
// specific double-precision operations dispatched from
// SplitVarnode::applyRuleIn.
//
// Ported Forms (REAL):
//   - AddForm        (double.cc:1433 -- checkForCarry, verify, applyRule)
//   - SubForm        (double.cc:1616 -- verify, applyRule)
//   - LogicalForm    (double.cc:1704 -- findHiMatch, verify, applyRule)
//   - ShiftForm      (double.cc:2550 -- mapLeft/mapRight, verify*, applyRule*)
//   - PhiForm        (double.cc:3028 -- verify, applyRule)
//   - CopyForceForm  (double.cc:3137 -- verify, applyRule; returnCopy variant stubbed)
//   - LessConstForm  (double.cc:2505 -- applyRule)
//
// Stubbed Forms (always return false):
//   - Equal1Form, Equal2Form, Equal3Form  (needs CBRANCH edge layout parity)
//   - LessThreeWay                         (cross-block state machine)
//   - MultForm                             (large zext/sub recovery)
//   - IndirectForm                         (needs newVarnodeIop plumbing)

// -----------------------------------------------------------------------------
// AddForm
// -----------------------------------------------------------------------------

// AddForm recovers a double-precision addition from its piece-wise form.
// C++ parity: class AddForm (double.hh:102)
type AddForm struct {
	in       SplitVarnode
	hi1, hi2 *Varnode
	lo1, lo2 *Varnode
	reshi    *Varnode
	reslo    *Varnode

	zextop *PcodeOp
	loadd  *PcodeOp
	add2   *PcodeOp

	hizext1, hizext2 *Varnode
	slot1            int
	negconst         uint64

	existop *PcodeOp
	indoub  SplitVarnode
	outdoub SplitVarnode
}

// checkForCarry mirrors AddForm::checkForCarry (double.cc:1433).
// If op is a CARRY(x, lo1) construction, set lo2 (and negconst when lo1 is
// a constant) and return true.
func (a *AddForm) checkForCarry(op *PcodeOp) bool {
	if op.Code() != CPUI_INT_ZEXT {
		return false
	}
	in0 := op.Input(0)
	if !in0.IsWritten() {
		return false
	}
	carryop := in0.Def()
	switch carryop.Code() {
	case CPUI_INT_CARRY:
		switch {
		case carryop.Input(0) == a.lo1:
			a.lo2 = carryop.Input(1)
		case carryop.Input(1) == a.lo1:
			a.lo2 = carryop.Input(0)
		default:
			return false
		}
		if a.lo2.IsConstant() {
			return false
		}
		return true
	case CPUI_INT_LESS:
		tmpvn := carryop.Input(0)
		if tmpvn.IsConstant() {
			if carryop.Input(1) != a.lo1 {
				return false
			}
			a.negconst = tmpvn.Offset()
			a.negconst = (^a.negconst) & doubleMaskOfSize(a.lo1.Size())
			a.lo2 = nil
			return true
		}
		if tmpvn.IsWritten() {
			loaddOp := tmpvn.Def()
			if loaddOp.Code() != CPUI_INT_ADD {
				return false
			}
			var othervn *Varnode
			switch {
			case loaddOp.Input(0) == a.lo1:
				othervn = loaddOp.Input(1)
			case loaddOp.Input(1) == a.lo1:
				othervn = loaddOp.Input(0)
			default:
				return false
			}
			if othervn.IsConstant() {
				a.negconst = othervn.Offset()
				a.lo2 = nil
				relvn := carryop.Input(1)
				if relvn == a.lo1 {
					return true
				}
				if !relvn.IsConstant() {
					return false
				}
				if relvn.Offset() != a.negconst {
					return false
				}
				return true
			}
			a.lo2 = othervn
			compvn := carryop.Input(1)
			if compvn == a.lo2 || compvn == a.lo1 {
				return true
			}
		}
		return false
	case CPUI_INT_NOTEQUAL:
		if !carryop.Input(1).IsConstant() {
			return false
		}
		if carryop.Input(0) != a.lo1 {
			return false
		}
		if carryop.Input(1).Offset() != 0 {
			return false
		}
		a.negconst = doubleMaskOfSize(a.lo1.Size())
		a.lo2 = nil
		return true
	}
	return false
}

// verify mirrors AddForm::verify (double.cc:1515).
func (a *AddForm) verify(h, l *Varnode, op *PcodeOp) bool {
	a.hi1 = h
	a.lo1 = l
	a.slot1 = op.GetSlot(a.hi1)
	for i := 0; i < 3; i++ {
		switch i {
		case 0:
			a.add2 = op.Output().LoneDescend()
			if a.add2 == nil {
				continue
			}
			if a.add2.Code() != CPUI_INT_ADD {
				continue
			}
			a.reshi = a.add2.Output()
			a.hizext1 = op.Input(1 - a.slot1)
			a.hizext2 = a.add2.Input(1 - a.add2.GetSlot(op.Output()))
		case 1:
			tmpvn := op.Input(1 - a.slot1)
			if !tmpvn.IsWritten() {
				continue
			}
			a.add2 = tmpvn.Def()
			if a.add2.Code() != CPUI_INT_ADD {
				continue
			}
			a.reshi = op.Output()
			a.hizext1 = a.add2.Input(0)
			a.hizext2 = a.add2.Input(1)
		case 2:
			a.reshi = op.Output()
			a.hizext1 = op.Input(1 - a.slot1)
			a.hizext2 = nil
		}
		for j := 0; j < 2; j++ {
			if i == 2 {
				if !a.hizext1.IsWritten() {
					continue
				}
				a.zextop = a.hizext1.Def()
				a.hi2 = nil
			} else if j == 0 {
				if !a.hizext1.IsWritten() {
					continue
				}
				a.zextop = a.hizext1.Def()
				a.hi2 = a.hizext2
			} else {
				if a.hizext2 == nil || !a.hizext2.IsWritten() {
					continue
				}
				a.zextop = a.hizext2.Def()
				a.hi2 = a.hizext1
			}
			if !a.checkForCarry(a.zextop) {
				continue
			}
			for _, cand := range a.lo1.DescendIter() {
				if cand.Code() != CPUI_INT_ADD {
					continue
				}
				tmpvn := cand.Input(1 - cand.GetSlot(a.lo1))
				if a.lo2 == nil {
					if !tmpvn.IsConstant() {
						continue
					}
					if tmpvn.Offset() != a.negconst {
						continue
					}
					a.lo2 = tmpvn
				} else if a.lo2.IsConstant() {
					if !tmpvn.IsConstant() {
						continue
					}
					if a.lo2.Offset() != tmpvn.Offset() {
						continue
					}
				} else if cand.Input(1-cand.GetSlot(a.lo1)) != a.lo2 {
					continue
				}
				a.loadd = cand
				a.reslo = cand.Output()
				return true
			}
		}
	}
	return false
}

// ApplyRule mirrors AddForm::applyRule (double.cc:1589).
func (a *AddForm) ApplyRule(i *SplitVarnode, op *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	a.in = *i
	if !a.verify(a.in.GetHi(), a.in.GetLo(), op) {
		return false
	}
	a.indoub.InitPartialPieces(a.in.GetSize(), a.lo2, a.hi2)
	if a.indoub.ExceedsConstPrecision() {
		return false
	}
	a.outdoub.InitPartialPieces(a.in.GetSize(), a.reslo, a.reshi)
	a.existop = SplitVarnodePrepareBinaryOp(&a.outdoub, &a.in, &a.indoub)
	if a.existop == nil {
		return false
	}
	SplitVarnodeCreateBinaryOp(data, &a.outdoub, &a.in, &a.indoub, a.existop, CPUI_INT_ADD)
	*i = a.in
	return true
}

// -----------------------------------------------------------------------------
// SubForm
// -----------------------------------------------------------------------------

// SubForm recovers a double-precision subtraction.
// C++ parity: class SubForm (double.hh:119)
type SubForm struct {
	in               SplitVarnode
	hi1, hi2         *Varnode
	lo1, lo2         *Varnode
	reshi, reslo     *Varnode
	zextop           *PcodeOp
	lessop           *PcodeOp
	negop            *PcodeOp
	loadd            *PcodeOp
	add2             *PcodeOp
	hineg1, hineg2   *Varnode
	hizext1, hizext2 *Varnode
	slot1            int
	existop          *PcodeOp
	indoub           SplitVarnode
	outdoub          SplitVarnode
}

// verify mirrors SubForm::verify (double.cc:1616).
func (s *SubForm) verify(h, l *Varnode, op *PcodeOp) bool {
	s.hi1 = h
	s.lo1 = l
	s.slot1 = op.GetSlot(s.hi1)
	for i := 0; i < 2; i++ {
		if i == 0 {
			s.add2 = op.Output().LoneDescend()
			if s.add2 == nil {
				continue
			}
			if s.add2.Code() != CPUI_INT_ADD {
				continue
			}
			s.reshi = s.add2.Output()
			s.hineg1 = op.Input(1 - s.slot1)
			s.hineg2 = s.add2.Input(1 - s.add2.GetSlot(op.Output()))
		} else {
			tmpvn := op.Input(1 - s.slot1)
			if !tmpvn.IsWritten() {
				continue
			}
			s.add2 = tmpvn.Def()
			if s.add2.Code() != CPUI_INT_ADD {
				continue
			}
			s.reshi = op.Output()
			s.hineg1 = s.add2.Input(0)
			s.hineg2 = s.add2.Input(1)
		}
		if !s.hineg1.IsWritten() || !s.hineg2.IsWritten() {
			continue
		}
		if !SplitVarnodeVerifyMultNegOne(s.hineg1.Def()) {
			continue
		}
		if !SplitVarnodeVerifyMultNegOne(s.hineg2.Def()) {
			continue
		}
		s.hizext1 = s.hineg1.Def().Input(0)
		s.hizext2 = s.hineg2.Def().Input(0)
		for j := 0; j < 2; j++ {
			if j == 0 {
				if !s.hizext1.IsWritten() {
					continue
				}
				s.zextop = s.hizext1.Def()
				s.hi2 = s.hizext2
			} else {
				if !s.hizext2.IsWritten() {
					continue
				}
				s.zextop = s.hizext2.Def()
				s.hi2 = s.hizext1
			}
			if s.zextop.Code() != CPUI_INT_ZEXT {
				continue
			}
			if !s.zextop.Input(0).IsWritten() {
				continue
			}
			s.lessop = s.zextop.Input(0).Def()
			if s.lessop.Code() != CPUI_INT_LESS {
				continue
			}
			if s.lessop.Input(0) != s.lo1 {
				continue
			}
			s.lo2 = s.lessop.Input(1)
			for _, cand := range s.lo1.DescendIter() {
				if cand.Code() != CPUI_INT_ADD {
					continue
				}
				tmpvn := cand.Input(1 - cand.GetSlot(s.lo1))
				if !tmpvn.IsWritten() {
					continue
				}
				s.negop = tmpvn.Def()
				if !SplitVarnodeVerifyMultNegOne(s.negop) {
					continue
				}
				if s.negop.Input(0) != s.lo2 {
					continue
				}
				s.loadd = cand
				s.reslo = cand.Output()
				return true
			}
		}
	}
	return false
}

// ApplyRule mirrors SubForm::applyRule (double.cc:1683).
func (s *SubForm) ApplyRule(i *SplitVarnode, op *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	s.in = *i
	if !s.verify(s.in.GetHi(), s.in.GetLo(), op) {
		return false
	}
	s.indoub.InitPartialPieces(s.in.GetSize(), s.lo2, s.hi2)
	if s.indoub.ExceedsConstPrecision() {
		return false
	}
	s.outdoub.InitPartialPieces(s.in.GetSize(), s.reslo, s.reshi)
	s.existop = SplitVarnodePrepareBinaryOp(&s.outdoub, &s.in, &s.indoub)
	if s.existop == nil {
		return false
	}
	SplitVarnodeCreateBinaryOp(data, &s.outdoub, &s.in, &s.indoub, s.existop, CPUI_INT_SUB)
	*i = s.in
	return true
}

// -----------------------------------------------------------------------------
// LogicalForm
// -----------------------------------------------------------------------------

// LogicalForm recovers a double-precision AND/OR/XOR.
// C++ parity: class LogicalForm (double.hh:135)
type LogicalForm struct {
	in       SplitVarnode
	loop     *PcodeOp
	hiop     *PcodeOp
	hi1, hi2 *Varnode
	lo1, lo2 *Varnode
	existop  *PcodeOp
	indoub   SplitVarnode
	outdoub  SplitVarnode
}

// findHiMatch mirrors LogicalForm::findHiMatch (double.cc:1704).
// Returns 0 when a matching hi op was found, -1/-2 otherwise.
func (lf *LogicalForm) findHiMatch() int {
	lo1Tmp := lf.in.GetLo()
	vn2 := lf.loop.Input(1 - lf.loop.GetSlot(lo1Tmp))

	var out SplitVarnode
	if out.InHandLoOut(lo1Tmp) {
		hi := out.GetHi()
		if hi.IsWritten() {
			maybeop := hi.Def()
			if maybeop.Code() == lf.loop.Code() {
				if maybeop.Input(0) == lf.hi1 {
					if maybeop.Input(1).IsConstant() == vn2.IsConstant() {
						lf.hiop = maybeop
						return 0
					}
				} else if maybeop.Input(1) == lf.hi1 {
					if maybeop.Input(0).IsConstant() == vn2.IsConstant() {
						lf.hiop = maybeop
						return 0
					}
				}
			}
		}
	}

	if !vn2.IsConstant() {
		var in2 SplitVarnode
		if in2.InHandLo(vn2) {
			for _, maybeop := range in2.GetHi().DescendIter() {
				if maybeop.Code() == lf.loop.Code() {
					if maybeop.Input(0) == lf.hi1 || maybeop.Input(1) == lf.hi1 {
						lf.hiop = maybeop
						return 0
					}
				}
			}
		}
		return -1
	}

	// vn2 is constant: look for a unique matching op off hi1
	count := 0
	var lastop *PcodeOp
	for _, maybeop := range lf.hi1.DescendIter() {
		if maybeop.Code() == lf.loop.Code() {
			if maybeop.Input(1).IsConstant() {
				count++
				if count > 1 {
					break
				}
				lastop = maybeop
			}
		}
	}
	if count == 1 {
		lf.hiop = lastop
		return 0
	}
	if count > 1 {
		return -1
	}
	return -2
}

// verify mirrors LogicalForm::verify (double.cc:1787).
func (lf *LogicalForm) verify(h, l *Varnode, lop *PcodeOp) bool {
	lf.loop = lop
	lf.lo1 = l
	lf.hi1 = h
	if lf.findHiMatch() != 0 {
		return false
	}
	lf.lo2 = lf.loop.Input(1 - lf.loop.GetSlot(lf.lo1))
	lf.hi2 = lf.hiop.Input(1 - lf.hiop.GetSlot(lf.hi1))
	if lf.lo2 == lf.lo1 || lf.lo2 == lf.hi1 || lf.hi2 == lf.hi1 || lf.hi2 == lf.lo1 {
		return false
	}
	if lf.lo2 == lf.hi2 {
		return false
	}
	return true
}

// ApplyRule mirrors LogicalForm::applyRule (double.cc:1805).
func (lf *LogicalForm) ApplyRule(i *SplitVarnode, lop *PcodeOp, workishi bool, data *Funcdata) bool {
	if workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	lf.in = *i
	if !lf.verify(lf.in.GetHi(), lf.in.GetLo(), lop) {
		return false
	}
	lf.outdoub.InitPartialPieces(lf.in.GetSize(), lf.loop.Output(), lf.hiop.Output())
	lf.indoub.InitPartialPieces(lf.in.GetSize(), lf.lo2, lf.hi2)
	if lf.indoub.ExceedsConstPrecision() {
		return false
	}
	lf.existop = SplitVarnodePrepareBinaryOp(&lf.outdoub, &lf.in, &lf.indoub)
	if lf.existop == nil {
		return false
	}
	SplitVarnodeCreateBinaryOp(data, &lf.outdoub, &lf.in, &lf.indoub, lf.existop, lf.loop.Code())
	*i = lf.in
	return true
}

// -----------------------------------------------------------------------------
// ShiftForm
// -----------------------------------------------------------------------------

// ShiftForm recovers a double-precision shift.
// C++ parity: class ShiftForm (double.hh:228)
type ShiftForm struct {
	in                  SplitVarnode
	opc                 OpCode
	loshift             *PcodeOp
	midshift            *PcodeOp
	hishift             *PcodeOp
	orop                *PcodeOp
	lo, hi              *Varnode
	midlo, midhi        *Varnode
	salo, sahi, samid   *Varnode
	reslo, reshi        *Varnode
	out                 SplitVarnode
	existop             *PcodeOp
}

// mapLeft mirrors ShiftForm::mapLeft (double.cc:2550).
func (sf *ShiftForm) mapLeft() bool {
	if !sf.reslo.IsWritten() || !sf.reshi.IsWritten() {
		return false
	}
	sf.loshift = sf.reslo.Def()
	sf.opc = sf.loshift.Code()
	if sf.opc != CPUI_INT_LEFT {
		return false
	}
	sf.orop = sf.reshi.Def()
	switch sf.orop.Code() {
	case CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_ADD:
	default:
		return false
	}
	sf.midlo = sf.orop.Input(0)
	sf.midhi = sf.orop.Input(1)
	if !sf.midlo.IsWritten() || !sf.midhi.IsWritten() {
		return false
	}
	if sf.midhi.Def().Code() != CPUI_INT_LEFT {
		sf.midhi, sf.midlo = sf.midlo, sf.midhi
	}
	sf.midshift = sf.midlo.Def()
	if sf.midshift.Code() != CPUI_INT_RIGHT {
		return false
	}
	sf.hishift = sf.midhi.Def()
	if sf.hishift.Code() != CPUI_INT_LEFT {
		return false
	}
	if sf.lo != sf.loshift.Input(0) {
		return false
	}
	if sf.hi != sf.hishift.Input(0) {
		return false
	}
	if sf.lo != sf.midshift.Input(0) {
		return false
	}
	sf.salo = sf.loshift.Input(1)
	sf.sahi = sf.hishift.Input(1)
	sf.samid = sf.midshift.Input(1)
	return true
}

// mapRight mirrors ShiftForm::mapRight (double.cc:2584).
func (sf *ShiftForm) mapRight() bool {
	if !sf.reslo.IsWritten() || !sf.reshi.IsWritten() {
		return false
	}
	sf.hishift = sf.reshi.Def()
	sf.opc = sf.hishift.Code()
	if sf.opc != CPUI_INT_RIGHT && sf.opc != CPUI_INT_SRIGHT {
		return false
	}
	sf.orop = sf.reslo.Def()
	switch sf.orop.Code() {
	case CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_ADD:
	default:
		return false
	}
	sf.midlo = sf.orop.Input(0)
	sf.midhi = sf.orop.Input(1)
	if !sf.midlo.IsWritten() || !sf.midhi.IsWritten() {
		return false
	}
	if sf.midlo.Def().Code() != CPUI_INT_RIGHT {
		sf.midhi, sf.midlo = sf.midlo, sf.midhi
	}
	sf.midshift = sf.midhi.Def()
	if sf.midshift.Code() != CPUI_INT_LEFT {
		return false
	}
	sf.loshift = sf.midlo.Def()
	if sf.loshift.Code() != CPUI_INT_RIGHT {
		return false
	}
	if sf.lo != sf.loshift.Input(0) {
		return false
	}
	if sf.hi != sf.hishift.Input(0) {
		return false
	}
	if sf.hi != sf.midshift.Input(0) {
		return false
	}
	sf.salo = sf.loshift.Input(1)
	sf.sahi = sf.hishift.Input(1)
	sf.samid = sf.midshift.Input(1)
	return true
}

// verifyShiftAmount mirrors ShiftForm::verifyShiftAmount (double.cc:2618).
func (sf *ShiftForm) verifyShiftAmount() bool {
	if !sf.salo.IsConstant() || !sf.samid.IsConstant() || !sf.sahi.IsConstant() {
		return false
	}
	val := sf.salo.Offset()
	if val != sf.sahi.Offset() {
		return false
	}
	if val >= uint64(8*sf.lo.Size()) {
		return false
	}
	complement := uint64(8*sf.lo.Size()) - val
	return sf.samid.Offset() == complement
}

// verifyLeft mirrors ShiftForm::verifyLeft (double.cc:2632).
func (sf *ShiftForm) verifyLeft(h, l *Varnode, loop *PcodeOp) bool {
	sf.hi = h
	sf.lo = l
	sf.loshift = loop
	sf.reslo = sf.loshift.Output()
	for _, hishift := range sf.hi.DescendIter() {
		if hishift.Code() != CPUI_INT_LEFT {
			continue
		}
		sf.hishift = hishift
		outvn := hishift.Output()
		for _, midshift := range outvn.DescendIter() {
			sf.midshift = midshift
			tmpvn := midshift.Output()
			if tmpvn == nil {
				continue
			}
			sf.reshi = tmpvn
			if !sf.mapLeft() {
				continue
			}
			if !sf.verifyShiftAmount() {
				continue
			}
			return true
		}
	}
	return false
}

// verifyRight mirrors ShiftForm::verifyRight (double.cc:2666).
func (sf *ShiftForm) verifyRight(h, l *Varnode, hiop *PcodeOp) bool {
	sf.hi = h
	sf.lo = l
	sf.hishift = hiop
	sf.reshi = hiop.Output()
	for _, loshift := range sf.lo.DescendIter() {
		if loshift.Code() != CPUI_INT_RIGHT {
			continue
		}
		sf.loshift = loshift
		outvn := loshift.Output()
		for _, midshift := range outvn.DescendIter() {
			sf.midshift = midshift
			tmpvn := midshift.Output()
			if tmpvn == nil {
				continue
			}
			sf.reslo = tmpvn
			if !sf.mapRight() {
				continue
			}
			if !sf.verifyShiftAmount() {
				continue
			}
			return true
		}
	}
	return false
}

// ApplyRuleLeft mirrors ShiftForm::applyRuleLeft (double.cc:2699).
func (sf *ShiftForm) ApplyRuleLeft(i *SplitVarnode, loop *PcodeOp, workishi bool, data *Funcdata) bool {
	if workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	sf.in = *i
	if !sf.verifyLeft(sf.in.GetHi(), sf.in.GetLo(), loop) {
		return false
	}
	sf.out.InitPartialPieces(sf.in.GetSize(), sf.reslo, sf.reshi)
	sf.existop = SplitVarnodePrepareShiftOp(&sf.out, &sf.in)
	if sf.existop == nil {
		return false
	}
	SplitVarnodeCreateShiftOp(data, &sf.out, &sf.in, sf.salo, sf.existop, sf.opc)
	*i = sf.in
	return true
}

// ApplyRuleRight mirrors ShiftForm::applyRuleRight (double.cc:2717).
func (sf *ShiftForm) ApplyRuleRight(i *SplitVarnode, hiop *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	sf.in = *i
	if !sf.verifyRight(sf.in.GetHi(), sf.in.GetLo(), hiop) {
		return false
	}
	sf.out.InitPartialPieces(sf.in.GetSize(), sf.reslo, sf.reshi)
	sf.existop = SplitVarnodePrepareShiftOp(&sf.out, &sf.in)
	if sf.existop == nil {
		return false
	}
	SplitVarnodeCreateShiftOp(data, &sf.out, &sf.in, sf.salo, sf.existop, sf.opc)
	*i = sf.in
	return true
}

// -----------------------------------------------------------------------------
// PhiForm
// -----------------------------------------------------------------------------

// PhiForm recovers a double-precision MULTIEQUAL.
// C++ parity: class PhiForm (double.hh:274)
type PhiForm struct {
	in             SplitVarnode
	outvn          SplitVarnode
	inslot         int
	hibase, lobase *Varnode
	blbase         *BlockBasic
	lophi, hiphi   *PcodeOp
	existop        *PcodeOp
}

// verify mirrors PhiForm::verify (double.cc:3028).
func (pf *PhiForm) verify(h, l *Varnode, hphi *PcodeOp) bool {
	pf.hibase = h
	pf.lobase = l
	pf.hiphi = hphi
	pf.inslot = hphi.GetSlot(pf.hibase)
	if pf.hiphi.Output() == nil || pf.hiphi.Output().HasNoDescend() {
		return false
	}
	pf.blbase = pf.hiphi.Parent()
	for _, cand := range pf.lobase.DescendIter() {
		if cand.Code() != CPUI_MULTIEQUAL {
			continue
		}
		if cand.Parent() != pf.blbase {
			continue
		}
		if cand.Input(pf.inslot) != pf.lobase {
			continue
		}
		pf.lophi = cand
		return true
	}
	return false
}

// ApplyRule mirrors PhiForm::applyRule (double.cc:3054).
func (pf *PhiForm) ApplyRule(i *SplitVarnode, hphi *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	pf.in = *i
	if !pf.verify(pf.in.GetHi(), pf.in.GetLo(), hphi) {
		return false
	}
	numin := pf.hiphi.NumInput()
	inlist := make([]SplitVarnode, 0, numin)
	for j := 0; j < numin; j++ {
		vhi := pf.hiphi.Input(j)
		vlo := pf.lophi.Input(j)
		inlist = append(inlist, NewSplitVarnodePieces(vlo, vhi))
	}
	pf.outvn.InitPartialPieces(pf.in.GetSize(), pf.lophi.Output(), pf.hiphi.Output())
	pf.existop = SplitVarnodePreparePhiOp(&pf.outvn, inlist)
	if pf.existop == nil {
		return false
	}
	SplitVarnodeCreatePhiOp(data, &pf.outvn, inlist, pf.existop)
	*i = pf.in
	return true
}

// -----------------------------------------------------------------------------
// CopyForceForm
// -----------------------------------------------------------------------------

// CopyForceForm collapses two COPYs into a contiguous address-forced COPY.
// C++ parity: class CopyForceForm (double.hh:303)
type CopyForceForm struct {
	in             SplitVarnode
	reslo, reshi   *Varnode
	copylo, copyhi *PcodeOp
	addrOut        address.Address
}

// verify mirrors CopyForceForm::verify (double.cc:3137).
// The ReturnCopy special form is not ported: PcodeOp.isReturnCopy/markReturnCopy
// are not yet plumbed. Common case (single block, contiguous storage) works.
func (cf *CopyForceForm) verify(h, l, w *Varnode, cpy *PcodeOp) bool {
	if w == nil {
		return false
	}
	cf.copyhi = cpy
	if cf.copyhi.Input(0) != h {
		return false
	}
	cf.reshi = cf.copyhi.Output()
	if !cf.reshi.IsAddrForce() || !cf.reshi.HasNoDescend() {
		return false
	}
	for _, cand := range l.DescendIter() {
		if cand.Code() != CPUI_COPY || cand.Parent() != cf.copyhi.Parent() {
			continue
		}
		cf.copylo = cand
		cf.reslo = cand.Output()
		if !cf.reslo.IsAddrForce() || !cf.reslo.HasNoDescend() {
			continue
		}
		addrOut, ok := SplitVarnodeIsAddrTiedContiguous(cf.reslo, cf.reshi)
		if !ok {
			continue
		}
		cf.addrOut = addrOut
		return true
	}
	return false
}

// ApplyRule mirrors CopyForceForm::applyRule (double.cc:3186).
func (cf *CopyForceForm) ApplyRule(i *SplitVarnode, cpy *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	cf.in = *i
	if !cf.verify(cf.in.GetHi(), cf.in.GetLo(), cf.in.GetWhole(), cpy) {
		return false
	}
	// Ensure the whole exists (C++ assumes in.whole != nil; we also accept
	// an InitPartial whole via FindCreateWhole for safety).
	if cf.in.GetWhole() == nil {
		cf.in.FindCreateWhole(data)
	}
	SplitVarnodeReplaceCopyForce(data, cf.addrOut, &cf.in, cf.copylo, cf.copyhi)
	*i = cf.in
	return true
}

// -----------------------------------------------------------------------------
// LessConstForm
// -----------------------------------------------------------------------------

// LessConstForm recovers a double-precision less-than against a constant.
// C++ parity: class LessConstForm (double.hh:218)
type LessConstForm struct {
	in                        SplitVarnode
	vn, cvn                   *Varnode
	inslot                    int
	signcompare, hilessequal  bool
	constin                   SplitVarnode
}

// ApplyRule mirrors LessConstForm::applyRule (double.cc:2505).
func (lcf *LessConstForm) ApplyRule(i *SplitVarnode, op *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if i.GetHi() == nil {
		return false
	}
	lcf.in = *i
	lcf.vn = lcf.in.GetHi()
	lcf.inslot = op.GetSlot(lcf.vn)
	lcf.cvn = op.Input(1 - lcf.inslot)
	losize := lcf.in.GetSize() - lcf.vn.Size()
	if !lcf.cvn.IsConstant() {
		return false
	}
	lcf.signcompare = op.Code() == CPUI_INT_SLESSEQUAL || op.Code() == CPUI_INT_SLESS
	lcf.hilessequal = op.Code() == CPUI_INT_SLESSEQUAL || op.Code() == CPUI_INT_LESSEQUAL
	val := lcf.cvn.Offset() << uint(8*losize)
	if lcf.hilessequal != (lcf.inslot == 1) {
		val |= doubleMaskOfSize(losize)
	}
	desc := op.Output().LoneDescend()
	if desc == nil || desc.Code() != CPUI_CBRANCH {
		return false
	}
	lcf.constin.InitPartialConst(lcf.in.GetSize(), val)
	if lcf.constin.ExceedsConstPrecision() {
		return false
	}
	if lcf.inslot == 0 {
		if SplitVarnodePrepareBoolOp(&lcf.in, &lcf.constin, op) {
			SplitVarnodeReplaceBoolOp(data, op, &lcf.in, &lcf.constin, op.Code())
			*i = lcf.in
			return true
		}
	} else {
		if SplitVarnodePrepareBoolOp(&lcf.constin, &lcf.in, op) {
			SplitVarnodeReplaceBoolOp(data, op, &lcf.constin, &lcf.in, op.Code())
			*i = lcf.in
			return true
		}
	}
	return false
}
