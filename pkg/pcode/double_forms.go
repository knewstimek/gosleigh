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
//   - Equal1Form     (double.cc:1836 -- applyRule over CBRANCH edge layout)
//   - Equal2Form     (double.cc:1918 -- replace, applyRule over BOOL_AND/OR)
//   - Equal3Form     (double.cc:1984 -- verify, applyRule over INT_AND + cmp)
//   - MultForm       (double.cc:2735 -- map/verify/replace zext+sub recovery)
//   - LessThreeWay   (double.cc:2026 -- cross-block three-way compare FSM)
//
// Ported Forms (PARTIAL):
//   - IndirectForm   (double.cc:3080 -- IOP-affector lookup approximated by
//                     seqnum address match; see TODO in IndirectForm comment)

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

// -----------------------------------------------------------------------------
// Equal1Form
// -----------------------------------------------------------------------------

// Equal1Form recovers a double-precision equality test expressed as a pair of
// CBRANCHes where the high piece is tested first and the low piece follows on
// the "equal" edge (or vice versa).
// C++ parity: class Equal1Form (double.hh:148)
type Equal1Form struct {
	in1, in2                       SplitVarnode
	loop, hiop                     *PcodeOp
	hibool, lobool                 *PcodeOp
	hi1, lo1, hi2, lo2             *Varnode
	hi1slot, lo1slot               int
	notequalformhi, notequalformlo bool
	setonlow                       bool
}

// ApplyRule mirrors Equal1Form::applyRule (double.cc:1836).
func (ef *Equal1Form) ApplyRule(i *SplitVarnode, hop *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	ef.in1 = *i
	ef.hiop = hop
	ef.hi1 = ef.in1.GetHi()
	ef.lo1 = ef.in1.GetLo()
	ef.hi1slot = ef.hiop.GetSlot(ef.hi1)
	ef.hi2 = ef.hiop.Input(1 - ef.hi1slot)
	ef.notequalformhi = ef.hiop.Code() == CPUI_INT_NOTEQUAL

	loDescs := append([]*PcodeOp(nil), ef.lo1.DescendIter()...)
	for _, loop := range loDescs {
		ef.loop = loop
		switch loop.Code() {
		case CPUI_INT_EQUAL:
			ef.notequalformlo = false
		case CPUI_INT_NOTEQUAL:
			ef.notequalformlo = true
		default:
			continue
		}
		ef.lo1slot = loop.GetSlot(ef.lo1)
		ef.lo2 = loop.Input(1 - ef.lo1slot)

		hiOut := ef.hiop.Output()
		if hiOut == nil {
			continue
		}
		loOut := loop.Output()
		if loOut == nil {
			continue
		}
		hiDescs := append([]*PcodeOp(nil), hiOut.DescendIter()...)
		for _, hibool := range hiDescs {
			ef.hibool = hibool
			loDescs2 := append([]*PcodeOp(nil), loOut.DescendIter()...)
			for _, lobool := range loDescs2 {
				ef.lobool = lobool

				ef.in2.InitPartialPieces(ef.in1.GetSize(), ef.lo2, ef.hi2)
				if ef.in2.ExceedsConstPrecision() {
					continue
				}

				if hibool.Code() != CPUI_CBRANCH || lobool.Code() != CPUI_CBRANCH {
					continue
				}
				hibooltrue, hiboolfalse := SplitVarnodeGetTrueFalse(hibool, ef.notequalformhi)
				lobooltrue, loboolfalse := SplitVarnodeGetTrueFalse(lobool, ef.notequalformlo)

				if hibooltrue == lobool.Parent() && hiboolfalse == loboolfalse && SplitVarnodeOtherwiseEmpty(lobool) {
					// hi is checked first then lo
					if SplitVarnodePrepareBoolOp(&ef.in1, &ef.in2, hibool) {
						ef.setonlow = true
						opc := CPUI_INT_EQUAL
						if ef.notequalformhi {
							opc = CPUI_INT_NOTEQUAL
						}
						SplitVarnodeCreateBoolOp(data, hibool, &ef.in1, &ef.in2, opc)
						// Force lobool to always reach the original TRUE block.
						var lobConst uint64 = 1
						if ef.notequalformlo {
							lobConst = 0
						}
						data.OpSetInput(lobool, data.NewConstant(1, lobConst), 1)
						*i = ef.in1
						return true
					}
				} else if lobooltrue == hibool.Parent() && hiboolfalse == loboolfalse && SplitVarnodeOtherwiseEmpty(hibool) {
					// lo is checked first then hi
					if SplitVarnodePrepareBoolOp(&ef.in1, &ef.in2, lobool) {
						ef.setonlow = false
						opc := CPUI_INT_EQUAL
						if ef.notequalformlo {
							opc = CPUI_INT_NOTEQUAL
						}
						SplitVarnodeCreateBoolOp(data, lobool, &ef.in1, &ef.in2, opc)
						// Force hibool to always reach the original TRUE block.
						var hibConst uint64 = 1
						if ef.notequalformhi {
							hibConst = 0
						}
						data.OpSetInput(hibool, data.NewConstant(1, hibConst), 1)
						*i = ef.in1
						return true
					}
				}
				_ = hibooltrue
				_ = lobooltrue
			}
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Equal2Form
// -----------------------------------------------------------------------------

// Equal2Form recovers a double-precision equality expressed through
// BOOL_AND / BOOL_OR of two matching INT_EQUAL / INT_NOTEQUAL ops on the
// high and low pieces.
// C++ parity: class Equal2Form (double.hh:161)
type Equal2Form struct {
	in                 SplitVarnode
	hi1, hi2, lo1, lo2 *Varnode
	boolAndOr          *PcodeOp
	param2             SplitVarnode
}

// replace mirrors Equal2Form::replace (double.cc:1918).
// C++ parity: Equal2Form::replace (double.cc:1918)
func (ef *Equal2Form) replace(data *Funcdata) bool {
	if ef.hi2.IsConstant() && ef.lo2.IsConstant() {
		val := ef.hi2.Offset()
		val <<= uint(8 * ef.lo1.Size())
		val |= ef.lo2.Offset()
		ef.param2.InitPartialConst(ef.in.GetSize(), val)
		return SplitVarnodePrepareBoolOp(&ef.in, &ef.param2, ef.boolAndOr)
	}
	if ef.hi2.IsConstant() || ef.lo2.IsConstant() {
		// Mixed form is not handled -- the C++ rule bails out too.
		return false
	}
	ef.param2.InitPartialPieces(ef.in.GetSize(), ef.lo2, ef.hi2)
	return SplitVarnodePrepareBoolOp(&ef.in, &ef.param2, ef.boolAndOr)
}

// ApplyRule mirrors Equal2Form::applyRule (double.cc:1942).
func (ef *Equal2Form) ApplyRule(i *SplitVarnode, op *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	ef.in = *i
	ef.hi1 = ef.in.GetHi()
	ef.lo1 = ef.in.GetLo()
	eqCode := op.Code()
	hi1slot := op.GetSlot(ef.hi1)
	ef.hi2 = op.Input(1 - hi1slot)
	outvn := op.Output()
	if outvn == nil {
		return false
	}
	descs := append([]*PcodeOp(nil), outvn.DescendIter()...)
	for _, boolAndOr := range descs {
		ef.boolAndOr = boolAndOr
		if eqCode == CPUI_INT_EQUAL && boolAndOr.Code() != CPUI_BOOL_AND {
			continue
		}
		if eqCode == CPUI_INT_NOTEQUAL && boolAndOr.Code() != CPUI_BOOL_OR {
			continue
		}
		slot := boolAndOr.GetSlot(outvn)
		othervn := boolAndOr.Input(1 - slot)
		if !othervn.IsWritten() {
			continue
		}
		equalLo := othervn.Def()
		if equalLo.Code() != eqCode {
			continue
		}
		if equalLo.Input(0) == ef.lo1 {
			ef.lo2 = equalLo.Input(1)
		} else if equalLo.Input(1) == ef.lo1 {
			ef.lo2 = equalLo.Input(0)
		} else {
			continue
		}
		if !ef.replace(data) {
			continue
		}
		if ef.param2.ExceedsConstPrecision() {
			continue
		}
		SplitVarnodeReplaceBoolOp(data, boolAndOr, &ef.in, &ef.param2, eqCode)
		*i = ef.in
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// Equal3Form
// -----------------------------------------------------------------------------

// Equal3Form recovers `a == -1` / `a != -1` expressed as `(hi & lo) == -1`.
// C++ parity: class Equal3Form (double.hh:171)
type Equal3Form struct {
	in                  SplitVarnode
	hi, lo              *Varnode
	andop, compareop    *PcodeOp
	smallc              *Varnode
}

// verify mirrors Equal3Form::verify (double.cc:1984).
// C++ parity: Equal3Form::verify (double.cc:1984)
func (ef *Equal3Form) verify(h, l *Varnode, aop *PcodeOp) bool {
	if aop.Code() != CPUI_INT_AND {
		return false
	}
	ef.hi = h
	ef.lo = l
	ef.andop = aop
	hislot := aop.GetSlot(ef.hi)
	if aop.Input(1-hislot) != ef.lo {
		return false
	}
	out := aop.Output()
	if out == nil {
		return false
	}
	ef.compareop = out.LoneDescend()
	if ef.compareop == nil {
		return false
	}
	if ef.compareop.Code() != CPUI_INT_EQUAL && ef.compareop.Code() != CPUI_INT_NOTEQUAL {
		return false
	}
	allones := doubleMaskOfSize(ef.lo.Size())
	ef.smallc = ef.compareop.Input(1)
	if !ef.smallc.IsConstant() {
		return false
	}
	if ef.smallc.Offset() != allones {
		return false
	}
	return true
}

// ApplyRule mirrors Equal3Form::applyRule (double.cc:2009).
func (ef *Equal3Form) ApplyRule(i *SplitVarnode, op *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	ef.in = *i
	if !ef.verify(ef.in.GetHi(), ef.in.GetLo(), op) {
		return false
	}
	var in2 SplitVarnode
	in2.InitPartialConst(ef.in.GetSize(), doubleMaskOfSize(ef.in.GetSize()))
	if in2.ExceedsConstPrecision() {
		return false
	}
	if !SplitVarnodePrepareBoolOp(&ef.in, &in2, ef.compareop) {
		return false
	}
	SplitVarnodeReplaceBoolOp(data, ef.compareop, &ef.in, &in2, ef.compareop.Code())
	*i = ef.in
	return true
}

// -----------------------------------------------------------------------------
// LessThreeWay
// -----------------------------------------------------------------------------

// LessThreeWay recovers a double-precision less-than comparison expressed as
// three sequential CBRANCH blocks:
//
//	if (hi1  <  hi2) goto true   else goto blocksecond
//	blocksecond: if (hi1 == hi2) goto blockthird else goto false
//	blockthird:  if (lo1  <  lo2) goto true   else goto false
//
// The three blocks are collapsed into a single double-precision comparison
// at the entry CBRANCH; the middle and low CBRANCHes become unconditional
// (the lolessbool block is left unreachable for later removal).
// C++ parity: class LessThreeWay (double.hh:182, double.cc:2026-2496)
type LessThreeWay struct {
	in  SplitVarnode
	in2 SplitVarnode

	hilessbl, lolessbl, hieqbl     *BlockBasic
	hilesstrue, hilessfalse        *BlockBasic
	hieqtrue, hieqfalse            *BlockBasic
	lolesstrue, lolessfalse        *BlockBasic
	hilessbool, lolessbool, hieqbool *PcodeOp
	hiless, hiequal, loless        *PcodeOp
	vnhil1, vnhil2                 *Varnode
	vnhie1, vnhie2                 *Varnode
	vnlo1, vnlo2                   *Varnode
	hi, lo, hi2, lo2               *Varnode
	hislot                         int

	hiflip, equalflip, loflip      bool
	lolessiszerocomp               bool
	lolessequalform                bool
	hilessequalform, signcompare   bool
	midlessform, midlessequal      bool
	midsigncompare                 bool
	hiconstform, midconstform      bool
	loconstform                    bool
	hival, midval, loval           uint64
	finalopc                       OpCode
}

// mapBlocksFromLow walks back from the low-piece compare block to the
// hieq and hiless blocks. Returns false if the surrounding shape does not
// match a three-way compare (each prior block must have exactly one entry
// and exactly two exits).
// C++ parity: LessThreeWay::mapBlocksFromLow (double.cc:2026)
func (l *LessThreeWay) mapBlocksFromLow(lobl *BlockBasic) bool {
	l.lolessbl = lobl
	if l.lolessbl == nil {
		return false
	}
	if l.lolessbl.SizeIn() != 1 {
		return false
	}
	if l.lolessbl.SizeOut() != 2 {
		return false
	}
	hieqFB := l.lolessbl.InEdge(0).Point
	if hieqFB == nil {
		return false
	}
	hieqbb, ok := hieqFB.Concrete().(*BlockBasic)
	if !ok {
		return false
	}
	l.hieqbl = hieqbb
	if l.hieqbl.SizeIn() != 1 {
		return false
	}
	if l.hieqbl.SizeOut() != 2 {
		return false
	}
	hilessFB := l.hieqbl.InEdge(0).Point
	if hilessFB == nil {
		return false
	}
	hilessbb, ok := hilessFB.Concrete().(*BlockBasic)
	if !ok {
		return false
	}
	l.hilessbl = hilessbb
	if l.hilessbl.SizeOut() != 2 {
		return false
	}
	return true
}

// mapOpsFromBlocks identifies the trailing CBRANCH ops in each of the three
// candidate blocks and decodes the comparison flavour for each.
// C++ parity: LessThreeWay::mapOpsFromBlocks (double.cc:2041)
func (l *LessThreeWay) mapOpsFromBlocks() bool {
	l.lolessbool = l.lolessbl.LastOp()
	if l.lolessbool == nil || l.lolessbool.Code() != CPUI_CBRANCH {
		return false
	}
	l.hieqbool = l.hieqbl.LastOp()
	if l.hieqbool == nil || l.hieqbool.Code() != CPUI_CBRANCH {
		return false
	}
	l.hilessbool = l.hilessbl.LastOp()
	if l.hilessbool == nil || l.hilessbool.Code() != CPUI_CBRANCH {
		return false
	}

	l.hiflip = false
	l.equalflip = false
	l.loflip = false
	l.midlessform = false
	l.lolessiszerocomp = false

	vn := l.hieqbool.Input(1)
	if vn == nil || !vn.IsWritten() {
		return false
	}
	l.hiequal = vn.Def()
	switch l.hiequal.Code() {
	case CPUI_INT_EQUAL:
		l.midlessform = false
	case CPUI_INT_NOTEQUAL:
		l.midlessform = false
	case CPUI_INT_LESS:
		l.midlessequal = false
		l.midsigncompare = false
		l.midlessform = true
	case CPUI_INT_LESSEQUAL:
		l.midlessequal = true
		l.midsigncompare = false
		l.midlessform = true
	case CPUI_INT_SLESS:
		l.midlessequal = false
		l.midsigncompare = true
		l.midlessform = true
	case CPUI_INT_SLESSEQUAL:
		l.midlessequal = true
		l.midsigncompare = true
		l.midlessform = true
	default:
		return false
	}

	vn = l.lolessbool.Input(1)
	if vn == nil || !vn.IsWritten() {
		return false
	}
	l.loless = vn.Def()
	switch l.loless.Code() {
	case CPUI_INT_LESS:
		l.lolessequalform = false
	case CPUI_INT_LESSEQUAL:
		l.lolessequalform = true
	case CPUI_INT_EQUAL:
		if !l.loless.Input(1).IsConstant() {
			return false
		}
		if l.loless.Input(1).Offset() != 0 {
			return false
		}
		l.lolessiszerocomp = true
		l.lolessequalform = true
	case CPUI_INT_NOTEQUAL:
		if !l.loless.Input(1).IsConstant() {
			return false
		}
		if l.loless.Input(1).Offset() != 0 {
			return false
		}
		l.lolessiszerocomp = true
		l.lolessequalform = false
	default:
		return false
	}

	vn = l.hilessbool.Input(1)
	if vn == nil || !vn.IsWritten() {
		return false
	}
	l.hiless = vn.Def()
	switch l.hiless.Code() {
	case CPUI_INT_LESS:
		l.hilessequalform = false
		l.signcompare = false
	case CPUI_INT_LESSEQUAL:
		l.hilessequalform = true
		l.signcompare = false
	case CPUI_INT_SLESS:
		l.hilessequalform = false
		l.signcompare = true
	case CPUI_INT_SLESSEQUAL:
		l.hilessequalform = true
		l.signcompare = true
	default:
		return false
	}
	return true
}

// checkSignedness verifies that the middle compare (when expressed as a
// less-than rather than an equality) uses the same signedness as the high
// less-than. Without this, the three-way reconstruction is incorrect.
// C++ parity: LessThreeWay::checkSignedness (double.cc:2148)
func (l *LessThreeWay) checkSignedness() bool {
	if l.midlessform {
		if l.midsigncompare != l.signcompare {
			return false
		}
	}
	return true
}

// normalizeHi normalises the high compare so that constants live on the
// right and the false branch contains the equal case. Constant forms are
// folded into a hival shifted into the high half.
// C++ parity: LessThreeWay::normalizeHi (double.cc:2157)
func (l *LessThreeWay) normalizeHi() bool {
	var tmpvn *Varnode
	l.vnhil1 = l.hiless.Input(0)
	l.vnhil2 = l.hiless.Input(1)
	if l.vnhil1.IsConstant() {
		l.hiflip = !l.hiflip
		l.hilessequalform = !l.hilessequalform
		tmpvn = l.vnhil1
		l.vnhil1 = l.vnhil2
		l.vnhil2 = tmpvn
	}
	l.hiconstform = false
	if l.vnhil2.IsConstant() {
		// uintb in C++ is uint64; we need at least 8 bytes of precision.
		if l.in.GetSize() > 8 {
			return false
		}
		l.hiconstform = true
		l.hival = l.vnhil2.Offset()
		l.hilesstrue, l.hilessfalse = SplitVarnodeGetTrueFalse(l.hilessbool, l.hiflip)
		inc := int64(1)
		if l.hilessfalse != l.hieqbl {
			l.hiflip = !l.hiflip
			l.hilessequalform = !l.hilessequalform
			tmpvn = l.vnhil1
			l.vnhil1 = l.vnhil2
			l.vnhil2 = tmpvn
			inc = -1
		}
		if l.hilessequalform {
			if inc >= 0 {
				l.hival += uint64(inc)
			} else {
				l.hival -= uint64(-inc)
			}
			l.hival &= doubleMaskOfSize(l.in.GetSize())
			l.hilessequalform = false
		}
		l.hival >>= uint(l.in.GetLo().Size() * 8)
	} else {
		if l.hilessequalform {
			l.hilessequalform = false
			l.hiflip = !l.hiflip
			tmpvn = l.vnhil1
			l.vnhil1 = l.vnhil2
			l.vnhil2 = tmpvn
		}
	}
	return true
}

// normalizeMid normalises the middle compare to an equality. If both sides
// are constant, the middle constant must agree with the high constant
// (modulo a one-off correction when the original middle was a less-than).
// C++ parity: LessThreeWay::normalizeMid (double.cc:2204)
func (l *LessThreeWay) normalizeMid() bool {
	var tmpvn *Varnode
	l.vnhie1 = l.hiequal.Input(0)
	l.vnhie2 = l.hiequal.Input(1)
	if l.vnhie1.IsConstant() {
		tmpvn = l.vnhie1
		l.vnhie1 = l.vnhie2
		l.vnhie2 = tmpvn
		if l.midlessform {
			l.equalflip = !l.equalflip
			l.midlessequal = !l.midlessequal
		}
	}
	l.midconstform = false
	if l.vnhie2.IsConstant() {
		if !l.hiconstform {
			return false
		}
		l.midconstform = true
		l.midval = l.vnhie2.Offset()
		if l.vnhie2.Size() == l.in.GetSize() {
			lopart := l.midval & doubleMaskOfSize(l.in.GetLo().Size())
			l.midval >>= uint(l.in.GetLo().Size() * 8)
			if l.midlessform {
				if l.midlessequal {
					if lopart != doubleMaskOfSize(l.in.GetLo().Size()) {
						return false
					}
				} else {
					if lopart != 0 {
						return false
					}
				}
			} else {
				return false
			}
		}
		if l.midval != l.hival {
			if !l.midlessform {
				return false
			}
			if l.midlessequal {
				l.midval += 1
			} else {
				l.midval -= 1
			}
			l.midval &= doubleMaskOfSize(l.in.GetLo().Size())
			l.midlessequal = !l.midlessequal
			if l.midval != l.hival {
				return false
			}
		}
	}
	if l.midlessform {
		if !l.midlessequal {
			l.equalflip = !l.equalflip
		}
	} else {
		if l.hiequal.Code() == CPUI_INT_NOTEQUAL {
			l.equalflip = !l.equalflip
		}
	}
	return true
}

// normalizeLo normalises the low compare similarly to normalizeHi. The
// special "compare to zero" form is rewritten to compare against 1.
// C++ parity: LessThreeWay::normalizeLo (double.cc:2261)
func (l *LessThreeWay) normalizeLo() bool {
	var tmpvn *Varnode
	l.vnlo1 = l.loless.Input(0)
	l.vnlo2 = l.loless.Input(1)
	if l.lolessiszerocomp {
		l.loconstform = true
		if l.lolessequalform {
			l.loval = 1
			l.lolessequalform = false
		} else {
			l.loflip = !l.loflip
			l.loval = 1
		}
		return true
	}
	if l.vnlo1.IsConstant() {
		l.loflip = !l.loflip
		l.lolessequalform = !l.lolessequalform
		tmpvn = l.vnlo1
		l.vnlo1 = l.vnlo2
		l.vnlo2 = tmpvn
	}
	l.loconstform = false
	if l.vnlo2.IsConstant() {
		l.loconstform = true
		l.loval = l.vnlo2.Offset()
		if l.lolessequalform {
			l.loval += 1
			l.loval &= doubleMaskOfSize(l.vnlo2.Size())
			l.lolessequalform = false
		}
	} else {
		if l.lolessequalform {
			l.lolessequalform = false
			l.loflip = !l.loflip
			tmpvn = l.vnlo1
			l.vnlo1 = l.vnlo2
			l.vnlo2 = tmpvn
		}
	}
	return true
}

// checkBlockForm verifies that the three CBRANCHes wire up exactly as the
// expected three-way compare graph and that the middle/low blocks contain
// nothing else.
// C++ parity: LessThreeWay::checkBlockForm (double.cc:2308)
func (l *LessThreeWay) checkBlockForm() bool {
	l.hilesstrue, l.hilessfalse = SplitVarnodeGetTrueFalse(l.hilessbool, l.hiflip)
	l.lolesstrue, l.lolessfalse = SplitVarnodeGetTrueFalse(l.lolessbool, l.loflip)
	l.hieqtrue, l.hieqfalse = SplitVarnodeGetTrueFalse(l.hieqbool, l.equalflip)
	if l.hilesstrue == l.lolesstrue &&
		l.hieqfalse == l.lolessfalse &&
		l.hilessfalse == l.hieqbl &&
		l.hieqtrue == l.lolessbl {
		if SplitVarnodeOtherwiseEmpty(l.hieqbool) && SplitVarnodeOtherwiseEmpty(l.lolessbool) {
			return true
		}
	}
	return false
}

// checkOpForm matches the high/low piece varnodes against the candidate
// SplitVarnode pieces and assigns the slot/whole arrangement.
// C++ parity: LessThreeWay::checkOpForm (double.cc:2331)
func (l *LessThreeWay) checkOpForm() bool {
	l.lo = l.in.GetLo()
	l.hi = l.in.GetHi()

	if l.midconstform {
		if !l.hiconstform {
			return false
		}
		if l.vnhie2.Size() == l.in.GetSize() {
			if l.vnhie1 != l.vnhil1 && l.vnhie1 != l.vnhil2 {
				return false
			}
		} else {
			if l.vnhie1 != l.in.GetHi() {
				return false
			}
		}
	} else {
		if l.vnhil1 != l.vnhie1 && l.vnhil1 != l.vnhie2 {
			return false
		}
		if l.vnhil2 != l.vnhie1 && l.vnhil2 != l.vnhie2 {
			return false
		}
	}
	if l.hi != nil && l.hi == l.vnhil1 {
		if l.hiconstform {
			return false
		}
		l.hislot = 0
		l.hi2 = l.vnhil2
		if l.vnlo1 != l.lo {
			tmpvn := l.vnlo1
			l.vnlo1 = l.vnlo2
			l.vnlo2 = tmpvn
			if l.vnlo1 != l.lo {
				return false
			}
			l.loflip = !l.loflip
			l.lolessequalform = !l.lolessequalform
		}
		l.lo2 = l.vnlo2
	} else if l.hi != nil && l.hi == l.vnhil2 {
		if l.hiconstform {
			return false
		}
		l.hislot = 1
		l.hi2 = l.vnhil1
		if l.vnlo2 != l.lo {
			tmpvn := l.vnlo1
			l.vnlo1 = l.vnlo2
			l.vnlo2 = tmpvn
			if l.vnlo2 != l.lo {
				return false
			}
			l.loflip = !l.loflip
			l.lolessequalform = !l.lolessequalform
		}
		l.lo2 = l.vnlo1
	} else if l.in.GetWhole() == l.vnhil1 {
		if !l.hiconstform {
			return false
		}
		if !l.loconstform {
			return false
		}
		if l.vnlo1 != l.lo {
			return false
		}
		l.hislot = 0
	} else if l.in.GetWhole() == l.vnhil2 {
		if !l.hiconstform {
			return false
		}
		if !l.loconstform {
			return false
		}
		if l.vnlo2 != l.lo {
			l.loflip = !l.loflip
			l.loval -= 1
			l.loval &= doubleMaskOfSize(l.lo.Size())
			if l.vnlo1 != l.lo {
				return false
			}
		}
		l.hislot = 1
	} else {
		return false
	}
	return true
}

// setOpCode picks the final double-precision opcode based on the
// accumulated flip flags.
// C++ parity: LessThreeWay::setOpCode (double.cc:2403)
func (l *LessThreeWay) setOpCode() {
	if l.lolessequalform != l.hiflip {
		if l.signcompare {
			l.finalopc = CPUI_INT_SLESSEQUAL
		} else {
			l.finalopc = CPUI_INT_LESSEQUAL
		}
	} else {
		if l.signcompare {
			l.finalopc = CPUI_INT_SLESS
		} else {
			l.finalopc = CPUI_INT_LESS
		}
	}
	if l.hiflip {
		l.hislot = 1 - l.hislot
		l.hiflip = false
	}
}

// setBoolOp orders the two SplitVarnode operands by hislot and runs the
// feasibility check that prepareBoolOp performs.
// C++ parity: LessThreeWay::setBoolOp (double.cc:2416)
func (l *LessThreeWay) setBoolOp() bool {
	if l.hislot == 0 {
		if SplitVarnodePrepareBoolOp(&l.in, &l.in2, l.hilessbool) {
			return true
		}
	} else {
		if SplitVarnodePrepareBoolOp(&l.in2, &l.in, l.hilessbool) {
			return true
		}
	}
	return false
}

// mapFromLow is the top-level map driver: it walks back from the low
// compare to the surrounding blocks, decodes ops, and runs the four
// normalize phases plus the form checks.
// C++ parity: LessThreeWay::mapFromLow (double.cc:2430)
func (l *LessThreeWay) mapFromLow(op *PcodeOp) bool {
	out := op.Output()
	if out == nil {
		return false
	}
	loop := out.LoneDescend()
	if loop == nil {
		return false
	}
	if !l.mapBlocksFromLow(loop.Parent()) {
		return false
	}
	if !l.mapOpsFromBlocks() {
		return false
	}
	if !l.checkSignedness() {
		return false
	}
	if !l.normalizeHi() {
		return false
	}
	if !l.normalizeMid() {
		return false
	}
	if !l.normalizeLo() {
		return false
	}
	if !l.checkOpForm() {
		return false
	}
	if !l.checkBlockForm() {
		return false
	}
	return true
}

// testReplace assembles the second SplitVarnode (constant or paired) and
// makes sure the prepare step succeeds before any rewrite is committed.
// C++ parity: LessThreeWay::testReplace (double.cc:2447)
func (l *LessThreeWay) testReplace() bool {
	l.setOpCode()
	if l.hiconstform {
		val := (l.hival << uint(8*l.in.GetLo().Size())) | l.loval
		l.in2.InitPartialConst(l.in.GetSize(), val)
		if !l.setBoolOp() {
			return false
		}
	} else {
		l.in2.InitPartialPieces(l.in.GetSize(), l.lo2, l.hi2)
		if !l.setBoolOp() {
			return false
		}
	}
	return true
}

// ApplyRule mirrors LessThreeWay::applyRule (double.cc:2476).
// The rewrite leaves the original CBRANCH ops in place but rewires them so
// that the entry CBRANCH is a single double-precision compare and the
// middle equality always falls through to the original FALSE block. The
// low block then becomes unreachable and is removed by later passes.
func (l *LessThreeWay) ApplyRule(i *SplitVarnode, loop *PcodeOp, workishi bool, data *Funcdata) bool {
	if workishi {
		return false
	}
	if i.GetLo() == nil {
		return false
	}
	l.in = *i
	if !l.mapFromLow(loop) {
		return false
	}
	if !l.testReplace() {
		return false
	}
	if l.in2.ExceedsConstPrecision() {
		return false
	}
	if l.hislot == 0 {
		SplitVarnodeCreateBoolOp(data, l.hilessbool, &l.in, &l.in2, l.finalopc)
	} else {
		SplitVarnodeCreateBoolOp(data, l.hilessbool, &l.in2, &l.in, l.finalopc)
	}
	// Rewire the middle CBRANCH so it always goes to the original FALSE
	// block. The lolessbool block becomes unreachable and is removed by a
	// later pass; we cannot delete it here because the basic-block remover
	// runs as its own action in C++ as well.
	var equalConst uint64
	if l.equalflip {
		equalConst = 1
	}
	data.OpSetInput(l.hieqbool, data.NewConstant(1, equalConst), 1)
	*i = l.in
	return true
}

// -----------------------------------------------------------------------------
// MultForm
// -----------------------------------------------------------------------------

// MultForm recovers a double-precision multiplication from its piece-wise
// form: reshi = hi1*lo2 + hi2*lo1 + ((lo1*lo2) >> wordsize), reslo = lo1*lo2.
// Also handles the small-constant form where hi2 is implicitly zero.
// C++ parity: class MultForm (double.hh:248)
type MultForm struct {
	in                      SplitVarnode
	add1, add2              *PcodeOp
	subhi                   *PcodeOp
	multlo, multhi1, multhi2 *PcodeOp
	midtmp, lo1zext, lo2zext *Varnode
	hi1, lo1, hi2, lo2      *Varnode
	reslo, reshi            *Varnode
	outdoub                 SplitVarnode
	in2                     SplitVarnode
	existop                 *PcodeOp
}

// mapResHiSmallConst finds reshi = hi1*lo2 + (tmp>>wordsize) where lo2 is
// a small constant and hi2 is implicitly zero.
// C++ parity: MultForm::mapResHiSmallConst (double.cc:2735)
func (mf *MultForm) mapResHiSmallConst(rhi *Varnode) bool {
	mf.reshi = rhi
	if !mf.reshi.IsWritten() {
		return false
	}
	mf.add1 = mf.reshi.Def()
	if mf.add1.Code() != CPUI_INT_ADD {
		return false
	}
	ad1 := mf.add1.Input(0)
	ad2 := mf.add1.Input(1)
	if !ad1.IsWritten() || !ad2.IsWritten() {
		return false
	}
	mf.multhi1 = ad1.Def()
	if mf.multhi1.Code() != CPUI_INT_MULT {
		mf.subhi = mf.multhi1
		mf.multhi1 = ad2.Def()
	} else {
		mf.subhi = ad2.Def()
	}
	if mf.multhi1.Code() != CPUI_INT_MULT {
		return false
	}
	if mf.subhi.Code() != CPUI_SUBPIECE {
		return false
	}
	mf.midtmp = mf.subhi.Input(0)
	if !mf.midtmp.IsWritten() {
		return false
	}
	mf.multlo = mf.midtmp.Def()
	if mf.multlo.Code() != CPUI_INT_MULT {
		return false
	}
	mf.lo1zext = mf.multlo.Input(0)
	mf.lo2zext = mf.multlo.Input(1)
	return true
}

// mapResHi finds reshi = hi1*lo2 + hi2*lo1 + (tmp>>wordsize) in one of the
// three possible associativity orderings.
// C++ parity: MultForm::mapResHi (double.cc:2765)
func (mf *MultForm) mapResHi(rhi *Varnode) bool {
	mf.reshi = rhi
	if !mf.reshi.IsWritten() {
		return false
	}
	mf.add1 = mf.reshi.Def()
	if mf.add1.Code() != CPUI_INT_ADD {
		return false
	}
	ad1 := mf.add1.Input(0)
	ad2 := mf.add1.Input(1)
	var ad3 *Varnode
	if !ad1.IsWritten() || !ad2.IsWritten() {
		return false
	}
	mf.add2 = ad1.Def()
	if mf.add2.Code() == CPUI_INT_ADD {
		ad1 = mf.add2.Input(0)
		ad3 = mf.add2.Input(1)
	} else {
		mf.add2 = ad2.Def()
		if mf.add2.Code() != CPUI_INT_ADD {
			return false
		}
		ad2 = mf.add2.Input(0)
		ad3 = mf.add2.Input(1)
	}
	if !ad1.IsWritten() || !ad2.IsWritten() || !ad3.IsWritten() {
		return false
	}
	mf.subhi = ad1.Def()
	if mf.subhi.Code() == CPUI_SUBPIECE {
		mf.multhi1 = ad2.Def()
		mf.multhi2 = ad3.Def()
	} else {
		mf.subhi = ad2.Def()
		if mf.subhi.Code() == CPUI_SUBPIECE {
			mf.multhi1 = ad1.Def()
			mf.multhi2 = ad3.Def()
		} else {
			mf.subhi = ad3.Def()
			if mf.subhi.Code() == CPUI_SUBPIECE {
				mf.multhi1 = ad1.Def()
				mf.multhi2 = ad2.Def()
			} else {
				return false
			}
		}
	}
	if mf.multhi1.Code() != CPUI_INT_MULT {
		return false
	}
	if mf.multhi2.Code() != CPUI_INT_MULT {
		return false
	}
	mf.midtmp = mf.subhi.Input(0)
	if !mf.midtmp.IsWritten() {
		return false
	}
	mf.multlo = mf.midtmp.Def()
	if mf.multlo.Code() != CPUI_INT_MULT {
		return false
	}
	mf.lo1zext = mf.multlo.Input(0)
	mf.lo2zext = mf.multlo.Input(1)
	return true
}

// findLoFromInSmallConst labels lo2 given we already have multhi1 / hi1 / lo1.
// C++ parity: MultForm::findLoFromInSmallConst (double.cc:2824)
func (mf *MultForm) findLoFromInSmallConst() bool {
	vn1 := mf.multhi1.Input(0)
	vn2 := mf.multhi1.Input(1)
	switch {
	case vn1 == mf.hi1:
		mf.lo2 = vn2
	case vn2 == mf.hi1:
		mf.lo2 = vn1
	default:
		return false
	}
	if !mf.lo2.IsConstant() {
		return false
	}
	mf.hi2 = nil // implied zero
	return true
}

// findLoFromIn labels lo2/hi2 given multhi1 / multhi2 / hi1 / lo1.
// C++ parity: MultForm::findLoFromIn (double.cc:2840)
func (mf *MultForm) findLoFromIn() bool {
	vn1 := mf.multhi1.Input(0)
	vn2 := mf.multhi1.Input(1)
	if vn1 != mf.lo1 && vn2 != mf.lo1 {
		// Normalize so multhi1 contains lo1.
		mf.multhi1, mf.multhi2 = mf.multhi2, mf.multhi1
		vn1 = mf.multhi1.Input(0)
		vn2 = mf.multhi1.Input(1)
	}
	switch {
	case vn1 == mf.lo1:
		mf.hi2 = vn2
	case vn2 == mf.lo1:
		mf.hi2 = vn1
	default:
		return false
	}
	vn1 = mf.multhi2.Input(0)
	vn2 = mf.multhi2.Input(1)
	switch {
	case vn1 == mf.hi1:
		mf.lo2 = vn2
	case vn2 == mf.hi1:
		mf.lo2 = vn1
	default:
		return false
	}
	return true
}

// zextOf verifies big is a zero-extension of small -- either a CPUI_INT_ZEXT
// or an INT_AND mask applied to a whole from which small is SUBPIECEd.
// C++ parity: MultForm::zextOf (double.cc:2870)
func (mf *MultForm) zextOf(big, small *Varnode) bool {
	if small.IsConstant() {
		if !big.IsConstant() {
			return false
		}
		return big.Offset() == small.Offset()
	}
	if !big.IsWritten() {
		return false
	}
	op := big.Def()
	if op.Code() == CPUI_INT_ZEXT {
		return op.Input(0) == small
	}
	if op.Code() == CPUI_INT_AND {
		if !op.Input(1).IsConstant() {
			return false
		}
		if op.Input(1).Offset() != doubleMaskOfSize(small.Size()) {
			return false
		}
		whole := op.Input(0)
		if !small.IsWritten() {
			return false
		}
		sub := small.Def()
		if sub.Code() != CPUI_SUBPIECE {
			return false
		}
		return sub.Input(0) == whole
	}
	return false
}

// verifyLo checks that midtmp = lo1zext * lo2zext with the pieces matching.
// C++ parity: MultForm::verifyLo (double.cc:2895)
func (mf *MultForm) verifyLo() bool {
	if mf.subhi.Input(1).Offset() != uint64(mf.lo1.Size()) {
		return false
	}
	if mf.zextOf(mf.lo1zext, mf.lo1) {
		if mf.zextOf(mf.lo2zext, mf.lo2) {
			return true
		}
	} else if mf.zextOf(mf.lo1zext, mf.lo2) {
		if mf.zextOf(mf.lo2zext, mf.lo1) {
			return true
		}
	}
	return false
}

// findResLo finds the low result Varnode from either a SUBPIECE of midtmp
// or a separate lo1*lo2 multiply.
// C++ parity: MultForm::findResLo (double.cc:2911)
func (mf *MultForm) findResLo() bool {
	descs := append([]*PcodeOp(nil), mf.midtmp.DescendIter()...)
	for _, op := range descs {
		if op.Code() != CPUI_SUBPIECE {
			continue
		}
		if op.Input(1).Offset() != 0 {
			continue
		}
		mf.reslo = op.Output()
		if mf.reslo.Size() != mf.lo1.Size() {
			continue
		}
		return true
	}
	// Fall back: a separate lo1*lo2 multiply was used for reslo.
	loDescs := append([]*PcodeOp(nil), mf.lo1.DescendIter()...)
	for _, op := range loDescs {
		if op.Code() != CPUI_INT_MULT {
			continue
		}
		vn1 := op.Input(0)
		vn2 := op.Input(1)
		if mf.lo2 != nil && mf.lo2.IsConstant() {
			ok1 := vn1.IsConstant() && vn1.Offset() == mf.lo2.Offset()
			ok2 := vn2.IsConstant() && vn2.Offset() == mf.lo2.Offset()
			if !ok1 && !ok2 {
				continue
			}
		} else {
			if op.Input(0) != mf.lo2 && op.Input(1) != mf.lo2 {
				continue
			}
		}
		mf.reslo = op.Output()
		return true
	}
	return false
}

// mapFromInSmallConst is the small-constant driver.
// C++ parity: MultForm::mapFromInSmallConst (double.cc:2948)
func (mf *MultForm) mapFromInSmallConst(rhi *Varnode) bool {
	if !mf.mapResHiSmallConst(rhi) {
		return false
	}
	if !mf.findLoFromInSmallConst() {
		return false
	}
	if !mf.verifyLo() {
		return false
	}
	if !mf.findResLo() {
		return false
	}
	return true
}

// mapFromIn is the full double-precision driver.
// C++ parity: MultForm::mapFromIn (double.cc:2958)
func (mf *MultForm) mapFromIn(rhi *Varnode) bool {
	if !mf.mapResHi(rhi) {
		return false
	}
	if !mf.findLoFromIn() {
		return false
	}
	if !mf.verifyLo() {
		return false
	}
	if !mf.findResLo() {
		return false
	}
	return true
}

// replace performs the final rewrite once the form has been fully matched.
// C++ parity: MultForm::replace (double.cc:2968)
func (mf *MultForm) replace(data *Funcdata) bool {
	mf.outdoub.InitPartialPieces(mf.in.GetSize(), mf.reslo, mf.reshi)
	mf.in2.InitPartialPieces(mf.in.GetSize(), mf.lo2, mf.hi2)
	if mf.in2.ExceedsConstPrecision() {
		return false
	}
	mf.existop = SplitVarnodePrepareBinaryOp(&mf.outdoub, &mf.in, &mf.in2)
	if mf.existop == nil {
		return false
	}
	SplitVarnodeCreateBinaryOp(data, &mf.outdoub, &mf.in, &mf.in2, mf.existop, CPUI_INT_MULT)
	return true
}

// verify searches the descendants of hop.Output() for an INT_ADD chain that
// matches one of the three mapping drivers.
// C++ parity: MultForm::verify (double.cc:2982)
func (mf *MultForm) verify(h, l *Varnode, hop *PcodeOp) bool {
	mf.hi1 = h
	mf.lo1 = l
	hopOut := hop.Output()
	if hopOut == nil {
		return false
	}
	descs := append([]*PcodeOp(nil), hopOut.DescendIter()...)
	for _, add1 := range descs {
		mf.add1 = add1
		if add1.Code() != CPUI_INT_ADD {
			continue
		}
		add1Out := add1.Output()
		if add1Out != nil {
			descs2 := append([]*PcodeOp(nil), add1Out.DescendIter()...)
			for _, add2 := range descs2 {
				mf.add2 = add2
				if add2.Code() != CPUI_INT_ADD {
					continue
				}
				if mf.mapFromIn(add2.Output()) {
					return true
				}
			}
		}
		if mf.mapFromIn(add1.Output()) {
			return true
		}
		if mf.mapFromInSmallConst(add1.Output()) {
			return true
		}
	}
	return false
}

// ApplyRule mirrors MultForm::applyRule (double.cc:3012).
func (mf *MultForm) ApplyRule(i *SplitVarnode, hop *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !i.HasBothPieces() {
		return false
	}
	mf.in = *i
	if !mf.verify(mf.in.GetHi(), mf.in.GetLo(), hop) {
		return false
	}
	if mf.replace(data) {
		*i = mf.in
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// IndirectForm (PARTIAL)
// -----------------------------------------------------------------------------

// IndirectForm recovers a double-precision INDIRECT whose low and high pieces
// are affected by the same affector op.
// C++ parity: class IndirectForm (double.hh:287, double.cc:3080-3129)
//
// PARTIAL port. The C++ implementation identifies the affector op by
// decoding the IOP-encoded constant on input(1) of each INDIRECT
// (PcodeOp::getOpFromConst). Gosleigh has not ported the IOP-space encoding
// for INDIRECT cause-references yet -- our NewIndirectOp helper writes a
// zero constant placeholder in that slot (see funcdata.go:725, comment
// "cause ref (IOP stub)"). To stay parity-safe without that primitive, we
// approximate the affector match by comparing the seqnum address of the
// INDIRECT op: in well-formed input both halves of a double-precision
// INDIRECT share the affector op's address. Once newVarnodeIop and
// getOpFromConst are ported, this should switch back to the structural
// pointer comparison from the C++ source.
//
// TODO known mismatch: false positives are possible if two unrelated
// INDIRECT pairs share an instruction address.
type IndirectForm struct {
	in       SplitVarnode
	outvn    SplitVarnode
	lo, hi   *Varnode
	reslo    *Varnode
	reshi    *Varnode
	affector *PcodeOp
	indhi    *PcodeOp
	indlo    *PcodeOp
}

// verify mirrors IndirectForm::verify (double.cc:3080). It locates a sibling
// CPUI_INDIRECT on lo with the same affector and checks the temporary /
// addr-tied invariants.
// C++ parity: IndirectForm::verify (double.cc:3080)
func (ifm *IndirectForm) verify(h, l *Varnode, ind *PcodeOp) bool {
	ifm.hi = h
	ifm.lo = l
	ifm.indhi = ind
	if ind.NumInput() < 2 {
		return false
	}
	// PARTIAL: use the indhi seqnum address as a stand-in for the affector
	// pointer. We cannot recover a real affector op without IOP encoding.
	ifm.affector = ind
	ifm.reshi = ind.Output()
	if ifm.reshi == nil {
		return false
	}
	// C++ rejects INDIRECT through unique (IPTR_INTERNAL) outputs.
	hispc := ifm.reshi.Space()
	if hispc != nil && hispc.Kind == address.SpaceKindUnique {
		return false
	}
	for _, indlo := range append([]*PcodeOp(nil), ifm.lo.DescendIter()...) {
		if indlo.IsDead() {
			continue
		}
		if indlo.Code() != CPUI_INDIRECT {
			continue
		}
		// PARTIAL: match by seqnum address rather than IOP-decoded affector.
		if indlo.Addr() != ind.Addr() {
			continue
		}
		ifm.reslo = indlo.Output()
		if ifm.reslo == nil {
			continue
		}
		lospc := ifm.reslo.Space()
		if lospc != nil && lospc.Kind == address.SpaceKindUnique {
			return false
		}
		if ifm.reslo.IsAddrTied() || ifm.reshi.IsAddrTied() {
			if _, ok := SplitVarnodeIsAddrTiedContiguous(ifm.reslo, ifm.reshi); !ok {
				return false
			}
		}
		ifm.indlo = indlo
		return true
	}
	return false
}

// ApplyRule mirrors IndirectForm::applyRule (double.cc:3114).
func (ifm *IndirectForm) ApplyRule(sp *SplitVarnode, ind *PcodeOp, workishi bool, data *Funcdata) bool {
	if !workishi {
		return false
	}
	if !sp.HasBothPieces() {
		return false
	}
	ifm.in = *sp
	if !ifm.verify(ifm.in.GetHi(), ifm.in.GetLo(), ind) {
		return false
	}
	ifm.outvn.InitPartialPieces(ifm.in.GetSize(), ifm.reslo, ifm.reshi)
	if !SplitVarnodePrepareIndirectOp(&ifm.in, ifm.affector) {
		return false
	}
	SplitVarnodeReplaceIndirectOp(data, &ifm.outvn, &ifm.in, ifm.affector)
	*sp = ifm.in
	return true
}
