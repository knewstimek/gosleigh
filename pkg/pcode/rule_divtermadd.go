// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

// divTermConst adds 2^n to a multiplier constant of the given size.
// TODO known mismatch: C++ does this in 128 bits (isConstantExtended /
// newExtendedConstant); only multipliers of at most 8 bytes with n < 64 are
// handled, which covers 32-bit division sequences.
func divTermConst(mult *Varnode, n int, size int32) (uint64, bool) {
	if !mult.IsConstant() || n >= 64 || size > 8 {
		return 0, false
	}
	return (mult.Offset() + uint64(1)<<uint(n)) & maskForSize(size), true
}

// divTermFindSubshift matches sub(V,c) or sub(V,c) >> n with the SUBPIECE
// taking the high part, and returns it with the total truncation n+8c.
// C++ parity: RuleDivTermAdd::findSubshift.
func divTermFindSubshift(op *PcodeOp) (*PcodeOp, int, OpCode) {
	var subop *PcodeOp
	n := 0
	shiftopc := op.Code()
	if shiftopc != CPUI_SUBPIECE {
		vn := op.Input(0)
		if !vn.IsWritten() {
			return nil, 0, 0
		}
		subop = vn.Def()
		if subop.Code() != CPUI_SUBPIECE || !op.Input(1).IsConstant() {
			return nil, 0, 0
		}
		n = int(op.Input(1).Offset())
	} else {
		shiftopc = CPUI_MAX
		subop = op
	}
	c := int(subop.Input(1).Offset())
	if int(subop.Output().Size())+c != int(subop.Input(0).Size()) {
		return nil, 0, 0 // SUBPIECE is not the high part
	}
	return subop, n + 8*c, shiftopc
}

// apply folds sub(ext(V)*c,b)>>d + V into sub((ext(V)*(c+2^n))>>n,0).
// C++ parity: ruleaction.cc RuleDivTermAdd::applyOp.
func (r *RuleDivTermAdd) apply(op *PcodeOp, data *Funcdata) int {
	subop, n, shiftopc := divTermFindSubshift(op)
	if subop == nil || n > 127 {
		return 0
	}
	multvn := subop.Input(0)
	if !multvn.IsWritten() || multvn.Def().Code() != CPUI_INT_MULT {
		return 0
	}
	multop := multvn.Def()
	extvn := multop.Input(0)
	if !extvn.IsWritten() {
		return 0
	}
	extop := extvn.Def()
	switch extop.Code() {
	case CPUI_INT_ZEXT:
		if op.Code() == CPUI_INT_SRIGHT {
			return 0
		}
	case CPUI_INT_SEXT:
		if op.Code() == CPUI_INT_RIGHT {
			return 0
		}
	}
	multConst, ok := divTermConst(multop.Input(1), n, extvn.Size())
	if !ok {
		return 0
	}
	x := extop.Input(0)
	for _, addop := range op.Output().DescendIter() {
		if addop.Code() != CPUI_INT_ADD || (addop.Input(0) != x && addop.Input(1) != x) {
			continue
		}
		newmultop := data.NewOp(2, op.Addr())
		data.OpSetOpcode(newmultop, CPUI_INT_MULT)
		newmultvn := data.NewUniqueOut(extvn.Size(), newmultop)
		data.OpSetInput(newmultop, extvn, 0)
		data.OpSetInput(newmultop, data.NewConstant(extvn.Size(), multConst), 1)
		data.OpInsertBefore(newmultop, op)

		newshiftop := data.NewOp(2, op.Addr())
		if shiftopc == CPUI_MAX {
			shiftopc = CPUI_INT_RIGHT
		}
		data.OpSetOpcode(newshiftop, shiftopc)
		newshiftvn := data.NewUniqueOut(extvn.Size(), newshiftop)
		data.OpSetInput(newshiftop, newmultvn, 0)
		data.OpSetInput(newshiftop, data.NewConstant(4, uint64(n)), 1)
		data.OpInsertBefore(newshiftop, op)

		data.OpSetOpcode(addop, CPUI_SUBPIECE)
		data.OpSetInput(addop, newshiftvn, 0)
		data.OpSetInput(addop, data.NewConstant(4, 0), 1)
		return 1
	}
	return 0
}

// apply folds W+((V-W)>>1), W = sub(zext(V)*c,d), into
// sub((zext(V)*(c+2^n))>>(n+1),0).
// C++ parity: ruleaction.cc RuleDivTermAdd2::applyOp.
func (r *RuleDivTermAdd2) apply(op *PcodeOp, data *Funcdata) int {
	if !isConstValue(op.Input(1), 1) || !op.Input(0).IsWritten() {
		return 0
	}
	subop := op.Input(0).Def()
	if subop.Code() != CPUI_INT_ADD {
		return 0
	}
	var x, compvn *Varnode
	for i := 0; i < 2; i++ {
		cv := subop.Input(i)
		if cv.IsWritten() && cv.Def().Code() == CPUI_INT_MULT {
			if invn := cv.Def().Input(1); invn.IsConstant() && invn.Offset() == maskForSize(invn.Size()) {
				x, compvn = subop.Input(1-i), cv
				break
			}
		}
	}
	if compvn == nil {
		return 0
	}
	z := compvn.Def().Input(0)
	if !z.IsWritten() || z.Def().Code() != CPUI_SUBPIECE {
		return 0
	}
	subpieceop := z.Def()
	n := int(subpieceop.Input(1).Offset()) * 8
	if n != 8*int(subpieceop.Input(0).Size()-z.Size()) {
		return 0
	}
	multvn := subpieceop.Input(0)
	if !multvn.IsWritten() || multvn.Def().Code() != CPUI_INT_MULT {
		return 0
	}
	multop := multvn.Def()
	zextvn := multop.Input(0)
	if !zextvn.IsWritten() || zextvn.Def().Code() != CPUI_INT_ZEXT || zextvn.Def().Input(0) != x {
		return 0
	}
	multConst, ok := divTermConst(multop.Input(1), n, zextvn.Size())
	if !ok {
		return 0
	}
	for _, addop := range op.Output().DescendIter() {
		if addop.Code() != CPUI_INT_ADD || (addop.Input(0) != z && addop.Input(1) != z) {
			continue
		}
		newmultop := data.NewOp(2, op.Addr())
		data.OpSetOpcode(newmultop, CPUI_INT_MULT)
		newmultvn := data.NewUniqueOut(zextvn.Size(), newmultop)
		data.OpSetInput(newmultop, zextvn, 0)
		data.OpSetInput(newmultop, data.NewConstant(zextvn.Size(), multConst), 1)
		data.OpInsertBefore(newmultop, op)

		newshiftop := data.NewOp(2, op.Addr())
		data.OpSetOpcode(newshiftop, CPUI_INT_RIGHT)
		newshiftvn := data.NewUniqueOut(zextvn.Size(), newshiftop)
		data.OpSetInput(newshiftop, newmultvn, 0)
		data.OpSetInput(newshiftop, data.NewConstant(4, uint64(n+1)), 1)
		data.OpInsertBefore(newshiftop, op)

		data.OpSetOpcode(addop, CPUI_SUBPIECE)
		data.OpSetInput(addop, newshiftvn, 0)
		data.OpSetInput(addop, data.NewConstant(4, 0), 1)
		return 1
	}
	return 0
}
