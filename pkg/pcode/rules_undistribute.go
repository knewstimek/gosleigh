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

// addExpression collects up to two additive terms (with multiplicative
// coefficients) and a constant from an expression tree.
// C++ parity: expression.cc AddExpression.
type addExpression struct {
	constval uint64
	terms    []addTerm
}

type addTerm struct {
	vn    *Varnode
	coeff uint64
}

func (e *addExpression) add(vn *Varnode, coeff uint64) {
	if len(e.terms) < 2 {
		e.terms = append(e.terms, addTerm{vn, coeff})
	}
}

func (e *addExpression) gather(vn *Varnode, coeff uint64, depth int) {
	if vn.IsConstant() {
		e.constval = (e.constval + coeff*vn.Offset()) & maskForSize(vn.Size())
		return
	}
	if vn.IsWritten() {
		op := vn.Def()
		switch op.Code() {
		case CPUI_INT_ADD:
			if !op.Input(1).IsConstant() {
				depth--
			}
			if depth >= 0 {
				e.gather(op.Input(0), coeff, depth)
				e.gather(op.Input(1), coeff, depth)
				return
			}
		case CPUI_INT_MULT:
			if op.Input(1).IsConstant() {
				coeff = (coeff * op.Input(1).Offset()) & maskForSize(vn.Size())
				e.gather(op.Input(0), coeff, depth)
				return
			}
		}
	}
	e.add(vn, coeff)
}

func (e *addExpression) gatherTwoTermsAdd(a, b *Varnode) {
	depth := 0
	if a.IsConstant() || b.IsConstant() {
		depth = 1
	}
	e.gather(a, 1, depth)
	e.gather(b, 1, depth)
}

func (e *addExpression) gatherTwoTermsRoot(root *Varnode) {
	e.gather(root, 1, 1)
}

func (t addTerm) isEquivalent(o addTerm) bool {
	return t.coeff == o.coeff && functionalEquality(t.vn, o.vn)
}

func (e *addExpression) isEquivalent(o *addExpression) bool {
	if e.constval != o.constval || len(e.terms) != len(o.terms) {
		return false
	}
	switch len(e.terms) {
	case 1:
		return e.terms[0].isEquivalent(o.terms[0])
	case 2:
		return (e.terms[0].isEquivalent(o.terms[0]) && e.terms[1].isEquivalent(o.terms[1])) ||
			(e.terms[0].isEquivalent(o.terms[1]) && e.terms[1].isEquivalent(o.terms[0]))
	}
	return false
}

// apply simplifies signed comparisons built from INT_SCARRY:
// scarry(V,#W) != (V + #W s< 0) => V s< -#W, and the related forms.
// C++ parity: ruleaction.cc RuleScarry::applyOp.
func (r *RuleScarry) apply(op *PcodeOp, data *Funcdata) int {
	svn := op.Output()
	avn, bvn := op.Input(0), op.Input(1)
	if (bvn.IsConstant() && bvn.Offset() == 0) || (avn.IsConstant() && avn.Offset() == 0) {
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpSetInput(op, data.NewConstant(1, 0), 0)
		data.OpRemoveInput(op, 1)
		return 1
	}
	if !bvn.IsConstant() {
		if !avn.IsConstant() {
			return 0
		}
		avn, bvn = bvn, op.Input(0)
		val := maskForSize(bvn.Size())
		if val^(val>>1) == bvn.Offset() {
			return 0 // the integer minimum has no negation
		}
	}
	for _, compop := range svn.DescendIter() {
		if compop.Code() != CPUI_INT_EQUAL && compop.Code() != CPUI_INT_NOTEQUAL {
			continue
		}
		cvn := compop.Input(0)
		if cvn == svn {
			cvn = compop.Input(1)
		}
		if !cvn.IsWritten() {
			continue
		}
		signop := cvn.Def()
		if signop.Code() != CPUI_INT_SLESS {
			continue
		}
		zside := 0
		if !isConstValue(signop.Input(0), 0) {
			if !isConstValue(signop.Input(1), 0) {
				continue
			}
			zside = 1
		}
		xvn := signop.Input(1 - zside)
		if !xvn.IsWritten() {
			continue
		}
		var expr1, expr2 addExpression
		expr1.gatherTwoTermsAdd(avn, bvn)
		expr2.gatherTwoTermsRoot(xvn)
		if !expr1.isEquivalent(&expr2) {
			continue
		}
		newConst := data.NewConstant(bvn.Size(), -bvn.Offset()&maskForSize(bvn.Size()))
		if compop.Code() == CPUI_INT_NOTEQUAL {
			data.OpSetOpcode(compop, CPUI_INT_SLESS)
			data.OpSetInput(compop, avn, 1-zside)
			data.OpSetInput(compop, newConst, zside)
		} else {
			data.OpSetOpcode(compop, CPUI_INT_SLESSEQUAL)
			data.OpSetInput(compop, avn, zside)
			data.OpSetInput(compop, newConst, 1-zside)
		}
		return 1
	}
	return 0
}

// isConstValue reports a constant Varnode holding val.
// C++ parity: Varnode::constantMatch.
func isConstValue(vn *Varnode, val uint64) bool {
	return vn.IsConstant() && vn.Offset() == val
}

// apply undoes an extension or shift distributed over a bitwise op:
// zext(V) & zext(W) => zext(V & W), (V >> X) | (W >> X) => (V | W) >> X.
// C++ parity: ruleaction.cc RuleBitUndistribute::applyOp.
func (r *RuleBitUndistribute) apply(op *PcodeOp, data *Funcdata) int {
	vn1, vn2 := op.Input(0), op.Input(1)
	if !vn1.IsWritten() || !vn2.IsWritten() {
		return 0
	}
	opc := vn1.Def().Code()
	if vn2.Def().Code() != opc {
		return 0
	}
	var in1, in2 *Varnode
	switch opc {
	case CPUI_INT_ZEXT, CPUI_INT_SEXT:
		in1 = vn1.Def().Input(0)
		in2 = vn2.Def().Input(0)
		if in1.IsFree() || in2.IsFree() || in1.Size() != in2.Size() {
			return 0
		}
		data.OpRemoveInput(op, 1)
	case CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		s1, s2 := vn1.Def().Input(1), vn2.Def().Input(1)
		var vnextra *Varnode
		switch {
		case s1.IsConstant() && s2.IsConstant():
			if s1.Offset() != s2.Offset() {
				return 0
			}
			vnextra = data.NewConstant(s1.Size(), s1.Offset())
		case s1 != s2 || s1.IsFree():
			return 0
		default:
			vnextra = s1
		}
		in1 = vn1.Def().Input(0)
		in2 = vn2.Def().Input(0)
		if in1.IsFree() || in2.IsFree() {
			return 0
		}
		data.OpSetInput(op, vnextra, 1)
	default:
		return 0
	}
	newext := data.NewOp(2, op.Addr())
	smalllogic := data.NewUniqueOut(in1.Size(), newext)
	data.OpSetInput(newext, in1, 0)
	data.OpSetInput(newext, in2, 1)
	data.OpSetOpcode(newext, op.Code())
	data.OpSetOpcode(op, opc)
	data.OpSetInput(op, smalllogic, 0)
	data.OpInsertBefore(newext, op)
	return 1
}

// apply undoes BOOL_AND/BOOL_OR distributed through a boolean comparison:
// A && B != A && C => A && (B != C), and the complementary forms.
// C++ parity: ruleaction.cc RuleBooleanUndistribute::applyOp.
func (r *RuleBooleanUndistribute) apply(op *PcodeOp, data *Funcdata) int {
	vn0, vn1 := op.Input(0), op.Input(1)
	if !vn0.IsWritten() || !vn1.IsWritten() {
		return 0
	}
	op0, op1 := vn0.Def(), vn1.Def()
	opc0, opc1 := op0.Code(), op1.Code()
	if (opc0 != CPUI_BOOL_AND && opc0 != CPUI_BOOL_OR) || (opc1 != CPUI_BOOL_AND && opc1 != CPUI_BOOL_OR) {
		return 0
	}
	ins := [4]*Varnode{op0.Input(0), op0.Input(1), op1.Input(0), op1.Input(1)}
	for _, v := range ins {
		if v.IsFree() {
			return 0
		}
	}
	var flipped [4]bool
	centralEqual := op.Code() == CPUI_INT_EQUAL
	if opc0 == CPUI_BOOL_OR {
		flipped[0], flipped[1] = true, true
		centralEqual = !centralEqual
	}
	if opc1 == CPUI_BOOL_OR {
		flipped[2], flipped[3] = true, true
		centralEqual = !centralEqual
	}
	isMatch := func(l, rslot int) bool {
		switch BoolEvaluate(ins[l], ins[rslot], 1) {
		case BoolMatchSame:
			return true
		case BoolMatchComplementary:
			flipped[rslot] = !flipped[rslot]
			return true
		}
		return false
	}
	var leftSlot, rightSlot int
	switch {
	case isMatch(0, 2):
		leftSlot, rightSlot = 0, 2
	case isMatch(0, 3):
		leftSlot, rightSlot = 0, 3
	case isMatch(1, 2):
		leftSlot, rightSlot = 1, 2
	case isMatch(1, 3):
		leftSlot, rightSlot = 1, 3
	default:
		return 0
	}
	if flipped[leftSlot] != flipped[rightSlot] {
		return 0
	}
	combineOpc := CPUI_BOOL_AND
	if centralEqual {
		combineOpc = CPUI_BOOL_OR
		flipped[leftSlot] = !flipped[leftSlot]
	}
	finalA := ins[leftSlot]
	if flipped[leftSlot] {
		finalA = data.OpBoolNegate(finalA, op, false)
	}
	if flipped[1-leftSlot] {
		centralEqual = !centralEqual
	}
	if flipped[5-rightSlot] {
		centralEqual = !centralEqual
	}
	finalB, finalC := ins[1-leftSlot], ins[5-rightSlot]
	eqOp := data.NewOp(2, op.Addr())
	if centralEqual {
		data.OpSetOpcode(eqOp, CPUI_INT_EQUAL)
	} else {
		data.OpSetOpcode(eqOp, CPUI_INT_NOTEQUAL)
	}
	tmp1 := data.NewUniqueOut(1, eqOp)
	data.OpSetInput(eqOp, finalB, 0)
	data.OpSetInput(eqOp, finalC, 1)
	data.OpInsertBefore(eqOp, op)
	data.OpSetOpcode(op, combineOpc)
	data.OpSetInput(op, tmp1, 1)
	data.OpSetInput(op, finalA, 0)
	return 1
}
