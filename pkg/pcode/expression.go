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

// C++ parity: expression.hh/expression.cc BooleanMatch.
const (
	BoolMatchSame          = 1
	BoolMatchComplementary = 2
	BoolMatchUncorrelated  = 3
)

// C++ parity: expression.cc BooleanMatch::sameOpComplement.
func sameOpComplement(bin1op, bin2op *PcodeOp) bool {
	if bin1op == nil || bin2op == nil {
		return false
	}
	opcode := bin1op.Code()
	if opcode != CPUI_INT_SLESS && opcode != CPUI_INT_LESS {
		return false
	}
	constslot := 0
	if bin1op.Input(1) != nil && bin1op.Input(1).IsConstant() {
		constslot = 1
	}
	if !bin1op.Input(constslot).IsConstant() {
		return false
	}
	if !bin2op.Input(1 - constslot).IsConstant() {
		return false
	}
	if !varnodeSame(bin1op.Input(1-constslot), bin2op.Input(constslot)) {
		return false
	}
	val1 := bin1op.Input(constslot).Offset()
	val2 := bin2op.Input(1 - constslot).Offset()
	if constslot != 0 {
		val1, val2 = val2, val1
	}
	if val1+1 != val2 {
		return false
	}
	if val2 == 0 && opcode == CPUI_INT_LESS {
		return false
	}
	if opcode == CPUI_INT_SLESS {
		sz := bin1op.Input(constslot).Size()
		if signBitForSize(sz)&val2 != 0 && signBitForSize(sz)&val1 == 0 {
			return false
		}
	}
	return true
}

// C++ parity: expression.cc BooleanMatch::varnodeSame.
func varnodeSame(a, b *Varnode) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.IsConstant() && b.IsConstant() {
		return a.Offset() == b.Offset()
	}
	return false
}

// C++ parity: expression.cc BooleanMatch::evaluate.
func BoolEvaluate(vn1, vn2 *Varnode, depth int) int {
	if vn1 == vn2 {
		return BoolMatchSame
	}
	var op1, op2 *PcodeOp
	var opc1, opc2 OpCode
	if vn1 != nil && vn1.IsWritten() {
		op1 = vn1.Def()
		opc1 = op1.Code()
		if opc1 == CPUI_BOOL_NEGATE {
			res := BoolEvaluate(op1.Input(0), vn2, depth)
			if res == BoolMatchSame {
				res = BoolMatchComplementary
			} else if res == BoolMatchComplementary {
				res = BoolMatchSame
			}
			return res
		}
	} else {
		op1 = nil
		opc1 = CPUI_MAX
	}
	if vn2 != nil && vn2.IsWritten() {
		op2 = vn2.Def()
		opc2 = op2.Code()
		if opc2 == CPUI_BOOL_NEGATE {
			res := BoolEvaluate(vn1, op2.Input(0), depth)
			if res == BoolMatchSame {
				res = BoolMatchComplementary
			} else if res == BoolMatchComplementary {
				res = BoolMatchSame
			}
			return res
		}
	} else {
		return BoolMatchUncorrelated
	}
	if op1 == nil {
		return BoolMatchUncorrelated
	}
	if !op1.IsBoolOutput() || !op2.IsBoolOutput() {
		return BoolMatchUncorrelated
	}
	if depth != 0 && (opc1 == CPUI_BOOL_AND || opc1 == CPUI_BOOL_OR || opc1 == CPUI_BOOL_XOR) {
		if opc2 == CPUI_BOOL_AND || opc2 == CPUI_BOOL_OR || opc2 == CPUI_BOOL_XOR {
			if opc1 == opc2 || (opc1 == CPUI_BOOL_AND && opc2 == CPUI_BOOL_OR) || (opc1 == CPUI_BOOL_OR && opc2 == CPUI_BOOL_AND) {
				pair1 := BoolEvaluate(op1.Input(0), op2.Input(0), depth-1)
				var pair2 int
				if pair1 == BoolMatchUncorrelated {
					pair1 = BoolEvaluate(op1.Input(0), op2.Input(1), depth-1)
					if pair1 == BoolMatchUncorrelated {
						return BoolMatchUncorrelated
					}
					pair2 = BoolEvaluate(op1.Input(1), op2.Input(0), depth-1)
				} else {
					pair2 = BoolEvaluate(op1.Input(1), op2.Input(1), depth-1)
				}
				if pair2 == BoolMatchUncorrelated {
					return BoolMatchUncorrelated
				}
				if opc1 == opc2 {
					if pair1 == BoolMatchSame && pair2 == BoolMatchSame {
						return BoolMatchSame
					}
					if opc1 == CPUI_BOOL_XOR {
						if pair1 == BoolMatchComplementary && pair2 == BoolMatchComplementary {
							return BoolMatchSame
						}
						return BoolMatchComplementary
					}
				} else {
					if pair1 == BoolMatchComplementary && pair2 == BoolMatchComplementary {
						return BoolMatchComplementary
					}
				}
			}
		}
	} else {
		if opc1 == opc2 {
			sameOp := true
			for i := 0; i < op1.NumInput(); i++ {
				if !varnodeSame(op1.Input(i), op2.Input(i)) {
					sameOp = false
					break
				}
			}
			if sameOp {
				return BoolMatchSame
			}
			if sameOpComplement(op1, op2) {
				return BoolMatchComplementary
			}
			return BoolMatchUncorrelated
		}
		slot1 := 0
		slot2 := 0
		reorder := false
		flip, reorder2, ok := getBooleanFlipOpcode(opc2)
		if !ok || opc1 != flip {
			return BoolMatchUncorrelated
		}
		reorder = reorder2
		if reorder {
			slot2 = 1
		}
		if !varnodeSame(op1.Input(slot1), op2.Input(slot2)) {
			return BoolMatchUncorrelated
		}
		if !varnodeSame(op1.Input(1-slot1), op2.Input(1-slot2)) {
			return BoolMatchUncorrelated
		}
		return BoolMatchComplementary
	}
	return BoolMatchUncorrelated
}

// C++ parity: expression.cc BooleanExpressionMatch.
type BooleanExpressionMatch struct {
	MatchFlip bool
}

// C++ parity: expression.cc BooleanExpressionMatch::verifyCondition.
func (m *BooleanExpressionMatch) VerifyCondition(op, iop *PcodeOp) bool {
	res := BoolEvaluate(op.Input(1), iop.Input(1), 1)
	if res == BoolMatchUncorrelated {
		return false
	}
	m.MatchFlip = res == BoolMatchComplementary
	if op.HasFlag(PcodeOpBooleanFlip) {
		m.MatchFlip = !m.MatchFlip
	}
	if iop.HasFlag(PcodeOpBooleanFlip) {
		m.MatchFlip = !m.MatchFlip
	}
	return true
}

// C++ parity: expression.cc BooleanExpressionMatch::getMultiSlot.
func (m *BooleanExpressionMatch) MultiSlot() int {
	return -1
}

// C++ parity: expression.cc BooleanExpressionMatch::getFlip.
func (m *BooleanExpressionMatch) Flip() bool {
	return m.MatchFlip
}

// C++ parity: expression.cc functionalEqualityLevel0.
func functionalEqualityLevel0(vn1, vn2 *Varnode) int {
	if vn1 == vn2 {
		return 0
	}
	if vn1 == nil || vn2 == nil {
		return -1
	}
	if vn1.Size() != vn2.Size() {
		return -1
	}
	if vn1.IsConstant() {
		if vn2.IsConstant() {
			if vn1.Offset() == vn2.Offset() {
				return 0
			}
		}
		return -1
	}
	if vn1.IsFree() || vn2.IsFree() {
		return -1
	}
	return 1
}

// C++ parity: expression.cc functionalEqualityLevel.
func functionalEqualityLevel(vn1, vn2 *Varnode, res1, res2 []*Varnode) int {
	testval := functionalEqualityLevel0(vn1, vn2)
	if testval != 1 {
		return testval
	}
	if !vn1.IsWritten() || !vn2.IsWritten() {
		return -1
	}
	op1 := vn1.Def()
	op2 := vn2.Def()
	opc := op1.Code()
	if opc != op2.Code() {
		return -1
	}
	num := op1.NumInput()
	if num != op2.NumInput() {
		return -1
	}
	if op1.IsMarker() || op2.IsCall() {
		return -1
	}
	if opc == CPUI_LOAD && op1.Addr() != op2.Addr() {
		return -1
	}
	if num >= 3 {
		if opc != CPUI_PTRADD {
			return -1
		}
		if op1.Input(2).Offset() != op2.Input(2).Offset() {
			return -1
		}
		num = 2
	}
	for i := 0; i < num; i++ {
		res1[i] = op1.Input(i)
		res2[i] = op2.Input(i)
	}
	testval = functionalEqualityLevel0(res1[0], res2[0])
	if testval == 0 {
		if num == 1 {
			return 0
		}
		testval = functionalEqualityLevel0(res1[1], res2[1])
		if testval == 0 {
			return 0
		}
		if testval < 0 {
			return -1
		}
		res1[0] = res1[1]
		res2[0] = res2[1]
		return 1
	}
	if num == 1 {
		return testval
	}
	testval2 := functionalEqualityLevel0(res1[1], res2[1])
	if testval2 == 0 {
		return testval
	}
	unmatchsize := -1
	if testval == 1 && testval2 == 1 {
		unmatchsize = 2
	}
	if !op1.IsCommutative() {
		return unmatchsize
	}
	comm1 := functionalEqualityLevel0(res1[0], res2[1])
	comm2 := functionalEqualityLevel0(res1[1], res2[0])
	if comm1 == 0 && comm2 == 0 {
		return 0
	}
	if comm1 < 0 || comm2 < 0 {
		return unmatchsize
	}
	if comm1 == 0 {
		res1[0] = res1[1]
		return 1
	}
	if comm2 == 0 {
		res2[0] = res2[1]
		return 1
	}
	if unmatchsize == 2 {
		return 2
	}
	res2[0], res2[1] = res2[1], res2[0]
	return 2
}

// C++ parity: expression.cc functionalEquality.
func functionalEquality(vn1, vn2 *Varnode) bool {
	var buf1, buf2 [2]*Varnode
	return functionalEqualityLevel(vn1, vn2, buf1[:], buf2[:]) == 0
}
