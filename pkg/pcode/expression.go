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

// functionalEqualityLevel0 returns 0 (equal), 1 (need more), or -1 (not equal)
// without recursion.
// C++ parity: expression.cc functionalEqualityLevel0
func functionalEqualityLevel0(vn1, vn2 *Varnode) int {
	if vn1 == vn2 {
		return 0
	}
	if vn1.Size() != vn2.Size() {
		return -1
	}
	if vn1.IsConstant() {
		if vn2.IsConstant() {
			if vn1.Offset() == vn2.Offset() {
				return 0
			}
			return -1
		}
		return -1
	}
	if vn1.IsFree() || vn2.IsFree() {
		return -1
	}
	return 1
}

// functionalEqualityLevel checks if vn1 and vn2 contain the same value.
// Returns: -1 (different/unknown), 0 (same), 1 or 2 (contingent on pairs in res1/res2).
// res1 and res2 must be slices of length >= 2.
// C++ parity: expression.cc functionalEqualityLevel (lines 625-705)
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
	if op1.IsMarker() {
		return -1
	}
	if op2.IsCall() {
		return -1
	}
	if opc == CPUI_LOAD {
		if op1.Addr() != op2.Addr() {
			return -1
		}
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

// functionalEquality returns true if vn1 and vn2 provably hold the same value.
// C++ parity: expression.cc functionalEquality
func functionalEquality(vn1, vn2 *Varnode) bool {
	var res1, res2 [2]*Varnode
	return functionalEqualityLevel(vn1, vn2, res1[:], res2[:]) == 0
}
