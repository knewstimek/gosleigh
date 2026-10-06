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

import "math/bits"

// apply rewrites the parity of a POPCOUNT over shifted booleans:
// popcount((b1 << 6) | (b2 << 2)) & 1 => b1 ^ b2.
// C++ parity: ruleaction.cc RulePopcountBoolXor::applyOp.
func (r *RulePopcountBoolXor) apply(op *PcodeOp, data *Funcdata) int {
	for _, baseOp := range op.Output().DescendIter() {
		if baseOp.Code() != CPUI_INT_AND {
			continue
		}
		if c := baseOp.Input(1); !c.IsConstant() || c.Offset() != 1 || c.Size() != 1 {
			continue
		}
		inVn := op.Input(0)
		if !inVn.IsWritten() {
			return 0
		}
		nz := inVn.NZMask()
		switch bits.OnesCount64(nz) {
		case 1:
			b1, _ := popcountBooleanResult(inVn, leastSigBitSet(nz))
			if b1 == nil {
				continue
			}
			data.OpSetOpcode(baseOp, CPUI_COPY)
			data.OpRemoveInput(baseOp, 1)
			data.OpSetInput(baseOp, b1, 0)
			return 1
		case 2:
			b1, c0 := popcountBooleanResult(inVn, leastSigBitSet(nz))
			if b1 == nil && c0 != 1 {
				continue
			}
			b2, c1 := popcountBooleanResult(inVn, mostSigBitSet(nz))
			if b2 == nil && c1 != 1 {
				continue
			}
			if b1 == nil && b2 == nil {
				continue
			}
			if b1 == nil {
				b1 = data.NewConstant(1, 1)
			}
			if b2 == nil {
				b2 = data.NewConstant(1, 1)
			}
			data.OpSetOpcode(baseOp, CPUI_INT_XOR)
			data.OpSetInput(baseOp, b1, 0)
			data.OpSetInput(baseOp, b2, 1)
			return 1
		}
	}
	return 0
}

// popcountBooleanResult walks back through extensions, shifts and bitwise
// combinations to the boolean producing bit bitPos of vn. A constant bit is
// passed back as constRes (0 or 1) with a nil result; -1 means not found.
// C++ parity: RulePopcountBoolXor::getBooleanResult.
func popcountBooleanResult(vn *Varnode, bitPos int) (*Varnode, int) {
	mask := uint64(1) << uint(bitPos)
	for {
		if vn.IsConstant() {
			return nil, int((vn.Offset() >> uint(bitPos)) & 1)
		}
		if !vn.IsWritten() {
			return nil, -1
		}
		if bitPos == 0 && vn.Size() == 1 && vn.NZMask() == mask {
			return vn, -1
		}
		op := vn.Def()
		switch op.Code() {
		case CPUI_INT_AND:
			if !op.Input(1).IsConstant() {
				return nil, -1
			}
			vn = op.Input(0)
		case CPUI_INT_XOR, CPUI_INT_OR:
			vn0, vn1 := op.Input(0), op.Input(1)
			switch {
			case vn0.NZMask()&mask != 0:
				if vn1.NZMask()&mask != 0 {
					return nil, -1 // no unique path
				}
				vn = vn0
			case vn1.NZMask()&mask != 0:
				vn = vn1
			default:
				return nil, -1
			}
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			vn = op.Input(0)
			if bitPos >= int(vn.Size())*8 {
				return nil, -1
			}
		case CPUI_SUBPIECE:
			sa := int(op.Input(1).Offset()) * 8
			bitPos += sa
			mask <<= uint(sa)
			vn = op.Input(0)
		case CPUI_PIECE:
			vn0, vn1 := op.Input(0), op.Input(1)
			sa := int(vn1.Size()) * 8
			if bitPos >= sa {
				vn = vn0
				bitPos -= sa
				mask >>= uint(sa)
			} else {
				vn = vn1
			}
		case CPUI_INT_LEFT:
			vn1 := op.Input(1)
			if !vn1.IsConstant() {
				return nil, -1
			}
			sa := int(vn1.Offset())
			if sa > bitPos {
				return nil, -1
			}
			bitPos -= sa
			mask >>= uint(sa)
			vn = op.Input(0)
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			vn1 := op.Input(1)
			if !vn1.IsConstant() {
				return nil, -1
			}
			sa := int(vn1.Offset())
			vn = op.Input(0)
			bitPos += sa
			if bitPos >= int(vn.Size())*8 {
				return nil, -1
			}
			mask <<= uint(sa)
		default:
			return nil, -1
		}
	}
}
