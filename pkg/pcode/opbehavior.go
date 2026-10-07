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

import (
	"errors"
	"math/bits"
)

// errEvaluation is OpBehavior's LowlevelError/EvaluationError: the op has no
// emulation for these inputs (unimplemented opcode, divide by zero, missing
// float format).
var errEvaluation = errors.New("op evaluation unimplemented")

// evaluateUnary emulates a unary op on constant inputs.
// C++ parity: OpBehavior*::evaluateUnary (opbehavior.cc).
func evaluateUnary(code OpCode, sizeout, sizein int32, in1 uint64) (uint64, error) {
	switch code {
	case CPUI_COPY, CPUI_INT_ZEXT:
		return in1, nil
	case CPUI_INT_SEXT:
		return signExtendSize(in1, sizein, sizeout), nil
	case CPUI_INT_2COMP:
		return (^(in1 - 1)) & maskForSize(sizein), nil
	case CPUI_INT_NEGATE:
		return ^in1 & maskForSize(sizein), nil
	case CPUI_BOOL_NEGATE:
		return in1 ^ 1, nil
	case CPUI_POPCOUNT:
		return uint64(bits.OnesCount64(in1)), nil
	case CPUI_LZCOUNT:
		return uint64(bits.LeadingZeros64(in1) - 8*(8-int(sizein))), nil
	case CPUI_FLOAT_INT2FLOAT:
		if f := getFloatFormat(sizeout); f != nil {
			return f.opInt2Float(in1, sizein), nil
		}
	case CPUI_FLOAT_FLOAT2FLOAT:
		fout, fin := getFloatFormat(sizeout), getFloatFormat(sizein)
		if fout != nil && fin != nil {
			return fin.opFloat2Float(in1, fout), nil
		}
	case CPUI_FLOAT_NAN, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT,
		CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
		f := getFloatFormat(sizein)
		if f == nil {
			break
		}
		switch code {
		case CPUI_FLOAT_NAN:
			return f.opNan(in1), nil
		case CPUI_FLOAT_NEG:
			return f.opNeg(in1), nil
		case CPUI_FLOAT_ABS:
			return f.opAbs(in1), nil
		case CPUI_FLOAT_SQRT:
			return f.opSqrt(in1), nil
		case CPUI_FLOAT_TRUNC:
			return f.opTrunc(in1, sizeout), nil
		case CPUI_FLOAT_CEIL:
			return f.opCeil(in1), nil
		case CPUI_FLOAT_FLOOR:
			return f.opFloor(in1), nil
		default:
			return f.opRound(in1), nil
		}
	}
	return 0, errEvaluation
}

// evaluateBinary emulates a binary op on constant inputs; sizein is the size
// of input 0. C++ parity: OpBehavior*::evaluateBinary (opbehavior.cc).
func evaluateBinary(code OpCode, sizeout, sizein int32, in1, in2 uint64) (uint64, error) {
	switch code {
	case CPUI_INT_EQUAL:
		return boolToUint64(in1 == in2), nil
	case CPUI_INT_NOTEQUAL:
		return boolToUint64(in1 != in2), nil
	case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL:
		if sizein <= 0 {
			return 0, nil
		}
		mask := uint64(0x80) << uint(8*(sizein-1))
		bit1, bit2 := in1&mask, in2&mask
		if bit1 != bit2 {
			return boolToUint64(bit1 != 0), nil
		}
		if code == CPUI_INT_SLESS {
			return boolToUint64(in1 < in2), nil
		}
		return boolToUint64(in1 <= in2), nil
	case CPUI_INT_LESS:
		return boolToUint64(in1 < in2), nil
	case CPUI_INT_LESSEQUAL:
		return boolToUint64(in1 <= in2), nil
	case CPUI_INT_ADD, CPUI_PTRSUB:
		return (in1 + in2) & maskForSize(sizeout), nil
	case CPUI_INT_SUB:
		return (in1 - in2) & maskForSize(sizeout), nil
	case CPUI_INT_CARRY:
		return boolToUint64(in1 > (in1+in2)&maskForSize(sizein)), nil
	case CPUI_INT_SCARRY:
		res := in1 + in2
		sb := uint(sizein*8 - 1)
		a, b, r := (in1>>sb)&1, (in2>>sb)&1, (res>>sb)&1
		r ^= a
		a ^= b
		a ^= 1
		return r & a, nil
	case CPUI_INT_SBORROW:
		res := in1 - in2
		sb := uint(sizein*8 - 1)
		a, b, r := (in1>>sb)&1, (in2>>sb)&1, (res>>sb)&1
		a ^= r
		r ^= b
		r ^= 1
		return a & r, nil
	case CPUI_INT_XOR, CPUI_BOOL_XOR:
		return in1 ^ in2, nil
	case CPUI_INT_AND, CPUI_BOOL_AND:
		return in1 & in2, nil
	case CPUI_INT_OR, CPUI_BOOL_OR:
		return in1 | in2, nil
	case CPUI_INT_LEFT:
		if in2 >= uint64(sizeout)*8 {
			return 0, nil
		}
		return (in1 << in2) & maskForSize(sizeout), nil
	case CPUI_INT_RIGHT:
		if in2 >= uint64(sizeout)*8 {
			return 0, nil
		}
		return (in1 & maskForSize(sizeout)) >> in2, nil
	case CPUI_INT_SRIGHT:
		if in2 >= 8*uint64(sizeout) {
			if signbitNegative(in1, sizein) {
				return maskForSize(sizeout), nil
			}
			return 0, nil
		}
		res := in1 >> in2
		if signbitNegative(in1, sizein) {
			mask := maskForSize(sizein)
			res |= (mask >> in2) ^ mask
		}
		return res, nil
	case CPUI_INT_MULT:
		return (in1 * in2) & maskForSize(sizeout), nil
	case CPUI_INT_DIV:
		if in2 == 0 {
			return 0, errEvaluation // Divide by 0
		}
		return in1 / in2, nil
	case CPUI_INT_SDIV:
		if in2 == 0 {
			return 0, errEvaluation
		}
		return uint64(signedVal(in1, sizein)/signedVal(in2, sizein)) & maskForSize(sizeout), nil
	case CPUI_INT_REM:
		if in2 == 0 {
			return 0, errEvaluation // Remainder by 0
		}
		return in1 % in2, nil
	case CPUI_INT_SREM:
		if in2 == 0 {
			return 0, errEvaluation
		}
		return uint64(signedVal(in1, sizein)%signedVal(in2, sizein)) & maskForSize(sizeout), nil
	case CPUI_PIECE:
		return in1<<uint((sizeout-sizein)*8) | in2, nil
	case CPUI_SUBPIECE:
		if in2 >= 8 {
			return 0, nil
		}
		return (in1 >> (in2 * 8)) & maskForSize(sizeout), nil
	case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB:
		f := getFloatFormat(sizein)
		if f == nil {
			break
		}
		switch code {
		case CPUI_FLOAT_EQUAL:
			return f.opEqual(in1, in2), nil
		case CPUI_FLOAT_NOTEQUAL:
			return f.opNotEqual(in1, in2), nil
		case CPUI_FLOAT_LESS:
			return f.opLess(in1, in2), nil
		case CPUI_FLOAT_LESSEQUAL:
			return f.opLessEqual(in1, in2), nil
		case CPUI_FLOAT_ADD:
			return f.opAdd(in1, in2), nil
		case CPUI_FLOAT_DIV:
			return f.opDiv(in1, in2), nil
		case CPUI_FLOAT_MULT:
			return f.opMult(in1, in2), nil
		default:
			return f.opSub(in1, in2), nil
		}
	}
	return 0, errEvaluation
}

// signExtendSize sign-extends in from sizein to sizeout bytes.
// C++ parity: sign_extend(uintb,int4,int4) (address.cc).
func signExtendSize(in uint64, sizein, sizeout int32) uint64 {
	in &= maskForSize(sizein)
	if sizein >= sizeout {
		return in
	}
	if in>>uint(sizein*8-1) != 0 {
		in |= ^maskForSize(sizein) & maskForSize(sizeout)
	}
	return in
}

// isCollapsible reports whether op can fold to a constant.
// C++ parity: PcodeOp::isCollapsible.
func (op *PcodeOp) isCollapsible() bool {
	if op.flags&PcodeOpNoCollapse != 0 || !op.IsAssignment() || op.NumInput() == 0 {
		return false
	}
	for i := 0; i < op.NumInput(); i++ {
		if !op.Input(i).IsConstant() {
			return false
		}
	}
	return op.Output().Size() <= 8
}

// collapse evaluates a collapsible op. C++ parity: PcodeOp::collapse.
func (op *PcodeOp) collapse() (uint64, error) {
	vn0 := op.Input(0)
	switch et := op.EvalType(); {
	case et&PcodeOpUnary != 0:
		return evaluateUnary(op.Code(), op.Output().Size(), vn0.Size(), vn0.Offset())
	case et&PcodeOpBinary != 0:
		return evaluateBinary(op.Code(), op.Output().Size(), vn0.Size(), vn0.Offset(), op.Input(1).Offset())
	}
	return 0, errEvaluation // Invalid constant collapse
}
