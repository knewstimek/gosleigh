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

// ActionConstantFold evaluates pure ops whose every input is a constant
// varnode and replaces the op with COPY(result_const).
//
// Runs to fixpoint: folding one op may expose its output as a new constant
// input to downstream ops, enabling further folding (e.g. INT_AND(c,c2) ->
// const, then POPCOUNT(const) -> const).
//
// C++ parity: typeop.cc TypeOp::evaluateBinary / evaluateUnary
// (Ghidra folds constants inside the TypeOp dispatch; here we centralise
// the pass in one action rather than spreading it across per-opcode rules.)
type ActionConstantFold struct {
	ActionBase
}

// NewActionConstantFold constructs an ActionConstantFold.
func NewActionConstantFold(group string) *ActionConstantFold {
	a := &ActionConstantFold{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "constantfold", group)
	return a
}

func (a *ActionConstantFold) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionConstantFold(a.GetGroup())
}

// Apply folds constant-input pure ops to COPY(const) until no more change.
// Phase 2 then handles identity-element simplifications (e.g. INT_ADD(x, 0))
// using foldedConstantValue so that patterns like INT_ADD(x, COPY(0)) -- where
// the zero was itself produced by phase 1 constant-folding INT_2COMP(0) -- are
// also eliminated.  Without phase 2, RuleIdentityEl in BatchA would miss these
// because its guard requires IsConstant(), which is false for COPY outputs.
func (a *ActionConstantFold) Apply(data *Funcdata) int {
	total := 0

	// Phase 1: fold ops whose every input resolves to a constant.
	for {
		count := 0
		for _, op := range data.allOpsOrdered() {
			if op.IsDead() {
				continue
			}
			out := op.Output()
			if out == nil {
				continue
			}
			res, ok := evalConstOp(op)
			if !ok {
				continue
			}
			// Replace op with COPY(newConst).
			newConst := data.NewConstant(out.Size(), truncateToSize(res, out.Size()))
			rewriteToCopy(data, op, newConst)
			count++
		}
		total += count
		if count == 0 {
			break
		}
	}

	// Phase 2: identity-element simplifications via foldedConstantValue.
	// Handles cases such as INT_ADD(x, COPY(0)) that arise after phase 1
	// converts INT_2COMP(0) -> COPY(0), where the zero is hidden behind a COPY.
	// C++ parity: RuleIdentityEl::applyOp covers the direct-constant cases;
	// this phase extends that to COPY-forwarded constants.
	for {
		count := 0
		for _, op := range data.allOpsOrdered() {
			if op.IsDead() || op.NumInput() < 2 {
				continue
			}
			if applyIdentityFold(data, op) {
				count++
			}
		}
		total += count
		if count == 0 {
			break
		}
	}

	if total > 0 {
		return 1
	}
	return 0
}

// applyIdentityFold simplifies binary ops whose second operand resolves (via
// foldedConstantValue) to the identity element for that operation.
// Returns true if the op was rewritten.
func applyIdentityFold(data *Funcdata, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	b, bok := foldedConstantValue(op.Input(1))
	if !bok {
		return false
	}
	switch op.Code() {
	case CPUI_INT_ADD, CPUI_INT_XOR, CPUI_INT_OR:
		if b == 0 {
			rewriteToCopy(data, op, op.Input(0))
			return true
		}
	case CPUI_INT_SUB:
		// INT_SUB(x, 0) -> COPY(x).
		// RuleIdentityEl does not handle INT_SUB; cover it here.
		if b == 0 {
			rewriteToCopy(data, op, op.Input(0))
			return true
		}
	case CPUI_INT_MULT:
		if b == 1 {
			rewriteToCopy(data, op, op.Input(0))
			return true
		}
		if b == 0 {
			rewriteToConst(data, op, 0)
			return true
		}
	}
	return false
}

// evalConstOp attempts to constant-fold op.
// Returns (result, true) if all inputs are constants (or constant-valued via
// COPY(const) forwarding) and the opcode is supported.
// The result is NOT yet masked to output size; callers must mask.
func evalConstOp(op *PcodeOp) (uint64, bool) {
	switch op.Code() {
	// --- binary ops ---
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_MULT,
		CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR,
		CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
		CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW,
		CPUI_BOOL_AND, CPUI_BOOL_OR:
		if op.NumInput() != 2 {
			return 0, false
		}
		a, aok := foldedConstantValue(op.Input(0))
		b, bok := foldedConstantValue(op.Input(1))
		if !aok || !bok {
			return 0, false
		}
		inSize := foldedSize(op.Input(0))
		return evalBinary(op.Code(), a, b, inSize), true

	// --- unary ops ---
	case CPUI_INT_ZEXT, CPUI_INT_SEXT,
		CPUI_INT_2COMP, CPUI_INT_NEGATE,
		CPUI_BOOL_NEGATE,
		CPUI_POPCOUNT:
		if op.NumInput() != 1 {
			return 0, false
		}
		a, aok := foldedConstantValue(op.Input(0))
		if !aok {
			return 0, false
		}
		inSize := foldedSize(op.Input(0))
		return evalUnary(op.Code(), a, inSize), true
	}
	return 0, false
}

// foldedConstantValue returns the constant value of vn, following a chain of
// COPY ops: if vn is defined by COPY(const) the constant is forwarded.
// This allows the fixpoint loop to fold chains in a single pass by resolving
// already-folded upstream ops without waiting for another iteration.
func foldedConstantValue(vn *Varnode) (uint64, bool) {
	if vn == nil {
		return 0, false
	}
	// Direct constant varnode.
	if vn.IsConstant() {
		return truncateToSize(vn.Offset(), vn.Size()), true
	}
	// COPY(const) forwarding: if the defining op is COPY with a constant input,
	// treat this varnode as having that constant value.
	def := vn.Def()
	if def != nil && def.Code() == CPUI_COPY && def.NumInput() == 1 {
		src := def.Input(0)
		if src != nil && src.IsConstant() {
			return truncateToSize(src.Offset(), src.Size()), true
		}
	}
	return 0, false
}

// foldedSize returns the effective input size for signed-arithmetic purposes,
// following COPY forwarding the same way foldedConstantValue does.
func foldedSize(vn *Varnode) int32 {
	if vn == nil {
		return 1
	}
	if vn.IsConstant() {
		return vn.Size()
	}
	def := vn.Def()
	if def != nil && def.Code() == CPUI_COPY && def.NumInput() == 1 {
		src := def.Input(0)
		if src != nil && src.IsConstant() {
			return src.Size()
		}
	}
	return vn.Size()
}

// evalBinary evaluates a binary constant op.
// inSize is the size of the input operands (needed for signed comparisons).
// C++ parity: typeop.cc TypeOpBinary::evaluateBinary
func evalBinary(code OpCode, a, b uint64, inSize int32) uint64 {
	switch code {
	case CPUI_INT_ADD:
		return a + b
	case CPUI_INT_SUB:
		return a - b
	case CPUI_INT_MULT:
		return a * b
	case CPUI_INT_AND:
		return a & b
	case CPUI_INT_OR:
		return a | b
	case CPUI_INT_XOR:
		return a ^ b
	case CPUI_INT_EQUAL:
		return boolToUint64(a == b)
	case CPUI_INT_NOTEQUAL:
		return boolToUint64(a != b)
	case CPUI_INT_LESS:
		return boolToUint64(a < b)
	case CPUI_INT_LESSEQUAL:
		return boolToUint64(a <= b)
	case CPUI_INT_SLESS:
		return boolToUint64(signedVal(a, inSize) < signedVal(b, inSize))
	case CPUI_INT_SLESSEQUAL:
		return boolToUint64(signedVal(a, inSize) <= signedVal(b, inSize))
	case CPUI_INT_CARRY:
		// unsigned carry: result overflows inSize bits
		mask := maskForSize(inSize)
		return boolToUint64((a+b)&mask < a&mask)
	case CPUI_INT_SCARRY:
		// signed carry (overflow): operands same sign, result different
		sb := signBitForSize(inSize)
		sum := a + b
		return boolToUint64(((a^sum)&(b^sum))&sb != 0)
	case CPUI_INT_SBORROW:
		// signed borrow (overflow on subtract): operands differ in sign, result same sign as subtrahend
		sb := signBitForSize(inSize)
		diff := a - b
		return boolToUint64(((a^b)&(a^diff))&sb != 0)
	case CPUI_BOOL_AND:
		return boolToUint64(a != 0 && b != 0)
	case CPUI_BOOL_OR:
		return boolToUint64(a != 0 || b != 0)
	}
	return 0
}

// evalUnary evaluates a unary constant op.
// inSize is the size of the input operand.
// C++ parity: typeop.cc TypeOpUnary::evaluateUnary
func evalUnary(code OpCode, a uint64, inSize int32) uint64 {
	switch code {
	case CPUI_INT_ZEXT:
		// Zero-extend: value is already unsigned, no sign bits to extend.
		return a
	case CPUI_INT_SEXT:
		// Sign-extend to 64 bits; output is sign-extended from inSize.
		return uint64(signedVal(a, inSize))
	case CPUI_INT_2COMP:
		return -a
	case CPUI_INT_NEGATE:
		return ^a
	case CPUI_BOOL_NEGATE:
		return boolToUint64(a == 0)
	case CPUI_POPCOUNT:
		return uint64(bits.OnesCount64(a))
	}
	return 0
}

// signedVal interprets val as a two's-complement signed integer of inSize bytes.
func signedVal(val uint64, inSize int32) int64 {
	if inSize <= 0 || inSize >= 8 {
		return int64(val)
	}
	nb := uint(inSize) * 8
	// Sign-extend from nb bits.
	// Shift left to put sign bit at bit 63, then arithmetic shift right.
	return int64(val<<(64-nb)) >> (64 - nb)
}

// boolToUint64 converts a bool to 0 or 1.
func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
