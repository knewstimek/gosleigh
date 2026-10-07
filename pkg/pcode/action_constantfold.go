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

// collapsibleOpcodes lists every opcode PcodeOp::collapse can evaluate: the
// unary and binary TypeOps not marked nocollapse. C++ RuleCollapseConstants
// applies to all opcodes and gates on isCollapsible; Go dispatches rules by
// opcode, and the remaining opcodes can never collapse.
var collapsibleOpcodes = func() []OpCode {
	var res []OpCode
	for code, t := range RegisterTypeOps() {
		if t == nil {
			continue
		}
		fl := t.GetFlags()
		if fl&(PcodeOpUnary|PcodeOpBinary) != 0 && fl&PcodeOpNoCollapse == 0 {
			res = append(res, OpCode(code))
		}
	}
	return res
}()

// evalConstOp folds a collapsible op. C++ parity: PcodeOp::isCollapsible +
// PcodeOp::collapse.
func evalConstOp(op *PcodeOp) (uint64, bool) {
	if !op.isCollapsible() {
		return 0, false
	}
	res, err := op.collapse()
	return res, err == nil
}

// foldedConstantValue returns the value of a constant Varnode.
func foldedConstantValue(vn *Varnode) (uint64, bool) {
	if vn == nil || !vn.IsConstant() {
		return 0, false
	}
	return truncateToSize(vn.Offset(), vn.Size()), true
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
