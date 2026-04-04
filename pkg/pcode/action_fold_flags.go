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

// ActionFoldFlagConditions eliminates named CPU flag register varnodes (ZF, SF,
// OF, CF, ...) from the C output by redirecting their defining op's output to
// an anonymous unique-space temp varnode and rewiring all consumers to the temp.
//
// Motivation: x86 CMP/TEST instructions define ZF/SF/OF/CF via p-code ops like
//   INT_EQUAL, INT_SLESS, INT_LESS, INT_CARRY, INT_SCARRY.
//
// After Heritage, the SSA graph may look like:
//
//	ZF_1 = INT_EQUAL(EAX, 0)         -- block A
//	ZF_2 = INT_EQUAL(EAX, 0)         -- block B
//	ZF_m = MULTIEQUAL(ZF_1, ZF_2)    -- phi-merge
//	CBRANCH(target, ZF_1)
//	CBRANCH(target, ZF_m)
//
// Flag varnodes are register-space, 1-byte varnodes. The pass replaces each
// such flag varnode that is the output of a boolean/comparison/phi op with
// an anonymous unique temp:
//
//	tmp_1 = INT_EQUAL(EAX, 0)
//	tmp_2 = INT_EQUAL(EAX, 0)
//	tmp_m = MULTIEQUAL(tmp_1, tmp_2)
//	CBRANCH(target, tmp_1)
//	CBRANCH(target, tmp_m)
//
// The original ZF_1/ZF_2/ZF_m varnodes now have no consumers and are
// eliminated by ActionDeadCode. Because they are in register space they had
// PrintC-visible names (e.g. "ZF"), which caused "if (ZF)" in the output.
// After this pass they are gone and the conditions look like "if (tmp_N != 0)".
//
// Consumers allowed: CBRANCH (condition slot), MULTIEQUAL (any slot),
// or other boolean/comparison ops (i.e. flag chains). Any other consumer
// (e.g. STORE, CALL, LOAD) indicates the flag has a non-trivial use and we
// leave it alone.
//
// C++ parity: similar intent to Ghidra's flag-sink elimination; the full
// Ghidra pipeline uses type analysis + FuncProto to anchor live registers,
// which makes flag writes naturally dead.
type ActionFoldFlagConditions struct {
	ActionBase
}

// NewActionFoldFlagConditions creates an ActionFoldFlagConditions pass.
func NewActionFoldFlagConditions(group string) *ActionFoldFlagConditions {
	a := &ActionFoldFlagConditions{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "fold-flag-conditions", group)
	return a
}

func (a *ActionFoldFlagConditions) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionFoldFlagConditions(a.GetGroup())
}

// Apply runs the flag-folding pass.
//
// For each op whose output is a flag varnode (register space, 1-byte, boolean
// or phi op) and whose every consumer is "flag-safe" (CBRANCH, MULTIEQUAL, or
// another boolean/comparison op), the output is redirected to a unique temp and
// all consumers are rewired to the temp.
//
// The pass runs to fixpoint so that phi-chained flags (MULTIEQUAL whose inputs
// are themselves flag varnodes) are resolved in the right order.
func (a *ActionFoldFlagConditions) Apply(data *Funcdata) int {
	total := 0
	for {
		n := foldFlagRound(data)
		total += n
		if n == 0 {
			break
		}
	}
	if total > 0 {
		return 1
	}
	return 0
}

// foldFlagRound performs one sweep, returning the number of flag varnodes
// redirected to unique temps.
func foldFlagRound(data *Funcdata) int {
	changed := 0
	for _, defOp := range data.allOpsOrdered() {
		if defOp == nil || defOp.IsDead() {
			continue
		}
		if !isFlagProducingOp(defOp.Code()) {
			continue
		}
		flagVn := defOp.Output()
		if flagVn == nil || !isFlagVarnode(flagVn) {
			continue
		}
		if flagVn.NumDescend() == 0 {
			continue // already dead -- ActionDeadCode will clean up
		}

		// Check that every consumer is flag-safe: CBRANCH (condition slot),
		// MULTIEQUAL (any slot), or another boolean/comparison op output that
		// is itself a flag varnode (so it will be handled in a later round).
		consumers := flagVn.DescendIter()
		safe := true
		for _, consumer := range consumers {
			if !isFlagSafeConsumer(consumer, flagVn) {
				safe = false
				break
			}
		}
		if !safe {
			continue
		}

		// Redirect defOp output from flagVn to a new unique temp.
		// Step 1: Disconnect flagVn from defOp.
		// OpUnsetOutput: flagVn has consumers -> MakeFree (stays in bank).
		data.OpUnsetOutput(defOp)

		// Step 2: Wire a new unique temp as defOp's output.
		tmpVn := data.NewUniqueOut(flagVn.Size(), defOp)

		// Step 3: Rewire every consumer from flagVn to tmpVn.
		for _, consumer := range consumers {
			// Find the slot(s) where flagVn is an input to consumer.
			for slot := 0; slot < consumer.NumInput(); slot++ {
				if consumer.Input(slot) == flagVn {
					flagVn.EraseDescend(consumer)
					consumer.SetInput(nil, slot) // raw clear, no descend side-effect
					data.OpSetInput(consumer, tmpVn, slot)
				}
			}
		}

		changed++
	}
	return changed
}

// isFlagSafeConsumer returns true if consumer uses flagVn in a "flag-safe"
// context -- one where replacing flagVn with an anonymous temp is harmless:
//
//   - CBRANCH at condition slot (slot 1)
//   - MULTIEQUAL at any slot (phi-merge of flags)
//   - A boolean/comparison op (the flag is an operand to another flag computation)
func isFlagSafeConsumer(consumer *PcodeOp, flagVn *Varnode) bool {
	switch consumer.Code() {
	case CPUI_CBRANCH:
		// Condition is slot 1. Slot 0 is the branch target address.
		return consumer.NumInput() >= 2 && consumer.Input(1) == flagVn
	case CPUI_MULTIEQUAL:
		// Phi-merge: flagVn can be any input slot.
		return true
	default:
		// Allow other boolean/comparison ops -- the flag feeds another flag.
		return isBooleanOp(consumer.Code())
	}
}

// isFlagProducingOp returns true for opcodes that can produce a CPU flag
// (boolean) result: comparison ops, boolean ops, and phi-merges.
func isFlagProducingOp(code OpCode) bool {
	if code == CPUI_MULTIEQUAL {
		return true
	}
	return isBooleanOp(code)
}

// isFlagVarnode returns true when vn looks like a named CPU flag register:
// lives in register space (not unique/constant), and is exactly 1 byte wide.
func isFlagVarnode(vn *Varnode) bool {
	if vn == nil || vn.Space() == nil {
		return false
	}
	// Constant and unique space varnodes are not named CPU flags.
	if vn.Space().IsConstant() || vn.Space().IsUnique() {
		return false
	}
	// Flag registers are exactly 1 byte.
	return vn.Size() == 1
}

// isBooleanOp returns true for opcodes that produce a 1-bit (size-1) boolean
// result from a comparison or logical operation.
func isBooleanOp(code OpCode) bool {
	switch code {
	case CPUI_INT_EQUAL,
		CPUI_INT_NOTEQUAL,
		CPUI_INT_LESS,
		CPUI_INT_LESSEQUAL,
		CPUI_INT_SLESS,
		CPUI_INT_SLESSEQUAL,
		CPUI_INT_CARRY,
		CPUI_INT_SCARRY,
		CPUI_INT_SBORROW,
		CPUI_BOOL_NEGATE,
		CPUI_BOOL_AND,
		CPUI_BOOL_OR,
		CPUI_BOOL_XOR,
		CPUI_FLOAT_EQUAL,
		CPUI_FLOAT_NOTEQUAL,
		CPUI_FLOAT_LESS,
		CPUI_FLOAT_LESSEQUAL:
		return true
	}
	return false
}
