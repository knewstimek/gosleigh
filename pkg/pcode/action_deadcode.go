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

// ActionDeadCode is a general dead store eliminator. It removes ops whose
// output varnode has no consumers (NumDescend == 0) and no side effects.
// Runs to fixpoint: eliminating one op may expose its inputs as newly dead.
// C++ parity: action.hh ActionDeadCode (simplified)
type ActionDeadCode struct {
	ActionBase
}

func NewActionDeadCode(group string) *ActionDeadCode {
	a := &ActionDeadCode{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "deadcode", group)
	return a
}

func (a *ActionDeadCode) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionDeadCode(a.GetGroup())
}

// Apply eliminates dead stores to fixpoint.
//
// An op is eligible for removal when:
//   - Its output varnode exists and has zero descendants (no consumers), AND
//   - The op has no side effects (not STORE/CALL/BRANCH/RETURN/INDIRECT).
//
// Flag-computing ops (INT_CARRY, INT_SCARRY, INT_SBORROW, POPCOUNT, BOOL_*)
// are a primary target, but the pass is general: any dead pure op is removed.
// Running to fixpoint ensures that chains like
// POPCOUNT -> BOOL_AND -> INT_EQUAL -> (dead varnode)
// are fully pruned once the chain tail is eliminated.
func (a *ActionDeadCode) Apply(data *Funcdata) int {
	total := 0
	for {
		count := 0
		ops := data.allOpsOrdered()
		for _, op := range ops {
			if op.IsDead() {
				continue
			}
			out := op.Output()
			if out == nil {
				// Ops with no output varnode model side effects (STORE, CALL,
				// BRANCH, RETURN). Never eliminate these.
				continue
			}
			if out.NumDescend() != 0 {
				continue
			}
			if !opHasSideEffects(op.Code()) {
				data.OpDestroy(op)
				count++
			}
		}
		total += count
		if count == 0 {
			break
		}
	}
	if total > 0 {
		return 1 // signal modification
	}
	return 0
}

// opHasSideEffects returns true for opcodes that must not be eliminated even
// when their output varnode has no consumers, because they have effects beyond
// the output (memory writes, control flow, external calls).
func opHasSideEffects(code OpCode) bool {
	switch code {
	case CPUI_STORE,
		CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER,
		CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND,
		CPUI_RETURN,
		CPUI_INDIRECT: // models call clobber; conservative, keep it
		return true
	}
	return false
}

// ActionSetCasts is a stub for future cast insertion.
// C++ parity: action.hh ActionSetCasts (stub)
type ActionSetCasts struct {
	ActionBase
}

func NewActionSetCasts(group string) *ActionSetCasts {
	a := &ActionSetCasts{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "setcasts", group)
	return a
}

func (a *ActionSetCasts) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionSetCasts(a.GetGroup())
}

func (a *ActionSetCasts) Apply(data *Funcdata) int {
	return 0 // stub -- no-op for now
}
