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
	// Run return recovery after the dead-code pass: prune any return-register
	// varnodes that still have non-RETURN consumers (the real uses that survived
	// dead-code elimination indicate the function has no explicit return value).
	// C++ parity: ActionReturnRecovery runs after ActionDeadCode in actmainloop.
	applyReturnRecovery(data)
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

// ActionSetCasts inserts explicit CPUI_CAST ops wherever the data-type a
// PcodeOp expects differs from the data-type its actual Varnode carries, so the
// C output renders the casts a compiler would require.
// C++ parity: coreaction.cc ActionSetCasts.
//
// Ported subset (documented gaps vs C++):
//   - Union/resolution machinery (resolveUnion, inheritResolution,
//     forceFacingType, needsResolution, tryResolutionAdjustment) is omitted:
//     Gosleigh does not model union field resolution.
//   - testStructOffset0 / insertPtrsubZero (PTRSUB-as-cast for struct field 0)
//     is omitted: struct-field pointer adjustment is not modeled here.
//   - markExplicitUnsigned / markExplicitLongSize are not ported, so castInput
//     returns 0 (no change) when no cast type is required.
//   - PTRADD/PTRSUB refit checks (opUndoPtradd, PTRSUB->INT_ADD) are omitted.
//   - Block order uses allOpsOrdered rather than dominance order; the per-op
//     cast decision is local, so this does not affect the inserted casts.
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

// Apply walks the ops and inserts input/output casts. C++ parity:
// ActionSetCasts::apply (coreaction.cc 2724-2776).
func (a *ActionSetCasts) Apply(data *Funcdata) int {
	cs := sharedCastStrategyC
	for _, op := range data.allOpsOrdered() {
		if op.IsDead() || op.HasFlag(PcodeOpNonPrinting) {
			continue
		}
		if op.Code() == CPUI_CAST {
			continue
		}
		// Do input casts first, as the output token may depend on the inputs.
		for i := 0; i < op.NumInput(); i++ {
			a.castInput(op, i, data, cs)
		}
		if op.Output() == nil {
			continue
		}
		a.castOutput(op, data, cs)
	}
	return 0
}

// castInput inserts a CAST producing the input Varnode at slot if the op expects
// a different type than the Varnode carries. C++ parity: ActionSetCasts::castInput
// (coreaction.cc 2657-2722).
func (a *ActionSetCasts) castInput(op *PcodeOp, slot int, data *Funcdata, cs *CastStrategyC) int {
	ct := op.GetOpcode().GetInputCast(op, slot, cs)
	if ct == nil {
		// markExplicitUnsigned / markExplicitLongSize not ported -> no change.
		return 0
	}
	vn := op.Input(slot)
	if vn == nil {
		return 0
	}
	vnin := vn
	// Guard against chains of casts.
	if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_CAST {
		if vn.IsImplied() {
			if vn.LoneDescend() == op {
				vn.UpdateType(ct)
				if vn.Type() == ct {
					return 1
				}
			}
			vnin = vn.Def().Input(0) // cast directly from input of previous cast
			if vnin != nil && ct == vnin.Type() {
				data.OpSetInput(op, vnin, slot)
				return 1
			}
		}
	} else if vn.IsConstant() {
		vn.UpdateType(ct)
		if vn.Type() == ct {
			return 1
		}
	}
	// resolveUnion / testStructOffset0 / tryResolutionAdjustment omitted.
	if vnin == nil {
		return 0
	}
	newop := data.NewOp(1, op.Addr())
	vnout := data.NewUniqueOut(vnin.Size(), newop)
	vnout.UpdateType(ct)
	vnout.SetImplied()
	data.OpSetOpcode(newop, CPUI_CAST)
	data.OpSetInput(newop, vnin, 0)
	data.OpSetInput(op, vnout, slot)
	data.OpInsertBefore(newop, op) // cast comes BEFORE the operation
	return 1
}

// castOutput inserts a CAST after op when the type a C compiler assigns to the
// op's output expression differs from the output Varnode's type. C++ parity:
// ActionSetCasts::castOutput (coreaction.cc 2534-2618).
func (a *ActionSetCasts) castOutput(op *PcodeOp, data *Funcdata, cs *CastStrategyC) int {
	tokenct := op.GetOpcode().GetOutputToken(op, cs)
	outvn := op.Output()
	outHighType := outvn.Type()
	if tokenct == outHighType {
		return 0 // same type, no cast
	}
	outHighResolve := outHighType
	if outvn.IsImplied() {
		// Implied varnode must take on the parse (token) type for atomic types,
		// or for pointers that do not point to a composite.
		if outHighResolve == nil || outHighResolve.Metatype() != TYPE_PTR {
			outvn.UpdateType(tokenct)
			outHighResolve = outvn.Type()
		} else if tokenct != nil && tokenct.Metatype() == TYPE_PTR {
			if ptr, ok := outHighResolve.(*Pointer); ok && ptr.Pointee() != nil {
				meta := ptr.Pointee().Metatype()
				if meta != TYPE_ARRAY && meta != TYPE_STRUCT && meta != TYPE_UNION {
					outvn.UpdateType(tokenct)
					outHighResolve = outvn.Type()
				}
			}
		}
		// Type-lock force branch omitted (no implied type locks modeled here).
	}
	// testStructOffset0 (PTRSUB-as-cast) omitted; always use a plain CAST.
	ct := cs.CastStandard(outHighResolve, tokenct, false, true)
	if ct == nil {
		return 0
	}
	// Generate the cast op: op now writes a fresh implied unique, and the CAST
	// produces the original output Varnode from it.
	vn := data.NewUnique(outvn.Size())
	vn.UpdateType(tokenct)
	vn.SetImplied()
	newop := data.NewOp(1, op.Addr())
	data.OpSetOpcode(newop, CPUI_CAST)
	data.OpSetOutput(newop, outvn)
	data.OpSetInput(newop, vn, 0)
	data.OpSetOutput(op, vn)
	data.OpInsertAfter(newop, op) // cast comes AFTER the operation
	return 1
}
