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
	"os"

	"gosleigh/pkg/address"
)

// ActionDeadCode is a general dead store eliminator. It removes ops whose
// output varnode has no consumers (NumDescend == 0) and no side effects.
// Runs to fixpoint: eliminating one op may expose its inputs as newly dead.
// C++ parity: action.hh ActionDeadCode (simplified)
type ActionDeadCode struct {
	ActionBase
}

func NewActionDeadCode(group string) *ActionDeadCode {
	a := &ActionDeadCode{}
	// flags=0: re-run every repeat of the enclosing action group, matching C++
	// ActionDeadCode (coreaction.hh:560 `Action(0,"deadcode",g)`), which the
	// actmainloop registers as an ordinary repeat member (coreaction.cc:5514).
	// A prior OncePerFunc simplification made this pass run only once per group,
	// so an op that becomes dead LATER in the loop (e.g. the residual
	// RAX = ZEXT(EAX_return) orphaned when subvariable flow retargets the RETURN
	// to the narrow value) was never cleaned inside the type-recovery loop. That
	// stale ZEXT kept feeding a UINT input-local into its operand's getLocalType,
	// flooding unsigned types onto loop accumulators/parameters. Running every
	// pass (as C++ does) removes the orphan before the next InferTypes sweep.
	// ActionDeadCode is monotonic (only removes ops), so re-running cannot loop
	// forever. Its embedded applyReturnRecovery call likewise now runs every
	// pass, matching C++ ActionReturnRecovery also being a flags=0 actmainloop
	// member (coreaction.cc:5511).
	a.ActionBase = NewActionBase(a, 0, "deadcode", group)
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
	// Consume-bit dead-code is the default (the faithful C++ mechanism, H7 step 2).
	// The legacy descendant-count path is kept as a transition fallback so any
	// edge case is a one-env-var A/B revert; it can be removed once consume-based
	// deadcode is proven across the broader corpus. C++ parity: ActionDeadCode::apply.
	if os.Getenv("GOSL_DESCENDANT_DC") == "" {
		return a.applyConsume(data)
	}
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

// applyConsume runs the consume-bit analysis (deadcode_consume.go) and then
// makes one pass over the written Varnodes of every heritaged space: an op
// whose output was never reached by a consume push is removed (a call only
// loses its output), and an output reached only vacuously (consume mask 0)
// has its reads replaced by constant 0 (neverConsumed).
// C++ parity: ActionDeadCode::apply (coreaction.cc 4035-4068). Like C++ it
// reports no change to the enclosing action: removing dead code is not a
// data-flow transform that should repeat the main loop.
func (a *ActionDeadCode) applyConsume(data *Funcdata) int {
	ca := newConsumeAnalysis()
	ca.computeConsumed(data)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() { // Location order
		if !vn.IsWritten() {
			continue
		}
		op := vn.Def()
		if op == nil || op.IsDead() || op.Output() != vn {
			continue
		}
		sp := vn.Space()
		if sp == nil || !spaceDoesDeadcode(sp) || !data.deadRemovalAllowed(sp) {
			continue // Don't eliminate if the space has not been heritaged
		}
		if !ca.vacuous[vn] { // Not even vacuously consumed
			if op.IsCall() {
				data.OpUnsetOutput(op) // For calls just get rid of the output
			} else {
				data.OpDestroy(op)
			}
			data.seenDeadcode(sp)
		} else if vn.Consumed() == 0 && a.neverConsumed(vn, data) {
			data.seenDeadcode(sp) // A value that is never used but bangs around
		}
	}
	data.ClearDeadVarnodes()
	return 0
}

// neverConsumed replaces every read of a Varnode whose bits are never used by
// constant 0 and removes its definition.
// C++ parity: ActionDeadCode::neverConsumed.
func (a *ActionDeadCode) neverConsumed(vn *Varnode, data *Funcdata) bool {
	if vn.Size() > 8 {
		return false // Not enough precision to really tell
	}
	for _, op := range append([]*PcodeOp(nil), vn.DescendIter()...) {
		data.OpSetInput(op, data.NewConstant(vn.Size(), 0), op.GetSlot(vn))
	}
	op := vn.Def()
	if op.IsCall() {
		data.OpUnsetOutput(op)
	} else {
		data.OpDestroy(op)
	}
	return true
}

// deadIndirectCreationCandidate reports an INDIRECT creation (a call killing
// a register: no prior value flows through it) in the register space. C++
// ActionDeadCode removes any op whose output is never consumed, INDIRECTs
// included; Gosleigh keeps INDIRECTs conservatively because it does not gate
// removal on per-space heritage progress (deadRemovalAllowed). A register
// creation carries no guarded data-flow and the register space is heritaged
// from the first pass, so removing it when unconsumed is the C++ outcome --
// and it is what keeps an unused callee return value from being taken as the
// call's output (checkOutputTrialUse sees the creation gone).
// C++ parity: coreaction.cc ActionDeadCode::apply (deletion loop).
func deadIndirectCreationCandidate(op *PcodeOp) bool {
	if op.Code() != CPUI_INDIRECT || !op.IsIndirectCreation() {
		return false
	}
	out := op.Output()
	return out != nil && out.Space() != nil && out.Space().Kind == address.SpaceKindProcessor
}

// opHasSideEffects returns true for opcodes that must not be eliminated even
// when their output varnode has no consumers, because they have effects beyond
// the output (memory writes, control flow, external calls).
func opHasSideEffects(code OpCode) bool {
	switch code {
	case CPUI_STORE,
		CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER,
		CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND,
		CPUI_RETURN:
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
	// Give the cast strategy access to the current function's scopes so a
	// spacebase PTRSUB output token can be resolved to its symbol pointer type.
	// C++ parity: the CastStrategy is bound to the Architecture/Funcdata.
	cs.fd = data
	// Ops are visited block by block in list order, as C++ does, so an op's
	// output cast (which may retype an implied output) is settled before its
	// readers in the same block are checked. A seq-number order would visit a
	// STORE before the PTRADD inserted ahead of it at the same address.
	var ops []*PcodeOp
	if bbs := data.GetBasicBlocks(); bbs != nil && bbs.GetSize() > 0 {
		for j := 0; j < bbs.GetSize(); j++ {
			if bb := asBasic(bbs.GetBlock(j)); bb != nil {
				ops = append(ops, bb.Ops()...)
			}
		}
	} else {
		ops = data.allOpsOrdered()
	}
	for _, op := range ops {
		// Skip NonPrinting ops. C++ parity: ActionSetCasts::apply skips op->notPrinted()
		// (coreaction.cc 2729). These are redundant internal COPYs marked by
		// ActionCopyMarker. ActionForLoops now runs AFTER ActionSetCasts, so the
		// for-loop iterate/initialize ops are still printing here and DO receive their
		// inserted CAST (e.g. sum_list: param_3 = (int *)param_3[1] is an output cast on
		// the LOAD iterator). That CAST is what ActionForLoops then folds into the
		// for-header, replacing the old render-time assignCastStr fallback.
		if op.IsDead() || op.NotPrinted() {
			continue
		}
		if op.Code() == CPUI_CAST {
			continue
		}
		if op.Code() == CPUI_PTRADD {
			// A PTRADD that no longer fits its pointer (as the variable is
			// typed) reverts to integer math.
			sz := int32(op.Input(2).Offset())
			ptr, ok := op.Input(0).HighTypeReadFacing(op).(*Pointer)
			if !ok || ptr.Pointee() == nil || ptr.Pointee().AlignSize() != sz*int32(ptr.WordSize()) {
				data.OpUndoPtradd(op, true)
			}
		} else if op.Code() == CPUI_PTRSUB {
			// Likewise a PTRSUB whose base no longer points at a matching
			// component: an offset becomes INT_ADD, a zero offset a COPY.
			base := op.Input(0)
			if !isPtrsubMatching(data, base.GetSpaceFromConst(), base.TypeReadFacing(op), int64(op.Input(1).Offset()), 0, 0) {
				if op.Input(1).Offset() == 0 {
					data.OpRemoveInput(op, 1)
					data.OpSetOpcode(op, CPUI_COPY)
				} else {
					data.OpSetOpcode(op, CPUI_INT_ADD)
				}
			}
		}
		// C++ parity: ActionSetCasts::apply (the PTRADD/PTRSUB re-checks).
		// Do input casts first, as the output token may depend on the inputs.
		for i := 0; i < op.NumInput(); i++ {
			a.resolveUnion(op, i, data, cs) // Union resolution must happen before casts are determined
			a.castInput(op, i, data, cs)
		}
		if op.Code() == CPUI_LOAD {
			checkPointerIssues(op, op.Output(), data)
		} else if op.Code() == CPUI_STORE {
			checkPointerIssues(op, op.Input(2), data)
		}
		if op.Output() == nil {
			continue
		}
		a.castOutput(op, data, cs)
	}
	return 0
}

// checkPointerIssues warns when the pointer of a LOAD or STORE does not point
// at a value of the size moved, or is bound to a different address space
// than the op accesses. Gosleigh has no overlay spaces, so the C++
// getContain() exemption never applies.
// C++ parity: ActionSetCasts::checkPointerIssues.
func checkPointerIssues(op *PcodeOp, vn *Varnode, data *Funcdata) {
	if op.addlFlags&PcodeOpSpecialPrint != 0 || vn == nil {
		return
	}
	ptr, ok := op.Input(1).HighTypeReadFacing(op).(*Pointer)
	if !ok || ptr.Pointee() == nil || ptr.Pointee().Size() != vn.Size() {
		name := "Load" // TypeOpLoad name "load", first letter upper-cased
		if op.Code() == CPUI_STORE {
			name = "Store"
		}
		data.warning(name+" size is inaccurate", op.Addr())
	}
	if ok && ptr.SpaceName() != "" {
		if opSpc := op.Input(0).GetSpaceFromConst(); opSpc != nil && opSpc.Name != ptr.SpaceName() {
			name := "Load"
			if op.Code() == CPUI_STORE {
				name = "Store"
			}
			data.warning(name+" refers to '"+opSpc.Name+"' but pointer attribute is '"+ptr.SpaceName()+"'", op.Addr())
		}
	}
}

// castInput inserts a CAST producing the input Varnode at slot if the op expects
// a different type than the Varnode carries. C++ parity: ActionSetCasts::castInput
// (coreaction.cc 2657-2722).
func (a *ActionSetCasts) castInput(op *PcodeOp, slot int, data *Funcdata, cs *CastStrategyC) int {
	ct := op.GetOpcode().GetInputCast(op, slot, cs)
	if ct == nil {
		// No cast type required: the input may still need an explicit unsigned
		// marker (a trailing 'U') or an explicit long size ('L'/'LL') on a
		// constant.
		resUnsigned := cs.markExplicitUnsigned(op, slot)
		resSized := cs.markExplicitLongSize(op, slot)
		if resUnsigned || resSized {
			return 1
		}
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
				if !vn.IsTypeLock() { // C++ Varnode::updateType(ct) leaves a locked type
					vn.UpdateType(ct)
				}
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
		if !vn.IsTypeLock() { // A locked constant (read-only fill) keeps its type and gets a cast
			vn.UpdateType(ct)
		}
		if vn.Type() == ct {
			return 1
		}
	} else if ct.Metatype() == TYPE_PTR && testStructOffset0(ct, vn.HighTypeReadFacing(op), cs) {
		// Insert a PTRSUB(vn,#0) instead of a CAST
		newop := insertPtrsubZero(op, slot, ct, data)
		if ht := vn.High().Type(); ht != nil && ht.NeedsResolution() {
			data.inheritResolution(ht, newop, 0, op, slot)
		}
		return 1
	} else if tryResolutionAdjustment(op, slot, data) {
		return 1
	}
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
	if ct.NeedsResolution() {
		data.forceFacingType(ct, -1, newop, -1)
	}
	if hv := vn.High(); hv != nil && hv.Type() != nil && hv.Type().NeedsResolution() {
		data.inheritResolution(hv.Type(), newop, 0, op, slot)
	}
	return 1
}

// isOpIdentical reports whether a variable of type ct1 can stand in for one
// of type ct2 in every operation: the same type once matching pointer levels
// and typedefs are stripped.
// C++ parity: ActionSetCasts::isOpIdentical.
func isOpIdentical(ct1, ct2 Datatype) bool {
	for {
		p1, ok1 := ct1.(*Pointer)
		p2, ok2 := ct2.(*Pointer)
		if !ok1 || !ok2 {
			break
		}
		ct1, ct2 = p1.Pointee(), p2.Pointee()
	}
	return stripTypedef(ct1) == stripTypedef(ct2)
}

// stripTypedef follows typedef links to the named data-type.
func stripTypedef(ct Datatype) Datatype {
	for {
		td, ok := ct.(interface{ Typedef() Datatype })
		if !ok || td.Typedef() == nil {
			return ct
		}
		ct = td.Typedef()
	}
}

// tryResolutionAdjustment removes the need for a cast between an input and
// the output of op by resolving a union (or single-component) data-type on
// either side to a compatible form.
// C++ parity: ActionSetCasts::tryResolutionAdjustment.
func tryResolutionAdjustment(op *PcodeOp, slot int, data *Funcdata) bool {
	outvn := op.Output()
	if outvn == nil || outvn.High() == nil || op.Input(slot).High() == nil {
		return false
	}
	outType := outvn.High().Type()
	inType := op.Input(slot).High().Type()
	if outType == nil || inType == nil || (!inType.NeedsResolution() && !outType.NeedsResolution()) {
		return false
	}
	inResolve, outResolve := -1, -1
	if inType.NeedsResolution() {
		if inResolve = findCompatibleResolve(inType, outType); inResolve < 0 {
			return false
		}
	}
	if outType.NeedsResolution() {
		if inResolve >= 0 {
			outResolve = findCompatibleResolve(outType, datatypeDepend(inType, inResolve))
		} else {
			outResolve = findCompatibleResolve(outType, inType)
		}
		if outResolve < 0 {
			return false
		}
	}
	if inType.NeedsResolution() && !data.setUnionField(inType, op, slot, newResolvedField(inType, inResolve, sharedTypeFactory)) {
		return false
	}
	if outType.NeedsResolution() && !data.setUnionField(outType, op, -1, newResolvedField(outType, outResolve, sharedTypeFactory)) {
		return false
	}
	return true
}

// resolveUnion settles the union field the input at slot reads: a pointer
// to a union gets a PTRSUB #0 naming the field, an implied value is marked
// to print the field.
// C++ parity: ActionSetCasts::resolveUnion.
func (a *ActionSetCasts) resolveUnion(op *PcodeOp, slot int, data *Funcdata, cs *CastStrategyC) int {
	vn := op.Input(slot)
	if vn == nil || vn.IsAnnotation() || vn.High() == nil {
		return 0
	}
	dt := vn.High().Type()
	if dt == nil || !dt.NeedsResolution() {
		return 0
	}
	if dt != vn.Type() {
		resolveInFlow(dt, op, slot) // Last chance to resolve data-type based on flow
	}
	resUnion := data.getUnionField(dt, op, slot)
	if resUnion == nil || resUnion.fieldNum < 0 {
		return 0
	}
	if dt.Metatype() == TYPE_PTR {
		// Test if a cast is still needed even after resolution
		reqtype := vn.TypeReadFacing(op)
		if cs.CastStandard(reqtype, resUnion.resolve, true, true) != nil {
			return 0 // If cast still needed, don't do the resolve
		}
		// Insert specific placeholder indicating which field is accessed
		ptrsub := insertPtrsubZero(op, slot, reqtype, data)
		data.setUnionField(dt, ptrsub, -1, *resUnion) // Attach the resolution to the PTRSUB
	} else if vn.IsImplied() {
		if vn.IsWritten() {
			// Identical write- and read-facing resolutions: treat vn as having
			// the field data-type, no implied field to print
			if writeRes := data.getUnionField(dt, vn.Def(), -1); writeRes != nil && writeRes.fieldNum == resUnion.fieldNum {
				return 0
			}
		}
		vn.SetAddlFlags(VarnodeHasImpliedField)
	}
	return 1
}

// castOutput inserts a CAST after op when the type a C compiler assigns to the
// op's output expression differs from the output Varnode's type. C++ parity:
// ActionSetCasts::castOutput (coreaction.cc 2534-2618).
func (a *ActionSetCasts) castOutput(op *PcodeOp, data *Funcdata, cs *CastStrategyC) int {
	tokenct := op.GetOpcode().GetOutputToken(op, cs)
	outvn := op.Output()
	outHighType := outvn.HighTypeDefFacing()
	if hv := outvn.High(); hv != nil && hv.Type() != nil {
		outHighType = hv.Type()
	}
	if tokenct == outHighType {
		if tokenct != nil && tokenct.NeedsResolution() {
			// The operation copies directly to outvn AS a union
			data.setUnionField(tokenct, op, -1, newResolvedSelf(tokenct))
		}
		return 0 // same type, no cast
	}
	outHighResolve := outHighType
	if outHighType != nil && outHighType.NeedsResolution() {
		if outHighType != outvn.Type() {
			resolveInFlow(outHighType, op, -1) // Last chance to resolve data-type based on flow
		}
		outHighResolve = findResolve(outHighType, op, -1) // Finish fetching DefFacing data-type
	}
	force := false
	if outvn.IsImplied() {
		// Implied varnode must take on the parse (token) type for atomic types,
		// or for pointers that do not point to a composite.
		if outvn.IsTypeLock() {
			// The Varnode input to a RETURN is marked as implied but casting
			// should act as if it were explicit.
			if outOp := outvn.LoneDescend(); outOp == nil || outOp.Code() != CPUI_RETURN {
				force = !isOpIdentical(outHighResolve, tokenct)
			}
		} else if outHighResolve == nil || outHighResolve.Metatype() != TYPE_PTR {
			outvn.UpdateType(tokenct)
			outHighResolve = outvn.HighTypeDefFacing()
		} else if tokenct != nil && tokenct.Metatype() == TYPE_PTR {
			if ptr, ok := outHighResolve.(*Pointer); ok && ptr.Pointee() != nil {
				meta := ptr.Pointee().Metatype()
				if meta != TYPE_ARRAY && meta != TYPE_STRUCT && meta != TYPE_UNION {
					outvn.UpdateType(tokenct)
					outHighResolve = outvn.HighTypeDefFacing()
				}
			}
		}
	}
	opc := CPUI_CAST
	if !force {
		if outHighResolve != nil && outHighResolve.Metatype() == TYPE_PTR && testStructOffset0(outHighResolve, tokenct, cs) {
			opc = CPUI_PTRSUB
		} else if cs.CastStandard(outHighResolve, tokenct, false, true) == nil {
			return 0
		}
	}
	// Generate the cast op: op now writes a fresh implied unique, and the CAST
	// produces the original output Varnode from it.
	vn := data.NewUnique(outvn.Size())
	vn.UpdateType(tokenct)
	vn.SetImplied()
	nin := 1
	if opc != CPUI_CAST {
		nin = 2
	}
	newop := data.NewOp(nin, op.Addr())
	data.OpSetOpcode(newop, opc)
	data.OpSetOutput(newop, outvn)
	data.OpSetInput(newop, vn, 0)
	if opc != CPUI_CAST {
		data.OpSetInput(newop, data.NewConstant(4, 0), 1)
	}
	data.OpSetOutput(op, vn)
	data.OpInsertAfter(newop, op) // cast comes AFTER the operation
	if tokenct != nil && tokenct.NeedsResolution() {
		data.forceFacingType(tokenct, -1, newop, 0)
	}
	if outHighType != nil && outHighType.NeedsResolution() {
		data.inheritResolution(outHighType, newop, -1, op, -1) // Inherit write resolution
	}
	return 1
}

// testStructOffset0 reports whether a pointer to a structure (or array) can
// stand for a pointer to its first field (element) of the required type, so a
// PTRSUB(vn,#0) replaces the cast.
// C++ parity: ActionSetCasts::testStructOffset0.
func testStructOffset0(reqtype, curtype Datatype, cs *CastStrategyC) bool {
	curPtr, ok := curtype.(*Pointer)
	reqPtr, rok := reqtype.(*Pointer)
	if !ok || !rok || curPtr.Pointee() == nil || reqPtr.Pointee() == nil {
		return false
	}
	var req, cur Datatype
	switch high := curPtr.Pointee().(type) {
	case *Struct:
		fields := high.Fields()
		if len(fields) == 0 || fields[0].Offset != 0 || fields[0].Type == nil {
			return false
		}
		req, cur = reqPtr.Pointee(), fields[0].Type
		if arr, ok := req.(*Array); ok {
			req = arr.Element()
		}
		if arr, ok := cur.(*Array); ok {
			cur = arr.Element()
		}
	case *Array:
		req, cur = reqPtr.Pointee(), high.Element()
	default:
		return false
	}
	if req == nil || cur == nil || req.Metatype() == TYPE_VOID {
		return false // Don't induce PTRSUB for "void *"
	}
	return cs.CastStandard(req, cur, true, true) == nil
}

// insertPtrsubZero makes input slot of op a PTRSUB(vn,#0) of type ct.
// C++ parity: ActionSetCasts::insertPtrsubZero.
func insertPtrsubZero(op *PcodeOp, slot int, ct Datatype, data *Funcdata) *PcodeOp {
	vn := op.Input(slot)
	newop := data.NewOp(2, op.Addr())
	vnout := data.NewUniqueOut(vn.Size(), newop)
	vnout.UpdateType(ct)
	vnout.SetImplied()
	data.OpSetOpcode(newop, CPUI_PTRSUB)
	data.OpSetInput(newop, vn, 0)
	data.OpSetInput(newop, data.NewConstant(4, 0), 1)
	data.OpSetInput(op, vnout, slot)
	data.OpInsertBefore(newop, op)
	return newop
}
