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

import "gosleigh/pkg/address"

// This file ports the call-site input ("parameter") recovery machinery from
// Ghidra's FuncCallSpecs. It is the mirror image of funccallspec_output.go:
//
//	Heritage::guardCalls registers one input trial per heritaged storage range
//	that the prototype model says could carry a parameter, and appends a fresh
//	Varnode at that storage as an extra CALL input so the renaming pass wires it
//	to the reaching definition. ActionActiveParam then decides which of those
//	speculative inputs are real (checkInputTrialUse), lets the ParamList pick the
//	formal map (deriveInputMap -> ParamListStandard::fillinMap), and rewrites the
//	CALL's input list to exactly the surviving parameters (buildInputFromTrials).
//
// C++ parity: fspec.cc FuncCallSpecs::{checkInputTrialUse,finalInputCheck,
// buildInputFromTrials}, FuncProto::{characterizeAsInputParam,resolveModel,
// deriveInputMap}, heritage.cc Heritage::guardCalls (1495-1508),
// coreaction.cc ActionActiveParam::apply (1726-1772).

// trimRecurseMax caps the ancestor recursion in ancestorOpUse.
// C++ parity: Architecture::trim_recurse_max = 5 (architecture.cc:1419).
const trimRecurseMax = 5

// spacebaseOffsetUnknown is the "magic" stack offset meaning the stack-pointer
// offset at a call site has not been resolved.
// C++ parity: FuncCallSpecs::offset_unknown (fspec.hh:1677).
const spacebaseOffsetUnknown = uint64(0xBADBEEF)

// GetSpacebaseOffset returns the stack-pointer offset at this call site,
// relative to the caller's spacebase origin.
//
// TODO known mismatch: Gosleigh does not run the stack-placeholder resolution
// (FuncCallSpecs::resolveSpacebaseRelative) -- Funcdata.NewSpacebasePtr has no
// registered spacebase register for the x64 stack space, so ActionFuncLink's
// createPlaceholder never materializes a placeholder LOAD to read the offset
// from. Reporting offset_unknown takes exactly the C++ branch for that state:
// Heritage::guardCalls sets tryregister=false and registers no stack trial, so
// a stack-passed argument stays unrecovered instead of being registered at a
// wrong (untranslated) callee-relative address.
// C++ parity: FuncCallSpecs::getSpacebaseOffset (fspec.hh:1689).
func (fc *FuncCallSpecs) GetSpacebaseOffset() uint64 {
	return spacebaseOffsetUnknown
}

// ClearActiveInput turns off input-parameter recovery for this call.
// C++ parity: FuncCallSpecs::clearActiveInput (fspec.hh:1696).
func (fc *FuncCallSpecs) ClearActiveInput() {
	if fc == nil {
		return
	}
	fc.setActiveInputState(nil)
}

// CharacterizeAsInputParam classifies how the storage range [addr,addr+size)
// relates to this prototype's input parameters.
//
// The C++ routine first tests the locked ProtoParameter list and only falls
// through to the model when no parameter is type-locked. Gosleigh's FuncProto
// records parameters as HighVariables without the ProtoParameter storage /
// typelock pair, and call-site prototypes are never input-locked (ActionFuncLink
// only reaches initActiveInput on the unlocked path), so the locked branch is
// unreachable here and the model is authoritative. Porting the locked branch
// needs ProtoParameter storage first.
// C++ parity: fspec.cc FuncProto::characterizeAsInputParam (fspec.cc:4289).
func (fp *FuncProto) CharacterizeAsInputParam(addr address.Address, size int32) int {
	if fp == nil || fp.model == nil || fp.model.InputParams == nil {
		return peNoContainment
	}
	return fp.model.InputParams.characterizeAsParam(addr, size)
}

// DeriveInputMap hands the trials to the model's input ParamList so it can pick
// the formal parameter map (which trials survive, in what order, at what size).
// C++ parity: FuncProto::deriveInputMap -> ParamList::fillinMap (fspec.hh:1420).
func (fp *FuncProto) DeriveInputMap(active *ParamActive) {
	if fp == nil || fp.model == nil || fp.model.InputParams == nil || active == nil {
		return
	}
	fp.model.InputParams.FillinMap(active)
}

// ResolveModel specializes a \e merged prototype model down to a single model
// using the trials. Gosleigh has no ProtoModelMerged, so -- exactly as in C++
// when model->isMerged() is false -- this is a no-op.
// C++ parity: fspec.cc FuncProto::resolveModel (fspec.cc:3767).
func (fp *FuncProto) ResolveModel(_ *ParamActive) {}

// checkInputTrialUse marks each unchecked input trial active/inactive/no-use by
// asking whether a write reached the trial storage with no intervening read
// before the call (AncestorRealistic) and whether the value flowing in is used
// for anything besides this call (ancestorOpUse).
//
// Divergences from C++ (fspec.cc:5585), each forced by an unported dependency:
//   - AliasChecker is not ported, so the hasLocalAlias(vn) rejection for
//     stack-space Varnodes is skipped. Gosleigh registers no stack trials today
//     (GetSpacebaseOffset is unknown), so the branch is only reachable when copy
//     propagation has already replaced a register trial's Varnode with a stack
//     one, where the localRange test below still applies.
//   - callee_pop: FuncProto tracks no extrapop. Every x86/x86-64 model in the
//     corpus declares a concrete extrapop (4 / 8), for which C++ also computes
//     callee_pop == false, so the branch is dead for the ported ABIs.
//
// C++ parity: fspec.cc FuncCallSpecs::checkInputTrialUse.
func (fc *FuncCallSpecs) checkInputTrialUse(data *Funcdata) {
	active := fc.GetActiveInput()
	if active == nil || fc.op == nil || fc.op.IsDead() || data == nil {
		return
	}
	fp := data.GetFuncProto()
	var ar ancestorRealistic
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		if trial.IsChecked() {
			continue
		}
		slot := int(trial.GetSlot())
		if slot < 0 || slot >= fc.op.NumInput() {
			continue
		}
		vn := fc.op.Input(slot)
		if vn == nil || vn.Space() == nil {
			continue
		}
		if vn.Space().Kind == address.SpaceKindStack {
			// C++ rejects a stack Varnode outside the prototype's <localrange>
			// (for x86-64 __fastcall: the negative frame plus the [8,39] shadow
			// band). Gosleigh has no localrange list; IsLocalOffset covers the
			// negative frame and IsParamOffset the non-negative side. The union
			// is deliberately more permissive than C++'s range: rejecting here
			// zeroes the CALL input, so a false reject would destroy a live
			// argument, while a false accept only defers to the ancestor tests.
			switch {
			case fp == nil || fp.Model() == nil ||
				(!fp.Model().IsLocalOffset(vn.Offset()) && !fp.Model().IsParamOffset(vn.Offset())):
				trial.MarkNoUse()
			case ar.execute(fc.op, slot, trial, false):
				if data.ancestorOpUse(trimRecurseMax, vn, fc.op, trial, 0, 0) {
					trial.MarkActive()
				} else {
					trial.MarkInactive()
				}
			default:
				// A stack variable with an unrealistic ancestor is definitely
				// not a parameter.
				trial.MarkNoUse()
			}
		} else {
			switch {
			case ar.execute(fc.op, slot, trial, true):
				if data.ancestorOpUse(trimRecurseMax, vn, fc.op, trial, 0, 0) {
					trial.MarkActive()
					if trial.HasCondExeEffect() {
						active.MarkNeedsFinalCheck()
					}
				} else {
					trial.MarkInactive()
				}
			case vn.IsInput():
				trial.MarkInactive() // not likely a parameter, but maybe
			default:
				// An ancestor is unaffected, an unusual input, or killed by a call.
				trial.MarkNoUse()
			}
		}
		if trial.IsDefinitelyNotUsed() { // free up the dataflow
			data.OpSetInput(fc.op, data.NewConstant(vn.Size(), 0), slot)
		}
	}
}

// finalInputCheck re-tests the trials whose activity could have been changed by
// conditional-execution analysis.
// C++ parity: fspec.cc FuncCallSpecs::finalInputCheck (fspec.cc:5564).
func (fc *FuncCallSpecs) finalInputCheck() {
	active := fc.GetActiveInput()
	if active == nil || fc.op == nil {
		return
	}
	var ar ancestorRealistic
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		if !trial.IsActive() {
			continue
		}
		if !trial.HasCondExeEffect() {
			continue
		}
		slot := int(trial.GetSlot())
		if slot < 0 || slot >= fc.op.NumInput() {
			continue
		}
		if !ar.execute(fc.op, slot, trial, false) {
			trial.MarkNoUse()
		}
	}
}

// buildInputFromTrials rewrites the CALL op's input list to exactly the trials
// the model kept: unused speculative inputs are dropped, oversized Varnodes are
// truncated with a SUBPIECE, and the fspec input (slot 0) is preserved.
//
// TODO known mismatch: the isUnref branch (a parameter the model inferred but
// that has no Varnode) creates the Varnode at the trial address; for a stack
// parameter C++ also calls ScopeLocal::markNotMapped, which Gosleigh has not
// ported. Gosleigh registers no stack trials today, so no unref stack parameter
// can reach that path.
// C++ parity: fspec.cc FuncCallSpecs::buildInputFromTrials (fspec.cc:5685).
func (fc *FuncCallSpecs) buildInputFromTrials(data *Funcdata) {
	active := fc.GetActiveInput()
	if active == nil || fc.op == nil || data == nil {
		return
	}
	op := fc.op
	newparam := []*Varnode{op.Input(0)} // preserve the fspec parameter

	if fc.IsDotdotdot() && fc.IsInputLocked() {
		// Varargs: move the fixed args to the front so the relative order of the
		// variable args is preserved.
		active.SortFixedPosition()
	}

	for i := 0; i < active.NumTrials(); i++ {
		paramtrial := active.Trial(i)
		if !paramtrial.IsUsed() {
			continue // don't keep unused parameters
		}
		sz := paramtrial.GetSize()
		addr := paramtrial.GetAddress()
		spc := addr.Space
		if spc == nil {
			continue
		}
		off := addr.Offset
		isspacebase := spc.Kind == address.SpaceKindStack
		if isspacebase {
			// Translate the parameter address back to the caller's spacebase.
			off += fc.GetSpacebaseOffset()
		}
		var vn *Varnode
		if paramtrial.IsUnref() {
			// A parameter the model recovered that has no Varnode yet.
			vn = data.NewVarnode(sz, address.Address{Space: spc, Offset: off})
		} else {
			slot := int(paramtrial.GetSlot())
			if slot < 0 || slot >= op.NumInput() {
				continue
			}
			vn = op.Input(slot)
			if vn == nil {
				continue
			}
			if vn.Size() > sz { // Varnode is bigger than the parameter type
				truncAddr := vn.Addr()
				if vn.Space() != nil && vn.Space().BigEndian {
					truncAddr = truncAddr.Add(uint64(vn.Size() - sz))
				}
				newop := data.NewOp(2, op.Addr())
				data.OpSetOpcode(newop, CPUI_SUBPIECE)
				outvn := data.NewVarnodeOut(sz, truncAddr, newop)
				data.OpSetInput(newop, vn, 0)
				data.OpSetInput(newop, data.NewConstant(1, 0), 1)
				data.OpInsertBefore(newop, op)
				vn = outvn
			}
		}
		newparam = append(newparam, vn)
	}
	data.OpSetAllInput(op, newparam) // set the final parameter list
	active.DeleteUnusedTrials()
}

// -----------------------------------------------------------------------------
// Funcdata::onlyOpUse / checkCallDoubleUse / ancestorOpUse
// -----------------------------------------------------------------------------

// TraverseNode flag bits describing what a forward traversal crossed.
// C++ parity: expression.hh struct TraverseNode enum (expression.hh:62-68).
const (
	traverseActionAlt   uint32 = 1    // alternate path crossed a solid action / non-incidental COPY
	traverseIndirect    uint32 = 2    // main path crossed an INDIRECT
	traverseIndirectAlt uint32 = 4    // alternate path crossed an INDIRECT
	traverseLsbTrunc    uint32 = 8    // least significant byte(s) truncated away
	traverseConcatHigh  uint32 = 0x10 // value concatenated as the most significant portion
)

// isAlternatePathValid reports whether the alternate path (ending at vn) looks
// more like real parameter passing than the main path.
// C++ parity: expression.cc TraverseNode::isAlternatePathValid (expression.cc:29).
func isAlternatePathValid(vn *Varnode, flags uint32) bool {
	if flags&(traverseIndirect|traverseIndirectAlt) == traverseIndirect {
		return true // main path crossed an INDIRECT, the alternate did not
	}
	if flags&(traverseIndirect|traverseIndirectAlt) == traverseIndirectAlt {
		return false // alternate path crossed an INDIRECT, the main did not
	}
	if flags&traverseActionAlt != 0 {
		return true // alternate path crossed a dedicated COPY
	}
	if vn.LoneDescend() == nil {
		return false
	}
	op := vn.Def()
	if op == nil {
		return true
	}
	for op.IsIncidentalCopy() && op.Code() == CPUI_COPY { // skip incidental COPYs
		vn = op.Input(0)
		if vn == nil || vn.LoneDescend() == nil {
			return false
		}
		op = vn.Def()
		if op == nil {
			return true
		}
	}
	return !op.IsMarker() // MULTIEQUAL or INDIRECT indicates multiple values
}

// traverseNode is one entry of the onlyOpUse worklist.
// C++ parity: expression.hh TraverseNode.
type traverseNode struct {
	vn    *Varnode
	flags uint32
}

// checkCallDoubleUse decides whether a Varnode reaching a second CALL (op) as
// well as the CALL under analysis (opmatch) is still a legitimate parameter for
// opmatch.
//
// TODO known mismatch: the "same callee" shortcut compares FuncCallSpecs entry
// addresses, which Gosleigh does not track (FuncCallSpecs has no entryaddress).
// For a direct CALL we substitute the target Varnode identity (op->getIn(0)),
// which is the same discriminator C++ applies to CALLIND and is exact for the
// direct case as well: two direct CALLs with equal target constants call the
// same function.
// C++ parity: funcdata_varnode.cc Funcdata::checkCallDoubleUse (1775).
func (fd *Funcdata) checkCallDoubleUse(opmatch, op *PcodeOp, vn *Varnode, fl uint32, trial *ParamTrial) bool {
	j := op.GetSlot(vn)
	if j <= 0 {
		return false // flow traces to the indirect call variable, definitely not a param
	}
	fc := fd.callSpecsForOp(op)
	if fc == nil {
		return false
	}
	if op.Code() == opmatch.Code() && op.Input(0) == opmatch.Input(0) {
		// Same callee. Varnode addresses are unreliable here because copy
		// propagation may have run, so compare the trial storage instead.
		if fc.IsInputActive() {
			if curtrial := fc.GetActiveInput().TrialForInputVarnode(j); curtrial != nil {
				if curtrial.GetAddress() == trial.GetAddress() {
					if op.Parent() == opmatch.Parent() {
						if opmatch.Seq().Order < op.Seq().Order {
							return true // opmatch has dibs, don't reject
						}
					} else {
						return true // same function, different blocks: legit double use
					}
				}
			}
		}
	}

	if fc.IsInputActive() {
		curtrial := fc.GetActiveInput().TrialForInputVarnode(j)
		if curtrial == nil {
			return true
		}
		if curtrial.IsChecked() {
			if curtrial.IsActive() {
				return false
			}
		} else if isAlternatePathValid(vn, fl) {
			return false
		}
		return true
	}
	return false
}

// onlyOpUse reports whether the given Varnode appears to be used only as a
// parameter to opmatch. It walks forward through every descendant, treating
// pass-through ops (MULTIEQUAL/SEXT/ZEXT/CAST/PIECE/SUBPIECE/COPY/INDIRECT) as
// continuations and anything else as a disqualifying explicit use.
// C++ parity: funcdata_varnode.cc Funcdata::onlyOpUse (1824).
func (fd *Funcdata) onlyOpUse(invn *Varnode, opmatch *PcodeOp, trial *ParamTrial, mainFlags uint32) bool {
	res := true
	varlist := []traverseNode{{invn, mainFlags}}
	invn.SetMark()

	for i := 0; i < len(varlist); i++ {
		vn := varlist[i].vn
		baseFlags := varlist[i].flags
		for _, op := range vn.DescendIter() {
			if op == nil || op.IsDead() {
				continue
			}
			if op == opmatch {
				slot := int(trial.GetSlot())
				if slot >= 0 && slot < op.NumInput() && op.Input(slot) == vn {
					continue
				}
			}
			curFlags := baseFlags
			switch op.Code() {
			case CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND, CPUI_LOAD, CPUI_STORE:
				res = false
			case CPUI_CALL, CPUI_CALLIND:
				if fd.checkCallDoubleUse(opmatch, op, vn, curFlags, trial) {
					continue
				}
				res = false
			case CPUI_INDIRECT:
				curFlags |= traverseIndirectAlt
			case CPUI_COPY:
				out := op.Output()
				if out != nil && out.Space() != nil && !out.Space().IsUnique() &&
					!op.IsIncidentalCopy() && !vn.IsIncidentalCopy() {
					curFlags |= traverseActionAlt
				}
			case CPUI_RETURN:
				if opmatch.Code() == CPUI_RETURN { // a different RETURN
					slot := int(trial.GetSlot())
					if slot >= 0 && slot < op.NumInput() && op.Input(slot) == vn {
						continue // but at the same slot
					}
				}
				res = false
			case CPUI_MULTIEQUAL, CPUI_INT_SEXT, CPUI_INT_ZEXT, CPUI_CAST:
				// pass through
			case CPUI_PIECE:
				if op.Input(0) == vn { // concatenated as the most significant piece
					if curFlags&traverseLsbTrunc != 0 {
						continue // original lsb truncated and replaced: no longer a use
					}
					curFlags |= traverseConcatHigh
				}
			case CPUI_SUBPIECE:
				if in1 := op.Input(1); in1 != nil && in1.Offset() != 0 {
					if curFlags&traverseConcatHigh == 0 {
						curFlags |= traverseLsbTrunc
					}
				}
			default:
				curFlags |= traverseActionAlt
			}
			if !res {
				break
			}
			subvn := op.Output()
			if subvn != nil {
				if subvn.IsPersist() {
					res = false
					break
				}
				if !subvn.IsMark() {
					varlist = append(varlist, traverseNode{subvn, curFlags})
					subvn.SetMark()
				}
			}
		}
		if !res {
			break
		}
	}
	for _, tn := range varlist {
		tn.vn.ClearMark()
	}
	return res
}

// ancestorOpUse reports whether invn (and the ancestors it was copied from) is
// used only to feed the given CALL/RETURN op.
// C++ parity: funcdata_varnode.cc Funcdata::ancestorOpUse (1936).
func (fd *Funcdata) ancestorOpUse(maxlevel int, invn *Varnode, op *PcodeOp, trial *ParamTrial,
	offset int32, mainFlags uint32) bool {

	if maxlevel == 0 || invn == nil {
		return false
	}
	if !invn.IsWritten() {
		if !invn.IsInput() {
			return false
		}
		if !invn.IsTypeLock() {
			return false
		}
		// A typelocked input is as good as being written.
		return fd.onlyOpUse(invn, op, trial, mainFlags)
	}

	def := invn.Def()
	if def == nil {
		return false
	}
	switch def.Code() {
	case CPUI_INDIRECT:
		// An indirect creation indicates an output trial; that is not an "only use".
		if def.IsIndirectCreation() {
			return false
		}
		return fd.ancestorOpUse(maxlevel-1, def.Input(0), op, trial, offset, mainFlags|traverseIndirect)
	case CPUI_MULTIEQUAL:
		// Check whether any ancestor's only use is in this op. The PcodeOp mark
		// flag is the loop trimmer here, exactly as in C++ (onlyOpUse marks
		// Varnodes, so the two marking schemes do not collide).
		if def.HasFlag(PcodeOpMark) {
			return false // trim the loop
		}
		def.SetFlag(PcodeOpMark)
		for i := 0; i < def.NumInput(); i++ {
			if fd.ancestorOpUse(maxlevel-1, def.Input(i), op, trial, offset, mainFlags) {
				def.ClearFlag(PcodeOpMark)
				return true
			}
		}
		def.ClearFlag(PcodeOpMark)
		return false
	case CPUI_COPY:
		in0 := def.Input(0)
		if invn.Space() != nil && invn.Space().IsUnique() || def.IsIncidentalCopy() ||
			(in0 != nil && in0.IsIncidentalCopy()) {
			return fd.ancestorOpUse(maxlevel-1, in0, op, trial, offset, mainFlags)
		}
	case CPUI_PIECE:
		// Concatenation tends to be artificial, so recurse through the piece
		// corresponding to the later SUBPIECE.
		in1 := def.Input(1)
		if in1 == nil {
			return false
		}
		if offset == 0 {
			return fd.ancestorOpUse(maxlevel-1, in1, op, trial, 0, mainFlags) // least significant piece
		}
		if offset == in1.Size() {
			return fd.ancestorOpUse(maxlevel-1, def.Input(0), op, trial, 0, mainFlags) // most significant piece
		}
		return false
	case CPUI_SUBPIECE:
		in1 := def.Input(1)
		in0 := def.Input(0)
		if in1 == nil || in0 == nil {
			return false
		}
		newOff := int32(in1.Offset())
		// Kludge from C++: a DIV/REM writing the register that looks like the
		// high-precision piece of a return value gets flagged here.
		if newOff == 0 && in0.IsWritten() {
			if remop := in0.Def(); remop != nil &&
				(remop.Code() == CPUI_INT_REM || remop.Code() == CPUI_INT_SREM) {
				trial.SetRemFormed()
			}
		}
		if invn.Space() != nil && invn.Space().IsUnique() || def.IsIncidentalCopy() ||
			in0.IsIncidentalCopy() || int32(invn.Overlap(in0)) == newOff {
			return fd.ancestorOpUse(maxlevel-1, in0, op, trial, offset+newOff, mainFlags)
		}
	case CPUI_CALL, CPUI_CALLIND:
		return false // a call is never a good indication of a single-op use
	}
	// This Varnode must be the top ancestor at this point.
	return fd.onlyOpUse(invn, op, trial, mainFlags)
}
