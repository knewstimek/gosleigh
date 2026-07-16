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

// This file ports the call-site return-value ("output") recovery machinery from
// Ghidra's FuncCallSpecs. When a CALL/CALLIND has an active output ParamActive,
// heritage seeds INDIRECT-creation ops for the caller-saved registers the call
// clobbers (Heritage::guardCalls). ActionActiveReturn then decides which of
// those indirectly-created varnodes is the call's real return value and moves it
// to be the CALL op's output, destroying the placeholder INDIRECT.
//
// The single-register path (one active output trial) is the faithful port used
// by the x64 indirect-call return carrier (a demoted BRANCHIND that returns in
// RAX). The two-register/join path (double-precision returns) is not yet ported;
// leaving it a no-op reproduces the pre-port behavior (no output recovered) so
// no existing result regresses.
//
// C++ parity: fspec.cc FuncCallSpecs::{collectOutputTrialVarnodes,
// checkOutputTrialUse,buildOutputFromTrials}, fspec.hh deriveOutputMap/
// characterizeAsOutput, coreaction.cc ActionActiveReturn::apply.

// IsOutputActive reports whether return-value recovery is active for this call.
// Ghidra stores an explicit isoutputactive flag; Gosleigh models the same state
// as the presence of the (call-local) active-output ParamActive that
// InitActiveOutput installs and ClearActiveOutput removes.
// C++ parity: FuncCallSpecs::isOutputActive (fspec.hh:1700).
func (fc *FuncCallSpecs) IsOutputActive() bool {
	return fc != nil && fc.GetActiveOutput() != nil
}

// CharacterizeAsOutput classifies how the storage range [addr,addr+size) relates
// to this call's single integer return register (the model's ReturnReg*). This
// is the register-space subset of FuncProto::characterizeAsOutput, matching the
// containment classes used by Heritage.characterizeReturnOutput for the
// function's own return. Gosleigh has not ported the ParamEntry output model, so
// only the one configured return register participates.
// C++ parity: fspec.cc FuncProto::characterizeAsOutput (register subset).
func (fc *FuncCallSpecs) CharacterizeAsOutput(addr address.Address, size int32) int {
	m := fc.Model()
	if m == nil || m.ReturnRegSpaceIndex < 0 || m.ReturnRegSize == 0 {
		return retOutNoContainment
	}
	if addr.Space == nil || int(addr.Space.Index) != m.ReturnRegSpaceIndex {
		return retOutNoContainment
	}
	qStart := addr.Offset
	qEnd := addr.Offset + uint64(size)
	oStart := m.ReturnRegOffset
	oEnd := m.ReturnRegOffset + uint64(m.ReturnRegSize)
	if qEnd <= oStart || oEnd <= qStart {
		return retOutNoContainment
	}
	if qStart <= oStart && oEnd <= qEnd && size > m.ReturnRegSize {
		return retOutContainedBy
	}
	return retOutOther
}

// collectOutputTrialVarnodes returns the trial-indexed Varnodes for this call's
// active output: for each output trial, the INDIRECT-creation output Varnode at
// the trial's storage, or nil if no such varnode survives. Ghidra walks the ops
// immediately preceding the CALL (previousOp); Gosleigh's PcodeOp.previousOp is
// not linked, so we instead identify the call's INDIRECT-creation ops by their
// IOP cause reference (input(1) -> GetIndirectCause == this call).
// C++ parity: fspec.cc FuncCallSpecs::collectOutputTrialVarnodes.
func (fc *FuncCallSpecs) collectOutputTrialVarnodes(data *Funcdata) []*Varnode {
	active := fc.GetActiveOutput()
	trialvn := make([]*Varnode, active.NumTrials())
	for _, indop := range data.GetPcodeOpBank().AllOps() {
		if indop == nil || indop.IsDead() {
			continue
		}
		if indop.Code() != CPUI_INDIRECT || !indop.IsIndirectCreation() {
			continue
		}
		cause := indop.Input(1)
		if cause == nil || cause.GetIndirectCause() != fc.op {
			continue
		}
		vn := indop.Output()
		if vn == nil {
			continue
		}
		index := active.WhichTrial(vn.Addr(), vn.Size())
		if index >= 0 {
			trialvn[index] = vn
		}
	}
	return trialvn
}

// checkOutputTrialUse marks each output trial active or inactive depending on
// whether its INDIRECT-creation varnode survived data-flow/deadcode analysis.
// C++ parity: fspec.cc FuncCallSpecs::checkOutputTrialUse.
func (fc *FuncCallSpecs) checkOutputTrialUse(data *Funcdata) []*Varnode {
	active := fc.GetActiveOutput()
	trialvn := fc.collectOutputTrialVarnodes(data)
	for i := 0; i < len(trialvn); i++ {
		curtrial := active.Trial(i)
		if curtrial == nil {
			continue
		}
		if trialvn[i] != nil {
			curtrial.MarkActive()
		} else {
			// Not markNoUse: the value may be returned but simply unused here.
			curtrial.MarkInactive()
		}
	}
	return trialvn
}

// deriveOutputMap marks the active output trials that fit the model's return
// storage as \e used. Ghidra delegates to output->fillinMap (the ParamList
// output model). Gosleigh has not ported the ParamEntry output model, so this
// mirrors the register-subset outcome: an active trial that characterizes as the
// return register is used; everything else is not.
// C++ parity: fspec.hh FuncProto::deriveOutputMap -> ParamListStandardOut::fillinMap.
func (fc *FuncCallSpecs) deriveOutputMap() {
	active := fc.GetActiveOutput()
	if active.NumTrials() == 0 {
		return
	}
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		if trial == nil {
			continue
		}
		if trial.IsActive() && fc.CharacterizeAsOutput(trial.GetAddress(), trial.GetSize()) == retOutOther {
			trial.MarkUsed()
		} else {
			trial.MarkNoUse()
		}
	}
	active.SortTrials()
}

// buildOutputFromTrials moves this call's recovered return value into place: the
// single used output trial's Varnode becomes the CALL op's output, and the
// placeholder INDIRECT-creation op that defined it is destroyed.
// C++ parity: fspec.cc FuncCallSpecs::buildOutputFromTrials (single-trial path).
func (fc *FuncCallSpecs) buildOutputFromTrials(data *Funcdata, trialvn []*Varnode) {
	active := fc.GetActiveOutput()
	var finalvn []*Varnode
	for i := 0; i < active.NumTrials(); i++ {
		curtrial := active.Trial(i)
		if curtrial == nil || !curtrial.IsUsed() {
			break
		}
		slot := int(curtrial.GetSlot()) - 1
		if slot < 0 || slot >= len(trialvn) {
			break
		}
		finalvn = append(finalvn, trialvn[slot])
	}
	active.DeleteUnusedTrials() // deletes unused, renumbers used to match finalvn
	if active.NumTrials() == 0 {
		return // Nothing is a formal output
	}

	var deletedops []*PcodeOp
	if active.NumTrials() == 1 { // A single, properly justified output
		finaloutvn := finalvn[0]
		if finaloutvn == nil {
			return
		}
		deletedops = append(deletedops, finaloutvn.Def())
		data.OpSetOutput(fc.op, finaloutvn) // move varnode to be the call output
	} else {
		// TODO known mismatch: the two-trial join path (double-precision returns,
		// findPreexistingWhole + constructJoinAddress) is not yet ported. Leaving
		// the output unrecovered reproduces the pre-port behavior for such calls.
		return
	}

	for _, dop := range deletedops { // destroy the original INDIRECT ops
		if dop == nil {
			continue
		}
		in0 := dop.Input(0)
		in1 := dop.Input(1)
		data.OpDestroy(dop)
		if in0 != nil {
			data.DeleteVarnode(in0)
		}
		if in1 != nil {
			data.DeleteVarnode(in1)
		}
	}
}
