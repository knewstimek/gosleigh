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
	"sort"
	"strings"

	"gosleigh/pkg/address"
)

// recoverMissingStackParams recovers formal stack input parameters that the main
// loop's ActionActiveParam could not see because it locked the prototype before
// ActionSpacebase materialized the stack varnode. It uses the faithful
// ParamListStandard input map (ParamEntry / findEntry / fillinMap) to classify
// the final input-def Varnodes, then adds any used stack parameter that is not
// already named as a formal parameter.
//
// The register parameters (and stack parameters that were already visible in the
// main loop) are left untouched: this pass is strictly additive for the stack
// inputs the main loop missed. Register/stack "hole" (unref) trials are computed
// by fillinMap but not materialized here -- creating new input Varnodes after the
// merge phase is out of scope for this slice.
//
// C++ parity: ActionInputPrototype::apply (coreaction.cc:4718) trial
// registration -> deriveInputMap (ParamListStandard::fillinMap) -> formal input
// assignment (updateInputTypes), restricted to the stack inputs.
func recoverMissingStackParams(data *Funcdata, fp *FuncProto) {
	if data == nil || fp == nil {
		return
	}
	model := fp.Model()
	if model == nil || model.InputParams == nil {
		return
	}
	sl := data.GetScopeLocal()
	if sl == nil {
		return
	}

	// Register a trial for every input Varnode at a possible parameter location,
	// in address order, tracking the backing Varnode per registration slot.
	// C++ parity: coreaction.cc:4728-4741.
	active := NewParamActive(false)
	var triallist []*Varnode
	for _, vn := range inputVarnodesInAddrOrder(data) {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if !model.InputParams.possibleParam(vn.Addr(), vn.Size()) {
			continue
		}
		slot := active.NumTrials()
		active.RegisterTrial(vn.Addr(), vn.Size())
		if vn.NumDescend() > 0 {
			active.Trial(slot).MarkActive()
		}
		triallist = append(triallist, vn)
	}
	if active.NumTrials() == 0 {
		return
	}
	model.InputParams.FillinMap(active)

	// Create the unreferenced register inputs fillinMap kept (a __fastcall
	// ECX hole before a used EDX). C++ frees them again in clearDeadVarnodes
	// but keeps their parameter symbol; Gosleigh's signature is read from
	// input Varnodes, so the Varnode is kept alive as a locked input instead.
	// C++ parity: ActionInputPrototype::apply (unref trial creation).
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if !pt.IsUnref() || !pt.IsUsed() {
			continue
		}
		if data.hasInputIntersection(pt.GetSize(), pt.GetAddress()) {
			pt.MarkNoUse()
			continue
		}
		if pt.GetAddress().Space == nil {
			continue
		}
		vn := data.SetInputVarnode(data.NewVarnode(pt.GetSize(), pt.GetAddress()))
		vn.SetAddlFlags(VarnodeLockedInput)
		// Nothing reads the hole, so it keeps the undefined type of its size.
		SetVarnodeType(vn, sharedTypeFactory.GetBase(pt.GetSize(), TYPE_UNKNOWN, ""))
		triallist = append(triallist, vn)
		pt.SetSlot(int32(len(triallist)))
	}

	// The main loop named its parameters before the stack inputs settled; an
	// input fillinMap rejects (an active slot after a chain of inactive ones)
	// is no parameter after all, just an irregular input.
	// C++ parity: ActionInputPrototype::apply derives the inputs only here.
	if !fp.hostInputLocked {
		for i := 0; i < active.NumTrials(); i++ {
			pt := active.Trial(i)
			slot := int(pt.GetSlot()) - 1
			if pt.IsUsed() || slot < 0 || slot >= len(triallist) {
				continue
			}
			vn := triallist[slot]
			if !isAlreadyNamedParam(vn) {
				continue
			}
			hv := vn.High()
			fp.removeParam(hv)
			delete(sl.paramByVn, vn)
			hv.SetName("")
		}
	}

	// A parameter's index is its position among the used trials, which
	// fillinMap left sorted in ABI order (register groups, then stack).
	// C++ parity: FuncProto::updateInputTypes.
	pos := 0
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if !pt.IsUsed() {
			continue
		}
		name := GetParamName(pos)
		pos++
		slot := int(pt.GetSlot()) - 1
		if slot < 0 || slot >= len(triallist) {
			continue
		}
		vn := triallist[slot]
		if vn == nil || isAlreadyNamedParam(vn) {
			continue
		}
		// A locked host prototype names and types the parameter at this
		// storage. C++ parity: updateInputNoTypes keeps the locked
		// ProtoParameters of an input-locked prototype.
		if vn.Space().Kind == address.SpaceKindStack {
			if t, typed := sl.ext().hostLocalTypes[vn.Offset()]; typed {
				if n := sl.ext().hostLocals[vn.Offset()]; n != "" {
					name = n
				}
				if t.Size() == vn.Size() {
					SetVarnodeType(vn, t)
					vn.SetFlags(VarnodeTypeLock)
				}
			}
		} else if pn, nlock, _, found := fp.LockedParamName(vn.Offset()); found && nlock {
			name = pn
		}
		hv := vn.High()
		if hv != nil {
			// Reuse the merged HighVariable so the value's SSA instances stay
			// intact; only stamp the formal parameter name onto it.
			hv.SetName(name)
		} else {
			hv = NewHighVariable(name)
			hv.AddInstance(vn)
		}
		if vn.Space().Kind == address.SpaceKindStack {
			sl.registerStackParam(vn, hv)
		} else {
			sl.paramByVn[vn] = hv
		}
		fp.AddParam(hv)
	}
}

// hasInputIntersection reports whether an input Varnode overlaps the range.
// C++ parity: VarnodeBank::hasInputIntersection.
func (fd *Funcdata) hasInputIntersection(sz int32, addr address.Address) bool {
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn != nil && vn.IsInput() && vn.IntersectsAddr(addr, sz) {
			return true
		}
	}
	return false
}

// inputVarnodesInAddrOrder returns the function's input Varnodes sorted by
// (space index, offset), mirroring the C++ VarnodeDefSet iteration order used by
// data.beginDef(Varnode::input). Deterministic ordering keeps trial-slot
// assignment stable across runs.
func inputVarnodesInAddrOrder(data *Funcdata) []*Varnode {
	var ins []*Varnode
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || !vn.IsInput() || vn.Space() == nil {
			continue
		}
		ins = append(ins, vn)
	}
	sort.SliceStable(ins, func(i, j int) bool {
		a, b := ins[i], ins[j]
		if a.Space().Index != b.Space().Index {
			return a.Space().Index < b.Space().Index
		}
		if a.Offset() != b.Offset() {
			return a.Offset() < b.Offset()
		}
		return a.Size() < b.Size()
	})
	return ins
}

// isAlreadyNamedParam reports whether the Varnode's HighVariable already carries
// a formal parameter name (param_N), meaning the main loop already recovered it.
func isAlreadyNamedParam(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	hv := vn.High()
	if hv == nil {
		return false
	}
	return strings.HasPrefix(hv.Name(), "param_")
}

// demoteUnlockedParams unnames every provisional parameter of a prototype the
// host locked that no locked parameter covers: the locked list is the whole
// signature, so such an input is irregular (in_R8).
// C++ parity: a locked FuncProto is never re-derived from the inputs.
func demoteUnlockedParams(data *Funcdata, fp *FuncProto) {
	if !fp.hostInputLocked {
		return
	}
	sl := data.GetScopeLocal()
	for _, vn := range inputVarnodesInAddrOrder(data) {
		if !isAlreadyNamedParam(vn) || fp.selfLockedCovers(vn) {
			continue
		}
		hv := vn.High()
		fp.removeParam(hv)
		if sl != nil {
			delete(sl.paramByVn, vn)
		}
		hv.SetName("")
	}
}
