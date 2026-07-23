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

	// Collect used stack trials whose Varnode is not already a named parameter.
	type missingParam struct {
		vn  *Varnode
		off uint64
	}
	var miss []missingParam
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if !pt.IsUsed() || pt.IsUnref() {
			continue
		}
		addr := pt.GetAddress()
		if addr.Space == nil || addr.Space.Kind != address.SpaceKindStack {
			continue
		}
		slot := int(pt.GetSlot()) - 1
		if slot < 0 || slot >= len(triallist) {
			continue
		}
		vn := triallist[slot]
		if vn == nil || isAlreadyNamedParam(vn) {
			continue
		}
		miss = append(miss, missingParam{vn, addr.Offset})
	}
	if len(miss) == 0 {
		return
	}
	// Number the missing stack parameters after the already-recovered params,
	// ascending by stack offset (ABI order). C++ parity: stack pentry is the last
	// group, so its slots follow every register parameter, low offset first.
	sort.Slice(miss, func(i, j int) bool { return miss[i].off < miss[j].off })
	base := fp.NumParams()
	for i, m := range miss {
		name := GetParamName(base + i)
		hv := m.vn.High()
		if hv != nil {
			// Reuse the merged HighVariable so the value's SSA instances stay
			// intact; only stamp the formal parameter name onto it.
			hv.SetName(name)
		} else {
			hv = NewHighVariable(name)
			hv.AddInstance(m.vn)
		}
		sl.registerStackParam(m.vn, hv)
		fp.AddParam(hv)
	}
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
