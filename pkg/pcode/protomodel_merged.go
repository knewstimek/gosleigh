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

import "sort"

// NewMergedModel folds several named models into one that defers the choice
// between them until the function's parameter trials are known (e.g. x86
// "__fastcall/__thiscall/__stdcall"). It carries what the components share:
// the stack space and ranges, the union of register parameter slots for trial
// discovery, the intersection of effects, and an extrapop that is unknown
// unless all agree.
// C++ parity: fspec.cc ProtoModelMerged::foldIn / decode. The input list is
// not rebuilt as a ParamListMerged; possible-parameter queries go to the
// components instead (any component accepting the storage), which is the
// union ParamListMerged::foldIn computes.
func NewMergedModel(name string, models []*ProtoModel) *ProtoModel {
	if len(models) == 0 {
		return nil
	}
	first := models[0]
	m := *first // inherit output/return, stack space, data organization
	m.Name = name
	m.Merged = append([]*ProtoModel(nil), models...)
	m.InputParams = nil
	m.RegParams = nil
	m.RegParamOffsets = make(map[uint64]int)
	m.Effects = append([]EffectRecord(nil), first.Effects...)
	m.StackParamRanges = append([][2]uint64(nil), first.StackParamRanges...)
	for _, mod := range models {
		if mod.ExtraPop != m.ExtraPop {
			m.ExtraPop = ExtrapopUnknown
		}
		for off, idx := range mod.RegParamOffsets {
			if _, ok := m.RegParamOffsets[off]; !ok {
				m.RegParamOffsets[off] = idx
			}
		}
		if mod != first {
			m.Effects = intersectEffects(m.Effects, mod.Effects)
			m.LikelyTrash = intersectLikelyTrash(m.LikelyTrash, mod.LikelyTrash)
			m.StackParamRanges = append(m.StackParamRanges, mod.StackParamRanges...)
		}
	}
	return &m
}

// IsMerged reports a model that must be resolved against parameter trials.
// C++ parity: ProtoModel::isMerged.
func (pm *ProtoModel) IsMerged() bool { return pm != nil && len(pm.Merged) > 0 }

// intersectLikelyTrash keeps the registers present in both sorted lists.
// C++ parity: ProtoModelMerged::intersectLikelyTrash.
func intersectLikelyTrash(a, b []VarnodeData) []VarnodeData {
	var out []VarnodeData
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case VarnodeDataLess(a[i], b[j]):
			i++
		case VarnodeDataLess(b[j], a[i]):
			j++
		default:
			out = append(out, a[i])
			i++
			j++
		}
	}
	return out
}

// intersectEffects keeps the records present (same address, size and type) in
// both sorted lists. C++ parity: ProtoModelMerged::intersectEffects.
func intersectEffects(a, b []EffectRecord) []EffectRecord {
	var out []EffectRecord
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case effectLess(a[i].Addr, b[j].Addr):
			i++
		case effectLess(b[j].Addr, a[i].Addr):
			j++
		default:
			if a[i] == b[j] {
				out = append(out, a[i])
			}
			i++
			j++
		}
	}
	return out
}

// scoreEntry is one trial placed into a model's parameter slots.
type scoreEntry struct {
	origIndex, slot, size int32
}

// scoreProtoModel scores how well a set of input trials fits one model: holes
// in the slot sequence and duplicated slots cost, storage the model cannot
// hold costs most. Lower is better.
// C++ parity: fspec.cc ScoreProtoModel (addParameter / doScore).
func scoreProtoModel(model *ProtoModel, active *ParamActive) int {
	var entries []scoreEntry
	mismatch := 0
	for j := 0; j < active.NumTrials(); j++ {
		trial := active.Trial(j)
		if !trial.IsActive() {
			continue
		}
		var slot, slotsize int32
		ok := false
		if model.InputParams != nil {
			slot, slotsize, ok = model.InputParams.possibleParamWithSlot(trial.GetAddress(), trial.GetSize())
		}
		if ok {
			entries = append(entries, scoreEntry{origIndex: int32(len(entries)), slot: slot, size: slotsize})
		} else {
			mismatch++
		}
	}
	// PEntry::operator< orders by slot only.
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].slot < entries[j].slot })
	penalty := [4]int{16, 10, 7, 5}
	const penaltyfinal = 3
	const mismatchpenalty = 20
	nextfree := int32(0)
	basescore := 0
	for _, p := range entries {
		switch {
		case p.slot > nextfree: // A hole in the slot coverage
			for nextfree < p.slot {
				if nextfree < 4 {
					basescore += penalty[nextfree]
				} else {
					basescore += penaltyfinal
				}
				nextfree++
			}
			nextfree += p.size
		case nextfree > p.slot: // Slot duplication
			basescore += mismatchpenalty
			if p.slot+p.size > nextfree {
				nextfree = p.slot + p.size
			}
		default:
			nextfree = p.slot + p.size
		}
	}
	return basescore + mismatchpenalty*mismatch
}

// resolveFuncModel picks the component of a merged model that best fits the
// function's input Varnodes: each input a component could hold as a parameter
// is a trial, active when it has descendants.
// C++ parity: ActionInputPrototype::apply trial registration (coreaction.cc
// 4728-4741, possibleInputParam on the merged list) + FuncProto::resolveModel.
func resolveFuncModel(fd *Funcdata, merged *ProtoModel) *ProtoModel {
	active := NewParamActive(false)
	for _, vn := range inputVarnodesInAddrOrder(fd) {
		possible := false
		for _, m := range merged.Merged {
			if m.InputParams != nil && m.InputParams.possibleParam(vn.Addr(), vn.Size()) {
				possible = true
				break
			}
		}
		if !possible {
			continue
		}
		active.RegisterTrial(vn.Addr(), vn.Size())
		if vn.NumDescend() > 0 {
			active.Trial(active.NumTrials() - 1).MarkActive()
		}
	}
	return merged.SelectModel(active)
}

// SelectModel returns the component that best fits the active input trials.
// C++ parity: fspec.cc ProtoModelMerged::selectModel (2877-2902).
func (pm *ProtoModel) SelectModel(active *ParamActive) *ProtoModel {
	best, bestscore := (*ProtoModel)(nil), 500
	for _, mod := range pm.Merged {
		if score := scoreProtoModel(mod, active); score < bestscore {
			best, bestscore = mod, score
			if bestscore == 0 {
				break // Can't get any lower
			}
		}
	}
	if best == nil {
		return pm.Merged[0] // C++ throws "No model matches : missing default"
	}
	return best
}
