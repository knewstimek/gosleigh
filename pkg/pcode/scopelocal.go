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

	"gosleigh/pkg/address"
)

// stackSpaceKind returns the SpaceKind used for stack address spaces.
func stackSpaceKind() address.SpaceKind { return address.SpaceKindStack }

// ScopeLocal manages the mapping from low-level Varnodes to named high-level
// symbols (parameters and locals) within a single function scope.
//
// C++ parity: funcdata.hh ScopeLocal (partial)
type ScopeLocal struct {
	model *ProtoModel

	// paramByVn maps a stack input varnode to its HighVariable.
	paramByVn map[*Varnode]*HighVariable
	// localByVn maps a stack local varnode to its HighVariable.
	localByVn map[*Varnode]*HighVariable
}

// NewScopeLocal creates an empty ScopeLocal for the given calling convention.
// C++ parity: ScopeLocal::ScopeLocal
func NewScopeLocal(model *ProtoModel) *ScopeLocal {
	return &ScopeLocal{
		model:     model,
		paramByVn: make(map[*Varnode]*HighVariable),
		localByVn: make(map[*Varnode]*HighVariable),
	}
}

// ResetLocalWindow clears all symbol assignments.
// C++ parity: ScopeLocal::resetLocalWindow
func (sl *ScopeLocal) ResetLocalWindow() {
	if sl == nil {
		return
	}
	sl.paramByVn = make(map[*Varnode]*HighVariable)
	sl.localByVn = make(map[*Varnode]*HighVariable)
}

// BuildFromVarnodes scans all varnodes, classifies stack-space ones as params
// or locals, creates HighVariables for each, and populates both ScopeLocal and
// FuncProto.
//
// Naming convention:
//   - Parameters: small positive offsets (>= paramBaseOffset) -> param_0, param_1, ...
//     sorted ascending by offset.
//   - Locals: large unsigned offsets (>= 0x80000000, negative frame offsets) ->
//     local_0, local_1, ... sorted descending by offset (0xfffffffc = local_0,
//     0xfffffff8 = local_1, etc. matching Ghidra's frame layout).
//
// C++ parity: ScopeLocal::buildFromVarnodes / ScopeLocal::restructureHigh
func (sl *ScopeLocal) BuildFromVarnodes(varnodes []*Varnode, fp *FuncProto) {
	if sl == nil || sl.model == nil {
		return
	}

	// Collect stack-space varnodes that are input (params) or written (locals).
	var paramEntries []stackEntry
	var localEntries []stackEntry

	for _, vn := range varnodes {
		if vn == nil || vn.Space() == nil {
			continue
		}
		// Only examine stack-space varnodes.
		if !isStackSpace(vn, sl.model) {
			continue
		}
		if sl.model.IsParamOffset(vn.Offset()) {
			// Input varnodes in the param range are parameters.
			// Also accept written varnodes in the param range -- after Heritage,
			// stack params often appear as both input and written.
			paramEntries = append(paramEntries, stackEntry{vn, vn.Offset()})
		} else if sl.model.IsLocalOffset(vn.Offset()) {
			localEntries = append(localEntries, stackEntry{vn, vn.Offset()})
		}
	}

	// Deduplicate by offset: keep only the first varnode seen per offset
	// (stack varnodes at the same offset are aliases; one name is enough).
	paramEntries = deduplicateByOffset(paramEntries)
	localEntries = deduplicateByOffset(localEntries)

	// Sort params ascending by offset: offset 4 < 8 < 12 -> param_0, param_1, ...
	sort.Slice(paramEntries, func(i, j int) bool {
		return paramEntries[i].offset < paramEntries[j].offset
	})

	// Sort locals descending by offset: 0xfffffffc > 0xfffffff8 -> local_0, local_1, ...
	// This matches Ghidra's frame layout where the first local below EBP is local_0.
	sort.Slice(localEntries, func(i, j int) bool {
		return localEntries[i].offset > localEntries[j].offset
	})

	// Create HighVariables for params.
	for i, e := range paramEntries {
		name := GetParamName(i)
		hv := NewHighVariable(name)
		hv.AddInstance(e.vn)
		sl.paramByVn[e.vn] = hv
		if fp != nil {
			fp.AddParam(hv)
		}
	}

	// Create HighVariables for locals.
	for i, e := range localEntries {
		name := GetLocalName(i)
		hv := NewHighVariable(name)
		hv.AddInstance(e.vn)
		sl.localByVn[e.vn] = hv
		if fp != nil {
			fp.AddLocal(hv)
		}
	}
}

// FindEntry returns the HighVariable associated with the given varnode, if any.
// C++ parity: ScopeLocal::findEntry
func (sl *ScopeLocal) FindEntry(vn *Varnode) *HighVariable {
	if sl == nil || vn == nil {
		return nil
	}
	if hv, ok := sl.paramByVn[vn]; ok {
		return hv
	}
	if hv, ok := sl.localByVn[vn]; ok {
		return hv
	}
	return nil
}

// isStackSpace reports whether vn lives in the stack address space according
// to model. Uses SpaceKindStack kind or name=="stack" as fallback.
// C++ parity: Varnode::getSpaceFromConst / ScopeLocal::buildFromVarnodes
func isStackSpace(vn *Varnode, model *ProtoModel) bool {
	if vn == nil || vn.Space() == nil {
		return false
	}
	if model.StackSpace != nil {
		// Exact pointer match first.
		if vn.Space() == model.StackSpace {
			return true
		}
		// Name match as secondary (different pointer to same logical space).
		if vn.Space().Name == model.StackSpace.Name && model.StackSpace.Name != "" {
			return true
		}
	}
	// Fallback: match by SpaceKind or name.
	if vn.Space().Kind == stackSpaceKind() {
		return true
	}
	return vn.Space().Name == "stack"
}

// deduplicateByOffset removes duplicate stack entries that share the same offset.
// The first entry at each offset is kept (arbitrary but deterministic).
func deduplicateByOffset(entries []stackEntry) []stackEntry {
	if len(entries) == 0 {
		return entries
	}
	seen := make(map[uint64]struct{}, len(entries))
	out := entries[:0]
	for _, e := range entries {
		if _, exists := seen[e.offset]; exists {
			continue
		}
		seen[e.offset] = struct{}{}
		out = append(out, e)
	}
	return out
}

// stackEntry is a local helper type used in BuildFromVarnodes.
type stackEntry struct {
	vn     *Varnode
	offset uint64
}
