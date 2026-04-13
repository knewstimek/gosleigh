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
	"fmt"
	"sort"
)

// ActionNameVars assigns human-readable Ghidra-style names to unnamed register-space
// HighVariables (temporaries that are not parameters and have no stack address).
// After ActionMergeCopy all SSA merging is complete, so each HighVariable's final
// type is known and can be used to choose the type prefix (i=int, u=uint/undefined,
// f=float, etc.).
//
// Naming scheme: {typePrefix}Var{N} with N 1-based, per-prefix.
// Examples: iVar1 (signed int), uVar1 (unsigned/undefined), fVar1 (float).
//
// This covers the subset of ScopeLocal::assignDefaultNames that handles
// register-space local variables. Stack locals already receive hex-offset names
// (local_c, local_8) from ScopeLocal::BuildFromVarnodes and are skipped here.
//
// C++ parity: coreaction.cc ActionNameVars::apply(),
//   database.cc ScopeInternal::assignDefaultNames(),
//   database.cc Scope::buildDefaultName() / ScopeInternal::buildVariableName()
type ActionNameVars struct {
	ActionBase
}

var _ Action = (*ActionNameVars)(nil)

func NewActionNameVars(group string) *ActionNameVars {
	act := &ActionNameVars{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "namevars", group)
	return act
}

func (a *ActionNameVars) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionNameVars(a.GetGroup())
}

// hvTypePrefix returns the Ghidra variable name prefix for a HighVariable based
// on its type metatype. Mirrors Datatype::printNameBase() in C++.
// C++ parity: database.cc ScopeInternal::buildVariableName (the local-var branch)
func hvTypePrefix(hv *HighVariable) string {
	if hv == nil {
		return "uVar"
	}
	dt := hv.Type()
	if dt == nil {
		return "uVar"
	}
	switch dt.Metatype() {
	case TYPE_INT:
		if dt.Size() >= 8 {
			return "lVar"
		}
		return "iVar"
	case TYPE_FLOAT:
		return "fVar"
	case TYPE_BOOL:
		return "bVar"
	default:
		// TYPE_UINT, TYPE_UNKNOWN, and others -> uVar (matches undefined* prefix)
		return "uVar"
	}
}

// Apply assigns iVar1/uVar1-style names to unnamed register-space HighVariables.
// Stack locals already have local_hex names from ScopeLocal and are not touched.
// Must be called after ActionMergeCopy so all HV merging is complete.
// C++ parity: ActionNameVars::apply() -> ScopeLocal::assignDefaultNames()
func (a *ActionNameVars) Apply(data *Funcdata) int {
	// Collect unique unnamed register-space HighVariables.
	type hvEntry struct {
		hv        *HighVariable
		prefix    string
		sortKey   uint64 // (offset<<16 | createIndex) for deterministic ordering
		createIdx uint32
		offset    uint64
	}

	// Collect candidate HVs: unnamed HVs that have at least one non-unique,
	// non-input varnode instance. We use two maps to handle the case where
	// the first varnode encountered for an HV is unique-space or input-only:
	// the HV should still be named if a non-unique non-input instance exists.
	//
	// Two-pass approach:
	// 1. Walk all varnodes; for each HV track the "best" (non-unique, non-input) instance.
	// 2. HVs with a valid best instance and no existing name get assigned iVar/uVar names.
	type hvCandidate struct {
		hv        *HighVariable
		bestVn    *Varnode // best representative (non-unique, non-input)
	}
	hvMap := make(map[*HighVariable]*hvCandidate)

	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsConstant() || vn.IsAnnotation() || vn.IsFree() {
			continue
		}
		hv := vn.High()
		if hv == nil {
			continue
		}
		// Skip if already has a human-readable name.
		if hv.Name() != "" {
			if _, ok := hvMap[hv]; !ok {
				hvMap[hv] = &hvCandidate{hv: hv, bestVn: nil} // mark as skip
			}
			continue
		}
		c, exists := hvMap[hv]
		if !exists {
			c = &hvCandidate{hv: hv}
			hvMap[hv] = c
		}
		// Prefer non-unique, non-input varnodes as the representative.
		// Unique-space and input varnodes are secondary: they do not produce
		// the user-visible name in C output.
		if vn.Space() != nil && !vn.Space().IsUnique() && !vn.IsInput() {
			if c.bestVn == nil {
				c.bestVn = vn
			} else if vn.CreateIndex() < c.bestVn.CreateIndex() {
				// Prefer earlier-created varnode for stable sort key.
				c.bestVn = vn
			}
		}
	}

	var toName []hvEntry
	for _, c := range hvMap {
		if c.bestVn == nil {
			// No non-unique non-input instance -- skip (params, unique-only HVs).
			continue
		}
		prefix := hvTypePrefix(c.hv)
		toName = append(toName, hvEntry{
			hv:        c.hv,
			prefix:    prefix,
			offset:    c.bestVn.Offset(),
			createIdx: uint32(c.bestVn.CreateIndex()),
		})
	}

	if len(toName) == 0 {
		return 0
	}

	// Sort by register offset first (lower register address = lower index),
	// then by create index for stability when two varnodes share an offset.
	// C++ parity: ScopeInternal::assignDefaultNames iterates nametree which
	// is sorted by Address; we approximate this with offset+createIndex.
	sort.Slice(toName, func(i, j int) bool {
		if toName[i].offset != toName[j].offset {
			return toName[i].offset < toName[j].offset
		}
		return toName[i].createIdx < toName[j].createIdx
	})

	// Assign sequential names per type prefix, starting from 1.
	// C++ parity: base=1, incremented per name in ScopeInternal::buildVariableName.
	prefixIdx := make(map[string]int)
	for _, e := range toName {
		if _, ok := prefixIdx[e.prefix]; !ok {
			prefixIdx[e.prefix] = 1
		}
		name := fmt.Sprintf("%s%d", e.prefix, prefixIdx[e.prefix])
		prefixIdx[e.prefix]++
		e.hv.SetName(name)
		a.count++
	}

	return 0
}
