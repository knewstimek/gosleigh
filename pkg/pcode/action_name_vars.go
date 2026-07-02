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

// highNameRepresentative returns the HighVariable's canonical name-representative
// member -- the instance whose properties most dominate the choice of name.
// C++ parity: HighVariable::getNameRepresentative (variable.cc:492-511), which
// scans the members keeping the one that wins HighVariable::compareName.
func highNameRepresentative(hv *HighVariable) *Varnode {
	if hv == nil || hv.NumInstances() == 0 {
		return nil
	}
	rep := hv.GetInstance(0)
	for i := 1; i < hv.NumInstances(); i++ {
		vn := hv.GetInstance(i)
		if vn == nil {
			continue
		}
		if rep == nil || compareNameRep(rep, vn) {
			rep = vn
		}
	}
	return rep
}

// highNameRepresentativeLive is highNameRepresentative restricted to instances
// for which live reports true. C++ parity: HighVariable::getNameRepresentative
// (variable.cc:492) scans hv->inst, which only ever holds live members because
// HighVariable::remove (variable.cc:515) purges a member when its Varnode is
// destroyed. HighVariable::remove is not ported here, so hv.instances can retain
// a dead member; restricting the scan to live instances reproduces the C++
// invariant locally so the name representative is a real, declarable Varnode.
func highNameRepresentativeLive(hv *HighVariable, live func(*Varnode) bool) *Varnode {
	if hv == nil {
		return nil
	}
	var rep *Varnode
	for i := 0; i < hv.NumInstances(); i++ {
		vn := hv.GetInstance(i)
		if vn == nil {
			continue
		}
		if live != nil && !live(vn) {
			continue
		}
		if rep == nil || compareNameRep(rep, vn) {
			rep = vn
		}
	}
	return rep
}

// compareNameRep reports whether vn2 is preferred over vn1 as the name
// representative. Faithful port of HighVariable::compareName (variable.cc:456).
// Precedence (most preferred first): name-lock, unaffected, persistent, input,
// address-tied, proto-partial, non-internal (non-unique), written, earliest def.
// Def-time ordering uses the output Varnode's create index as a proxy for
// PcodeOp::getTime (only breaks ties between same-address members, so it never
// changes the selected Symbol).
func compareNameRep(vn1, vn2 *Varnode) bool {
	if vn1.IsNameLock() {
		return false
	}
	if vn2.IsNameLock() {
		return true
	}
	if vn1.IsUnaffected() != vn2.IsUnaffected() {
		return vn2.IsUnaffected()
	}
	if vn1.IsPersist() != vn2.IsPersist() {
		return vn2.IsPersist()
	}
	if vn1.IsInput() != vn2.IsInput() {
		return vn2.IsInput()
	}
	if vn1.IsAddrTied() != vn2.IsAddrTied() {
		return vn2.IsAddrTied()
	}
	if vn1.IsProtoPartial() != vn2.IsProtoPartial() {
		return vn2.IsProtoPartial()
	}
	u1 := vn1.Space() != nil && vn1.Space().IsUnique()
	u2 := vn2.Space() != nil && vn2.Space().IsUnique()
	if !u1 && u2 {
		return false
	}
	if u1 && !u2 {
		return true
	}
	if vn1.IsWritten() != vn2.IsWritten() {
		return vn2.IsWritten()
	}
	if !vn1.IsWritten() {
		return false
	}
	if vn1.CreateIndex() != vn2.CreateIndex() {
		return vn2.CreateIndex() < vn1.CreateIndex()
	}
	return false
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
		hv     *HighVariable
		bestVn *Varnode // best representative (non-unique, non-input)
		uniqVn *Varnode // explicit unique-space fallback (e.g. loop-head snapshot iVar1)
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
		} else if vn.Space() != nil && vn.Space().IsUnique() && vn.IsExplicit() {
			// Explicit unique-space varnodes are printed as standalone temporaries
			// (e.g. the loop-head snapshot iVar1 = COPY(param)). They need a name
			// when the HV has no register/stack representative. C++ parity:
			// ScopeInternal::assignDefaultNames names explicit temporaries too.
			if c.uniqVn == nil || vn.CreateIndex() < c.uniqVn.CreateIndex() {
				c.uniqVn = vn
			}
		}
	}

	// A HighVariable backed by a mapped stack local takes its name from the
	// attached ScopeLocal Symbol (local_<hex>), never the iVar/uVar convention.
	// In the flag-off path ScopeLocal.BuildFromVarnodes already named these HVs
	// before this action runs (so hv.Name() != "" skips them at collection). In
	// the faithful stack path the stack varnodes appear later (oppool2), so the HV
	// reaches this action unnamed; here we adopt the Symbol name instead of
	// assigning iVarN. C++ parity: ScopeInternal::assignDefaultNames leaves
	// already-symboled storage named by its Symbol; buildVariableName supplies the
	// stack hex-offset name.
	//
	// The symbol is looked up on the HV's NAME REPRESENTATIVE (the addr-tied stack
	// member when the HV also contains register/unique members), not the arbitrary
	// iVar-prefix representative -- otherwise a merged accumulator whose live value
	// is carried in a register (e.g. sum_to_n) would miss its stack symbol and
	// print iVarN. C++ parity: ActionNameVars names an HV via
	// high->getNameRepresentative()/getSymbol() (coreaction.cc:2891,2961);
	// getNameRepresentative selects by HighVariable::compareName precedence
	// (variable.cc:456), which prefers input/addr-tied/non-unique members.
	sl := data.GetScopeLocal()

	var toName []hvEntry
	for _, c := range hvMap {
		rep := c.bestVn
		if rep == nil {
			// Fall back to an explicit unique-space instance (e.g. snapshot iVar1).
			rep = c.uniqVn
		}
		if rep == nil {
			// No nameable representative -- skip (params, implied unique-only HVs).
			continue
		}
		if sl != nil {
			if nr := highNameRepresentative(c.hv); nr != nil {
				if e := sl.FindOverlap(nr.Addr(), nr.Size()); e != nil && e.Symbol() != nil {
					c.hv.SetName(e.Symbol().Name())
					a.count++
					continue
				}
			}
		}
		prefix := hvTypePrefix(c.hv)
		toName = append(toName, hvEntry{
			hv:        c.hv,
			prefix:    prefix,
			offset:    rep.Offset(),
			createIdx: uint32(rep.CreateIndex()),
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
