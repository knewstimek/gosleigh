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
	"strings"

	"gosleigh/pkg/address"
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
//
//	database.cc ScopeInternal::assignDefaultNames(),
//	database.cc Scope::buildDefaultName() / ScopeInternal::buildVariableName()
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
// address-tied, proto-partial, non-internal (non-unique), written, earliest def
// (PcodeOp time, numbered in C++ flow order by the bridge).
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
	// Prefer earlier
	if t1, t2 := vn1.Def().Seq().Time, vn2.Def().Seq().Time; t1 != t2 {
		return t2 < t1
	}
	return false
}

// hvTypePrefix returns the Ghidra variable name prefix for a HighVariable based
// on its type metatype. Mirrors Datatype::printNameBase() in C++.
// C++ parity: database.cc ScopeInternal::buildVariableName (the local-var branch)
func hvTypePrefix(hv *HighVariable) string {
	if hv == nil || hv.Type() == nil {
		return "uVar"
	}
	// C++ parity: ScopeInternal::buildVariableName -- ct->printNameBase(s)
	// followed by "Var" (puVar for undefined4 *, lVar for longlong, ...).
	return datatypeNameBase(hv.Type()) + "Var"
}

// regParamSlotOfHigh returns the calling-convention argument slot index of the
// HighVariable when one of its live instances is a function input Varnode stored
// in an argument register, i.e. when the HighVariable is a formal parameter.
// The lowest slot index wins so the result is deterministic if the HighVariable
// ever spans two argument registers.
//
// C++ parity: HighVariable::isInput (variable.hh) drives the parameter branch of
// Scope::buildDefaultName (database.cc:1764); the slot index corresponds to
// Symbol::getCategoryIndex() for a Symbol::function_parameter, which
// ProtoStoreSymbol::setInput assigns from the recovered input map position.
// Unused inputs (no descendants) are skipped: ActionInputPrototype only marks a
// trial active when the Varnode has descendants (coreaction.cc:4738), so a dead
// argument register never becomes a parameter Symbol.
func regParamSlotOfHigh(hv *HighVariable, sl *ScopeLocal) (int, bool) {
	if hv == nil || sl == nil || sl.model == nil {
		return 0, false
	}
	best := -1
	for i := 0; i < hv.NumInstances(); i++ {
		vn := hv.GetInstance(i)
		if vn == nil || !vn.IsInput() || vn.NumDescend() == 0 {
			continue
		}
		if !isRegisterSpace(vn) {
			continue
		}
		idx, ok := sl.model.IsRegParam(vn.Offset())
		if !ok {
			continue
		}
		if best < 0 || idx < best {
			best = idx
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

// Apply assigns iVar1/uVar1-style names to unnamed register-space HighVariables.
// Stack locals already have local_hex names from ScopeLocal and are not touched.
// Must be called after ActionMergeCopy so all HV merging is complete.
// C++ parity: ActionNameVars::apply() -> ScopeLocal::assignDefaultNames()
func (a *ActionNameVars) Apply(data *Funcdata) int {
	finalizeLocalHighTypes(data)
	// Collect unique unnamed register-space HighVariables.
	type hvEntry struct {
		hv        *HighVariable
		prefix    string
		sortKey   uint64 // (offset<<16 | createIndex) for deterministic ordering
		spaceIdx  int
		createIdx uint32
		offset    uint64
		key       *Varnode
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
		inVn   *Varnode // an input instance (irregular input naming)
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
		// A piece of a grouped variable is named through the whole variable.
		if namedGroupRoot(hv, data.GetScopeLocal()) != nil {
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
		//
		// Only EXPLICIT varnodes are named. An implied varnode is inlined into its
		// consumer expression by PrintC (never printed as a standalone variable), so
		// Ghidra creates no Symbol for it and it never advances the default-name
		// counter. C++ parity: ActionNameVars::apply names only the Varnodes in
		// namerec (linkSymbols, coreaction.cc:2985) plus the mapped symbols in
		// nametree (ScopeInternal::assignDefaultNames, database.cc:2850); implied
		// varnodes have no Symbol and are absent from both. Without this gate a
		// cheap multi-use expression that ActionMarkImplied term-duplicated (e.g.
		// a>>0x20 used twice) would still consume a uVarN slot, shifting the numbers
		// of the real explicit locals (umulhi: cross should be uVar1, not uVar3).
		if vn.IsInput() && (c.inVn == nil || vn.CreateIndex() < c.inVn.CreateIndex()) {
			c.inVn = vn
		}
		if vn.Space() != nil && !vn.Space().IsUnique() && !vn.IsInput() && vn.IsExplicit() {
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

	// A stack local named early (ScopeLocal.BuildFromVarnodes, before the
	// frame was restructured) takes the name of the Symbol now covering its
	// storage: a piece of local_1c [3] is local_1c, not local_18.
	// C++ parity: ActionNameVars names a mapped variable by its Symbol.
	if sl != nil && sl.SpaceID() != nil {
		for hv := range hvMap {
			if !strings.HasPrefix(hv.Name(), "local_") || groupRootOf(hv) != nil {
				continue
			}
			nr := highNameRepresentative(hv)
			if nr == nil || nr.Space() != sl.SpaceID() || !nr.IsAddrTied() {
				continue
			}
			e := sl.FindOverlap(nr.Addr(), nr.Size())
			if e == nil || e.Symbol() == nil {
				continue
			}
			if nm := e.Symbol().Name(); nm != "" && nm != hv.Name() && e.Addr().Offset < nr.Offset() &&
				nr.Offset()+uint64(nr.Size()) <= e.Addr().Offset+uint64(e.Size()) {
				hv.SetName(nm)
			}
		}
	}

	recmap := lookForFuncParamNames(data)
	used := make(map[string]bool)
	for _, c := range hvMap {
		if c.hv.Name() != "" {
			used[c.hv.Name()] = true
		}
	}

	cands := make([]*hvCandidate, 0, len(hvMap))
	for _, c := range hvMap {
		cands = append(cands, c)
	}
	// Names are handed out walking the variables by name representative in
	// location order (the namerec list linkSymbols builds); a variable
	// without one keeps its creation order behind them.
	// C++ parity: ActionNameVars::lookForFuncParamNames (varlist order).
	repOf := make(map[*HighVariable]*Varnode, len(cands))
	for _, c := range cands {
		repOf[c.hv] = highNameRepresentative(c.hv)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := repOf[cands[i].hv], repOf[cands[j].hv]
		if a == nil || b == nil {
			if (a == nil) != (b == nil) {
				return b == nil
			}
			return cands[i].hv.serial < cands[j].hv.serial
		}
		if c := CompareLocDef(a, b); c != 0 {
			return c < 0
		}
		return cands[i].hv.serial < cands[j].hv.serial
	})
	var toName []hvEntry
	for _, c := range cands {
		rep := c.bestVn
		if rep == nil {
			// Fall back to an explicit unique-space instance (e.g. snapshot iVar1).
			rep = c.uniqVn
		}
		irregular := sl != nil && sl.model != nil && (sl.model.EntryPoint || !regParamHigh(c.hv, sl))
		lockedIrregular := false
		if fp := data.GetFuncProto(); fp != nil && fp.hostInputLocked && c.inVn != nil {
			irregular = !fp.selfLockedCovers(c.inVn) // The locked list is the whole signature
			// Only an argument-register input would otherwise take a param_N
			// name below; a stack input keeps its local Symbol.
			lockedIrregular = irregular && sl != nil && regParamHigh(c.hv, sl)
		}
		// A stack input outside every mapped Symbol (a hole in the frame map)
		// names the variable: the name representative prefers the input.
		// C++ parity: HighVariable::compareName (isInput) + buildDefaultName.
		unmappedStackInput := c.inVn != nil && sl != nil && c.inVn.Space() == sl.SpaceID() && !c.inVn.IsAddrTied()
		// A stack input past the local frame that is no formal parameter is
		// named as an irregular input (in_stack_<off>), whatever else merged
		// into it. C++ parity: Scope::buildDefaultName (high->isInput) ->
		// ScopeInternal::buildVariableName (input, index < 0).
		if c.inVn != nil && sl != nil && c.inVn.Space() == sl.SpaceID() && c.inVn.IsAddrTied() &&
			sl.model != nil && !sl.model.InLocalRange(c.inVn.Offset()) && !regParamHigh(c.hv, sl) {
			unmappedStackInput = true
		}
		// A register input merged into the variable names it: the name
		// representative prefers an input and buildDefaultName names an
		// input variable that is no parameter in_<reg>.
		// C++ parity: HighVariable::compareName + Scope::buildDefaultName
		// (high->isInput()).
		regInput := c.inVn != nil && c.inVn.Space() != nil && c.inVn.Space().Kind == address.SpaceKindProcessor
		if (rep == nil || lockedIrregular || unmappedStackInput || regInput) && c.inVn != nil && highHasName(c.hv) && irregular && c.inVn.Space() != nil {
			// An input that is not a formal parameter: in_<register>.
			// C++ parity: ScopeInternal::buildVariableName (irregular input,
			// index < 0).
			nm := "in_" + c.inVn.Space().Name + "_" + fmt.Sprintf("%08x", c.inVn.Offset())
			if rn := data.registerName(c.inVn); rn != "" {
				nm = "in_" + rn
			}
			// An address-tied input in the local frame takes the stack name
			// even though it is an input.
			// C++ parity: ScopeLocal::buildVariableName (addrtied branch first).
			if c.inVn.IsAddrTied() && !c.inVn.IsPersist() && c.inVn.Space() == sl.SpaceID() &&
				(sl.model == nil || sl.model.InLocalRange(c.inVn.Offset())) {
				nm = sl.addrTiedLinkName(c.inVn.Addr(), c.hv.Type())
			}
			nm = makeNameUnique(nm, used)
			used[nm] = true
			c.hv.SetName(nm)
			c.hv.irregularInput = true
			a.count++
			continue
		}
		if rep == nil {
			// No nameable representative -- skip (params, implied unique-only HVs).
			continue
		}
		if !highHasName(c.hv) {
			continue
		}
		// A global variable is named by its global symbol (ActionMapGlobals),
		// never from the local default-name counter.
		if data.globalEntryOf(rep) != nil {
			continue
		}
		// A HighVariable that still holds a live input Varnode sitting in a
		// calling-convention argument register IS the formal parameter, however many
		// re-definitions were merged into it, and takes the param_N name.
		//
		// This is the storage-driven half of the C++ naming rule: ActionInputPrototype
		// (coreaction.cc:4718) re-derives the input map from the FINAL SSA at the
		// fixateproto stage, and FuncProto::updateInputTypes -> ProtoStoreSymbol::setInput
		// (fspec.cc) drops and re-creates the parameter Symbol whenever the recovered
		// storage no longer matches the old SymbolEntry (addr or size). ActionNameVars
		// then names it through Scope::buildDefaultName (database.cc:1756), whose first
		// branch is "sym->getCategory() == function_parameter || high->isInput()"
		// (database.cc:1764) -> buildVariableName(..., index, flags|input) ->
		// "param_<index>" (database.cc:2481).
		//
		// Gosleigh stamps register parameter names once, early, inside
		// ScopeLocal.BuildFromVarnodes, onto the Varnode that was the input at that
		// moment. When a parameter is re-assigned in the body, subvariable/lane flow
		// later replaces the full-width input (RDX:8) with its sub-register (EDX:4)
		// AFTER parameter recovery locked, so the named HighVariable dies with the
		// discarded wide input and the surviving one reaches here unnamed -- which used
		// to yield iVarN for a variable Ghidra prints as param_N. Recovering the name
		// from the argument-register storage here is the same "storage, not Varnode
		// identity, owns the parameter name" invariant the C++ re-derivation provides.
		//
		// Entry-point functions are excluded: they run the stack-only processEntry
		// model, so an argument register carries no parameter index (index<0) and C++
		// names it in_<reg> (database.cc:2470) -- the renderer handles that case.
		// A name-locked symbol attached to an instance names the variable.
		// C++ parity: Funcdata::linkSymbol through Varnode::getSymbolEntry.
		if nm := lockedSymbolName(c.hv); nm != "" {
			c.hv.SetName(nm)
			a.count++
			continue
		}
		if sl != nil && sl.model != nil && !sl.model.EntryPoint {
			if idx, ok := regParamSlotOfHigh(c.hv, sl); ok {
				name := GetParamName(idx)
				// A locked prototype names the parameter at this storage.
				for _, vn := range c.hv.Instances() {
					if !vn.IsInput() {
						continue
					}
					if pn, nlock, _, found := data.GetFuncProto().LockedParamName(vn.Offset()); found && nlock {
						name = pn
					}
				}
				c.hv.SetName(name)
				a.count++
				continue
			}
		}
		if sl != nil {
			if nr := highNameRepresentative(c.hv); nr != nil {
				if e := sl.FindOverlap(nr.Addr(), nr.Size()); e != nil && e.Symbol() != nil {
					name := e.Symbol().Name()
					if name == "" && nr.IsAddrTied() && !nr.IsPersist() {
						// An unnamed symbol gets its default name from its storage.
						// C++ parity: Scope::buildDefaultName -> buildVariableName.
						name = makeNameUnique(sl.addrTiedLinkName(nr.Addr(), c.hv.Type()), used)
						used[name] = true
					}
					c.hv.SetName(name)
					a.count++
					continue
				}
			}
		}
		// A variable passed to a locked callee parameter inherits its name.
		// C++ parity: ActionNameVars::lookForFuncParamNames.
		// No inherited name for a speculatively merged variable.
		if nm, ok := recmap[c.hv]; ok && !highHasInput(c.hv) && c.hv.numMergeClasses() == 1 {
			c.hv.SetName(makeNameUnique(nm, used))
			a.count++
			continue
		}
		prefix := hvTypePrefix(c.hv)
		key := rep
		if nr := highNameRepresentative(c.hv); nr != nil {
			key = nr
		}
		spcIdx := 0
		if key.Space() != nil {
			spcIdx = int(key.Space().Index)
		}
		toName = append(toName, hvEntry{
			hv:        c.hv,
			prefix:    prefix,
			spaceIdx:  spcIdx,
			offset:    key.Offset(),
			createIdx: uint32(key.CreateIndex()),
			key:       key,
		})
	}

	if len(toName) == 0 {
		return 0
	}

	// Sort by register offset first (lower register address = lower index),
	// then by create index for stability when two varnodes share an offset.
	// C++ parity: ScopeInternal::assignDefaultNames iterates nametree which
	// is sorted by Address; we approximate this with offset+createIndex.
	// C++ parity: ActionNameVars::linkSymbols walks spaces by index, then
	// each space's varnodes in location order, visiting a high at its name
	// representative.
	sort.SliceStable(toName, func(i, j int) bool {
		return CompareLocDef(toName[i].key, toName[j].key) < 0
	})

	// One counter shared by every prefix (iVar1, puVar2, ...).
	// C++ parity: ScopeInternal::buildVariableName "Var" << index++ with the
	// single base assignDefaultNames threads through.
	// Symbols are linked in this order; a variable whose name representative
	// lands on storage and a use point an earlier variable's entry already
	// covers conflicts with it and gets a dynamic symbol.
	// C++ parity: ActionNameVars::linkSymbols -> Funcdata::linkSymbol
	// (queryProperties at the use point) -> handleSymbolConflict.
	type claim struct {
		space    *address.Space
		lo, hi   uint64
		usepoint address.Address
	}
	var claims []claim
	usePoint := func(vn *Varnode) address.Address { // Varnode::getUsePoint
		if vn.IsWritten() {
			return vn.Def().Addr()
		}
		return data.BaseAddr().Add(^uint64(0))
	}
	// A piece of a structure visited before its whole links the whole's
	// symbol first, so the whole claims its storage at the piece's position.
	// C++ parity: Funcdata::linkSymbol -> linkProtoPartial.
	linkAt := make(map[*HighVariable]*Varnode)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		hv := vn.High()
		if vn.IsFree() || !vn.IsProtoPartial() || hv == nil || hv.piece == nil || !highHasName(hv) || highNameRepresentative(hv) != vn {
			continue
		}
		root := pieceFindRoot(vn)
		if root == vn || root.High() == nil || root.High().piece == nil || root.High().piece.group != hv.piece.group {
			continue
		}
		if cur := linkAt[root.High()]; cur == nil || CompareLocDef(vn, cur) < 0 {
			linkAt[root.High()] = vn
		}
	}
	claimOrder := append([]hvEntry(nil), toName...)
	claimKey := func(e hvEntry) *Varnode {
		if vn := linkAt[e.hv]; vn != nil && CompareLocDef(vn, e.key) < 0 {
			return vn
		}
		return e.key
	}
	sort.SliceStable(claimOrder, func(i, j int) bool {
		return CompareLocDef(claimKey(claimOrder[i]), claimKey(claimOrder[j])) < 0
	})
	for _, e := range claimOrder {
		vn := e.key
		up := usePoint(vn)
		conflict := false
		for _, c := range claims {
			if c.space == vn.Space() && vn.Offset() >= c.lo && vn.Offset() < c.hi && c.usepoint == up {
				conflict = true
				break
			}
		}
		if conflict && !(vn.IsInput() || vn.IsAddrTied() || vn.IsPersist() || vn.IsConstant()) {
			e.hv.dynamicSym = true
			continue
		}
		sz := uint64(vn.Size())
		if t := e.hv.Type(); t != nil && t.Size() > 0 {
			sz = uint64(t.Size())
		}
		claims = append(claims, claim{vn.Space(), vn.Offset(), vn.Offset() + sz, up})
	}

	idx := 1
	for _, e := range toName {
		// The output of an INDIRECT creation (a register a call clobbers) is
		// extraout_<reg> and does not consume an index.
		// C++ parity: ScopeInternal::buildVariableName (indirect_creation branch).
		if e.key.HasFlags(VarnodeIndirectCreation) {
			nm := "extraout_var"
			if rn := data.registerName(e.key); rn != "" {
				nm = "extraout_" + rn
			}
			e.hv.SetName(makeNameUnique(nm, used))
			a.count++
			continue
		}
		// An address-tied variable is named by its storage and does not
		// consume an index. C++ parity: ScopeInternal::buildVariableName
		// (addrtied branch) through ScopeLocal::buildVariableName.
		if sl != nil && e.key.IsAddrTied() && !e.key.IsPersist() && !e.key.IsInput() {
			nm := makeNameUnique(sl.addrTiedLinkName(e.key.Addr(), e.hv.Type()), used)
			used[nm] = true
			e.hv.SetName(nm)
			a.count++
			continue
		}
		e.hv.SetName(fmt.Sprintf("%s%d", e.prefix, idx))
		idx++
		a.count++
	}

	return 0
}

// highHasName reports whether a HighVariable gets a name (a symbol) at all:
// not an implied (inlined) value, and not a register the function merely
// preserves (unaffected, unless it is a used, non-spacebase input).
// C++ parity: variable.cc HighVariable::hasName.
func highHasName(hv *HighVariable) bool {
	indirectOnly := true
	unaffected := false
	used := false
	var input *Varnode
	for _, vn := range hv.Instances() {
		if vn.NumDescend() > 0 || vn.IsAddrTied() {
			used = true
		}
		if vn.IsImplied() {
			return false
		}
		if !vn.IsIndirectOnly() {
			indirectOnly = false
		}
		if vn.IsUnaffected() {
			unaffected = true
		}
		if vn.IsInput() {
			input = vn
		}
	}
	// A value nothing reads is dead code in C++ and never reaches naming;
	// Gosleigh can still hold one (bridge constant materialization).
	if !used {
		return false
	}
	if unaffected {
		if input == nil || indirectOnly {
			return false
		}
		if input.IsSpaceBase() {
			return false
		}
	}
	return true
}

// lockedSymbolName is the name of a name-locked symbol attached to one of the
// variable's instances, or "".
func lockedSymbolName(hv *HighVariable) string {
	for _, vn := range hv.Instances() {
		if e := vn.GetSymbolEntry(); e != nil && e.Symbol() != nil && e.Symbol().Flags()&VarnodeNameLock != 0 {
			return e.Symbol().Name()
		}
	}
	return ""
}

// lookForFuncParamNames maps each variable passed to a name-locked parameter
// of a locked callee prototype to that parameter's name, preferring the
// most specific parameter type and uncast arguments.
// C++ parity: ActionNameVars::lookForFuncParamNames / makeRec.
func lookForFuncParamNames(data *Funcdata) map[*HighVariable]string {
	type rec struct {
		ct   Datatype
		name string
	}
	recs := make(map[*HighVariable]*rec)
	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil || !fc.IsInputLocked() || fc.op == nil {
			continue
		}
		for j := 0; j+1 < fc.op.NumInput(); j++ {
			param, ok := fc.LockedParam(j)
			if !ok {
				break
			}
			vn := fc.op.Input(j + 1)
			if param.Name == "" || vn.Size() != param.Size {
				continue
			}
			ct := param.Type
			if vn.IsImplied() && vn.IsWritten() && vn.Def().Code() == CPUI_CAST {
				vn = vn.Def().Input(0) // skip a cast into the function
				ct = nil               // a less preferred name
			}
			high := vn.High()
			if high == nil || high.IsAddrTied() || strings.HasPrefix(param.Name, "param_") {
				continue
			}
			if old, seen := recs[high]; seen {
				if ct == nil {
					continue
				}
				if old.ct != nil && TypeOrder(old.ct, ct) <= 0 {
					continue
				}
				old.ct, old.name = ct, param.Name
				continue
			}
			recs[high] = &rec{ct, param.Name}
		}
	}
	res := make(map[*HighVariable]string, len(recs))
	for h, r := range recs {
		res[h] = r.name
	}
	return res
}

// highHasInput reports whether the variable holds an input Varnode.
func highHasInput(hv *HighVariable) bool {
	for _, vn := range hv.Instances() {
		if vn.IsInput() {
			return true
		}
	}
	return false
}

// makeNameUnique returns nm, or nm with a _NN suffix if nm is taken, and
// records the result. C++ parity: ScopeInternal::makeNameUnique.
func makeNameUnique(nm string, used map[string]bool) string {
	res := nm
	for i := 0; used[res]; i++ {
		res = fmt.Sprintf("%s_%02x", nm, i)
	}
	used[res] = true
	return res
}

// finalizeLocalHighTypes records the representative each named variable is
// linked to its symbol through, and fixes the data-type of each named, address-tied
// variable mapped to a local symbol to that symbol's data-type.
// C++ parity: ActionNameVars::linkSymbols (the finalizeDatatype arm).
func finalizeLocalHighTypes(data *Funcdata) {
	sl := data.GetScopeLocal()
	if sl == nil {
		return
	}
	local := make(map[*SymbolEntry]bool)
	for _, e := range sl.Entries() {
		local[e] = true
	}
	seen := make(map[*HighVariable]bool)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn.IsFree() {
			continue
		}
		high := vn.High()
		if high == nil || seen[high] {
			continue
		}
		seen[high] = true
		rep := highNameRepresentative(high)
		if rep == nil || !highHasName(high) {
			continue
		}
		high.linkedRep = rep
		var entry *SymbolEntry
		for _, inst := range high.Instances() {
			if e := inst.GetSymbolEntry(); e != nil {
				entry = e
				break
			}
		}
		if entry == nil && !rep.IsPersist() {
			// Funcdata::linkSymbol: find the entry through the scope
			entry = sl.QueryContainer(rep.Addr(), 1, address.Address{})
		}
		if entry == nil || !rep.IsAddrTied() || !local[entry] {
			continue
		}
		off := int64(rep.Offset()-entry.Addr().Offset) + int64(entry.Offset())
		high.finalizeDatatype(data.TypeFactory(), entry.Symbol(), off)
	}
}

// regParamHigh reports whether the variable holds a formal register parameter.
func regParamHigh(hv *HighVariable, sl *ScopeLocal) bool {
	_, ok := regParamSlotOfHigh(hv, sl)
	return ok
}
