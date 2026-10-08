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

// This file extends ScopeLocal (scopelocal.go) with the real symbol-map
// machinery: a SymbolEntry container keyed by address-range, dynamic-symbol
// lookups by hash, name/type recommendations, and the high-level
// restructureVarnode / queryContainer entry points used by the Action layer.
//
// The original Ghidra implementation stores SymbolEntry records inside a
// rangemap<> templated on an AddrSpace. We instead use a flat slice per
// scope which is sorted on demand; the lookup functions walk the slice and
// select the narrowest containing entry. This matches the only queries the
// Go port needs for now (exact / overlap / contains); a proper interval tree
// can replace it later if profiling demands.
//
// C++ parity: database.hh ScopeInternal (SymbolEntry storage subset)
// C++ parity: varmap.hh ScopeLocal (name/type recommendations + restructure)

// NameRecommendation is a name proposal tied to a concrete storage address.
// C++ parity: varmap.hh NameRecommend
type NameRecommendation struct {
	Addr    address.Address // Starting address of the storage location
	UseAddr address.Address // Code address at the point of use
	Size    int32           // Optional size hint
	Name    string          // Proposed symbol name
	SymID   uint64          // Original Symbol id
}

// DynamicRecommendation is a name proposal for dynamic (hash-identified)
// storage.
// C++ parity: varmap.hh DynamicRecommend
type DynamicRecommendation struct {
	UsePoint address.Address // Use point of the symbol
	Hash     uint64          // DynamicHash identifier
	Name     string          // Proposed symbol name
	SymID    uint64          // Original Symbol id
}

// TypeRecommendation seeds a data-type onto an input Varnode at a specific
// storage address. Applied at the tail of ScopeLocal::applyTypeRecommendations.
// C++ parity: varmap.hh TypeRecommend
type TypeRecommendation struct {
	Addr address.Address
	Type Datatype
}

// ensureExt makes sure the extended ScopeLocal state is populated. Because the
// base struct is defined in scopelocal.go, the extra fields live on a side
// struct that is lazily initialized on first use and pinned to the ScopeLocal
// via the package-scoped scopeLocalExt map.
// C++ parity: ScopeLocal extra fields live directly on the class in C++.
// We use a side table to keep ScopeLocal's declared struct stable and avoid
// invalidating existing tests that construct it via a struct literal.
type scopeLocalExt struct {
	entries     []*SymbolEntry                // Non-dynamic storage entries
	dynEntries  []*SymbolEntry                // Dynamic storage entries
	vnMap       map[*Varnode]*SymbolEntry     // Varnode -> resolved SymbolEntry
	nameRec     []NameRecommendation          // Symbol name recommendations
	dynRec      []DynamicRecommendation       // Dynamic name recommendations
	typeRec     []TypeRecommendation          // Data-type recommendations
	stackSpace  *address.Space                // Space managed by this scope
	stackGrows  bool                          // True if stack grows toward lower offsets
	rangeLocked bool                          // True if the mapped address range is locked
	hostLocals  map[uint64]string             // Host name-locked stack symbols by offset
	// hostLocalTypes are the host's type-locked stack symbol types by offset.
	hostLocalTypes map[uint64]Datatype
	// hostIsolated are the host's merge="false" stack parameters by offset.
	hostIsolated map[uint64]bool
	// notMapped are the [first,last] stack offset ranges removed from the
	// scope's owned range (saved registers, call parameter areas).
	notMapped [][2]uint64
	// minParamOffset/maxParamOffset bound the stack parameters passed to
	// called functions; max < min when there are none.
	// C++ parity: ScopeLocal::minParamOffset / maxParamOffset.
	minParamOffset uint64
	maxParamOffset uint64
}

func (sl *ScopeLocal) ext() *scopeLocalExt {
	if sl == nil {
		return nil
	}
	if sl.extState != nil {
		return sl.extState
	}
	e := &scopeLocalExt{
		vnMap:          make(map[*Varnode]*SymbolEntry),
		minParamOffset: ^uint64(0), // C++ parity: ScopeLocal::resetLocalWindow
	}
	if sl.model != nil {
		e.stackSpace = sl.model.StackSpace
	}
	e.stackGrows = true // Ghidra default on stack-negative architectures
	sl.extState = e
	return e
}

// SpaceID returns the stack address space associated with this scope.
// C++ parity: ScopeLocal::getSpaceId
func (sl *ScopeLocal) SpaceID() *address.Space {
	if sl == nil {
		return nil
	}
	return sl.ext().stackSpace
}

// SetSpaceID records the stack space managed by the scope.
// C++ parity: ScopeLocal constructor `space` assignment.
func (sl *ScopeLocal) SetSpaceID(spc *address.Space) {
	if sl == nil || spc == nil {
		return
	}
	sl.ext().stackSpace = spc
}

// Entries returns the live non-dynamic SymbolEntry records.
// C++ parity: ScopeInternal::maptable entry iteration.
func (sl *ScopeLocal) Entries() []*SymbolEntry {
	if sl == nil {
		return nil
	}
	return sl.ext().entries
}

// DynamicEntries returns the live dynamic SymbolEntry records.
// C++ parity: ScopeInternal dynamic entry iteration.
func (sl *ScopeLocal) DynamicEntries() []*SymbolEntry {
	if sl == nil {
		return nil
	}
	return sl.ext().dynEntries
}

// AddSymbol attaches a name+type to a storage address and returns the created
// SymbolEntry. Pre-existing entries at the same address are replaced so
// repeated calls converge on the last-specified symbol, matching the
// restructure-then-recreate pattern used by ScopeLocal::restructure.
// C++ parity: ScopeInternal::addMapInternal + Scope::addSymbol
func (sl *ScopeLocal) AddSymbol(name string, dt Datatype, addr address.Address, size int32) *SymbolEntry {
	if sl == nil {
		return nil
	}
	sym := NewSymbol(name, dt)
	entry := NewSymbolEntry(sym, 0, addr, size, 0)
	sym.attachEntry(entry)
	ext := sl.ext()
	// Replace any entry at the same address so we keep a single record per slot.
	for i, e := range ext.entries {
		if e != nil && e.addr.Space == addr.Space && e.addr.Offset == addr.Offset && e.size == size {
			ext.entries[i] = entry
			return entry
		}
	}
	ext.entries = append(ext.entries, entry)
	return entry
}

// AddDynamicSymbol attaches a name+type to a DynamicHash-identified location.
// C++ parity: ScopeInternal::addDynamicMapInternal + Scope::addDynamicSymbol
func (sl *ScopeLocal) AddDynamicSymbol(name string, dt Datatype, caddr address.Address, hash uint64) *SymbolEntry {
	if sl == nil {
		return nil
	}
	sym := NewSymbol(name, dt)
	entry := NewDynamicSymbolEntry(sym, 0, hash, 0, 0)
	if !caddr.IsInvalid() {
		entry.SetUseLimit([]useRange{{space: caddr.Space, first: caddr.Offset, last: caddr.Offset}})
	}
	sym.attachEntry(entry)
	ext := sl.ext()
	ext.dynEntries = append(ext.dynEntries, entry)
	return entry
}

// clearCategory removes every Symbol of the given category.
// C++ parity: ScopeInternal::clearCategory.
func (sl *ScopeLocal) clearCategory(cat int) {
	var doomed []*Symbol
	for _, e := range sl.ext().entries {
		if e != nil && e.symbol != nil && e.symbol.Category() == cat {
			doomed = append(doomed, e.symbol)
		}
	}
	for _, sym := range doomed {
		sl.RemoveSymbol(sym)
	}
}

// RemoveSymbol drops any SymbolEntry owned by the given Symbol from the scope.
// C++ parity: ScopeInternal::removeSymbolMappings / removeSymbol
func (sl *ScopeLocal) RemoveSymbol(sym *Symbol) {
	if sl == nil || sym == nil {
		return
	}
	ext := sl.ext()
	keep := ext.entries[:0]
	for _, e := range ext.entries {
		if e != nil && e.symbol != sym {
			keep = append(keep, e)
		}
	}
	ext.entries = keep
	keepDyn := ext.dynEntries[:0]
	for _, e := range ext.dynEntries {
		if e != nil && e.symbol != sym {
			keepDyn = append(keepDyn, e)
		}
	}
	ext.dynEntries = keepDyn
}

// QueryContainer returns the smallest SymbolEntry that wholly contains the
// given address range. Size may be 0 to search for any entry that starts at
// the address. The usepoint narrows the match to entries whose UseLimit
// contains it (an empty UseLimit matches any usepoint).
//
// C++ parity: Scope::queryContainer
func (sl *ScopeLocal) QueryContainer(addr address.Address, size int32, usepoint address.Address) *SymbolEntry {
	if sl == nil {
		return nil
	}
	var best *SymbolEntry
	for _, e := range sl.ext().entries {
		if e == nil || e.IsDynamic() {
			continue
		}
		if e.addr.Space != addr.Space {
			continue
		}
		if !containsRange(e, addr.Offset, size) {
			continue
		}
		if !e.InUse(usepoint) {
			continue
		}
		// Narrow wins: replace the candidate with any strictly smaller
		// containing entry.
		if best == nil || e.size < best.size {
			best = e
		}
	}
	return best
}

// FindOverlap returns the first SymbolEntry whose storage overlaps the given
// [addr,addr+size) range. This mirrors ScopeLocal::findOverlap, which is a
// thinner query than queryContainer: any intersection is enough, the entry
// does not need to fully contain the range.
// C++ parity: ScopeLocal::findOverlap
func (sl *ScopeLocal) FindOverlap(addr address.Address, size int32) *SymbolEntry {
	if sl == nil || size <= 0 {
		return nil
	}
	target := addr.Offset
	targetEnd := target + uint64(size) - 1
	for _, e := range sl.ext().entries {
		if e == nil || e.IsDynamic() {
			continue
		}
		if e.addr.Space != addr.Space {
			continue
		}
		if e.size <= 0 {
			continue
		}
		first := e.First()
		last := e.Last()
		if last < target {
			continue
		}
		if first > targetEnd {
			continue
		}
		return e
	}
	return nil
}

// FindDynamicEntry returns the SymbolEntry whose dynamic hash and use point
// match the given pair, or nil. An invalid usepoint is treated as a wildcard
// so ActionDynamicMapping can iterate through all dynamic entries with the
// same hash.
// C++ parity: ScopeInternal::findOverlap (dynamic variant)
func (sl *ScopeLocal) FindDynamicEntry(hash uint64, usepoint address.Address) *SymbolEntry {
	if sl == nil {
		return nil
	}
	for _, e := range sl.ext().dynEntries {
		if e == nil {
			continue
		}
		if e.hash != hash {
			continue
		}
		if usepoint.IsInvalid() || e.InUse(usepoint) {
			return e
		}
	}
	return nil
}

// InScope reports whether the given [addr,addr+size) range is mapped into the
// scope's managed address space. With the partial port we accept any address
// that lives in the scope's stack space; Ghidra additionally consults a
// per-scope RangeList but that list is always "whole stack" on the paths used
// by syncVarnodesWithSymbols.
// C++ parity: Scope::inScope (subset)
func (sl *ScopeLocal) InScope(addr address.Address, size int32, usepoint address.Address) bool {
	if sl == nil {
		return false
	}
	ext := sl.ext()
	if ext.stackSpace == nil {
		return false
	}
	// The scope owns its whole space except ranges removed by MarkNotMapped.
	// C++ parity: Scope::inScope over the scope's rangetree.
	return addr.Space == ext.stackSpace && !sl.isNotMapped(addr.Offset, size)
}

// IsUnmappedUnaliased reports whether a stack Varnode that no SymbolEntry
// covers should nonetheless be treated as having no local alias.
func (sl *ScopeLocal) IsUnmappedUnaliased(vn *Varnode) bool {
	if sl == nil || sl.model == nil || vn.Space() != sl.model.StackSpace {
		return false // Must be in the mapped local (stack) space
	}
	// C++ parity: varmap.cc ScopeLocal::isUnmappedUnaliased (494-502).
	ext := sl.ext()
	if ext.maxParamOffset < ext.minParamOffset {
		return true // If no min/max, then we have no known stack parameters
	}
	return vn.Offset() < ext.minParamOffset || vn.Offset() > ext.maxParamOffset
}

// AttachEntryToVarnode records the mapping between a Varnode and a resolved
// SymbolEntry. syncVarnodesWithSymbols uses this to carry entry results across
// the analysis pipeline.
// C++ parity: Varnode::setSymbolEntry
func (sl *ScopeLocal) AttachEntryToVarnode(vn *Varnode, entry *SymbolEntry) {
	if sl == nil || vn == nil {
		return
	}
	sl.ext().vnMap[vn] = entry
}

// EntryForVarnode returns the previously attached SymbolEntry for a Varnode,
// or nil if none has been resolved yet.
// C++ parity: Varnode::getSymbolEntry
func (sl *ScopeLocal) EntryForVarnode(vn *Varnode) *SymbolEntry {
	if sl == nil || vn == nil {
		return nil
	}
	return sl.ext().vnMap[vn]
}

// FindEntryAt returns the stack SymbolEntry whose address matches addr (same
// space and starting offset), preferring an exact size match. RestructureVarnode
// builds entries per stack slot but does not populate vnMap, so this address
// lookup is how printc resolves a stack Varnode to its Symbol.
// C++ parity: ScopeInternal::findOverlap / SymbolEntry lookup by address.
func (sl *ScopeLocal) FindEntryAt(addr address.Address, size int32) *SymbolEntry {
	if sl == nil {
		return nil
	}
	var fallback *SymbolEntry
	for _, e := range sl.ext().entries {
		if e == nil {
			continue
		}
		ea := e.Addr()
		if ea.Space != addr.Space || ea.Offset != addr.Offset {
			continue
		}
		if e.Size() == size {
			return e
		}
		if fallback == nil {
			fallback = e
		}
	}
	return fallback
}

// AddTypeRecommendation appends a data-type hint for the given address.
// C++ parity: ScopeLocal::addTypeRecommendation
func (sl *ScopeLocal) AddTypeRecommendation(addr address.Address, dt Datatype) {
	if sl == nil || dt == nil {
		return
	}
	sl.ext().typeRec = append(sl.ext().typeRec, TypeRecommendation{Addr: addr, Type: dt})
}

// HasTypeRecommendations reports whether any TypeRecommendation is pending.
// C++ parity: ScopeLocal::hasTypeRecommendations
func (sl *ScopeLocal) HasTypeRecommendations() bool {
	return sl != nil && len(sl.ext().typeRec) > 0
}

// ApplyTypeRecommendations walks the pending TypeRecommendations and seeds the
// matching input Varnodes with their recommended data-type. Each recommendation
// is consumed even if no matching Varnode exists so repeated calls are a no-op.
// C++ parity: varmap.cc ScopeLocal::applyTypeRecommendations
func (sl *ScopeLocal) ApplyTypeRecommendations(fd *Funcdata) {
	if sl == nil || fd == nil {
		return
	}
	ext := sl.ext()
	if len(ext.typeRec) == 0 {
		return
	}
	for _, rec := range ext.typeRec {
		if rec.Type == nil {
			continue
		}
		sz := rec.Type.Size()
		if sz <= 0 {
			continue
		}
		vn := fd.FindVarnodeInput(int32(sz), rec.Addr)
		if vn == nil {
			continue
		}
		SetVarnodeType(vn, rec.Type)
	}
	ext.typeRec = nil
}

// AddRecommendName turns an unlocked Symbol into a NameRecommendation (or a
// DynamicRecommendation if its storage is dynamic). The symbol is then
// detached from the scope so the restructure pass can rebuild the layout.
// C++ parity: varmap.cc ScopeLocal::addRecommendName
func (sl *ScopeLocal) AddRecommendName(sym *Symbol) {
	if sl == nil || sym == nil {
		return
	}
	entry := sym.FirstWholeMap()
	if entry == nil {
		return
	}
	ext := sl.ext()
	if entry.IsDynamic() {
		ext.dynRec = append(ext.dynRec, DynamicRecommendation{
			UsePoint: entry.FirstUseAddress(),
			Hash:     entry.hash,
			Name:     sym.Name(),
			SymID:    sym.ID(),
		})
	} else {
		use := address.Address{}
		if ranges := entry.UseLimit(); len(ranges) > 0 {
			use = address.Address{Space: ranges[0].space, Offset: ranges[0].first}
		}
		ext.nameRec = append(ext.nameRec, NameRecommendation{
			Addr:    entry.Addr(),
			UseAddr: use,
			Size:    entry.Size(),
			Name:    sym.Name(),
			SymID:   sym.ID(),
		})
	}
	if sym.Category() < 0 {
		sl.RemoveSymbol(sym)
	}
}

// NameRecommendations returns the pending storage-backed name recommendations.
// C++ parity: varmap.hh ScopeLocal::nameRecommend
func (sl *ScopeLocal) NameRecommendations() []NameRecommendation {
	if sl == nil {
		return nil
	}
	return sl.ext().nameRec
}

// DynamicRecommendations returns the pending dynamic-hash name recommendations.
// C++ parity: varmap.hh ScopeLocal::dynRecommend
func (sl *ScopeLocal) DynamicRecommendations() []DynamicRecommendation {
	if sl == nil {
		return nil
	}
	return sl.ext().dynRec
}

// CollectNameRecs walks the currently-mapped non-locked symbols and converts
// them into name recommendations (used before ScopeLocal::restructureVarnode
// rebuilds the layout from raw varnodes). The mapping is preserved for
// post-decompile name reattachment.
// C++ parity: varmap.cc ScopeLocal::collectNameRecs
func (sl *ScopeLocal) CollectNameRecs() {
	if sl == nil {
		return
	}
	ext := sl.ext()
	// Walk a snapshot because AddRecommendName mutates ext.entries.
	snapshot := append([]*SymbolEntry(nil), ext.entries...)
	for _, entry := range snapshot {
		if entry == nil || entry.symbol == nil {
			continue
		}
		sym := entry.symbol
		if sym.IsTypeLocked() {
			// Locked data-type -> fold into a type recommendation so the
			// next restructure pass re-seeds the same type.
			if sym.Type() != nil {
				sl.AddTypeRecommendation(entry.Addr(), sym.Type())
			}
			continue
		}
		if sym.IsNameLocked() || sym.IsNameUndefined() {
			continue
		}
		sl.AddRecommendName(sym)
	}
}

// ResetLocalWindowExt is a hook for the ScopeLocal::resetLocalWindow path that
// needs to clear the extended state in addition to the base maps. The base
// ResetLocalWindow in scopelocal.go continues to wipe paramByVn/localByVn;
// this helper drops the extended SymbolEntry layout.
// C++ parity: ScopeLocal::resetLocalWindow (SymbolEntry wipe half)
func (sl *ScopeLocal) ResetLocalWindowExt() {
	if sl == nil {
		return
	}
	ext := sl.ext()
	ext.entries = nil
	ext.dynEntries = nil
	ext.vnMap = make(map[*Varnode]*SymbolEntry)
}

// RestructureVarnode rebuilds the stack-slot symbol layout from the current
// Varnode population. This is the real entry point that downstream
// ActionRestructureVarnode calls; it replaces whatever entries exist with a
// fresh set derived from live varnodes in the scope's stack space.
//
// The full C++ implementation assembles RangeHint objects via MapState and
// merges overlapping hints; here we follow the same outer structure but rely
// on the simpler per-offset grouping already in BuildFromVarnodes. A full
// RangeHint port is TODO once MapState / AliasChecker land.
// C++ parity: varmap.cc ScopeLocal::restructureVarnode
func (sl *ScopeLocal) RestructureVarnode(fd *Funcdata, aliasyes bool) bool {
	if sl == nil || fd == nil {
		return false
	}
	ext := sl.ext()
	// Carry any non-locked names forward as recommendations.
	sl.CollectNameRecs()
	// Drop old entries and vnMap before rebuilding from live varnodes.
	ext.entries = nil
	ext.vnMap = make(map[*Varnode]*SymbolEntry)

	// Turn the stack Varnodes and the pointers into the frame into RangeHints
	// and sweep them into a disjoint cover of Symbols.
	// C++ parity: ScopeLocal::restructureVarnode (gatherVarnodes, gatherOpen,
	// restructure).
	if space := sl.SpaceID(); space != nil && sl.model != nil {
		ms := &mapState{sl: sl, space: space, types: sharedTypeFactory,
			defaultType: sharedTypeFactory.GetBase(1, TYPE_UNKNOWN, "")}
		ms.gatherVarnodes(fd)
		for _, h := range sl.gatherOpen(fd) {
			ms.addRange(h.start, h.elem, 0, rhOpen, h.minItems)
		}
		sl.restructureMap(ms)
		sl.fakeInputSymbols(fd)
	}

	alias := sl.gatherAlias(fd)
	if aliasyes {
		sl.markUnaliased(alias)
	}
	if len(alias) > 0 && alias[0] == 0 { // A zero offset use of the stack pointer exists
		sl.annotateRawStackPtr(fd)
	}
	// Re-stamp existing stack Varnodes with their (just-built) SymbolEntry flags --
	// chiefly addrtied. The Varnodes were created by StackPtrFlow before any symbol
	// existed, so setVarnodeProperties at their creation time found nothing. Now that
	// the entries exist, stamp them so addrtied is set BEFORE the speculative type-merge
	// (mergeByDatatype) runs in the merge group; its addr-tied guard needs the flag to
	// keep distinct stack locals apart. C++ sets these properties at Varnode creation
	// because its default scope already carries the entries; Gosleigh builds the stack
	// scope lazily, so it re-stamps here. setVarnodeProperties is idempotent (skips
	// already-mapped Varnodes), so repeated mainloop passes do not oscillate.
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() || vn.Space() == nil {
			continue
		}
		if isStackSpace(vn, sl.model) {
			fd.setVarnodeProperties(vn)
		}
	}
	// overlapProblems == false because the per-offset grouping cannot
	// produce overlaps by construction.
	return false
}

// annotateRawStackPtr routes every direct (non-additive) use of the raw stack
// pointer through a placeholder PTRSUB(sp,#0), so the use is typed and printed
// as a reference to the stack frame.
// C++ parity: varmap.cc ScopeLocal::annotateRawStackPtr.
func (sl *ScopeLocal) annotateRawStackPtr(fd *Funcdata) {
	if !fd.HasTypeRecoveryStarted() {
		return
	}
	spVn := fd.findSpacebaseInput(sl.SpaceID())
	if spVn == nil {
		return
	}
	var refOps []*PcodeOp
	for _, op := range spVn.DescendIter() {
		if op.EvalType() == PcodeOpSpecial && !op.IsCall() {
			continue
		}
		switch op.Code() {
		case CPUI_INT_ADD, CPUI_PTRSUB, CPUI_PTRADD:
			continue
		}
		refOps = append(refOps, op)
	}
	for _, op := range refOps {
		slot := op.GetSlot(spVn)
		ptrsub := fd.newUntypedOpBefore(op, CPUI_PTRSUB, spVn.Size(), spVn, fd.NewConstant(spVn.Size(), 0))
		fd.OpSetInput(op, ptrsub.Output(), slot)
	}
}

// gatherAlias returns the sorted stack offsets at which a pointer into the
// frame is formed (the start of each potentially aliased region).
// C++ parity: varmap.cc AliasChecker::gather/gatherInternal + sortAlias, as
// used by MapState::gatherOpen; the alias boundary used by hasLocalAlias is
// not needed here.
func (sl *ScopeLocal) gatherAlias(fd *Funcdata) []uint64 {
	if sl.model == nil || sl.model.StackSpace == nil {
		return nil
	}
	point := sl.model.StackSpace.GetSpacebase(0)
	if point.Space == nil {
		return nil
	}
	spacebase := fd.GetVarnodeBank().FindInput(point.Size, address.Address{Space: point.Space, Offset: point.Offset})
	if spacebase == nil {
		return nil // No possible alias
	}
	var alias []uint64
	for _, ab := range gatherAdditiveBase(spacebase) {
		alias = append(alias, aliasGatherOffset(ab.base)) // word size 1: already byte offsets
	}
	sort.Slice(alias, func(i, j int) bool { return alias[i] < alias[j] })
	return alias
}

// aliasBlockLevel is the default Architecture::alias_block_level: locked
// structures and arrays block aliases, primitive types do not.
const aliasBlockLevel = 2

// markUnaliased marks each stack Symbol that no alias start can reach as
// nolocalalias. An alias reaches every Symbol after it until an unmapped gap
// in the scope's ranges, a locked aggregate, or more than 0xffff bytes.
// C++ parity: varmap.cc ScopeLocal::markUnaliased (1332-1384), walking the
// scope's range tree with the markNotMapped holes cut out.
func (sl *ScopeLocal) markUnaliased(alias []uint64) {
	ext := sl.ext()
	entries := append([]*SymbolEntry(nil), ext.entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Addr().Offset < entries[j].Addr().Offset })
	ranges := sl.scopeRanges()
	ri := 0
	aliason := false
	var curalias uint64
	i := 0
	for _, entry := range entries {
		curoff := entry.Addr().Offset + uint64(entry.Size()) - 1
		for i < len(alias) && alias[i] <= curoff {
			aliason = true
			curalias = alias[i]
			i++
		}
		// Aliases shouldn't go through unmapped regions of the local variables
		for ; ri < len(ranges); ri++ {
			first, last := ranges[ri][0], ranges[ri][1]
			if first > curalias && curoff >= first {
				aliason = false
			}
			if last >= curoff {
				break // Symbol is not past the end of this mapped range
			}
			if last > curalias {
				aliason = false // Past the end of the range AND past the last alias offset
			}
		}
		sym := entry.Symbol()
		// Enough distance between the symbol and the last alias resets aliasing
		// (primarily between stack parameters and stack locals).
		if aliason && curoff-curalias > 0xffff {
			aliason = false
		}
		if !aliason {
			sym.SetFlags(VarnodeNoLocalAlias)
		}
		if sym.IsTypeLocked() && aliasBlockLevel != 0 {
			switch meta := sym.Type().Metatype(); {
			case aliasBlockLevel == 3:
				aliason = false
			case meta == TYPE_STRUCT:
				aliason = false
			case meta == TYPE_ARRAY && aliasBlockLevel > 1:
				aliason = false
			}
		}
	}
}

// buildVariableName picks a default display name for a stack slot.
//
// Scalar slots keep the Java-layer spelling (see stackLocalName): every scalar
// frame slot in the goldens reaches the decompiler already named by the Ghidra
// Program DB. A decompiler-recovered aggregate has no Program-DB variable --
// the Java stack-frame analysis never allocated one for that byte range -- so
// the C++ core name is the one that survives into the listing. The x64_auto
// array_init_then_sum golden shows both spellings in one function:
// local_58 / local_54 (Java) next to aiStack_48 (core).
//
// C++ parity: ScopeLocal::buildVariableName (varmap.cc:548).
func (sl *ScopeLocal) buildVariableName(addr address.Address, pc address.Address, ct Datatype) string {
	if sl == nil {
		return ""
	}
	// A host symbol at this offset is name-locked: its name wins over both
	// spellings below.
	if n, ok := sl.ext().hostLocals[addr.Offset]; ok && n != "" {
		return n
	}
	name := ""
	if ct == nil || ct.Metatype() != TYPE_ARRAY {
		name = sl.stackLocalName(addr.Offset)
	}
	if name == "" {
		growsNegative := true
		if e := sl.ext(); e != nil {
			growsNegative = e.stackGrows
		}
		name = sl.coreStackName(addr.Space, addr.Offset, growsNegative, ct)
	}
	return name
}

// containsRange reports whether the [e.first, e.last] range wholly contains
// [addr, addr+size). A zero size degenerates to an exact-start match.
func containsRange(e *SymbolEntry, addr uint64, size int32) bool {
	if e == nil || e.size <= 0 {
		return false
	}
	first := e.First()
	last := e.Last()
	if addr < first {
		return false
	}
	if size <= 0 {
		return addr <= last
	}
	end := addr + uint64(size) - 1
	return end <= last
}

