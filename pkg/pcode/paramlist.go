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
	"gosleigh/pkg/address"
)

// This file is a faithful port of the parameter-storage model machinery that
// Ghidra uses to recover a function's formal input list from a set of Varnode
// trials: ParamEntry + ParamListStandard (fspec.cc / fspec.hh).
//
// It replaces the earlier IsParamOffset threshold heuristic with the C++
// findEntry / buildTrialMap / fillinMap algorithm, including the generation of
// unreferenced ("unref") trials for storage slots that have no representative
// Varnode but must still be recovered as parameters.
//
// C++ parity: ParamEntry (fspec.cc:60-577), ParamListStandard (fspec.cc:597-1313).

// typeClass mirrors the subset of Ghidra type_class (type.hh:132) needed for
// parameter-storage classification. Only GENERAL and FLOAT participate in the
// x86/x64 recovery paths exercised here.
type typeClass int32

const (
	typeclassGeneral typeClass = 0   // TYPECLASS_GENERAL
	typeclassFloat   typeClass = 1   // TYPECLASS_FLOAT
	typeclassClass4  typeClass = 103 // TYPECLASS_CLASS4 sentinel
)

// ParamEntry boolean property flags (subset of ParamEntry enum, fspec.hh:86-99).
const (
	peForceLeftJustify uint32 = 1
	peReverseStack     uint32 = 2
	peIsGrouped        uint32 = 0x200
)

// paramEntry is the full port of Ghidra ParamEntry: a contiguous range of
// memory that can pass either a single parameter (exclusion, alignment==0) or,
// as a resource, multiple parameters allocated in aligned slots (alignment!=0).
//
// The denormalized fields group/exclusion/reverseStack are kept in sync with
// groupSet[0]/alignment/flags so ParamTrial.Less (paramactive.go, which reads
// them directly) needs no change.
//
// C++ parity: fspec.hh class ParamEntry.
type paramEntry struct {
	flags       uint32
	tclass      typeClass
	groupSet    []int32
	space       *address.Space
	spaceIndex  uint16
	bigEndian   bool
	addressbase uint64
	size        int32 // maximum size of the range in bytes
	minsize     int32 // minimum bytes for a logical value
	alignment   int32 // 0 means exclusion (single value)
	numslots    int32

	// Denormalized mirrors read directly by ParamTrial ordering (paramactive.go).
	group        int32
	exclusion    bool
	reverseStack bool
}

func (pe *paramEntry) getGroup() int32       { return pe.groupSet[0] }
func (pe *paramEntry) getAllGroups() []int32 { return pe.groupSet }
func (pe *paramEntry) getSize() int32        { return pe.size }
func (pe *paramEntry) getMinSize() int32     { return pe.minsize }
func (pe *paramEntry) getAlign() int32       { return pe.alignment }
func (pe *paramEntry) getType() typeClass    { return pe.tclass }
func (pe *paramEntry) isExclusion() bool     { return pe.alignment == 0 }
func (pe *paramEntry) isReverseStack() bool  { return pe.flags&peReverseStack != 0 }

// isLeftJustified reports whether the logical value is left-justified within its
// container. C++ parity: ParamEntry::isLeftJustified (fspec.hh:123).
func (pe *paramEntry) isLeftJustified() bool {
	return pe.flags&peForceLeftJustify != 0 || !pe.bigEndian
}

// groupOverlap reports whether two entries share any group id.
// C++ parity: ParamEntry::groupOverlap (fspec.cc:157).
func (pe *paramEntry) groupOverlap(op2 *paramEntry) bool {
	i, j := 0, 0
	valThis := pe.groupSet[i]
	valOther := op2.groupSet[j]
	for valThis != valOther {
		if valThis < valOther {
			i++
			if i >= len(pe.groupSet) {
				return false
			}
			valThis = pe.groupSet[i]
		} else {
			j++
			if j >= len(op2.groupSet) {
				return false
			}
			valOther = op2.groupSet[j]
		}
	}
	return true
}

// justifiedContain returns the endian-aware alignment of the given range inside
// this entry, or -1 if not contained. C++ parity: ParamEntry::justifiedContain
// (fspec.cc:248). Join records are not modeled (no join pentries in the ABIs
// exercised here).
func (pe *paramEntry) justifiedContain(addr address.Address, sz int32) int32 {
	if pe.alignment == 0 {
		entry := address.Address{Space: pe.space, Offset: pe.addressbase}
		return addressJustifiedContain(entry, pe.size, addr, sz, pe.flags&peForceLeftJustify != 0)
	}
	if addr.Space == nil || addr.Space.Index != pe.spaceIndex {
		return -1
	}
	startaddr := addr.Offset
	if startaddr < pe.addressbase {
		return -1
	}
	endaddr := startaddr + uint64(sz) - 1
	if endaddr < startaddr {
		return -1
	}
	if endaddr > pe.addressbase+uint64(pe.size)-1 {
		return -1
	}
	startaddr -= pe.addressbase
	endaddr -= pe.addressbase
	if !pe.isLeftJustified() {
		res := int32((endaddr + 1) % uint64(pe.alignment))
		if res == 0 {
			return 0
		}
		return pe.alignment - res
	}
	return int32(startaddr % uint64(pe.alignment))
}

// getSlot returns the slot index occupied by addr+skip. C++ parity:
// ParamEntry::getSlot (fspec.cc:407).
func (pe *paramEntry) getSlot(addr address.Address, skip int32) int32 {
	res := pe.groupSet[0]
	if pe.alignment != 0 {
		diff := addr.Offset + uint64(skip) - pe.addressbase
		baseslot := int32(diff / uint64(pe.alignment))
		if pe.isReverseStack() {
			res += (pe.numslots - 1) - baseslot
		} else {
			res += baseslot
		}
	} else if skip != 0 {
		res = pe.groupSet[len(pe.groupSet)-1]
	}
	return res
}

// getAddrBySlot computes the storage address for a parameter of the given size,
// consuming slots from *slotnum. Returns an invalid (nil-space) address when the
// size is too small or there are not enough slots. C++ parity:
// ParamEntry::getAddrBySlot (fspec.cc:450). smallsize_floatext and typeAlign
// padding are not modeled: typeAlign is always 1 at the call sites here.
func (pe *paramEntry) getAddrBySlot(slotnum *int32, sz int32) address.Address {
	var res address.Address
	var spaceused int32
	if sz < pe.minsize {
		return res
	}
	if pe.alignment == 0 {
		if *slotnum != 0 {
			return res
		}
		if sz > pe.size {
			return res
		}
		res = address.Address{Space: pe.space, Offset: pe.addressbase}
		spaceused = pe.size
	} else {
		slotsused := sz / pe.alignment
		if sz%pe.alignment != 0 {
			slotsused++
		}
		if *slotnum+slotsused > pe.numslots {
			return res
		}
		spaceused = slotsused * pe.alignment
		var index int32
		if pe.isReverseStack() {
			index = pe.numslots - *slotnum - slotsused
		} else {
			index = *slotnum
		}
		res = address.Address{Space: pe.space, Offset: pe.addressbase + uint64(index*pe.alignment)}
		*slotnum += slotsused
	}
	if !pe.isLeftJustified() {
		res = res.Add(uint64(spaceused - sz))
	}
	return res
}

// containsOffset reports whether addr lies within this entry's range in the same
// space. Used by findEntry's resolver walk.
func (pe *paramEntry) containsOffset(addr address.Address) bool {
	if addr.Space == nil || addr.Space.Index != pe.spaceIndex {
		return false
	}
	return addr.Offset >= pe.addressbase && addr.Offset <= pe.addressbase+uint64(pe.size)-1
}

// ParamListStandard is the faithful port of the standard parameter list model:
// an ordered list of ParamEntry plus the resource-section boundaries. It maps a
// set of Varnode trials (ParamActive) onto formal parameter storage.
//
// C++ parity: fspec.hh class ParamListStandard (recovery path: findEntry,
// buildTrialMap, fillinMap and helpers).
type ParamListStandard struct {
	entry         []*paramEntry
	numgroup      int32
	resourceStart []int32
}

// ParamEntrySpec is the resolved description of one <pentry> that the caller
// (bridge, which owns the register/stack address spaces) hands to
// NewParamListStandard. It decouples cspec/register resolution (sla) from the
// pcode package.
type ParamEntrySpec struct {
	Space       *address.Space
	BigEndian   bool
	AddressBase uint64
	MinSize     int32
	MaxSize     int32
	Align       int32
	IsFloat     bool
	Grouped     bool
	GroupID     int32
}

// NewParamListStandard builds a ParamListStandard from resolved pentry specs, in
// document order. It mirrors ParamListStandard::decode's group-id assignment and
// resourceStart construction (fspec.cc:1451, parsePentry:1226).
func NewParamListStandard(specs []ParamEntrySpec) *ParamListStandard {
	pl := &ParamListStandard{}
	var numgroup int32
	const splitFloat = true
	lastClass := typeclassClass4
	for _, s := range specs {
		grp := s.GroupID
		pe := &paramEntry{
			space:       s.Space,
			bigEndian:   s.BigEndian,
			addressbase: s.AddressBase,
			size:        s.MaxSize,
			minsize:     s.MinSize,
			alignment:   s.Align,
			groupSet:    []int32{grp},
		}
		if s.Space != nil {
			pe.spaceIndex = s.Space.Index
		}
		pe.tclass = typeclassGeneral
		if s.IsFloat {
			pe.tclass = typeclassFloat
		}
		if pe.alignment == pe.size { // decode(): alignment==size means exclusion
			pe.alignment = 0
		}
		if pe.alignment != 0 {
			pe.numslots = pe.size / pe.alignment
		} else {
			pe.numslots = 1
		}
		if s.Grouped {
			pe.flags |= peIsGrouped
		}
		// reverse_stack is set only for positive-growth stacks (!normalstack); the
		// x86/x64 ABIs exercised here are all normalstack, so it stays clear.
		pe.group = pe.groupSet[0]
		pe.exclusion = pe.alignment == 0
		pe.reverseStack = pe.flags&peReverseStack != 0

		currentClass := pe.tclass
		if s.Grouped {
			currentClass = typeclassGeneral
		}
		// splitFloat: push a resource-section boundary when the storage class
		// changes between consecutive entries. In C++ (parsePentry, fspec.cc:1235)
		// lastClass < currentClass is a spec ordering error (throw); our specs
		// order specific classes before general so it never trips. The CLASS4
		// sentinel is the largest value, so the FIRST entry always takes the push
		// branch, seeding resourceStart[0]=groupid (separateSections reads [1]).
		if splitFloat && lastClass != currentClass {
			pl.resourceStart = append(pl.resourceStart, grp)
		}
		lastClass = currentClass

		pl.entry = append(pl.entry, pe)
		maxgroup := pe.groupSet[len(pe.groupSet)-1] + 1
		if maxgroup > numgroup {
			numgroup = maxgroup
		}
	}
	pl.numgroup = numgroup
	pl.resourceStart = append(pl.resourceStart, numgroup) // fspec.cc:1502
	return pl
}

// findEntry returns the first ParamEntry containing the given range. When just
// is true the range must be properly justified within the entry. C++ parity:
// ParamListStandard::findEntry (fspec.cc:661). Entries are walked in insertion
// order, matching the resolver's position sub-sort for the non-overlapping
// register/stack ABIs modeled here.
func (pl *ParamListStandard) findEntry(loc address.Address, size int32, just bool) *paramEntry {
	for _, pe := range pl.entry {
		if !pe.containsOffset(loc) {
			continue
		}
		if pe.getMinSize() > size {
			continue
		}
		if !just || pe.justifiedContain(loc, size) == 0 {
			return pe
		}
	}
	return nil
}

// possibleParam reports whether the given range could be a parameter under this
// model. C++ parity: ParamListStandard::possibleParam (fspec.cc:1354).
func (pl *ParamListStandard) possibleParam(loc address.Address, size int32) bool {
	return pl.findEntry(loc, size, true) != nil
}

// selectUnreferenceEntry returns the entry in the given group that best matches
// the preferred storage class. C++ parity:
// ParamListStandard::selectUnreferenceEntry (fspec.cc:820).
func (pl *ParamListStandard) selectUnreferenceEntry(grp int32, prefType typeClass) *paramEntry {
	bestScore := -1
	var bestEntry *paramEntry
	for _, pe := range pl.entry {
		if pe.getGroup() != grp {
			continue
		}
		var curScore int
		if pe.getType() == prefType {
			curScore = 2
		} else if prefType == typeclassGeneral {
			curScore = 1
		} else {
			curScore = 0
		}
		if curScore > bestScore {
			bestScore = curScore
			bestEntry = pe
		}
	}
	return bestEntry
}

// buildTrialMap associates each trial with a model ParamEntry, fills holes in
// the resource list with unreferenced trials, and sorts the trials. C++ parity:
// ParamListStandard::buildTrialMap (fspec.cc:849).
func (pl *ParamListStandard) buildTrialMap(active *ParamActive) {
	var hitlist []*paramEntry
	floatCount := 0
	intCount := 0

	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		entrySlot := pl.findEntry(pt.GetAddress(), pt.GetSize(), true)
		if entrySlot == nil {
			pt.MarkNoUse()
			continue
		}
		pt.SetEntry(entrySlot, 0)
		if pt.IsActive() {
			if entrySlot.getType() == typeclassFloat {
				floatCount++
			} else {
				intCount++
			}
		}
		grp := entrySlot.getGroup()
		for int32(len(hitlist)) <= grp {
			hitlist = append(hitlist, nil)
		}
		if hitlist[grp] == nil {
			hitlist[grp] = entrySlot
		}
	}

	// Create unref trials for any group without a representative that occurs
	// before a group that does have one. C++ parity: fspec.cc:886-935.
	for i := 0; i < len(hitlist); i++ {
		curentry := hitlist[i]
		if curentry == nil {
			pref := typeclassGeneral
			if floatCount > intCount {
				pref = typeclassFloat
			}
			curentry = pl.selectUnreferenceEntry(int32(i), pref)
			if curentry == nil {
				continue
			}
			sz := curentry.getSize()
			if !curentry.isExclusion() {
				sz = curentry.getAlign()
			}
			nextslot := int32(0)
			addr := curentry.getAddrBySlot(&nextslot, sz)
			trialpos := active.NumTrials()
			active.RegisterTrial(addr, sz)
			pt := active.Trial(trialpos)
			pt.MarkUnref()
			pt.SetEntry(curentry, 0)
		} else if !curentry.isExclusion() {
			var slotlist []int32
			for j := 0; j < active.NumTrials(); j++ {
				pt := active.Trial(j)
				if pt.GetEntry() != curentry {
					continue
				}
				slot := curentry.getSlot(pt.GetAddress(), 0) - curentry.getGroup()
				endslot := curentry.getSlot(pt.GetAddress(), pt.GetSize()-1) - curentry.getGroup()
				if endslot < slot {
					slot, endslot = endslot, slot
				}
				for int32(len(slotlist)) <= endslot {
					slotlist = append(slotlist, 0)
				}
				for slot <= endslot {
					slotlist[slot] = 1
					slot++
				}
			}
			for j := 0; j < len(slotlist); j++ {
				if slotlist[j] == 0 {
					nextslot := int32(j)
					addr := curentry.getAddrBySlot(&nextslot, curentry.getAlign())
					trialpos := active.NumTrials()
					active.RegisterTrial(addr, curentry.getAlign())
					pt := active.Trial(trialpos)
					pt.MarkUnref()
					pt.SetEntry(curentry, 0)
				}
			}
		}
	}
	active.SortTrials()
}

// separateSections computes the [start,stop) trial index ranges for each
// resource section. C++ parity: ParamListStandard::separateSections
// (fspec.cc:946).
func (pl *ParamListStandard) separateSections(active *ParamActive) []int32 {
	numtrials := active.NumTrials()
	currentTrial := 0
	nextGroup := pl.resourceStart[1]
	nextSection := 2
	trialStart := []int32{int32(currentTrial)}
	for ; currentTrial < numtrials; currentTrial++ {
		pt := active.Trial(currentTrial)
		if pt.GetEntry() == nil {
			continue
		}
		if pt.GetEntry().getGroup() >= nextGroup {
			nextGroup = pl.resourceStart[nextSection]
			nextSection++
			trialStart = append(trialStart, int32(currentTrial))
		}
	}
	trialStart = append(trialStart, int32(numtrials))
	return trialStart
}

// markGroupNoUse marks all trials intersecting the active trial's group set as
// definitely not used, except the active trial. C++ parity:
// ParamListStandard::markGroupNoUse (fspec.cc:974).
func (pl *ParamListStandard) markGroupNoUse(active *ParamActive, activeTrial, trialStart int32) {
	numTrials := int32(active.NumTrials())
	activeEntry := active.Trial(int(activeTrial)).GetEntry()
	for i := trialStart; i < numTrials; i++ {
		if i == activeTrial {
			continue
		}
		other := active.Trial(int(i))
		if other.IsDefinitelyNotUsed() {
			continue
		}
		if !other.GetEntry().groupOverlap(activeEntry) {
			break
		}
		other.MarkNoUse()
	}
}

// markBestInactive selects the most likely active trial among inactive ones in a
// group and marks the others not used. C++ parity:
// ParamListStandard::markBestInactive (fspec.cc:997).
func (pl *ParamListStandard) markBestInactive(active *ParamActive, group, groupStart int32, prefType typeClass) {
	numTrials := int32(active.NumTrials())
	bestTrial := int32(-1)
	bestScore := -1
	for i := groupStart; i < numTrials; i++ {
		trial := active.Trial(int(i))
		if trial.IsDefinitelyNotUsed() {
			continue
		}
		entry := trial.GetEntry()
		if entry.getGroup() != group {
			break
		}
		if len(entry.getAllGroups()) > 1 {
			continue
		}
		score := 0
		if trial.HasAncestorRealistic() {
			score += 5
			if trial.HasAncestorSolid() {
				score += 5
			}
		}
		if entry.getType() == prefType {
			score += 1
		}
		if score > bestScore {
			bestScore = score
			bestTrial = i
		}
	}
	if bestTrial >= 0 {
		pl.markGroupNoUse(active, bestTrial, groupStart)
	}
}

// forceExclusionGroup enforces that at most one active trial survives per
// exclusion group. C++ parity: ParamListStandard::forceExclusionGroup
// (fspec.cc:1032).
func (pl *ParamListStandard) forceExclusionGroup(active *ParamActive) {
	numTrials := int32(active.NumTrials())
	curGroup := int32(-1)
	groupStart := int32(-1)
	inactiveCount := 0
	for i := int32(0); i < numTrials; i++ {
		curtrial := active.Trial(int(i))
		if curtrial.IsDefinitelyNotUsed() || !curtrial.GetEntry().isExclusion() {
			continue
		}
		grp := curtrial.GetEntry().getGroup()
		if grp != curGroup {
			if inactiveCount > 1 {
				pl.markBestInactive(active, curGroup, groupStart, typeclassGeneral)
			}
			curGroup = grp
			groupStart = i
			inactiveCount = 0
		}
		if curtrial.IsActive() {
			pl.markGroupNoUse(active, i, groupStart)
		} else {
			inactiveCount++
		}
	}
	if inactiveCount > 1 {
		pl.markBestInactive(active, curGroup, groupStart, typeclassGeneral)
	}
}

// forceNoUse marks every trial above the first definitely-not-used as inactive
// within [start,stop). C++ parity: ParamListStandard::forceNoUse (fspec.cc:1069).
func (pl *ParamListStandard) forceNoUse(active *ParamActive, start, stop int32) {
	seendefnouse := false
	curgroup := int32(-1)
	alldefnouse := false
	for i := start; i < stop; i++ {
		curtrial := active.Trial(int(i))
		if curtrial.GetEntry() == nil {
			continue
		}
		grp := curtrial.GetEntry().getGroup()
		exclusion := curtrial.GetEntry().isExclusion()
		if grp <= curgroup && exclusion {
			if !curtrial.IsDefinitelyNotUsed() {
				alldefnouse = false
			}
		} else {
			if alldefnouse {
				seendefnouse = true
			}
			alldefnouse = curtrial.IsDefinitelyNotUsed()
			curgroup = grp
		}
		if seendefnouse {
			curtrial.MarkInactive()
		}
	}
}

// forceInactiveChain enforces rules about chains of inactive slots within a
// resource section. C++ parity: ParamListStandard::forceInactiveChain
// (fspec.cc:1111).
func (pl *ParamListStandard) forceInactiveChain(active *ParamActive, maxchain, start, stop, groupstart int32) {
	seenchain := false
	chainlength := int32(0)
	max := int32(-1)
	for i := start; i < stop; i++ {
		trial := active.Trial(int(i))
		if trial.IsDefinitelyNotUsed() {
			continue
		}
		if !trial.IsActive() {
			if trial.IsUnref() && active.IsRecoverSubcall() {
				// Only fires for register storage in sub-call recovery; current
				// function recovery uses recoversubcall=false. Retained for
				// faithfulness. C++ parity: fspec.cc:1121.
				if trial.GetAddress().Space != nil && trial.GetAddress().Space.Kind == address.SpaceKindStack {
					seenchain = true
				}
			}
			if i == start {
				chainlength += trial.slotGroup() - groupstart + 1
			} else {
				chainlength += trial.slotGroup() - active.Trial(int(i-1)).slotGroup()
			}
			if chainlength > maxchain {
				seenchain = true
			}
		} else {
			chainlength = 0
			if !seenchain {
				max = i
			}
		}
		if seenchain {
			trial.MarkInactive()
		}
	}
	for i := start; i <= max; i++ {
		trial := active.Trial(int(i))
		if trial.IsDefinitelyNotUsed() {
			continue
		}
		if !trial.IsActive() {
			trial.MarkActive()
		}
	}
}

// FillinMap derives the formal input map for the given trials: it associates
// trials with entries, enforces exclusion/inactivity rules, and marks the
// surviving trials as used. C++ parity: ParamListStandard::fillinMap
// (fspec.cc:1285).
func (pl *ParamListStandard) FillinMap(active *ParamActive) {
	if active.NumTrials() == 0 {
		return
	}
	if len(pl.entry) == 0 {
		return // C++ throws; we no-op faithfully (no entries -> nothing to derive)
	}
	pl.buildTrialMap(active)
	pl.forceExclusionGroup(active)
	trialStart := pl.separateSections(active)
	numSection := len(trialStart) - 1
	for i := 0; i < numSection; i++ {
		pl.forceNoUse(active, trialStart[i], trialStart[i+1])
	}
	for i := 0; i < numSection; i++ {
		pl.forceInactiveChain(active, 2, trialStart[i], trialStart[i+1], pl.resourceStart[i])
	}
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if pt.IsActive() {
			pt.MarkUsed()
		}
	}
}

// addressJustifiedContain ports Address::justifiedContain (address.cc:131): is
// [op2, op2+sz2) contained in [base, base+sz), returning the endian-aware offset
// or -1. forceleft suppresses big-endian right justification.
func addressJustifiedContain(base address.Address, sz int32, op2 address.Address, sz2 int32, forceleft bool) int32 {
	if base.Space != op2.Space {
		return -1
	}
	if op2.Offset < base.Offset {
		return -1
	}
	off1 := base.Offset + uint64(sz-1)
	off2 := op2.Offset + uint64(sz2-1)
	if off2 > off1 {
		return -1
	}
	if base.Space != nil && base.Space.BigEndian && !forceleft {
		return int32(off1 - off2)
	}
	return int32(op2.Offset - base.Offset)
}
