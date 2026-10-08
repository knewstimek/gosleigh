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
	typeclassGeneral   typeClass = 0   // TYPECLASS_GENERAL
	typeclassFloat     typeClass = 1   // TYPECLASS_FLOAT
	typeclassPtr       typeClass = 2   // TYPECLASS_PTR
	typeclassHiddenret typeClass = 3   // TYPECLASS_HIDDENRET
	typeclassClass4    typeClass = 103 // TYPECLASS_CLASS4 sentinel
)

// ParamEntry boolean property flags (subset of ParamEntry enum, fspec.hh:86-99).
const (
	peForceLeftJustify uint32 = 1
	peReverseStack     uint32 = 2
	peExtracheckHigh   uint32 = 0x80
	peExtracheckLow    uint32 = 0x100
	peIsGrouped        uint32 = 0x200
	peOverlapping      uint32 = 0x400
	peFirstStorage     uint32 = 0x800
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
	// joinrec is the record of a join-space entry (pieces most significant
	// first), nil otherwise. C++ parity: ParamEntry::joinrec.
	joinrec *address.JoinRecord

	// pos is the entry's place in its list (document order). C++ orders
	// trials of one group by ParamEntry pointer; the entries live in a
	// std::list built in that order, so its nodes ascend in practice.
	pos int32

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

// isFirstInClass: the entry is the first of its storage class.
// C++ parity: ParamEntry::isFirstInClass.
func (pe *paramEntry) isFirstInClass() bool { return pe.flags&peFirstStorage != 0 }

// isParamCheckHigh / isParamCheckLow: a join piece overlapping an earlier
// entry needs extra checks. C++ parity: ParamEntry::isParamCheckHigh/Low.
func (pe *paramEntry) isParamCheckHigh() bool { return pe.flags&peExtracheckHigh != 0 }
func (pe *paramEntry) isParamCheckLow() bool  { return pe.flags&peExtracheckLow != 0 }

// resolveJoin takes the groups of the earlier entries the join pieces overlap.
// C++ parity: ParamEntry::resolveJoin / findEntryByStorage.
func (pe *paramEntry) resolveJoin(prev []*paramEntry) {
	if pe.joinrec == nil {
		return
	}
	var groups []int32
	for i, piece := range pe.joinrec.Pieces {
		for j := len(prev) - 1; j >= 0; j-- { // Most recent first
			e := prev[j]
			if e.joinrec == nil && e.space == piece.Space && e.addressbase == piece.Offset {
				groups = append(groups, e.groupSet...)
				// The overlapping most significant part puts extra checks on
				// the least significant part, and vice versa
				if i == 0 {
					pe.flags |= peExtracheckLow
				} else {
					pe.flags |= peExtracheckHigh
				}
				break
			}
		}
	}
	if len(groups) == 0 {
		return // C++ throws: a join must overlap a previous entry
	}
	sort.Slice(groups, func(a, b int) bool { return groups[a] < groups[b] })
	pe.groupSet = groups
	pe.flags |= peOverlapping
}

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
	if pe.joinrec != nil {
		res := int32(0)
		for i := len(pe.joinrec.Pieces) - 1; i >= 0; i-- { // Least significant first
			v := pe.joinrec.Pieces[i]
			cur := addressJustifiedContain(v.Addr(), v.Size, addr, sz, false)
			if cur < 0 {
				res += v.Size // Skipped this many less significant bytes
			} else {
				return res + cur
			}
		}
		return -1 // Not contained at all
	}
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

// possibleParamWithSlot reports whether the storage could be a parameter and,
// if so, its starting slot and the number of slots it covers.
// C++ parity: fspec.cc ParamListStandard::possibleParamWithSlot.
func (pl *ParamListStandard) possibleParamWithSlot(loc address.Address, size int32) (slot, slotsize int32, ok bool) {
	pe := pl.findEntry(loc, size, true)
	if pe == nil {
		return 0, 0, false
	}
	slot = pe.getSlot(loc, 0)
	if pe.isExclusion() {
		slotsize = pe.groupSet[len(pe.groupSet)-1] - pe.groupSet[0] + 1 // getGroupSize
	} else {
		slotsize = (size-1)/pe.getAlign() + 1
	}
	return slot, slotsize, true
}

// getAddrBySlot computes the storage address for a parameter of the given size,
// consuming slots from *slotnum. Returns an invalid (nil-space) address when the
// size is too small or there are not enough slots. C++ parity:
// ParamEntry::getAddrBySlot (fspec.cc:450). smallsize_floatext and typeAlign
// padding are not modeled: typeAlign is always 1 at the call sites here.
func (pe *paramEntry) getAddrBySlot(slotnum *int32, sz, typeAlign int32) address.Address {
	return pe.getAddrBySlotJustify(slotnum, sz, typeAlign, !pe.isLeftJustified())
}

// getAddrBySlotJustify is getAddrBySlot with an explicit justification: when
// justifyRight the leading bytes of the slot space are padding.
// C++ parity: ParamEntry::getAddrBySlot(slotnum,sz,typeAlign,justifyRight).
func (pe *paramEntry) getAddrBySlotJustify(slotnum *int32, sz, typeAlign int32, justifyRight bool) address.Address {
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
		if typeAlign > pe.alignment {
			if tmp := (*slotnum * pe.alignment) % typeAlign; tmp != 0 {
				*slotnum += (typeAlign - tmp) / pe.alignment // Waste slots to achieve typeAlign
			}
		}
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
	if justifyRight {
		res = res.Add(uint64(spaceused - sz))
	}
	return res
}

// containsOffset reports whether addr lies within this entry's range in the same
// space. Used by findEntry's resolver walk.
func (pe *paramEntry) containsOffset(addr address.Address) bool {
	if pe.joinrec != nil { // The resolver holds each piece range
		for _, v := range pe.joinrec.Pieces {
			if addr.Space == v.Space && addr.Offset >= v.Offset && addr.Offset <= v.Offset+uint64(v.Size)-1 {
				return true
			}
		}
		return false
	}
	if addr.Space == nil || addr.Space.Index != pe.spaceIndex {
		return false
	}
	return addr.Offset >= pe.addressbase && addr.Offset <= pe.addressbase+uint64(pe.size)-1
}

// containedBy reports whether this entry's whole range fits inside the given
// range. C++ parity: ParamEntry::containedBy (fspec.cc:199). Join entries are
// not modeled (no join pentries in the ABIs exercised here).
func (pe *paramEntry) containedBy(addr address.Address, sz int32) bool {
	if addr.Space == nil || addr.Space.Index != pe.spaceIndex {
		return false
	}
	if pe.addressbase < addr.Offset {
		return false
	}
	entryoff := pe.addressbase + uint64(pe.size) - 1
	rangeoff := addr.Offset + uint64(sz) - 1
	return entryoff <= rangeoff
}

// ParamEntry containment codes: how a storage range relates to the parameter
// entries of a ParamList. C++ parity: fspec.hh ParamEntry enum (fspec.hh:100-105);
// the ordinal values match so a straight port of the switch logic reads the same.
const (
	peNoContainment       = 0 // range neither contains nor is contained by an entry
	peContainsUnjustified = 1 // an entry contains the range, but not its least significant bytes
	peContainsJustified   = 2 // an entry contains the range as its least significant bytes
	peContainedBy         = 3 // the range contains at least one entry
)

// characterizeAsParam classifies how the given range relates to this list's
// parameter entries. C++ parity: ParamListStandard::characterizeAsParam
// (fspec.cc:682). The C++ version drives the walk from a ParamEntryResolver
// (an interval map keyed by offset); Gosleigh keeps the entries in document
// order and reproduces the same two phases explicitly:
//   - phase 1 walks the entries whose range covers loc (resolver->find(offset)),
//   - phase 2 walks the entries that merely *start* inside [loc, loc+size)
//     (resolver->find_end(offset+size-1)), which is how a range wider than an
//     entry is recognized as contained_by.
func (pl *ParamListStandard) characterizeAsParam(loc address.Address, size int32) int {
	if pl == nil || loc.Space == nil || size <= 0 {
		return peNoContainment
	}
	resContains := false
	resContainedBy := false
	for _, pe := range pl.entry {
		if !pe.containsOffset(loc) {
			continue
		}
		off := pe.justifiedContain(loc, size)
		if off == 0 {
			return peContainsJustified
		} else if off > 0 {
			resContains = true
		}
		if pe.isExclusion() && pe.containedBy(loc, size) {
			resContainedBy = true
		}
	}
	if resContains {
		return peContainsUnjustified
	}
	if resContainedBy {
		return peContainedBy
	}
	last := loc.Offset + uint64(size) - 1
	for _, pe := range pl.entry {
		if pe.containsOffset(loc) {
			continue // already visited in phase 1
		}
		if loc.Space.Index != pe.spaceIndex {
			continue
		}
		if pe.addressbase < loc.Offset || pe.addressbase > last {
			continue
		}
		if pe.isExclusion() && pe.containedBy(loc, size) {
			return peContainedBy
		}
	}
	return peNoContainment
}

// getContainer returns the slot-aligned storage of this entry holding the
// given range. C++ parity: ParamEntry::getContainer.
func (pe *paramEntry) getContainer(addr address.Address, sz int32) (address.Address, int32, bool) {
	endaddr := addr
	endaddr.Offset += uint64(sz - 1)
	if pe.joinrec != nil {
		for i := len(pe.joinrec.Pieces) - 1; i >= 0; i-- { // least significant first
			v := pe.joinrec.Pieces[i]
			if overlaps(addr, 1, v.Addr(), v.Size) && overlaps(endaddr, 1, v.Addr(), v.Size) {
				return v.Addr(), v.Size, true
			}
		}
		return address.Address{}, 0, false
	}
	entry := address.Address{Space: pe.space, Offset: pe.addressbase}
	if !overlaps(addr, 1, entry, pe.size) || !overlaps(endaddr, 1, entry, pe.size) {
		return address.Address{}, 0, false
	}
	if pe.alignment == 0 {
		return entry, pe.size, true
	}
	al := (addr.Offset - pe.addressbase) % uint64(pe.alignment)
	res := address.Address{Space: pe.space, Offset: addr.Offset - al}
	size := int32(endaddr.Offset-res.Offset) + 1
	if al2 := size % pe.alignment; al2 != 0 {
		size += pe.alignment - al2 // up to the next alignment
	}
	return res, size, true
}

// unjustifiedContainer returns the container of a range an entry holds
// improperly justified. C++ parity: ParamListStandard::unjustifiedContainer.
func (pl *ParamListStandard) unjustifiedContainer(loc address.Address, size int32) (address.Address, int32, bool) {
	if pl == nil {
		return address.Address{}, 0, false
	}
	for _, pe := range pl.entry {
		if pe.minsize > size {
			continue
		}
		just := pe.justifiedContain(loc, size)
		if just < 0 {
			continue
		}
		if just == 0 {
			return address.Address{}, 0, false
		}
		return pe.getContainer(loc, size)
	}
	return address.Address{}, 0, false
}

// getBiggestContainedParam returns the storage of the biggest entry lying
// inside [loc, loc+size); that entry must hold a single value (exclusion).
// C++ parity: ParamListStandard::getBiggestContainedParam (its resolver walk
// goes in address order and only a strictly bigger entry replaces the last).
func (pl *ParamListStandard) getBiggestContainedParam(loc address.Address, size int32) (address.Address, int32, bool) {
	if pl == nil || loc.Space == nil || size <= 0 {
		return address.Address{}, 0, false
	}
	if loc.Offset+uint64(size)-1 < loc.Offset {
		return address.Address{}, 0, false // Assume no parameter when the range wraps
	}
	var maxEntry *paramEntry
	for _, pe := range pl.entry {
		if !pe.containedBy(loc, size) {
			continue
		}
		if maxEntry == nil || pe.size > maxEntry.size ||
			(pe.size == maxEntry.size && pe.addressbase < maxEntry.addressbase) {
			maxEntry = pe
		}
	}
	if maxEntry == nil || !maxEntry.isExclusion() {
		return address.Address{}, 0, false
	}
	return address.Address{Space: loc.Space, Offset: maxEntry.addressbase}, maxEntry.size, true
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
	// modelRules are the list's <rule>s (plus the pointermax rule).
	// C++ parity: ParamListStandard::modelRules.
	modelRules []modelRule
	// pointerSize is the size of a pointer a rule converts a parameter to.
	pointerSize int32
	// isOutput: this is a return-value list (ParamListStandardOut).
	isOutput bool
	// useFillinFallback: no output rule can decide the return storage, so
	// fillinMap uses the legacy best-entry match.
	// C++ parity: ParamListStandardOut::useFillinFallback.
	useFillinFallback bool
	// joinSpace and regName build join storage for parameters that span
	// several entries. C++ parity: Architecture::findAddJoin and
	// Translate::getExactRegisterName (JoinRecord::mergeSequence).
	joinSpace *address.Space
	regName   func(sp *address.Space, off uint64, size int32) string
}

// SetJoinContext gives the list the join space and register names that
// parameters spanning several entries are built with.
func (pl *ParamListStandard) SetJoinContext(join *address.Space, regName func(sp *address.Space, off uint64, size int32) string) {
	pl.joinSpace, pl.regName = join, regName
}

// extractTiles lists the single-group exclusion entries of the storage class.
// C++ parity: ParamListStandard::extractTiles.
func (pl *ParamListStandard) extractTiles(tp typeClass) []*paramEntry {
	var tiles []*paramEntry
	for _, pe := range pl.entry {
		if !pe.isExclusion() || pe.tclass != tp || len(pe.getAllGroups()) != 1 {
			continue
		}
		tiles = append(tiles, pe)
	}
	return tiles
}

// getStackEntry is the trailing stack entry, nil if there is none.
// C++ parity: ParamListStandard::getStackEntry.
func (pl *ParamListStandard) getStackEntry() *paramEntry {
	if len(pl.entry) == 0 {
		return nil
	}
	pe := pl.entry[len(pl.entry)-1]
	if !pe.isExclusion() && pe.space != nil && pe.space.Kind == address.SpaceKindStack {
		return pe
	}
	return nil
}

// isBigEndian reports the byte order of the list's storage.
func (pl *ParamListStandard) isBigEndian() bool {
	return len(pl.entry) != 0 && pl.entry[0].bigEndian
}

// metatypeTypeClass is the storage class a data-type of metatype m draws on.
// C++ parity: metatype2typeclass.
func metatypeTypeClass(m metatype) typeClass {
	switch m {
	case TYPE_FLOAT:
		return typeclassFloat
	case TYPE_PTR:
		return typeclassPtr
	}
	return typeclassGeneral
}

// assignAddressFallback gives tp the first entry of the resource class (or
// of the general class) with a slot left in its group, consuming the slot
// (or every group of an exclusion entry). status holds the next slot per
// group, -1 once the group is used up.
// C++ parity: ParamListStandard::assignAddressFallback.
func (pl *ParamListStandard) assignAddressFallback(resource typeClass, tp Datatype, matchExact bool, status []int32) (address.Address, bool) {
	for _, pe := range pl.entry {
		grp := pe.getGroup()
		if status[grp] < 0 {
			continue
		}
		if resource != pe.tclass && (matchExact || pe.tclass != typeclassGeneral) {
			continue // Wrong type
		}
		addr := pe.getAddrBySlot(&status[grp], tp.AlignSize(), tp.Alignment())
		if addr.Space == nil {
			continue // tp does not fit
		}
		if pe.isExclusion() {
			for _, g := range pe.getAllGroups() {
				status[g] = -1 // An exclusion entry takes up its groups
			}
		}
		return addr, true
	}
	return address.Address{}, false
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
	// Join is the record of a join-space pentry (Space is the join space).
	Join *address.JoinRecord
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
			pos:         int32(len(pl.entry)),
		}
		if s.Space != nil {
			pe.spaceIndex = s.Space.Index
		}
		pe.joinrec = s.Join
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
		pe.resolveJoin(pl.entry)
		// The first entry, or one whose storage class differs from the entry
		// before it, is first in its class. C++ parity: ParamEntry::resolveFirst.
		if len(pl.entry) == 0 || pl.entry[len(pl.entry)-1].tclass != pe.tclass {
			pe.flags |= peFirstStorage
		}
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

// checkJoin reports whether the hi/lo storage pair forms one logical
// parameter. C++ parity: ParamListStandard::checkJoin (fspec.cc).
func (pl *ParamListStandard) checkJoin(hiaddr address.Address, hisize int32, loaddr address.Address, losize int32) bool {
	entryHi := pl.findEntry(hiaddr, hisize, true)
	if entryHi == nil {
		return false
	}
	entryLo := pl.findEntry(loaddr, losize, true)
	if entryLo == nil {
		return false
	}
	if entryHi.getGroup() == entryLo.getGroup() {
		if entryHi.isExclusion() || entryLo.isExclusion() {
			return false
		}
		if !address.IsContiguous(hiaddr, hisize, loaddr, losize) {
			return false
		}
		if (hiaddr.Offset-entryHi.addressbase)%uint64(entryHi.getAlign()) != 0 {
			return false
		}
		return (loaddr.Offset-entryLo.addressbase)%uint64(entryLo.getAlign()) == 0
	}
	sizesum := hisize + losize
	for _, pe := range pl.entry {
		if pe.getSize() < sizesum {
			continue
		}
		if pe.justifiedContain(loaddr, losize) != 0 {
			continue
		}
		if pe.justifiedContain(hiaddr, hisize) != losize {
			continue
		}
		return true
	}
	return false
}

// checkSplit reports whether the storage at loc may be split at splitpoint
// into two parameters. C++ parity: ParamListStandard::checkSplit (fspec.cc).
func (pl *ParamListStandard) checkSplit(loc address.Address, size, splitpoint int32) bool {
	loc2 := address.Address{Space: loc.Space, Offset: loc.Offset + uint64(splitpoint)}
	if pl.findEntry(loc, splitpoint, true) == nil {
		return false
	}
	return pl.findEntry(loc2, size-splitpoint, true) != nil
}

// GetMaxDelay returns the maximum heritage delay across the spaces that hold a
// parameter entry. A non-zero delay means parameter storage lives in a space
// that is heritaged late (the stack spacebase), so trial classification must be
// deferred for several passes -- see FuncCallSpecs.InitActiveInput.
// C++ parity: ParamListStandard::calcDelay / getMaxDelay (fspec.cc:1153).
func (pl *ParamListStandard) GetMaxDelay() int32 {
	if pl == nil {
		return 0
	}
	var maxdelay int32
	for _, pe := range pl.entry {
		if pe.space == nil {
			continue
		}
		if pe.space.Delay > maxdelay {
			maxdelay = pe.space.Delay
		}
	}
	return maxdelay
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
			addr := curentry.getAddrBySlot(&nextslot, sz, 1)
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
					addr := curentry.getAddrBySlot(&nextslot, curentry.getAlign(), 1)
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

// FillinMapOut decides which active output trials form the return value: a
// model rule that can decide it is tried first, else the best matching entry.
// C++ parity: ParamListStandardOut::fillinMap.
func (pl *ParamListStandard) FillinMapOut(active *ParamActive) {
	if active.NumTrials() == 0 {
		return // No trials to check
	}
	if pl.useFillinFallback {
		pl.fillinMapFallback(active, false)
		return
	}
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		trial.SetEntry(nil, 0)
		if !trial.IsActive() {
			continue
		}
		entry := pl.findEntry(trial.GetAddress(), trial.GetSize(), false)
		if entry == nil {
			trial.MarkNoUse()
			continue
		}
		res := entry.justifiedContain(trial.GetAddress(), trial.GetSize())
		if (trial.IsRemFormed() || trial.IsIndCreateFormed()) && !entry.isFirstInClass() {
			trial.MarkNoUse()
			continue
		}
		trial.SetEntry(entry, res)
	}
	active.SortTrials()
	for i := range pl.modelRules {
		if !pl.modelRules[i].assign.fillinOutputMap(active) {
			continue
		}
		for j := 0; j < active.NumTrials(); j++ {
			trial := active.Trial(j)
			if trial.IsActive() {
				trial.MarkUsed()
			} else {
				trial.MarkNoUse()
				trial.SetEntry(nil, 0)
			}
		}
		return
	}
	pl.fillinMapFallback(active, true)
}

// fillinMapFallback marks the active trials covered by the best matching
// output entry as used; firstOnly restricts the match to the first entry of
// each storage class. C++ parity: ParamListStandardOut::fillinMapFallback.
func (pl *ParamListStandard) fillinMapFallback(active *ParamActive, firstOnly bool) {
	var bestentry *paramEntry
	bestcover := int32(0)
	bestclass := typeclassPtr
	// Find the entry best covered by the active trials
	for _, curentry := range pl.entry {
		if firstOnly && !curentry.isFirstInClass() && curentry.isExclusion() && len(curentry.getAllGroups()) == 1 {
			continue // Not the first entry in the storage class
		}
		putativematch := false
		for j := 0; j < active.NumTrials(); j++ { // Evaluate all trials against curentry
			trial := active.Trial(j)
			if trial.IsActive() {
				if res := curentry.justifiedContain(trial.GetAddress(), trial.GetSize()); res >= 0 {
					trial.SetEntry(curentry, res)
					putativematch = true
					continue
				}
			}
			trial.SetEntry(nil, 0)
		}
		if !putativematch {
			continue
		}
		active.SortTrials()
		// Number of least justified, contiguous bytes for this entry
		offmatch := int32(0)
		k := 0
		for ; k < active.NumTrials(); k++ {
			trial := active.Trial(k)
			if trial.GetEntry() == nil {
				continue
			}
			if offmatch != trial.GetOffset() {
				break
			}
			if (offmatch == 0 && curentry.isParamCheckLow()) || (offmatch != 0 && curentry.isParamCheckHigh()) {
				// Multi-precision: check this portion is not created normally
				if trial.IsRemFormed() || trial.IsIndCreateFormed() {
					break
				}
			}
			offmatch += trial.GetSize()
		}
		if offmatch < curentry.getMinSize() { // Not enough to cover the minimum size
			k = 0
		}
		// Prefer a more generic type restriction, then the larger coverage
		if k == active.NumTrials() && (curentry.getType() < bestclass || offmatch > bestcover) {
			bestentry = curentry
			bestcover = offmatch
			bestclass = curentry.getType()
		}
	}
	if bestentry == nil {
		for i := 0; i < active.NumTrials(); i++ {
			active.Trial(i).MarkNoUse()
		}
		return
	}
	for i := 0; i < active.NumTrials(); i++ {
		trial := active.Trial(i)
		if trial.IsActive() {
			if res := bestentry.justifiedContain(trial.GetAddress(), trial.GetSize()); res >= 0 {
				trial.MarkUsed() // Only actives are ever marked used
				trial.SetEntry(bestentry, res)
				continue
			}
		}
		trial.MarkNoUse()
		trial.SetEntry(nil, 0)
	}
	active.SortTrials()
}

// PossibleOutput reports that some output entry contains the storage.
// C++ parity: ParamListStandardOut::possibleParam.
func (pl *ParamListStandard) PossibleOutput(loc address.Address, size int32) bool {
	for _, pe := range pl.entry {
		if pe.justifiedContain(loc, size) >= 0 {
			return true
		}
	}
	return false
}
