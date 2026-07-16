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

// Symbol categories.
// C++ parity: database.hh Symbol::category enum
const (
	SymbolNoCategory        int = -1
	SymbolFunctionParameter int = 0
	SymbolEquate            int = 1
	SymbolUnionFacet        int = 2
	SymbolFakeInput         int = 3
)

// Symbol is a named storage object with a data-type and a category. This is a
// pared-down port of the Ghidra Symbol class: we keep the fields that the
// decompiler keeps referring to (name, type, flags, category, mapEntry list)
// while leaving namespace / scope tree and display helpers out.
//
// C++ parity: database.hh Symbol (subset)
type Symbol struct {
	name     string
	dataType Datatype
	flags    uint32 // Varnode-like property flags mirrored into the symbol
	category int
	catIndex int
	symbolId uint64

	// mapEntry is the list of storage locations that resolve to this symbol.
	// C++ parity: Symbol::mapentry (list<list<SymbolEntry>::iterator>).
	mapEntry []*SymbolEntry

	// wholeCount tracks how many mapEntry items cover the whole storage.
	// C++ parity: Symbol::wholeCount.
	wholeCount int
}

// NewSymbol constructs a new Symbol bound to a name and data-type.
// C++ parity: Symbol::Symbol(Scope*,const string&,Datatype*)
func NewSymbol(name string, dt Datatype) *Symbol {
	return &Symbol{
		name:     name,
		dataType: dt,
		category: SymbolNoCategory,
	}
}

// Name returns the local name of the symbol.
// C++ parity: Symbol::getName
func (s *Symbol) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// SetName updates the local name. Callers are responsible for any scope
// re-indexing; the in-memory ScopeLocal port is flat so there is none.
// C++ parity: ScopeInternal::renameSymbol (name-only subset)
func (s *Symbol) SetName(name string) {
	if s == nil {
		return
	}
	s.name = name
}

// Type returns the data-type associated with the symbol.
// C++ parity: Symbol::getType
func (s *Symbol) Type() Datatype {
	if s == nil {
		return nil
	}
	return s.dataType
}

// SetType replaces the data-type stored on the symbol.
// C++ parity: Symbol::setType (via ScopeInternal::retypeSymbol)
func (s *Symbol) SetType(dt Datatype) {
	if s == nil {
		return
	}
	s.dataType = dt
}

// Flags returns the Varnode-like property flags copied onto the symbol.
// C++ parity: Symbol::getFlags
func (s *Symbol) Flags() uint32 {
	if s == nil {
		return 0
	}
	return s.flags
}

// SetFlags turns on one or more Varnode-flag bits on the symbol.
// C++ parity: Symbol::flags direct mutation inside ScopeInternal.
func (s *Symbol) SetFlags(fl uint32) {
	if s == nil {
		return
	}
	s.flags |= fl
}

// ClearFlags clears the given Varnode-flag bits.
// C++ parity: Symbol::flags direct mutation inside ScopeInternal.
func (s *Symbol) ClearFlags(fl uint32) {
	if s == nil {
		return
	}
	s.flags &^= fl
}

// Category returns the symbol category, or SymbolNoCategory.
// C++ parity: Symbol::getCategory
func (s *Symbol) Category() int {
	if s == nil {
		return SymbolNoCategory
	}
	return s.category
}

// SetCategory assigns the symbol category and its position within that category.
// C++ parity: Symbol::setCategory (Scope-driven category assignment).
func (s *Symbol) SetCategory(cat int, index int) {
	if s == nil {
		return
	}
	s.category = cat
	s.catIndex = index
}

// CategoryIndex returns the position within the category (function_parameter).
// C++ parity: Symbol::getCategoryIndex
func (s *Symbol) CategoryIndex() int {
	if s == nil {
		return 0
	}
	return s.catIndex
}

// ID returns the globally unique symbol identifier.
// C++ parity: Symbol::getId
func (s *Symbol) ID() uint64 {
	if s == nil {
		return 0
	}
	return s.symbolId
}

// SetID assigns the globally unique symbol identifier.
// C++ parity: Symbol::symbolId direct assignment in ScopeInternal.
func (s *Symbol) SetID(id uint64) {
	if s == nil {
		return
	}
	s.symbolId = id
}

// IsTypeLocked reports whether Varnode::typelock is set on the symbol.
// C++ parity: Symbol::isTypeLocked
func (s *Symbol) IsTypeLocked() bool { return s != nil && s.flags&VarnodeTypeLock != 0 }

// IsNameLocked reports whether Varnode::namelock is set on the symbol.
// C++ parity: Symbol::isNameLocked
func (s *Symbol) IsNameLocked() bool { return s != nil && s.flags&VarnodeNameLock != 0 }

// IsNameUndefined matches Symbol::isNameUndefined: an auto-generated name whose
// prefix is "$$undef" or starts with the decompiler-assigned default marker.
// We follow the same policy: treat the empty string and any name beginning with
// "$$undef" as undefined.
// C++ parity: Symbol::isNameUndefined
func (s *Symbol) IsNameUndefined() bool {
	if s == nil {
		return true
	}
	if s.name == "" {
		return true
	}
	const tag = "$$undef"
	if len(s.name) >= len(tag) && s.name[:len(tag)] == tag {
		return true
	}
	return false
}

// NumEntries returns the number of SymbolEntry records pointing at this symbol.
// C++ parity: Symbol::numEntries
func (s *Symbol) NumEntries() int {
	if s == nil {
		return 0
	}
	return len(s.mapEntry)
}

// Entry returns the i-th SymbolEntry, or nil if out of range.
// C++ parity: Symbol::getMapEntry(int4)
func (s *Symbol) Entry(i int) *SymbolEntry {
	if s == nil || i < 0 || i >= len(s.mapEntry) {
		return nil
	}
	return s.mapEntry[i]
}

// FirstWholeMap returns the first SymbolEntry that covers the whole storage.
// With the partial port we treat every attached entry as a whole-map entry, so
// this simply returns the first one.
// C++ parity: Symbol::getFirstWholeMap
func (s *Symbol) FirstWholeMap() *SymbolEntry {
	if s == nil || len(s.mapEntry) == 0 {
		return nil
	}
	return s.mapEntry[0]
}

// IsMultiEntry reports whether the Symbol has more than one whole-mapping.
// C++ parity: Symbol::isMultiEntry
func (s *Symbol) IsMultiEntry() bool { return s != nil && s.wholeCount > 1 }

// attachEntry records that the given SymbolEntry maps to this symbol.
// C++ parity: Symbol::mapentry push_back in ScopeInternal::addMapInternal.
func (s *Symbol) attachEntry(e *SymbolEntry) {
	if s == nil || e == nil {
		return
	}
	s.mapEntry = append(s.mapEntry, e)
	if e.size >= 0 && e.offset == 0 {
		s.wholeCount++
	}
}

// SymbolEntry is a single storage location for a Symbol. A Symbol that is
// split across several storage locations will own several SymbolEntry records.
//
// C++ parity: database.hh SymbolEntry
type SymbolEntry struct {
	symbol     *Symbol         // Symbol being mapped
	extraFlags uint32          // Varnode flags specific to this storage location
	addr       address.Address // Starting address of the storage location (invalid for dynamic)
	hash       uint64          // Dynamic storage hash (0 for non-dynamic)
	offset     int32           // Offset into the Symbol that this entry covers
	size       int32           // Number of bytes consumed by this entry
	// uselimit is the range of code addresses where this storage is valid.
	// An empty uselimit means the entry is valid across the whole function.
	// C++ parity: SymbolEntry::uselimit (RangeList).
	useLimit []useRange
}

// useRange is a single [first,last] instruction-address range.
// C++ parity: RangeList element (Range).
type useRange struct {
	space *address.Space
	first uint64
	last  uint64
}

// NewSymbolEntry builds a storage-mapped SymbolEntry for the given symbol.
// C++ parity: SymbolEntry(const EntryInitData&,uintb,uintb)
func NewSymbolEntry(sym *Symbol, extraFlags uint32, addr address.Address, size int32, offset int32) *SymbolEntry {
	return &SymbolEntry{
		symbol:     sym,
		extraFlags: extraFlags,
		addr:       addr,
		size:       size,
		offset:     offset,
	}
}

// NewDynamicSymbolEntry builds a dynamic SymbolEntry identified by a hash.
// C++ parity: SymbolEntry(Symbol*,uint4,uint8,int4,int4,const RangeList&)
func NewDynamicSymbolEntry(sym *Symbol, extraFlags uint32, hash uint64, size int32, offset int32) *SymbolEntry {
	return &SymbolEntry{
		symbol:     sym,
		extraFlags: extraFlags,
		hash:       hash,
		size:       size,
		offset:     offset,
	}
}

// Symbol returns the symbol this entry is tied to.
// C++ parity: SymbolEntry::getSymbol
func (e *SymbolEntry) Symbol() *Symbol {
	if e == nil {
		return nil
	}
	return e.symbol
}

// Addr returns the starting address of the storage.
// C++ parity: SymbolEntry::getAddr
func (e *SymbolEntry) Addr() address.Address {
	if e == nil {
		return address.Address{}
	}
	return e.addr
}

// Size returns the number of bytes consumed by this entry.
// C++ parity: SymbolEntry::getSize
func (e *SymbolEntry) Size() int32 {
	if e == nil {
		return 0
	}
	return e.size
}

// Offset returns the offset of this entry within the Symbol.
// C++ parity: SymbolEntry::getOffset
func (e *SymbolEntry) Offset() int32 {
	if e == nil {
		return 0
	}
	return e.offset
}

// First returns the first byte offset of the storage location.
// C++ parity: SymbolEntry::getFirst
func (e *SymbolEntry) First() uint64 {
	if e == nil {
		return 0
	}
	return e.addr.Offset
}

// Last returns the last byte offset of the storage location.
// C++ parity: SymbolEntry::getLast
func (e *SymbolEntry) Last() uint64 {
	if e == nil || e.size <= 0 {
		return 0
	}
	return e.addr.Offset + uint64(e.size) - 1
}

// Hash returns the dynamic storage hash.
// C++ parity: SymbolEntry::getHash
func (e *SymbolEntry) Hash() uint64 {
	if e == nil {
		return 0
	}
	return e.hash
}

// IsDynamic reports whether the entry identifies storage via DynamicHash.
// C++ parity: SymbolEntry::isDynamic
func (e *SymbolEntry) IsDynamic() bool { return e != nil && e.addr.IsInvalid() }

// IsInvalid reports whether the entry has neither an address nor a hash.
// C++ parity: SymbolEntry::isInvalid
func (e *SymbolEntry) IsInvalid() bool {
	return e != nil && e.addr.IsInvalid() && e.hash == 0
}

// AllFlags returns the union of the entry's extra flags and the symbol flags.
// C++ parity: SymbolEntry::getAllFlags
func (e *SymbolEntry) AllFlags() uint32 {
	if e == nil {
		return 0
	}
	if e.symbol == nil {
		return e.extraFlags
	}
	return e.extraFlags | e.symbol.flags
}

// IsAddrTied reports whether the underlying symbol is address-tied.
// C++ parity: SymbolEntry::isAddrTied
func (e *SymbolEntry) IsAddrTied() bool {
	if e == nil || e.symbol == nil {
		return false
	}
	return e.symbol.flags&VarnodeAddrTied != 0
}

// UseLimit returns the list of code-address ranges where this entry is valid.
// An empty list means the entry is valid across the whole function.
// C++ parity: SymbolEntry::getUseLimit
func (e *SymbolEntry) UseLimit() []useRange {
	if e == nil {
		return nil
	}
	return e.useLimit
}

// SetUseLimit replaces the use-limit range list.
// C++ parity: SymbolEntry::setUseLimit
func (e *SymbolEntry) SetUseLimit(ranges []useRange) {
	if e == nil {
		return
	}
	e.useLimit = ranges
}

// InUse reports whether the storage is valid at the given code address.
// An empty uselimit means valid-everywhere (matches C++ convention).
// C++ parity: SymbolEntry::inUse
func (e *SymbolEntry) InUse(usepoint address.Address) bool {
	if e == nil {
		return false
	}
	if len(e.useLimit) == 0 {
		return true
	}
	if usepoint.IsInvalid() {
		return false
	}
	for _, r := range e.useLimit {
		if r.space != usepoint.Space {
			continue
		}
		if usepoint.Offset >= r.first && usepoint.Offset <= r.last {
			return true
		}
	}
	return false
}

// FirstUseAddress returns the first code address where this entry is valid,
// or the invalid address if the entry is valid everywhere.
// C++ parity: SymbolEntry::getFirstUseAddress
func (e *SymbolEntry) FirstUseAddress() address.Address {
	if e == nil || len(e.useLimit) == 0 {
		return address.Address{}
	}
	r := e.useLimit[0]
	return address.Address{Space: r.space, Offset: r.first}
}

// GetSizedType picks a data-type for the requested sub-slice of this storage.
// For the partial port we defer to the symbol's data-type when the request
// covers the entire storage, and return nil otherwise. The full C++ routine
// walks into TypeStruct / TypeArray members to return a piece; that walk
// depends on the TypeFactory::getSubType machinery which is not yet ported.
// TODO: wire in TypeFactory::getExactPiece once Datatype::getSubType lands.
// C++ parity: SymbolEntry::getSizedType (fallback path only)
func (e *SymbolEntry) GetSizedType(addr address.Address, sz int32) Datatype {
	if e == nil || e.symbol == nil {
		return nil
	}
	if e.addr.Space != addr.Space {
		return nil
	}
	if addr.Offset != e.addr.Offset {
		return nil
	}
	if sz != e.size {
		return nil
	}
	return e.symbol.dataType
}

// UpdateType applies the data-type stored on the entry to the given Varnode.
// Returns true on success. The full C++ path consults UnionFacetSymbol for a
// union override; that code requires ResolvedUnion which is not ported yet.
// TODO: handle UnionFacetSymbol once ResolvedUnion lands.
// C++ parity: SymbolEntry::updateType (fallback path)
func (e *SymbolEntry) UpdateType(vn *Varnode) bool {
	if e == nil || vn == nil || e.symbol == nil {
		return false
	}
	dt := e.symbol.dataType
	if dt == nil {
		return false
	}
	SetVarnodeType(vn, dt)
	return true
}
