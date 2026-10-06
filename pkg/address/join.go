// Copyright 2026 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package address

import "sync"

// VarnodeData is a (space, offset, size) storage triple.
// C++ parity: translate.hh VarnodeData.
type VarnodeData struct {
	Space  *Space
	Offset uint64
	Size   int32
}

// Addr is the start address of the storage. C++ parity: VarnodeData::getAddr.
func (v VarnodeData) Addr() Address { return Address{Space: v.Space, Offset: v.Offset} }

// JoinRecord describes logical storage split across several physical pieces,
// most significant piece first, and the unified range it occupies in the join
// space. C++ parity: translate.hh class JoinRecord.
type JoinRecord struct {
	Pieces  []VarnodeData
	Unified VarnodeData
}

// NumPieces is the number of physical pieces. C++ parity: JoinRecord::numPieces.
func (j *JoinRecord) NumPieces() int { return len(j.Pieces) }

// Piece is the i-th piece, most significant first. C++ parity: JoinRecord::getPiece.
func (j *JoinRecord) Piece(i int) VarnodeData { return j.Pieces[i] }

// IsFloatExtension: a single piece logically wider than the record.
// C++ parity: JoinRecord::isFloatExtension.
func (j *JoinRecord) IsFloatExtension() bool { return len(j.Pieces) == 1 }

// joinManager allocates join-space ranges for JoinRecords, shared by every
// function of the process like the C++ per-Architecture AddrSpaceManager.
// C++ parity: AddrSpaceManager splitset/splitlist/joinallocate.
type joinManager struct {
	mu       sync.Mutex
	list     []*JoinRecord
	allocate uint64
}

var joins joinManager

func samePieces(a, b []VarnodeData) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FindAddJoin returns the record for the given pieces, creating it if needed.
// A logicalsize of 0 means the sum of the piece sizes.
// C++ parity: AddrSpaceManager::findAddJoin.
func FindAddJoin(joinSpace *Space, pieces []VarnodeData, logicalsize int32) *JoinRecord {
	totalsize := logicalsize
	if totalsize == 0 {
		for _, p := range pieces {
			totalsize += p.Size
		}
	}
	joins.mu.Lock()
	defer joins.mu.Unlock()
	for _, rec := range joins.list {
		if rec.Unified.Size == totalsize && samePieces(rec.Pieces, pieces) {
			return rec
		}
	}
	rec := &JoinRecord{Pieces: append([]VarnodeData(nil), pieces...)}
	roundsize := (uint64(totalsize) + 15) &^ 0xf // Next biggest multiple of 16
	rec.Unified = VarnodeData{Space: joinSpace, Offset: joins.allocate, Size: totalsize}
	joins.allocate += roundsize
	joins.list = append(joins.list, rec)
	return rec
}

// FindJoin returns the record whose unified range starts at offset, or nil.
// C++ parity: AddrSpaceManager::findJoin.
func FindJoin(offset uint64) *JoinRecord {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	for _, rec := range joins.list {
		if rec.Unified.Offset == offset {
			return rec
		}
	}
	return nil
}

// IsContiguous reports whether hi and lo are adjacent with hi the more
// significant. C++ parity: Address::isContiguous.
func IsContiguous(hi Address, hisz int32, lo Address, losz int32) bool {
	if hi.Space != lo.Space {
		return false
	}
	if hi.Space.BigEndian {
		return hi.Offset+uint64(hisz) == lo.Offset
	}
	return lo.Offset+uint64(losz) == hi.Offset
}

// ConstructJoinAddress returns the storage address of the whole formed by hi
// and lo: the low address when contiguous in a mappable space (or a named
// parent register), otherwise a join-space address.
// C++ parity: AddrSpaceManager::constructJoinAddress. regExists reports
// whether a register of the given size starts at the address; codeSpace is
// the default code space.
func ConstructJoinAddress(joinSpace, codeSpace *Space, hi Address, hisz int32, lo Address, losz int32, regExists func(Address, int32) bool) Address {
	usejoinspace := hi.Space.Kind != SpaceKindStack && lo.Space.Kind != SpaceKindStack &&
		hi.Space != codeSpace && lo.Space != codeSpace
	if IsContiguous(hi, hisz, lo, losz) {
		if !usejoinspace { // A mappable space: the earliest address
			if hi.Space.BigEndian {
				return hi
			}
			return lo
		}
		// A register space: use a parent register if one exists
		whole := lo
		if hi.Space.BigEndian {
			whole = hi
		}
		if regExists != nil && regExists(whole, hisz+losz) {
			return whole
		}
	}
	rec := FindAddJoin(joinSpace, []VarnodeData{
		{Space: hi.Space, Offset: hi.Offset, Size: hisz},
		{Space: lo.Space, Offset: lo.Offset, Size: losz},
	}, 0)
	// The record is shared across functions; the address is in this
	// function's join space
	return Address{Space: joinSpace, Offset: rec.Unified.Offset}
}

var (
	joinSpacesMu sync.Mutex
	joinSpaces   = map[uint16]*Space{}
)

// JoinSpaceAt is the join space with the given index, created on first use.
// C++ parity: Architecture::restoreFromSpec inserts the JoinSpace after the
// processor spaces (and before any spacebase space).
func JoinSpaceAt(index uint16) *Space {
	joinSpacesMu.Lock()
	defer joinSpacesMu.Unlock()
	if s, ok := joinSpaces[index]; ok {
		return s
	}
	s := &Space{Name: "join", Kind: SpaceKindJoin, Index: index, AddrSize: 4, WordSize: 1}
	joinSpaces[index] = s
	return s
}
