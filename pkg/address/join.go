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

// findJoinInternal returns the record whose unified range contains offset.
// C++ parity: AddrSpaceManager::findJoinInternal.
func findJoinInternal(offset uint64) *JoinRecord {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	for _, rec := range joins.list {
		if rec.Unified.Offset <= offset && offset < rec.Unified.Offset+uint64(rec.Unified.Size) {
			return rec
		}
	}
	return nil
}

// equivalentAddress maps a join-space offset to the address within the
// piece that holds it, and that piece's index (-1 when out of range).
// C++ parity: JoinRecord::getEquivalentAddress.
func (j *JoinRecord) equivalentAddress(offset uint64) (Address, int) {
	if offset < j.Unified.Offset {
		return Address{}, -1 // offset comes before this range
	}
	smallOff := int32(offset - j.Unified.Offset)
	pos := 0
	if j.Pieces[0].Space.BigEndian {
		for ; pos < len(j.Pieces); pos++ {
			if smallOff < j.Pieces[pos].Size {
				break
			}
			smallOff -= j.Pieces[pos].Size
		}
		if pos == len(j.Pieces) {
			return Address{}, -1 // offset comes after this range
		}
	} else {
		for pos = len(j.Pieces) - 1; pos >= 0; pos-- {
			if smallOff < j.Pieces[pos].Size {
				break
			}
			smallOff -= j.Pieces[pos].Size
		}
		if pos < 0 {
			return Address{}, -1
		}
	}
	return Address{Space: j.Pieces[pos].Space, Offset: j.Pieces[pos].Offset + uint64(smallOff)}, pos
}

// renormalizeJoin rewrites a join address of the given size to the real
// storage it covers: a single piece's address, or the join record of the
// covered pieces. C++ parity: AddrSpaceManager::renormalizeJoinAddress.
func renormalizeJoin(addr *Address, size int32) {
	rec := findJoinInternal(addr.Offset)
	if rec == nil {
		return // C++ throws: join address not covered by a JoinRecord
	}
	if addr.Offset == rec.Unified.Offset && size == rec.Unified.Size {
		return // JoinRecord matches perfectly, no change necessary
	}
	addr1, pos1 := rec.equivalentAddress(addr.Offset)
	addr2, pos2 := rec.equivalentAddress(addr.Offset + uint64(size-1))
	if pos1 < 0 || pos2 < 0 {
		return // C++ throws: join address range not covered
	}
	if pos1 == pos2 {
		*addr = addr1
		return
	}
	sizeTrunc1 := int32(addr1.Offset - rec.Pieces[pos1].Offset)
	sizeTrunc2 := rec.Pieces[pos2].Size - int32(addr2.Offset-rec.Pieces[pos2].Offset) - 1
	var newPieces []VarnodeData
	if pos2 < pos1 { // Little endian
		newPieces = append(newPieces, rec.Pieces[pos2:pos1+1]...)
		newPieces[len(newPieces)-1].Offset = addr1.Offset
		newPieces[len(newPieces)-1].Size -= sizeTrunc1
		newPieces[0].Size -= sizeTrunc2
	} else {
		newPieces = append(newPieces, rec.Pieces[pos1:pos2+1]...)
		newPieces[0].Offset = addr1.Offset
		newPieces[0].Size -= sizeTrunc1
		newPieces[len(newPieces)-1].Size -= sizeTrunc2
	}
	nrec := FindAddJoin(rec.Unified.Space, newPieces, 0)
	*addr = Address{Space: nrec.Unified.Space, Offset: nrec.Unified.Offset}
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
