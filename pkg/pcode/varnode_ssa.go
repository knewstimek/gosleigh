package pcode

import (
	"fmt"

	"gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// Varnode flags -- uint32 bitmask (explicit hex values, NOT iota)
// C++ parity: varnode.hh Varnode::varnode_flags
// ---------------------------------------------------------------------------

const (
	VarnodeMark             uint32 = 0x01
	VarnodeConstant         uint32 = 0x02
	VarnodeAnnotation       uint32 = 0x04
	VarnodeInput            uint32 = 0x08
	VarnodeWritten          uint32 = 0x10
	VarnodeInsert           uint32 = 0x20
	VarnodeImplied          uint32 = 0x40
	VarnodeExplicit         uint32 = 0x80
	VarnodeTypeLock         uint32 = 0x100
	VarnodeNameLock         uint32 = 0x200
	VarnodeNoLocalAlias     uint32 = 0x400
	VarnodeVolatile         uint32 = 0x800
	VarnodeExternRef        uint32 = 0x1000
	VarnodeReadOnly         uint32 = 0x2000
	VarnodePersist          uint32 = 0x4000
	VarnodeAddrTied         uint32 = 0x8000
	VarnodeUnaffected       uint32 = 0x10000
	VarnodeSpaceBase        uint32 = 0x20000
	VarnodeIndirectOnly     uint32 = 0x40000
	VarnodeDirectWrite      uint32 = 0x80000
	VarnodeAddrForce        uint32 = 0x100000
	VarnodeMapped           uint32 = 0x200000
	VarnodeIndirectCreation uint32 = 0x400000
	VarnodeReturnAddress    uint32 = 0x800000
	VarnodeCoverDirty       uint32 = 0x1000000
	VarnodePrecisLo         uint32 = 0x2000000
	VarnodePrecisHi         uint32 = 0x4000000
	VarnodeIndirectStorage  uint32 = 0x8000000
	VarnodeHiddenRetParm    uint32 = 0x10000000
	VarnodeIncidentalCopy   uint32 = 0x20000000
	VarnodeAutoLiveHold     uint32 = 0x40000000
	VarnodeProtoPartial     uint32 = 0x80000000
)

// ---------------------------------------------------------------------------
// Varnode additional flags -- uint16 bitmask
// C++ parity: varnode.hh Varnode::addl_flags
// ---------------------------------------------------------------------------

const (
	VarnodeActiveHeritage       uint16 = 0x01
	VarnodeWriteMask            uint16 = 0x02
	VarnodeVacConsume           uint16 = 0x04
	VarnodeLisConsume           uint16 = 0x08
	VarnodePtrCheck             uint16 = 0x10
	VarnodePtrFlow              uint16 = 0x20
	VarnodeUnsignedPrint        uint16 = 0x40
	VarnodeLongPrint            uint16 = 0x80
	VarnodeStackStore           uint16 = 0x100
	VarnodeLockedInput          uint16 = 0x200
	VarnodeSpacebasePlaceholder uint16 = 0x400
	VarnodeStopUpPropagation    uint16 = 0x800
	VarnodeHasImpliedField      uint16 = 0x1000
)

// ---------------------------------------------------------------------------
// Varnode -- SSA data node in the P-code IR graph
// C++ parity: varnode.hh Varnode
// ---------------------------------------------------------------------------

// Varnode is an SSA data node in the P-code IR graph.
// Distinct from VarnodeData which is just a raw storage triple.
// C++ parity: varnode.hh Varnode
type Varnode struct {
	flags       uint32          // VarnodeXxx flags
	addlFlags   uint16          // additional flags
	size        int32           // size in bytes
	createIndex uint32          // monotonic creation ID (unique within VarnodeBank)
	mergeGroup  int16           // forced-merge group number
	loc         address.Address // storage location

	// SSA links
	def     *PcodeOp   // defining operation (nil if input or free)
	descend []*PcodeOp // operations that read this varnode

	// Non-zero mask and consumed bits
	nzm      uint64 // bits known to possibly be non-zero
	consumed uint64 // bits consumed by descendants
}

// NewVarnode creates a Varnode. Initializes flags based on space type.
// C++ parity: Varnode::Varnode(int4 s, const Address &m, Datatype *dt)
func NewVarnode(size int32, loc address.Address) *Varnode {
	vn := &Varnode{
		size:     size,
		loc:      loc,
		consumed: ^uint64(0), // all bits consumed initially
	}
	if loc.Space != nil {
		switch {
		case loc.Space.IsConstant():
			vn.flags = VarnodeConstant
			vn.nzm = loc.Offset
		case loc.Space.Kind == address.SpaceKindFspec || loc.Space.Kind == address.SpaceKindIop:
			vn.flags = VarnodeAnnotation | VarnodeCoverDirty
			vn.nzm = ^uint64(0)
		default:
			vn.flags = VarnodeCoverDirty
			vn.nzm = ^uint64(0)
		}
	}
	return vn
}

// ---------------------------------------------------------------------------
// Basic accessors
// ---------------------------------------------------------------------------

func (vn *Varnode) Addr() address.Address    { return vn.loc }
func (vn *Varnode) Space() *address.Space     { return vn.loc.Space }
func (vn *Varnode) Offset() uint64            { return vn.loc.Offset }
func (vn *Varnode) Size() int32               { return vn.size }
func (vn *Varnode) Def() *PcodeOp             { return vn.def }
func (vn *Varnode) SetDef(op *PcodeOp)        { vn.def = op }
func (vn *Varnode) CreateIndex() uint32       { return vn.createIndex }
func (vn *Varnode) MergeGroup() int16         { return vn.mergeGroup }
func (vn *Varnode) SetMergeGroup(g int16)     { vn.mergeGroup = g }
func (vn *Varnode) NZMask() uint64            { return vn.nzm }
func (vn *Varnode) SetNZMask(m uint64)        { vn.nzm = m }
func (vn *Varnode) Consumed() uint64          { return vn.consumed }
func (vn *Varnode) SetConsumed(c uint64)      { vn.consumed = c }
func (vn *Varnode) AddlFlags() uint16         { return vn.addlFlags }

// Additional flag operations
// C++ parity: varnode.hh Varnode addl_flags accessors

func (vn *Varnode) SetAddlFlags(fl uint16)      { vn.addlFlags |= fl }
func (vn *Varnode) ClearAddlFlags(fl uint16)    { vn.addlFlags &^= fl }
func (vn *Varnode) HasAddlFlags(fl uint16) bool { return vn.addlFlags&fl != 0 }
func (vn *Varnode) IsActiveHeritage() bool      { return vn.addlFlags&VarnodeActiveHeritage != 0 }
func (vn *Varnode) SetActiveHeritage()          { vn.addlFlags |= VarnodeActiveHeritage }
func (vn *Varnode) ClearActiveHeritage()        { vn.addlFlags &^= VarnodeActiveHeritage }

// ---------------------------------------------------------------------------
// Flag operations
// ---------------------------------------------------------------------------

func (vn *Varnode) Flags() uint32           { return vn.flags }
func (vn *Varnode) SetFlags(fl uint32)      { vn.flags |= fl }
func (vn *Varnode) ClearFlags(fl uint32)    { vn.flags &^= fl }
func (vn *Varnode) HasFlags(fl uint32) bool { return vn.flags&fl != 0 }

// ---------------------------------------------------------------------------
// Boolean queries
// ---------------------------------------------------------------------------

func (vn *Varnode) IsConstant() bool      { return vn.flags&VarnodeConstant != 0 }
func (vn *Varnode) IsAnnotation() bool    { return vn.flags&VarnodeAnnotation != 0 }
func (vn *Varnode) IsInput() bool         { return vn.flags&VarnodeInput != 0 }
func (vn *Varnode) IsWritten() bool       { return vn.flags&VarnodeWritten != 0 }
func (vn *Varnode) IsFree() bool          { return vn.flags&(VarnodeWritten|VarnodeInput) == 0 }
func (vn *Varnode) IsImplied() bool       { return vn.flags&VarnodeImplied != 0 }
func (vn *Varnode) IsExplicit() bool      { return vn.flags&VarnodeExplicit != 0 }
func (vn *Varnode) IsMark() bool          { return vn.flags&VarnodeMark != 0 }
func (vn *Varnode) SetMark()              { vn.flags |= VarnodeMark }
func (vn *Varnode) ClearMark()            { vn.flags &^= VarnodeMark }
func (vn *Varnode) IsAddrTied() bool      { return vn.flags&VarnodeAddrTied != 0 }
func (vn *Varnode) IsAddrForce() bool     { return vn.flags&VarnodeAddrForce != 0 }
func (vn *Varnode) IsPersist() bool       { return vn.flags&VarnodePersist != 0 }
func (vn *Varnode) IsReadOnly() bool      { return vn.flags&VarnodeReadOnly != 0 }
func (vn *Varnode) IsVolatile() bool      { return vn.flags&VarnodeVolatile != 0 }
func (vn *Varnode) IsSpaceBase() bool     { return vn.flags&VarnodeSpaceBase != 0 }
func (vn *Varnode) IsTypeLock() bool      { return vn.flags&VarnodeTypeLock != 0 }
func (vn *Varnode) IsNameLock() bool      { return vn.flags&VarnodeNameLock != 0 }
func (vn *Varnode) IsReturnAddress() bool { return vn.flags&VarnodeReturnAddress != 0 }
func (vn *Varnode) IsPrecisLo() bool      { return vn.flags&VarnodePrecisLo != 0 }
func (vn *Varnode) IsPrecisHi() bool      { return vn.flags&VarnodePrecisHi != 0 }
func (vn *Varnode) IsDirectWrite() bool   { return vn.flags&VarnodeDirectWrite != 0 }
func (vn *Varnode) IsIndirectOnly() bool  { return vn.flags&VarnodeIndirectOnly != 0 }
func (vn *Varnode) IsUnaffected() bool    { return vn.flags&VarnodeUnaffected != 0 }
func (vn *Varnode) IsAutoLive() bool      { return vn.flags&VarnodeAutoLiveHold != 0 }
func (vn *Varnode) IsMapped() bool        { return vn.flags&VarnodeMapped != 0 }
func (vn *Varnode) HasNoDescend() bool    { return len(vn.descend) == 0 }

// ---------------------------------------------------------------------------
// Descendant management
// ---------------------------------------------------------------------------

// AddDescend adds a reading PcodeOp to this varnode's descendant list.
func (vn *Varnode) AddDescend(op *PcodeOp) {
	vn.descend = append(vn.descend, op)
}

// EraseDescend removes one occurrence of op from the descendant list.
func (vn *Varnode) EraseDescend(op *PcodeOp) {
	for i, d := range vn.descend {
		if d == op {
			vn.descend = append(vn.descend[:i], vn.descend[i+1:]...)
			return
		}
	}
}

// DestroyDescend clears the entire descendant list.
func (vn *Varnode) DestroyDescend() {
	vn.descend = vn.descend[:0]
}

// LoneDescend returns the single reading op, or nil if zero or multiple readers.
func (vn *Varnode) LoneDescend() *PcodeOp {
	if len(vn.descend) == 1 {
		return vn.descend[0]
	}
	return nil
}

// NumDescend returns the number of reading operations.
func (vn *Varnode) NumDescend() int {
	return len(vn.descend)
}

// DescendIter returns a snapshot copy of the descendant list.
func (vn *Varnode) DescendIter() []*PcodeOp {
	out := make([]*PcodeOp, len(vn.descend))
	copy(out, vn.descend)
	return out
}

// ---------------------------------------------------------------------------
// Overlap / intersection / containment
// C++ parity: varnode.cc Varnode::intersects, Varnode::contains, Varnode::overlap
// ---------------------------------------------------------------------------

// Intersects returns true if the byte ranges of two varnodes overlap in the same space.
// Constant-space varnodes never intersect (matching C++ behavior).
func (vn *Varnode) Intersects(other *Varnode) bool {
	if vn.loc.Space != other.loc.Space {
		return false
	}
	if vn.loc.Space.IsConstant() {
		return false
	}
	a := vn.loc.Offset
	b := other.loc.Offset
	if b < a {
		return a < b+uint64(other.size)
	}
	return b < a+uint64(vn.size)
}

// IntersectsAddr returns true if this varnode's range overlaps [addr, addr+sz).
func (vn *Varnode) IntersectsAddr(addr address.Address, sz int32) bool {
	if vn.loc.Space != addr.Space {
		return false
	}
	if vn.loc.Space.IsConstant() {
		return false
	}
	a := vn.loc.Offset
	b := addr.Offset
	if b < a {
		return a < b+uint64(sz)
	}
	return b < a+uint64(vn.size)
}

// Contains returns a containment code:
//
//	-1: other starts before this
//	 0: other is fully contained (equal extent or within)
//	 1: other starts inside but extends past end
//	 2: other starts at or after end
//	 3: different or constant spaces (non-comparable)
//
// C++ parity: varnode.cc Varnode::contains
func (vn *Varnode) Contains(other *Varnode) int {
	if vn.loc.Space != other.loc.Space {
		return 3
	}
	if vn.loc.Space.IsConstant() {
		return 3
	}
	a := vn.loc.Offset
	b := other.loc.Offset
	if b < a {
		return -1
	}
	if b >= a+uint64(vn.size) {
		return 2
	}
	if b+uint64(other.size) > a+uint64(vn.size) {
		return 1
	}
	return 0
}

// Overlap returns the byte offset where the LSB of this varnode falls within other,
// or -1 if no overlap. Endian-aware.
// C++ parity: varnode.cc Varnode::overlap
func (vn *Varnode) Overlap(other *Varnode) int {
	if vn.loc.Space != other.loc.Space {
		return -1
	}
	if vn.loc.Space.IsConstant() {
		return -1
	}
	if !vn.loc.Space.BigEndian {
		// Little endian: check offset+0 within other
		return addrOverlap(vn.loc.Offset, other.loc.Offset, int32(other.size))
	}
	// Big endian: check offset+(size-1) within other
	over := addrOverlap(vn.loc.Offset+uint64(vn.size-1), other.loc.Offset, other.size)
	if over != -1 {
		return int(other.size) - 1 - over
	}
	return -1
}

// OverlapAddr returns the byte offset where the LSB of this varnode falls within
// [addr, addr+sz), or -1 if no overlap. Endian-aware.
// C++ parity: varnode.cc Varnode::overlap(const Address&, int4)
func (vn *Varnode) OverlapAddr(addr address.Address, sz int32) int {
	if vn.loc.Space != addr.Space {
		return -1
	}
	if vn.loc.Space.IsConstant() {
		return -1
	}
	if !vn.loc.Space.BigEndian {
		return addrOverlap(vn.loc.Offset, addr.Offset, sz)
	}
	over := addrOverlap(vn.loc.Offset+uint64(vn.size-1), addr.Offset, sz)
	if over != -1 {
		return int(sz) - 1 - over
	}
	return -1
}

// addrOverlap checks if (self) falls in [base, base+size).
// Returns the distance from base, or -1.
// C++ parity: Address::overlap(int4 skip, const Address &op, int4 size)
// with skip=0 (little-endian path) or skip=size-1 (big-endian path).
func addrOverlap(self, base uint64, size int32) int {
	dist := self - base // unsigned wraparound is intentional
	if dist >= uint64(size) {
		return -1
	}
	return int(dist)
}

// ---------------------------------------------------------------------------
// String representation (debug)
// ---------------------------------------------------------------------------

func (vn *Varnode) String() string {
	status := "free"
	if vn.IsInput() {
		status = "input"
	} else if vn.IsWritten() {
		status = "written"
	}
	spaceName := "<nil>"
	if vn.loc.Space != nil {
		spaceName = vn.loc.Space.Name
	}
	return fmt.Sprintf("Varnode(%s:0x%x[%d] %s #%d)",
		spaceName, vn.loc.Offset, vn.size, status, vn.createIndex)
}

// ---------------------------------------------------------------------------
// SeqNum comparison (needed by VarnodeBank sort)
// C++ parity: address.hh SeqNum::operator<
// ---------------------------------------------------------------------------

// SeqNumLess returns true if a < b in the natural SeqNum ordering.
// Compares address first, then the unique id (Time field).
func SeqNumLess(a, b SeqNum) bool {
	if a.Address != b.Address {
		return a.Address.Less(b.Address)
	}
	return a.Time < b.Time
}

// SeqNumEqual returns true if two SeqNums are identical.
func SeqNumEqual(a, b SeqNum) bool {
	if a.Time != b.Time {
		return false
	}
	if a.Address.Space != b.Address.Space {
		return false
	}
	return a.Address.Offset == b.Address.Offset
}
