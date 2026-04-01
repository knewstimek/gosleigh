package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// VarnodeBank -- manages all Varnodes within a function
// C++ parity: varnode.hh VarnodeBank
// ---------------------------------------------------------------------------

// VarnodeBank manages all Varnodes within a function with two sorted indices.
// locTree is sorted by (space, offset, size, status, seqnum/createIndex).
// defTree is sorted by (status, seqnum, space, offset, size, createIndex).
type VarnodeBank struct {
	locTree     []*Varnode     // sorted by location-then-definition
	defTree     []*Varnode     // sorted by definition-then-location
	uniqSpace   *address.Space // unique/temp space
	uniqBase    uint64         // starting offset for unique allocations
	uniqID      uint64         // current unique offset counter
	createIndex uint32         // monotonic varnode creation counter
}

// NewVarnodeBank creates a VarnodeBank.
func NewVarnodeBank(uniqSpace *address.Space, uniqBase uint64) *VarnodeBank {
	return &VarnodeBank{
		uniqSpace: uniqSpace,
		uniqBase:  uniqBase,
		uniqID:    uniqBase,
	}
}

// ---------------------------------------------------------------------------
// Comparison functions
// C++ parity: varnode.cc VarnodeCompareLocDef, VarnodeCompareDefLoc
// ---------------------------------------------------------------------------

// varnodeStatusOrder returns the sort key for varnode status flags.
// The (f-1) unsigned trick makes free varnodes sort last:
//
//	input  (0x08) -> 0x07
//	written(0x10) -> 0x0F
//	free   (0x00) -> 0xFFFFFFFF
//
// C++ parity: (f-1) trick in VarnodeCompareLocDef/VarnodeCompareDefLoc
func varnodeStatusOrder(flags uint32) uint32 {
	f := flags & (VarnodeInput | VarnodeWritten)
	return f - 1 // unsigned wraparound for free (0-1 = MaxUint32)
}

// CompareLocDef compares two Varnodes in loc_tree order.
// Order: space.Index, offset, size, status, (seqnum if written, createIndex if free).
// Returns -1, 0, or 1.
// C++ parity: VarnodeCompareLocDef::operator()
func CompareLocDef(a, b *Varnode) int {
	// 1. Space index
	if a.loc.Space.Index != b.loc.Space.Index {
		return cmpUint16(a.loc.Space.Index, b.loc.Space.Index)
	}
	// 2. Offset
	if a.loc.Offset != b.loc.Offset {
		return cmpUint64(a.loc.Offset, b.loc.Offset)
	}
	// 3. Size
	if a.size != b.size {
		return cmpInt32(a.size, b.size)
	}
	// 4. Status
	sa := varnodeStatusOrder(a.flags)
	sb := varnodeStatusOrder(b.flags)
	if sa != sb {
		return cmpUint32(sa, sb)
	}
	// 5. If both written: compare by defining op SeqNum
	fa := a.flags & (VarnodeInput | VarnodeWritten)
	if fa == VarnodeWritten {
		seqA := a.def.Seq()
		seqB := b.def.Seq()
		if !SeqNumEqual(seqA, seqB) {
			if SeqNumLess(seqA, seqB) {
				return -1
			}
			return 1
		}
	} else if fa == 0 {
		// 6. If both free: compare by createIndex
		if a.createIndex != b.createIndex {
			return cmpUint32(a.createIndex, b.createIndex)
		}
	}
	return 0
}

// CompareDefLoc compares two Varnodes in def_tree order.
// Order: status, (seqnum if written), space.Index, offset, size, (createIndex if free).
// Returns -1, 0, or 1.
// C++ parity: VarnodeCompareDefLoc::operator()
func CompareDefLoc(a, b *Varnode) int {
	// 1. Status
	fa := a.flags & (VarnodeInput | VarnodeWritten)
	fb := b.flags & (VarnodeInput | VarnodeWritten)
	sa := fa - 1
	sb := fb - 1
	if sa != sb {
		return cmpUint32(sa, sb)
	}
	// 2. If both written: compare by defining op SeqNum
	if fa == VarnodeWritten {
		seqA := a.def.Seq()
		seqB := b.def.Seq()
		if !SeqNumEqual(seqA, seqB) {
			if SeqNumLess(seqA, seqB) {
				return -1
			}
			return 1
		}
	}
	// 3. Space index
	if a.loc.Space.Index != b.loc.Space.Index {
		return cmpUint16(a.loc.Space.Index, b.loc.Space.Index)
	}
	// 4. Offset
	if a.loc.Offset != b.loc.Offset {
		return cmpUint64(a.loc.Offset, b.loc.Offset)
	}
	// 5. Size
	if a.size != b.size {
		return cmpInt32(a.size, b.size)
	}
	// 6. If both free: compare by createIndex
	if fa == 0 {
		if a.createIndex != b.createIndex {
			return cmpUint32(a.createIndex, b.createIndex)
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Numeric comparison helpers
// ---------------------------------------------------------------------------

func cmpUint16(a, b uint16) int {
	if a < b {
		return -1
	}
	return 1
}

func cmpUint32(a, b uint32) int {
	if a < b {
		return -1
	}
	return 1
}

func cmpUint64(a, b uint64) int {
	if a < b {
		return -1
	}
	return 1
}

func cmpInt32(a, b int32) int {
	if a < b {
		return -1
	}
	return 1
}

// ---------------------------------------------------------------------------
// Tree insertion/removal helpers
// ---------------------------------------------------------------------------

// insertLoc inserts vn into locTree maintaining sorted order.
func (vb *VarnodeBank) insertLoc(vn *Varnode) {
	pos := sort.Search(len(vb.locTree), func(i int) bool {
		return CompareLocDef(vb.locTree[i], vn) >= 0
	})
	vb.locTree = append(vb.locTree, nil)
	copy(vb.locTree[pos+1:], vb.locTree[pos:])
	vb.locTree[pos] = vn
}

// insertDef inserts vn into defTree maintaining sorted order.
func (vb *VarnodeBank) insertDef(vn *Varnode) {
	pos := sort.Search(len(vb.defTree), func(i int) bool {
		return CompareDefLoc(vb.defTree[i], vn) >= 0
	})
	vb.defTree = append(vb.defTree, nil)
	copy(vb.defTree[pos+1:], vb.defTree[pos:])
	vb.defTree[pos] = vn
}

// removeLoc removes vn from locTree.
func (vb *VarnodeBank) removeLoc(vn *Varnode) {
	pos := sort.Search(len(vb.locTree), func(i int) bool {
		return CompareLocDef(vb.locTree[i], vn) >= 0
	})
	// Find exact pointer match at or near pos
	for i := pos; i < len(vb.locTree); i++ {
		if vb.locTree[i] == vn {
			vb.locTree = append(vb.locTree[:i], vb.locTree[i+1:]...)
			return
		}
		if CompareLocDef(vb.locTree[i], vn) > 0 {
			break
		}
	}
}

// removeDef removes vn from defTree.
func (vb *VarnodeBank) removeDef(vn *Varnode) {
	pos := sort.Search(len(vb.defTree), func(i int) bool {
		return CompareDefLoc(vb.defTree[i], vn) >= 0
	})
	for i := pos; i < len(vb.defTree); i++ {
		if vb.defTree[i] == vn {
			vb.defTree = append(vb.defTree[:i], vb.defTree[i+1:]...)
			return
		}
		if CompareDefLoc(vb.defTree[i], vn) > 0 {
			break
		}
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Create creates a free varnode and inserts it in both trees.
func (vb *VarnodeBank) Create(size int32, loc address.Address) *Varnode {
	vn := NewVarnode(size, loc)
	vn.createIndex = vb.createIndex
	vb.createIndex++
	vb.insertLoc(vn)
	vb.insertDef(vn)
	return vn
}

// CreateDef creates a varnode with a defining op and inserts it in both trees.
func (vb *VarnodeBank) CreateDef(size int32, loc address.Address, op *PcodeOp) *Varnode {
	vn := NewVarnode(size, loc)
	vn.createIndex = vb.createIndex
	vb.createIndex++
	vn.def = op
	vn.flags |= VarnodeWritten
	vb.insertLoc(vn)
	vb.insertDef(vn)
	return vn
}

// CreateUnique allocates a varnode in unique space, advancing the unique counter.
func (vb *VarnodeBank) CreateUnique(size int32) *Varnode {
	loc := address.Address{Space: vb.uniqSpace, Offset: vb.uniqID}
	vb.uniqID += uint64(size)
	return vb.Create(size, loc)
}

// CreateDefUnique allocates a unique-space varnode with a defining op.
func (vb *VarnodeBank) CreateDefUnique(size int32, op *PcodeOp) *Varnode {
	loc := address.Address{Space: vb.uniqSpace, Offset: vb.uniqID}
	vb.uniqID += uint64(size)
	return vb.CreateDef(size, loc, op)
}

// SetInput transitions a free varnode to input status.
// The varnode must currently be free.
func (vb *VarnodeBank) SetInput(vn *Varnode) {
	vb.removeLoc(vn)
	vb.removeDef(vn)
	vn.flags |= VarnodeInput
	vb.insertLoc(vn)
	vb.insertDef(vn)
}

// SetDef transitions a free varnode to written status with the given defining op.
// The varnode must currently be free.
func (vb *VarnodeBank) SetDef(vn *Varnode, op *PcodeOp) {
	vb.removeLoc(vn)
	vb.removeDef(vn)
	vn.def = op
	vn.flags |= VarnodeWritten
	vb.insertLoc(vn)
	vb.insertDef(vn)
}

// MakeFree transitions an input or written varnode back to free status.
func (vb *VarnodeBank) MakeFree(vn *Varnode) {
	vb.removeLoc(vn)
	vb.removeDef(vn)
	vn.flags &^= (VarnodeInput | VarnodeWritten)
	vn.def = nil
	vb.insertLoc(vn)
	vb.insertDef(vn)
}

// Destroy removes a varnode from both trees. The varnode must be free
// with no descendants.
func (vb *VarnodeBank) Destroy(vn *Varnode) {
	vb.removeLoc(vn)
	vb.removeDef(vn)
}

// Replace rewires all descendant PcodeOps from oldVn to newVn.
// This is a placeholder -- full input-slot rewiring requires PcodeOp input tracking
// which is part of WU1. For now it moves the descend list.
func (vb *VarnodeBank) Replace(oldVn, newVn *Varnode) {
	for _, op := range oldVn.descend {
		newVn.AddDescend(op)
	}
	oldVn.DestroyDescend()
}

// FindInput finds an input varnode with the exact (size, loc) in the loc_tree.
// Returns nil if not found.
func (vb *VarnodeBank) FindInput(size int32, loc address.Address) *Varnode {
	// Build a search key: an input varnode at the given location
	for _, vn := range vb.locTree {
		if vn.loc.Space != loc.Space {
			if vn.loc.Space.Index > loc.Space.Index {
				break
			}
			continue
		}
		if vn.loc.Offset != loc.Offset {
			if vn.loc.Offset > loc.Offset {
				break
			}
			continue
		}
		if vn.size != size {
			if vn.size > size {
				break
			}
			continue
		}
		if vn.IsInput() {
			return vn
		}
		// In locTree order, input comes before written/free at same loc+size,
		// so if we passed it, stop.
		if vn.IsWritten() || vn.IsFree() {
			break
		}
	}
	return nil
}

// NumVarnodes returns the total number of managed varnodes.
func (vb *VarnodeBank) NumVarnodes() int {
	return len(vb.locTree)
}

// Clear removes all varnodes.
func (vb *VarnodeBank) Clear() {
	vb.locTree = vb.locTree[:0]
	vb.defTree = vb.defTree[:0]
	vb.uniqID = vb.uniqBase
	vb.createIndex = 0
}

// AllVarnodes returns a snapshot of all varnodes in locTree order.
func (vb *VarnodeBank) AllVarnodes() []*Varnode {
	out := make([]*Varnode, len(vb.locTree))
	copy(out, vb.locTree)
	return out
}
