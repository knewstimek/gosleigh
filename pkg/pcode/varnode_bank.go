package pcode

import (

	"github.com/knewstimek/gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// VarnodeBank -- manages all Varnodes within a function
// C++ parity: varnode.hh VarnodeBank
// ---------------------------------------------------------------------------

// VarnodeBank manages all Varnodes within a function, sorted by location:
// (space, offset, size, status, seqnum/createIndex). The C++ def tree is not
// kept: nothing here iterates Varnodes in definition order.
type VarnodeBank struct {
	locTree     vnList         // sorted by location-then-definition
	maxSize     int32          // largest Varnode size ever inserted (bounds LocRange)
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
	if ia, ib := spaceOrder(a.loc.Space), spaceOrder(b.loc.Space); ia != ib {
		return cmpUint16(ia, ib)
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
		if a.def == nil || b.def == nil {
			if a.def == nil && b.def == nil {
				if a.createIndex != b.createIndex {
					return cmpUint32(a.createIndex, b.createIndex)
				}
				return 0
			}
			if a.def == nil {
				return -1
			}
			return 1
		}
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
		if a.def == nil || b.def == nil {
			if a.def == nil && b.def == nil {
				if a.createIndex != b.createIndex {
					return cmpUint32(a.createIndex, b.createIndex)
				}
				return 0
			}
			if a.def == nil {
				return -1
			}
			return 1
		}
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
	if ia, ib := spaceOrder(a.loc.Space), spaceOrder(b.loc.Space); ia != ib {
		return cmpUint16(ia, ib)
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
	p := vb.locTree.search(func(x *Varnode) bool { return CompareLocDef(x, vn) >= 0 })
	vb.locTree.insertAt(p, vn)
	if vn.size > vb.maxSize {
		vb.maxSize = vn.size
	}
}

// removeLoc removes vn from locTree.
func (vb *VarnodeBank) removeLoc(vn *Varnode) {
	p := vb.locTree.search(func(x *Varnode) bool { return CompareLocDef(x, vn) >= 0 })
	// Find the exact pointer among the equal keys.
	for x := vb.locTree.at(p); x != nil; x = vb.locTree.at(p) {
		if x == vn {
			vb.locTree.removeAt(p)
			return
		}
		if CompareLocDef(x, vn) > 0 {
			return
		}
		p = vb.locTree.next(p)
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Create creates a free varnode and inserts it in the loc tree.
func (vb *VarnodeBank) Create(size int32, loc address.Address) *Varnode {
	vn := NewVarnode(size, loc)
	vn.createIndex = vb.createIndex
	vb.createIndex++
	vb.insertLoc(vn)
	return vn
}

// CreateDef creates a varnode with a defining op and inserts it in the loc tree.
// Sets VarnodeInsert to match C++ VarnodeBank::xref which sets Varnode::insert
// for every non-free varnode entering the loc/def trees.
func (vb *VarnodeBank) CreateDef(size int32, loc address.Address, op *PcodeOp) *Varnode {
	vn := NewVarnode(size, loc)
	vn.createIndex = vb.createIndex
	vb.createIndex++
	vn.def = op
	vn.flags |= VarnodeWritten | VarnodeInsert
	vb.insertLoc(vn)
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
// Sets VarnodeInsert -- C++ xref sets Varnode::insert for all non-free varnodes.
func (vb *VarnodeBank) SetInput(vn *Varnode) {
	vb.removeLoc(vn)
	vn.flags |= VarnodeInput | VarnodeInsert
	vb.insertLoc(vn)
}

// SetDef transitions a free varnode to written status with the given defining op.
// The varnode must currently be free.
// Sets VarnodeInsert -- C++ xref sets Varnode::insert for all non-free varnodes.
func (vb *VarnodeBank) SetDef(vn *Varnode, op *PcodeOp) {
	vb.removeLoc(vn)
	vn.def = op
	vn.flags |= VarnodeWritten | VarnodeInsert
	vb.insertLoc(vn)
}

// MakeFree transitions an input or written varnode back to free status.
// Clears VarnodeInsert -- C++ makeFree clears insert|input|indirect_creation.
func (vb *VarnodeBank) MakeFree(vn *Varnode) {
	vb.removeLoc(vn)
	vn.flags &^= (VarnodeInput | VarnodeWritten | VarnodeInsert | VarnodeIndirectCreation)
	vn.def = nil
	vb.insertLoc(vn)
}

// Destroy removes a varnode from the loc tree. The varnode must be free
// with no descendants.
func (vb *VarnodeBank) Destroy(vn *Varnode) {
	vb.removeLoc(vn)
	// A destroyed Varnode leaves its HighVariable, or the high keeps a stale
	// instance whose type still votes in getTypeRepresentative.
	// C++ parity: Varnode::~Varnode (high->remove(this)).
	if hv := vn.high; hv != nil {
		hv.removeInstance(vn)
		vn.high = nil
	}
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

// lowerLoc is the first locTree position whose (space, offset, size) is not
// below the given key. C++ parity: VarnodeBank::beginLoc (loc_tree lower_bound).
func (vb *VarnodeBank) lowerLoc(spc *address.Space, off uint64, size int32) vnPos {
	so := spaceOrder(spc)
	return vb.locTree.search(func(vn *Varnode) bool {
		if o := spaceOrder(vn.loc.Space); o != so {
			return o > so
		}
		if vn.loc.Offset != off {
			return vn.loc.Offset > off
		}
		return vn.size >= size
	})
}

// FindInput finds an input varnode with the exact (size, loc) in the loc_tree.
// Returns nil if not found.
// C++ parity: VarnodeBank::findInput.
func (vb *VarnodeBank) FindInput(size int32, loc address.Address) *Varnode {
	for p := vb.lowerLoc(loc.Space, loc.Offset, size); ; p = vb.locTree.next(p) {
		vn := vb.locTree.at(p)
		if vn == nil || vn.loc.Space != loc.Space || vn.loc.Offset != loc.Offset || vn.size != size {
			return nil
		}
		if vn.IsInput() {
			return vn
		}
		// In locTree order, input comes before written/free at same loc+size,
		// so if we passed it, stop.
		if vn.IsWritten() || vn.IsFree() {
			return nil
		}
	}
}

// NumVarnodes returns the total number of managed varnodes.
func (vb *VarnodeBank) NumVarnodes() int {
	return vb.locTree.Len()
}

// Clear removes all varnodes.
func (vb *VarnodeBank) Clear() {
	vb.locTree.clear()
	vb.maxSize = 0
	vb.uniqID = vb.uniqBase
	vb.createIndex = 0
}

// AllVarnodes returns a snapshot of all varnodes in locTree order.
func (vb *VarnodeBank) AllVarnodes() []*Varnode {
	return vb.locTree.all()
}

// LocRange returns all varnodes whose address overlaps [addr, addr+size)
// within the given space, in loc order. The scan starts maxSize bytes before
// the range: no Varnode starting earlier can reach into it.
// C++ parity: VarnodeBank loc-tree range queries
func (vb *VarnodeBank) LocRange(addr address.Address, size int32) []*Varnode {
	var result []*Varnode
	if size <= 0 {
		return nil
	}
	// Compare last bytes so a range ending at the top of the space does not
	// wrap. C++ parity: Heritage::collect (endaddr wraparound check).
	last := addr.Offset + uint64(size) - 1
	start := uint64(0)
	if back := uint64(vb.maxSize); addr.Offset > back {
		start = addr.Offset - back
	}
	so := spaceOrder(addr.Space)
	for p := vb.lowerLoc(addr.Space, start, 0); ; p = vb.locTree.next(p) {
		vn := vb.locTree.at(p)
		if vn == nil || spaceOrder(vn.loc.Space) != so || vn.loc.Offset > last {
			break // sorted by offset: nothing later can overlap
		}
		if vn.loc.Space == addr.Space && vn.size > 0 && vn.loc.Offset+uint64(vn.size)-1 >= addr.Offset {
			result = append(result, vn)
		}
	}
	return result
}

// LocExact returns the varnodes with exactly this address and size, in loc
// order (input first, then written by definition, then free).
// C++ parity: VarnodeBank::beginLoc(size,addr) / endLoc(size,addr).
func (vb *VarnodeBank) LocExact(addr address.Address, size int32) []*Varnode {
	var result []*Varnode
	for p := vb.lowerLoc(addr.Space, addr.Offset, size); ; p = vb.locTree.next(p) {
		vn := vb.locTree.at(p)
		if vn == nil || vn.loc != addr || vn.size != size {
			break
		}
		result = append(result, vn)
	}
	return result
}

// BySpace returns all varnodes in the given address space.
// C++ parity: VarnodeBank space iteration
func (vb *VarnodeBank) BySpace(spc *address.Space) []*Varnode {
	var result []*Varnode
	so := spaceOrder(spc)
	for p := vb.lowerLoc(spc, 0, 0); ; p = vb.locTree.next(p) {
		vn := vb.locTree.at(p)
		if vn == nil || spaceOrder(vn.loc.Space) != so {
			break
		}
		if vn.loc.Space == spc {
			result = append(result, vn)
		}
	}
	return result
}

// spaceOrder is the space's position in Varnode location order. The constant
// space always comes first (Gosleigh gives it a sentinel index).
// C++ parity: translate.cc -- the constant space is assigned index 0.
func spaceOrder(sp *address.Space) uint16 {
	if sp.Kind == address.SpaceKindConstant {
		return 0
	}
	return sp.Index
}
