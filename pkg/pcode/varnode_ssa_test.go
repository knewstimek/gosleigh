package pcode

import (
	"math"
	"testing"

	"gosleigh/pkg/address"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeSpace(name string, kind address.SpaceKind, idx uint16) *address.Space {
	return &address.Space{
		Name:     name,
		Kind:     kind,
		Index:    idx,
		AddrSize: 8,
		WordSize: 1,
	}
}

func makeBigEndianSpace(name string, kind address.SpaceKind, idx uint16) *address.Space {
	return &address.Space{
		Name:      name,
		Kind:      kind,
		Index:     idx,
		AddrSize:  8,
		WordSize:  1,
		BigEndian: true,
	}
}

var (
	testRAM   = makeSpace("ram", address.SpaceKindProcessor, 1)
	testConst = makeSpace("const", address.SpaceKindConstant, 0)
	testUniq  = makeSpace("unique", address.SpaceKindUnique, 2)
	testFspec = makeSpace("fspec", address.SpaceKindFspec, 3)
	testIop   = makeSpace("iop", address.SpaceKindIop, 4)
)

func addr(sp *address.Space, off uint64) address.Address {
	return address.Address{Space: sp, Offset: off}
}

// ---------------------------------------------------------------------------
// Varnode construction and flag tests
// ---------------------------------------------------------------------------

func TestNewVarnode_ConstantSpace(t *testing.T) {
	vn := NewVarnode(8, addr(testConst, 0x42))
	if !vn.IsConstant() {
		t.Fatal("expected constant flag")
	}
	if vn.NZMask() != 0x42 {
		t.Fatalf("expected nzm=0x42, got 0x%x", vn.NZMask())
	}
	if vn.HasFlags(VarnodeCoverDirty) {
		t.Fatal("constant should not have cover dirty")
	}
}

func TestNewVarnode_FspecSpace(t *testing.T) {
	vn := NewVarnode(4, addr(testFspec, 0))
	if !vn.IsAnnotation() {
		t.Fatal("expected annotation flag for fspec")
	}
	if !vn.HasFlags(VarnodeCoverDirty) {
		t.Fatal("expected cover dirty for fspec")
	}
	if vn.NZMask() != ^uint64(0) {
		t.Fatal("expected all-ones nzm for fspec")
	}
}

func TestNewVarnode_IopSpace(t *testing.T) {
	vn := NewVarnode(4, addr(testIop, 0))
	if !vn.IsAnnotation() {
		t.Fatal("expected annotation flag for iop")
	}
}

func TestNewVarnode_NormalSpace(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0x1000))
	if vn.IsConstant() || vn.IsAnnotation() {
		t.Fatal("normal space should not be constant or annotation")
	}
	if !vn.HasFlags(VarnodeCoverDirty) {
		t.Fatal("expected cover dirty for normal space")
	}
	if vn.NZMask() != ^uint64(0) {
		t.Fatal("expected all-ones nzm")
	}
}

func TestNewVarnode_NilSpace(t *testing.T) {
	vn := NewVarnode(4, address.Address{})
	if vn.Flags() != 0 {
		t.Fatalf("nil space should produce zero flags, got 0x%x", vn.Flags())
	}
}

func TestVarnode_FlagOps(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0))
	vn.SetFlags(VarnodeTypeLock | VarnodeNameLock)
	if !vn.HasFlags(VarnodeTypeLock) {
		t.Fatal("expected type lock")
	}
	if !vn.HasFlags(VarnodeNameLock) {
		t.Fatal("expected name lock")
	}
	vn.ClearFlags(VarnodeTypeLock)
	if vn.HasFlags(VarnodeTypeLock) {
		t.Fatal("type lock should be cleared")
	}
	if !vn.HasFlags(VarnodeNameLock) {
		t.Fatal("name lock should still be set")
	}
}

func TestVarnode_BooleanQueries(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0))
	// Free by default (not written, not input)
	if !vn.IsFree() {
		t.Fatal("expected free")
	}
	if vn.IsInput() || vn.IsWritten() {
		t.Fatal("should not be input or written")
	}

	vn.SetFlags(VarnodeInput)
	if vn.IsFree() {
		t.Fatal("input should not be free")
	}
	if !vn.IsInput() {
		t.Fatal("expected input")
	}

	vn.ClearFlags(VarnodeInput)
	vn.SetFlags(VarnodeWritten)
	if vn.IsFree() {
		t.Fatal("written should not be free")
	}
	if !vn.IsWritten() {
		t.Fatal("expected written")
	}
}

func TestVarnode_MarkSetClear(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0))
	if vn.IsMark() {
		t.Fatal("should not be marked initially")
	}
	vn.SetMark()
	if !vn.IsMark() {
		t.Fatal("should be marked")
	}
	vn.ClearMark()
	if vn.IsMark() {
		t.Fatal("should not be marked after clear")
	}
}

func TestVarnode_ConsumedDefault(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0))
	if vn.Consumed() != ^uint64(0) {
		t.Fatal("consumed should default to all-ones")
	}
}

// ---------------------------------------------------------------------------
// Descendant management
// ---------------------------------------------------------------------------

func TestVarnode_Descendants(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0))
	op1 := &PcodeOp{}
	op2 := &PcodeOp{}

	if !vn.HasNoDescend() {
		t.Fatal("should have no descendants initially")
	}

	vn.AddDescend(op1)
	vn.AddDescend(op2)
	if vn.NumDescend() != 2 {
		t.Fatalf("expected 2 descendants, got %d", vn.NumDescend())
	}
	if vn.LoneDescend() != nil {
		t.Fatal("lone descend should be nil with 2 readers")
	}

	vn.EraseDescend(op1)
	if vn.NumDescend() != 1 {
		t.Fatalf("expected 1 descendant after erase, got %d", vn.NumDescend())
	}
	if vn.LoneDescend() != op2 {
		t.Fatal("lone descend should be op2")
	}

	snap := vn.DescendIter()
	if len(snap) != 1 || snap[0] != op2 {
		t.Fatal("snapshot mismatch")
	}

	vn.DestroyDescend()
	if !vn.HasNoDescend() {
		t.Fatal("should have no descendants after destroy")
	}
}

// ---------------------------------------------------------------------------
// Overlap / intersection / containment
// ---------------------------------------------------------------------------

func TestVarnode_Intersects(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x100))
	b := NewVarnode(4, addr(testRAM, 0x102))
	c := NewVarnode(4, addr(testRAM, 0x104))

	if !a.Intersects(b) {
		t.Fatal("a and b should intersect")
	}
	if a.Intersects(c) {
		t.Fatal("a and c should not intersect")
	}

	// Different spaces
	d := NewVarnode(4, addr(testUniq, 0x100))
	if a.Intersects(d) {
		t.Fatal("different spaces should not intersect")
	}

	// Constant space never intersects
	e := NewVarnode(4, addr(testConst, 0x100))
	f := NewVarnode(4, addr(testConst, 0x100))
	if e.Intersects(f) {
		t.Fatal("constant varnodes should not intersect")
	}
}

func TestVarnode_IntersectsAddr(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x100))
	if !a.IntersectsAddr(addr(testRAM, 0x102), 4) {
		t.Fatal("should intersect")
	}
	if a.IntersectsAddr(addr(testRAM, 0x104), 4) {
		t.Fatal("should not intersect")
	}
}

func TestVarnode_Contains(t *testing.T) {
	big := NewVarnode(8, addr(testRAM, 0x100))
	small := NewVarnode(2, addr(testRAM, 0x100))
	before := NewVarnode(2, addr(testRAM, 0x0FF))
	after := NewVarnode(2, addr(testRAM, 0x108))
	partial := NewVarnode(4, addr(testRAM, 0x106))
	constVn := NewVarnode(4, addr(testConst, 0x100))

	if big.Contains(small) != 0 {
		t.Fatal("small should be contained in big")
	}
	if big.Contains(before) != -1 {
		t.Fatal("before should return -1")
	}
	if big.Contains(after) != 2 {
		t.Fatal("after should return 2")
	}
	if big.Contains(partial) != 1 {
		t.Fatal("partial overlap should return 1")
	}
	if big.Contains(constVn) != 3 {
		t.Fatal("different spaces should return 3")
	}
}

func TestVarnode_Overlap_LittleEndian(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x100))
	b := NewVarnode(4, addr(testRAM, 0x100))
	if a.Overlap(b) != 0 {
		t.Fatal("exact overlap should return 0")
	}

	c := NewVarnode(4, addr(testRAM, 0x102))
	over := a.Overlap(c)
	// a starts at 0x100, c starts at 0x102 with size 4 (covers 0x102..0x105)
	// a's LSB is at 0x100, which is before c's range, so -1
	if over != -1 {
		t.Fatalf("expected -1 for non-overlapping LSB, got %d", over)
	}

	// c.Overlap(a): c's LSB at 0x102, a covers 0x100..0x103
	over2 := c.Overlap(a)
	// c's offset 0x102 falls at distance 2 from a's start 0x100
	if over2 != 2 {
		t.Fatalf("expected overlap offset 2, got %d", over2)
	}
}

func TestVarnode_Overlap_BigEndian(t *testing.T) {
	beRAM := makeBigEndianSpace("ram_be", address.SpaceKindProcessor, 10)
	a := NewVarnode(4, address.Address{Space: beRAM, Offset: 0x100})
	b := NewVarnode(4, address.Address{Space: beRAM, Offset: 0x100})
	if a.Overlap(b) != 0 {
		t.Fatal("exact overlap in big-endian should return 0")
	}
}

func TestVarnode_OverlapAddr(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x100))
	over := a.OverlapAddr(addr(testRAM, 0x100), 8)
	if over != 0 {
		t.Fatalf("expected 0, got %d", over)
	}

	over2 := a.OverlapAddr(addr(testRAM, 0x200), 4)
	if over2 != -1 {
		t.Fatalf("expected -1, got %d", over2)
	}
}

// ---------------------------------------------------------------------------
// Status ordering: input < written < free
// ---------------------------------------------------------------------------

func TestStatusOrder(t *testing.T) {
	inputOrder := varnodeStatusOrder(VarnodeInput)
	writtenOrder := varnodeStatusOrder(VarnodeWritten)
	freeOrder := varnodeStatusOrder(0)

	if inputOrder >= writtenOrder {
		t.Fatalf("input(0x%x) should be < written(0x%x)", inputOrder, writtenOrder)
	}
	if writtenOrder >= freeOrder {
		t.Fatalf("written(0x%x) should be < free(0x%x)", writtenOrder, freeOrder)
	}
	if freeOrder != math.MaxUint32 {
		t.Fatalf("free order should be MaxUint32, got 0x%x", freeOrder)
	}
}

// ---------------------------------------------------------------------------
// Flag constants are distinct
// ---------------------------------------------------------------------------

func TestFlagConstantsDistinct(t *testing.T) {
	flags := []uint32{
		VarnodeMark, VarnodeConstant, VarnodeAnnotation, VarnodeInput,
		VarnodeWritten, VarnodeInsert, VarnodeImplied, VarnodeExplicit,
		VarnodeTypeLock, VarnodeNameLock, VarnodeNoLocalAlias, VarnodeVolatile,
		VarnodeExternRef, VarnodeReadOnly, VarnodePersist, VarnodeAddrTied,
		VarnodeUnaffected, VarnodeSpaceBase, VarnodeIndirectOnly, VarnodeDirectWrite,
		VarnodeAddrForce, VarnodeMapped, VarnodeIndirectCreation, VarnodeReturnAddress,
		VarnodeCoverDirty, VarnodePrecisLo, VarnodePrecisHi, VarnodeIndirectStorage,
		VarnodeHiddenRetParm, VarnodeIncidentalCopy, VarnodeAutoLiveHold, VarnodeProtoPartial,
	}
	seen := make(map[uint32]bool)
	for _, f := range flags {
		if seen[f] {
			t.Fatalf("duplicate flag value 0x%x", f)
		}
		seen[f] = true
	}
}

func TestAddlFlagConstantsDistinct(t *testing.T) {
	flags := []uint16{
		VarnodeActiveHeritage, VarnodeWriteMask, VarnodeVacConsume,
		VarnodeLisConsume, VarnodePtrCheck, VarnodePtrFlow,
		VarnodeUnsignedPrint, VarnodeLongPrint, VarnodeStackStore,
		VarnodeLockedInput, VarnodeSpacebasePlaceholder,
		VarnodeStopUpPropagation, VarnodeHasImpliedField,
	}
	seen := make(map[uint16]bool)
	for _, f := range flags {
		if seen[f] {
			t.Fatalf("duplicate addl flag value 0x%x", f)
		}
		seen[f] = true
	}
}

// ---------------------------------------------------------------------------
// VarnodeBank tests
// ---------------------------------------------------------------------------

func TestVarnodeBank_CreateAndFind(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)

	vn1 := vb.Create(4, addr(testRAM, 0x100))
	vn2 := vb.Create(4, addr(testRAM, 0x200))
	vn3 := vb.Create(8, addr(testRAM, 0x100))

	if vb.NumVarnodes() != 3 {
		t.Fatalf("expected 3 varnodes, got %d", vb.NumVarnodes())
	}

	// createIndex should be monotonic
	if vn1.CreateIndex() >= vn2.CreateIndex() || vn2.CreateIndex() >= vn3.CreateIndex() {
		t.Fatal("create indices should be strictly increasing")
	}
}

func TestVarnodeBank_LocTreeOrder(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)

	// Insert in reverse order
	vb.Create(4, addr(testRAM, 0x300))
	vb.Create(4, addr(testRAM, 0x100))
	vb.Create(4, addr(testRAM, 0x200))

	all := vb.AllVarnodes()
	for i := 1; i < len(all); i++ {
		if CompareLocDef(all[i-1], all[i]) >= 0 {
			t.Fatalf("locTree not sorted at index %d: %v >= %v", i, all[i-1], all[i])
		}
	}
}

func TestVarnodeBank_StateTransition_FreeToInput(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vn := vb.Create(4, addr(testRAM, 0x100))

	if !vn.IsFree() {
		t.Fatal("should start free")
	}

	vb.SetInput(vn)
	if !vn.IsInput() {
		t.Fatal("should be input after SetInput")
	}
	if vn.IsFree() {
		t.Fatal("should not be free after SetInput")
	}

	// FindInput should locate it
	found := vb.FindInput(4, addr(testRAM, 0x100))
	if found != vn {
		t.Fatal("FindInput should find the input varnode")
	}

	// Verify sorted invariant maintained
	all := vb.AllVarnodes()
	for i := 1; i < len(all); i++ {
		if CompareLocDef(all[i-1], all[i]) >= 0 {
			t.Fatalf("locTree not sorted after SetInput at index %d", i)
		}
	}
}

func TestVarnodeBank_StateTransition_FreeToWritten(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vn := vb.Create(4, addr(testRAM, 0x100))

	op := &PcodeOp{}
	op.SetSeqNum(SeqNum{Address: addr(testRAM, 0x400), Time: 1})

	vb.SetDef(vn, op)
	if !vn.IsWritten() {
		t.Fatal("should be written after SetDef")
	}
	if vn.Def() != op {
		t.Fatal("def should be the op we set")
	}
}

func TestVarnodeBank_StateTransition_WrittenToFree(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vn := vb.Create(4, addr(testRAM, 0x100))

	op := &PcodeOp{}
	op.SetSeqNum(SeqNum{Address: addr(testRAM, 0x400), Time: 1})

	vb.SetDef(vn, op)
	if !vn.IsWritten() {
		t.Fatal("should be written")
	}

	vb.MakeFree(vn)
	if !vn.IsFree() {
		t.Fatal("should be free after MakeFree")
	}
	if vn.Def() != nil {
		t.Fatal("def should be nil after MakeFree")
	}
}

func TestVarnodeBank_Destroy(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vn := vb.Create(4, addr(testRAM, 0x100))
	vb.Create(4, addr(testRAM, 0x200))

	vb.Destroy(vn)
	if vb.NumVarnodes() != 1 {
		t.Fatalf("expected 1 varnode after destroy, got %d", vb.NumVarnodes())
	}
}

func TestVarnodeBank_UniqueAllocation(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)

	vn1 := vb.CreateUnique(4)
	vn2 := vb.CreateUnique(8)

	if vn1.Offset() != 0x10000 {
		t.Fatalf("first unique offset should be 0x10000, got 0x%x", vn1.Offset())
	}
	if vn2.Offset() != 0x10004 {
		t.Fatalf("second unique offset should be 0x10004, got 0x%x", vn2.Offset())
	}
	if vn1.Space() != testUniq || vn2.Space() != testUniq {
		t.Fatal("unique varnodes should be in unique space")
	}
}

func TestVarnodeBank_CreateDefUnique(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x20000)
	op := &PcodeOp{}
	op.SetSeqNum(SeqNum{Address: addr(testRAM, 0x400), Time: 5})

	vn := vb.CreateDefUnique(4, op)
	if !vn.IsWritten() {
		t.Fatal("should be written")
	}
	if vn.Def() != op {
		t.Fatal("def mismatch")
	}
	if vn.Offset() != 0x20000 {
		t.Fatalf("expected offset 0x20000, got 0x%x", vn.Offset())
	}
}

func TestVarnodeBank_Clear(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vb.Create(4, addr(testRAM, 0x100))
	vb.Create(4, addr(testRAM, 0x200))
	vb.CreateUnique(4)

	vb.Clear()
	if vb.NumVarnodes() != 0 {
		t.Fatalf("expected 0 after clear, got %d", vb.NumVarnodes())
	}
}

func TestVarnodeBank_FindInput_NotFound(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	vb.Create(4, addr(testRAM, 0x100)) // free, not input

	found := vb.FindInput(4, addr(testRAM, 0x100))
	if found != nil {
		t.Fatal("should not find a free varnode as input")
	}
}

func TestVarnodeBank_Replace(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)
	oldVn := vb.Create(4, addr(testRAM, 0x100))
	newVn := vb.Create(4, addr(testRAM, 0x200))

	op1 := &PcodeOp{}
	op2 := &PcodeOp{}
	oldVn.AddDescend(op1)
	oldVn.AddDescend(op2)

	vb.Replace(oldVn, newVn)
	if oldVn.NumDescend() != 0 {
		t.Fatal("old varnode should have no descendants after replace")
	}
	if newVn.NumDescend() != 2 {
		t.Fatalf("new varnode should have 2 descendants, got %d", newVn.NumDescend())
	}
}

// ---------------------------------------------------------------------------
// CompareLocDef ordering tests
// ---------------------------------------------------------------------------

func TestCompareLocDef_DifferentSpace(t *testing.T) {
	a := NewVarnode(4, addr(testConst, 0x100)) // space index 0
	b := NewVarnode(4, addr(testRAM, 0x100))   // space index 1
	if CompareLocDef(a, b) >= 0 {
		t.Fatal("lower space index should come first")
	}
	if CompareLocDef(b, a) <= 0 {
		t.Fatal("higher space index should come second")
	}
}

func TestCompareLocDef_DifferentOffset(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x100))
	b := NewVarnode(4, addr(testRAM, 0x200))
	if CompareLocDef(a, b) >= 0 {
		t.Fatal("lower offset should come first")
	}
}

func TestCompareLocDef_DifferentSize(t *testing.T) {
	a := NewVarnode(2, addr(testRAM, 0x100))
	b := NewVarnode(4, addr(testRAM, 0x100))
	if CompareLocDef(a, b) >= 0 {
		t.Fatal("smaller size should come first")
	}
}

func TestCompareLocDef_StatusOrder(t *testing.T) {
	// Create three varnodes at same loc+size with different status
	input := NewVarnode(4, addr(testRAM, 0x100))
	input.flags |= VarnodeInput

	written := NewVarnode(4, addr(testRAM, 0x100))
	written.flags |= VarnodeWritten
	written.def = &PcodeOp{}
	written.def.SetSeqNum(SeqNum{Address: addr(testRAM, 0), Time: 1})

	free := NewVarnode(4, addr(testRAM, 0x100))

	// input < written < free
	if CompareLocDef(input, written) >= 0 {
		t.Fatal("input should come before written")
	}
	if CompareLocDef(written, free) >= 0 {
		t.Fatal("written should come before free")
	}
	if CompareLocDef(input, free) >= 0 {
		t.Fatal("input should come before free")
	}
}

func TestCompareLocDef_WrittenBySeqNum(t *testing.T) {
	op1 := &PcodeOp{}
	op1.SetSeqNum(SeqNum{Address: addr(testRAM, 0x100), Time: 1})
	op2 := &PcodeOp{}
	op2.SetSeqNum(SeqNum{Address: addr(testRAM, 0x100), Time: 2})

	a := NewVarnode(4, addr(testRAM, 0x200))
	a.flags |= VarnodeWritten
	a.def = op1

	b := NewVarnode(4, addr(testRAM, 0x200))
	b.flags |= VarnodeWritten
	b.def = op2

	if CompareLocDef(a, b) >= 0 {
		t.Fatal("lower seqnum should come first among written varnodes")
	}
}

func TestCompareLocDef_FreeByCreateIndex(t *testing.T) {
	a := NewVarnode(4, addr(testRAM, 0x200))
	a.createIndex = 5
	b := NewVarnode(4, addr(testRAM, 0x200))
	b.createIndex = 10

	if CompareLocDef(a, b) >= 0 {
		t.Fatal("lower createIndex should come first among free varnodes")
	}
}

// ---------------------------------------------------------------------------
// CompareDefLoc ordering tests
// ---------------------------------------------------------------------------

func TestCompareDefLoc_StatusFirst(t *testing.T) {
	input := NewVarnode(4, addr(testRAM, 0x300))
	input.flags |= VarnodeInput

	free := NewVarnode(4, addr(testRAM, 0x100))
	// free has lower address but should still come after input

	if CompareDefLoc(input, free) >= 0 {
		t.Fatal("input should come before free in DefLoc order regardless of address")
	}
}

func TestCompareDefLoc_WrittenBySeqNumThenLoc(t *testing.T) {
	op1 := &PcodeOp{}
	op1.SetSeqNum(SeqNum{Address: addr(testRAM, 0x100), Time: 1})

	a := NewVarnode(4, addr(testRAM, 0x300))
	a.flags |= VarnodeWritten
	a.def = op1

	b := NewVarnode(4, addr(testRAM, 0x100))
	b.flags |= VarnodeWritten
	b.def = op1 // same seqnum, so fall through to location

	if CompareDefLoc(b, a) >= 0 {
		t.Fatal("same seqnum: lower address should come first in DefLoc")
	}
}

// ---------------------------------------------------------------------------
// VarnodeBank: mixed status sorting
// ---------------------------------------------------------------------------

func TestVarnodeBank_MixedStatusLocTree(t *testing.T) {
	vb := NewVarnodeBank(testUniq, 0x10000)

	// Create three varnodes at the same location
	vn1 := vb.Create(4, addr(testRAM, 0x100))
	vn2 := vb.Create(4, addr(testRAM, 0x100))

	op := &PcodeOp{}
	op.SetSeqNum(SeqNum{Address: addr(testRAM, 0x500), Time: 1})
	vb.SetDef(vn1, op)
	vb.SetInput(vn2)

	vn3 := vb.Create(4, addr(testRAM, 0x100)) // remains free

	_ = vn3 // used only for presence in bank

	all := vb.AllVarnodes()
	for i := 1; i < len(all); i++ {
		if CompareLocDef(all[i-1], all[i]) >= 0 {
			t.Fatalf("locTree invariant broken at index %d", i)
		}
	}

	// Verify input comes first among same-loc varnodes
	// Find varnodes at 0x100
	var atLoc []*Varnode
	for _, vn := range all {
		if vn.Offset() == 0x100 && vn.Space() == testRAM && vn.Size() == 4 {
			atLoc = append(atLoc, vn)
		}
	}
	if len(atLoc) != 3 {
		t.Fatalf("expected 3 varnodes at 0x100, got %d", len(atLoc))
	}
	if !atLoc[0].IsInput() {
		t.Fatal("first varnode at loc should be input")
	}
	if !atLoc[1].IsWritten() {
		t.Fatal("second varnode at loc should be written")
	}
	if !atLoc[2].IsFree() {
		t.Fatal("third varnode at loc should be free")
	}
}

// ---------------------------------------------------------------------------
// Varnode String representation
// ---------------------------------------------------------------------------

func TestVarnode_String(t *testing.T) {
	vn := NewVarnode(4, addr(testRAM, 0x100))
	s := vn.String()
	if s == "" {
		t.Fatal("String() should not be empty")
	}
	// Should contain space name, offset, size
	if len(s) < 10 {
		t.Fatalf("String() too short: %s", s)
	}
}

// ---------------------------------------------------------------------------
// SeqNum comparison
// ---------------------------------------------------------------------------

func TestSeqNumLess(t *testing.T) {
	s1 := SeqNum{Address: addr(testRAM, 0x100), Time: 1}
	s2 := SeqNum{Address: addr(testRAM, 0x100), Time: 2}
	s3 := SeqNum{Address: addr(testRAM, 0x200), Time: 0}

	if !SeqNumLess(s1, s2) {
		t.Fatal("s1 < s2 by time")
	}
	if SeqNumLess(s2, s1) {
		t.Fatal("s2 should not be < s1")
	}
	if !SeqNumLess(s1, s3) {
		t.Fatal("s1 < s3 by address")
	}
}

func TestSeqNumEqual(t *testing.T) {
	s1 := SeqNum{Address: addr(testRAM, 0x100), Time: 1}
	s2 := SeqNum{Address: addr(testRAM, 0x100), Time: 1}
	s3 := SeqNum{Address: addr(testRAM, 0x100), Time: 2}

	if !SeqNumEqual(s1, s2) {
		t.Fatal("s1 should equal s2")
	}
	if SeqNumEqual(s1, s3) {
		t.Fatal("s1 should not equal s3")
	}
}
