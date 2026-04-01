package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// helpers shared across funcdata tests

func makeTestSpaces() (ram, reg, uniq, cnst *address.Space) {
	ram = &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	reg = &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 4, WordSize: 1}
	uniq = &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 3, AddrSize: 8, WordSize: 1}
	cnst = &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 4, AddrSize: 8, WordSize: 1}
	return
}

func makeFD() (*Funcdata, *address.Space, *address.Space, *address.Space, *address.Space) {
	ram, reg, uniq, cnst := makeTestSpaces()
	fd := NewFuncdata("test_func", address.Address{Space: ram, Offset: 0x401000}, uniq, 0x100000, cnst)
	return fd, ram, reg, uniq, cnst
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewFuncdata(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	if fd.Name() != "test_func" {
		t.Fatalf("Name() = %q, want %q", fd.Name(), "test_func")
	}
	if fd.BaseAddr().Space != ram || fd.BaseAddr().Offset != 0x401000 {
		t.Fatalf("BaseAddr() mismatch: %v", fd.BaseAddr())
	}
	if fd.NumVarnodes() != 0 {
		t.Fatalf("NumVarnodes() = %d, want 0", fd.NumVarnodes())
	}
	if fd.NumOps() != 0 {
		t.Fatalf("NumOps() = %d, want 0", fd.NumOps())
	}
	if fd.Flags() != 0 {
		t.Fatalf("Flags() = %d, want 0", fd.Flags())
	}
}

// ---------------------------------------------------------------------------
// Flag operations
// ---------------------------------------------------------------------------

func TestFuncdataFlags(t *testing.T) {
	fd, _, _, _, _ := makeFD()

	fd.SetFlag(FuncBlocksGenerated)
	if !fd.HasFlag(FuncBlocksGenerated) {
		t.Fatal("HasFlag should be true after SetFlag")
	}
	fd.ClearFlag(FuncBlocksGenerated)
	if fd.HasFlag(FuncBlocksGenerated) {
		t.Fatal("HasFlag should be false after ClearFlag")
	}
}

// ---------------------------------------------------------------------------
// Varnode creation
// ---------------------------------------------------------------------------

func TestNewVarnode(t *testing.T) {
	fd, reg, _, _, _ := makeFD()

	loc := address.Address{Space: reg, Offset: 0x20}
	vn := fd.NewVarnode(4, loc)
	if vn == nil {
		t.Fatal("NewVarnode returned nil")
	}
	if vn.Size() != 4 {
		t.Fatalf("size = %d, want 4", vn.Size())
	}
	if fd.NumVarnodes() != 1 {
		t.Fatalf("NumVarnodes() = %d, want 1", fd.NumVarnodes())
	}
	if !vn.IsFree() {
		t.Fatal("new varnode should be free")
	}
}

func TestNewVarnodeOut(t *testing.T) {
	fd, ram, reg, _, _ := makeFD()

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	loc := address.Address{Space: reg, Offset: 0x10}
	vn := fd.NewVarnodeOut(4, loc, op)

	if vn == nil {
		t.Fatal("NewVarnodeOut returned nil")
	}
	if op.Output() != vn {
		t.Fatal("op.Output() should point to vn")
	}
	if vn.Def() != op {
		t.Fatal("vn.Def() should point to op")
	}
	if !vn.IsWritten() {
		t.Fatal("output varnode should be written")
	}
}

func TestNewUniqueOut(t *testing.T) {
	fd, ram, _, uniq, _ := makeFD()

	op := fd.NewOp(1, address.Address{Space: ram, Offset: 0x401000})
	vn := fd.NewUniqueOut(4, op)

	if vn == nil {
		t.Fatal("NewUniqueOut returned nil")
	}
	if vn.Space() != uniq {
		t.Fatalf("unique output should be in unique space, got %v", vn.Space())
	}
	if op.Output() != vn {
		t.Fatal("op.Output() should point to unique vn")
	}
	if vn.Def() != op {
		t.Fatal("vn.Def() should point to op")
	}
}

func TestNewConstant(t *testing.T) {
	fd, _, _, _, cnst := makeFD()

	vn := fd.NewConstant(4, 42)
	if vn == nil {
		t.Fatal("NewConstant returned nil")
	}
	if vn.Space() != cnst {
		t.Fatalf("constant should be in const space, got %v", vn.Space())
	}
	if vn.Offset() != 42 {
		t.Fatalf("constant offset = %d, want 42", vn.Offset())
	}
	if !vn.IsConstant() {
		t.Fatal("constant varnode should have constant flag")
	}
}

// ---------------------------------------------------------------------------
// SetInputVarnode
// ---------------------------------------------------------------------------

func TestSetInputVarnode(t *testing.T) {
	fd, _, reg, _, _ := makeFD()

	loc := address.Address{Space: reg, Offset: 0x20}
	vn := fd.NewVarnode(4, loc)
	if !vn.IsFree() {
		t.Fatal("varnode should start as free")
	}

	fd.SetInputVarnode(vn)
	if !vn.IsInput() {
		t.Fatal("varnode should be input after SetInputVarnode")
	}
	if vn.IsFree() {
		t.Fatal("input varnode should not be free")
	}
}

// ---------------------------------------------------------------------------
// PcodeOp creation and opcode assignment
// ---------------------------------------------------------------------------

func TestNewOpAndSetOpcode(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	if op == nil {
		t.Fatal("NewOp returned nil")
	}
	if fd.NumOps() != 1 {
		t.Fatalf("NumOps() = %d, want 1", fd.NumOps())
	}
	if !op.IsDead() {
		t.Fatal("new op should be dead")
	}

	fd.OpSetOpcode(op, CPUI_INT_ADD)
	if op.Code() != CPUI_INT_ADD {
		t.Fatalf("Code() = %v, want INT_ADD", op.Code())
	}
	if !op.IsCommutative() {
		t.Fatal("INT_ADD should be commutative")
	}
}

// ---------------------------------------------------------------------------
// Wiring: OpSetOutput / OpSetInput
// ---------------------------------------------------------------------------

func TestOpSetOutputAndInput(t *testing.T) {
	fd, ram, reg, _, cnst := makeFD()

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	fd.OpSetOpcode(op, CPUI_INT_ADD)

	// Create output
	outLoc := address.Address{Space: reg, Offset: 0x00}
	outVn := fd.NewVarnode(4, outLoc)
	fd.OpSetOutput(op, outVn)

	if op.Output() != outVn {
		t.Fatal("op.Output() mismatch")
	}
	if outVn.Def() != op {
		t.Fatal("output varnode def mismatch")
	}

	// Create inputs
	in0Loc := address.Address{Space: reg, Offset: 0x10}
	in0 := fd.NewVarnode(4, in0Loc)
	fd.OpSetInput(op, in0, 0)

	in1 := fd.NewConstant(4, 0x10)
	_ = cnst // used for NewConstant
	fd.OpSetInput(op, in1, 1)

	if op.Input(0) != in0 {
		t.Fatal("input 0 mismatch")
	}
	if op.Input(1) != in1 {
		t.Fatal("input 1 mismatch")
	}
	if in0.NumDescend() != 1 {
		t.Fatalf("in0 descend count = %d, want 1", in0.NumDescend())
	}
	if in1.NumDescend() != 1 {
		t.Fatalf("in1 descend count = %d, want 1", in1.NumDescend())
	}
	if in0.LoneDescend() != op {
		t.Fatal("in0 lone descend should be op")
	}
}

// ---------------------------------------------------------------------------
// Unwiring: OpUnsetOutput / OpUnsetInput
// ---------------------------------------------------------------------------

func TestOpUnsetOutput(t *testing.T) {
	fd, ram, reg, _, _ := makeFD()

	op := fd.NewOp(0, address.Address{Space: ram, Offset: 0x401000})
	outVn := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x00})
	fd.OpSetOutput(op, outVn)

	fd.OpUnsetOutput(op)
	if op.Output() != nil {
		t.Fatal("op.Output() should be nil after unset")
	}
	if outVn.Def() != nil {
		t.Fatal("varnode def should be nil after unset")
	}
}

func TestOpUnsetInput(t *testing.T) {
	fd, ram, reg, _, _ := makeFD()

	op := fd.NewOp(1, address.Address{Space: ram, Offset: 0x401000})
	inVn := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x10})
	fd.OpSetInput(op, inVn, 0)

	if inVn.NumDescend() != 1 {
		t.Fatalf("descend count before unset = %d, want 1", inVn.NumDescend())
	}

	fd.OpUnsetInput(op, 0)
	if op.Input(0) != nil {
		t.Fatal("input slot should be nil after unset")
	}
	if inVn.NumDescend() != 0 {
		t.Fatalf("descend count after unset = %d, want 0", inVn.NumDescend())
	}
}

// ---------------------------------------------------------------------------
// OpMarkAlive / OpMarkDead transitions
// ---------------------------------------------------------------------------

func TestOpMarkAliveAndDead(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	op := fd.NewOp(0, address.Address{Space: ram, Offset: 0x401000})
	if !op.IsDead() {
		t.Fatal("new op should start dead")
	}

	fd.OpMarkAlive(op)
	if op.IsDead() {
		t.Fatal("op should be alive after MarkAlive")
	}

	fd.OpMarkDead(op)
	if !op.IsDead() {
		t.Fatal("op should be dead after MarkDead")
	}
}

// ---------------------------------------------------------------------------
// OpDestroy
// ---------------------------------------------------------------------------

func TestOpDestroy(t *testing.T) {
	fd, ram, reg, _, _ := makeFD()

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	fd.OpSetOpcode(op, CPUI_INT_ADD)

	outVn := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x00})
	fd.OpSetOutput(op, outVn)

	in0 := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x10})
	in1 := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x20})
	fd.OpSetInput(op, in0, 0)
	fd.OpSetInput(op, in1, 1)

	fd.OpDestroy(op)

	if fd.NumOps() != 0 {
		t.Fatalf("NumOps() = %d, want 0 after destroy", fd.NumOps())
	}
	if outVn.Def() != nil {
		t.Fatal("output varnode def should be nil after destroy")
	}
	if in0.NumDescend() != 0 {
		t.Fatalf("in0 descend = %d, want 0 after destroy", in0.NumDescend())
	}
	if in1.NumDescend() != 0 {
		t.Fatalf("in1 descend = %d, want 0 after destroy", in1.NumDescend())
	}
}

// ---------------------------------------------------------------------------
// FindVarnodeInput / FindOp
// ---------------------------------------------------------------------------

func TestFindVarnodeInput(t *testing.T) {
	fd, _, reg, _, _ := makeFD()

	loc := address.Address{Space: reg, Offset: 0x20}
	vn := fd.NewVarnode(4, loc)
	fd.SetInputVarnode(vn)

	found := fd.FindVarnodeInput(4, loc)
	if found != vn {
		t.Fatal("FindVarnodeInput should find the input varnode")
	}

	notFound := fd.FindVarnodeInput(8, loc)
	if notFound != nil {
		t.Fatal("FindVarnodeInput should return nil for wrong size")
	}
}

func TestFindOp(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	op := fd.NewOp(0, address.Address{Space: ram, Offset: 0x401000})
	seq := op.Seq()

	found := fd.FindOp(seq)
	if found != op {
		t.Fatal("FindOp should find the op by seq")
	}

	bogus := SeqNum{Address: address.Address{Space: ram, Offset: 0xDEAD}, Time: 999}
	if fd.FindOp(bogus) != nil {
		t.Fatal("FindOp should return nil for unknown seq")
	}
}

// ---------------------------------------------------------------------------
// Integration: small IR graph
// ---------------------------------------------------------------------------

func TestIntegrationSmallIRGraph(t *testing.T) {
	fd, ram, reg, _, _ := makeFD()

	// Build: out = in0 + in1
	//   op = INT_ADD
	//   in0 = register:0x10[4]  (input)
	//   in1 = constant 0x42
	//   out = register:0x00[4]

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	fd.OpSetOpcode(op, CPUI_INT_ADD)
	fd.OpMarkAlive(op)

	// Create and wire output
	outVn := fd.NewVarnodeOut(4, address.Address{Space: reg, Offset: 0x00}, op)

	// Create input 0 as function input
	in0 := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x10})
	fd.SetInputVarnode(in0)
	fd.OpSetInput(op, in0, 0)

	// Create input 1 as constant
	in1 := fd.NewConstant(4, 0x42)
	fd.OpSetInput(op, in1, 1)

	// Verify graph structure
	if op.Code() != CPUI_INT_ADD {
		t.Fatalf("op code = %v, want INT_ADD", op.Code())
	}
	if op.Output() != outVn {
		t.Fatal("op output mismatch")
	}
	if op.Input(0) != in0 {
		t.Fatal("op input 0 mismatch")
	}
	if op.Input(1) != in1 {
		t.Fatal("op input 1 mismatch")
	}
	if outVn.Def() != op {
		t.Fatal("output def mismatch")
	}
	if in0.LoneDescend() != op {
		t.Fatal("in0 should read by op")
	}
	if in1.LoneDescend() != op {
		t.Fatal("in1 should read by op")
	}
	if !in0.IsInput() {
		t.Fatal("in0 should be input")
	}
	if !in1.IsConstant() {
		t.Fatal("in1 should be constant")
	}
	if !outVn.IsWritten() {
		t.Fatal("output should be written")
	}
	if op.IsDead() {
		t.Fatal("op should be alive")
	}

	// Verify counts
	if fd.NumOps() != 1 {
		t.Fatalf("NumOps = %d, want 1", fd.NumOps())
	}
	// 3 varnodes: out, in0, in1
	if fd.NumVarnodes() != 3 {
		t.Fatalf("NumVarnodes = %d, want 3", fd.NumVarnodes())
	}

	// Destroy and verify cleanup
	fd.OpDestroy(op)
	if fd.NumOps() != 0 {
		t.Fatalf("NumOps after destroy = %d, want 0", fd.NumOps())
	}
	if outVn.Def() != nil {
		t.Fatal("output def should be nil after destroy")
	}
	if in0.NumDescend() != 0 {
		t.Fatal("in0 descend should be 0 after destroy")
	}
	if in1.NumDescend() != 0 {
		t.Fatal("in1 descend should be 0 after destroy")
	}
}

// ---------------------------------------------------------------------------
// DeleteVarnode
// ---------------------------------------------------------------------------

func TestDeleteVarnode(t *testing.T) {
	fd, _, reg, _, _ := makeFD()

	vn := fd.NewVarnode(4, address.Address{Space: reg, Offset: 0x30})
	if fd.NumVarnodes() != 1 {
		t.Fatalf("NumVarnodes = %d, want 1", fd.NumVarnodes())
	}

	fd.DeleteVarnode(vn)
	if fd.NumVarnodes() != 0 {
		t.Fatalf("NumVarnodes after delete = %d, want 0", fd.NumVarnodes())
	}
}

// ---------------------------------------------------------------------------
// OpUnsetOutput on op with no output (no-op)
// ---------------------------------------------------------------------------

func TestOpUnsetOutputNoop(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	op := fd.NewOp(0, address.Address{Space: ram, Offset: 0x401000})
	// Should not panic when output is already nil
	fd.OpUnsetOutput(op)
}

// ---------------------------------------------------------------------------
// OpUnsetInput on nil slot (no-op)
// ---------------------------------------------------------------------------

func TestOpUnsetInputNoop(t *testing.T) {
	fd, ram, _, _, _ := makeFD()

	op := fd.NewOp(2, address.Address{Space: ram, Offset: 0x401000})
	// Slot 0 is nil -- should not panic
	fd.OpUnsetInput(op, 0)
}
