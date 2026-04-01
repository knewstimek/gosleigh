package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func makeTestSpace() *address.Space {
	return &address.Space{
		Name: "ram", Kind: address.SpaceKindProcessor,
		Index: 1, AddrSize: 8, WordSize: 1,
	}
}

func makeTestAddr(space *address.Space, off uint64) address.Address {
	return address.Address{Space: space, Offset: off}
}

// --- PcodeOp flag tests ---

func TestPcodeOpFlagSetClear(t *testing.T) {
	op := NewPcodeOp(0, SeqNum{})

	op.SetFlag(PcodeOpDead)
	if !op.IsDead() {
		t.Fatal("expected Dead after SetFlag")
	}

	op.ClearFlag(PcodeOpDead)
	if op.IsDead() {
		t.Fatal("expected not Dead after ClearFlag")
	}

	op.SetFlag(PcodeOpCall | PcodeOpBranch)
	if !op.IsCall() {
		t.Fatal("expected IsCall")
	}
	if !op.IsBranch() {
		t.Fatal("expected IsBranch")
	}
	if !op.IsFlowBreak() {
		t.Fatal("expected IsFlowBreak for branch")
	}

	op.ClearFlag(PcodeOpCall)
	if op.IsCall() {
		t.Fatal("expected not IsCall after clear")
	}
}

func TestPcodeOpAdditionalFlags(t *testing.T) {
	op := NewPcodeOp(0, SeqNum{})
	op.SetAdditionalFlag(PcodeOpModified)
	if op.addlFlags&PcodeOpModified == 0 {
		t.Fatal("expected Modified addl flag set")
	}
	op.ClearAdditionalFlag(PcodeOpModified)
	if op.addlFlags&PcodeOpModified != 0 {
		t.Fatal("expected Modified addl flag cleared")
	}
}

func TestPcodeOpEvalType(t *testing.T) {
	op := NewPcodeOp(0, SeqNum{})
	op.SetFlag(PcodeOpBinary | PcodeOpDead)
	if got := op.EvalType(); got != PcodeOpBinary {
		t.Fatalf("EvalType() = 0x%x, want 0x%x", got, PcodeOpBinary)
	}
}

func TestPcodeOpHaltType(t *testing.T) {
	op := NewPcodeOp(0, SeqNum{})
	op.SetFlag(PcodeOpHalt | PcodeOpBadInstruction | PcodeOpDead)
	want := PcodeOpHalt | PcodeOpBadInstruction
	if got := op.HaltType(); got != want {
		t.Fatalf("HaltType() = 0x%x, want 0x%x", got, want)
	}
}

// --- SetOpcode tests ---

func TestPcodeOpSetOpcodeClearsAndReapplies(t *testing.T) {
	ops := RegisterTypeOps()
	op := NewPcodeOp(2, SeqNum{})

	// First set to INT_ADD (binary, commutative)
	op.SetOpcode(ops[CPUI_INT_ADD])
	if !op.IsCommutative() {
		t.Fatal("expected commutative after INT_ADD")
	}
	if op.EvalType() != PcodeOpBinary {
		t.Fatal("expected binary eval type for INT_ADD")
	}

	// Switch to BRANCH (special, branch, coderef)
	op.SetOpcode(ops[CPUI_BRANCH])
	if op.IsCommutative() {
		t.Fatal("commutative should be cleared after switch to BRANCH")
	}
	if !op.IsBranch() {
		t.Fatal("expected branch after BRANCH")
	}
	if op.EvalType() != PcodeOpSpecial {
		t.Fatalf("expected special eval type, got 0x%x", op.EvalType())
	}

	// Non-behavioral flags must survive opcode change
	op.SetFlag(PcodeOpDead | PcodeOpMark)
	op.SetOpcode(ops[CPUI_COPY])
	if !op.IsDead() {
		t.Fatal("Dead flag should survive SetOpcode")
	}
	if op.flags&PcodeOpMark == 0 {
		t.Fatal("Mark flag should survive SetOpcode")
	}
}

// --- Input/output slot management ---

func TestPcodeOpInputSlots(t *testing.T) {
	op := NewPcodeOp(3, SeqNum{})
	vn0, vn1, vn2 := &Varnode{}, &Varnode{}, &Varnode{}

	op.SetInput(vn0, 0)
	op.SetInput(vn1, 1)
	op.SetInput(vn2, 2)

	if op.NumInput() != 3 {
		t.Fatalf("NumInput() = %d, want 3", op.NumInput())
	}
	if op.Input(1) != vn1 {
		t.Fatal("Input(1) mismatch")
	}
	if slot := op.GetSlot(vn2); slot != 2 {
		t.Fatalf("GetSlot(vn2) = %d, want 2", slot)
	}
	if slot := op.GetSlot(&Varnode{}); slot != -1 {
		t.Fatalf("GetSlot(unknown) = %d, want -1", slot)
	}
}

func TestPcodeOpRemoveInput(t *testing.T) {
	op := NewPcodeOp(3, SeqNum{})
	vn0, vn1, vn2 := &Varnode{}, &Varnode{}, &Varnode{}
	op.SetInput(vn0, 0)
	op.SetInput(vn1, 1)
	op.SetInput(vn2, 2)

	op.RemoveInput(1) // remove middle
	if op.NumInput() != 2 {
		t.Fatalf("after remove: NumInput() = %d, want 2", op.NumInput())
	}
	if op.Input(0) != vn0 || op.Input(1) != vn2 {
		t.Fatal("inputs not correctly spliced")
	}
}

func TestPcodeOpInsertInput(t *testing.T) {
	op := NewPcodeOp(2, SeqNum{})
	vn0, vn1 := &Varnode{}, &Varnode{}
	op.SetInput(vn0, 0)
	op.SetInput(vn1, 1)

	op.InsertInput(1) // insert nil at position 1
	if op.NumInput() != 3 {
		t.Fatalf("after insert: NumInput() = %d, want 3", op.NumInput())
	}
	if op.Input(0) != vn0 {
		t.Fatal("slot 0 should be vn0")
	}
	if op.Input(1) != nil {
		t.Fatal("slot 1 should be nil (inserted)")
	}
	if op.Input(2) != vn1 {
		t.Fatal("slot 2 should be vn1 (shifted)")
	}
}

func TestPcodeOpSetNumInputs(t *testing.T) {
	op := NewPcodeOp(2, SeqNum{})
	vn := &Varnode{}
	op.SetInput(vn, 0)

	// Grow
	op.SetNumInputs(5)
	if op.NumInput() != 5 {
		t.Fatalf("NumInput() = %d after grow, want 5", op.NumInput())
	}
	if op.Input(0) != vn {
		t.Fatal("existing input lost after grow")
	}

	// Shrink
	op.SetNumInputs(1)
	if op.NumInput() != 1 {
		t.Fatalf("NumInput() = %d after shrink, want 1", op.NumInput())
	}
	if op.Input(0) != vn {
		t.Fatal("existing input lost after shrink")
	}
}

func TestPcodeOpOutputAndAssignment(t *testing.T) {
	op := NewPcodeOp(0, SeqNum{})
	if op.IsAssignment() {
		t.Fatal("should not be assignment without output")
	}
	vn := &Varnode{}
	op.SetOutput(vn)
	if !op.IsAssignment() {
		t.Fatal("should be assignment with output")
	}
	if op.Output() != vn {
		t.Fatal("Output() mismatch")
	}
}

func TestPcodeOpSeqAndAddr(t *testing.T) {
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x1000)
	seq := SeqNum{Address: addr, Time: 5, Order: 3}
	op := NewPcodeOp(0, seq)

	if op.Seq() != seq {
		t.Fatal("Seq() mismatch")
	}
	if op.Addr() != addr {
		t.Fatal("Addr() mismatch")
	}
}

func TestPcodeOpString(t *testing.T) {
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x400)
	ops := RegisterTypeOps()

	op := NewPcodeOp(2, SeqNum{Address: addr, Order: 1})
	op.SetOpcode(ops[CPUI_INT_ADD])
	s := op.String()
	if s == "" {
		t.Fatal("String() should not be empty")
	}
}

// --- PcodeOpBank tests ---

func TestPcodeOpBankCreateAndFind(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x1000)

	op := bank.Create(2, addr)
	if op == nil {
		t.Fatal("Create returned nil")
	}
	if !op.IsDead() {
		t.Fatal("newly created op should be dead")
	}
	if bank.NumOps() != 1 {
		t.Fatalf("NumOps() = %d, want 1", bank.NumOps())
	}

	found := bank.FindOp(op.Seq())
	if found != op {
		t.Fatal("FindOp did not return the created op")
	}
}

func TestPcodeOpBankAliveDeadTransitions(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x2000)

	op := bank.Create(0, addr)

	// Initially dead
	if len(bank.DeadOps()) != 1 || len(bank.AliveOps()) != 0 {
		t.Fatal("initial state: expected 1 dead, 0 alive")
	}

	// Mark alive
	bank.MarkAlive(op)
	if op.IsDead() {
		t.Fatal("op should not be dead after MarkAlive")
	}
	if len(bank.DeadOps()) != 0 || len(bank.AliveOps()) != 1 {
		t.Fatal("after MarkAlive: expected 0 dead, 1 alive")
	}

	// Mark dead again
	bank.MarkDead(op)
	if !op.IsDead() {
		t.Fatal("op should be dead after MarkDead")
	}
	if len(bank.DeadOps()) != 1 || len(bank.AliveOps()) != 0 {
		t.Fatal("after MarkDead: expected 1 dead, 0 alive")
	}
}

func TestPcodeOpBankDestroy(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x3000)

	op := bank.Create(0, addr)
	seq := op.Seq()

	bank.Destroy(op)
	if bank.NumOps() != 0 {
		t.Fatal("NumOps should be 0 after destroy")
	}
	if bank.FindOp(seq) != nil {
		t.Fatal("FindOp should return nil after destroy")
	}
}

func TestPcodeOpBankDestroyAlive(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()

	op := bank.Create(0, makeTestAddr(sp, 0x100))
	bank.MarkAlive(op)
	bank.Destroy(op)

	if len(bank.AliveOps()) != 0 {
		t.Fatal("alive list should be empty after destroying alive op")
	}
}

func TestPcodeOpBankClear(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()

	bank.Create(0, makeTestAddr(sp, 0x100))
	bank.Create(0, makeTestAddr(sp, 0x200))

	bank.Clear()
	if bank.NumOps() != 0 {
		t.Fatal("NumOps should be 0 after Clear")
	}
}

func TestPcodeOpBankCreateWithSeq(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()
	seq := SeqNum{Address: makeTestAddr(sp, 0x500), Time: 42, Order: 7}

	op := bank.CreateWithSeq(1, seq)
	if op.Seq() != seq {
		t.Fatal("CreateWithSeq: seq mismatch")
	}

	// uniqID should advance past the provided Time
	op2 := bank.Create(0, makeTestAddr(sp, 0x600))
	if op2.Seq().Time <= 42 {
		t.Fatal("uniqID should have advanced past CreateWithSeq's time")
	}
}

func TestPcodeOpBankTarget(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()
	addr := makeTestAddr(sp, 0x4000)

	op := bank.Create(0, addr)
	found := bank.Target(addr)
	if found != op {
		t.Fatal("Target did not find op at address")
	}

	notFound := bank.Target(makeTestAddr(sp, 0x9999))
	if notFound != nil {
		t.Fatal("Target should return nil for unknown address")
	}
}

func TestPcodeOpBankAllOps(t *testing.T) {
	bank := NewPcodeOpBank()
	sp := makeTestSpace()

	bank.Create(0, makeTestAddr(sp, 0x100))
	bank.Create(0, makeTestAddr(sp, 0x200))
	bank.Create(0, makeTestAddr(sp, 0x300))

	all := bank.AllOps()
	if len(all) != 3 {
		t.Fatalf("AllOps() len = %d, want 3", len(all))
	}
}

// --- TypeOp registration ---

func TestTypeOpRegistrationCoversAllOpcodes(t *testing.T) {
	ops := RegisterTypeOps()

	// Every valid opcode (1..CPUI_MAX-1) that is not a gap should be registered.
	// The only known gap is between CPUI_FLOAT_LESSEQUAL and CPUI_FLOAT_NAN
	// (the blank _ in the iota enum, value = CPUI_FLOAT_LESSEQUAL+1).
	gap := CPUI_FLOAT_LESSEQUAL + 1

	for i := OpCode(1); i < CPUI_MAX; i++ {
		if i == gap {
			continue // known gap in enum
		}
		if ops[i] == nil {
			t.Errorf("OpCode %d (%s) has no TypeOp registration", i, i.String())
		}
	}
}

func TestTypeOpFlags(t *testing.T) {
	ops := RegisterTypeOps()

	add := ops[CPUI_INT_ADD]
	if add.GetOpCode() != CPUI_INT_ADD {
		t.Fatal("INT_ADD opcode mismatch")
	}
	if !add.IsCommutative() {
		t.Fatal("INT_ADD should be commutative")
	}
	if add.GetName() != "+" {
		t.Fatalf("INT_ADD name = %q, want '+'", add.GetName())
	}

	branch := ops[CPUI_BRANCH]
	if branch.IsCommutative() {
		t.Fatal("BRANCH should not be commutative")
	}
	if branch.GetFlags()&PcodeOpBranch == 0 {
		t.Fatal("BRANCH should have Branch flag")
	}
}

// --- Flag uniqueness ---

func TestPrimaryFlagBitsDistinct(t *testing.T) {
	flags := []uint32{
		PcodeOpStartBasic, PcodeOpBranch, PcodeOpCall, PcodeOpReturns,
		PcodeOpNoCollapse, PcodeOpDead, PcodeOpMarker, PcodeOpBoolOutput,
		PcodeOpBooleanFlip, PcodeOpFallthruTrue, PcodeOpIndirectSource,
		PcodeOpCodeRef, PcodeOpStartMark, PcodeOpMark, PcodeOpCommutative,
		PcodeOpUnary, PcodeOpBinary, PcodeOpSpecial, PcodeOpTernary,
		PcodeOpReturnCopy, PcodeOpNonPrinting, PcodeOpHalt,
		PcodeOpBadInstruction, PcodeOpUnimplemented, PcodeOpNoReturn,
		PcodeOpMissing, PcodeOpSpacebasePtr, PcodeOpIndirectCreation,
		PcodeOpCalculatedBool, PcodeOpHasCallSpec, PcodeOpPtrFlow,
		PcodeOpIndirectStore,
	}
	seen := make(map[uint32]bool)
	for _, f := range flags {
		if seen[f] {
			t.Fatalf("duplicate primary flag bit: 0x%x", f)
		}
		seen[f] = true
		// Each should be a single bit
		if f == 0 || f&(f-1) != 0 {
			t.Fatalf("flag 0x%x is not a single bit", f)
		}
	}
}

func TestAdditionalFlagBitsDistinct(t *testing.T) {
	flags := []uint32{
		PcodeOpSpecialProp, PcodeOpSpecialPrint, PcodeOpModified,
		PcodeOpWarning, PcodeOpIncidentalCopy, PcodeOpIsCpoolTransformed,
		PcodeOpStopTypePropagation, PcodeOpHoldOutput, PcodeOpConcatRoot,
		PcodeOpNoIndirectCollapse, PcodeOpStoreUnmapped,
	}
	seen := make(map[uint32]bool)
	for _, f := range flags {
		if seen[f] {
			t.Fatalf("duplicate additional flag bit: 0x%x", f)
		}
		seen[f] = true
		if f == 0 || f&(f-1) != 0 {
			t.Fatalf("flag 0x%x is not a single bit", f)
		}
	}
}
