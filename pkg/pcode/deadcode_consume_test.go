package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func TestConsumeMaskHelpers(t *testing.T) {
	if got := coveringMask(0x8); got != 0xf {
		t.Errorf("coveringMask(0x8)=0x%x, want 0xf", got)
	}
	if got := coveringMask(0); got != 0 {
		t.Errorf("coveringMask(0)=0x%x, want 0", got)
	}
	if got := coveringMask(0x80); got != 0xff {
		t.Errorf("coveringMask(0x80)=0x%x, want 0xff", got)
	}
	if got := minimalMask(0x1); got != 0xff {
		t.Errorf("minimalMask(0x1)=0x%x, want 0xff", got)
	}
	if got := minimalMask(0x1234); got != 0xffff {
		t.Errorf("minimalMask(0x1234)=0x%x, want 0xffff", got)
	}
	if got := minimalMask(0xdeadbeef); got != 0xffffffff {
		t.Errorf("minimalMask(0xdeadbeef)=0x%x, want 0xffffffff", got)
	}
	if got := leastSigBitSet(0); got != -1 {
		t.Errorf("leastSigBitSet(0)=%d, want -1", got)
	}
	if got := leastSigBitSet(0x18); got != 3 {
		t.Errorf("leastSigBitSet(0x18)=%d, want 3", got)
	}
}

// TestConsumeAnalysisReturnReachable verifies that the computeConsumed pass marks
// the full RETURN-reachable computation chain as consumed while leaving an
// unreachable (dead) Varnode unconsumed. This is the property the H7 return
// preservation depends on: a return value and everything feeding it stays alive.
func TestConsumeAnalysisReturnReachable(t *testing.T) {
	ramSp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	constSp := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	uniqSp := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	fd := NewFuncdata("consume_test", address.Address{Space: ramSp, Offset: 0}, uniqSp, 0, constSp)
	addr := address.Address{Space: constSp, Offset: 0}
	bb := NewBlockBasic()

	wire := func(op *PcodeOp) {
		fd.OpMarkAlive(op)
		op.SetParent(bb)
		bb.InsertOpEnd(op)
	}

	// aVn = COPY(7)
	copyA := fd.NewOp(1, addr)
	fd.OpSetOpcode(copyA, CPUI_COPY)
	aVn := fd.NewUniqueOut(4, copyA)
	fd.OpSetInput(copyA, fd.NewConstant(4, 7), 0)
	wire(copyA)

	// sumVn = INT_ADD(aVn, 3)
	add := fd.NewOp(2, addr)
	fd.OpSetOpcode(add, CPUI_INT_ADD)
	sumVn := fd.NewUniqueOut(4, add)
	fd.OpSetInput(add, aVn, 0)
	fd.OpSetInput(add, fd.NewConstant(4, 3), 1)
	wire(add)

	// RETURN(0, sumVn)
	ret := fd.NewOp(2, addr)
	fd.OpSetOpcode(ret, CPUI_RETURN)
	fd.OpSetInput(ret, fd.NewConstant(4, 0), 0)
	fd.OpSetInput(ret, sumVn, 1)
	wire(ret)

	// deadVn = COPY(9), read by nothing.
	deadCopy := fd.NewOp(1, addr)
	fd.OpSetOpcode(deadCopy, CPUI_COPY)
	deadVn := fd.NewUniqueOut(4, deadCopy)
	fd.OpSetInput(deadCopy, fd.NewConstant(4, 9), 0)
	wire(deadCopy)

	newConsumeAnalysis().computeConsumed(fd)

	if sumVn.Consumed() == 0 {
		t.Errorf("sumVn (RETURN value) consume=0, want nonzero (must stay alive)")
	}
	if aVn.Consumed() == 0 {
		t.Errorf("aVn (feeds RETURN via INT_ADD) consume=0, want nonzero (propagation failed)")
	}
	if deadVn.Consumed() != 0 {
		t.Errorf("deadVn (unreachable) consume=0x%x, want 0 (must be deletable)", deadVn.Consumed())
	}
}
