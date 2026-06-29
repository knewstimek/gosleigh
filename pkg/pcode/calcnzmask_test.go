package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// TestCalcNZMaskPropagation verifies Funcdata.CalcNZMask propagates non-zero
// masks through the common opcodes per op.cc PcodeOp::getNZMaskLocal: AND with a
// constant clears bits, ZEXT zero-fills the high bytes, left shift moves the
// mask, and a constant carries its exact value.
func TestCalcNZMaskPropagation(t *testing.T) {
	ramSp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	constSp := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	uniqSp := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	fd := NewFuncdata("nzm_test", address.Address{Space: ramSp, Offset: 0}, uniqSp, 0, constSp)
	addr := address.Address{Space: constSp, Offset: 0}
	bb := NewBlockBasic()
	wire := func(op *PcodeOp) {
		fd.OpMarkAlive(op)
		op.SetParent(bb)
		bb.InsertOpEnd(op)
	}

	// xByte = COPY(reg byte) -- a 1-byte register read (leaf), nzm should be 0xff.
	regByte := fd.NewVarnode(1, address.Address{Space: ramSp, Offset: 0x40})
	copyB := fd.NewOp(1, addr)
	fd.OpSetOpcode(copyB, CPUI_COPY)
	xByte := fd.NewUniqueOut(1, copyB)
	fd.OpSetInput(copyB, regByte, 0)
	wire(copyB)

	// zx = ZEXT(xByte) to 4 bytes -- high 3 bytes provably zero -> nzm 0xff.
	zext := fd.NewOp(1, addr)
	fd.OpSetOpcode(zext, CPUI_INT_ZEXT)
	zx := fd.NewUniqueOut(4, zext)
	fd.OpSetInput(zext, xByte, 0)
	wire(zext)

	// andv = INT_AND(reg4, 0x0f) -- nzm should be 0x0f.
	reg4 := fd.NewVarnode(4, address.Address{Space: ramSp, Offset: 0x50})
	andOp := fd.NewOp(2, addr)
	fd.OpSetOpcode(andOp, CPUI_INT_AND)
	andv := fd.NewUniqueOut(4, andOp)
	fd.OpSetInput(andOp, reg4, 0)
	fd.OpSetInput(andOp, fd.NewConstant(4, 0x0f), 1)
	wire(andOp)

	// shl = INT_LEFT(andv, 8) -- nzm 0x0f << 8 = 0xf00.
	shl := fd.NewOp(2, addr)
	fd.OpSetOpcode(shl, CPUI_INT_LEFT)
	shlv := fd.NewUniqueOut(4, shl)
	fd.OpSetInput(shl, andv, 0)
	fd.OpSetInput(shl, fd.NewConstant(4, 8), 1)
	wire(shl)

	fd.CalcNZMask()

	if got := xByte.NZMask(); got != 0xff {
		t.Errorf("xByte (COPY of 1-byte reg) nzm=0x%x, want 0xff", got)
	}
	if got := zx.NZMask(); got != 0xff {
		t.Errorf("zext nzm=0x%x, want 0xff (high bytes zero)", got)
	}
	if got := andv.NZMask(); got != 0x0f {
		t.Errorf("and-with-0x0f nzm=0x%x, want 0x0f", got)
	}
	if got := shlv.NZMask(); got != 0xf00 {
		t.Errorf("left-shift-8 nzm=0x%x, want 0xf00", got)
	}
}
