package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func newRulesFuncdata() *Funcdata {
	sp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	cs := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	us := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	return NewFuncdata("rules", address.Address{Space: sp, Offset: 0}, us, 0, cs)
}

func newRuleInput(data *Funcdata, size int32, off uint64) *Varnode {
	sp := data.BaseAddr().Space
	return data.SetInputVarnode(data.NewVarnode(size, address.Address{Space: sp, Offset: off}))
}

func newRuleOp(data *Funcdata, opcode OpCode, outSize int32, inputs ...*Varnode) *PcodeOp {
	addr := address.Address{Space: data.BaseAddr().Space, Offset: uint64(0x1000 + data.NumOps()*0x10)}
	op := data.NewOp(len(inputs), addr)
	data.OpSetOpcode(op, opcode)
	data.NewUniqueOut(outSize, op)
	for i, in := range inputs {
		data.OpSetInput(op, in, i)
	}
	data.OpMarkAlive(op)
	return op
}

func TestRulesArith_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	y := newRuleInput(data, 4, 0x20)

	neg := newRuleOp(data, CPUI_INT_2COMP, 4, y)
	add := newRuleOp(data, CPUI_INT_ADD, 4, x, neg.Output())
	if got := NewRule2Comp2Sub("arith").ApplyOp(add, data); got != 1 {
		t.Fatalf("2comp2sub ApplyOp=%d, want 1", got)
	}
	if add.Code() != CPUI_INT_SUB || add.Input(0) != x || add.Input(1) != y {
		t.Fatalf("unexpected add rewrite: opcode=%v in0=%v in1=%v", add.Code(), add.Input(0), add.Input(1))
	}

	same := newRuleOp(data, CPUI_INT_OR, 4, x, x)
	if got := NewRuleTrivialArith("arith").ApplyOp(same, data); got != 1 {
		t.Fatalf("trivialarith ApplyOp=%d, want 1", got)
	}
	if same.Code() != CPUI_COPY || same.Input(0) != x {
		t.Fatalf("trivialarith failed: opcode=%v in0=%v", same.Code(), same.Input(0))
	}

	mult := newRuleOp(data, CPUI_INT_MULT, 4, x, data.NewConstant(4, 3))
	collapse := newRuleOp(data, CPUI_INT_ADD, 4, mult.Output(), x)
	if got := NewRuleAddMultCollapse("arith").ApplyOp(collapse, data); got != 1 {
		t.Fatalf("addmultcollapse ApplyOp=%d, want 1", got)
	}
	if collapse.Code() != CPUI_INT_MULT {
		t.Fatalf("expected INT_MULT, got %v", collapse.Code())
	}
	if val, ok := constantValue(collapse.Input(1)); !ok || val != 4 {
		t.Fatalf("expected multiplier 4, got %d ok=%v", val, ok)
	}

	noneg := newRuleOp(data, CPUI_INT_ADD, 4, x, data.NewConstant(4, 7))
	if got := NewRule2Comp2Sub("arith").ApplyOp(noneg, data); got != 0 {
		t.Fatalf("2comp2sub non-rewrite=%d, want 0", got)
	}
}
