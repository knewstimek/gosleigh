package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func newStoreRuleOp(data *Funcdata, inputs ...*Varnode) *PcodeOp {
	addr := address.Address{Space: data.BaseAddr().Space, Offset: uint64(0x2000 + data.NumOps()*0x10)}
	op := data.NewOp(len(inputs), addr)
	data.OpSetOpcode(op, CPUI_STORE)
	for i, in := range inputs {
		data.OpSetInput(op, in, i)
	}
	data.OpMarkAlive(op)
	return op
}

func TestRuleLoadVarnode_ConstantAddress(t *testing.T) {
	data := newRulesFuncdata()
	ram := data.BaseAddr().Space
	spaceID := data.NewSpaceIDConst(ram)
	ptr := data.NewConstant(4, 0x220)
	load := newRuleOp(data, CPUI_LOAD, 4, spaceID, ptr)
	SetVarnodeType(load.Output(), sharedTypeFactory.GetBase(4, TYPE_INT, "int4"))

	if got := NewRuleLoadVarnode("mem").ApplyOp(load, data); got != 1 {
		t.Fatalf("loadvarnode ApplyOp = %d, want 1", got)
	}
	if load.Code() != CPUI_COPY {
		t.Fatalf("load opcode = %v, want COPY", load.Code())
	}
	if load.Input(0).Space() != ram || load.Input(0).Offset() != 0x220 {
		t.Fatalf("load source = %v:0x%x, want ram:0x220", load.Input(0).Space(), load.Input(0).Offset())
	}
}

func TestRuleLoadVarnode_SpacebasePlaceholderClear(t *testing.T) {
	data := newRulesFuncdata()
	stack := &address.Space{Name: "stack", Kind: address.SpaceKindStack, Index: 7, AddrSize: 4, WordSize: 1}
	spaceID := data.NewSpaceIDConst(stack)
	int4 := sharedTypeFactory.GetBase(4, TYPE_INT, "int4")
	ptrType := sharedTypeFactory.GetPointer(4, int4, 1)
	sp := newRuleInput(data, 4, 0x40)
	BindSpacebase(sp, stack)
	SetVarnodeType(sp, ptrType)
	addrAdd := newRuleOp(data, CPUI_INT_ADD, 4, sp, data.NewConstant(4, 0x10))
	SetVarnodeType(addrAdd.Output(), ptrType)
	load := newRuleOp(data, CPUI_LOAD, 4, spaceID, addrAdd.Output())
	load.Output().SetSpacebasePlaceholder()
	SetVarnodeType(load.Output(), int4)

	if got := NewRuleLoadVarnode("mem").ApplyOp(load, data); got != 1 {
		t.Fatalf("loadvarnode(spacebase) ApplyOp = %d, want 1", got)
	}
	if load.Code() != CPUI_COPY {
		t.Fatalf("load opcode = %v, want COPY", load.Code())
	}
	if load.Input(0).Space() != stack || load.Input(0).Offset() != 0x10 {
		t.Fatalf("load source offset = 0x%x in %v, want stack:0x10", load.Input(0).Offset(), load.Input(0).Space())
	}
	if load.Output().IsSpacebasePlaceholder() {
		t.Fatal("spacebase placeholder flag should be cleared")
	}
}

func TestRuleStoreVarnode_ConstantAddress(t *testing.T) {
	data := newRulesFuncdata()
	stack := &address.Space{Name: "stack", Kind: address.SpaceKindStack, Index: 8, AddrSize: 4, WordSize: 1}
	spaceID := data.NewSpaceIDConst(stack)
	value := newRuleInput(data, 4, 0x80)
	SetVarnodeType(value, sharedTypeFactory.GetBase(4, TYPE_INT, "int4"))
	store := newStoreRuleOp(data, spaceID, data.NewConstant(4, 0x24), value)

	if got := NewRuleStoreVarnode("mem").ApplyOp(store, data); got != 1 {
		t.Fatalf("storevarnode ApplyOp = %d, want 1", got)
	}
	if store.Code() != CPUI_COPY {
		t.Fatalf("store opcode = %v, want COPY", store.Code())
	}
	if store.Output() == nil || store.Output().Space() != stack || store.Output().Offset() != 0x24 {
		t.Fatalf("store output = %v, want stack:0x24", store.Output())
	}
	if !store.Output().IsStackStore() {
		t.Fatal("rewritten store output should be marked stack store")
	}
	if store.NumInput() != 1 || store.Input(0) != value {
		t.Fatalf("store copy input mismatch: got %d inputs", store.NumInput())
	}
}

func TestRuleStoreSpacebase_RewritesRelativeStore(t *testing.T) {
	data := newRulesFuncdata()
	stack := &address.Space{Name: "stack", Kind: address.SpaceKindStack, Index: 9, AddrSize: 4, WordSize: 1}
	spaceID := data.NewSpaceIDConst(stack)
	int4 := sharedTypeFactory.GetBase(4, TYPE_INT, "int4")
	ptrType := sharedTypeFactory.GetPointer(4, int4, 1)
	sp := newRuleInput(data, 4, 0x90)
	BindSpacebase(sp, stack)
	SetVarnodeType(sp, ptrType)
	addrAdd := newRuleOp(data, CPUI_INT_ADD, 4, sp, data.NewConstant(4, 0x14))
	SetVarnodeType(addrAdd.Output(), ptrType)
	value := newRuleInput(data, 4, 0x94)
	SetVarnodeType(value, int4)
	store := newStoreRuleOp(data, spaceID, addrAdd.Output(), value)

	if got := NewRuleStoreSpacebase("mem").ApplyOp(store, data); got != 1 {
		t.Fatalf("storespacebase ApplyOp = %d, want 1", got)
	}
	if store.Code() != CPUI_COPY {
		t.Fatalf("store opcode = %v, want COPY", store.Code())
	}
	if store.Output() == nil || store.Output().Space() != stack || store.Output().Offset() != 0x14 {
		t.Fatalf("store output = %v, want stack:0x14", store.Output())
	}
	if !store.Output().IsStackStore() {
		t.Fatal("expected stack store mark on rewritten store")
	}
}
