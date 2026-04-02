package pcode

import "testing"

func makePointerRuleTypes() (*Base, *Struct, *Pointer) {
	int4 := sharedTypeFactory.GetBase(4, TYPE_INT, "int4")
	st := sharedTypeFactory.GetStruct("node", []TypeField{
		{Offset: 0, Name: "head", Type: int4},
		{Offset: 4, Name: "tail", Type: int4},
	})
	ptr := sharedTypeFactory.GetPointer(4, st, 1)
	return int4, st, ptr
}

func TestAddTreeState_ClassifyAndRebuild(t *testing.T) {
	data := newRulesFuncdata()
	data.SetFlag(FuncTypeRecoveryOn)
	int4, _, ptrType := makePointerRuleTypes()

	ptr := newRuleInput(data, 4, 0x10)
	idx := newRuleInput(data, 4, 0x20)
	delta := newRuleInput(data, 4, 0x30)
	SetVarnodeType(ptr, ptrType)
	SetVarnodeType(idx, int4)
	SetVarnodeType(delta, int4)

	mul := newRuleOp(data, CPUI_INT_MULT, 4, idx, data.NewConstant(4, 8))
	SetVarnodeType(mul.Output(), int4)
	tail1 := newRuleOp(data, CPUI_INT_ADD, 4, mul.Output(), data.NewConstant(4, 4))
	SetVarnodeType(tail1.Output(), int4)
	tail2 := newRuleOp(data, CPUI_INT_ADD, 4, tail1.Output(), delta)
	SetVarnodeType(tail2.Output(), int4)
	root := newRuleOp(data, CPUI_INT_ADD, 4, ptr, tail2.Output())
	SetVarnodeType(root.Output(), ptrType)
	_ = newRuleOp(data, CPUI_COPY, 4, root.Output())

	state := NewAddTreeState(data, root, 0)
	state.clear()
	state.spanAddTree(root, 1)
	if !state.valid {
		t.Fatal("expected add tree classification to be valid")
	}
	state.calcSubtype()
	if len(state.multiple) != 1 {
		t.Fatalf("multiple len = %d, want 1", len(state.multiple))
	}
	if !state.isSubtype || state.offset != 0 {
		t.Fatalf("subtype=%v offset=%d, want true/0", state.isSubtype, state.offset)
	}
	if len(state.nonmult) != 2 {
		t.Fatalf("nonmult len = %d, want 2", len(state.nonmult))
	}

	out := root.Output()
	state = NewAddTreeState(data, root, 0)
	if !state.Apply() {
		t.Fatal("expected add tree rewrite to succeed")
	}
	finalOp := out.Def()
	if finalOp == nil || finalOp.Code() != CPUI_INT_ADD {
		t.Fatalf("final op = %v, want INT_ADD", finalOp)
	}
	ptrSub := finalOp.Input(0).Def()
	if ptrSub == nil || ptrSub.Code() != CPUI_PTRSUB {
		t.Fatalf("ptrsub = %v, want PTRSUB", ptrSub)
	}
	ptrAdd := ptrSub.Input(0).Def()
	if ptrAdd == nil || ptrAdd.Code() != CPUI_PTRADD {
		t.Fatalf("ptradd = %v, want PTRADD", ptrAdd)
	}
	if val, ok := constantValue(ptrSub.Input(1)); !ok || val != 0 {
		t.Fatalf("ptrsub offset = %d ok=%v, want 0/true", val, ok)
	}
	if val, ok := constantValue(ptrAdd.Input(2)); !ok || val != 8 {
		t.Fatalf("ptradd scale = %d ok=%v, want 8/true", val, ok)
	}
}

func TestRulePtrArith_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	data.SetFlag(FuncTypeRecoveryOn)
	int4, _, ptrType := makePointerRuleTypes()

	ptr := newRuleInput(data, 4, 0x100)
	idx := newRuleInput(data, 4, 0x104)
	SetVarnodeType(ptr, ptrType)
	SetVarnodeType(idx, int4)
	mul := newRuleOp(data, CPUI_INT_MULT, 4, idx, data.NewConstant(4, 8))
	SetVarnodeType(mul.Output(), int4)
	root := newRuleOp(data, CPUI_INT_ADD, 4, ptr, mul.Output())
	SetVarnodeType(root.Output(), ptrType)
	out := root.Output()
	use := newRuleOp(data, CPUI_COPY, 4, out)
	SetVarnodeType(use.Output(), ptrType)

	if got := NewRulePtrArith("ptr").ApplyOp(root, data); got != 1 {
		t.Fatalf("ptrarith ApplyOp = %d, want 1", got)
	}
	if out.Def() == nil || out.Def().Code() != CPUI_COPY {
		t.Fatalf("expected rewritten root to feed COPY, got %v", out.Def())
	}

	noUse := newRuleOp(data, CPUI_INT_ADD, 4, ptr, data.NewConstant(4, 4))
	SetVarnodeType(noUse.Output(), ptrType)
	if got := NewRulePtrArith("ptr").ApplyOp(noUse, data); got != 0 {
		t.Fatalf("ptrarith ApplyOp = %d, want 0 when tree has no descendant", got)
	}
}

func TestRulePtrUndoPaths(t *testing.T) {
	data := newRulesFuncdata()
	data.SetFlag(FuncTypeRecoveryOn)
	int4 := sharedTypeFactory.GetBase(4, TYPE_INT, "int4")
	ptrType := sharedTypeFactory.GetPointer(4, int4, 1)

	ptr := newRuleInput(data, 4, 0x200)
	idx := newRuleInput(data, 4, 0x204)
	SetVarnodeType(ptr, ptrType)
	SetVarnodeType(idx, int4)

	ptrAdd := newRuleOp(data, CPUI_PTRADD, 4, ptr, idx, data.NewConstant(4, 8))
	SetVarnodeType(ptrAdd.Output(), ptrType)
	if got := NewRulePtraddUndo("ptr").ApplyOp(ptrAdd, data); got != 1 {
		t.Fatalf("ptraddundo ApplyOp = %d, want 1", got)
	}
	if ptrAdd.Code() != CPUI_INT_ADD {
		t.Fatalf("ptraddundo opcode = %v, want INT_ADD", ptrAdd.Code())
	}
	if def := ptrAdd.Input(1).Def(); def == nil || def.Code() != CPUI_INT_MULT {
		t.Fatalf("expected scaled index multiply, got %v", def)
	}

	ptrSub := newRuleOp(data, CPUI_PTRSUB, 4, ptr, data.NewConstant(4, 4))
	SetVarnodeType(ptrSub.Output(), ptrType)
	add := newRuleOp(data, CPUI_INT_ADD, 4, ptrSub.Output(), data.NewConstant(4, 2))
	SetVarnodeType(add.Output(), ptrType)
	if got := NewRulePtrsubUndo("ptr").ApplyOp(ptrSub, data); got != 1 {
		t.Fatalf("ptrsubundo ApplyOp = %d, want 1", got)
	}
	if ptrSub.Code() != CPUI_INT_ADD {
		t.Fatalf("ptrsubundo opcode = %v, want INT_ADD", ptrSub.Code())
	}
	if val, ok := constantValue(ptrSub.Input(1)); !ok || val != 6 {
		t.Fatalf("ptrsubundo offset = %d ok=%v, want 6/true", val, ok)
	}
	if add.Code() != CPUI_COPY {
		t.Fatalf("descendant opcode = %v, want COPY", add.Code())
	}
}

func TestRulePtrFlowMarksFlags(t *testing.T) {
	data := newRulesFuncdata()
	data.SetFlag(FuncTypeRecoveryOn)
	int4, _, ptrType := makePointerRuleTypes()

	ptr := newRuleInput(data, 4, 0x300)
	idx := newRuleInput(data, 4, 0x304)
	SetVarnodeType(ptr, ptrType)
	SetVarnodeType(idx, int4)
	ptrAdd := newRuleOp(data, CPUI_PTRADD, 4, ptr, idx, data.NewConstant(4, 8))
	SetVarnodeType(ptrAdd.Output(), ptrType)

	if got := NewRulePtrFlow("ptr").ApplyOp(ptrAdd, data); got != 1 {
		t.Fatalf("ptrflow ApplyOp = %d, want 1", got)
	}
	if !ptrAdd.HasPtrFlow() || !ptrAdd.Output().HasPtrFlow() || !ptr.HasPtrFlow() {
		t.Fatal("expected pointer flow flags to be set on op and varnodes")
	}

	copyOp := newRuleOp(data, CPUI_COPY, 4, ptrAdd.Output())
	SetVarnodeType(copyOp.Output(), ptrType)
	if got := NewRulePtrFlowCopy("ptr").ApplyOp(copyOp, data); got != 1 {
		t.Fatalf("ptrflowcopy ApplyOp = %d, want 1", got)
	}
	if !copyOp.HasPtrFlow() || !copyOp.Output().HasPtrFlow() {
		t.Fatal("expected ptrflow copy propagation")
	}
}
