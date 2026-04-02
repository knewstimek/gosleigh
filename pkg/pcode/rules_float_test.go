package pcode

import "testing"

func TestRuleFloatCastRewrites(t *testing.T) {
	data := newRulesFuncdata()
	f := newRuleInput(data, 4, 0x10)
	i := newRuleInput(data, 4, 0x20)

	inner := newRuleOp(data, CPUI_FLOAT_FLOAT2FLOAT, 8, f)
	outer := newRuleOp(data, CPUI_FLOAT_FLOAT2FLOAT, 4, inner.Output())
	if got := NewRuleFloatCast("float").ApplyOp(outer, data); got != 1 {
		t.Fatalf("floatcast float->float ApplyOp=%d, want 1", got)
	}
	if outer.Code() != CPUI_COPY || outer.Input(0) != f {
		t.Fatalf("floatcast collapse failed opcode=%v input0=%v", outer.Code(), outer.Input(0))
	}

	int2float := newRuleOp(data, CPUI_FLOAT_INT2FLOAT, 4, i)
	widen := newRuleOp(data, CPUI_FLOAT_FLOAT2FLOAT, 8, int2float.Output())
	if got := NewRuleFloatCast("float").ApplyOp(widen, data); got != 1 {
		t.Fatalf("floatcast int->float ApplyOp=%d, want 1", got)
	}
	if widen.Code() != CPUI_FLOAT_INT2FLOAT || widen.Input(0) != i {
		t.Fatalf("floatcast int collapse failed opcode=%v input0=%v", widen.Code(), widen.Input(0))
	}

	plain := newRuleOp(data, CPUI_FLOAT_FLOAT2FLOAT, 8, f)
	if got := NewRuleFloatCast("float").ApplyOp(plain, data); got != 0 {
		t.Fatalf("floatcast nonrewrite=%d, want 0", got)
	}
}

func TestRuleIgnoreNanProtectingCompareOnly(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x40)
	y := newRuleInput(data, 4, 0x44)
	flag := newRuleInput(data, 1, 0x48)

	nanop := newRuleOp(data, CPUI_FLOAT_NAN, 1, x)
	cmp := newRuleOp(data, CPUI_FLOAT_LESS, 1, x, y)
	guard := newRuleOp(data, CPUI_BOOL_OR, 1, nanop.Output(), cmp.Output())
	if got := NewRuleIgnoreNan("float").ApplyOp(nanop, data); got != 1 {
		t.Fatalf("ignorenan ApplyOp=%d, want 1", got)
	}
	if guard.Code() != CPUI_COPY || guard.Input(0) != cmp.Output() {
		t.Fatalf("ignorenan rewrite failed opcode=%v input0=%v", guard.Code(), guard.Input(0))
	}

	nanop2 := newRuleOp(data, CPUI_FLOAT_NAN, 1, y)
	none := newRuleOp(data, CPUI_BOOL_OR, 1, nanop2.Output(), flag)
	if got := NewRuleIgnoreNan("float").ApplyOp(nanop2, data); got != 0 {
		t.Fatalf("ignorenan nonrewrite=%d, want 0", got)
	}
	if none.Code() != CPUI_BOOL_OR {
		t.Fatalf("ignorenan should not rewrite unrelated guard, got %v", none.Code())
	}
}

func TestRuleUnsigned2FloatRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x60)
	shift := newRuleOp(data, CPUI_INT_RIGHT, 4, x, data.NewConstant(4, 1))
	andop := newRuleOp(data, CPUI_INT_AND, 4, x, data.NewConstant(4, 1))
	orop := newRuleOp(data, CPUI_INT_OR, 4, shift.Output(), andop.Output())
	conv := newRuleOp(data, CPUI_FLOAT_INT2FLOAT, 4, orop.Output())
	add := newRuleOp(data, CPUI_FLOAT_ADD, 4, conv.Output(), conv.Output())

	if got := NewRuleUnsigned2Float("float").ApplyOp(conv, data); got != 1 {
		t.Fatalf("unsigned2float ApplyOp=%d, want 1", got)
	}
	if add.Code() != CPUI_FLOAT_INT2FLOAT {
		t.Fatalf("unsigned2float consumer opcode=%v, want FLOAT_INT2FLOAT", add.Code())
	}
	zext := add.Input(0).Def()
	if zext == nil || zext.Code() != CPUI_INT_ZEXT || zext.Input(0) != x {
		t.Fatalf("unsigned2float zext=%v, want INT_ZEXT of x", zext)
	}

	plain := newRuleOp(data, CPUI_FLOAT_INT2FLOAT, 4, x)
	if got := NewRuleUnsigned2Float("float").ApplyOp(plain, data); got != 0 {
		t.Fatalf("unsigned2float nonrewrite=%d, want 0", got)
	}
}

func TestRuleFloatSignAndCleanup(t *testing.T) {
	data := newRulesFuncdata()
	float4 := sharedTypeFactory.GetBase(4, TYPE_FLOAT, "float4")

	bits := newRuleInput(data, 4, 0x80)
	other := newRuleInput(data, 4, 0x84)
	SetVarnodeType(other, float4)
	absBits := newRuleOp(data, CPUI_INT_AND, 4, bits, data.NewConstant(4, 0x7fffffff))
	add := newRuleOp(data, CPUI_FLOAT_ADD, 4, absBits.Output(), other)
	if got := NewRuleFloatSign("float").ApplyOp(add, data); got != 1 {
		t.Fatalf("floatsign ApplyOp=%d, want 1", got)
	}
	if absBits.Code() != CPUI_FLOAT_ABS || absBits.NumInput() != 1 || absBits.Input(0) != bits {
		t.Fatalf("floatsign rewrite failed opcode=%v inputs=%d", absBits.Code(), absBits.NumInput())
	}

	negBits := newRuleOp(data, CPUI_INT_XOR, 4, bits, data.NewConstant(4, 0x80000000))
	SetVarnodeType(negBits.Output(), float4)
	if got := NewRuleFloatSignCleanup("float").ApplyOp(negBits, data); got != 1 {
		t.Fatalf("floatsigncleanup ApplyOp=%d, want 1", got)
	}
	if negBits.Code() != CPUI_FLOAT_NEG || negBits.NumInput() != 1 || negBits.Input(0) != bits {
		t.Fatalf("floatsigncleanup rewrite failed opcode=%v inputs=%d", negBits.Code(), negBits.NumInput())
	}

	none := newRuleOp(data, CPUI_INT_AND, 4, bits, data.NewConstant(4, 0xffffffff))
	SetVarnodeType(none.Output(), float4)
	if got := NewRuleFloatSignCleanup("float").ApplyOp(none, data); got != 0 {
		t.Fatalf("floatsigncleanup nonrewrite=%d, want 0", got)
	}
}

func TestBatchCFloatRulesRegistration(t *testing.T) {
	pool := NewActionPool(0, "batch-c-float")
	count := AddBatchCFloatRules(pool, "batch-c")
	if count != len(BatchCFloatRules("batch-c")) {
		t.Fatalf("registration count mismatch: %d vs %d", count, len(BatchCFloatRules("batch-c")))
	}
	if count != 5 {
		t.Fatalf("registration count=%d, want 5", count)
	}
	if pool.GetSubRule("ignorenan") == nil {
		t.Fatal("expected ignorenan to be registered")
	}
	if pool.GetSubRule("floatsigncleanup") == nil {
		t.Fatal("expected floatsigncleanup to be registered")
	}
}
