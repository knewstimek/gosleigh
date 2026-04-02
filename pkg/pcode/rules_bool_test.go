package pcode

import "testing"

func TestRulesBool_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	flag := newRuleInput(data, 1, 0x10)
	x := newRuleInput(data, 4, 0x20)

	trivial := newRuleOp(data, CPUI_BOOL_XOR, 1, flag, data.NewConstant(1, 1))
	if got := NewRuleTrivialBool("bool").ApplyOp(trivial, data); got != 1 {
		t.Fatalf("trivialbool ApplyOp=%d, want 1", got)
	}
	if trivial.Code() != CPUI_BOOL_NEGATE || trivial.Input(0) != flag {
		t.Fatalf("expected BOOL_NEGATE(flag), got %v", trivial.Code())
	}

	cond := newRuleOp(data, CPUI_INT_EQUAL, 1, x, data.NewConstant(4, 0))
	cmp := newRuleOp(data, CPUI_INT_EQUAL, 1, cond.Output(), data.NewConstant(1, 0))
	if got := NewRuleBooleanNegate("bool").ApplyOp(cmp, data); got != 1 {
		t.Fatalf("booleannegate ApplyOp=%d, want 1", got)
	}
	if cmp.Code() != CPUI_BOOL_NEGATE || cmp.Input(0) != cond.Output() {
		t.Fatalf("expected BOOL_NEGATE(cond), got %v", cmp.Code())
	}

	inner := newRuleOp(data, CPUI_INT_EQUAL, 1, x, data.NewConstant(4, 3))
	neg := newRuleOp(data, CPUI_BOOL_NEGATE, 1, inner.Output())
	if got := NewRuleBoolNegate("bool").ApplyOp(neg, data); got != 1 {
		t.Fatalf("boolnegate ApplyOp=%d, want 1", got)
	}
	if neg.Code() != CPUI_INT_NOTEQUAL {
		t.Fatalf("expected flipped compare, got %v", neg.Code())
	}

	xor := newRuleOp(data, CPUI_INT_XOR, 4, x, data.NewConstant(4, 0x55))
	eq0 := newRuleOp(data, CPUI_INT_EQUAL, 1, xor.Output(), data.NewConstant(4, 0))
	if got := NewRuleEqual2Zero("bool").ApplyOp(eq0, data); got != 1 {
		t.Fatalf("equal2zero ApplyOp=%d, want 1", got)
	}
	if eq0.Code() != CPUI_INT_EQUAL {
		t.Fatalf("expected INT_EQUAL, got %v", eq0.Code())
	}
	if val, ok := constantValue(eq0.Input(1)); !ok || val != 0x55 {
		t.Fatalf("expected compare against 0x55, got %d ok=%v", val, ok)
	}

	none := newRuleOp(data, CPUI_INT_AND, 4, x, data.NewConstant(4, 1))
	if got := NewRuleLogic2Bool("bool").ApplyOp(none, data); got != 0 {
		t.Fatalf("logic2bool non-rewrite=%d, want 0", got)
	}
}
