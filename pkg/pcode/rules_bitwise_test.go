package pcode

import "testing"

func TestRulesBitwise_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	y := newRuleInput(data, 1, 0x20)

	bxor := newRuleOp(data, CPUI_BOOL_XOR, 1, y, data.NewConstant(1, 1))
	if got := NewRuleBxor2NotEqual("bitwise").ApplyOp(bxor, data); got != 1 {
		t.Fatalf("bxor2notequal ApplyOp=%d, want 1", got)
	}
	if bxor.Code() != CPUI_INT_NOTEQUAL {
		t.Fatalf("expected INT_NOTEQUAL, got %v", bxor.Code())
	}

	ormask := newRuleOp(data, CPUI_INT_OR, 4, x, data.NewConstant(4, 0xffffffff))
	if got := NewRuleOrMask("bitwise").ApplyOp(ormask, data); got != 1 {
		t.Fatalf("ormask ApplyOp=%d, want 1", got)
	}
	if ormask.Code() != CPUI_COPY || !isAllOnesConst(ormask.Input(0)) {
		t.Fatalf("ormask failed: opcode=%v input=%v", ormask.Code(), ormask.Input(0))
	}

	andop := newRuleOp(data, CPUI_INT_AND, 4, data.NewConstant(4, 0xff), x)
	if got := NewRuleAndCommute("bitwise").ApplyOp(andop, data); got != 1 {
		t.Fatalf("andcommute ApplyOp=%d, want 1", got)
	}
	if andop.Input(0) != x {
		t.Fatalf("expected variable first after commute")
	}

	neg := newRuleOp(data, CPUI_INT_NEGATE, 4, x)
	identity := newRuleOp(data, CPUI_INT_AND, 4, neg.Output(), x)
	if got := NewRuleNegateIdentity("bitwise").ApplyOp(identity, data); got != 1 {
		t.Fatalf("negateidentity ApplyOp=%d, want 1", got)
	}
	if identity.Code() != CPUI_COPY || !isZeroConst(identity.Input(0)) {
		t.Fatalf("expected zero copy, got opcode=%v input=%v", identity.Code(), identity.Input(0))
	}

	none := newRuleOp(data, CPUI_INT_OR, 4, x, data.NewConstant(4, 0x7fffffff))
	if got := NewRuleOrMask("bitwise").ApplyOp(none, data); got != 0 {
		t.Fatalf("ormask non-rewrite=%d, want 0", got)
	}
}
