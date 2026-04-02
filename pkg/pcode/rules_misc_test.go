package pcode

import "testing"

func TestBatchCMisc(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		pool := NewActionPool(0, "batch-c-misc")
		count := AddBatchCMiscRules(pool, "batch-c")
		if count != len(BatchCMiscRules("batch-c")) {
			t.Fatalf("registration count mismatch: %d vs %d", count, len(BatchCMiscRules("batch-c")))
		}
		if count < 30 {
			t.Fatalf("registration count=%d, want at least 30", count)
		}
		names := []string{
			"switchsingle",
			"transformcpool",
			"segment",
			"piecepathology",
			"expandload",
			"conditionalmove",
			"funcptrencoding",
			"pullsub_multi",
			"pullsub_indirect",
			"push_multi",
			"pushptr",
		}
		for _, name := range names {
			if pool.GetSubRule(name) == nil {
				t.Fatalf("expected %s to be registered", name)
			}
		}
	})

	t.Run("lessone", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x10)
		op := newRuleOp(data, CPUI_INT_LESS, 1, x, data.NewConstant(4, 1))
		if got := NewRuleLessOne("misc").ApplyOp(op, data); got != 1 {
			t.Fatalf("lessone ApplyOp=%d, want 1", got)
		}
		if op.Code() != CPUI_INT_EQUAL || op.Input(0) != x || !isZeroConst(op.Input(1)) {
			t.Fatalf("lessone rewrite failed opcode=%v in0=%v in1=%v", op.Code(), op.Input(0), op.Input(1))
		}
	})

	t.Run("xorswap", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x20)
		y := newRuleInput(data, 4, 0x24)
		inner := newRuleOp(data, CPUI_INT_XOR, 4, x, y)
		outer := newRuleOp(data, CPUI_INT_XOR, 4, inner.Output(), y)
		if got := NewRuleXorSwap("misc").ApplyOp(outer, data); got != 1 {
			t.Fatalf("xorswap ApplyOp=%d, want 1", got)
		}
		if outer.Code() != CPUI_COPY || outer.Input(0) != x {
			t.Fatalf("xorswap rewrite failed opcode=%v in0=%v", outer.Code(), outer.Input(0))
		}
	})

	t.Run("lzcountshiftbool", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x30)
		lzc := newRuleOp(data, CPUI_LZCOUNT, 4, x)
		shift := newRuleOp(data, CPUI_INT_RIGHT, 1, lzc.Output(), data.NewConstant(4, 5))
		if got := NewRuleLzcountShiftBool("misc").ApplyOp(shift, data); got != 1 {
			t.Fatalf("lzcountshiftbool ApplyOp=%d, want 1", got)
		}
		if shift.Code() != CPUI_INT_EQUAL || shift.Input(0) != x || !isZeroConst(shift.Input(1)) {
			t.Fatalf("lzcountshiftbool rewrite failed opcode=%v in0=%v in1=%v", shift.Code(), shift.Input(0), shift.Input(1))
		}
	})

	t.Run("orcompare", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x40)
		y := newRuleInput(data, 4, 0x44)
		less := newRuleOp(data, CPUI_INT_LESS, 1, x, y)
		eq := newRuleOp(data, CPUI_INT_EQUAL, 1, x, y)
		orop := newRuleOp(data, CPUI_BOOL_OR, 1, less.Output(), eq.Output())
		if got := NewRuleOrCompare("misc").ApplyOp(orop, data); got != 1 {
			t.Fatalf("orcompare ApplyOp=%d, want 1", got)
		}
		if orop.Code() != CPUI_INT_LESSEQUAL || orop.Input(0) != x || orop.Input(1) != y {
			t.Fatalf("orcompare rewrite failed opcode=%v in0=%v in1=%v", orop.Code(), orop.Input(0), orop.Input(1))
		}
	})
}
