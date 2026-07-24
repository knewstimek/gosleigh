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

	// C++ parity: RuleOrCompare fires on CPUI_INT_OR (ruleaction.cc:10805-10874).
	// `(V | W) == 0` => `(V==0) && (W==0)`.
	t.Run("orcompare equal", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x40)
		y := newRuleInput(data, 4, 0x44)
		orop := newRuleOp(data, CPUI_INT_OR, 4, x, y)
		eq := newRuleOp(data, CPUI_INT_EQUAL, 1, orop.Output(), data.NewConstant(4, 0))
		if got := NewRuleOrCompare("misc").ApplyOp(orop, data); got != 1 {
			t.Fatalf("orcompare ApplyOp=%d, want 1", got)
		}
		if eq.Code() != CPUI_BOOL_AND {
			t.Fatalf("orcompare rewrite failed: opcode=%v, want BOOL_AND", eq.Code())
		}
		eqV := eq.Input(0).Def()
		eqW := eq.Input(1).Def()
		if eqV == nil || eqV.Code() != CPUI_INT_EQUAL || eqV.Input(0) != x || !isZeroConst(eqV.Input(1)) {
			t.Fatalf("orcompare slot0 not INT_EQUAL(x,0): %v", eqV)
		}
		if eqW == nil || eqW.Code() != CPUI_INT_EQUAL || eqW.Input(0) != y || !isZeroConst(eqW.Input(1)) {
			t.Fatalf("orcompare slot1 not INT_EQUAL(y,0): %v", eqW)
		}
	})

	// `(V | W) != 0` => `(V!=0) || (W!=0)`.
	t.Run("orcompare notequal", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x50)
		y := newRuleInput(data, 4, 0x54)
		orop := newRuleOp(data, CPUI_INT_OR, 4, x, y)
		ne := newRuleOp(data, CPUI_INT_NOTEQUAL, 1, orop.Output(), data.NewConstant(4, 0))
		if got := NewRuleOrCompare("misc").ApplyOp(orop, data); got != 1 {
			t.Fatalf("orcompare ApplyOp=%d, want 1", got)
		}
		if ne.Code() != CPUI_BOOL_OR {
			t.Fatalf("orcompare rewrite failed: opcode=%v, want BOOL_OR", ne.Code())
		}
		neV := ne.Input(0).Def()
		neW := ne.Input(1).Def()
		if neV == nil || neV.Code() != CPUI_INT_NOTEQUAL || neV.Input(0) != x || !isZeroConst(neV.Input(1)) {
			t.Fatalf("orcompare slot0 not INT_NOTEQUAL(x,0): %v", neV)
		}
		if neW == nil || neW.Code() != CPUI_INT_NOTEQUAL || neW.Input(0) != y || !isZeroConst(neW.Input(1)) {
			t.Fatalf("orcompare slot1 not INT_NOTEQUAL(y,0): %v", neW)
		}
	})

	// A descendant that is not a ==0/!=0 comparison must block the rule entirely.
	t.Run("orcompare non-comparison descendant blocks", func(t *testing.T) {
		data := newRulesFuncdata()
		x := newRuleInput(data, 4, 0x60)
		y := newRuleInput(data, 4, 0x64)
		orop := newRuleOp(data, CPUI_INT_OR, 4, x, y)
		_ = newRuleOp(data, CPUI_INT_EQUAL, 1, orop.Output(), data.NewConstant(4, 0))
		_ = newRuleOp(data, CPUI_INT_ADD, 4, orop.Output(), data.NewConstant(4, 1))
		if got := NewRuleOrCompare("misc").ApplyOp(orop, data); got != 0 {
			t.Fatalf("orcompare ApplyOp=%d, want 0 (non-comparison descendant present)", got)
		}
	})
}
