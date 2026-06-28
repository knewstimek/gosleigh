package pcode

import "testing"

func TestRulesCopy_RewriteAndRegistration(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	y := newRuleInput(data, 4, 0x20)

	copyop := newRuleOp(data, CPUI_COPY, 4, x)
	use := newRuleOp(data, CPUI_INT_ADD, 4, copyop.Output(), y)
	if got := NewRulePropagateCopy("copy").ApplyOp(use, data); got != 1 {
		t.Fatalf("propagatecopy ApplyOp=%d, want 1", got)
	}
	if use.Input(0) != x {
		t.Fatalf("expected propagated x input")
	}

	piece := newRuleOp(data, CPUI_PIECE, 4, newRuleInput(data, 2, 0x30), newRuleInput(data, 2, 0x40))
	sub := newRuleOp(data, CPUI_SUBPIECE, 2, piece.Output(), data.NewConstant(4, 0))
	if got := NewRuleSubCancel("copy").ApplyOp(sub, data); got != 1 {
		t.Fatalf("subcancel ApplyOp=%d, want 1", got)
	}
	if sub.Code() != CPUI_COPY || sub.Input(0) != piece.Input(1) {
		t.Fatalf("expected COPY of low piece, got %v", sub.Code())
	}

	// C++ parity: RuleMultiCollapse on absolute equality calls totalReplace +
	// opDestroy, so the MULTIEQUAL is destroyed (readers redirected to the
	// surviving value) rather than rewritten in place to a COPY.
	multi := newRuleOp(data, CPUI_MULTIEQUAL, 4, x, x, x)
	adduse := newRuleOp(data, CPUI_INT_ADD, 4, multi.Output(), y)
	if got := NewRuleMultiCollapse("copy").ApplyOp(multi, data); got != 1 {
		t.Fatalf("multicollapse ApplyOp=%d, want 1", got)
	}
	if !multi.IsDead() {
		t.Fatalf("expected collapsed MULTIEQUAL to be destroyed, got %v", multi.Code())
	}
	if adduse.Input(0) != x {
		t.Fatalf("expected MULTIEQUAL reader redirected to x, got %v", adduse.Input(0))
	}

	pool := NewActionPool(0, "batch-a")
	count := AddBatchARules(pool, "batch-a")
	if count != len(BatchARules("batch-a")) {
		t.Fatalf("registration count mismatch: %d vs %d", count, len(BatchARules("batch-a")))
	}
	if count < 40 {
		t.Fatalf("expected at least 40 rules, got %d", count)
	}
	if len(pool.allRules) != count {
		t.Fatalf("pool registered %d rules, want %d", len(pool.allRules), count)
	}
	if pool.allRules[0].GetName() != "piece2zext" || pool.allRules[len(pool.allRules)-1].GetName() != "stringstore" {
		t.Fatalf("unexpected registration order: first=%s last=%s", pool.allRules[0].GetName(), pool.allRules[len(pool.allRules)-1].GetName())
	}
	if pool.GetSubRule("trivialarith") == nil || pool.GetSubRule("propagatecopy") == nil {
		t.Fatal("expected registered rules to be addressable from ActionPool")
	}

	none := newRuleOp(data, CPUI_SUBPIECE, 1, piece.Output(), data.NewConstant(4, 1))
	if got := NewRuleSubCancel("copy").ApplyOp(none, data); got != 0 {
		t.Fatalf("subcancel non-rewrite=%d, want 0", got)
	}
}
