package pcode

import "testing"

func TestRulesExt_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 2, 0x10)

	pieceZ := newRuleOp(data, CPUI_PIECE, 4, data.NewConstant(2, 0), x)
	if got := NewRulePiece2Zext("ext").ApplyOp(pieceZ, data); got != 1 {
		t.Fatalf("piece2zext ApplyOp=%d, want 1", got)
	}
	if pieceZ.Code() != CPUI_INT_ZEXT || pieceZ.Input(0) != x {
		t.Fatalf("expected INT_ZEXT(x), got %v", pieceZ.Code())
	}

	shift := newRuleOp(data, CPUI_INT_SRIGHT, 2, x, data.NewConstant(2, 15))
	pieceS := newRuleOp(data, CPUI_PIECE, 4, shift.Output(), x)
	if got := NewRulePiece2Sext("ext").ApplyOp(pieceS, data); got != 1 {
		t.Fatalf("piece2sext ApplyOp=%d, want 1", got)
	}
	if pieceS.Code() != CPUI_INT_SEXT || pieceS.Input(0) != x {
		t.Fatalf("expected INT_SEXT(x), got %v", pieceS.Code())
	}

	zext := newRuleOp(data, CPUI_INT_ZEXT, 4, x)
	sub := newRuleOp(data, CPUI_SUBPIECE, 2, zext.Output(), data.NewConstant(4, 0))
	if got := NewRuleSubZext("ext").ApplyOp(sub, data); got != 1 {
		t.Fatalf("subzext ApplyOp=%d, want 1", got)
	}
	if sub.Code() != CPUI_COPY || sub.Input(0) != x {
		t.Fatalf("expected COPY(x), got %v", sub.Code())
	}

	cmp := newRuleOp(data, CPUI_INT_SLESS, 1, zext.Output(), data.NewConstant(4, 0))
	if got := NewRuleZextSless("ext").ApplyOp(cmp, data); got != 1 {
		t.Fatalf("zextsless ApplyOp=%d, want 1", got)
	}
	if cmp.Code() != CPUI_COPY || !isZeroConst(cmp.Input(0)) {
		t.Fatalf("expected false copy, got %v", cmp.Code())
	}

	noneShift := newRuleOp(data, CPUI_INT_SRIGHT, 2, x, data.NewConstant(2, 1))
	nonePiece := newRuleOp(data, CPUI_PIECE, 4, noneShift.Output(), x)
	if got := NewRulePiece2Sext("ext").ApplyOp(nonePiece, data); got != 0 {
		t.Fatalf("piece2sext non-rewrite=%d, want 0", got)
	}
}
