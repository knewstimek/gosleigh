package pcode

import "testing"

func TestRulePositiveDivAndDivChain(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	y := newRuleInput(data, 4, 0x20)
	x.SetNZMask(0x7fffffff)
	y.SetNZMask(0x7fffffff)

	sdiv := newRuleOp(data, CPUI_INT_SDIV, 4, x, y)
	if got := NewRulePositiveDiv("divmod").ApplyOp(sdiv, data); got != 1 {
		t.Fatalf("positivediv ApplyOp=%d, want 1", got)
	}
	if sdiv.Code() != CPUI_INT_DIV {
		t.Fatalf("positivediv opcode=%v, want INT_DIV", sdiv.Code())
	}

	div1 := newRuleOp(data, CPUI_INT_DIV, 4, x, data.NewConstant(4, 3))
	div2 := newRuleOp(data, CPUI_INT_DIV, 4, div1.Output(), data.NewConstant(4, 5))
	if got := NewRuleDivChain("divmod").ApplyOp(div2, data); got != 1 {
		t.Fatalf("divchain ApplyOp=%d, want 1", got)
	}
	if div2.Code() != CPUI_INT_DIV {
		t.Fatalf("divchain opcode=%v, want INT_DIV", div2.Code())
	}
	if val, ok := constantValue(div2.Input(1)); !ok || val != 15 {
		t.Fatalf("divchain divisor=%d ok=%v, want 15/true", val, ok)
	}
}

func TestRuleDivOptCompilerIdioms(t *testing.T) {
	data := newRulesFuncdata()

	ux := newRuleInput(data, 4, 0x100)
	ux.SetNZMask(0xffffffff)
	uz := newRuleOp(data, CPUI_INT_ZEXT, 8, ux)
	um := newRuleOp(data, CPUI_INT_MULT, 8, uz.Output(), data.NewConstant(8, 0xcccccccd))
	usub := newRuleOp(data, CPUI_SUBPIECE, 4, um.Output(), data.NewConstant(4, 4))
	uroot := newRuleOp(data, CPUI_INT_RIGHT, 4, usub.Output(), data.NewConstant(4, 3))
	if got := NewRuleDivOpt("divmod").ApplyOp(uroot, data); got != 1 {
		t.Fatalf("divopt unsigned ApplyOp=%d, want 1", got)
	}
	if uroot.Code() != CPUI_INT_DIV || uroot.Input(0) != ux {
		t.Fatalf("divopt unsigned rewrite opcode=%v input0=%v", uroot.Code(), uroot.Input(0))
	}
	if val, ok := constantValue(uroot.Input(1)); !ok || val != 10 {
		t.Fatalf("divopt unsigned divisor=%d ok=%v, want 10/true", val, ok)
	}

	sx := newRuleInput(data, 4, 0x120)
	sx.SetNZMask(0xffffffff)
	sz := newRuleOp(data, CPUI_INT_SEXT, 8, sx)
	sm := newRuleOp(data, CPUI_INT_MULT, 8, sz.Output(), data.NewConstant(8, 0x66666667))
	ssub := newRuleOp(data, CPUI_SUBPIECE, 4, sm.Output(), data.NewConstant(4, 4))
	sroot := newRuleOp(data, CPUI_INT_SRIGHT, 4, ssub.Output(), data.NewConstant(4, 1))
	if got := NewRuleDivOpt("divmod").ApplyOp(sroot, data); got != 1 {
		t.Fatalf("divopt signed ApplyOp=%d, want 1", got)
	}
	if sroot.Code() != CPUI_INT_ADD {
		t.Fatalf("divopt signed opcode=%v, want INT_ADD", sroot.Code())
	}
	divop := sroot.Input(0).Def()
	if divop == nil || divop.Code() != CPUI_INT_SDIV {
		t.Fatalf("divopt signed divop=%v, want INT_SDIV", divop)
	}
	if val, ok := constantValue(divop.Input(1)); !ok || val != 5 {
		t.Fatalf("divopt signed divisor=%d ok=%v, want 5/true", val, ok)
	}
	signop := sroot.Input(1).Def()
	if signop == nil || signop.Code() != CPUI_INT_SRIGHT {
		t.Fatalf("divopt signed signop=%v, want INT_SRIGHT", signop)
	}

	bad := newRuleOp(data, CPUI_INT_SRIGHT, 4, usub.Output(), data.NewConstant(4, 3))
	if got := NewRuleDivOpt("divmod").ApplyOp(bad, data); got != 0 {
		t.Fatalf("divopt mismatch ApplyOp=%d, want 0", got)
	}
}

func TestRuleSignDivAndModFamilies(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x200)
	x.SetNZMask(0xffffffff)

	sign := newRuleOp(data, CPUI_INT_SRIGHT, 4, x, data.NewConstant(4, 31))
	neg := newRuleOp(data, CPUI_INT_MULT, 4, sign.Output(), data.NewConstant(4, 0xffffffff))
	add := newRuleOp(data, CPUI_INT_ADD, 4, x, neg.Output())
	sdiv2 := newRuleOp(data, CPUI_INT_SRIGHT, 4, add.Output(), data.NewConstant(4, 1))
	if got := NewRuleSignDiv2("divmod").ApplyOp(sdiv2, data); got != 1 {
		t.Fatalf("signdiv2 ApplyOp=%d, want 1", got)
	}
	if sdiv2.Code() != CPUI_INT_SDIV {
		t.Fatalf("signdiv2 opcode=%v, want INT_SDIV", sdiv2.Code())
	}

	divu := newRuleOp(data, CPUI_INT_DIV, 4, x, data.NewConstant(4, 10))
	multu := newRuleOp(data, CPUI_INT_MULT, 4, divu.Output(), data.NewConstant(4, 10))
	remu := newRuleOp(data, CPUI_INT_SUB, 4, x, multu.Output())
	if got := NewRuleModOpt("divmod").ApplyOp(divu, data); got != 1 {
		t.Fatalf("modopt unsigned ApplyOp=%d, want 1", got)
	}
	if remu.Code() != CPUI_INT_REM {
		t.Fatalf("modopt unsigned opcode=%v, want INT_REM", remu.Code())
	}

	divs := newRuleOp(data, CPUI_INT_SDIV, 4, x, data.NewConstant(4, 5))
	mults := newRuleOp(data, CPUI_INT_MULT, 4, divs.Output(), data.NewConstant(4, 0xfffffffb))
	rems := newRuleOp(data, CPUI_INT_ADD, 4, x, mults.Output())
	if got := NewRuleModOpt("divmod").ApplyOp(divs, data); got != 1 {
		t.Fatalf("modopt signed ApplyOp=%d, want 1", got)
	}
	if rems.Code() != CPUI_INT_SREM {
		t.Fatalf("modopt signed opcode=%v, want INT_SREM", rems.Code())
	}
}

func TestRuleSignFormsAndSignedModuloPatterns(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x300)
	x.SetNZMask(0xffffffff)

	sext := newRuleOp(data, CPUI_INT_SEXT, 8, x)
	signForm := newRuleOp(data, CPUI_SUBPIECE, 4, sext.Output(), data.NewConstant(4, 4))
	if got := NewRuleSignForm("divmod").ApplyOp(signForm, data); got != 1 {
		t.Fatalf("signform ApplyOp=%d, want 1", got)
	}
	if signForm.Code() != CPUI_INT_SRIGHT || signForm.Input(0) != x {
		t.Fatalf("signform rewrite failed opcode=%v input0=%v", signForm.Code(), signForm.Input(0))
	}

	sx := newRuleInput(data, 4, 0x320)
	sx.SetNZMask(0xffffffff)
	sext2 := newRuleOp(data, CPUI_INT_SEXT, 8, sx)
	mult2 := newRuleOp(data, CPUI_INT_MULT, 8, sext2.Output(), data.NewConstant(8, 2))
	high := newRuleOp(data, CPUI_SUBPIECE, 4, mult2.Output(), data.NewConstant(4, 4))
	signForm2 := newRuleOp(data, CPUI_INT_SRIGHT, 4, high.Output(), data.NewConstant(4, 31))
	if got := NewRuleSignForm2("divmod").ApplyOp(signForm2, data); got != 1 {
		t.Fatalf("signform2 ApplyOp=%d, want 1", got)
	}
	if signForm2.Input(0) != sx {
		t.Fatalf("signform2 input0=%v, want %v", signForm2.Input(0), sx)
	}

	mx := newRuleInput(data, 4, 0x340)
	mx.SetNZMask(0xffffffff)
	msign := newRuleOp(data, CPUI_INT_SRIGHT, 4, mx, data.NewConstant(4, 31))
	mneg := newRuleOp(data, CPUI_INT_MULT, 4, msign.Output(), data.NewConstant(4, 0xffffffff))
	madd := newRuleOp(data, CPUI_INT_ADD, 4, mx, mneg.Output())
	mand := newRuleOp(data, CPUI_INT_AND, 4, madd.Output(), data.NewConstant(4, 1))
	mroot := newRuleOp(data, CPUI_INT_ADD, 4, mand.Output(), msign.Output())
	if got := NewRuleSignMod2Opt("divmod").ApplyOp(mand, data); got != 1 {
		t.Fatalf("signmod2opt ApplyOp=%d, want 1", got)
	}
	if mroot.Code() != CPUI_INT_SREM {
		t.Fatalf("signmod2opt opcode=%v, want INT_SREM", mroot.Code())
	}

	nx := newRuleInput(data, 4, 0x360)
	nx.SetNZMask(0xffffffff)
	nsign := newRuleOp(data, CPUI_INT_SRIGHT, 4, nx, data.NewConstant(4, 31))
	ncorr := newRuleOp(data, CPUI_INT_RIGHT, 4, nsign.Output(), data.NewConstant(4, 30))
	nadd := newRuleOp(data, CPUI_INT_ADD, 4, nx, ncorr.Output())
	nand := newRuleOp(data, CPUI_INT_AND, 4, nadd.Output(), data.NewConstant(4, 3))
	nneg := newRuleOp(data, CPUI_INT_MULT, 4, ncorr.Output(), data.NewConstant(4, 0xffffffff))
	nroot := newRuleOp(data, CPUI_INT_ADD, 4, nneg.Output(), nand.Output())
	if got := NewRuleSignMod2nOpt("divmod").ApplyOp(ncorr, data); got != 1 {
		t.Fatalf("signmod2nopt ApplyOp=%d, want 1", got)
	}
	if nroot.Code() != CPUI_INT_SREM {
		t.Fatalf("signmod2nopt opcode=%v, want INT_SREM", nroot.Code())
	}

	px := newRuleInput(data, 4, 0x380)
	psign := newRuleOp(data, CPUI_INT_SRIGHT, 4, px, data.NewConstant(4, 31))
	pneg := newRuleOp(data, CPUI_INT_MULT, 4, psign.Output(), data.NewConstant(4, 0xffffffff))
	padj := newRuleOp(data, CPUI_INT_ADD, 4, px, pneg.Output())
	pand := newRuleOp(data, CPUI_INT_AND, 4, padj.Output(), data.NewConstant(4, 0xfffffffc))
	pmult := newRuleOp(data, CPUI_INT_MULT, 4, pand.Output(), data.NewConstant(4, 0xffffffff))
	proot := newRuleOp(data, CPUI_INT_ADD, 4, pmult.Output(), px)
	if got := NewRuleSignMod2nOpt2("divmod").ApplyOp(pmult, data); got != 1 {
		t.Fatalf("signmod2nopt2 ApplyOp=%d, want 1", got)
	}
	if proot.Code() != CPUI_INT_SREM {
		t.Fatalf("signmod2nopt2 opcode=%v, want INT_SREM", proot.Code())
	}
}

func TestBatchCDivModRulesRegistration(t *testing.T) {
	pool := NewActionPool(0, "batch-c-divmod")
	count := AddBatchCDivModRules(pool, "batch-c")
	if count != len(BatchCDivModRules("batch-c")) {
		t.Fatalf("registration count mismatch: %d vs %d", count, len(BatchCDivModRules("batch-c")))
	}
	if count != 10 {
		t.Fatalf("registration count=%d, want 10", count)
	}
	if pool.GetSubRule("divopt") == nil {
		t.Fatal("expected divopt to be registered")
	}
	if pool.GetSubRule("signmod2opt") == nil {
		t.Fatal("expected signmod2opt to be registered")
	}
}
