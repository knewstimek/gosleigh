package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

func newRulesFuncdata() *Funcdata {
	sp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	cs := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	us := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	return NewFuncdata("rules", address.Address{Space: sp, Offset: 0}, us, 0, cs)
}

func newRuleInput(data *Funcdata, size int32, off uint64) *Varnode {
	sp := data.BaseAddr().Space
	return data.SetInputVarnode(data.NewVarnode(size, address.Address{Space: sp, Offset: off}))
}

func newRuleOp(data *Funcdata, opcode OpCode, outSize int32, inputs ...*Varnode) *PcodeOp {
	addr := address.Address{Space: data.BaseAddr().Space, Offset: uint64(0x1000 + data.NumOps()*0x10)}
	op := data.NewOp(len(inputs), addr)
	data.OpSetOpcode(op, opcode)
	data.NewUniqueOut(outSize, op)
	for i, in := range inputs {
		data.OpSetInput(op, in, i)
	}
	data.OpMarkAlive(op)
	return op
}

func TestRulesArith_RewriteAndNonRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	y := newRuleInput(data, 4, 0x20)

	neg := newRuleOp(data, CPUI_INT_2COMP, 4, y)
	add := newRuleOp(data, CPUI_INT_ADD, 4, x, neg.Output())
	if got := NewRule2Comp2Sub("arith").ApplyOp(add, data); got != 1 {
		t.Fatalf("2comp2sub ApplyOp=%d, want 1", got)
	}
	if add.Code() != CPUI_INT_SUB || add.Input(0) != x || add.Input(1) != y {
		t.Fatalf("unexpected add rewrite: opcode=%v in0=%v in1=%v", add.Code(), add.Input(0), add.Input(1))
	}

	same := newRuleOp(data, CPUI_INT_OR, 4, x, x)
	if got := NewRuleTrivialArith("arith").ApplyOp(same, data); got != 1 {
		t.Fatalf("trivialarith ApplyOp=%d, want 1", got)
	}
	if same.Code() != CPUI_COPY || same.Input(0) != x {
		t.Fatalf("trivialarith failed: opcode=%v in0=%v", same.Code(), same.Input(0))
	}

	mult := newRuleOp(data, CPUI_INT_MULT, 4, x, data.NewConstant(4, 3))
	collapse := newRuleOp(data, CPUI_INT_ADD, 4, mult.Output(), x)
	if got := NewRuleAddMultCollapse("arith").ApplyOp(collapse, data); got != 1 {
		t.Fatalf("addmultcollapse ApplyOp=%d, want 1", got)
	}
	if collapse.Code() != CPUI_INT_MULT {
		t.Fatalf("expected INT_MULT, got %v", collapse.Code())
	}
	if val, ok := constantValue(collapse.Input(1)); !ok || val != 4 {
		t.Fatalf("expected multiplier 4, got %d ok=%v", val, ok)
	}

	noneg := newRuleOp(data, CPUI_INT_ADD, 4, x, data.NewConstant(4, 7))
	if got := NewRule2Comp2Sub("arith").ApplyOp(noneg, data); got != 0 {
		t.Fatalf("2comp2sub non-rewrite=%d, want 0", got)
	}
}

func TestRuleIdentityEl_IntAdd(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	zero := data.NewConstant(4, 0)
	op := newRuleOp(data, CPUI_INT_ADD, 4, x, zero)
	rule := NewRuleIdentityEl("arith")
	if got := rule.ApplyOp(op, data); got != 1 {
		t.Fatalf("identityel INT_ADD(x,0) ApplyOp=%d, want 1", got)
	}
	if op.Code() != CPUI_COPY {
		t.Fatalf("expected CPUI_COPY after INT_ADD(x,0) collapse, got %v", op.Code())
	}
	if op.Input(0) != x {
		t.Fatalf("expected input[0]==x after INT_ADD(x,0) collapse, got %v", op.Input(0))
	}
}

func TestRuleIdentityEl_IntMult(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	one := data.NewConstant(4, 1)
	op := newRuleOp(data, CPUI_INT_MULT, 4, x, one)
	rule := NewRuleIdentityEl("arith")
	if got := rule.ApplyOp(op, data); got != 1 {
		t.Fatalf("identityel INT_MULT(x,1) ApplyOp=%d, want 1", got)
	}
	if op.Code() != CPUI_COPY {
		t.Fatalf("expected CPUI_COPY after INT_MULT(x,1) collapse, got %v", op.Code())
	}
	if op.Input(0) != x {
		t.Fatalf("expected input[0]==x after INT_MULT(x,1) collapse, got %v", op.Input(0))
	}
}

func TestRuleIdentityEl_IntMultByZero(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	zero := data.NewConstant(4, 0)
	op := newRuleOp(data, CPUI_INT_MULT, 4, x, zero)
	rule := NewRuleIdentityEl("arith")
	if got := rule.ApplyOp(op, data); got != 1 {
		t.Fatalf("identityel INT_MULT(x,0) ApplyOp=%d, want 1", got)
	}
	// After rewriteToConst the op becomes COPY of a constant 0.
	if op.Code() != CPUI_COPY {
		t.Fatalf("expected CPUI_COPY after INT_MULT(x,0) collapse, got %v", op.Code())
	}
	if val, ok := constantValue(op.Input(0)); !ok || val != 0 {
		t.Fatalf("expected constant 0 after INT_MULT(x,0) collapse, got val=%d ok=%v", val, ok)
	}
}

func TestRuleIdentityEl_NoRewrite(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	// INT_ADD(x, 5) -- non-identity constant, must not rewrite.
	nonzero := data.NewConstant(4, 5)
	op := newRuleOp(data, CPUI_INT_ADD, 4, x, nonzero)
	rule := NewRuleIdentityEl("arith")
	if got := rule.ApplyOp(op, data); got != 0 {
		t.Fatalf("identityel INT_ADD(x,5) should not rewrite, got %d", got)
	}
	if op.Code() != CPUI_INT_ADD {
		t.Fatalf("opcode should remain INT_ADD, got %v", op.Code())
	}
}

func TestRuleIdentityEl_IntXorZero(t *testing.T) {
	data := newRulesFuncdata()
	x := newRuleInput(data, 4, 0x10)
	zero := data.NewConstant(4, 0)
	op := newRuleOp(data, CPUI_INT_XOR, 4, x, zero)
	rule := NewRuleIdentityEl("arith")
	if got := rule.ApplyOp(op, data); got != 1 {
		t.Fatalf("identityel INT_XOR(x,0) ApplyOp=%d, want 1", got)
	}
	if op.Code() != CPUI_COPY || op.Input(0) != x {
		t.Fatalf("INT_XOR(x,0) collapse failed: opcode=%v in0=%v", op.Code(), op.Input(0))
	}
}

// TestActionSeedSignedOps_SetsTypeInt verifies that ActionSeedSignedOps seeds
// TYPE_INT on inputs of signed arithmetic opcodes (INT_2COMP / INT_SRIGHT / etc.).
// SLESS/SLESSEQUAL are intentionally excluded: TypeOpIntSless::propagateType
// returns nullptr in C++, so comparisons do not establish operand signedness.
func TestActionSeedSignedOps_SetsTypeInt(t *testing.T) {
	data := newRulesFuncdata()
	a := newRuleInput(data, 4, 0x10)
	// INT_2COMP (two's complement negation) has exactly one input that should
	// be seeded as TYPE_INT because negation is a signed-specific operation.
	newRuleOp(data, CPUI_INT_2COMP, 1, a)

	action := NewActionSeedSignedOps("analysis")
	ret := action.Apply(data)
	if ret != 1 {
		t.Fatalf("ActionSeedSignedOps.Apply=%d, want 1", ret)
	}
	if a.Type() == nil {
		t.Fatal("expected vn_a to have TYPE_INT set, got nil")
	}
	if a.Type().Metatype() != TYPE_INT {
		t.Fatalf("expected vn_a metatype TYPE_INT (%d), got %d", TYPE_INT, a.Type().Metatype())
	}
}

// TestActionSeedSignedOps_SLessDoesNotSeed verifies that INT_SLESS comparisons
// do NOT seed TYPE_INT on their inputs.
// C++ parity: TypeOpIntSless::propagateType returns nullptr (typeop.cc).
func TestActionSeedSignedOps_SLessDoesNotSeed(t *testing.T) {
	data := newRulesFuncdata()
	a := newRuleInput(data, 4, 0x10)
	b := newRuleInput(data, 4, 0x20)
	newRuleOp(data, CPUI_INT_SLESS, 1, a, b)

	action := NewActionSeedSignedOps("analysis")
	ret := action.Apply(data)
	if ret != 0 {
		t.Fatalf("ActionSeedSignedOps.Apply=%d on SLESS, want 0 (no seeding)", ret)
	}
	if a.Type() != nil {
		t.Fatalf("SLESS input vn_a should not be seeded, got type %v", a.Type())
	}
	if b.Type() != nil {
		t.Fatalf("SLESS input vn_b should not be seeded, got type %v", b.Type())
	}
}

// TestActionSeedSignedOps_DoesNotOverrideUint verifies that ActionSeedSignedOps
// does not override a varnode whose type is already TYPE_UINT (more specific
// than TYPE_INT in Ghidra's metatype ordering).
// Uses INT_2COMP (a signed-seeding op) since SLESS no longer seeds at all.
func TestActionSeedSignedOps_DoesNotOverrideUint(t *testing.T) {
	data := newRulesFuncdata()
	a := newRuleInput(data, 4, 0x10)
	// Pre-set vn_a to TYPE_UINT -- more specific than TYPE_INT (13 < 14).
	tf := sharedTypeFactory
	utype := tf.GetExactType(4, TYPE_UINT)
	if utype != nil {
		SetVarnodeType(a, utype)
	}
	newRuleOp(data, CPUI_INT_2COMP, 1, a)
	action := NewActionSeedSignedOps("analysis")
	action.Apply(data)
	// vn_a must still have TYPE_UINT, not overridden to TYPE_INT.
	if a.Type() != nil && a.Type().Metatype() == TYPE_INT {
		t.Fatalf("ActionSeedSignedOps overrode TYPE_UINT with TYPE_INT on vn_a")
	}
}
