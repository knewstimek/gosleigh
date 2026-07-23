package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// RuleXorCollapse -- ruleaction.cc:4058. Covers both C++ forms plus the guards.
func TestRuleXorCollapse_ComparisonForms(t *testing.T) {
	// (V ^ W) == 0  =>  V == W
	data := newRulesFuncdata()
	v := newRuleInput(data, 4, 0x10)
	w := newRuleInput(data, 4, 0x20)
	xorop := newRuleOp(data, CPUI_INT_XOR, 4, v, w)
	eq := newRuleOp(data, CPUI_INT_EQUAL, 1, xorop.Output(), data.NewConstant(4, 0))
	if got := NewRuleXorCollapse("analysis").ApplyOp(eq, data); got != 1 {
		t.Fatalf("(V^W)==0 ApplyOp=%d, want 1", got)
	}
	if eq.Input(0) != v || eq.Input(1) != w {
		t.Fatalf("(V^W)==0 did not become V==W: in0=%v in1=%v", eq.Input(0), eq.Input(1))
	}

	// (V ^ c) != d  =>  V != (c^d)
	data = newRulesFuncdata()
	v = newRuleInput(data, 4, 0x10)
	xorop = newRuleOp(data, CPUI_INT_XOR, 4, v, data.NewConstant(4, 0x30))
	ne := newRuleOp(data, CPUI_INT_NOTEQUAL, 1, xorop.Output(), data.NewConstant(4, 0x12))
	if got := NewRuleXorCollapse("analysis").ApplyOp(ne, data); got != 1 {
		t.Fatalf("(V^c)!=d ApplyOp=%d, want 1", got)
	}
	if ne.Input(0) != v {
		t.Fatalf("(V^c)!=d left side not collapsed: %v", ne.Input(0))
	}
	if !ne.Input(1).IsConstant() || ne.Input(1).Offset() != 0x22 {
		t.Fatalf("(V^c)!=d constant fold wrong: %v", ne.Input(1))
	}

	// (V ^ W) == d with d != 0 must not fire (only the zero form moves a term).
	data = newRulesFuncdata()
	v = newRuleInput(data, 4, 0x10)
	w = newRuleInput(data, 4, 0x20)
	xorop = newRuleOp(data, CPUI_INT_XOR, 4, v, w)
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, xorop.Output(), data.NewConstant(4, 5))
	if got := NewRuleXorCollapse("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("(V^W)==5 ApplyOp=%d, want 0", got)
	}

	// Non-constant right side must not fire.
	data = newRulesFuncdata()
	v = newRuleInput(data, 4, 0x10)
	w = newRuleInput(data, 4, 0x20)
	u := newRuleInput(data, 4, 0x30)
	xorop = newRuleOp(data, CPUI_INT_XOR, 4, v, w)
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, xorop.Output(), u)
	if got := NewRuleXorCollapse("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("(V^W)==U ApplyOp=%d, want 0", got)
	}

	// XOR result read by more than one op must not fire (loneDescend guard).
	data = newRulesFuncdata()
	v = newRuleInput(data, 4, 0x10)
	w = newRuleInput(data, 4, 0x20)
	xorop = newRuleOp(data, CPUI_INT_XOR, 4, v, w)
	newRuleOp(data, CPUI_INT_ADD, 4, xorop.Output(), data.NewConstant(4, 1))
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, xorop.Output(), data.NewConstant(4, 0))
	if got := NewRuleXorCollapse("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("multi-descend ApplyOp=%d, want 0", got)
	}
}

// The INT_XOR identity body preserved from the pre-parity rule of the same name.
func TestRuleXorIdentity_Elements(t *testing.T) {
	data := newRulesFuncdata()
	v := newRuleInput(data, 4, 0x10)

	zero := newRuleOp(data, CPUI_INT_XOR, 4, v, data.NewConstant(4, 0))
	if got := NewRuleXorIdentity("analysis").ApplyOp(zero, data); got != 1 {
		t.Fatalf("V^0 ApplyOp=%d, want 1", got)
	}
	if zero.Code() != CPUI_COPY || zero.Input(0) != v {
		t.Fatalf("V^0 did not collapse to COPY V: %v", zero.Code())
	}

	ones := newRuleOp(data, CPUI_INT_XOR, 4, v, data.NewConstant(4, 0xffffffff))
	if got := NewRuleXorIdentity("analysis").ApplyOp(ones, data); got != 1 {
		t.Fatalf("V^-1 ApplyOp=%d, want 1", got)
	}
	if ones.Code() != CPUI_INT_NEGATE || ones.Input(0) != v {
		t.Fatalf("V^-1 did not collapse to NEGATE V: %v", ones.Code())
	}
}

// RuleNotDistribute -- ruleaction.cc:1139. Boolean (not bitwise) De Morgan.
func TestRuleNotDistribute_BoolDeMorgan(t *testing.T) {
	data := newRulesFuncdata()
	a := newRuleInput(data, 1, 0x10)
	b := newRuleInput(data, 1, 0x20)

	and := newRuleOp(data, CPUI_BOOL_AND, 1, a, b)
	neg := newRuleOp(data, CPUI_BOOL_NEGATE, 1, and.Output())
	if got := NewRuleNotDistribute("analysis").ApplyOp(neg, data); got != 1 {
		t.Fatalf("!(a&&b) ApplyOp=%d, want 1", got)
	}
	if neg.Code() != CPUI_BOOL_OR || neg.NumInput() != 2 {
		t.Fatalf("!(a&&b) did not become BOOL_OR/2: %v/%d", neg.Code(), neg.NumInput())
	}
	for slot, want := range []*Varnode{a, b} {
		in := neg.Input(slot).Def()
		if in == nil || in.Code() != CPUI_BOOL_NEGATE || in.Input(0) != want {
			t.Fatalf("slot %d is not BOOL_NEGATE of the original operand: %v", slot, in)
		}
	}

	// The bitwise form the pre-parity rule used to expand must be left alone.
	x := newRuleInput(data, 4, 0x30)
	y := newRuleInput(data, 4, 0x40)
	bitand := newRuleOp(data, CPUI_INT_AND, 4, x, y)
	bitneg := newRuleOp(data, CPUI_INT_NEGATE, 4, bitand.Output())
	if got := NewRuleNotDistribute("analysis").ApplyOp(bitneg, data); got != 0 {
		t.Fatalf("~(x&y) ApplyOp=%d, want 0 (bitwise De Morgan has no C++ rule)", got)
	}
	if bitneg.Code() != CPUI_INT_NEGATE {
		t.Fatalf("~(x&y) was rewritten to %v", bitneg.Code())
	}
}

// RuleZextEliminate -- ruleaction.cc:2507. Drop an INT_ZEXT feeding a comparison
// against a constant that survives the narrowing. This rule does not fire on the
// current corpus (measured: 701 entries, every one bailing because neither
// comparison operand is INT_ZEXT-defined), so the behaviour is pinned here.
func TestRuleZextEliminate_ComparisonForms(t *testing.T) {
	// zext(V) == c  =>  V == c
	data := newRulesFuncdata()
	v := newRuleInput(data, 1, 0x10)
	zext := newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	eq := newRuleOp(data, CPUI_INT_EQUAL, 1, zext.Output(), data.NewConstant(4, 0x41))
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 1 {
		t.Fatalf("zext(V)==c ApplyOp=%d, want 1", got)
	}
	if eq.Input(0) != v {
		t.Fatalf("zext(V)==c did not reach through the extension: %v", eq.Input(0))
	}
	if !eq.Input(1).IsConstant() || eq.Input(1).Size() != 1 || eq.Input(1).Offset() != 0x41 {
		t.Fatalf("zext(V)==c constant not narrowed: size=%d off=%#x", eq.Input(1).Size(), eq.Input(1).Offset())
	}

	// c != zext(V)  =>  c != V   (extension in slot 1; slots must stay put)
	data = newRulesFuncdata()
	v = newRuleInput(data, 2, 0x10)
	zext = newRuleOp(data, CPUI_INT_ZEXT, 8, v)
	ne := newRuleOp(data, CPUI_INT_NOTEQUAL, 1, data.NewConstant(8, 0xffff), zext.Output())
	if got := NewRuleZextEliminate("analysis").ApplyOp(ne, data); got != 1 {
		t.Fatalf("c!=zext(V) ApplyOp=%d, want 1", got)
	}
	if ne.Input(1) != v {
		t.Fatalf("c!=zext(V) kept the extension in slot 1: %v", ne.Input(1))
	}
	if !ne.Input(0).IsConstant() || ne.Input(0).Size() != 2 || ne.Input(0).Offset() != 0xffff {
		t.Fatalf("c!=zext(V) constant not narrowed into slot 0: size=%d off=%#x", ne.Input(0).Size(), ne.Input(0).Offset())
	}

	// zext(V) <= c  =>  V <= c   (the INT_LESSEQUAL member of the op list)
	data = newRulesFuncdata()
	v = newRuleInput(data, 1, 0x10)
	zext = newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	le := newRuleOp(data, CPUI_INT_LESSEQUAL, 1, zext.Output(), data.NewConstant(4, 0x7f))
	if got := NewRuleZextEliminate("analysis").ApplyOp(le, data); got != 1 {
		t.Fatalf("zext(V)<=c ApplyOp=%d, want 1", got)
	}
	if le.Input(0) != v || le.Input(1).Size() != 1 {
		t.Fatalf("zext(V)<=c not rewritten: in0=%v in1size=%d", le.Input(0), le.Input(1).Size())
	}
}

func TestRuleZextEliminate_Guards(t *testing.T) {
	// A constant with non-zero bits above the unextended width must be kept.
	data := newRulesFuncdata()
	v := newRuleInput(data, 1, 0x10)
	zext := newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	eq := newRuleOp(data, CPUI_INT_EQUAL, 1, zext.Output(), data.NewConstant(4, 0x1234))
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("zext(V)==0x1234 on a 1-byte source ApplyOp=%d, want 0", got)
	}

	// The other operand has to be constant.
	data = newRulesFuncdata()
	v = newRuleInput(data, 1, 0x10)
	w := newRuleInput(data, 4, 0x20)
	zext = newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, zext.Output(), w)
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("zext(V)==W ApplyOp=%d, want 0", got)
	}

	// The extension must have no other reader.
	data = newRulesFuncdata()
	v = newRuleInput(data, 1, 0x10)
	zext = newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	newRuleOp(data, CPUI_INT_ADD, 4, zext.Output(), data.NewConstant(4, 1))
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, zext.Output(), data.NewConstant(4, 0x41))
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("multi-descend extension ApplyOp=%d, want 0", got)
	}

	// The extension source must be heritage-resolved (free reads are left alone).
	data = newRulesFuncdata()
	free := data.NewVarnode(1, address.Address{Space: data.BaseAddr().Space, Offset: 0x30})
	zext = newRuleOp(data, CPUI_INT_ZEXT, 4, free)
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, zext.Output(), data.NewConstant(4, 0x41))
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("zext of a free varnode ApplyOp=%d, want 0", got)
	}

	// Neither operand written by INT_ZEXT.
	data = newRulesFuncdata()
	a := newRuleInput(data, 4, 0x10)
	eq = newRuleOp(data, CPUI_INT_EQUAL, 1, a, data.NewConstant(4, 0x41))
	if got := NewRuleZextEliminate("analysis").ApplyOp(eq, data); got != 0 {
		t.Fatalf("plain V==c ApplyOp=%d, want 0", got)
	}
}

// The INT_ZEXT body preserved from the pre-parity rule that carried the
// RuleZextEliminate name.
func TestRuleZextIdentity_Elements(t *testing.T) {
	data := newRulesFuncdata()
	v := newRuleInput(data, 4, 0x10)

	same := newRuleOp(data, CPUI_INT_ZEXT, 4, v)
	if got := NewRuleZextIdentity("analysis").ApplyOp(same, data); got != 1 {
		t.Fatalf("width-preserving zext ApplyOp=%d, want 1", got)
	}
	if same.Code() != CPUI_COPY || same.Input(0) != v {
		t.Fatalf("width-preserving zext did not become COPY V: %v", same.Code())
	}

	konst := newRuleOp(data, CPUI_INT_ZEXT, 4, data.NewConstant(1, 0x41))
	if got := NewRuleZextIdentity("analysis").ApplyOp(konst, data); got != 1 {
		t.Fatalf("zext of a constant ApplyOp=%d, want 1", got)
	}
	if konst.Code() != CPUI_COPY || !konst.Input(0).IsConstant() || konst.Input(0).Size() != 4 {
		t.Fatalf("zext of a constant did not widen in place: %v", konst.Code())
	}
}
