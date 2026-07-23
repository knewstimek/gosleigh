package pcode

import "testing"

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
