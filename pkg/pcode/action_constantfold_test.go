// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import (
	"testing"

	"gosleigh/pkg/address"
)

// makeConstFoldFuncdata creates a minimal Funcdata for constant-fold tests.
// Exposes constSpace so tests can create constant varnodes directly.
func makeConstFoldFuncdata() (*Funcdata, *address.Space) {
	ramSp := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, WordSize: 1, AddrSize: 4}
	constSp := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, WordSize: 1, AddrSize: 4}
	uniqSp := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, WordSize: 1, AddrSize: 4}
	fd := NewFuncdata("fold_test", address.Address{Space: ramSp, Offset: 0}, uniqSp, 0, constSp)
	return fd, constSp
}

// buildSingleOp creates a 1-output op in fd with the given opcode and constant
// inputs, inserts it into a fresh basic block, and returns the op.
// Caller is responsible for calling OpMarkAlive if needed (allOpsOrdered uses
// AllOps which includes dead ops, but OpDestroy relies on parent).
func buildSingleOp(fd *Funcdata, opc OpCode, outSize int32, inputVals ...uint64) *PcodeOp {
	addr := address.Address{Space: fd.constSpace, Offset: 0}
	op := fd.NewOp(len(inputVals), addr)
	fd.OpSetOpcode(op, opc)

	// Allocate output varnode in unique space so it is not a constant.
	outVn := fd.NewUniqueOut(outSize, op)
	_ = outVn

	// Wire constant inputs.
	for i, v := range inputVals {
		cnst := fd.NewConstant(4, v) // size 4 for inputs (typical register size)
		fd.OpSetInput(op, cnst, i)
	}

	// Insert into a basic block so OpDestroy can call RemoveOp.
	bb := NewBlockBasic()
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpEnd(op)

	return op
}

// TestConstantFoldBinaryIntAdd verifies that INT_ADD(5, 3) folds to COPY(8).
func TestConstantFoldBinaryIntAdd(t *testing.T) {
	fd, _ := makeConstFoldFuncdata()

	op := buildSingleOp(fd, CPUI_INT_ADD, 4, 5, 3)
	out := op.Output()
	if out == nil {
		t.Fatal("op output varnode is nil")
	}

	action := NewActionConstantFold("test")
	res := action.Apply(fd)
	if res != 1 {
		t.Fatalf("Apply returned %d, want 1 (modification)", res)
	}

	// After folding, op should be COPY with a single constant input of value 8.
	if op.Code() != CPUI_COPY {
		t.Fatalf("op code = %v, want COPY", op.Code())
	}
	if op.NumInput() != 1 {
		t.Fatalf("op NumInput = %d, want 1", op.NumInput())
	}
	v, ok := constantValue(op.Input(0))
	if !ok {
		t.Fatal("input[0] is not a constant after fold")
	}
	if v != 8 {
		t.Fatalf("folded constant = %d, want 8", v)
	}
}

// TestConstantFoldUnaryPopcount verifies that POPCOUNT(7) folds to COPY(3).
// popcount(7) = popcount(0b111) = 3.
func TestConstantFoldUnaryPopcount(t *testing.T) {
	fd, _ := makeConstFoldFuncdata()

	op := buildSingleOp(fd, CPUI_POPCOUNT, 1, 7)

	action := NewActionConstantFold("test")
	res := action.Apply(fd)
	if res != 1 {
		t.Fatalf("Apply returned %d, want 1", res)
	}

	if op.Code() != CPUI_COPY {
		t.Fatalf("op code = %v, want COPY", op.Code())
	}
	if op.NumInput() != 1 {
		t.Fatalf("op NumInput = %d, want 1", op.NumInput())
	}
	v, ok := constantValue(op.Input(0))
	if !ok {
		t.Fatal("input[0] is not a constant after fold")
	}
	if v != 3 {
		t.Fatalf("folded POPCOUNT(7) = %d, want 3", v)
	}
}

// TestConstantFoldChain verifies that a multi-op chain is collapsed to a
// single constant by fixpoint iteration:
//
//	andOp  = INT_AND(0xff, 0xff)   -> COPY(0xff)
//	popOp  = POPCOUNT(andOp.out)   -> COPY(8)   (popcount(0xff)=8)
//	eqOp   = INT_EQUAL(popOp.out, 8) -> COPY(1) (8 == 8)
func TestConstantFoldChain(t *testing.T) {
	fd, _ := makeConstFoldFuncdata()

	ramSp := fd.baseAddr.Space
	baseAddr := address.Address{Space: ramSp, Offset: 0x1000}

	// andOp: INT_AND(0xff, 0xff) -> unique out (size 4)
	andOp := fd.NewOp(2, baseAddr)
	fd.OpSetOpcode(andOp, CPUI_INT_AND)
	andOut := fd.NewUniqueOut(4, andOp)
	fd.OpSetInput(andOp, fd.NewConstant(4, 0xff), 0)
	fd.OpSetInput(andOp, fd.NewConstant(4, 0xff), 1)
	bb := NewBlockBasic()
	fd.OpMarkAlive(andOp)
	andOp.SetParent(bb)
	bb.InsertOpEnd(andOp)

	// popOp: POPCOUNT(andOut) -> unique out (size 1)
	popOp := fd.NewOp(1, baseAddr)
	fd.OpSetOpcode(popOp, CPUI_POPCOUNT)
	popOut := fd.NewUniqueOut(1, popOp)
	fd.OpSetInput(popOp, andOut, 0)
	fd.OpMarkAlive(popOp)
	popOp.SetParent(bb)
	bb.InsertOpEnd(popOp)

	// eqOp: INT_EQUAL(popOut, const 8) -> unique out (size 1)
	eqOp := fd.NewOp(2, baseAddr)
	fd.OpSetOpcode(eqOp, CPUI_INT_EQUAL)
	_ = fd.NewUniqueOut(1, eqOp)
	fd.OpSetInput(eqOp, popOut, 0)
	fd.OpSetInput(eqOp, fd.NewConstant(1, 8), 1)
	fd.OpMarkAlive(eqOp)
	eqOp.SetParent(bb)
	bb.InsertOpEnd(eqOp)

	action := NewActionConstantFold("test")
	res := action.Apply(fd)
	if res != 1 {
		t.Fatalf("Apply returned %d, want 1", res)
	}

	// All three ops must now be COPY(const).
	for _, tc := range []struct {
		op    *PcodeOp
		label string
		want  uint64
	}{
		{andOp, "andOp INT_AND(0xff,0xff)", 0xff},
		{popOp, "popOp POPCOUNT(0xff)", 8},
		{eqOp, "eqOp INT_EQUAL(8,8)", 1},
	} {
		if tc.op.Code() != CPUI_COPY {
			t.Errorf("%s: code = %v, want COPY", tc.label, tc.op.Code())
			continue
		}
		v, ok := constantValue(tc.op.Input(0))
		if !ok {
			t.Errorf("%s: input[0] is not a constant", tc.label)
			continue
		}
		if v != tc.want {
			t.Errorf("%s: value = %d, want %d", tc.label, v, tc.want)
		}
	}
}
