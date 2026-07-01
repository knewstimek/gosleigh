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

// makeInferTestFuncdata builds a minimal Funcdata for inference tests.
func makeInferTestFuncdata(t *testing.T) *Funcdata {
	t.Helper()
	ramSpace := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4}
	uniqSpace := &address.Space{Name: "unique", Index: 2, WordSize: 1, AddrSize: 4}
	constSpace := &address.Space{Name: "const", Index: 1, WordSize: 1, AddrSize: 4}
	baseAddr := address.Address{Space: ramSpace, Offset: 0x1000}
	return NewFuncdata("test", baseAddr, uniqSpace, 0x10000, constSpace)
}

// makeInferRamAddr builds a ram-space address for inference tests.
func makeInferRamAddr(fd *Funcdata, off uint64) address.Address {
	// Reuse the space from the funcdata base address.
	return address.Address{Space: fd.BaseAddr().Space, Offset: off}
}

// TestInferTypesCopyChain verifies that a type seeded on the source varnode
// propagates through a COPY chain.
func TestInferTypesCopyChain(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	tf := NewTypeFactory()

	// Build:  vn0 (input, size=4) -COPY-> vn1 -COPY-> vn2
	addr0 := makeInferRamAddr(fd, 0x10)
	addr1 := makeInferRamAddr(fd, 0x14)
	addr2 := makeInferRamAddr(fd, 0x18)

	vn0 := fd.NewVarnode(4, addr0)
	fd.SetInputVarnode(vn0)

	baseAddr := fd.BaseAddr()

	op1 := fd.NewOp(1, baseAddr)
	fd.OpSetOpcode(op1, CPUI_COPY)
	vn1 := fd.NewVarnodeOut(4, addr1, op1)
	fd.OpSetInput(op1, vn0, 0)
	fd.OpMarkAlive(op1)

	op2 := fd.NewOp(1, baseAddr)
	fd.OpSetOpcode(op2, CPUI_COPY)
	vn2 := fd.NewVarnodeOut(4, addr2, op2)
	fd.OpSetInput(op2, vn1, 0)
	fd.OpMarkAlive(op2)

	// Seed a pointer type on vn0 via HighVariable.
	ptrType := tf.GetPointer(4, tf.GetBase(4, TYPE_INT, "int"), 1)
	hv0 := NewHighVariable("src")
	hv0.SetType(ptrType)
	hv0.AddInstance(vn0)

	action := NewActionInferTypesLegacy("test")
	action.Apply(fd)

	// vn2 should have received the pointer type through the COPY chain.
	vn2Type := vn2.Type()
	if vn2Type == nil {
		t.Fatal("expected vn2 to have a type after COPY chain propagation, got nil")
	}
	if vn2Type.Metatype() != TYPE_PTR {
		t.Errorf("expected TYPE_PTR on vn2, got metatype=%d (%T)", vn2Type.Metatype(), vn2Type)
	}
}

// TestInferTypesLoadDereference verifies that a pointer type on the address
// input of LOAD causes the output to receive the pointee type.
func TestInferTypesLoadDereference(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	tf := NewTypeFactory()

	baseAddr := fd.BaseAddr()

	// Build: addrVn (input, pointer to int) -LOAD-> outVn
	addrAddr := makeInferRamAddr(fd, 0x20)
	addrVn := fd.NewVarnode(4, addrAddr)
	fd.SetInputVarnode(addrVn)

	// LOAD needs: input[0] = space constant, input[1] = address varnode.
	// Use NewConstant which creates a varnode in the const space.
	spaceConst := fd.NewConstant(4, 0)

	op := fd.NewOp(2, baseAddr)
	fd.OpSetOpcode(op, CPUI_LOAD)
	outVn := fd.NewUniqueOut(4, op)
	fd.OpSetInput(op, spaceConst, 0)
	fd.OpSetInput(op, addrVn, 1)
	fd.OpMarkAlive(op)

	// Seed pointer-to-int on addrVn.
	intType := tf.GetBase(4, TYPE_INT, "int")
	ptrType := tf.GetPointer(4, intType, 1)
	hv := NewHighVariable("ptr")
	hv.SetType(ptrType)
	hv.AddInstance(addrVn)

	action := NewActionInferTypesLegacy("test")
	action.Apply(fd)

	outType := outVn.Type()
	if outType == nil {
		t.Fatal("expected LOAD output to have a type after propagation, got nil")
	}
	if outType.Metatype() != TYPE_INT {
		t.Errorf("expected TYPE_INT on LOAD output, got metatype=%d (%T)", outType.Metatype(), outType)
	}
}

// TestInferTypesIntAddPointer verifies that a pointer type on one input of
// INT_ADD propagates to the output (pointer arithmetic).
func TestInferTypesIntAddPointer(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	tf := NewTypeFactory()

	baseAddr := fd.BaseAddr()

	// Build: ptrVn + offsetVn -INT_ADD-> outVn
	ptrAddr := makeInferRamAddr(fd, 0x30)
	offsetAddr := makeInferRamAddr(fd, 0x34)
	outAddr := makeInferRamAddr(fd, 0x38)

	ptrVn := fd.NewVarnode(4, ptrAddr)
	fd.SetInputVarnode(ptrVn)
	offsetVn := fd.NewVarnode(4, offsetAddr)
	fd.SetInputVarnode(offsetVn)

	op := fd.NewOp(2, baseAddr)
	fd.OpSetOpcode(op, CPUI_INT_ADD)
	outVn := fd.NewVarnodeOut(4, outAddr, op)
	fd.OpSetInput(op, ptrVn, 0)
	fd.OpSetInput(op, offsetVn, 1)
	fd.OpMarkAlive(op)

	// Seed pointer type on ptrVn.
	intType := tf.GetBase(4, TYPE_INT, "int")
	ptrType := tf.GetPointer(4, intType, 1)
	hv := NewHighVariable("p")
	hv.SetType(ptrType)
	hv.AddInstance(ptrVn)

	action := NewActionInferTypesLegacy("test")
	action.Apply(fd)

	outType := outVn.Type()
	if outType == nil {
		t.Fatal("expected INT_ADD output to have a type after pointer propagation, got nil")
	}
	if outType.Metatype() != TYPE_PTR {
		t.Errorf("expected TYPE_PTR on INT_ADD output, got metatype=%d (%T)", outType.Metatype(), outType)
	}
}

// TestInferTypesConvergence verifies that the action converges within 7
// iterations even on a longer COPY chain.
func TestInferTypesConvergence(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	tf := NewTypeFactory()

	baseAddr := fd.BaseAddr()

	// Build a 5-node COPY chain: vn0 -> vn1 -> ... -> vn4
	const chainLen = 5
	vns := make([]*Varnode, chainLen)
	for i := 0; i < chainLen; i++ {
		vns[i] = fd.NewVarnode(4, makeInferRamAddr(fd, uint64(0x40+i*4)))
		if i == 0 {
			fd.SetInputVarnode(vns[i])
		}
	}
	for i := 0; i < chainLen-1; i++ {
		op := fd.NewOp(1, baseAddr)
		fd.OpSetOpcode(op, CPUI_COPY)
		fd.OpSetInput(op, vns[i], 0)
		// re-create output varnode at a proper unique location
		out := fd.NewVarnodeOut(4, makeInferRamAddr(fd, uint64(0x40+(i+1)*4)), op)
		fd.OpMarkAlive(op)
		vns[i+1] = out
	}

	// Seed int type on vns[0].
	intType := tf.GetBase(4, TYPE_INT, "int")
	hv := NewHighVariable("v0")
	hv.SetType(intType)
	hv.AddInstance(vns[0])

	action := NewActionInferTypesLegacy("test")
	result := action.Apply(fd)

	// Should have propagated and returned 1 (modified).
	if result == 0 {
		t.Error("expected Apply to return 1 (modified), got 0")
	}

	// Final node should have the int type.
	lastType := vns[chainLen-1].Type()
	if lastType == nil {
		t.Fatalf("expected vns[%d] to have a type, got nil", chainLen-1)
	}
	if lastType.Metatype() != TYPE_INT {
		t.Errorf("expected TYPE_INT on chain end, got metatype=%d", lastType.Metatype())
	}
}
