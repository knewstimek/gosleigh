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

import "testing"

// TestInputTypeLocal checks the per-opcode expected input type (metain table)
// against the metatypes from the C++ TypeOpBinary/Unary/Func constructors.
func TestInputTypeLocal(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	insts := RegisterTypeOps()
	tf := sharedTypeFactory
	base := fd.BaseAddr()

	cases := []struct {
		name string
		opc  OpCode
		nin  int
		slot int
		size int32
		want metatype
	}{
		{"int_add slot0", CPUI_INT_ADD, 2, 0, 4, TYPE_INT},
		{"int_less slot1", CPUI_INT_LESS, 2, 1, 4, TYPE_UINT},
		{"int_and slot0", CPUI_INT_AND, 2, 0, 4, TYPE_UINT},
		{"ptradd index", CPUI_PTRADD, 3, 1, 4, TYPE_INT},
		{"copy is unknown", CPUI_COPY, 1, 0, 4, TYPE_UNKNOWN},
		{"float_add slot0", CPUI_FLOAT_ADD, 2, 0, 8, TYPE_FLOAT},
	}

	for i, c := range cases {
		op := fd.NewOp(c.nin, base)
		fd.OpSetOpcode(op, c.opc)
		for s := 0; s < c.nin; s++ {
			vn := fd.NewVarnode(c.size, makeInferRamAddr(fd, uint64(0x2000+0x40*i+8*s)))
			fd.OpSetInput(op, vn, s)
		}
		got := insts[c.opc].InputTypeLocal(op, c.slot, tf)
		if got == nil {
			t.Errorf("%s: InputTypeLocal returned nil", c.name)
			continue
		}
		if got.Metatype() != c.want {
			t.Errorf("%s: metatype=%d, want %d", c.name, got.Metatype(), c.want)
		}
		if got.Size() != c.size {
			t.Errorf("%s: size=%d, want %d", c.name, got.Size(), c.size)
		}
	}
}

// TestGetInputCastCopy checks TypeOpCopy::getInputCast: the COPY input must be
// cast to match the output type. A pointer output over a non-pointer input of
// the same size requires a cast; matching types require none.
func TestGetInputCastCopy(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	insts := RegisterTypeOps()
	tf := sharedTypeFactory

	i4 := tf.GetBase(4, TYPE_INT, "int")
	ptrInt := Datatype(tf.GetPointer(4, i4, 1))

	op := fd.NewOp(1, fd.BaseAddr())
	fd.OpSetOpcode(op, CPUI_COPY)
	out := fd.NewVarnodeOut(4, makeInferRamAddr(fd, 0x3000), op)
	in := fd.NewVarnode(4, makeInferRamAddr(fd, 0x3008))
	fd.OpSetInput(op, in, 0)
	out.UpdateType(ptrInt)
	in.UpdateType(i4)

	got := insts[CPUI_COPY].GetInputCast(op, 0, sharedCastStrategyC)
	if got == nil {
		t.Fatalf("COPY ptr<-int: expected a cast, got nil")
	}
	if got != ptrInt {
		t.Errorf("COPY ptr<-int: cast type = %v, want %v", got, ptrInt)
	}

	// Matching pointer types: no cast.
	in.UpdateType(ptrInt)
	if got := insts[CPUI_COPY].GetInputCast(op, 0, sharedCastStrategyC); got != nil {
		t.Errorf("COPY ptr<-ptr: expected no cast, got %v", got)
	}
}

// TestGetInputCastSubpiece checks that SUBPIECE never requires an input cast
// (its metain is TYPE_UNKNOWN, so the base path yields nil).
func TestGetInputCastSubpiece(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	insts := RegisterTypeOps()
	tf := sharedTypeFactory

	op := fd.NewOp(2, fd.BaseAddr())
	fd.OpSetOpcode(op, CPUI_SUBPIECE)
	out := fd.NewVarnodeOut(2, makeInferRamAddr(fd, 0x4000), op)
	_ = out
	in := fd.NewVarnode(4, makeInferRamAddr(fd, 0x4008))
	off := fd.NewConstant(4, 0)
	fd.OpSetInput(op, in, 0)
	fd.OpSetInput(op, off, 1)
	in.UpdateType(tf.GetBase(4, TYPE_INT, "int"))

	if got := insts[CPUI_SUBPIECE].GetInputCast(op, 0, sharedCastStrategyC); got != nil {
		t.Errorf("SUBPIECE input cast: expected nil, got %v", got)
	}
}

// TestIntPromotionConstants exercises localExtensionType / intPromotionType on
// constant varnodes, the cases that do not require a defining op.
// C++ parity: cast.cc CastStrategyC::localExtensionType / intPromotionType.
func TestIntPromotionConstants(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	cs := sharedCastStrategyC

	// The shared test funcdata's const space has no SpaceKindConstant, so the
	// VarnodeConstant flag is not set at creation; mark it explicitly here.
	mkConst := func(size int32, val uint64) *Varnode {
		vn := fd.NewConstant(size, val)
		vn.SetFlags(VarnodeConstant)
		return vn
	}

	// Constant with high bit clear -> either extension (size 2, value 0x10).
	cPos := mkConst(2, 0x10)
	if got := cs.localExtensionType(cPos, cPos.LoneDescend()); got != eitherExtension {
		t.Errorf("localExtensionType(const 0x10:2) = %d, want eitherExtension(%d)", got, eitherExtension)
	}
	if got := cs.intPromotionType(cPos); got != eitherExtension {
		t.Errorf("intPromotionType(const 0x10:2) = %d, want eitherExtension(%d)", got, eitherExtension)
	}

	// Constant with high bit set, unsigned natural -> unsigned extension.
	cNeg := mkConst(1, 0x80)
	if got := cs.localExtensionType(cNeg, cNeg.LoneDescend()); got != unsignedExtension {
		t.Errorf("localExtensionType(const 0x80:1) = %d, want unsignedExtension(%d)", got, unsignedExtension)
	}

	// A value at or above promoteSize never promotes.
	cBig := mkConst(4, 0x12345678)
	if got := cs.intPromotionType(cBig); got != noPromotion {
		t.Errorf("intPromotionType(const :4) = %d, want noPromotion(%d)", got, noPromotion)
	}
}
