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

// TestActionSetCastsInsertsCopyCast verifies the ActionSetCasts driver inserts a
// CPUI_CAST feeding a COPY whose output is a pointer but whose input is a plain
// integer of the same size. C++ parity: ActionSetCasts::castInput via
// TypeOpCopy::getInputCast.
func TestActionSetCastsInsertsCopyCast(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	tf := sharedTypeFactory

	i4 := tf.GetBase(4, TYPE_INT, "int")
	ptrInt := Datatype(tf.GetPointer(4, i4, 1))

	op := fd.NewOp(1, fd.BaseAddr())
	fd.OpSetOpcode(op, CPUI_COPY)
	out := fd.NewVarnodeOut(4, makeInferRamAddr(fd, 0x5000), op)
	in := fd.NewVarnode(4, makeInferRamAddr(fd, 0x5008))
	fd.SetInputVarnode(in)
	fd.OpSetInput(op, in, 0)
	fd.OpMarkAlive(op)
	out.UpdateType(ptrInt)
	in.UpdateType(i4)

	NewActionSetCasts("test").Apply(fd)

	newIn := op.Input(0)
	if newIn == in {
		t.Fatalf("expected COPY input to be replaced by a CAST output, still original")
	}
	def := newIn.Def()
	if def == nil || def.Code() != CPUI_CAST {
		t.Fatalf("expected COPY input def to be CPUI_CAST, got %v", def)
	}
	if newIn.Type() != ptrInt {
		t.Errorf("CAST output type = %v, want %v", newIn.Type(), ptrInt)
	}
	if def.Input(0) != in {
		t.Errorf("CAST should take the original input varnode, got %v", def.Input(0))
	}
	if !newIn.IsImplied() {
		t.Errorf("CAST output should be implied")
	}
}

// TestGetInputCastSignedCompare verifies the signed-comparison getInputCast: an
// operand of INT_SLESS whose read-facing type is not already TYPE_INT/TYPE_BOOL is
// cast to int -- both the uint case (the complex_max `(int)param` pattern) and the
// undefined (TYPE_UNKNOWN) case. castStandard only waives the cast for a
// TYPE_UNKNOWN curbase when isptr is set (pointer-to-unknown), which never holds
// for a scalar compare operand.
// C++ parity: TypeOpIntSless::getInputCast (typeop.cc 1025-1033) ->
// CastStrategyC::castStandard (cast.cc 344-361, the care_uint_int TYPE_INT arm).
func TestGetInputCastSignedCompare(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	insts := RegisterTypeOps()
	tf := sharedTypeFactory

	u4 := tf.GetBase(4, TYPE_UINT, "uint")
	und4 := tf.GetBase(4, TYPE_UNKNOWN, "undefined4")
	i4 := Datatype(tf.GetBase(4, TYPE_INT, "int"))

	build := func(t0, t1 Datatype) *PcodeOp {
		op := fd.NewOp(2, fd.BaseAddr())
		fd.OpSetOpcode(op, CPUI_INT_SLESS)
		a := fd.NewVarnode(4, makeInferRamAddr(fd, 0x6100))
		b := fd.NewVarnode(4, makeInferRamAddr(fd, 0x6108))
		a.SetFlags(VarnodeExplicit)
		b.SetFlags(VarnodeExplicit)
		fd.OpSetInput(op, a, 0)
		fd.OpSetInput(op, b, 1)
		a.UpdateType(t0)
		b.UpdateType(t1)
		return op
	}

	// uint operand in a signed comparison -> cast to int.
	op := build(u4, u4)
	got := insts[CPUI_INT_SLESS].GetInputCast(op, 0, sharedCastStrategyC)
	if got == nil || got.Metatype() != TYPE_INT {
		t.Errorf("SLESS uint operand: expected cast to int, got %v", got)
	}
	_ = i4

	// undefined operand -> cast to int. castStandard reaches the TYPE_INT arm with
	// care_uint_int=true; TYPE_UNKNOWN is not TYPE_INT/TYPE_BOOL and isptr is false,
	// so it falls through to "return reqtype".
	op2 := build(und4, und4)
	if got := insts[CPUI_INT_SLESS].GetInputCast(op2, 0, sharedCastStrategyC); got == nil || got.Metatype() != TYPE_INT {
		t.Errorf("SLESS undefined operand: expected cast to int, got %v", got)
	}
}

// TestGetInputCastShiftUndefined pins the INT_RIGHT slot-0 cast over an undefined
// operand: the required type is unsigned, the read-facing type is undefined8, so
// castStandard returns the requirement and the shift renders as
// `(ulonglong)param >> n` (corpus2 add_pt). This is the case a former Gosleigh-only
// "suppress the cast when curtype is TYPE_UNKNOWN" guard silently swallowed.
// C++ parity: TypeOpIntRight::getInputCast (typeop.cc 1545-1558).
func TestGetInputCastShiftUndefined(t *testing.T) {
	fd := makeInferTestFuncdata(t)
	insts := RegisterTypeOps()
	tf := sharedTypeFactory

	und8 := tf.GetBase(8, TYPE_UNKNOWN, "undefined8")

	op := fd.NewOp(2, fd.BaseAddr())
	fd.OpSetOpcode(op, CPUI_INT_RIGHT)
	val := fd.NewVarnode(8, makeInferRamAddr(fd, 0x6200))
	amt := fd.NewVarnode(8, makeInferRamAddr(fd, 0x6208))
	val.SetFlags(VarnodeExplicit)
	amt.SetFlags(VarnodeExplicit)
	fd.OpSetInput(op, val, 0)
	fd.OpSetInput(op, amt, 1)
	val.UpdateType(und8)

	got := insts[CPUI_INT_RIGHT].GetInputCast(op, 0, sharedCastStrategyC)
	if got == nil || got.Metatype() != TYPE_UINT || got.Size() != 8 {
		t.Errorf("INT_RIGHT undefined8 operand: expected cast to 8-byte uint, got %v", got)
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
