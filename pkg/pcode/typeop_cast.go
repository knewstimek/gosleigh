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

// typeop_cast.go -- per-opcode input-type infrastructure used by cast insertion.
// C++ parity: typeop.cc TypeOp::getInputLocal / TypeOp::getInputCast and the
// per-opcode overrides (TypeOpCopy, TypeOpLoad, TypeOpStore, the comparison ops,
// TypeOpIntZext/Sext, TypeOpSubpiece, TypeOpPtradd/Ptrsub).
//
// This is the foundational layer for ActionSetCasts (coreaction.cc
// ActionSetCasts::castInput). The driver body (apply/castInput/castOutput) and
// its wiring into the decompile pipeline are a separate, later checkpoint; this
// file only supplies the "what type does op expect at input slot N, and does the
// actual input need a cast" query that castInput consumes.
//
// Gosleigh simplification: there is no HighVariable, so the C++ distinction
// between getHighTypeReadFacing(op) (read-facing) and getTypeReadFacing(op)
// (varnode's own type) collapses to vn.TypeReadFacing(op). Where the C++ code
// relies on that distinction (PTRADD/PTRSUB slot-0 cast tests) the comparison
// becomes trivially equal, so those paths return "no cast" -- documented inline.

// opInputMeta holds the metain (TypeOpBinary/Unary/Func input metatype) for each
// opcode. Opcodes whose C++ TypeOp derives directly from TypeOp (COPY, LOAD,
// STORE, branches, calls, markers, CAST, ...) keep the base behavior, modelled
// here as TYPE_UNKNOWN. C++ parity: the metain argument of the TypeOpBinary/
// TypeOpUnary/TypeOpFunc constructors in typeop.cc, plus the getInputLocal
// overrides for PTRADD/PTRSUB (treated as INT_ADD -> TYPE_INT).
var opInputMeta = buildOpInputMeta()

func buildOpInputMeta() []metatype {
	m := make([]metatype, CPUI_MAX+1)
	for i := range m {
		m[i] = TYPE_UNKNOWN
	}
	set := func(op OpCode, meta metatype) { m[op] = meta }

	// Integer comparison
	set(CPUI_INT_EQUAL, TYPE_INT)
	set(CPUI_INT_NOTEQUAL, TYPE_INT)
	set(CPUI_INT_SLESS, TYPE_INT)
	set(CPUI_INT_SLESSEQUAL, TYPE_INT)
	set(CPUI_INT_LESS, TYPE_UINT)
	set(CPUI_INT_LESSEQUAL, TYPE_UINT)

	// Extension
	set(CPUI_INT_ZEXT, TYPE_UINT)
	set(CPUI_INT_SEXT, TYPE_INT)

	// Integer arithmetic / logical
	set(CPUI_INT_ADD, TYPE_INT)
	set(CPUI_INT_SUB, TYPE_INT)
	set(CPUI_INT_CARRY, TYPE_UINT)
	set(CPUI_INT_SCARRY, TYPE_INT)
	set(CPUI_INT_SBORROW, TYPE_INT)
	set(CPUI_INT_2COMP, TYPE_INT)
	set(CPUI_INT_NEGATE, TYPE_UINT)
	set(CPUI_INT_XOR, TYPE_UINT)
	set(CPUI_INT_AND, TYPE_UINT)
	set(CPUI_INT_OR, TYPE_UINT)
	set(CPUI_INT_LEFT, TYPE_INT)
	set(CPUI_INT_RIGHT, TYPE_UINT)
	set(CPUI_INT_SRIGHT, TYPE_INT)
	set(CPUI_INT_MULT, TYPE_INT)
	set(CPUI_INT_DIV, TYPE_UINT)
	set(CPUI_INT_SDIV, TYPE_INT)
	set(CPUI_INT_REM, TYPE_UINT)
	set(CPUI_INT_SREM, TYPE_INT)

	// Boolean
	set(CPUI_BOOL_NEGATE, TYPE_BOOL)
	set(CPUI_BOOL_XOR, TYPE_BOOL)
	set(CPUI_BOOL_AND, TYPE_BOOL)
	set(CPUI_BOOL_OR, TYPE_BOOL)

	// Float
	set(CPUI_FLOAT_EQUAL, TYPE_FLOAT)
	set(CPUI_FLOAT_NOTEQUAL, TYPE_FLOAT)
	set(CPUI_FLOAT_LESS, TYPE_FLOAT)
	set(CPUI_FLOAT_LESSEQUAL, TYPE_FLOAT)
	set(CPUI_FLOAT_NAN, TYPE_FLOAT)
	set(CPUI_FLOAT_ADD, TYPE_FLOAT)
	set(CPUI_FLOAT_DIV, TYPE_FLOAT)
	set(CPUI_FLOAT_MULT, TYPE_FLOAT)
	set(CPUI_FLOAT_SUB, TYPE_FLOAT)
	set(CPUI_FLOAT_NEG, TYPE_FLOAT)
	set(CPUI_FLOAT_ABS, TYPE_FLOAT)
	set(CPUI_FLOAT_SQRT, TYPE_FLOAT)
	set(CPUI_FLOAT_INT2FLOAT, TYPE_INT)
	set(CPUI_FLOAT_FLOAT2FLOAT, TYPE_FLOAT)
	set(CPUI_FLOAT_TRUNC, TYPE_FLOAT)
	set(CPUI_FLOAT_CEIL, TYPE_FLOAT)
	set(CPUI_FLOAT_FLOOR, TYPE_FLOAT)
	set(CPUI_FLOAT_ROUND, TYPE_FLOAT)

	// Composite / bit manipulation
	set(CPUI_INSERT, TYPE_INT)
	set(CPUI_ZPULL, TYPE_INT)
	set(CPUI_SPULL, TYPE_INT)

	// PTRADD/PTRSUB: getInputLocal treats them as INT_ADD for type propagation.
	set(CPUI_PTRADD, TYPE_INT)
	set(CPUI_PTRSUB, TYPE_INT)

	return m
}

// opOutputMeta holds the metaout (output metatype) for each opcode. Mirrors
// opInputMeta but for the output side. C++ parity: the metaout argument of the
// TypeOpBinary/Unary/Func constructors, plus PTRADD/PTRSUB getOutputLocal
// (TYPE_INT). Opcodes deriving directly from TypeOp keep TYPE_UNKNOWN.
var opOutputMeta = buildOpOutputMeta()

func buildOpOutputMeta() []metatype {
	m := make([]metatype, CPUI_MAX+1)
	for i := range m {
		m[i] = TYPE_UNKNOWN
	}
	set := func(op OpCode, meta metatype) { m[op] = meta }

	// Comparisons produce bool.
	set(CPUI_INT_EQUAL, TYPE_BOOL)
	set(CPUI_INT_NOTEQUAL, TYPE_BOOL)
	set(CPUI_INT_SLESS, TYPE_BOOL)
	set(CPUI_INT_SLESSEQUAL, TYPE_BOOL)
	set(CPUI_INT_LESS, TYPE_BOOL)
	set(CPUI_INT_LESSEQUAL, TYPE_BOOL)
	set(CPUI_INT_CARRY, TYPE_BOOL)
	set(CPUI_INT_SCARRY, TYPE_BOOL)
	set(CPUI_INT_SBORROW, TYPE_BOOL)

	// Extension
	set(CPUI_INT_ZEXT, TYPE_UINT)
	set(CPUI_INT_SEXT, TYPE_INT)

	// Integer arithmetic / logical
	set(CPUI_INT_ADD, TYPE_INT)
	set(CPUI_INT_SUB, TYPE_INT)
	set(CPUI_INT_2COMP, TYPE_INT)
	set(CPUI_INT_NEGATE, TYPE_UINT)
	set(CPUI_INT_XOR, TYPE_UINT)
	set(CPUI_INT_AND, TYPE_UINT)
	set(CPUI_INT_OR, TYPE_UINT)
	set(CPUI_INT_LEFT, TYPE_INT)
	set(CPUI_INT_RIGHT, TYPE_UINT)
	set(CPUI_INT_SRIGHT, TYPE_INT)
	set(CPUI_INT_MULT, TYPE_INT)
	set(CPUI_INT_DIV, TYPE_UINT)
	set(CPUI_INT_SDIV, TYPE_INT)
	set(CPUI_INT_REM, TYPE_UINT)
	set(CPUI_INT_SREM, TYPE_INT)

	// Boolean
	set(CPUI_BOOL_NEGATE, TYPE_BOOL)
	set(CPUI_BOOL_XOR, TYPE_BOOL)
	set(CPUI_BOOL_AND, TYPE_BOOL)
	set(CPUI_BOOL_OR, TYPE_BOOL)

	// Float
	set(CPUI_FLOAT_EQUAL, TYPE_BOOL)
	set(CPUI_FLOAT_NOTEQUAL, TYPE_BOOL)
	set(CPUI_FLOAT_LESS, TYPE_BOOL)
	set(CPUI_FLOAT_LESSEQUAL, TYPE_BOOL)
	set(CPUI_FLOAT_NAN, TYPE_BOOL)
	set(CPUI_FLOAT_ADD, TYPE_FLOAT)
	set(CPUI_FLOAT_DIV, TYPE_FLOAT)
	set(CPUI_FLOAT_MULT, TYPE_FLOAT)
	set(CPUI_FLOAT_SUB, TYPE_FLOAT)
	set(CPUI_FLOAT_NEG, TYPE_FLOAT)
	set(CPUI_FLOAT_ABS, TYPE_FLOAT)
	set(CPUI_FLOAT_SQRT, TYPE_FLOAT)
	set(CPUI_FLOAT_INT2FLOAT, TYPE_FLOAT)
	set(CPUI_FLOAT_FLOAT2FLOAT, TYPE_FLOAT)
	set(CPUI_FLOAT_TRUNC, TYPE_INT)
	set(CPUI_FLOAT_CEIL, TYPE_FLOAT)
	set(CPUI_FLOAT_FLOOR, TYPE_FLOAT)
	set(CPUI_FLOAT_ROUND, TYPE_FLOAT)

	// Bit manipulation
	set(CPUI_ZPULL, TYPE_UINT)
	set(CPUI_SPULL, TYPE_INT)
	set(CPUI_POPCOUNT, TYPE_INT)
	set(CPUI_LZCOUNT, TYPE_INT)

	// PTRADD/PTRSUB getOutputLocal treat as INT_ADD.
	set(CPUI_PTRADD, TYPE_INT)
	set(CPUI_PTRSUB, TYPE_INT)

	return m
}

// baseForMeta returns the interned Base data-type of the given size and metatype.
// C++ parity: TypeFactory::getBase(size, meta).
func baseForMeta(tf *TypeFactory, size int32, meta metatype) Datatype {
	if size <= 0 {
		return nil
	}
	name := "unknown"
	switch meta {
	case TYPE_INT:
		name = "int"
	case TYPE_UINT:
		name = "uint"
	case TYPE_BOOL:
		name = "bool"
	case TYPE_FLOAT:
		name = "float"
	case TYPE_UNKNOWN:
		name = "unknown"
	}
	return tf.GetBase(size, meta, name)
}

// InputTypeLocal returns the data-type the opcode expects at input slot, as a C
// compiler parsing the grammar would assign. C++ parity: PcodeOp::inputTypeLocal
// -> TypeOp::getInputLocal (default TYPE_UNKNOWN) and the TypeOpBinary/Unary/Func
// overrides (getBase(insize, metain)).
func (t *typeOpBase) InputTypeLocal(op *PcodeOp, slot int, tf *TypeFactory) Datatype {
	if op == nil || slot < 0 || slot >= op.NumInput() || op.Input(slot) == nil {
		return nil
	}
	return baseForMeta(tf, op.Input(slot).Size(), opInputMeta[t.opcode])
}

// GetInputCast returns the data-type the input at slot must be cast to, or nil if
// the actual input Varnode does not need a cast. C++ parity: TypeOp::getInputCast
// (typeop.cc 296-304): castStandard(inputTypeLocal(slot), vn.readFacing, false, true).
func (t *typeOpBase) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	return baseGetInputCast(t, op, slot, cs)
}

// baseGetInputCast is the shared default getInputCast implementation, reused by
// overrides that fall through to the base behavior (PTRADD/PTRSUB non-zero slots).
func baseGetInputCast(t TypeOp, op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if op == nil || slot < 0 || slot >= op.NumInput() {
		return nil
	}
	vn := op.Input(slot)
	if vn == nil {
		return nil
	}
	reqtype := t.InputTypeLocal(op, slot, cs.tlst)
	curtype := vn.TypeReadFacing(op)
	return cs.CastStandard(reqtype, curtype, false, true)
}

// OutputTypeLocal returns the data-type the op naturally produces, as a C
// compiler parsing the grammar would assign. C++ parity: PcodeOp::outputTypeLocal
// -> TypeOp::getOutputLocal (default TYPE_UNKNOWN; binary/unary/func override to
// getBase(outsize, metaout)).
func (t *typeOpBase) OutputTypeLocal(op *PcodeOp, tf *TypeFactory) Datatype {
	if op == nil || op.Output() == nil {
		return nil
	}
	return baseForMeta(tf, op.Output().Size(), opOutputMeta[t.opcode])
}

// GetOutputToken returns the data-type a C compiler would assign to the op's
// output expression, used to decide whether an output cast is needed.
// C++ parity: TypeOp::getOutputToken (default = outputTypeLocal).
func (t *typeOpBase) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	return t.OutputTypeLocal(op, cs.tlst)
}

// COPY output token is the type read from input 0. C++: TypeOpCopy::getOutputToken.
func (t *typeOpCopy) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return nil
	}
	return op.Input(0).TypeReadFacing(op)
}

// LOAD output token: the pointee of the address pointer if it matches the output
// size, otherwise the output's own type (a cast is then assumed).
// C++ parity: TypeOpLoad::getOutputToken (typeop.cc 473-486).
func (t *typeOpLoad) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() < 2 || op.Output() == nil || op.Input(1) == nil {
		return nil
	}
	ct := op.Input(1).TypeReadFacing(op)
	if ptr, ok := ct.(*Pointer); ok && ptr.Pointee() != nil && ptr.Pointee().Size() == op.Output().Size() {
		return ptr.Pointee()
	}
	return op.Output().TypeDefFacing()
}

// INT_ADD output token uses the arithmetic typing rules. C++ parity:
// TypeOpIntAdd::getOutputToken -> arithmeticOutputStandard.
func (t *typeOpIntAdd) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	return cs.arithmeticOutputStandard(op)
}

// PTRADD output token is the input-0 pointer type (the op casts to it).
// C++ parity: TypeOpPtradd::getOutputToken (typeop.cc 2246-2250).
func (t *typeOpPtradd) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return nil
	}
	return op.Input(0).TypeReadFacing(op)
}

// PTRSUB output token in C++ walks the pointed-to structure (TypePointer::downChain)
// to find the sub-field type. downChain is not yet ported, so we fall back to the
// base output-local type. TODO: port downChain for struct-field PTRSUB output casts.
// C++ parity: TypeOpPtrsub::getOutputToken (typeop.cc 2351-2366).

// SUBPIECE output token in C++ uses findTruncation for composite fields, else the
// output's own type (or int when unknown). It is registered as a plain typeOpBase
// in Gosleigh, so it currently uses the base UNKNOWN token. TODO: give SUBPIECE a
// dedicated TypeOp with the (int)-truncation token once findTruncation lands; until
// then the render-time isSubpieceCast path produces the (int) cast.

// ---------------------------------------------------------------------------
// Per-opcode getInputCast overrides.
// ---------------------------------------------------------------------------

// COPY: input must match the output type. C++ parity: TypeOpCopy::getInputCast.
func (t *typeOpCopy) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if op == nil || op.Output() == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return nil
	}
	reqtype := op.Output().TypeDefFacing()
	curtype := op.Input(0).TypeReadFacing(op)
	return cs.CastStandard(reqtype, curtype, false, true)
}

// LOAD: only the pointer input (slot 1) can require a cast; the pointer is cast
// so its pointee matches the LOAD output. C++ parity: TypeOpLoad::getInputCast
// (typeop.cc 441-471).
func (t *typeOpLoad) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if slot != 1 || op == nil || op.Output() == nil || op.NumInput() < 2 {
		return nil
	}
	reqtype := op.Output().TypeDefFacing()
	invn := op.Input(1)
	if invn == nil {
		return nil
	}
	curtype := invn.TypeReadFacing(op)
	spc := op.Input(0).GetSpaceFromConst()
	wordSize := uint32(1)
	if spc != nil {
		wordSize = uint32(spc.WordSize)
	}
	// The input may not actually be a pointer to the output type (or a pointer
	// at all) due to cycle trimming in type propagation.
	if curPtr, ok := curtype.(*Pointer); ok {
		curtype = curPtr.Pointee()
	} else {
		return cs.tlst.GetPointer(invn.Size(), reqtype, wordSize)
	}
	if curtype != reqtype && curtype.Size() == reqtype.Size() {
		// Non-standard in=ptr-to-a out=b (a!=b): prefer casting AFTER the load
		// unless the input is itself a CAST to the wrong type.
		curmeta := curtype.Metatype()
		if curmeta != TYPE_STRUCT && curmeta != TYPE_ARRAY && curmeta != TYPE_SPACEBASE && curmeta != TYPE_UNION {
			if !invn.IsImplied() || !invn.IsWritten() || invn.Def() == nil || invn.Def().Code() != CPUI_CAST {
				return nil // postpone cast to output
			}
			// else fall through: the input is a CAST to the wrong type, recast.
		}
	}
	req := cs.CastStandard(reqtype, curtype, false, true)
	if req == nil {
		return nil
	}
	return cs.tlst.GetPointer(invn.Size(), req, wordSize)
}

// STORE: slot 0 (space id) never casts. The pointer (slot 1) or the value
// (slot 2) may be cast so the pointee matches the stored value.
// C++ parity: TypeOpStore::getInputCast (typeop.cc 521-557).
func (t *typeOpStore) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if slot == 0 || op == nil || op.NumInput() < 3 {
		return nil
	}
	pointerVn := op.Input(1)
	valueVn := op.Input(2)
	if pointerVn == nil || valueVn == nil {
		return nil
	}
	pointerType := pointerVn.TypeReadFacing(op)
	pointedToType := pointerType
	valueType := valueVn.TypeReadFacing(op)
	spc := op.Input(0).GetSpaceFromConst()
	wordSize := uint32(1)
	if spc != nil {
		wordSize = uint32(spc.WordSize)
	}
	destSize := int32(-1)
	if ptr, ok := pointerType.(*Pointer); ok {
		pointedToType = ptr.Pointee()
		destSize = pointedToType.Size()
	}
	if destSize != valueType.Size() {
		if slot == 1 {
			return cs.tlst.GetPointer(pointerVn.Size(), valueType, wordSize)
		}
		return nil
	}
	if slot == 1 {
		if pointerVn.IsWritten() && pointerVn.Def() != nil && pointerVn.Def().Code() == CPUI_CAST {
			if pointerVn.IsImplied() && pointerVn.LoneDescend() == op {
				newType := cs.tlst.GetPointer(pointerVn.Size(), valueType, wordSize)
				if pointerType != Datatype(newType) {
					return newType
				}
			}
		}
		return nil
	}
	// slot == 2: cast the value, not the pointer.
	return cs.CastStandard(pointedToType, valueType, false, true)
}

// SUBPIECE never needs a cast into it (C++ TypeOpSubpiece::getInputCast returns
// null). Gosleigh registers SUBPIECE as a plain typeOpBase, and its metain is
// TYPE_UNKNOWN, so baseGetInputCast -> CastStandard(unknown, cur, ...) already
// yields nil for the normal same-size input. No dedicated override is needed.

// Comparison getInputCast. typeOpIntCmp backs INT_EQUAL/NOTEQUAL (signed-agnostic,
// pick the more specific operand type) and the ordered comparisons (use the local
// input type). Dispatch on opcode mirrors the distinct C++ overrides.
// C++ parity: TypeOpEqual/NotEqual::getInputCast (934-945, 998-1009) and
// TypeOpIntSless/SlessEqual/Less/LessEqual::getInputCast (1025-1109).
func (t *typeOpIntCmp) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() < 2 || slot < 0 || slot >= op.NumInput() {
		return nil
	}
	switch t.opcode {
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
		// reqtype is the more specific of the two operand types. Gosleigh does not
		// yet model Datatype::typeOrder, so we keep input[0]'s type as the
		// requirement (the common case where both operands share a metatype).
		// TODO: port typeOrder to pick the strictly more specified side.
		reqtype := op.Input(0).TypeReadFacing(op)
		if cs.checkIntPromotionForCompare(op, slot) {
			return reqtype
		}
		othertype := op.Input(slot).TypeReadFacing(op)
		return cs.CastStandard(reqtype, othertype, false, false)
	case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL:
		reqtype := t.InputTypeLocal(op, slot, cs.tlst)
		if cs.checkIntPromotionForCompare(op, slot) {
			return reqtype
		}
		curtype := op.Input(slot).TypeReadFacing(op)
		return cs.castStandardRead(reqtype, curtype, true, true)
	case CPUI_INT_LESS, CPUI_INT_LESSEQUAL:
		reqtype := t.InputTypeLocal(op, slot, cs.tlst)
		if cs.checkIntPromotionForCompare(op, slot) {
			return reqtype
		}
		curtype := op.Input(slot).TypeReadFacing(op)
		return cs.castStandardRead(reqtype, curtype, true, false)
	default:
		// Float comparisons and others fall back to the base behavior.
		return baseGetInputCast(t, op, slot, cs)
	}
}

// INT_ZEXT getInputCast: cast the input unless the natural integer promotion
// already zero-extends. C++ parity: TypeOpIntZext::getInputCast (1133-1141).
func (t *typeOpZext) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() == 0 || op.Input(slot) == nil {
		return nil
	}
	reqtype := t.InputTypeLocal(op, slot, cs.tlst)
	if cs.checkIntPromotionForExtension(op) {
		return reqtype
	}
	curtype := op.Input(slot).TypeReadFacing(op)
	return cs.castStandardRead(reqtype, curtype, true, false)
}

// INT_SEXT getInputCast: cast the input unless the natural integer promotion
// already sign-extends. C++ parity: TypeOpIntSext::getInputCast (1159-1167).
func (t *typeOpSext) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if op == nil || op.NumInput() == 0 || op.Input(slot) == nil {
		return nil
	}
	reqtype := t.InputTypeLocal(op, slot, cs.tlst)
	if cs.checkIntPromotionForExtension(op) {
		return reqtype
	}
	curtype := op.Input(slot).TypeReadFacing(op)
	return cs.castStandardRead(reqtype, curtype, true, false)
}

// INT_RIGHT / INT_SRIGHT getInputCast: the shifted value (slot 0) must carry the
// op's signedness. Unlike the base getInputCast (careUintInt=false), these use
// careUintInt=true so a uint operand under an arithmetic shift -- or an int
// operand under a logical shift -- is cast. The shift-amount operand (slot 1)
// falls through to the base. C++ parity: typeop.cc TypeOpIntRight::getInputCast
// (1545-1558, wantExt=UNSIGNED) / TypeOpIntSright::getInputCast (1587-1600,
// wantExt=SIGNED).
func (t *typeOpIntRight) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	return shiftValueInputCast(t, op, slot, cs, unsignedExtension)
}

func (t *typeOpIntSright) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	return shiftValueInputCast(t, op, slot, cs, signedExtension)
}

// shiftValueInputCast is the shared slot-0 cast test for INT_RIGHT/INT_SRIGHT.
// wantExt is the promotion the op's signedness already provides (unsigned for
// logical, signed for arithmetic); when the natural promotion of the operand
// does not include it, a cast to the required signed/unsigned type is forced.
func shiftValueInputCast(t TypeOp, op *PcodeOp, slot int, cs *CastStrategyC, wantExt int) Datatype {
	if slot != 0 || op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return baseGetInputCast(t, op, slot, cs)
	}
	vn := op.Input(0)
	reqtype := t.InputTypeLocal(op, 0, cs.tlst)
	promoType := cs.intPromotionType(vn)
	if promoType != noPromotion && (promoType&wantExt) == 0 {
		return reqtype
	}
	curtype := vn.TypeReadFacing(op)
	return cs.castStandardRead(reqtype, curtype, true, true)
}

// PTRADD/PTRSUB slot-0 getInputCast in C++ compares the varnode's own type
// (getTypeReadFacing) against its HighVariable type (getHighTypeReadFacing). In
// Gosleigh those collapse to vn.TypeReadFacing(op), so the slot-0 cast test is
// always "no cast". Non-zero slots fall through to the base behavior (the index
// operands, treated as INT via opInputMeta). C++ parity: TypeOpPtradd::getInputCast
// (2252-2268) / TypeOpPtrsub::getInputCast (2322-2349).
func (t *typeOpPtradd) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if slot == 0 {
		return nil
	}
	return baseGetInputCast(t, op, slot, cs)
}

func (t *typeOpPtrsub) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	if slot == 0 {
		return nil
	}
	return baseGetInputCast(t, op, slot, cs)
}
