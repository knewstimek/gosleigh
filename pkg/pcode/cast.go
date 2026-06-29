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

// cast.go -- C-language cast strategy. Decides whether an explicit cast is
// needed between two data-types when rendering / inserting casts.
// C++ parity: cast.hh / cast.cc CastStrategy, CastStrategyC.
//
// This is the keystone primitive for ActionSetCasts, which is now live
// (apply/castInput/castOutput insert CPUI_CAST ops; see action_deadcode.go).
// CastStandard / IsSubpieceCast / IsSextCast / IsZextCast / arithmeticOutputStandard
// are ported; markExplicitUnsigned / LongSize and union resolution remain future work.

// sharedCastStrategyC is the process-wide C cast strategy used by ActionSetCasts
// (castInput/castOutput) to decide where to insert CPUI_CAST ops. It is backed by
// sharedTypeFactory.
var sharedCastStrategyC = NewCastStrategyC(sharedTypeFactory)

// Integer-promotion codes returned by intPromotionType / localExtensionType.
// C++ parity: cast.hh CastStrategyC IntPromotionCode enum.
const (
	noPromotion       = -1 // there is no integer promotion
	unknownPromotion  = 0  // the type of integer promotion cannot be determined
	unsignedExtension = 1  // the value is promoted using unsigned extension
	signedExtension   = 2  // the value is promoted using signed extension
	eitherExtension   = 3  // promoted using either signed or unsigned extension
)

// CastStrategyC implements the C-language casting rules.
// C++ parity: cast.hh CastStrategyC.
type CastStrategyC struct {
	tlst *TypeFactory
	// promoteSize is the size of the C "int" type: the width integers get
	// promoted to. C++ parity: CastStrategy::promoteSize (set by setTypeFactory).
	promoteSize int32
}

// NewCastStrategyC creates a C cast strategy backed by the given type factory.
func NewCastStrategyC(tf *TypeFactory) *CastStrategyC {
	return &CastStrategyC{tlst: tf, promoteSize: 4}
}

// signbitNegative reports whether the high (sign) bit of an unsigned value of
// the given byte size is set. C++ parity: signbit_negative (in address.hh).
func signbitNegative(val uint64, size int32) bool {
	if size <= 0 || size > 8 {
		return false
	}
	mask := uint64(1) << (uint(size)*8 - 1)
	return val&mask != 0
}

// localExtensionType determines how the value in vn is naturally extended when
// promoted to int, for the purpose of deciding whether an explicit
// extension/comparison needs a cast.
// C++ parity: cast.cc CastStrategyC::localExtensionType (140-176).
//
// Simplification vs C++: Gosleigh has no HighVariable, so getHighTypeReadFacing
// collapses to vn.TypeReadFacing(op).
func (cs *CastStrategyC) localExtensionType(vn *Varnode, op *PcodeOp) int {
	if vn == nil {
		return unknownPromotion
	}
	rt := vn.TypeReadFacing(op)
	if rt == nil {
		return unknownPromotion
	}
	meta := rt.Metatype()
	var natural int
	switch meta {
	case TYPE_UINT, TYPE_BOOL, TYPE_UNKNOWN, TYPE_PARTIALSTRUCT, TYPE_PARTIALUNION:
		natural = unsignedExtension
	case TYPE_INT:
		natural = signedExtension
	default:
		return unknownPromotion
	}
	if vn.IsConstant() {
		if !signbitNegative(vn.Offset(), vn.Size()) { // high-bit zero -> either extension
			return eitherExtension
		}
		return natural
	}
	if vn.IsExplicit() {
		return natural
	}
	if !vn.IsWritten() {
		return unknownPromotion
	}
	defOp := vn.Def()
	if defOp == nil {
		return unknownPromotion
	}
	if defOp.IsBoolOutput() {
		return eitherExtension
	}
	opc := defOp.Code()
	if opc == CPUI_CAST || opc == CPUI_LOAD || defOp.IsCall() {
		return natural
	}
	if opc == CPUI_INT_AND {
		tmpvn := defOp.Input(1)
		if tmpvn != nil && tmpvn.IsConstant() {
			if !signbitNegative(tmpvn.Offset(), tmpvn.Size()) {
				return eitherExtension
			}
			return natural
		}
	}
	return unknownPromotion
}

// intPromotionType classifies the integer promotion that the value held by vn
// undergoes. C++ parity: cast.cc CastStrategyC::intPromotionType (178-247).
func (cs *CastStrategyC) intPromotionType(vn *Varnode) int {
	if vn == nil {
		return unknownPromotion
	}
	if vn.Size() >= cs.promoteSize {
		return noPromotion
	}
	if vn.IsConstant() {
		return cs.localExtensionType(vn, vn.LoneDescend())
	}
	if vn.IsExplicit() {
		return noPromotion
	}
	if !vn.IsWritten() {
		return unknownPromotion
	}
	op := vn.Def()
	if op == nil {
		return unknownPromotion
	}
	switch op.Code() {
	case CPUI_INT_AND:
		if (cs.localExtensionType(op.Input(1), op) & unsignedExtension) != 0 {
			return unsignedExtension
		}
		if (cs.localExtensionType(op.Input(0), op) & unsignedExtension) != 0 {
			return unsignedExtension
		}
	case CPUI_INT_RIGHT:
		val := cs.localExtensionType(op.Input(0), op)
		if (val & unsignedExtension) != 0 {
			return val
		}
	case CPUI_INT_SRIGHT:
		val := cs.localExtensionType(op.Input(0), op)
		if (val & signedExtension) != 0 {
			return val
		}
	case CPUI_INT_XOR, CPUI_INT_OR, CPUI_INT_DIV, CPUI_INT_REM:
		if (cs.localExtensionType(op.Input(0), op) & unsignedExtension) == 0 {
			return unknownPromotion
		}
		if (cs.localExtensionType(op.Input(1), op) & unsignedExtension) == 0 {
			return unknownPromotion
		}
		return unsignedExtension
	case CPUI_INT_SDIV, CPUI_INT_SREM:
		if (cs.localExtensionType(op.Input(0), op) & signedExtension) == 0 {
			return unknownPromotion
		}
		if (cs.localExtensionType(op.Input(1), op) & signedExtension) == 0 {
			return unknownPromotion
		}
		return signedExtension
	case CPUI_INT_NEGATE, CPUI_INT_2COMP:
		if (cs.localExtensionType(op.Input(0), op) & signedExtension) != 0 {
			return signedExtension
		}
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_LEFT, CPUI_INT_MULT:
		// fallthrough to unknownPromotion below
	default:
		return noPromotion
	}
	return unknownPromotion
}

// checkIntPromotionForCompare reports whether the input at slot needs a cast
// because of mismatched integer promotion across a comparison operator.
// C++ parity: cast.cc CastStrategyC::checkIntPromotionForCompare (107-124).
func (cs *CastStrategyC) checkIntPromotionForCompare(op *PcodeOp, slot int) bool {
	exttype1 := cs.intPromotionType(op.Input(slot))
	if exttype1 == noPromotion {
		return false
	}
	if exttype1 == unknownPromotion {
		return true
	}
	exttype2 := cs.intPromotionType(op.Input(1 - slot))
	if (exttype1 & exttype2) != 0 {
		return false
	}
	if exttype2 == noPromotion {
		return false
	}
	return true
}

// checkIntPromotionForExtension reports whether the input to an INT_ZEXT/INT_SEXT
// needs a cast because the natural integer promotion differs from the explicit
// extension. C++ parity: cast.cc CastStrategyC::checkIntPromotionForExtension (126-138).
func (cs *CastStrategyC) checkIntPromotionForExtension(op *PcodeOp) bool {
	exttype := cs.intPromotionType(op.Input(0))
	if exttype == noPromotion {
		return false
	}
	if exttype == unknownPromotion {
		return true
	}
	if (exttype&unsignedExtension) != 0 && op.Code() == CPUI_INT_ZEXT {
		return false
	}
	if (exttype&signedExtension) != 0 && op.Code() == CPUI_INT_SEXT {
		return false
	}
	return true
}

// castStandardRead is CastStandard for the care_uint_int=true contexts (signed
// and ordered comparisons, integer extensions). Gosleigh has no read-facing
// HighVariable types, so an operand whose stored type is TYPE_UNKNOWN (e.g. an
// undefined4 local) would be spuriously cast to int here. In Ghidra the
// read-facing type of such an operand of a signed/ordered op is already int
// (the op carries inherits_sign), so no cast is emitted. We model that gap by
// suppressing the cast when curtype is undefined.
//
// C++ parity note: this compensates for the missing read-facing/def-facing type
// distinction; the underlying castStandard call is otherwise faithful.
func (cs *CastStrategyC) castStandardRead(reqtype, curtype Datatype, careUintInt, carePtrUint bool) Datatype {
	if curtype != nil && curtype.Metatype() == TYPE_UNKNOWN {
		return nil
	}
	return cs.CastStandard(reqtype, curtype, careUintInt, carePtrUint)
}

// arithmeticOutputStandard returns the data-type an arithmetic op (INT_ADD etc.)
// produces, following the C arithmetic typing rules: the most specific of the
// input read-facing types, treating bool as int.
// C++ parity: cast.cc CastStrategyC::arithmeticOutputStandard (394-409).
//
// Simplification vs C++: Datatype::typeOrder is not ported, so the "most
// specific" selection keeps input[0]'s type rather than scanning for a strictly
// more specified operand. The bool->int promotion of input[0] is preserved.
func (cs *CastStrategyC) arithmeticOutputStandard(op *PcodeOp) Datatype {
	if op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return nil
	}
	res1 := op.Input(0).TypeReadFacing(op)
	if res1 != nil && res1.Metatype() == TYPE_BOOL {
		res1 = baseForMeta(cs.tlst, res1.Size(), TYPE_INT)
	}
	return res1
}

// CastStandard returns the data-type to cast to when an expression of type
// curtype is used where reqtype is required, or nil when no cast is needed.
//
// careUintInt: when false, signed/unsigned integers of equal size do not need a
// cast (the token's signedness is treated as irrelevant). carePtrUint: when
// false, a pointer used where an unsigned integer is required needs no cast.
//
// C++ parity: cast.cc CastStrategyC::castStandard (lines 300-392).
//
// Simplifications vs C++ (documented Gosleigh type-system gaps):
//   - typedef resolution (getTypedef loop) is skipped: typedefs are not modelled.
//   - variable-length / hasSameVariableBase short-circuit is skipped.
//   - pointer address-space comparison is skipped: *Pointer carries no AddrSpace.
//   - TypeCode prototype comparison is skipped: two CODE types of equal size are
//     treated as not needing a cast.
func (cs *CastStrategyC) CastStandard(reqtype, curtype Datatype, careUintInt, carePtrUint bool) Datatype {
	if reqtype == nil || curtype == nil {
		return nil
	}
	if curtype == reqtype {
		return nil // types are equal, no cast required
	}
	if curtype.Metatype() == TYPE_VOID {
		return reqtype // coming from "void" (a dereferenced void*) needs a cast
	}

	reqbase := reqtype
	curbase := curtype
	isptr := false
	for reqbase.Metatype() == TYPE_PTR && curbase.Metatype() == TYPE_PTR {
		reqptr, ok1 := reqbase.(*Pointer)
		curptr, ok2 := curbase.(*Pointer)
		if !ok1 || !ok2 {
			break
		}
		if reqptr.WordSize() != curptr.WordSize() {
			return reqtype
		}
		// Address-space comparison omitted: Gosleigh *Pointer has no AddrSpace.
		reqbase = reqptr.Pointee()
		curbase = curptr.Pointee()
		careUintInt = true
		isptr = true
		if reqbase == nil || curbase == nil {
			return reqtype
		}
	}

	if curbase == reqbase {
		return nil // same underlying type
	}
	if reqbase.Metatype() == TYPE_VOID || curbase.Metatype() == TYPE_VOID {
		return nil // don't cast to or from a void pointer
	}
	if reqbase.Size() != curbase.Size() {
		return reqtype // always cast on a change in size
	}

	switch reqbase.Metatype() {
	case TYPE_UNKNOWN, TYPE_PARTIALSTRUCT, TYPE_PARTIALUNION:
		// Ultimately stripped; treat as undefined -- no cast.
		return nil
	case TYPE_UINT:
		if !careUintInt {
			meta := curbase.Metatype()
			if meta == TYPE_UNKNOWN || meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_BOOL ||
				meta == TYPE_PARTIALSTRUCT || meta == TYPE_PARTIALUNION {
				return nil
			}
		} else {
			meta := curbase.Metatype()
			if meta == TYPE_UINT || meta == TYPE_BOOL {
				return nil
			}
			if isptr && (meta == TYPE_UNKNOWN || meta == TYPE_PARTIALSTRUCT || meta == TYPE_PARTIALUNION) {
				return nil // don't cast pointers to unknown
			}
		}
		if !carePtrUint && curbase.Metatype() == TYPE_PTR {
			return nil
		}
	case TYPE_INT:
		if !careUintInt {
			meta := curbase.Metatype()
			if meta == TYPE_UNKNOWN || meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_BOOL ||
				meta == TYPE_PARTIALSTRUCT || meta == TYPE_PARTIALUNION {
				return nil
			}
		} else {
			meta := curbase.Metatype()
			if meta == TYPE_INT || meta == TYPE_BOOL {
				return nil
			}
			if isptr && (meta == TYPE_UNKNOWN || meta == TYPE_PARTIALSTRUCT || meta == TYPE_PARTIALUNION) {
				return nil // don't cast pointers to unknown
			}
		}
	case TYPE_CODE:
		if curbase.Metatype() == TYPE_CODE {
			// C++ distinguishes function-pointer vs generic code-pointer by
			// prototype; Gosleigh treats equal-size CODE types as no cast.
			return nil
		}
	}

	return reqtype
}

// IsSubpieceCast reports whether a SUBPIECE of intype into outtype at the given
// byte offset can be rendered as a plain cast rather than an explicit SUBPIECE().
// C++ parity: cast.cc CastStrategyC::isSubpieceCast (411-432).
func (cs *CastStrategyC) IsSubpieceCast(outtype, intype Datatype, offset uint32) bool {
	if outtype == nil || intype == nil {
		return false
	}
	if offset != 0 {
		return false
	}
	inmeta := intype.Metatype()
	if inmeta != TYPE_INT && inmeta != TYPE_UINT && inmeta != TYPE_UNKNOWN && inmeta != TYPE_PTR &&
		inmeta != TYPE_PARTIALSTRUCT && inmeta != TYPE_PARTIALUNION {
		return false
	}
	outmeta := outtype.Metatype()
	if outmeta != TYPE_INT && outmeta != TYPE_UINT && outmeta != TYPE_UNKNOWN &&
		outmeta != TYPE_PTR && outmeta != TYPE_FLOAT {
		return false
	}
	if inmeta == TYPE_PTR {
		if outmeta == TYPE_PTR {
			if outtype.Size() < intype.Size() {
				return true // cast from a far pointer to a near pointer
			}
		}
		if outmeta != TYPE_INT && outmeta != TYPE_UINT {
			return false // other casts don't make sense for pointers
		}
	}
	return true
}

// IsSextCast reports whether an INT_SEXT from intype to outtype can be rendered
// as a plain cast. C++ parity: cast.cc CastStrategyC::isSextCast (443-455).
func (cs *CastStrategyC) IsSextCast(outtype, intype Datatype) bool {
	if outtype == nil || intype == nil {
		return false
	}
	metaout := outtype.Metatype()
	if metaout != TYPE_UINT && metaout != TYPE_INT {
		return false
	}
	// Extension to larger storage follows the input's signedness, so the input
	// must be SIGNED for SEXT to read as a cast.
	metain := intype.Metatype()
	if metain != TYPE_INT && metain != TYPE_BOOL {
		return false
	}
	return true
}

// IsZextCast reports whether an INT_ZEXT from intype to outtype can be rendered
// as a plain cast. C++ parity: cast.cc CastStrategyC::isZextCast (457-469).
func (cs *CastStrategyC) IsZextCast(outtype, intype Datatype) bool {
	if outtype == nil || intype == nil {
		return false
	}
	metaout := outtype.Metatype()
	if metaout != TYPE_UINT && metaout != TYPE_INT {
		return false
	}
	// The input must be UNSIGNED for ZEXT to read as a cast.
	metain := intype.Metatype()
	if metain != TYPE_UINT && metain != TYPE_BOOL {
		return false
	}
	return true
}
