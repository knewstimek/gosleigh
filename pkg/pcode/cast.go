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
// This is the keystone primitive for ActionSetCasts (currently a no-op stub).
// Only CastStandard is ported so far; the remaining strategy methods
// (markExplicitUnsigned, arithmeticOutputStandard, isSubpieceCast, ...) and the
// ActionSetCasts apply/castInput/castOutput driver remain future work.

// sharedCastStrategyC is the process-wide C cast strategy used by render-time
// cast decisions (printc.go assignCastStr). It is backed by sharedTypeFactory.
var sharedCastStrategyC = NewCastStrategyC(sharedTypeFactory)

// CastStrategyC implements the C-language casting rules.
// C++ parity: cast.hh CastStrategyC.
type CastStrategyC struct {
	tlst *TypeFactory
}

// NewCastStrategyC creates a C cast strategy backed by the given type factory.
func NewCastStrategyC(tf *TypeFactory) *CastStrategyC {
	return &CastStrategyC{tlst: tf}
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
