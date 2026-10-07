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
	"strconv"
	"strings"

	"gosleigh/pkg/address"
)

// assignResponse is the outcome of assigning storage to one parameter.
// C++ parity: AssignAction response codes (modelrules.hh).
type assignResponse int

const (
	assignSuccess assignResponse = iota
	assignFail
	assignNoAssignment
	assignHiddenretPtrparam
	assignHiddenretSpecialreg
	assignHiddenretSpecialregVoid
)

// ParameterPieces flags. C++ parity: ParameterPieces::indirectstorage,
// ParameterPieces::hiddenretparm.
const (
	pieceIndirectStorage uint32 = 1 << iota
	pieceHiddenRetParm
)

// parameterPieces is the storage and data-type given to one parameter or the
// return value. C++ parity: ParameterPieces.
type parameterPieces struct {
	addr  address.Address
	typ   Datatype
	flags uint32
}

// modelRuleAction is the AssignAction a rule applies.
type modelRuleAction int

const (
	actionConvertToPointer modelRuleAction = iota
	actionHiddenReturn
)

// modelRule is one <rule> of a parameter list: a data-type filter and the
// action taken for a data-type that passes it.
// C++ parity: ModelRule with a SizeRestrictedFilter/MetaTypeFilter and a
// ConvertToPointer or HiddenReturnAssign action.
type modelRule struct {
	anyMeta          bool     // "any": SizeRestrictedFilter without a metatype
	meta             metatype // MetaTypeFilter's metatype
	minSize, maxSize int32
	sizes            map[int32]bool
	action           modelRuleAction
	retCode          assignResponse // HiddenReturnAssign's response
}

// newSizeFilter applies SizeRestrictedFilter's "no maxsize means unbounded".
// C++ parity: SizeRestrictedFilter::SizeRestrictedFilter / decode.
func newSizeFilter(r *modelRule) {
	if r.maxSize == 0 && r.minSize >= 0 {
		r.maxSize = 0x7fffffff
	}
}

// filter reports whether dt passes the rule's data-type filter.
// C++ parity: MetaTypeFilter::filter / SizeRestrictedFilter::filterOnSize.
func (r *modelRule) filter(dt Datatype) bool {
	if !r.anyMeta && dt.Metatype() != r.meta {
		return false
	}
	if r.maxSize == 0 {
		return true
	}
	if len(r.sizes) != 0 {
		return r.sizes[dt.Size()]
	}
	return dt.Size() >= r.minSize && dt.Size() <= r.maxSize
}

// assignAddress applies the rule. C++ parity: ModelRule::assignAddress (no
// qualifiers, preconditions or side-effects in the supported rules).
func (r *modelRule) assignAddress(pl *ParamListStandard, dt Datatype, pos int, status []int32, res *parameterPieces) assignResponse {
	if !r.filter(dt) {
		return assignFail
	}
	tmpStatus := append([]int32(nil), status...)
	var response assignResponse
	switch r.action {
	case actionConvertToPointer:
		// C++ parity: ConvertToPointer::assignAddress.
		pointertp := sharedTypeFactory.GetPointer(pl.pointerSize, dt, 1)
		response = pl.assignAddress(pointertp, pos, tmpStatus, res)
		res.flags = pieceIndirectStorage
	case actionHiddenReturn:
		response = r.retCode // C++ parity: HiddenReturnAssign::assignAddress
	}
	if response != assignFail {
		copy(status, tmpStatus)
	}
	return response
}

// CspecRuleSpec is a decoded <rule> element of a cspec parameter list.
type CspecRuleSpec struct {
	TypeName     string // <datatype name=...>
	MinSize      int32
	MaxSize      int32
	Sizes        string
	ConvertToPtr bool
	HiddenReturn bool
	VoidLock     bool   // <hidden_return voidlock="true">
	Strategy     string // <hidden_return strategy=...>
	// Unsupported names the first element no Go AssignAction or filter
	// covers (qualifiers, join, goto_stack, ...); such a rule is dropped.
	Unsupported string
}

// metatypeFromString is string2metatype. C++ parity: type.cc string2metatype.
func metatypeFromString(s string) (metatype, bool) {
	m, ok := map[string]metatype{
		"code": TYPE_CODE, "void": TYPE_VOID, "union": TYPE_UNION, "struct": TYPE_STRUCT,
		"partunion": TYPE_PARTIALUNION, "partstruct": TYPE_PARTIALSTRUCT, "array": TYPE_ARRAY,
		"ptrrel": TYPE_PTRREL, "ptr": TYPE_PTR, "float": TYPE_FLOAT, "spacebase": TYPE_SPACEBASE,
		"unknown": TYPE_UNKNOWN, "uint": TYPE_UINT, "int": TYPE_INT, "bool": TYPE_BOOL,
		"enum_int": TYPE_ENUM_INT, "enum_uint": TYPE_ENUM_UINT,
	}[s]
	return m, ok
}

// SetModelRules installs the list's <rule> elements and, when pointermax is
// set, the trailing rule converting larger data-types to pointers.
// Known mismatch: rules using a qualifier, homogeneous-float-aggregate or an
// action other than convert_to_ptr/hidden_return (gcc/swift x86-64 models)
// are not ported and are dropped.
// C++ parity: ParamListStandard::decode (ModelRule::decode, pointermax rule).
func (pl *ParamListStandard) SetModelRules(rules []CspecRuleSpec, pointerMax int32, pointerSize int32) {
	pl.pointerSize = pointerSize
	pl.modelRules = nil
	for _, rs := range rules {
		if rs.Unsupported != "" {
			continue
		}
		r := modelRule{minSize: rs.MinSize, maxSize: rs.MaxSize}
		switch rs.TypeName {
		case "any":
			r.anyMeta = true
		case "homogeneous-float-aggregate":
			continue
		default:
			m, ok := metatypeFromString(rs.TypeName)
			if !ok {
				continue
			}
			r.meta = m
		}
		if rs.Sizes != "" {
			r.sizes = map[int32]bool{}
			for _, f := range strings.FieldsFunc(rs.Sizes, func(c rune) bool { return c == ',' || c == ' ' }) {
				v, err := strconv.Atoi(f)
				if err != nil || v <= 0 {
					continue
				}
				r.sizes[int32(v)] = true
				if r.minSize == 0 || int32(v) < r.minSize {
					r.minSize = int32(v)
				}
				if int32(v) > r.maxSize {
					r.maxSize = int32(v)
				}
			}
		}
		newSizeFilter(&r)
		switch {
		case rs.ConvertToPtr:
			r.action = actionConvertToPointer
		case rs.HiddenReturn:
			r.action = actionHiddenReturn
			r.retCode = assignHiddenretSpecialreg
			if rs.VoidLock {
				r.retCode = assignHiddenretSpecialregVoid
			}
			switch rs.Strategy {
			case "normalparam":
				r.retCode = assignHiddenretPtrparam
			case "special":
				r.retCode = assignHiddenretSpecialreg
			}
		default:
			continue
		}
		pl.modelRules = append(pl.modelRules, r)
	}
	if pointerMax > 0 {
		r := modelRule{anyMeta: true, minSize: pointerMax + 1, action: actionConvertToPointer}
		newSizeFilter(&r)
		pl.modelRules = append(pl.modelRules, r)
	}
}

// assignAddress tries every model rule, then the fallback assignment.
// C++ parity: ParamListStandard::assignAddress.
func (pl *ParamListStandard) assignAddress(dt Datatype, pos int, status []int32, res *parameterPieces) assignResponse {
	for i := range pl.modelRules {
		if code := pl.modelRules[i].assignAddress(pl, dt, pos, status, res); code != assignFail {
			return code
		}
	}
	return pl.assignAddressFallbackPiece(metatypeTypeClass(dt.Metatype()), dt, status, res)
}

func (pl *ParamListStandard) assignAddressFallbackPiece(resource typeClass, dt Datatype, status []int32, res *parameterPieces) assignResponse {
	addr, ok := pl.assignAddressFallback(resource, dt, status)
	if !ok {
		return assignFail
	}
	res.addr, res.typ, res.flags = addr, dt, 0
	return assignSuccess
}

// assignOutput gives the return value its storage, switching to a hidden
// pointer when it cannot be returned directly. The second piece, when
// present, is the hidden input pointer still to be placed by assignInputs.
// C++ parity: ParamListStandardOut::assignMap.
func (pl *ParamListStandard) assignOutput(outtype Datatype) ([]parameterPieces, bool) {
	status := make([]int32, pl.numgroup)
	res := []parameterPieces{{}}
	if outtype.Metatype() == TYPE_VOID {
		res[0].typ = outtype
		return res, true // Leave the address invalid
	}
	code := pl.assignAddress(outtype, -1, status, &res[0])
	if code == assignFail {
		code = assignHiddenretPtrparam // Default hidden return input assignment
	}
	if code == assignHiddenretPtrparam || code == assignHiddenretSpecialreg || code == assignHiddenretSpecialregVoid {
		pointertp := sharedTypeFactory.GetPointer(pl.pointerSize, outtype, 1)
		if code == assignHiddenretSpecialregVoid {
			res[0].typ = sharedTypeFactory.GetVoid()
		} else {
			res[0].typ = pointertp
			if pl.assignAddress(pointertp, -1, status, &res[0]) == assignFail {
				return nil, false // Cannot assign return value as a pointer
			}
		}
		res[0].flags = pieceIndirectStorage
		hidden := parameterPieces{typ: pointertp}
		if code != assignHiddenretPtrparam {
			hidden.flags = pieceHiddenRetParm
		}
		res = append(res, hidden)
	}
	return res, true
}

// assignInputs places the hidden return pointer (if res holds one) and then
// every input type. C++ parity: ParamListStandard::assignMap.
func (pl *ParamListStandard) assignInputs(intypes []Datatype, res []parameterPieces) ([]parameterPieces, bool) {
	status := make([]int32, pl.numgroup)
	if len(res) == 2 {
		last := &res[1]
		if last.flags&pieceHiddenRetParm != 0 {
			if pl.assignAddressFallbackPiece(typeclassHiddenret, last.typ, status, last) == assignFail {
				return nil, false
			}
		} else if pl.assignAddress(last.typ, 0, status, last) == assignFail {
			return nil, false
		}
		last.flags |= pieceHiddenRetParm
	}
	for i, dt := range intypes {
		var p parameterPieces
		code := pl.assignAddress(dt, i, status, &p)
		if code == assignFail || code == assignNoAssignment {
			return nil, false // ParamUnassignedError
		}
		res = append(res, p)
	}
	return res, true
}

// assignParameterStorage assigns storage to the return value and all inputs.
// An output that cannot be placed becomes an unlocked void.
// C++ parity: ProtoModel::assignParameterStorage (ignoreOutputError).
func (pm *ProtoModel) assignParameterStorage(outtype Datatype, intypes []Datatype) ([]parameterPieces, bool) {
	var res []parameterPieces
	if pm.OutputParams != nil && outtype != nil {
		if out, ok := pm.OutputParams.assignOutput(outtype); ok {
			res = out
		}
	}
	if res == nil {
		res = []parameterPieces{{typ: sharedTypeFactory.GetVoid()}}
	}
	return pm.InputParams.assignInputs(intypes, res)
}
