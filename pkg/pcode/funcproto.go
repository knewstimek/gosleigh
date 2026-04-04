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

import "fmt"

// FuncProto holds the calling convention information attached to a single
// function. It references a ProtoModel for ABI rules and records the
// high-level parameter/local variable assignments.
//
// C++ parity: funcdata.hh FuncProto (partial)
type FuncProto struct {
	model *ProtoModel

	// params holds the discovered parameter HighVariables in order.
	params []*HighVariable
	// locals holds the discovered local HighVariables in order.
	locals []*HighVariable
}

// NewFuncProto creates a FuncProto that uses the given ProtoModel.
// C++ parity: FuncProto::FuncProto
func NewFuncProto(model *ProtoModel) *FuncProto {
	return &FuncProto{model: model}
}

// Model returns the underlying calling convention model.
func (fp *FuncProto) Model() *ProtoModel { return fp.model }

// AddParam registers a parameter HighVariable (in ABI order).
func (fp *FuncProto) AddParam(hv *HighVariable) {
	if fp == nil || hv == nil {
		return
	}
	fp.params = append(fp.params, hv)
}

// AddLocal registers a local HighVariable.
func (fp *FuncProto) AddLocal(hv *HighVariable) {
	if fp == nil || hv == nil {
		return
	}
	fp.locals = append(fp.locals, hv)
}

// NumParams returns the number of classified parameters.
func (fp *FuncProto) NumParams() int {
	if fp == nil {
		return 0
	}
	return len(fp.params)
}

// NumLocals returns the number of classified locals.
func (fp *FuncProto) NumLocals() int {
	if fp == nil {
		return 0
	}
	return len(fp.locals)
}

// GetParam returns the i-th parameter HighVariable, or nil.
func (fp *FuncProto) GetParam(i int) *HighVariable {
	if fp == nil || i < 0 || i >= len(fp.params) {
		return nil
	}
	return fp.params[i]
}

// GetLocal returns the i-th local HighVariable, or nil.
func (fp *FuncProto) GetLocal(i int) *HighVariable {
	if fp == nil || i < 0 || i >= len(fp.locals) {
		return nil
	}
	return fp.locals[i]
}

// IsParamVarnode reports whether the given varnode is a stack-based parameter
// according to this function's calling convention.
// C++ parity: FuncProto::isParamVarnode
func (fp *FuncProto) IsParamVarnode(vn *Varnode) bool {
	if fp == nil || fp.model == nil || vn == nil {
		return false
	}
	if vn.Space() == nil {
		return false
	}
	// Must be in the stack address space.
	if fp.model.StackSpace != nil && vn.Space() != fp.model.StackSpace {
		return false
	} else if fp.model.StackSpace == nil && vn.Space().Kind != 0 {
		// Fallback: check by space name if StackSpace not set.
		if vn.Space().Name != "stack" {
			return false
		}
	}
	return fp.model.IsParamOffset(vn.Offset())
}

// GetParamName returns a human-readable name like "param_0", "param_1" etc.
// for the given parameter index.
// C++ parity: ParameterBasic::getName / FuncProto::getParamSymbol
func GetParamName(index int) string {
	return fmt.Sprintf("param_%d", index)
}

// GetLocalName returns a human-readable name like "local_0", "local_1" etc.
func GetLocalName(index int) string {
	return fmt.Sprintf("local_%d", index)
}

// ApplyCallingConvention classifies all stack varnodes in fd's varnode bank
// as either parameters or locals according to model, creates HighVariables
// for each group, and stores the result on fd's FuncProto and ScopeLocal.
//
// This is called after Heritage so SSA input varnodes are available.
// C++ parity: Funcdata::startProcessing / ScopeLocal::resetLocalWindow
func ApplyCallingConvention(fd *Funcdata, model *ProtoModel) {
	if fd == nil || model == nil {
		return
	}
	fp := NewFuncProto(model)
	fd.SetFuncProto(fp)

	sl := NewScopeLocal(model)
	fd.SetScopeLocal(sl)

	sl.BuildFromVarnodes(fd.GetVarnodeBank().AllVarnodes(), fp)
}
