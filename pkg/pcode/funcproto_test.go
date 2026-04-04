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
	"gosleigh/pkg/address"
	"testing"
)

// makeStackVarnode builds a varnode located in the given stack space at offset.
func makeStackVarnode(sp *address.Space, offset uint64) *Varnode {
	return NewVarnode(4, address.Address{Space: sp, Offset: offset})
}

// TestIsParamVarnode verifies FuncProto.IsParamVarnode against the key boundary
// offsets in an x86 cdecl stack layout:
//
//   - offset 4  -> true  (param_0: first slot above return address)
//   - offset 8  -> true  (param_1)
//   - offset 0  -> false (return address, below ParamBaseOffset)
//   - offset 0xfffffffc -> false (negative frame offset, local area)
//   - non-stack space   -> false (register varnode cannot be a stack param)
func TestIsParamVarnode(t *testing.T) {
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		AddrSize: 4,
		WordSize: 1,
	}
	regSpace := &address.Space{
		Name:     "register",
		Kind:     address.SpaceKindProcessor,
		AddrSize: 4,
		WordSize: 1,
	}
	pm := &ProtoModel{
		StackSpace:       stackSpace,
		ParamBaseOffset:  4,
		ParamAlign:       4,
		UnaffectedRegs:   make(map[string]bool),
		KilledByCallRegs: make(map[string]bool),
	}
	fp := NewFuncProto(pm)

	cases := []struct {
		desc    string
		vn      *Varnode
		isParam bool
	}{
		{"offset 4 (param_0)", makeStackVarnode(stackSpace, 4), true},
		{"offset 8 (param_1)", makeStackVarnode(stackSpace, 8), true},
		{"offset 12 (param_2)", makeStackVarnode(stackSpace, 12), true},
		{"offset 0 (return addr)", makeStackVarnode(stackSpace, 0), false},
		{"offset 0xfffffffc (local)", makeStackVarnode(stackSpace, 0xfffffffc), false},
		{"offset 0x80000000 (local boundary)", makeStackVarnode(stackSpace, 0x80000000), false},
		{"register space", makeStackVarnode(regSpace, 4), false},
		{"nil varnode", nil, false},
	}

	for _, tc := range cases {
		got := fp.IsParamVarnode(tc.vn)
		if got != tc.isParam {
			t.Errorf("IsParamVarnode [%s] = %v, want %v", tc.desc, got, tc.isParam)
		}
	}

	// Nil FuncProto must not panic.
	var nilFp *FuncProto
	if nilFp.IsParamVarnode(makeStackVarnode(stackSpace, 4)) {
		t.Error("nil FuncProto.IsParamVarnode should return false")
	}
}

// TestIsParamVarnode_StackSpaceFallback verifies that when ProtoModel.StackSpace
// is nil, IsParamVarnode falls back to matching by space name "stack".
func TestIsParamVarnode_StackSpaceFallback(t *testing.T) {
	namedStackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindProcessor, // not SpaceKindStack -- tests name fallback
		AddrSize: 4,
		WordSize: 1,
	}
	pm := &ProtoModel{
		StackSpace:       nil, // trigger name-based fallback
		ParamBaseOffset:  4,
		ParamAlign:       4,
		UnaffectedRegs:   make(map[string]bool),
		KilledByCallRegs: make(map[string]bool),
	}
	fp := NewFuncProto(pm)

	vn := NewVarnode(4, address.Address{Space: namedStackSpace, Offset: 4})
	if !fp.IsParamVarnode(vn) {
		t.Error("expected IsParamVarnode true for named stack space with offset 4")
	}
}

// TestGetParamName verifies the naming scheme: param_0, param_1, ..., param_N.
func TestGetParamName(t *testing.T) {
	cases := []struct {
		index int
		want  string
	}{
		{0, "param_0"},
		{1, "param_1"},
		{5, "param_5"},
		{99, "param_99"},
	}
	for _, tc := range cases {
		got := GetParamName(tc.index)
		if got != tc.want {
			t.Errorf("GetParamName(%d) = %q, want %q", tc.index, got, tc.want)
		}
	}
}

// TestGetLocalName verifies the local naming scheme: local_0, local_1, ..., local_N.
func TestGetLocalName(t *testing.T) {
	cases := []struct {
		index int
		want  string
	}{
		{0, "local_0"},
		{1, "local_1"},
		{5, "local_5"},
		{99, "local_99"},
	}
	for _, tc := range cases {
		got := GetLocalName(tc.index)
		if got != tc.want {
			t.Errorf("GetLocalName(%d) = %q, want %q", tc.index, got, tc.want)
		}
	}
}

// TestFuncProto_AddGetParam verifies AddParam / GetParam / NumParams.
func TestFuncProto_AddGetParam(t *testing.T) {
	pm := makeTestProtoModel()
	fp := NewFuncProto(pm)

	if fp.NumParams() != 0 {
		t.Errorf("NumParams before adding = %d, want 0", fp.NumParams())
	}
	if fp.GetParam(0) != nil {
		t.Error("GetParam(0) on empty FuncProto should return nil")
	}

	hv0 := NewHighVariable("param_0")
	hv1 := NewHighVariable("param_1")
	fp.AddParam(hv0)
	fp.AddParam(hv1)

	if fp.NumParams() != 2 {
		t.Errorf("NumParams = %d, want 2", fp.NumParams())
	}
	if fp.GetParam(0) != hv0 {
		t.Error("GetParam(0) should return hv0")
	}
	if fp.GetParam(1) != hv1 {
		t.Error("GetParam(1) should return hv1")
	}
	if fp.GetParam(2) != nil {
		t.Error("GetParam(2) out of range should return nil")
	}

	// Nil guards.
	var nilFp *FuncProto
	nilFp.AddParam(hv0) // must not panic
	if nilFp.NumParams() != 0 {
		t.Error("nil FuncProto.NumParams() should return 0")
	}
}

// TestFuncProto_AddGetLocal verifies AddLocal / GetLocal / NumLocals.
func TestFuncProto_AddGetLocal(t *testing.T) {
	pm := makeTestProtoModel()
	fp := NewFuncProto(pm)

	hv := NewHighVariable("local_0")
	fp.AddLocal(hv)

	if fp.NumLocals() != 1 {
		t.Errorf("NumLocals = %d, want 1", fp.NumLocals())
	}
	if fp.GetLocal(0) != hv {
		t.Error("GetLocal(0) should return hv")
	}
	if fp.GetLocal(1) != nil {
		t.Error("GetLocal(1) out of range should return nil")
	}
}
