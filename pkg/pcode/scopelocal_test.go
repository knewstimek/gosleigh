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

// buildTestModel returns a cdecl ProtoModel with the given stack space pointer.
func buildTestModel(sp *address.Space) *ProtoModel {
	return &ProtoModel{
		StackSpace:       sp,
		ParamBaseOffset:  4,
		ParamAlign:       4,
		UnaffectedRegs:   make(map[string]bool),
		KilledByCallRegs: make(map[string]bool),
	}
}

// buildTestSpaces returns the three canonical address spaces used in tests.
func buildTestSpaces() (stack, reg, unique *address.Space) {
	stack = &address.Space{Name: "stack", Kind: address.SpaceKindStack, AddrSize: 4, WordSize: 1}
	reg = &address.Space{Name: "register", Kind: address.SpaceKindProcessor, AddrSize: 4, WordSize: 1}
	unique = &address.Space{Name: "unique", Kind: address.SpaceKindUnique, AddrSize: 4, WordSize: 1}
	return
}

// stackVn is a convenience constructor for a stack-space varnode at the given offset.
func stackVn(sp *address.Space, offset uint64) *Varnode {
	return NewVarnode(4, address.Address{Space: sp, Offset: offset})
}

// TestBuildFromVarnodes_Empty verifies that BuildFromVarnodes on an empty slice
// produces a ScopeLocal with no params and no locals.
func TestBuildFromVarnodes_Empty(t *testing.T) {
	sp, _, _ := buildTestSpaces()
	model := buildTestModel(sp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	sl.BuildFromVarnodes(nil, fp)

	if fp.NumParams() != 0 {
		t.Errorf("NumParams = %d, want 0", fp.NumParams())
	}
	if fp.NumLocals() != 0 {
		t.Errorf("NumLocals = %d, want 0", fp.NumLocals())
	}

	sl2 := NewScopeLocal(model)
	fp2 := NewFuncProto(model)
	sl2.BuildFromVarnodes([]*Varnode{}, fp2)
	if fp2.NumParams() != 0 || fp2.NumLocals() != 0 {
		t.Errorf("empty slice: NumParams=%d NumLocals=%d, want both 0",
			fp2.NumParams(), fp2.NumLocals())
	}
}

// TestBuildFromVarnodes_MixedSpaces verifies that only stack-space varnodes
// at param or local offsets are classified; register and unique varnodes
// are ignored entirely.
func TestBuildFromVarnodes_MixedSpaces(t *testing.T) {
	stackSp, regSp, uniqueSp := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	varnodes := []*Varnode{
		// Stack params (offsets 4, 8).
		stackVn(stackSp, 4),
		stackVn(stackSp, 8),
		// Stack local (offset 0xfffffffc = -4, first local below EBP).
		stackVn(stackSp, 0xfffffffc),
		// Register varnode -- must be ignored.
		NewVarnode(4, address.Address{Space: regSp, Offset: 0}),
		// Unique (temp) varnode -- must be ignored.
		NewVarnode(4, address.Address{Space: uniqueSp, Offset: 0x1000}),
		// Stack offset 0 = return address slot, not a param.
		stackVn(stackSp, 0),
	}

	sl.BuildFromVarnodes(varnodes, fp)

	if fp.NumParams() != 2 {
		t.Errorf("NumParams = %d, want 2 (offsets 4,8)", fp.NumParams())
	}
	if fp.NumLocals() != 1 {
		t.Errorf("NumLocals = %d, want 1 (offset 0xfffffffc)", fp.NumLocals())
	}

	// Params must be named param_0, param_1 in ascending offset order.
	if p0 := fp.GetParam(0); p0 == nil || p0.Name() != "param_0" {
		t.Errorf("param 0 name = %q, want param_0", nameOrNil(p0))
	}
	if p1 := fp.GetParam(1); p1 == nil || p1.Name() != "param_1" {
		t.Errorf("param 1 name = %q, want param_1", nameOrNil(p1))
	}

	// Local must be named local_0.
	if l0 := fp.GetLocal(0); l0 == nil || l0.Name() != "local_0" {
		t.Errorf("local 0 name = %q, want local_0", nameOrNil(l0))
	}
}

// TestBuildFromVarnodes_Duplicates verifies that multiple varnodes at the same
// stack offset are deduplicated -- each offset produces exactly one HighVariable.
func TestBuildFromVarnodes_Duplicates(t *testing.T) {
	stackSp, _, _ := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	// Three varnodes at the same param offset 4, two at local offset 0xfffffffc.
	varnodes := []*Varnode{
		stackVn(stackSp, 4),
		stackVn(stackSp, 4),
		stackVn(stackSp, 4),
		stackVn(stackSp, 0xfffffffc),
		stackVn(stackSp, 0xfffffffc),
	}
	sl.BuildFromVarnodes(varnodes, fp)

	if fp.NumParams() != 1 {
		t.Errorf("NumParams = %d, want 1 after dedup", fp.NumParams())
	}
	if fp.NumLocals() != 1 {
		t.Errorf("NumLocals = %d, want 1 after dedup", fp.NumLocals())
	}
}

// TestBuildFromVarnodes_ParamOrdering verifies that params are assigned names in
// ascending offset order (offset 4 -> param_0, offset 8 -> param_1, offset 12 -> param_2)
// regardless of the order they appear in the input slice.
func TestBuildFromVarnodes_ParamOrdering(t *testing.T) {
	stackSp, _, _ := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	// Provide params in reverse offset order to confirm sort.
	varnodes := []*Varnode{
		stackVn(stackSp, 12),
		stackVn(stackSp, 4),
		stackVn(stackSp, 8),
	}
	sl.BuildFromVarnodes(varnodes, fp)

	if fp.NumParams() != 3 {
		t.Fatalf("NumParams = %d, want 3", fp.NumParams())
	}

	// param_0 must correspond to the lowest offset varnode (4).
	vn0 := fp.GetParam(0).GetInstance(0)
	if vn0 == nil || vn0.Offset() != 4 {
		t.Errorf("param_0 instance offset = %d, want 4", vn0.Offset())
	}
	vn2 := fp.GetParam(2).GetInstance(0)
	if vn2 == nil || vn2.Offset() != 12 {
		t.Errorf("param_2 instance offset = %d, want 12", vn2.Offset())
	}
}

// TestBuildFromVarnodes_LocalOrdering verifies that locals are assigned names in
// descending offset order: 0xfffffffc -> local_0, 0xfffffff8 -> local_1 (Ghidra frame layout).
func TestBuildFromVarnodes_LocalOrdering(t *testing.T) {
	stackSp, _, _ := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	varnodes := []*Varnode{
		stackVn(stackSp, 0xfffffff8), // -8: second local
		stackVn(stackSp, 0xfffffffc), // -4: first local (closest to EBP)
		stackVn(stackSp, 0xfffffff4), // -12: third local
	}
	sl.BuildFromVarnodes(varnodes, fp)

	if fp.NumLocals() != 3 {
		t.Fatalf("NumLocals = %d, want 3", fp.NumLocals())
	}

	// local_0 must be the highest offset (0xfffffffc, closest to frame pointer).
	l0 := fp.GetLocal(0).GetInstance(0)
	if l0 == nil || l0.Offset() != 0xfffffffc {
		t.Errorf("local_0 offset = %#x, want 0xfffffffc", l0.Offset())
	}
	l2 := fp.GetLocal(2).GetInstance(0)
	if l2 == nil || l2.Offset() != 0xfffffff4 {
		t.Errorf("local_2 offset = %#x, want 0xfffffff4", l2.Offset())
	}
}

// TestFindEntry verifies that FindEntry returns the HighVariable for a known
// varnode and nil for an unknown one.
func TestFindEntry(t *testing.T) {
	stackSp, _, _ := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	paramVn := stackVn(stackSp, 4)
	localVn := stackVn(stackSp, 0xfffffffc)
	unknownVn := stackVn(stackSp, 100) // not added to varnodes list

	sl.BuildFromVarnodes([]*Varnode{paramVn, localVn}, fp)

	// Known param varnode.
	if hv := sl.FindEntry(paramVn); hv == nil {
		t.Error("FindEntry(paramVn) = nil, want non-nil HighVariable")
	} else if hv.Name() != "param_0" {
		t.Errorf("FindEntry(paramVn).Name() = %q, want param_0", hv.Name())
	}

	// Known local varnode.
	if hv := sl.FindEntry(localVn); hv == nil {
		t.Error("FindEntry(localVn) = nil, want non-nil HighVariable")
	} else if hv.Name() != "local_0" {
		t.Errorf("FindEntry(localVn).Name() = %q, want local_0", hv.Name())
	}

	// Unknown varnode.
	if hv := sl.FindEntry(unknownVn); hv != nil {
		t.Errorf("FindEntry(unknownVn) = %q, want nil", hv.Name())
	}

	// Nil varnode.
	if hv := sl.FindEntry(nil); hv != nil {
		t.Error("FindEntry(nil) should return nil")
	}

	// Nil ScopeLocal.
	var nilSl *ScopeLocal
	if nilSl.FindEntry(paramVn) != nil {
		t.Error("nil ScopeLocal.FindEntry should return nil")
	}
}

// TestResetLocalWindow verifies that after ResetLocalWindow all previously built
// entries are cleared.
func TestResetLocalWindow(t *testing.T) {
	stackSp, _, _ := buildTestSpaces()
	model := buildTestModel(stackSp)
	sl := NewScopeLocal(model)
	fp := NewFuncProto(model)

	vn := stackVn(stackSp, 4)
	sl.BuildFromVarnodes([]*Varnode{vn}, fp)

	if sl.FindEntry(vn) == nil {
		t.Fatal("expected entry before reset")
	}

	sl.ResetLocalWindow()

	if sl.FindEntry(vn) != nil {
		t.Error("expected nil after ResetLocalWindow")
	}
}

// BenchmarkBuildFromVarnodes measures the throughput of BuildFromVarnodes
// on a mixed workload of ~100 varnodes (stack params, stack locals, registers, uniques).
func BenchmarkBuildFromVarnodes(b *testing.B) {
	stackSp, regSp, uniqueSp := buildTestSpaces()
	model := buildTestModel(stackSp)

	// Pre-build the varnode slice outside the timed loop.
	const n = 100
	varnodes := make([]*Varnode, 0, n)
	// 20 stack params (offsets 4, 8, ..., 80).
	for i := 0; i < 20; i++ {
		varnodes = append(varnodes, stackVn(stackSp, uint64(4+i*4)))
	}
	// 20 stack locals (offsets 0xfffffffc, 0xfffffff8, ...).
	for i := 0; i < 20; i++ {
		varnodes = append(varnodes, stackVn(stackSp, uint64(0xfffffffc-i*4)))
	}
	// 30 register varnodes (ignored by BuildFromVarnodes).
	for i := 0; i < 30; i++ {
		varnodes = append(varnodes, NewVarnode(4, address.Address{Space: regSp, Offset: uint64(i * 4)}))
	}
	// 30 unique (temp) varnodes (ignored).
	for i := 0; i < 30; i++ {
		varnodes = append(varnodes, NewVarnode(4, address.Address{Space: uniqueSp, Offset: uint64(0x1000 + i*4)}))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sl := NewScopeLocal(model)
		fp := NewFuncProto(model)
		sl.BuildFromVarnodes(varnodes, fp)
	}
}

// BenchmarkCollectSymbols is intentionally omitted because collectSymbols is an
// unexported function inside printc.go and cannot be called from test code.
// Its hot path (iterating ScopeLocal entries) is covered by BenchmarkBuildFromVarnodes
// and the E2E tests in loader_test.go.

// nameOrNil is a test helper that extracts a HighVariable name or returns "<nil>".
func nameOrNil(hv *HighVariable) string {
	if hv == nil {
		return "<nil>"
	}
	return hv.Name()
}
