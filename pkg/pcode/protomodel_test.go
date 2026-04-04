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

// makeTestProtoModel builds a cdecl-style ProtoModel for unit tests.
// Callee-saved: EBP, ESI, EDI, ESP.  Caller-saved: EAX, ECX, EDX.
func makeTestProtoModel() *ProtoModel {
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		AddrSize: 4,
		WordSize: 1,
	}
	pm := &ProtoModel{
		StackSpace:       stackSpace,
		ParamBaseOffset:  4,
		ParamAlign:       4,
		UnaffectedRegs:   map[string]bool{"EBP": true, "ESI": true, "EDI": true, "ESP": true},
		KilledByCallRegs: map[string]bool{"EAX": true, "ECX": true, "EDX": true},
	}
	return pm
}

// TestClassifyInput_CdeclBoundary exercises IsParamOffset at the exact boundary
// values that distinguish parameters from locals in the x86 cdecl ABI:
//
//   - offset 4  -> first param slot (boundary; exact param base)
//   - offset 8  -> second param slot
//   - offsets 5,6,7 -> misaligned but still in param range (>= 4, < 0x80000000)
//   - offset 0  -> return address slot; below ParamBaseOffset, not a param
//   - offset 0xfffffffc -> large unsigned = -4 in two's complement; treated as local
func TestClassifyInput_CdeclBoundary(t *testing.T) {
	pm := makeTestProtoModel()

	paramCases := []struct {
		offset  uint64
		isParam bool
		desc    string
	}{
		{4, true, "first param (exact base)"},
		{8, true, "second param"},
		{12, true, "third param"},
		{5, true, "misaligned +1"},
		{6, true, "misaligned +2"},
		{7, true, "misaligned +3"},
		{0, false, "return address slot (below base)"},
		{1, false, "below base"},
		{3, false, "just below base"},
		{0xfffffffc, false, "large uint = local (negative frame offset)"},
		{0x80000000, false, "local threshold boundary (>= threshold)"},
		{0x7ffffffc, true, "just below threshold, treated as param"},
	}

	for _, tc := range paramCases {
		got := pm.IsParamOffset(tc.offset)
		if got != tc.isParam {
			t.Errorf("IsParamOffset(%#x) [%s] = %v, want %v",
				tc.offset, tc.desc, got, tc.isParam)
		}
	}
}

// TestIsLocalOffset verifies IsLocalOffset identifies large unsigned offsets
// (negative two's-complement frame offsets) as locals, and small positive
// offsets as non-locals.
func TestIsLocalOffset(t *testing.T) {
	pm := makeTestProtoModel()

	cases := []struct {
		offset  uint64
		isLocal bool
	}{
		{0xfffffffc, true},
		{0xfffffff8, true},
		{0x80000000, true},
		{0x7fffffff, false},
		{4, false},
		{8, false},
		{0, false},
	}
	for _, tc := range cases {
		got := pm.IsLocalOffset(tc.offset)
		if got != tc.isLocal {
			t.Errorf("IsLocalOffset(%#x) = %v, want %v", tc.offset, got, tc.isLocal)
		}
	}
}

// TestIsUnaffected verifies callee-saved register lookup.
// Registers in the unaffected set must return true; others false.
func TestIsUnaffected(t *testing.T) {
	pm := makeTestProtoModel()

	inSet := []string{"EBP", "ESI", "EDI", "ESP"}
	for _, reg := range inSet {
		if !pm.IsUnaffected(reg) {
			t.Errorf("IsUnaffected(%q) = false, want true", reg)
		}
	}

	notInSet := []string{"EAX", "ECX", "EDX", "EBX", ""}
	for _, reg := range notInSet {
		if pm.IsUnaffected(reg) {
			t.Errorf("IsUnaffected(%q) = true, want false", reg)
		}
	}

	// Nil receiver must not panic.
	var nilPm *ProtoModel
	if nilPm.IsUnaffected("EBP") {
		t.Error("nil ProtoModel.IsUnaffected should return false")
	}
}

// TestIsKilledByCall verifies caller-saved register lookup.
// Registers in the killedbycall set must return true; others false.
func TestIsKilledByCall(t *testing.T) {
	pm := makeTestProtoModel()

	inSet := []string{"EAX", "ECX", "EDX"}
	for _, reg := range inSet {
		if !pm.IsKilledByCall(reg) {
			t.Errorf("IsKilledByCall(%q) = false, want true", reg)
		}
	}

	notInSet := []string{"EBP", "ESI", "EDI", "ESP", "EBX", ""}
	for _, reg := range notInSet {
		if pm.IsKilledByCall(reg) {
			t.Errorf("IsKilledByCall(%q) = true, want false", reg)
		}
	}

	// Nil receiver must not panic.
	var nilPm *ProtoModel
	if nilPm.IsKilledByCall("EAX") {
		t.Error("nil ProtoModel.IsKilledByCall should return false")
	}
}

// TestNewProtoModelFromCspec verifies that NewProtoModelFromCspec correctly
// populates a ProtoModel from parsed CspecData.
func TestNewProtoModelFromCspec(t *testing.T) {
	cs, err := ParseCspecBytes([]byte(minimalCdeclXML))
	if err != nil {
		t.Fatalf("ParseCspecBytes: %v", err)
	}
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		AddrSize: 4,
		WordSize: 1,
	}
	pm := NewProtoModelFromCspec(cs, stackSpace, nil)
	if pm == nil {
		t.Fatal("expected non-nil ProtoModel")
	}
	if pm.ParamBaseOffset != 4 {
		t.Errorf("ParamBaseOffset = %d, want 4", pm.ParamBaseOffset)
	}
	if pm.ParamAlign != 4 {
		t.Errorf("ParamAlign = %d, want 4", pm.ParamAlign)
	}
	if pm.StackSpace != stackSpace {
		t.Error("StackSpace pointer not preserved")
	}
	if !pm.IsUnaffected("ESP") {
		t.Error("ESP should be in unaffected set")
	}
	if !pm.IsKilledByCall("EAX") {
		t.Error("EAX should be in killedbycall set")
	}
}

// TestNewProtoModelFromCspec_Nil verifies that a nil CspecData produces a
// ProtoModel with safe cdecl defaults rather than panicking.
func TestNewProtoModelFromCspec_Nil(t *testing.T) {
	pm := NewProtoModelFromCspec(nil, nil, nil)
	if pm == nil {
		t.Fatal("expected non-nil ProtoModel for nil cspec")
	}
	if pm.ParamBaseOffset != 4 {
		t.Errorf("default ParamBaseOffset = %d, want 4", pm.ParamBaseOffset)
	}
	if pm.ParamAlign != 4 {
		t.Errorf("default ParamAlign = %d, want 4", pm.ParamAlign)
	}
}

// TestProtoModelRegParams verifies that NewProtoModelFromCspec populates
// RegParams and RegParamOffsets correctly when a regLookup is provided.
// Uses x86-64-gcc.cspec which has RDI/RSI/RDX/RCX/R8/R9 as integer params.
func TestProtoModelRegParams(t *testing.T) {
	cs, err := ParseCspec("../../testdata/sla/x86-64-gcc.cspec")
	if err != nil {
		t.Fatalf("ParseCspec: %v", err)
	}

	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		AddrSize: 8,
		WordSize: 1,
	}

	// Fake register offsets for RDI..R9 (arbitrary but deterministic).
	fakeOffsets := map[string]uint64{
		"RDI": 0x38, "RSI": 0x30, "RDX": 0x10, "RCX": 0x08, "R8": 0x80, "R9": 0x88,
	}
	regLookup := func(name string) (uint64, bool) {
		off, ok := fakeOffsets[name]
		return off, ok
	}

	pm := NewProtoModelFromCspec(cs, stackSpace, regLookup)
	if pm == nil {
		t.Fatal("expected non-nil ProtoModel")
	}

	// PointerSize must be 8 for x86-64.
	if pm.PointerSize != 8 {
		t.Errorf("PointerSize = %d, want 8", pm.PointerSize)
	}

	// RegParams must be in SysV ABI order.
	wantRegs := []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}
	if len(pm.RegParams) != len(wantRegs) {
		t.Fatalf("RegParams = %v (len %d), want %v", pm.RegParams, len(pm.RegParams), wantRegs)
	}
	for i, want := range wantRegs {
		if pm.RegParams[i] != want {
			t.Errorf("RegParams[%d] = %q, want %q", i, pm.RegParams[i], want)
		}
	}

	// RegParamOffsets must map each fake offset to the correct ABI index.
	for i, name := range wantRegs {
		off := fakeOffsets[name]
		idx, ok := pm.IsRegParam(off)
		if !ok {
			t.Errorf("IsRegParam(0x%x) [%s] = false, want true", off, name)
			continue
		}
		if idx != i {
			t.Errorf("IsRegParam(0x%x) [%s] = idx %d, want %d", off, name, idx, i)
		}
	}

	// A random offset not in the map must return false.
	if _, ok := pm.IsRegParam(0xDEAD); ok {
		t.Error("IsRegParam(0xDEAD) = true, want false for unknown offset")
	}
}

// TestProtoModel64BitThreshold verifies that the local/param threshold is
// 0x8000000000000000 when PointerSize=8 and 0x80000000 when PointerSize<=4.
// This is critical: x86-32 behavior must be unchanged.
func TestProtoModel64BitThreshold(t *testing.T) {
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		AddrSize: 8,
		WordSize: 1,
	}

	// 64-bit: offsets >= 0x8000000000000000 are locals; smaller are params (if >= base).
	pm64 := &ProtoModel{
		StackSpace:      stackSpace,
		ParamBaseOffset: 8,
		ParamAlign:      8,
		PointerSize:     8,
	}
	if pm64.localThreshold() != 0x8000000000000000 {
		t.Errorf("64-bit localThreshold = 0x%x, want 0x8000000000000000", pm64.localThreshold())
	}
	if !pm64.IsParamOffset(8) {
		t.Error("IsParamOffset(8) should be true for 64-bit model")
	}
	if !pm64.IsParamOffset(0x7fffffffffffffff) {
		t.Error("IsParamOffset(0x7fffffffffffffff) should be true for 64-bit model")
	}
	if pm64.IsParamOffset(0x8000000000000000) {
		t.Error("IsParamOffset(0x8000000000000000) should be false (local threshold)")
	}
	if !pm64.IsLocalOffset(0x8000000000000000) {
		t.Error("IsLocalOffset(0x8000000000000000) should be true for 64-bit model")
	}

	// 32-bit: threshold must remain 0x80000000 regardless.
	for _, ptrSize := range []int{0, 4} {
		pm32 := &ProtoModel{
			StackSpace:      stackSpace,
			ParamBaseOffset: 4,
			ParamAlign:      4,
			PointerSize:     ptrSize,
		}
		if pm32.localThreshold() != 0x80000000 {
			t.Errorf("32-bit (PointerSize=%d) localThreshold = 0x%x, want 0x80000000", ptrSize, pm32.localThreshold())
		}
		if !pm32.IsParamOffset(4) {
			t.Errorf("32-bit (PointerSize=%d) IsParamOffset(4) should be true", ptrSize)
		}
		if pm32.IsParamOffset(0x80000000) {
			t.Errorf("32-bit (PointerSize=%d) IsParamOffset(0x80000000) should be false", ptrSize)
		}
		if !pm32.IsLocalOffset(0xfffffffc) {
			t.Errorf("32-bit (PointerSize=%d) IsLocalOffset(0xfffffffc) should be true", ptrSize)
		}
	}
}
