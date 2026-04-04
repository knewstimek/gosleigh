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
	pm := NewProtoModelFromCspec(cs, stackSpace)
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
	pm := NewProtoModelFromCspec(nil, nil)
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
