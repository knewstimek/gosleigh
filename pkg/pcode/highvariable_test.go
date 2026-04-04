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

// TestHighVariable_Basic creates a HighVariable, sets its name, adds multiple
// instances, and verifies NumInstances and GetInstance return correct values.
func TestHighVariable_Basic(t *testing.T) {
	hv := NewHighVariable("initial")
	if hv.Name() != "initial" {
		t.Errorf("Name() = %q, want initial", hv.Name())
	}

	hv.SetName("param_0")
	if hv.Name() != "param_0" {
		t.Errorf("Name() after SetName = %q, want param_0", hv.Name())
	}

	if hv.NumInstances() != 0 {
		t.Errorf("NumInstances before AddInstance = %d, want 0", hv.NumInstances())
	}

	// Build two distinct varnodes.
	sp := &address.Space{Name: "stack", Kind: address.SpaceKindStack, AddrSize: 4, WordSize: 1}
	vn0 := NewVarnode(4, address.Address{Space: sp, Offset: 4})
	vn1 := NewVarnode(4, address.Address{Space: sp, Offset: 8})

	hv.AddInstance(vn0)
	if hv.NumInstances() != 1 {
		t.Errorf("NumInstances after 1st AddInstance = %d, want 1", hv.NumInstances())
	}
	hv.AddInstance(vn1)
	if hv.NumInstances() != 2 {
		t.Errorf("NumInstances after 2nd AddInstance = %d, want 2", hv.NumInstances())
	}

	if hv.GetInstance(0) != vn0 {
		t.Error("GetInstance(0) should return first added varnode")
	}
	if hv.GetInstance(1) != vn1 {
		t.Error("GetInstance(1) should return second added varnode")
	}
	if hv.GetInstance(2) != nil {
		t.Error("GetInstance(2) out of range should return nil")
	}
	if hv.GetInstance(-1) != nil {
		t.Error("GetInstance(-1) should return nil")
	}
}

// TestHighVariable_BackPointer verifies that AddInstance sets the back-pointer
// on the varnode (vn.High() == hv) so that the SSA graph can traverse upward.
func TestHighVariable_BackPointer(t *testing.T) {
	hv := NewHighVariable("local_0")
	sp := &address.Space{Name: "stack", Kind: address.SpaceKindStack, AddrSize: 4, WordSize: 1}
	vn := NewVarnode(4, address.Address{Space: sp, Offset: 0xfffffffc})

	// Before AddInstance the back-pointer should be nil.
	if vn.High() != nil {
		t.Error("expected High() == nil before AddInstance")
	}

	hv.AddInstance(vn)

	// AddInstance must call vn.SetHigh(hv).
	if vn.High() != hv {
		t.Errorf("vn.High() = %p, want %p (hv)", vn.High(), hv)
	}

	// Verify SetHigh works independently (used by other paths).
	hv2 := NewHighVariable("local_1")
	vn.SetHigh(hv2)
	if vn.High() != hv2 {
		t.Error("SetHigh did not update High() pointer")
	}
}

// TestHighVariable_NilSafety verifies that all methods on a nil *HighVariable
// return safe zero values rather than panicking.
func TestHighVariable_NilSafety(t *testing.T) {
	var hv *HighVariable

	if hv.Name() != "" {
		t.Errorf("nil.Name() = %q, want empty string", hv.Name())
	}
	// SetName and AddInstance on nil must not panic.
	hv.SetName("x")
	sp := &address.Space{Name: "stack", Kind: address.SpaceKindStack, AddrSize: 4, WordSize: 1}
	vn := NewVarnode(4, address.Address{Space: sp, Offset: 4})
	hv.AddInstance(vn)

	if hv.NumInstances() != 0 {
		t.Errorf("nil.NumInstances() = %d, want 0", hv.NumInstances())
	}
	if hv.GetInstance(0) != nil {
		t.Error("nil.GetInstance(0) should return nil")
	}
}
