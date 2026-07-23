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
	"testing"

	"gosleigh/pkg/address"
)

// win64Model builds a ParamListStandard approximating the x86-64 Windows
// __fastcall <input>: four grouped register slots (RCX/RDX/R8/R9, each an
// exclusion entry) followed by a single non-exclusion stack entry at offset 0x28
// (align 8). The float XMM alternatives are omitted -- they never match an
// integer trial and do not affect the integer recovery path under test.
func win64Model() (*ParamListStandard, *address.Space, *address.Space) {
	reg := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8}
	stack := &address.Space{Name: "stack", Kind: address.SpaceKindStack, Index: 2, AddrSize: 8}
	// RCX/RDX/R8/R9 register offsets (arbitrary but distinct, non-overlapping).
	specs := []ParamEntrySpec{
		{Space: reg, AddressBase: 0x08, MinSize: 1, MaxSize: 8, Grouped: true, GroupID: 0},
		{Space: reg, AddressBase: 0x10, MinSize: 1, MaxSize: 8, Grouped: true, GroupID: 1},
		{Space: reg, AddressBase: 0x50, MinSize: 1, MaxSize: 8, Grouped: true, GroupID: 2},
		{Space: reg, AddressBase: 0x58, MinSize: 1, MaxSize: 8, Grouped: true, GroupID: 3},
		{Space: stack, AddressBase: 0x28, MinSize: 1, MaxSize: 500, Align: 8, GroupID: 4},
	}
	return NewParamListStandard(specs), reg, stack
}

// TestFillinMapHelperSum reproduces the helper_sum trial set: four active
// register inputs plus one active stack input at [stack+0x28]. FillinMap must
// mark all five as used, recovering the fifth (stack) parameter that the old
// IsParamOffset heuristic missed.
func TestFillinMapHelperSum(t *testing.T) {
	pl, reg, stack := win64Model()

	active := NewParamActive(false)
	regAddrs := []uint64{0x08, 0x10, 0x50, 0x58}
	for _, off := range regAddrs {
		active.RegisterTrial(address.Address{Space: reg, Offset: off}, 4)
		active.Trial(active.NumTrials() - 1).MarkActive()
	}
	active.RegisterTrial(address.Address{Space: stack, Offset: 0x28}, 4)
	active.Trial(active.NumTrials() - 1).MarkActive()

	pl.FillinMap(active)

	used := 0
	var stackUsed bool
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if !pt.IsUsed() {
			continue
		}
		used++
		if pt.GetAddress().Space == stack && pt.GetAddress().Offset == 0x28 {
			stackUsed = true
		}
	}
	if used != 5 {
		t.Fatalf("expected 5 used trials, got %d", used)
	}
	if !stackUsed {
		t.Fatalf("stack parameter at [stack+0x28] was not recovered as used")
	}
}

// TestFindEntryStackAndRegister verifies findEntry/possibleParam classify both a
// register slot and the stack slot, and reject an unrelated offset.
func TestFindEntryStackAndRegister(t *testing.T) {
	pl, reg, stack := win64Model()

	if !pl.possibleParam(address.Address{Space: reg, Offset: 0x08}, 4) {
		t.Error("register slot 0x08 should be a possible parameter")
	}
	if !pl.possibleParam(address.Address{Space: stack, Offset: 0x28}, 4) {
		t.Error("stack slot 0x28 should be a possible parameter")
	}
	// An offset below the stack entry base is not covered.
	if pl.possibleParam(address.Address{Space: stack, Offset: 0x08}, 4) {
		t.Error("stack offset 0x08 is below the stack entry base and must not match")
	}
	// A register offset with no pentry must not match.
	if pl.possibleParam(address.Address{Space: reg, Offset: 0x200}, 4) {
		t.Error("unrelated register offset 0x200 must not match")
	}
}

// TestFillinMapLeadingHoleUnref checks that when a later register group has a
// representative but an earlier one does not, buildTrialMap synthesizes an unref
// trial for the missing earlier group. C++ parity: fspec.cc:886-901.
func TestFillinMapLeadingHoleUnref(t *testing.T) {
	pl, reg, _ := win64Model()

	active := NewParamActive(false)
	// Only group 1 (offset 0x10) has a real active trial; group 0 is a hole.
	active.RegisterTrial(address.Address{Space: reg, Offset: 0x10}, 4)
	active.Trial(active.NumTrials() - 1).MarkActive()

	pl.buildTrialMap(active)

	// An unref trial for the missing group 0 (register offset 0x08) must exist.
	foundUnref := false
	for i := 0; i < active.NumTrials(); i++ {
		pt := active.Trial(i)
		if pt.IsUnref() && pt.GetEntry() != nil && pt.GetEntry().getGroup() == 0 {
			foundUnref = true
		}
	}
	if !foundUnref {
		t.Fatalf("expected an unref trial for the missing leading group 0")
	}
}
