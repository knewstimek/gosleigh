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

// makeTestMergeEnv builds a minimal Funcdata plus two BlockBasic blocks connected
// in a diamond pattern for use in merge tests.
//
// Block layout:
//
//	bb0 (entry) -> bb1, bb2
//	bb1 -> bb3
//	bb2 -> bb3
//	bb3 (merge block -- MULTIEQUAL lives here)
//
// Returns (fd, bb0, bb1, bb2, bb3).
func makeTestMergeEnv() (*Funcdata, *BlockBasic, *BlockBasic, *BlockBasic, *BlockBasic) {
	ramSpc := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindProcessor}
	cstSpc := &address.Space{Name: "const", Index: 1, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindConstant}
	uniqSpc := &address.Space{Name: "unique", Index: 2, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindUnique}
	fd := NewFuncdata("test_merge", address.Address{Space: ramSpc, Offset: 0x1000}, uniqSpc, 0, cstSpc)

	bb0 := NewBlockBasic()
	bb1 := NewBlockBasic()
	bb2 := NewBlockBasic()
	bb3 := NewBlockBasic()

	// Assign stable indices so Cover can use them.
	bb0.SetIndex(0)
	bb1.SetIndex(1)
	bb2.SetIndex(2)
	bb3.SetIndex(3)

	// Wire edges: bb0->bb1, bb0->bb2, bb1->bb3, bb2->bb3.
	bb3.FlowBlock.AddInEdge(&bb1.FlowBlock, 0)
	bb3.FlowBlock.AddInEdge(&bb2.FlowBlock, 0)
	bb1.FlowBlock.AddInEdge(&bb0.FlowBlock, 0)
	bb2.FlowBlock.AddInEdge(&bb0.FlowBlock, 0)

	return fd, bb0, bb1, bb2, bb3
}

// TestMergeMarker_MultiEqual verifies that MergeMarker coalesces the output
// and inputs of a MULTIEQUAL op into a single HighVariable.
//
// The block layout is a 2-predecessor diamond: bb1 -> bb3 and bb2 -> bb3,
// so vn0 (defined in bb1) and vn1 (defined in bb2) have non-overlapping Covers
// and can be merged directly without trimming.
func TestMergeMarker_MultiEqual(t *testing.T) {
	fd, _, bb1, bb2, bb3 := makeTestMergeEnv()

	ramSpc := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindProcessor}

	// vn0 defined in bb1, vn1 defined in bb2: distinct predecessor paths => no Cover overlap.
	defOp0 := fd.NewOp(1, address.Address{Space: ramSpc, Offset: 0x100})
	fd.OpSetOpcode(defOp0, CPUI_COPY)
	vn0 := fd.NewVarnodeOut(4, address.Address{Space: ramSpc, Offset: 0x10}, defOp0)
	fd.OpInsertEnd(defOp0, bb1)

	defOp1 := fd.NewOp(1, address.Address{Space: ramSpc, Offset: 0x300})
	fd.OpSetOpcode(defOp1, CPUI_COPY)
	vn1 := fd.NewVarnodeOut(4, address.Address{Space: ramSpc, Offset: 0x10}, defOp1)
	fd.OpInsertEnd(defOp1, bb2)

	// MULTIEQUAL in bb3 with two inputs and one output.
	// bb3 has two predecessors: bb1 (index 0) and bb2 (index 1).
	phiOp := fd.NewOp(2, address.Address{Space: ramSpc, Offset: 0x400})
	fd.OpSetOpcode(phiOp, CPUI_MULTIEQUAL)
	outVn := fd.NewVarnodeOut(4, address.Address{Space: ramSpc, Offset: 0x10}, phiOp)
	fd.OpSetInput(phiOp, vn0, 0)
	fd.OpSetInput(phiOp, vn1, 1)
	fd.OpInsertEnd(phiOp, bb3)

	// Assign a distinct HighVariable to each varnode (simulating post-Heritage state).
	h0 := NewHighVariable("v0")
	h0.AddInstance(vn0)
	h1 := NewHighVariable("v1")
	h1.AddInstance(vn1)
	hOut := NewHighVariable("vout")
	hOut.AddInstance(outVn)

	if h0 == h1 || h0 == hOut || h1 == hOut {
		t.Fatal("precondition: all HighVariables must be distinct")
	}

	// Run MergeMarker.
	merge := NewMerge(fd)
	merge.MergeMarker()

	// After merging, all input/output varnodes must share the same HighVariable.
	if vn0.High() != outVn.High() {
		t.Errorf("vn0.High() != outVn.High(): vn0=%p out=%p", vn0.High(), outVn.High())
	}
	if vn1.High() != outVn.High() {
		t.Errorf("vn1.High() != outVn.High(): vn1=%p out=%p", vn1.High(), outVn.High())
	}

	// The merged HighVariable must hold all three varnodes.
	merged := outVn.High()
	if merged.NumInstances() != 3 {
		t.Errorf("merged HighVariable has %d instances, want 3", merged.NumInstances())
	}
}

// TestMergeMarker_NoMergeOnNonMarker verifies that non-marker ops are untouched.
func TestMergeMarker_NoMergeOnNonMarker(t *testing.T) {
	ramSpc := &address.Space{Name: "ram", Index: 0, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindProcessor}
	cstSpc := &address.Space{Name: "const", Index: 1, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindConstant}
	uniqSpc := &address.Space{Name: "unique", Index: 2, WordSize: 1, AddrSize: 4, Kind: address.SpaceKindUnique}
	fd := NewFuncdata("test_nomerge", address.Address{Space: ramSpc, Offset: 0x1000}, uniqSpc, 0, cstSpc)
	bb := NewBlockBasic()
	bb.SetIndex(0)

	// INT_ADD op (not a marker) -- should not be merged.
	op := fd.NewOp(2, address.Address{Space: ramSpc, Offset: 0x100})
	fd.OpSetOpcode(op, CPUI_INT_ADD)
	a := fd.NewVarnode(4, address.Address{Space: ramSpc, Offset: 0x10})
	b := fd.NewVarnode(4, address.Address{Space: ramSpc, Offset: 0x14})
	outVn := fd.NewVarnodeOut(4, address.Address{Space: ramSpc, Offset: 0x18}, op)
	fd.OpSetInput(op, a, 0)
	fd.OpSetInput(op, b, 1)
	fd.OpInsertEnd(op, bb)

	ha := NewHighVariable("a")
	ha.AddInstance(a)
	hb := NewHighVariable("b")
	hb.AddInstance(b)
	hOut := NewHighVariable("out")
	hOut.AddInstance(outVn)

	merge := NewMerge(fd)
	merge.MergeMarker()

	// Nothing should have changed.
	if a.High() != ha {
		t.Error("non-marker op: a.High() was changed unexpectedly")
	}
	if b.High() != hb {
		t.Error("non-marker op: b.High() was changed unexpectedly")
	}
	if outVn.High() != hOut {
		t.Error("non-marker op: outVn.High() was changed unexpectedly")
	}
}
