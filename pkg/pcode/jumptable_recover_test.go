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
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/address"
)

// buildBranchless creates an alive op with the given inputs and no output
// (used for BRANCHIND / CBRANCH, which have no result Varnode).
func buildBranchless(fd *Funcdata, opcode OpCode, inputs ...*Varnode) *PcodeOp {
	addr := address.Address{Space: fd.BaseAddr().Space, Offset: uint64(0x1000 + fd.NumOps()*0x10)}
	op := fd.NewOp(len(inputs), addr)
	fd.OpSetOpcode(op, opcode)
	for i, in := range inputs {
		fd.OpSetInput(op, in, i)
	}
	fd.OpMarkAlive(op)
	return op
}

// buildHeritagedSwitch constructs an SSA'd (heritage-shaped) dense-switch
// Funcdata for op_switch: a straight-line RVA table computation from a free
// 4-byte selector into a BRANCHIND, guarded by a single `sel > 7` CBRANCH.
//
// This stands in for running the live pipeline up through ActionHeritage on
// switch.exe: every intermediate Varnode has a single reaching definition (the
// SSA property findDeterminingVarnodes back-walks), and the guard block feeds
// the switch block through a two-out CBRANCH exactly as Ghidra melds it. The
// live bridge.Build path is untouched -- there the pre-heritage BRANCHIND input
// is a fresh, unwritten read, so this same recovery collapses to a full range
// and fails (see RecoverModel doc comment), which is why X64_SWITCH still
// truncates to CALLIND.
//
// Returns the BRANCHIND op, the selector Varnode, and the recovered-order
// switch computation ops for assertions.
func buildHeritagedSwitch(fd *Funcdata) (branchind *PcodeOp, selector *Varnode) {
	ram := fd.BaseAddr().Space
	selector = newRuleInput(fd, 4, 0x40) // free 4-byte switch index

	// Straight-line RVA computation: sel -> SEXT -> *4 -> +tableVMA -> LOAD ->
	// ZEXT -> +imageBase -> BRANCHIND.
	sext := newRuleOp(fd, CPUI_INT_SEXT, 8, selector)
	mult := newRuleOp(fd, CPUI_INT_MULT, 8, sext.Output(), fd.NewConstant(8, 4))
	addr := newRuleOp(fd, CPUI_INT_ADD, 8, mult.Output(), fd.NewConstant(8, switchTableVMA))
	spaceID := fd.NewSpaceIDConst(ram)
	load := newRuleOp(fd, CPUI_LOAD, 4, spaceID, addr.Output())
	zext := newRuleOp(fd, CPUI_INT_ZEXT, 8, load.Output())
	tgt := newRuleOp(fd, CPUI_INT_ADD, 8, zext.Output(), fd.NewConstant(8, switchImageBase))
	branchind = buildBranchless(fd, CPUI_BRANCHIND, tgt.Output())

	// Guard: cond = (7 < sel) == INT_LESS(#7, sel); CBRANCH takes the switch
	// block on the fall-through (cond false, i.e. sel <= 7).
	cond := newRuleOp(fd, CPUI_INT_LESS, 1, fd.NewConstant(4, 7), selector)
	cbranch := buildBranchless(fd, CPUI_CBRANCH, fd.NewConstant(8, 0x2000), cond.Output())

	// Block graph: guard G -> {switch S (out 0), default D (out 1)}.
	graph := NewBlockGraph()
	g := graph.NewBlockBasicInGraph()
	s := graph.NewBlockBasicInGraph()
	d := graph.NewBlockBasicInGraph()

	g.AddOp(cond)
	g.AddOp(cbranch) // CBRANCH must be the block's last op
	cond.SetParent(g)
	cbranch.SetParent(g)

	s.AddOp(branchind)
	branchind.SetParent(s)

	// Edge order fixes InRevIndex: S is G's out[0] (fall-through to switch).
	graph.AddEdge(&g.FlowBlock, &s.FlowBlock, 0)
	graph.AddEdge(&g.FlowBlock, &d.FlowBlock, 0)
	return branchind, selector
}

// TestJumpBasicRecoverAddressesDenseSwitch is the B2 phase-2 gate: on a
// heritage'd dense-switch fixture, JumpTable.RecoverAddresses must recover the
// PathMeld sel..target chain, a [0,8) normalized range starting at the selector,
// and the eight case-target addresses (imageBase + RVA[i]).
func TestJumpBasicRecoverAddressesDenseSwitch(t *testing.T) {
	fd := newRulesFuncdata()
	// Synthetic RVA table: case k -> RVA 0x1200 + k*0x10 (deterministic, no .exe).
	rvaFor := func(k uint64) uint64 { return 0x1200 + k*0x10 }
	fd.SetImageReader(func(a address.Address, sz int) (uint64, error) {
		k := (a.Offset - switchTableVMA) / 4
		return rvaFor(k), nil
	})

	branchind, selector := buildHeritagedSwitch(fd)

	jt := NewJumpTable(branchind.Addr())
	jt.SetIndirectOp(branchind)
	if err := jt.RecoverAddresses(fd); err != nil {
		t.Fatalf("RecoverAddresses: %v", err)
	}

	model, ok := jt.JumpModel().(*JumpBasic)
	if !ok {
		t.Fatalf("expected *JumpBasic model, got %T", jt.JumpModel())
	}

	// (a) PathMeld holds the sel..target chain: target at index 0 (BRANCHIND
	// input) and the selector as the earliest common Varnode.
	pm := model.GetPathMeld()
	if pm.NumCommonVarnode() != 7 {
		t.Fatalf("PathMeld numCommonVarnode = %d, want 7", pm.NumCommonVarnode())
	}
	if pm.Varnode(0) != branchind.Input(0) {
		t.Fatalf("PathMeld varnode[0] is not the BRANCHIND target input")
	}
	if pm.Varnode(pm.NumCommonVarnode()-1) != selector {
		t.Fatalf("PathMeld earliest varnode is not the selector")
	}

	// (b) Normalized range is exactly [0,8) starting at the selector.
	jr := model.GetValueRange()
	if jr.Size() != 8 {
		t.Fatalf("jrange size = %d, want 8", jr.Size())
	}
	if jr.StartVarnode() != selector {
		t.Fatalf("jrange start Varnode is not the selector")
	}

	// (c) Address table holds the 8 case targets = imageBase + RVA[i], in .text.
	if jt.NumEntries() != 8 {
		t.Fatalf("address table has %d entries, want 8", jt.NumEntries())
	}
	for i := 0; i < 8; i++ {
		got := jt.AddressByIndex(i).Offset
		want := switchImageBase + rvaFor(uint64(i))
		if got != want {
			t.Fatalf("case %d target = 0x%x, want 0x%x", i, got, want)
		}
		t.Logf("case %d -> 0x%x", i, got)
	}

	// (d) sanityCheck passed: RecoverAddresses returned nil above, and the model
	// reports a positive table size.
	if model.TableSize() != 8 {
		t.Fatalf("model TableSize = %d, want 8", model.TableSize())
	}
}

// TestJumpBasicRecoverAddressesSwitchExe re-runs the phase-2 gate but backs the
// table LOAD with the real switch.exe .text bytes, so the eight recovered
// targets are the true case-body addresses. switch.exe is gitignored; the test
// skips when it is absent (generate with `py -3 testdata/x64_switch/build.py`).
func TestJumpBasicRecoverAddressesSwitchExe(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	exePath := filepath.Join(filepath.Dir(file), "../../testdata/x64_switch/switch.exe")
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("switch.exe absent (run `py -3 testdata/x64_switch/build.py`): %v", err)
	}
	pf, err := pe.Open(exePath)
	if err != nil {
		t.Fatalf("pe.Open: %v", err)
	}
	defer pf.Close()

	readImage := func(vma uint64, sz int) (uint64, bool) {
		for _, s := range pf.Sections {
			start := switchImageBase + uint64(s.VirtualAddress)
			end := start + uint64(s.VirtualSize)
			if vma < start || vma+uint64(sz) > end {
				continue
			}
			raw, rerr := s.Data()
			if rerr != nil {
				return 0, false
			}
			fileOff := vma - start
			if fileOff+uint64(sz) > uint64(len(raw)) {
				return 0, false
			}
			var buf [8]byte
			copy(buf[:], raw[fileOff:fileOff+uint64(sz)])
			return binary.LittleEndian.Uint64(buf[:]), true
		}
		return 0, false
	}

	fd := newRulesFuncdata()
	fd.SetImageReader(func(a address.Address, sz int) (uint64, error) {
		v, hit := readImage(a.Offset, sz)
		if !hit {
			return 0, os.ErrNotExist
		}
		return v, nil
	})

	branchind, _ := buildHeritagedSwitch(fd)
	jt := NewJumpTable(branchind.Addr())
	jt.SetIndirectOp(branchind)
	if err := jt.RecoverAddresses(fd); err != nil {
		t.Fatalf("RecoverAddresses over switch.exe: %v", err)
	}
	if jt.NumEntries() != 8 {
		t.Fatalf("address table has %d entries, want 8", jt.NumEntries())
	}
	for i := 0; i < 8; i++ {
		got := jt.AddressByIndex(i).Offset
		rva, ok := readImage(switchTableVMA+uint64(i)*4, 4)
		if !ok {
			t.Fatalf("could not read switch.exe table[%d]", i)
		}
		want := switchImageBase + rva
		if got != want {
			t.Fatalf("case %d target = 0x%x, want 0x%x (imageBase + real RVA)", i, got, want)
		}
		if _, hit := readImage(got, 1); !hit {
			t.Fatalf("case %d target 0x%x not inside a mapped section", i, got)
		}
		t.Logf("case %d RVA 0x%x -> target 0x%x", i, rva, got)
	}
}
