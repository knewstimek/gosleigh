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

package loader_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// TestX64SwitchCFGIntegration is the B2 phase-3b CFG gate. Unlike the phase-3a
// isolation test (which drives the partial mechanism by hand), this exercises
// the LIVE bridge.Build path end to end and asserts the recovered jump table is
// integrated into the main Funcdata's control-flow graph:
//
//	(a) the BRANCHIND survives as a BRANCHIND (it was NOT truncated to a CALLIND),
//	(b) the main fd has one jump table with the eight case entries,
//	(c) all eight case-body targets are decoded (their instruction addresses
//	    appear as live ops -- pre-3b they were unreachable and never decoded),
//	(d) the BRANCHIND's parent block has exactly eight out-edges (one per case),
//	(e) dominator recomputation over the switch graph did not panic.
//
// This is CFG-level: switchOver/default marking (3c) and switch{case}/label
// rendering (phase 4) are out of scope, so the C output is not asserted here.
//
// switch.exe is gitignored; the test skips when it is absent (generate with
// `py -3 testdata/x64_switch/build.py`).
func TestX64SwitchCFGIntegration(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)

	exePath := filepath.Join(dir, "../../testdata/x64_switch/switch.exe")
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("switch.exe absent (run `py -3 testdata/x64_switch/build.py`): %v", err)
	}

	entryVMA := uint64(0x140001000)
	sla := filepath.Join(dir, "../sla/testdata/x86-64-packed.sla")
	pspec := filepath.Join(dir, "../../testdata/sla/x86-64.pspec")
	cspec := filepath.Join(dir, "../../testdata/sla/x86-64-win.cspec")

	sections, err := loader.LoadPESections(exePath, ".text", ".rdata")
	if err != nil {
		t.Fatalf("LoadPESections: %v", err)
	}
	engine, base, err := (&loader.EngineBuilder{
		SLAPath:   sla,
		PspecPath: pspec,
		BaseAddr:  entryVMA,
		Sections:  sections,
	}).Build()
	if err != nil {
		t.Fatalf("EngineBuilder.Build: %v", err)
	}

	// (e) Build drives the live recovery + case decode + edge insertion, then
	// recomputes dominators over the completed switch graph. A panic here fails.
	var result *bridge.Result
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC during bridge.Build (dominator recompute over switch CFG): %v", r)
			}
		}()
		result, err = bridge.Build(engine, bridge.BuildConfig{
			Name: "FUN_140001000", Entry: base, MaxInstructions: 200,
			CspecPath: cspec, SymbolName: "FUN_140001000",
		})
	}()
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}
	fd := result.Funcdata

	// (b) exactly one jump table with eight entries, registered on the main fd.
	if fd.NumJumpTables() != 1 {
		t.Fatalf("NumJumpTables = %d, want 1", fd.NumJumpTables())
	}
	jt := fd.GetJumpTable(0)
	if jt == nil {
		t.Fatal("GetJumpTable(0) is nil")
	}
	if jt.NumEntries() != 8 {
		t.Fatalf("jump table NumEntries = %d, want 8", jt.NumEntries())
	}

	// (a) the BRANCHIND is still a BRANCHIND. Collect live op addresses at the
	// same time for the case-decode check below.
	liveOffsets := make(map[uint64]struct{})
	var branchind *pcode.PcodeOp
	callindAtBranch := false
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		liveOffsets[op.Addr().Offset] = struct{}{}
		switch op.Code() {
		case pcode.CPUI_BRANCHIND:
			if op.Addr().Offset == jt.OpAddress().Offset {
				branchind = op
			}
		case pcode.CPUI_CALLIND:
			if op.Addr().Offset == jt.OpAddress().Offset {
				callindAtBranch = true
			}
		}
	}
	if callindAtBranch {
		t.Fatal("indirect jump was truncated to a CALLIND (recovery not integrated)")
	}
	if branchind == nil {
		t.Fatal("no live BRANCHIND at the jump-table op address (survival check failed)")
	}

	// (c) all eight case-body targets decoded as live ops.
	for i := 0; i < jt.NumEntries(); i++ {
		off := jt.AddressByIndex(i).Offset
		if _, ok := liveOffsets[off]; !ok {
			t.Fatalf("case %d target 0x%x not decoded (no live op at that address)", i, off)
		}
	}

	// (d) the BRANCHIND parent block has one out-edge per case.
	parent := branchind.Parent()
	if parent == nil {
		t.Fatal("BRANCHIND has no parent block")
	}
	if parent.SizeOut() != 8 {
		t.Fatalf("BRANCHIND parent out-edges = %d, want 8 (one per case)", parent.SizeOut())
	}

	t.Logf("CFG OK: BRANCHIND survived, 1 table x 8 entries, 8 case bodies decoded, %d out-edges", parent.SizeOut())
}
