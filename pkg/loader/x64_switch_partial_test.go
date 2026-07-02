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
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// switchImageBase / switchTableVMA describe the fully-linked switch.exe used
// below: op_switch (FUN_140001000) is a dense 0..7 switch whose RVA table sits
// at 0x1400010B8 inside .text, and whose case targets are imageBase + RVA[i].
const (
	partialImageBase = uint64(0x140000000)
	partialTableVMA  = uint64(0x1400010B8)
)

// TestX64SwitchPartialHeritageRecovers is the B2 phase-3a isolation gate. It
// promotes the phase-2 hand-built SSA fixture (pcode/jumptable_recover_test.go
// buildHeritagedSwitch) to a REAL partial-Funcdata heritage over the actual
// switch.exe bytes:
//
//  1. bridge.BuildJumpTablePartial rebuilds a partial Funcdata from the same
//     instruction records the live Build path collects, but WITHOUT the raw-flow
//     BRANCHIND truncation (so the indirect jmp survives).
//  2. The "jumptable" action group (base+heritage, stackptrflow, stackvars, ...)
//     is run over the partial, putting the stack-routed selector -> table ->
//     BRANCHIND computation into SSA form -- exactly Ghidra's
//     Funcdata::stageJumpTable (funcdata_block.cc:491): truncatedFlow +
//     setCurrent("jumptable") + perform(partial) + jt->recoverAddresses(&partial).
//  3. JumpTable.RecoverAddresses over the heritage'd partial must recover the
//     eight case targets (imageBase + RVA[i]), a [0,8) normalized range, and pass
//     the model sanity check -- proving findDeterminingVarnodes feeds off the real
//     partial SSA, not a synthetic fixture.
//
// This is an ISOLATION test: it drives the partial mechanism only. The live
// pipeline (bridge.Build -> RecoverJumpTables -> Decompile) is untouched, so the
// live switch.exe decompile still truncates the BRANCHIND to a CALLIND and the
// X64_SWITCH golden still MISMATCHes (integration is phase 3b/3c).
//
// switch.exe is gitignored; the test skips when it is absent (generate with
// `py -3 testdata/x64_switch/build.py`).
func TestX64SwitchPartialHeritageRecovers(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)

	exePath := filepath.Join(dir, "../../testdata/x64_switch/switch.exe")
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("switch.exe absent (run `py -3 testdata/x64_switch/build.py`): %v", err)
	}

	// Independent reader of the real table bytes for the expected targets.
	pf, err := pe.Open(exePath)
	if err != nil {
		t.Fatalf("pe.Open: %v", err)
	}
	defer pf.Close()
	readImage := func(vma uint64, sz int) (uint64, bool) {
		for _, s := range pf.Sections {
			start := partialImageBase + uint64(s.VirtualAddress)
			end := start + uint64(s.VirtualSize)
			if vma < start || vma+uint64(sz) > end {
				continue
			}
			raw, rerr := s.Data()
			if rerr != nil {
				return 0, false
			}
			off := vma - start
			if off+uint64(sz) > uint64(len(raw)) {
				return 0, false
			}
			var buf [8]byte
			copy(buf[:], raw[off:off+uint64(sz)])
			return binary.LittleEndian.Uint64(buf[:]), true
		}
		return 0, false
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

	// Build the jump-table partial (NO live truncation) from the same records as
	// bridge.Build would collect.
	partial, err := bridge.BuildJumpTablePartial(engine, bridge.BuildConfig{
		Name: "FUN_140001000", Entry: base, MaxInstructions: 200,
		CspecPath: cspec, SymbolName: "FUN_140001000",
	})
	if err != nil {
		t.Fatalf("BuildJumpTablePartial: %v", err)
	}
	if len(partial.BranchInds) != 1 {
		t.Fatalf("partial has %d surviving BRANCHIND ops, want 1", len(partial.BranchInds))
	}
	branchind := partial.BranchInds[0]
	fd := partial.Funcdata

	// Run the "jumptable" heritage action group over the partial. This is the
	// mechanism under test: it must SSA-form the stack-routed selector chain.
	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC during jumptable-group heritage on partial: %v", r)
			}
		}()
		db.SetCurrent("jumptable").Perform(fd)
	}()

	// The BRANCHIND target input must now be an SSA-written varnode (heritage fed
	// findDeterminingVarnodes a real reaching-def chain, not a raw free read).
	tgt := branchind.Input(0)
	if tgt == nil {
		t.Fatal("BRANCHIND has no target input after heritage")
	}
	if !tgt.IsWritten() {
		t.Fatalf("BRANCHIND target %v is not SSA-written after jumptable heritage "+
			"(partial heritage did not put the address computation in SSA form)", tgt)
	}

	// Recover the address table off the heritage'd partial.
	jt := pcode.NewJumpTable(branchind.Addr())
	jt.SetIndirectOp(branchind)
	if err := jt.RecoverAddresses(fd); err != nil {
		t.Fatalf("RecoverAddresses over real partial-heritage: %v", err)
	}

	// (a) sanity: model recovered with a positive table size.
	model, ok := jt.JumpModel().(*pcode.JumpBasic)
	if !ok {
		t.Fatalf("expected *JumpBasic model, got %T", jt.JumpModel())
	}
	if model.TableSize() != 8 {
		t.Fatalf("model TableSize = %d, want 8 (sanityCheck)", model.TableSize())
	}

	// (b) normalized range is exactly [0,8).
	jr := model.GetValueRange()
	if jr.Size() != 8 {
		t.Fatalf("jrange size = %d, want 8", jr.Size())
	}

	// (c) the eight case targets = imageBase + real RVA[i], each inside .text.
	if jt.NumEntries() != 8 {
		t.Fatalf("address table has %d entries, want 8", jt.NumEntries())
	}
	for i := 0; i < 8; i++ {
		got := jt.AddressByIndex(i).Offset
		rva, okRVA := readImage(partialTableVMA+uint64(i)*4, 4)
		if !okRVA {
			t.Fatalf("could not read switch.exe table[%d]", i)
		}
		want := partialImageBase + rva
		if got != want {
			t.Fatalf("case %d target = 0x%x, want 0x%x (imageBase + real RVA)", i, got, want)
		}
		if _, hit := readImage(got, 1); !hit {
			t.Fatalf("case %d target 0x%x not inside a mapped section", i, got)
		}
		t.Logf("case %d RVA 0x%x -> target 0x%x", i, rva, got)
	}
}
