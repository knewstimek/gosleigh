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

// TestJumpValuesRangeEnumeratesDenseRange is the B2a gate: a [0,8) step-1
// CircleRange must enumerate exactly the eight values 0..7 through the
// JumpValuesRange iterator, using the real circlerange.go semantics.
func TestJumpValuesRangeEnumeratesDenseRange(t *testing.T) {
	jv := NewJumpValuesRange()
	jv.SetRange(newCircleRangeBounds(0, 8, 4, 1)) // [0,8) domain 4 bytes, step 1

	if got := jv.Size(); got != 8 {
		t.Fatalf("Size() = %d, want 8", got)
	}

	var vals []uint64
	if jv.InitializeForReading() {
		vals = append(vals, jv.Value())
		for jv.Next() {
			vals = append(vals, jv.Value())
		}
	}
	want := []uint64{0, 1, 2, 3, 4, 5, 6, 7}
	if len(vals) != len(want) {
		t.Fatalf("enumerated %d values %v, want %d", len(vals), vals, len(want))
	}
	for i := range want {
		if vals[i] != want[i] {
			t.Fatalf("value[%d] = %d, want %d (full: %v)", i, vals[i], want[i], vals)
		}
	}
	// Membership checks through the ported CircleRange.contains.
	if !jv.Contains(7) || jv.Contains(8) {
		t.Fatalf("Contains parity wrong: contains(7)=%v contains(8)=%v", jv.Contains(7), jv.Contains(8))
	}
}

// switchImageBase and switchTableVMA describe the fully-linked switch.exe
// corpus (op_switch, FUN_140001000): a dense 0..7 switch whose 8-entry RVA
// table sits inside .text at VMA 0x1400010B8. target = imageBase + RVA.
const (
	switchImageBase = uint64(0x140000000)
	switchTableVMA  = uint64(0x1400010B8)
)

// buildSwitchPath constructs the hand-written jump-table computation path used
// by the B2b emulator gate, matching the shape Ghidra melds for a dense RVA
// switch:
//
//	sel  = INT_SEXT(selector)        ; widen 4-byte index to 8 bytes
//	off  = INT_MULT(sel, 4)          ; scale by entry size
//	adr  = INT_ADD(off, tableVMA)    ; address of table[sel]
//	rva  = LOAD(ram, adr)            ; 4-byte RVA at table[sel]
//	rvaz = INT_ZEXT(rva)             ; widen to 8 bytes
//	tgt  = INT_ADD(rvaz, imageBase)  ; absolute target = imageBase + RVA
//	BRANCHIND(tgt)
//
// It returns the PathMeld ordered as Ghidra does (index 0 = BRANCHIND, highest
// index = the SEXT where the value is injected), plus the selector Varnode and
// the SEXT start op.
func buildSwitchPath(data *Funcdata) (pm *PathMeld, startop *PcodeOp, selector *Varnode) {
	ram := data.BaseAddr().Space
	selector = newRuleInput(data, 4, 0x40) // free 4-byte switch index

	sext := newRuleOp(data, CPUI_INT_SEXT, 8, selector)
	mult := newRuleOp(data, CPUI_INT_MULT, 8, sext.Output(), data.NewConstant(8, 4))
	addr := newRuleOp(data, CPUI_INT_ADD, 8, mult.Output(), data.NewConstant(8, switchTableVMA))
	spaceID := data.NewSpaceIDConst(ram)
	load := newRuleOp(data, CPUI_LOAD, 4, spaceID, addr.Output())
	zext := newRuleOp(data, CPUI_INT_ZEXT, 8, load.Output())
	tgt := newRuleOp(data, CPUI_INT_ADD, 8, zext.Output(), data.NewConstant(8, switchImageBase))
	branchind := newRuleOp(data, CPUI_BRANCHIND, 8, tgt.Output())

	// PathMeld op order: BRANCHIND first, source SEXT last.
	pm = &PathMeld{}
	pm.opMeld = []pathMeldRootedOp{
		{op: branchind, rootVn: 0},
		{op: tgt, rootVn: 0},
		{op: zext, rootVn: 0},
		{op: load, rootVn: 0},
		{op: addr, rootVn: 0},
		{op: mult, rootVn: 0},
		{op: sext, rootVn: 0},
	}
	pm.commonVn = []*Varnode{selector}
	return pm, sext, selector
}

// TestEmulatePathStubImageResolvesCase3 exercises the full B2b computational
// core with a synthetic image reader, independent of switch.exe: it verifies
// the SEXT/MULT/ADD address arithmetic (via the collected LoadTable), the LOAD
// dispatch through the image hook, and the final imageBase+RVA target for
// selector value 3.
func TestEmulatePathStubImageResolvesCase3(t *testing.T) {
	data := newRulesFuncdata()
	// Synthetic RVA table: case k -> RVA 0x1200 + k*0x10.
	rvaFor := func(k uint64) uint64 { return 0x1200 + k*0x10 }
	data.SetImageReader(func(a address.Address, sz int) (uint64, error) {
		// table[k] lives at switchTableVMA + k*4.
		k := (a.Offset - switchTableVMA) / 4
		return rvaFor(k), nil
	})

	pm, startop, selector := buildSwitchPath(data)

	var loads []LoadTable
	emul := NewEmulateFunction(data)
	emul.SetLoadCollect(&loads)

	got, err := emul.EmulatePath(3, pm, startop, selector)
	if err != nil {
		t.Fatalf("EmulatePath(3): %v", err)
	}
	wantTarget := switchImageBase + rvaFor(3)
	if got != wantTarget {
		t.Fatalf("target = 0x%x, want 0x%x (imageBase + RVA[3])", got, wantTarget)
	}

	// The load address must be table[3] = tableVMA + 3*4, size 4.
	if len(loads) != 1 {
		t.Fatalf("collected %d load points, want 1", len(loads))
	}
	wantLoadOff := switchTableVMA + 3*4
	if loads[0].Addr.Offset != wantLoadOff || loads[0].Size != 4 {
		t.Fatalf("load point = %v size %d, want offset 0x%x size 4", loads[0].Addr, loads[0].Size, wantLoadOff)
	}
}

// TestEmulatePathReadsSwitchExeRVA is the B2b image-read gate: it drives the
// same hand-built path but backs the LOAD with the real switch.exe .text bytes,
// reading the true RVA at table[3] and checking the emulator produces
// imageBase + RVA. switch.exe is gitignored; the test skips when it is absent
// (generate it with `py -3 testdata/x64_switch/build.py`).
func TestEmulatePathReadsSwitchExeRVA(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	exePath := filepath.Join(dir, "../../testdata/x64_switch/switch.exe")
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("switch.exe absent (run `py -3 testdata/x64_switch/build.py`): %v", err)
	}

	pf, err := pe.Open(exePath)
	if err != nil {
		t.Fatalf("pe.Open: %v", err)
	}
	defer pf.Close()

	// Map a VMA to file bytes via the PE section headers (VMA = imageBase +
	// VirtualAddress). This is the test's stand-in for the section-mapped
	// backend; it lets the pcode package read the image without importing the
	// loader (which would form an import cycle).
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

	// Independently read the true RVA at table[3] to compute the expected target.
	rva3, ok := readImage(switchTableVMA+3*4, 4)
	if !ok {
		t.Fatalf("could not read switch.exe table[3] at VMA 0x%x", switchTableVMA+3*4)
	}
	wantTarget := switchImageBase + rva3
	t.Logf("switch.exe table[3] RVA = 0x%x -> target 0x%x", rva3, wantTarget)

	data := newRulesFuncdata()
	data.SetImageReader(func(a address.Address, sz int) (uint64, error) {
		v, hit := readImage(a.Offset, sz)
		if !hit {
			return 0, os.ErrNotExist
		}
		return v, nil
	})

	pm, startop, selector := buildSwitchPath(data)
	emul := NewEmulateFunction(data)

	got, err := emul.EmulatePath(3, pm, startop, selector)
	if err != nil {
		t.Fatalf("EmulatePath(3) over switch.exe: %v", err)
	}
	if got != wantTarget {
		t.Fatalf("target = 0x%x, want 0x%x (imageBase + real RVA[3])", got, wantTarget)
	}
	// Sanity: the recovered target must land inside .text (a real case body).
	if _, hit := readImage(got, 1); !hit {
		t.Fatalf("recovered target 0x%x does not fall inside a mapped section", got)
	}
}
