package loader_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// TestX64BreadthGoldenMap (X64_BREADTH=1) runs the universal-action tree against
// the breadth extension corpus (testdata/x64_breadth: struct field access, 2D
// array indexing, dense jump-table switch) and reports a match/mismatch map.
// Diagnostic only -- it measures how far the tree is from real x64 patterns
// absent from the base x64_corpus. Reuses the x64CorpusEntry/normGhidraC/
// hexToBytes helpers defined in x64_corpus_diag_test.go.
func TestX64BreadthGoldenMap(t *testing.T) {
	if os.Getenv("X64_BREADTH") == "" {
		t.Skip("set X64_BREADTH=1 to run")
	}
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	goldenPath := filepath.Join(dir, "../../testdata/x64_breadth/x64_breadth_goldens.json")
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read goldens: %v", err)
	}
	var gf x64CorpusFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		t.Fatalf("unmarshal goldens: %v", err)
	}

	sla := filepath.Join(dir, "../sla/testdata/x86-64-packed.sla")
	pspec := filepath.Join(dir, "../../testdata/sla/x86-64.pspec")
	cspec := filepath.Join(dir, "../../testdata/sla/x86-64-win.cspec")

	pass := 0
	for _, fn := range gf.Functions {
		prog := hexToBytes(t, fn.Bytes)
		engine, base, err := (&loader.EngineBuilder{SLAPath: sla, PspecPath: pspec, Bytes: prog}).Build()
		if err != nil {
			t.Logf("[%s] BUILD-ERR: %v", fn.Name, err)
			continue
		}
		result, err := bridge.Build(engine, bridge.BuildConfig{
			Name: fn.Name, Entry: base, MaxInstructions: 200,
			CspecPath: cspec, SymbolName: fn.Name,
		})
		if err != nil {
			t.Logf("[%s] BRIDGE-ERR: %v", fn.Name, err)
			continue
		}
		fd := result.Funcdata
		db := pcode.NewActionDatabase()
		db.BuildUniversalAction(nil)
		db.BuildDefaultGroups()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("[%s] PANIC: %v", fn.Name, r)
				}
			}()
			db.SetCurrent("decompile").Perform(fd)
		}()
		out, err := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).SetGhidraFormat().Emit(fd)
		if err != nil {
			t.Logf("[%s] EMIT-ERR: %v", fn.Name, err)
			continue
		}
		want := normGhidraC(fn.C)
		got := normGhidraC(out)
		if want == got {
			pass++
			t.Logf("[%s] MATCH", fn.Name)
		} else {
			t.Logf("[%s] MISMATCH\n--- WANT ---\n%s\n--- GOT ---\n%s", fn.Name, want, got)
		}
	}
	t.Logf("X64 BREADTH MAP: %d/%d match (indent-insensitive)", pass, len(gf.Functions))
}
