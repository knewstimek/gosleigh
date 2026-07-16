package loader_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// loadChunk is one disjoint image chunk (bytes at a specific VMA). Ghidra's
// loadimage feeds the decompiler a sparse set of these; a function's body and
// its out-of-line default/case blocks can sit at non-contiguous VMAs.
type loadChunk struct {
	VMA uint64 `json:"vma"`
	Hex string `json:"hex"`
}

// loadImageFixture is the optional per-function loadimage override captured from
// Ghidra headless debug XML (see testdata/x64_breadth/dispatch_loadimage.json).
// When a function name is present here, the harness maps each chunk at its real
// VMA instead of packing the golden's single contiguous "bytes" blob at Entry.
// This matters when Ghidra saw multiple disjoint code chunks (e.g. dispatch's
// switch default block lives 56 bytes past the fall-through body); packing them
// contiguously puts the default block at the wrong VA so a range-guard branch
// target stays undecoded.
type loadImageFixture struct {
	Source    string                 `json:"source"`
	Functions map[string][]loadChunk `json:"functions"`
}

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

	// Optional per-function loadimage override: functions listed here are mapped
	// as multiple disjoint chunks at their real VMAs (matching Ghidra's
	// loadimage) instead of a single contiguous blob at Entry. Absent file or
	// absent function name -> the single-blob path (dist_sq/sum2d) is unchanged.
	var liFix loadImageFixture
	liPath := filepath.Join(dir, "../../testdata/x64_breadth/dispatch_loadimage.json")
	if liRaw, liErr := os.ReadFile(liPath); liErr == nil {
		if uErr := json.Unmarshal(liRaw, &liFix); uErr != nil {
			t.Fatalf("unmarshal loadimage fixture: %v", uErr)
		}
	}

	pass := 0
	for _, fn := range gf.Functions {
		// Resolve the loadimage for this function: fixture chunks if present,
		// otherwise the golden's single contiguous "bytes" at Entry.
		chunks := liFix.Functions[fn.Name]
		if len(chunks) == 0 {
			chunks = []loadChunk{{VMA: uint64(fn.Entry), Hex: fn.Bytes}}
		}
		// First chunk is the entry blob; any remaining chunks are mapped at their
		// own VMAs via Sections so the sparse image matches what Ghidra fed the
		// decompiler (e.g. dispatch's default block at 0x2524, past a 56-byte gap).
		var sections []loader.PESection
		for _, ch := range chunks[1:] {
			sections = append(sections, loader.PESection{
				Name:  fmt.Sprintf("chunk_%x", ch.VMA),
				VMA:   ch.VMA,
				Bytes: hexToBytes(t, ch.Hex),
			})
		}
		// Load each function at its true VA (Ghidra placed the breadth.obj
		// functions at these addresses during analysis). This matters for
		// RIP-relative operands: dispatch resolves &__ImageBase and its jump
		// table via lea [rip+disp], so the absolute constants only match the golden
		// when the function sits at its real VA. Loading at base 0 shifts every
		// RIP-derived constant down by fn.Entry.
		engine, base, err := (&loader.EngineBuilder{
			SLAPath: sla, PspecPath: pspec,
			Bytes: hexToBytes(t, chunks[0].Hex), BaseAddr: chunks[0].VMA,
			Sections: sections,
		}).Build()
		if err != nil {
			t.Logf("[%s] BUILD-ERR: %v", fn.Name, err)
			continue
		}
		// Inject the __ImageBase global symbol the way Ghidra's headless analysis
		// supplies it to the decompiler core. Source: measured Ghidra 12.0.4
		// headless debug XML for dispatch (debug_dispatch.xml) --
		//   <symbol name="__ImageBase" typelock="true" namelock="true" .../>
		//   <addr space="ram" offset="0x3610" size="1"/> typeref undefined(size 1)
		// It lets ActionConstantPtr promote the constant image base in dispatch to
		// a &__ImageBase reference. Harmless for functions that never reference it.
		undef1 := pcode.NewTypeFactory().GetBase(1, pcode.TYPE_UNKNOWN, "undefined")
		injected := []bridge.InjectedGlobal{{
			Name: "__ImageBase", Space: base.Space, Offset: 0x3610, Size: 1,
			Type: undef1, TypeLock: true, NameLock: true,
		}}
		result, err := bridge.Build(engine, bridge.BuildConfig{
			Name: fn.Name, Entry: base, MaxInstructions: 200,
			CspecPath: cspec, SymbolName: fn.Name,
			InjectedGlobals: injected,
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
