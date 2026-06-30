package loader_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// x64CorpusEntry mirrors one function in testdata/x64_corpus/x64_goldens.json
// (produced by GenGoldens.java via Ghidra 12 headless on an MSVC x64 .obj).
type x64CorpusEntry struct {
	Name  string `json:"name"`
	Entry int64  `json:"entry"`
	Bytes string `json:"bytes"`
	C     string `json:"c"`
}

type x64CorpusFile struct {
	Functions []x64CorpusEntry `json:"functions"`
}

// normGhidraC canonicalizes decompiled C for structural comparison: CRLF->LF,
// strip per-line leading indentation (the stored goldens and the tree both emit
// at column 0), and trim. Indentation parity is a separate known gap.
func normGhidraC(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimLeft(lines[i], " \t")
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func hexToBytes(t *testing.T, h string) []byte {
	t.Helper()
	if len(h)%2 != 0 {
		t.Fatalf("odd hex length %d", len(h))
	}
	out := make([]byte, len(h)/2)
	for i := 0; i < len(out); i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := h[i*2+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				t.Fatalf("bad hex char %q", c)
			}
		}
		out[i] = b
	}
	return out
}

// TestX64CorpusGoldenMap (X64_CORPUS=1) runs the universal-action tree against
// the MSVC x64 (Windows ABI: RCX/RDX/R8/R9) breadth corpus and reports a
// match/mismatch map after indentation-insensitive normalization. Diagnostic
// only; measures how far the tree is from real x64 register-param functions.
func TestX64CorpusGoldenMap(t *testing.T) {
	if os.Getenv("X64_CORPUS") == "" {
		t.Skip("set X64_CORPUS=1 to run")
	}
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	goldenPath := filepath.Join(dir, "../../testdata/x64_corpus/x64_goldens.json")
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
	t.Logf("X64 CORPUS MAP: %d/%d match (indent-insensitive)", pass, len(gf.Functions))
}
