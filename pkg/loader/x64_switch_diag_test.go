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

// TestX64SwitchGoldenMap (X64_SWITCH=1) is the track B / B1 end-to-end harness:
// it loads the fully-linked PE32+ switch.exe by mapping its sections at their
// real virtual addresses, decompiles the target function FUN_140001000
// (op_switch, VMA 0x140001000), and compares against the Ghidra switch golden.
//
// B1 covers only the loader + harness wiring. Real jump-table recovery
// (JumpBasic / EmulateFunction, jumptable.go) is B2 and is intentionally NOT
// touched here, so the BRANCHIND of the dense switch is demoted to a CALLIND by
// Component 1's truncateIndirectJump fallback. A MISMATCH is therefore the
// expected B1 outcome (CALLIND fallback vs a real switch); the test logs WANT
// (switch golden) vs GOT (current output) to document the B2 gap. Success for
// B1 is that switch.exe loads and the function decompiles end-to-end without
// panic/error and the harness reports MATCH/MISMATCH -- not a golden MATCH.
//
// switch.exe is gitignored; on a fresh checkout it is absent, so the test skips
// (generate it with `py -3 testdata/x64_switch/build.py`). The golden JSON is
// tracked. Reuses the x64CorpusEntry/x64CorpusFile/normGhidraC helpers from
// x64_corpus_diag_test.go, but drives an .exe section-load path instead of raw
// base-0 bytes.
func TestX64SwitchGoldenMap(t *testing.T) {
	if os.Getenv("X64_SWITCH") == "" {
		t.Skip("set X64_SWITCH=1 to run")
	}
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)

	exePath := filepath.Join(dir, "../../testdata/x64_switch/switch.exe")
	if _, err := os.Stat(exePath); err != nil {
		t.Skipf("switch.exe absent (run `py -3 testdata/x64_switch/build.py`): %v", err)
	}

	goldenPath := filepath.Join(dir, "../../testdata/x64_switch/x64_switch_goldens.json")
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read goldens: %v", err)
	}
	var gf x64CorpusFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		t.Fatalf("unmarshal goldens: %v", err)
	}

	// Locate the target function golden (op_switch = FUN_140001000).
	var target *x64CorpusEntry
	for i := range gf.Functions {
		if gf.Functions[i].Name == "FUN_140001000" {
			target = &gf.Functions[i]
			break
		}
	}
	if target == nil {
		t.Fatal("golden FUN_140001000 not found")
	}
	entryVMA := uint64(target.Entry) // 0x140001000

	sla := filepath.Join(dir, "../sla/testdata/x86-64-packed.sla")
	pspec := filepath.Join(dir, "../../testdata/sla/x86-64.pspec")
	cspec := filepath.Join(dir, "../../testdata/sla/x86-64-win.cspec")

	// Map .text (code + this corpus's jump table) and .rdata (jump tables in the
	// general MSVC case) at their real VMAs. The absolute `lea rcx,[0x140000000]`
	// image-base reference the function issues can only resolve when sections sit
	// at their linked virtual addresses -- the golden bytes-only path cannot do
	// this, which is why B1 needs the .exe section-load path.
	sections, err := loader.LoadPESections(exePath, ".text", ".rdata")
	if err != nil {
		t.Fatalf("LoadPESections: %v", err)
	}
	for _, s := range sections {
		t.Logf("mapped section %-6s VMA 0x%x (%d bytes)", s.Name, s.VMA, len(s.Bytes))
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
	if base.Offset != entryVMA {
		t.Fatalf("entry VMA mismatch: got 0x%x want 0x%x", base.Offset, entryVMA)
	}

	// Inject the fully-locked prototype Ghidra's headless analyzer committed for
	// this function before decompiling, captured from the core's debug archive
	// (scratchpad debug_op_switch.xml, <prototype extrapop="8" model="__fastcall"
	// modellock="true">): return uint@EAX(register:0x0,size4) typelock; params
	// param_1 undefined4@ECX(0x8), param_2 uint@EDX(0x10), param_3 uint@R8D(0x80),
	// all typelock+namelock. The output lock is what forces the distinct `uVar1`
	// return carrier in the golden (without it the return reuses the operand).
	tf := pcode.NewTypeFactory()
	uintT := tf.GetBase(4, pcode.TYPE_UINT, "uint")
	undef4 := tf.GetBase(4, pcode.TYPE_UNKNOWN, "undefined4")
	injProto := &bridge.InjectedPrototype{
		Model:     "__fastcall",
		ModelLock: true,
		Return: bridge.InjectedProtoParam{
			Name: "", Register: "EAX", Size: 4, Type: uintT, TypeLock: true,
		},
		// merge="false" (isolate) on every committed param -- measured in the
		// savefile debug_op_switch.xml -- is what makes the C++ core reject the
		// accumulator<->param_2 speculative merge (mergeTestAdjacent isolated guard),
		// producing the distinct `uVar1` return carrier.
		Params: []bridge.InjectedProtoParam{
			{Name: "param_1", Register: "ECX", Size: 4, Type: undef4, TypeLock: true, NameLock: true, Isolate: true},
			{Name: "param_2", Register: "EDX", Size: 4, Type: uintT, TypeLock: true, NameLock: true, Isolate: true},
			{Name: "param_3", Register: "R8D", Size: 4, Type: uintT, TypeLock: true, NameLock: true, Isolate: true},
		},
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name: target.Name, Entry: base, MaxInstructions: 200,
		CspecPath: cspec, SymbolName: target.Name,
		InjectedPrototype: injProto,
	})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}
	fd := result.Funcdata

	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("[%s] PANIC during decompile: %v", target.Name, r)
			}
		}()
		db.SetCurrent("decompile").Perform(fd)
	}()

	out, err := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).SetGhidraFormat().Emit(fd)
	if err != nil {
		t.Fatalf("[%s] EMIT-ERR: %v", target.Name, err)
	}

	want := normGhidraC(target.C)
	got := normGhidraC(out)
	if want == got {
		// Not expected in B1: would mean jump-table recovery already works.
		t.Logf("[%s] MATCH (unexpected in B1 -- recovery may already be wired)", target.Name)
	} else {
		// Expected B1 outcome: BRANCHIND demoted to CALLIND (no JumpBasic model
		// yet), so the switch is not reconstructed. WANT/GOT documents the B2 gap.
		t.Logf("[%s] MISMATCH (expected in B1: CALLIND fallback vs real switch)\n--- WANT (switch golden) ---\n%s\n--- GOT (B1, recovery stubbed) ---\n%s", target.Name, want, got)
	}
}
