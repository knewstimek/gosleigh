package loader_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

// buildGcd builds the MSVC x86-32 gcd function to a fresh (pre-analysis) bridge
// Result. The Funcdata carries its analysis context (graph + heritage spaces) so
// the universal-action tree can run self-contained.
func buildGcd(t *testing.T) (*sla.Engine, *bridge.Result) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")
	cspecPath := filepath.Join(dir, "../../testdata/sla/x86gcc.cspec")
	prog := []byte{0x8b, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x04, 0x85, 0xc9, 0x74, 0x0b, 0x99, 0xf7, 0xf9, 0x8b, 0xc1, 0x8b, 0xca, 0x85, 0xd2, 0x75, 0xf5, 0xc3}
	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// The faithful spacebase stack-recovery path reads the stack pointer register
	// from the compiler spec (Ghidra's <stackpointer> lives in the .cspec), so the
	// universal tree needs the cspec to mark ESP as the stack spacebase. This is a
	// processEntry entry-point function, so EntryPoint is set (matches the TREE_MAP
	// gcd case in tree_fullmap_diag_test.go, which produces byte-identical output).
	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60, CspecPath: cspecPath, EntryPoint: true})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}
	return engine, result
}

// TestUniversalActionTreeGcdGolden is the #1-gate regression guard: the faithful
// universal-action tree (BuildUniversalAction + BuildDefaultGroups +
// SetCurrent("decompile")) must emit gcd byte-identically to the Ghidra golden.
// This proves the tree -- not the 41-call hand-ordered subset -- produces correct
// output, including the do-while->while loop rotation (H8-debt-2 step3b: faithful
// RuleCondNegate, NodeJoin/NormalizeBranches/InferTypes flags=0, BlockCopy edge
// forwarding in NegateCondition, and RulePushMultiME).
func TestUniversalActionTreeGcdGolden(t *testing.T) {
	engine, result := buildGcd(t)
	fd := result.Funcdata

	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	act := db.SetCurrent("decompile")
	act.Perform(fd)

	out, err := pcode.NewPrintC().
		SetRegisterNames(engine.RegisterNamesByLocation()).
		SetProcessEntry("processEntry", 2).
		SetGhidraFormat().
		Emit(fd)
	if err != nil {
		t.Fatalf("PrintC: %v", err)
	}
	assertGoldenMatch(t, "gcd_x86_32", out)
}

// countOpcode returns the number of live ops of the given opcode in fd.
func countOpcode(fd *pcode.Funcdata, code pcode.OpCode) int {
	n := 0
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() == code {
			n++
		}
	}
	return n
}

// TestUniversalActionHeritageBuildsSSA verifies the first H8-debt-2 fill: the
// universal-tree ActionHeritage (via Funcdata.OpHeritage, using the attached
// analysis context) actually constructs SSA. Before this fill OpHeritage was an
// empty stub, so the tree's ActionHeritage was a no-op and the whole tree was
// hollow. gcd has a loop, so heritage must place MULTIEQUAL phi nodes.
func TestUniversalActionHeritageBuildsSSA(t *testing.T) {
	_, result := buildGcd(t)
	fd := result.Funcdata

	if got := countOpcode(fd, pcode.CPUI_MULTIEQUAL); got != 0 {
		t.Fatalf("pre-heritage MULTIEQUAL count = %d, want 0 (raw p-code has no phis)", got)
	}

	// Run the universal-tree heritage action directly.
	pcode.NewActionHeritage("base").Apply(fd)

	if got := countOpcode(fd, pcode.CPUI_MULTIEQUAL); got == 0 {
		t.Fatalf("post-ActionHeritage MULTIEQUAL count = 0, want > 0 (heritage must place loop phis)")
	}
}

// NOTE: running the FULL universal-action tree (db.BuildUniversalAction +
// BuildDefaultGroups + SetCurrent("decompile") + Perform) on gcd does NOT
// converge today -- it spins. Two reasons, both H8-debt-2 work items:
//  1. Many tree action bodies are still hollow/unported (delegate to stub
//     Funcdata methods), so the pipeline cannot reach a correct fixpoint.
//  2. ActionBase.Perform's repeat-apply loop (action.go ~279) has no
//     max-iteration safety cap, so a non-converging action loops forever.
// A converging, end-to-end tree run is the goal of filling the action bodies;
// until then this diagnostic is intentionally omitted (a hanging test is not
// committable). The focused test above proves the first filled body (heritage).
