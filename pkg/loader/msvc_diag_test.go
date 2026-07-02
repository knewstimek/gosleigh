package loader_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// goldenEntry mirrors the structure of each entry in ghidra_golden.json.
type goldenEntry struct {
	Functions []struct {
		Name string `json:"name"`
		C    string `json:"c"`
	} `json:"functions"`
}

// loadGhidraGolden reads testdata/ghidra_golden/ghidra_golden.json (relative
// to the test file) and returns the expected C string for the given key.
// The leading/trailing newline that Ghidra includes is kept as-is.
func loadGhidraGolden(t *testing.T, key string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	jsonPath := filepath.Join(dir, "../../testdata/ghidra_golden/ghidra_golden.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("loadGhidraGolden: read %s: %v", jsonPath, err)
	}
	var all map[string]goldenEntry
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatalf("loadGhidraGolden: unmarshal: %v", err)
	}
	entry, ok := all[key]
	if !ok {
		t.Fatalf("loadGhidraGolden: key %q not found in golden JSON", key)
	}
	if len(entry.Functions) == 0 {
		t.Fatalf("loadGhidraGolden: key %q has no functions", key)
	}
	return entry.Functions[0].C
}

// vnStr formats a Varnode as space:0xoff[size]#hv<flags> for SSA diagnosis.
// flags: I=input, T=addrtied. Used only by dumpSSA.
func vnStr(vn *pcode.Varnode) string {
	if vn == nil {
		return "<nil>"
	}
	name := ""
	if hv := vn.High(); hv != nil {
		name = hv.Name()
	}
	flags := ""
	if vn.IsInput() {
		flags += "I"
	}
	if vn.IsAddrTied() {
		flags += "T"
	}
	sp := "?"
	if vn.Space() != nil {
		sp = vn.Space().Name
	}
	return fmt.Sprintf("%s:0x%x[%d]#%s%s", sp, vn.Offset(), vn.Size(), name, flags)
}

// dumpSSA prints the SSA op stream block-by-block for diagnosis. Guarded by the
// GCD_DUMP env var so it stays silent in normal runs. Lets us correlate the
// loop-head COPY / addr-tied phi shape against the Ghidra-intended structure.
func dumpSSA(t *testing.T, fd *pcode.Funcdata, label string) {
	if os.Getenv("GCD_DUMP") == "" {
		return
	}
	t.Helper()
	var sb strings.Builder
	sb.WriteString("=== SSA DUMP: " + label + " ===\n")
	bg := fd.GetBasicBlocks()
	for i := 0; i < bg.GetSize(); i++ {
		bb, ok := bg.GetBlock(i).Concrete().(*pcode.BlockBasic)
		if !ok || bb == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("-- block %d --\n", i))
		for _, op := range bb.Ops() {
			sb.WriteString("  ")
			if out := op.Output(); out != nil {
				sb.WriteString(vnStr(out) + " = ")
			}
			sb.WriteString(op.Code().String())
			for s := 0; s < op.NumInput(); s++ {
				sb.WriteString(" " + vnStr(op.Input(s)))
			}
			sb.WriteString("\n")
		}
	}
	t.Logf("%s", sb.String())
}

// runPipelineGhidra runs the full decompiler pipeline with Ghidra-compatible
// output formatting enabled (no indent, brace on own line, else on new line,
// no comma-space). Used for golden comparison tests.
func runPipelineGhidra(t *testing.T, prog []byte, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")
	cspecPath := filepath.Join(dir, "../../testdata/sla/x86gcc.cspec")

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Supply the cspec + EntryPoint so the universal-action tree (the production
	// bridge.Decompile path since H8-debt-2) builds a faithful stack spacebase
	// space and the arch-aware default ProtoModel. The cspec is the one load-bearing
	// setup difference between the old 41-call subset and the tree: without it the
	// faithful ActionSpacebase/RuleLoadVarnode path has no StackSpace. These x86-32
	// MSVC leaf functions are entry points rendered under the processEntry
	// convention (EntryPoint: true).
	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name: "entry", Entry: base, MaxInstructions: 60,
		CspecPath: cspecPath, EntryPoint: true,
	})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	// The full decompile pipeline now lives in production: bridge.Decompile.
	// This test only loads bytes, runs the bridge, and renders Ghidra-format C.
	_ = name
	out, err := bridge.Decompile(engine, result, bridge.DecompileConfig{
		GhidraFormat:     true,
		ProcessEntryName: "processEntry",
		GhostParams:      2,
	})
	if err != nil {
		t.Fatalf("bridge.Decompile: %v", err)
	}
	return out
}

// assertGoldenMatch compares Gosleigh output to Ghidra golden, trimming leading/trailing
// whitespace from both sides for a clean diff. The golden value is loaded from
// testdata/ghidra_golden/ghidra_golden.json using the given key.
func assertGoldenMatch(t *testing.T, key string, got string) {
	t.Helper()
	want := loadGhidraGolden(t, key)
	// Trim both ends so that leading/trailing newline differences don't mask real issues.
	gotTrimmed := strings.TrimSpace(got)
	wantTrimmed := strings.TrimSpace(want)
	if gotTrimmed != wantTrimmed {
		t.Errorf("golden mismatch for %q:\nWANT:\n%s\nGOT:\n%s", key, wantTrimmed, gotTrimmed)
	}
}

func runPipeline(t *testing.T, prog []byte, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "entry", Entry: base, MaxInstructions: 60})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	// Build ProtoModel before Heritage so guardCalls can insert INDIRECT ops at
	// CALL sites to model caller-saved/callee-saved register effects.
	// StackSpace is nil here; updated after ActionStackPtrFlow resolves it.
	// C++ parity: ActionPrototypeTypes runs before Heritage in Ghidra's pipeline.
	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, nil, nil)
	xr2 := engine.XRefs()
	cdecl.WithEffectOffsets(func(name string) (uint64, int32, bool) {
		_, off, sz, ok := xr2.RegisterByName(name)
		return off, int32(sz), ok
	})

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).
		WithProtoModel(cdecl).
		Heritage(result.Graph)
	spf := pcode.NewActionStackPtrFlow("analysis")
	spf.Apply(result.Funcdata)

	// Run Heritage for each individual stack slot produced by ActionStackPtrFlow.
	// Each slot is processed independently to avoid the TaskList adjacency-merging
	// that would combine distinct locals into one wide range (causing wrong phi sizes).
	// C++ parity: Ghidra runs ActionStackPtrFlow before Heritage, so Heritage handles
	// stack SSA natively in one pass; we approximate by running HeritageRange per slot.
	if ss := spf.StackSpace(); ss != nil {
		stackHeritage := pcode.NewHeritage(result.Funcdata, []*address.Space{ss})
		stackHeritage.BuildADT(result.Graph)
		slots := spf.StackSlots()
		sizes := spf.StackSlotSizes()
		for i, addr := range slots {
			stackHeritage.HeritageRange(result.Graph, addr, sizes[i])
		}
	}

	// Resolve stack space and return register now that Heritage and StackPtrFlow are done.
	var regSpaceIdx int = -1
	cdecl.StackSpace = spf.StackSpace()
	for _, vn := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if (sp.Kind == address.SpaceKindStack || sp.Name == "stack") && cdecl.StackSpace == nil {
			cdecl.StackSpace = sp
		}
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" && regSpaceIdx < 0 {
			regSpaceIdx = int(sp.Index)
		}
	}
	if regSpaceIdx >= 0 {
		cdecl.WithReturnReg(regSpaceIdx, 0, 4)
	}
	pcode.ApplyCallingConvention(result.Funcdata, cdecl)
	pcode.NewMerge(result.Funcdata).MergeMarker()
	pcode.NewActionFoldFlagConditions("analysis").Apply(result.Funcdata)
	pcode.NewActionConstantFold("analysis").Apply(result.Funcdata)
	pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewBatchAActionPool("batch-a2", "analysis").Perform(result.Funcdata)
	// C++ parity: ActionDeadCode is in actmainloop alongside actprop (BatchA).
	// BatchA rules (RuleIdentityEl, RulePropagateCopy) can leave dead ops
	// (e.g., INT_XOR simplified to COPY then propagated) that need cleanup
	// before shouldInline's NumDescend check for inlining decisions.
	pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
	// Re-run MergeMarker after BatchA: RulePropagateCopy may have replaced
	// stack-space COPY inputs to MULTIEQUAL with unique-space varnodes that
	// have no HighVariable assigned. A second MergeMarker pass propagates the
	// MULTIEQUAL output's HighVariable (e.g. local_0) to those unique inputs
	// so they are rendered as the correct local variable in assignments.
	// C++ parity: Ghidra runs mergeMarker once before actprop, but actprop
	// does not perform COPY propagation into phi inputs; Gosleigh approximates
	// by re-running MergeMarker after BatchA propagation completes.
	pcode.NewMerge(result.Funcdata).MergeMarker()
	pcode.NewActionSeedSignedOps("analysis").Apply(result.Funcdata)
	pcode.NewActionInferTypesLegacy("analysis").Apply(result.Funcdata)
	// H8: run MergeRequired before NodeJoin so addr-tied snipReads COPYs are in
	// place before conditional-join phi creation. This matches Ghidra's merge
	// phase order more closely and removes the raw-stack/trim-COPY split.
	pcode.NewActionMergeRequired("analysis").Apply(result.Funcdata)
	dumpSSA(t, result.Funcdata, name+" after MergeRequired (pre-NodeJoin)")
	// H8: NormalizeBranches + NodeJoin (ConditionalJoin) + RulePushMultiME + DeadCode
	// before BlockStructure so the gcd while-loop condition is merged correctly.
	// C++ parity: coreaction.cc ActionNormalizeBranches + ActionNodeJoin run before
	// ActionBlockStructure in the main decompile loop.
	pcode.NewActionNormalizeBranches("analysis").Apply(result.Funcdata)
	pcode.NewActionNodeJoin("analysis").Apply(result.Funcdata)
	pcode.NewBatchAActionPool("batch-node-join", "analysis").Perform(result.Funcdata)
	pcode.NewActionDeadCode("analysis").Apply(result.Funcdata)
	// Loop-head snapshot (iVar1) now produced by MergeOp's trimOpOutput; no separate pass.
	// Re-run MergeMarker so new MULTIEQUAL ops from NodeJoin get HighVariable assignments.
	pcode.NewMerge(result.Funcdata).MergeMarker()
	dumpSSA(t, result.Funcdata, name+" after NodeJoin+MergeMarker (pre-BlockStructure)")
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionPreferComplement("analysis").Apply(result.Funcdata)
	// ActionForLoops: convert while-with-increment to for-loops.
	// C++ parity: BlockWhileDo::finalTransform runs during ActionFinalStructure
	// in C++; here we run it as a separate post-structure pass.
	pcode.NewActionForLoops("analysis").Apply(result.Funcdata)

	out, err := pcode.NewPrintC().
		SetRegisterNames(engine.RegisterNamesByLocation()).
		SetProcessEntry("processEntry", 2).
		Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	return out
}

func TestMSVC_CountedLoop(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x05, 0x7D, 0x0B, 0x8B, 0x4D, 0xF8, 0x03, 0x4D, 0xFC, 0x89, 0x4D, 0xF8, 0xEB, 0xE6, 0x8B, 0x45, 0xF8, 0x8B, 0xE5, 0x5D, 0xC3}
	out := runPipeline(t, prog, "counted_loop")
	t.Logf("GOSLEIGH:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "counted_loop")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	assertGoldenMatch(t, "counted_loop_x86_32", ghidra)
}

func TestMSVC_SumList(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x83, 0x7D, 0x08, 0x00, 0x74, 0x16, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xFC, 0x03, 0x08, 0x89, 0x4D, 0xFC, 0x8B, 0x55, 0x08, 0x8B, 0x42, 0x04, 0x89, 0x45, 0x08, 0xEB, 0xE4, 0x8B, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3}
	out := runPipeline(t, prog, "sum_list")
	t.Logf("GOSLEIGH:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "sum_list")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	assertGoldenMatch(t, "sum_list_x86_32", ghidra)
}

func TestMSVC_AbsVal(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7D, 0x07, 0x8B, 0x45, 0x08, 0xF7, 0xD8, 0xEB, 0x03, 0x8B, 0x45, 0x08, 0x5D, 0xC3}
	out := runPipeline(t, prog, "abs_val")
	t.Logf("GOSLEIGH:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "abs_val")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	assertGoldenMatch(t, "abs_ifelse_x86_32", ghidra)
}

func TestMSVC_Classify2(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7E, 0x18, 0x8B, 0x45, 0x0C, 0x3B, 0x45, 0x08, 0x7E, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xC0, 0x5D, 0xC3}
	out := runPipeline(t, prog, "classify2")
	t.Logf("GOSLEIGH:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "classify2")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	assertGoldenMatch(t, "nested_if_x86_32", ghidra)
}

// TestMSVC_Gcd tests a frameless x86-32 gcd function compiled with MSVC /O1.
// The function uses ESP-relative parameter access (no EBP frame) and CDQ+IDIV
// for modulo (INT_SREM). Bytes extracted from .text$mn section of gcd.obj.
// Ghidra golden generated via ELF32 wrapper + analyzeHeadless (PyGhidra mode).
//
// Frameless detection: ActionStackPtrFlow.findFramelessStackPointer now handles
// [esp+N] parameter access (2026-04-13). CDQ+IDIV -> INT_SREM simplification
// is now handled by RuleSubCommute (INT_SDIV/INT_SREM case, 2026-04-13).
//
// Remaining mismatch: Ghidra renders the loop condition as a comma expression:
//
//	while (iVar1 = param_4, iVar1 != 0) { ... }
//
// This requires PrintC comma_separate mode for while-condition blocks containing
// phi (MULTIEQUAL) assignments. Not yet implemented in Gosleigh's emitWhileBlock.
// C++ parity: PrintC::emitBlockWhile sets setMod(comma_separate) for condBlock
// emission (printc.cc ~3186).
// TestMSVC_Gcd_Diag logs what Gosleigh currently produces for gcd (no assertion).
// Used to diagnose block structure and output before implementing while-comma.
func TestMSVC_Gcd_Diag(t *testing.T) {
	prog := []byte{0x8b, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x04, 0x85, 0xc9, 0x74, 0x0b, 0x99, 0xf7, 0xf9, 0x8b, 0xc1, 0x8b, 0xca, 0x85, 0xd2, 0x75, 0xf5, 0xc3}
	out := runPipeline(t, prog, "gcd")
	t.Logf("GOSLEIGH output:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "gcd")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	want := loadGhidraGolden(t, "gcd_x86_32")
	t.Logf("GHIDRA golden:\n%s", strings.TrimSpace(want))
}

func TestMSVC_Gcd(t *testing.T) {
	// MSVC /O1 x86-32 gcd: frameless, ESP-relative params, CDQ+IDIV for modulo
	prog := []byte{0x8b, 0x4c, 0x24, 0x08, 0x8b, 0x44, 0x24, 0x04, 0x85, 0xc9, 0x74, 0x0b, 0x99, 0xf7, 0xf9, 0x8b, 0xc1, 0x8b, 0xca, 0x85, 0xd2, 0x75, 0xf5, 0xc3}
	out := runPipeline(t, prog, "gcd")
	t.Logf("GOSLEIGH:\n%s", out)
	ghidra := runPipelineGhidra(t, prog, "gcd")
	t.Logf("GOSLEIGH (Ghidra format):\n%s", ghidra)
	assertGoldenMatch(t, "gcd_x86_32", ghidra)
}
