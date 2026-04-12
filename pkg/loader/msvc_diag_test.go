package loader_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

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

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
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

	var regSpaceIdx int = -1
	stackSpace := spf.StackSpace()
	for _, vn := range result.Funcdata.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if (sp.Kind == address.SpaceKindStack || sp.Name == "stack") && stackSpace == nil {
			stackSpace = sp
		}
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" && regSpaceIdx < 0 {
			regSpaceIdx = int(sp.Index)
		}
	}
	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, stackSpace, nil)
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
	pcode.NewActionInferTypes("analysis").Apply(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionPreferComplement("analysis").Apply(result.Funcdata)

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
}

func TestMSVC_SumList(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x83, 0x7D, 0x08, 0x00, 0x74, 0x16, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xFC, 0x03, 0x08, 0x89, 0x4D, 0xFC, 0x8B, 0x55, 0x08, 0x8B, 0x42, 0x04, 0x89, 0x45, 0x08, 0xEB, 0xE4, 0x8B, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3}
	out := runPipeline(t, prog, "sum_list")
	t.Logf("GOSLEIGH:\n%s", out)
}

func TestMSVC_AbsVal(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7D, 0x07, 0x8B, 0x45, 0x08, 0xF7, 0xD8, 0xEB, 0x03, 0x8B, 0x45, 0x08, 0x5D, 0xC3}
	out := runPipeline(t, prog, "abs_val")
	t.Logf("GOSLEIGH:\n%s", out)
}

func TestMSVC_Classify2(t *testing.T) {
	prog := []byte{0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x7E, 0x18, 0x8B, 0x45, 0x0C, 0x3B, 0x45, 0x08, 0x7E, 0x09, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0xEB, 0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02, 0x33, 0xC0, 0x5D, 0xC3}
	out := runPipeline(t, prog, "classify2")
	t.Logf("GOSLEIGH:\n%s", out)
}
