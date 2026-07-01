package loader_test

import (
	"fmt"
	"os"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/pcode"
)

// TestTreeOutputDiag runs the universal-action tree on gcd and dumps the current
// C output plus proto/scopelocal state. Env-gated (TREE_DIAG=1) so it stays out
// of the normal suite. Diagnostic only -- no assertions.
func TestTreeOutputDiag(t *testing.T) {
	if os.Getenv("TREE_DIAG") == "" {
		t.Skip("set TREE_DIAG=1 to run")
	}
	engine, result := buildGcd(t)
	fd := result.Funcdata

	t.Logf("pre-tree: FuncProto=%v ScopeLocal=%v", fd.GetFuncProto() != nil, fd.GetScopeLocal() != nil)

	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	act := db.SetCurrent("decompile")
	act.Perform(fd)

	fp := fd.GetFuncProto()
	var ss interface{} = nil
	if fp != nil && fp.Model() != nil {
		ss = fp.Model().StackSpace
	}
	t.Logf("post-tree: FuncProto=%v ScopeLocal=%v numParams=%d stackSpace=%v",
		fp != nil, fd.GetScopeLocal() != nil, protoNumParams(fp), ss)

	dumpSSA(t, fd, "tree-final")

	out, err := pcode.NewPrintC().
		SetRegisterNames(engine.RegisterNamesByLocation()).
		SetProcessEntry("processEntry", 2).
		SetGhidraFormat().
		Emit(fd)
	if err != nil {
		t.Fatalf("PrintC: %v", err)
	}
	t.Logf("TREE OUTPUT (ghidra/processEntry):\n%s", out)

	// Production reference: run the hand-ordered decompile driver on a fresh build
	// (mutates result.Funcdata in place) and dump its SSA for comparison.
	engine2, result2 := buildGcd(t)
	pout, perr := bridge.Decompile(engine2, result2, bridge.DecompileConfig{
		GhidraFormat: true, ProcessEntryName: "processEntry", GhostParams: 2,
	})
	if perr != nil {
		t.Fatalf("production Decompile: %v", perr)
	}
	dumpSSA(t, result2.Funcdata, "production-final")
	t.Logf("PRODUCTION OUTPUT:\n%s", pout)
}

func protoNumParams(fp *pcode.FuncProto) int {
	if fp == nil {
		return -1
	}
	return fp.NumParams()
}

// blockShape returns the basic-block count and whether any block has a self-edge
// (a do-while self-loop). Used to pinpoint which production pass splits the gcd
// loop's self-loop block into a separate head + body (the while form).
func blockShape(fd *pcode.Funcdata) string {
	bg := fd.GetBasicBlocks()
	if bg == nil {
		return "no-blocks"
	}
	self := false
	for i := 0; i < bg.GetSize(); i++ {
		bb := bg.GetBlock(i)
		if bb == nil {
			continue
		}
		for j := 0; j < bb.SizeOut(); j++ {
			if bb.OutEdge(j).Point == bb {
				self = true
			}
		}
	}
	return fmt.Sprintf("blocks=%d selfLoop=%v", bg.GetSize(), self)
}

// TestProductionStagesDiag replicates the production decompile pipeline stage by
// stage, logging the basic-block shape after each block-affecting pass, to find
// where the gcd loop's self-loop block is split into a separate while head+body.
// Env-gated (TREE_DIAG=1). Diagnostic only.
func TestProductionStagesDiag(t *testing.T) {
	if os.Getenv("TREE_DIAG") == "" {
		t.Skip("set TREE_DIAG=1 to run")
	}
	engine, result := buildGcd(t)
	fd := result.Funcdata

	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, nil, nil)
	xr := engine.XRefs()
	cdecl.WithEffectOffsets(func(name string) (uint64, int32, bool) {
		_, off, sz, ok := xr.RegisterByName(name)
		return off, int32(sz), ok
	})
	pcode.NewHeritage(fd, result.HeritageSpaces).WithProtoModel(cdecl).Heritage(result.Graph)
	t.Logf("after register heritage: %s", blockShape(fd))

	spf := pcode.NewActionStackPtrFlow("analysis")
	spf.Apply(fd)
	if ss := spf.StackSpace(); ss != nil {
		stackHeritage := pcode.NewHeritage(fd, []*address.Space{ss})
		stackHeritage.BuildADT(result.Graph)
		slots := spf.StackSlots()
		sizes := spf.StackSlotSizes()
		for i, addr := range slots {
			stackHeritage.HeritageRange(result.Graph, addr, sizes[i])
		}
	}
	cdecl.StackSpace = spf.StackSpace()
	t.Logf("after StackPtrFlow + stack heritage: %s", blockShape(fd))

	regSpaceIdx := -1
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" && regSpaceIdx < 0 {
			regSpaceIdx = int(sp.Index)
		}
	}
	if regSpaceIdx >= 0 {
		cdecl.WithReturnReg(regSpaceIdx, 0, 4)
	}
	pcode.ApplyCallingConvention(fd, cdecl)
	pcode.ApplyGuardReturnsLive(fd, cdecl, result.HeritageSpaces, result.Graph)

	pcode.NewMerge(fd).MergeMarker()
	t.Logf("after MergeMarker #1: %s", blockShape(fd))
	pcode.NewActionFoldFlagConditions("analysis").Apply(fd)
	pcode.NewActionConstantFold("analysis").Apply(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(fd)
	pcode.NewBatchAActionPool("batch-a2", "analysis").Perform(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	pcode.NewMerge(fd).MergeMarker()
	t.Logf("after BatchA + DeadCode + MergeMarker #2: %s", blockShape(fd))
	pcode.NewActionSeedSignedOps("analysis").Apply(fd)
	pcode.NewActionInferTypesLegacy("analysis").Apply(fd)
	pcode.NewActionMergeRequired("analysis").Apply(fd)
	t.Logf("after InferTypes + MergeRequired: %s", blockShape(fd))
	pcode.NewActionNormalizeBranches("analysis").Apply(fd)
	t.Logf("after NormalizeBranches: %s", blockShape(fd))
	pcode.NewActionNodeJoin("analysis").Apply(fd)
	// NodeJoin (ConditionalJoin) splits the gcd self-loop into a separate while
	// head+body here ONLY because it runs before BlockStructure: once
	// BlockStructure's collapse sets PcodeOpBooleanFlip on the loop CBRANCH,
	// ConditionalJoin.findDups rejects it. The tree's mainloop runs BlockStructure
	// before NodeJoin, so the tree never gets this split (step3b root cause).
	t.Logf("after NodeJoin (splits self-loop into while head+body): %s", blockShape(fd))
	pcode.NewBatchAActionPool("batch-node-join", "analysis").Perform(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	pcode.NewActionAssignHigh("analysis").Apply(fd)
	pcode.NewMerge(fd).MergeMarker()
	t.Logf("after batchNJ + DeadCode + AssignHigh + MergeMarker #3: %s", blockShape(fd))
	pcode.NewActionBlockStructure("analysis").Apply(fd)
	t.Logf("after BlockStructure: %s", blockShape(fd))
	dumpSSA(t, fd, "production-after-blockstructure")
}
