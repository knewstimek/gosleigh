package bridge

import (
	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

// DecompileConfig controls the decompiler output formatting.
type DecompileConfig struct {
	// GhidraFormat enables Ghidra-compatible formatting (no indent, opening brace
	// on its own line, else on a new line, no space after commas).
	GhidraFormat bool
	// ProcessEntryName, when non-empty, renders the function in Ghidra's
	// processEntry style with GhostParams leading ghost parameters.
	ProcessEntryName string
	// GhostParams is the number of leading ghost parameters for ProcessEntry mode.
	GhostParams int
}

// Decompile runs the full Gosleigh decompiler action pipeline on a bridge Result
// and returns the C output. This is the production decompile path: the
// translate->pcode bridge (Build) produces the Funcdata, and Decompile drives the
// analysis actions through to PrintC.
//
// The pass order mirrors Ghidra's actmainloop for the subset of actions Gosleigh
// implements today. It is the same sequence that the MSVC golden tests exercise.
// The full coreaction.cc ActionDatabase::universalAction tree
// (BuildUniversalAction) is the eventual target; until every action in it is
// complete this hand-ordered subset is the authoritative decompile path.
//
// Engine supplies register naming and xref-based effect offsets; result carries
// the Funcdata, block graph, heritage spaces, and parsed cspec.
func Decompile(engine *sla.Engine, result *Result, cfg DecompileConfig) (string, error) {
	fd := result.Funcdata

	// Build ProtoModel before Heritage so guardCalls can insert INDIRECT ops at
	// CALL sites to model caller-saved/callee-saved register effects. StackSpace
	// is nil here; it is filled in after ActionStackPtrFlow resolves it.
	// C++ parity: ActionPrototypeTypes runs before Heritage in Ghidra's pipeline.
	cdecl := pcode.NewProtoModelFromCspec(result.CspecData, nil, nil)
	xr := engine.XRefs()
	cdecl.WithEffectOffsets(func(name string) (uint64, int32, bool) {
		_, off, sz, ok := xr.RegisterByName(name)
		return off, int32(sz), ok
	})

	pcode.NewHeritage(fd, result.HeritageSpaces).
		WithProtoModel(cdecl).
		Heritage(result.Graph)
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

	// Resolve stack space and return register now that Heritage and StackPtrFlow are done.
	regSpaceIdx := -1
	cdecl.StackSpace = spf.StackSpace()
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
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
	pcode.ApplyCallingConvention(fd, cdecl)
	// H7 step3c: faithful Heritage::guardReturns wiring of the return value (the
	// default), replacing the anchorReturnReg SeqNum heuristic. ApplyCallingConvention
	// skips anchorReturnReg unless GOSL_LEGACY_ANCHOR_RETURN restores it.
	pcode.ApplyGuardReturnsLive(fd, cdecl, result.HeritageSpaces, result.Graph)

	pcode.NewMerge(fd).MergeMarker()
	pcode.NewActionFoldFlagConditions("analysis").Apply(fd)
	pcode.NewActionConstantFold("analysis").Apply(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(fd)
	pcode.NewBatchAActionPool("batch-a2", "analysis").Perform(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	pcode.NewMerge(fd).MergeMarker()
	pcode.NewActionSeedSignedOps("analysis").Apply(fd)
	pcode.NewActionInferTypes("analysis").Apply(fd)
	// Run MergeRequired before NodeJoin so addr-tied snipReads COPYs are in place
	// before conditional-join phi creation, matching Ghidra's merge phase order.
	pcode.NewActionMergeRequired("analysis").Apply(fd)
	// NormalizeBranches + NodeJoin (ConditionalJoin) + BatchA + DeadCode before
	// BlockStructure so loop conditions merge correctly. C++ parity: coreaction.cc
	// ActionNormalizeBranches + ActionNodeJoin run before ActionBlockStructure.
	pcode.NewActionNormalizeBranches("analysis").Apply(fd)
	pcode.NewActionNodeJoin("analysis").Apply(fd)
	pcode.NewBatchAActionPool("batch-node-join", "analysis").Perform(fd)
	pcode.NewActionDeadCode("analysis").Apply(fd)
	// Create the loop-head snapshot (iVar1 = COPY(param)) for a unique-output
	// loop-cond MULTIEQUAL whose value is read after its back-edge value is defined
	// (a swapped loop variable). Gated to unique phi outputs so for-loops whose
	// loop variable is already addr-tied storage are left alone. C++ parity intent:
	// merge.cc eliminateIntersect/snipReads on the addr-tied loop phi output.
	pcode.NewMerge(fd).TrimJoinblockMultiequals()
	// NewUniqueOut does not call assignHigh in Go, so AssignHigh runs before the
	// MergeMarker that gives NodeJoin's new MULTIEQUAL outputs their HighVariables.
	pcode.NewActionAssignHigh("analysis").Apply(fd)
	pcode.NewMerge(fd).MergeMarker()
	pcode.NewActionBlockStructure("analysis").Apply(fd)
	pcode.NewActionFinalStructure("analysis").Apply(fd)
	pcode.NewActionPreferComplement("analysis").Apply(fd)
	// AssignHigh -> MergeRequired -> MarkExplicit -> MarkImplied -> MergeCopy.
	// C++ parity: coreaction.cc ~5734-5739. Placed before ForLoops so testTerminal's
	// IsExplicit check sees valid explicit/implied state.
	pcode.NewActionAssignHigh("analysis").Apply(fd)
	pcode.NewActionMergeRequired("analysis").Apply(fd)
	pcode.NewActionMarkExplicit("analysis").Apply(fd)
	pcode.NewActionMarkImplied("analysis").Apply(fd)
	// MergeCopy before ForLoops so tryMarkForLoop's cross-variable COPY rejection
	// sees post-merge HighVariables.
	pcode.NewActionMergeCopy("analysis").Apply(fd)
	// DominantCopy consolidates redundant copy-trim COPYs; CopyMarker marks
	// internal/redundant COPYs NonPrinting. C++ parity: coreaction.cc ActionDominantCopy
	// then ActionCopyMarker after ActionMergeCopy.
	pcode.NewActionDominantCopy("analysis").Apply(fd)
	pcode.NewActionCopyMarker("analysis").Apply(fd)
	// Re-infer types so trim COPYs created after the first InferTypes pass (the
	// loop-head snapshot) propagate their source type and name as iVar, not uVar.
	pcode.NewActionInferTypes("analysis").Apply(fd)
	// Enable type recovery so the pointer-arithmetic rules (RulePtrArith) activate,
	// then re-run RulePtrArith now that final types are known to form PTRADD from
	// pointer INT_ADD. C++ parity: ActionStartTypes precedes the actprop pointer
	// rules; Gosleigh defers it to here so the addr-tied SSA passes run first.
	pcode.NewActionStartTypes("analysis").Apply(fd)
	ptrArithLate := pcode.NewActionPool(0, "ptrarith-late")
	ptrArithLate.AddRule(pcode.NewRulePtrArith("analysis"))
	ptrArithLate.Perform(fd)
	// ActionNameVars assigns iVar1/uVar1 names to unnamed register/explicit-unique HVs.
	// C++ parity: coreaction.cc ActionNameVars::apply() + ScopeLocal::assignDefaultNames().
	pcode.NewActionNameVars("analysis").Apply(fd)

	// ActionSetCasts inserts explicit CPUI_CAST ops at type mismatches (analysis-time).
	// Runs after the late RulePtrArith so pointer arithmetic is PTRADD (whose
	// getInputCast leaves the pointer operand uncast) rather than INT_ADD (whose
	// base getInputCast would cast the pointer to (int), breaking subscripts).
	// C++ parity: coreaction.cc ActionSetCasts, late in the type-recovery phase.
	pcode.NewActionSetCasts("analysis").Apply(fd)

	// ActionForLoops folds while-do blocks into for-loops AFTER ActionSetCasts so
	// the inserted CPUI_CAST ops are already present when the for-loop iterate op is
	// detected and rendered. This matches Ghidra's order: ActionSetCasts runs in the
	// analysis loop, and the for-loop fold happens later at print time
	// (BlockWhileDo::finalTransform / finalizePrinting in block.cc), which is
	// cast-transparent (findLoopVariable/testIterateForm walk through CAST ops since
	// they are neither calls nor markers). Running it here lets a for-iterate op that
	// needed an output cast (e.g. sum_list: param_3 = (int *)param_3[1]) carry a real
	// inserted CAST, so PrintC renders it without the render-time assignCastStr hack.
	pcode.NewActionForLoops("analysis").Apply(fd)

	p := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation())
	if cfg.ProcessEntryName != "" {
		p = p.SetProcessEntry(cfg.ProcessEntryName, cfg.GhostParams)
	}
	if cfg.GhidraFormat {
		p = p.SetGhidraFormat()
	}
	return p.Emit(fd)
}
