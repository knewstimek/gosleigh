package bridge

import (
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
// Decompile drives the full coreaction.cc ActionDatabase::universalAction tree
// (BuildUniversalAction) -- the faithful Ghidra pass order and the authoritative
// decompile path. The former hand-ordered 41-call subset was removed once the tree
// became byte-identical to it on every production golden (H8-debt-2).
//
// Engine supplies register naming and xref-based effect offsets; result carries
// the Funcdata, block graph, heritage spaces, and parsed cspec.
func Decompile(engine *sla.Engine, result *Result, cfg DecompileConfig) (string, error) {
	fd := result.Funcdata

	// Drive the full faithful universal-action tree (coreaction.cc
	// ActionDatabase::universalAction) as the production decompile path. Build()
	// has already attached the analysis context (SetAnalysisContext: block graph +
	// heritage spaces) and the arch-aware default ProtoModel carrying the faithful
	// stack spacebase space (SetDefaultModel), so the tree runs self-contained:
	// ActionHeritage/ActionSpacebase + RuleLoadVarnode/RuleStoreVarnode recover the
	// stack frame, ActionPrototypeTypes/ActionActiveParam/ActionGuardReturns wire
	// parameters and the return value, and the actprop rule pool + block structuring
	// run in Ghidra's own order.
	//
	// This replaces the former hand-ordered 41-call subset (bespoke
	// ActionStackPtrFlow + manual Heritage/DeadCode/Merge sequencing). The tree is
	// byte-identical to that subset on every production golden and is the faithful
	// authority path going forward.
	//
	// Caller contract: bridge.Build MUST be given a cspec (BuildConfig.CspecPath),
	// and EntryPoint set for entry-point functions. The faithful stack path needs
	// the cspec <stackpointer> to construct the StackSpace; without a cspec no stack
	// spacebase is created and stack locals are not recovered. Ghidra always carries
	// a cspec, so requiring one here is faithful, not a Gosleigh simplification.
	// The lone in-repo callers are the golden test harnesses; any real downstream
	// integration must honor this contract.
	db := pcode.NewActionDatabase()
	db.BuildUniversalAction(nil)
	db.BuildDefaultGroups()
	db.SetCurrent("decompile").Perform(fd)

	p := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation())
	if cfg.ProcessEntryName != "" {
		p = p.SetProcessEntry(cfg.ProcessEntryName, cfg.GhostParams)
	}
	if cfg.GhidraFormat {
		p = p.SetGhidraFormat()
	}
	return p.Emit(fd)
}
