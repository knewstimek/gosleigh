package bridge

import (
	"fmt"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

// PartialResult holds a jump-table recovery partial Funcdata: a second Funcdata
// rebuilt from the same instruction records as Build but WITHOUT the raw-flow
// BRANCHIND truncation (RecoverJumpTables), so its indirect jumps survive into
// the "jumptable" heritage action group for address recovery.
//
// C++ parity: the partial Funcdata that Funcdata::stageJumpTable
// (funcdata_block.cc:491) builds via Funcdata::truncatedFlow
// (funcdata_op.cc:792) and then runs the "jumptable" action group over
// (setCurrent("jumptable") + reset + perform). Ghidra clones the raw dead pcode
// (FlowInfo::cloneOp) into the partial; Gosleigh re-runs addInstructionOps over
// the same InstructionTranslation records -- the Go-faithful equivalent of the
// raw-op clone, since our records ARE the raw ops. The partial's BRANCHIND has
// no out-edges (its indirect targets are not decoded), matching Ghidra's
// partial assumption (flow.cc:937).
type PartialResult struct {
	Funcdata       *pcode.Funcdata
	Graph          *pcode.BlockGraph
	HeritageSpaces []*address.Space
	// BranchInds lists the surviving (untruncated) BRANCHIND ops in the partial,
	// each a candidate for JumpTable.RecoverAddresses after heritage.
	BranchInds []*pcode.PcodeOp
	CspecData  *pcode.CspecData
}

// BuildJumpTablePartial rebuilds a partial Funcdata from the same instruction
// records the live Build path collects, but stops short of RecoverJumpTables so
// that BRANCHIND ops survive into the caller-driven "jumptable" heritage group.
// It reuses every live build helper (collectInstructions, summarizeSpaces,
// addInstructionOps, discoverBlockStarts, addCFGEdges, bindLoadStoreSpaces,
// buildDefaultModel) so the partial's ops, spaces, CFG, stack space, and image
// reader are identical to what Build produces -- the ONLY difference is the
// omitted truncation. It does not touch the live Build function or the live
// pipeline; callers run the recovery in isolation.
//
// C++ parity: Funcdata::truncatedFlow (funcdata_op.cc:792) followed by
// generateBlocks; the "jumptable" group perform and jt->recoverAddresses(&partial)
// are driven by the caller (Funcdata::stageJumpTable, funcdata_block.cc:491-537).
func BuildJumpTablePartial(engine *sla.Engine, cfg BuildConfig) (*PartialResult, error) {
	if engine == nil {
		return nil, fmt.Errorf("build partial: engine is nil")
	}
	if err := cfg.Entry.Validate(); err != nil {
		return nil, fmt.Errorf("build partial: entry address: %w", err)
	}
	if cfg.End.IsInvalid() && cfg.MaxInstructions <= 0 {
		return nil, fmt.Errorf("build partial: end address or max instructions is required")
	}

	records, _, err := collectInstructions(engine, cfg)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("build partial: no instructions translated")
	}

	summary := summarizeSpaces(records, cfg.Entry.Space)
	fd := pcode.NewFuncdata(resolveName(cfg.Name), cfg.Entry, summary.uniqueSpace, summary.uniqueBase, summary.constSpace)

	// Same load-image read hook as Build so JumpBasic address emulation can read
	// the section-mapped table entries at their virtual addresses.
	fd.SetImageReader(func(addr address.Address, sz int) (uint64, error) {
		data, ok, rerr := engine.LoadImageBytes(addr, sz)
		if rerr != nil {
			return 0, rerr
		}
		if !ok {
			return 0, fmt.Errorf("load image miss at %v", addr)
		}
		var res uint64
		for i := 0; i < sz && i < len(data); i++ {
			res |= uint64(data[i]) << (uint(i) * 8)
		}
		return res, nil
	})

	graph := pcode.NewBlockGraph()

	starts := discoverBlockStarts(records)
	blockByAddr := make(map[address.Address]*pcode.BlockBasic, len(starts))
	instToBlock := make(map[address.Address]*pcode.BlockBasic, len(records))
	lastInBlock := make(map[*pcode.BlockBasic]instructionRecord, len(starts))
	var instructionDefs map[varKey]*pcode.Varnode

	var current *pcode.BlockBasic
	for idx, record := range records {
		addr := record.translation.Address
		if starts[addr] {
			current = graph.NewBlockBasicInGraph()
			blockByAddr[addr] = current
			if idx == 0 {
				current.SetFlag(pcode.BlockFlagEntryPoint)
			}
		}
		if current == nil {
			return nil, fmt.Errorf("build partial: missing basic block for instruction %v", addr)
		}
		instToBlock[addr] = current
		lastInBlock[current] = record

		instructionDefs = make(map[varKey]*pcode.Varnode)
		if err := addInstructionOps(fd, current, record.translation, instructionDefs); err != nil {
			return nil, err
		}
	}

	bindLoadStoreSpaces(fd, buildSpaceIndex(cfg.Entry.Space, summary))

	addCFGEdges(graph, blockByAddr, instToBlock, lastInBlock)
	graph.FindSpanningTree()
	assignUnreachableIndices(graph)
	graph.CalcForwardDominator()
	fd.SetBasicBlocks(graph)
	fd.SetFlag(pcode.FuncBlocksGenerated)

	// Deliberately NO fd.RecoverJumpTables() here. In Build this demotes every
	// unrecoverable BRANCHIND to a CALLIND before the action tree; the partial
	// must instead keep the BRANCHIND so the "jumptable" heritage group can put
	// its address computation in SSA form for JumpBasic recovery. This is the one
	// and only difference from Build -- the whole point of the partial.

	fd.SetAnalysisContext(graph, summary.heritageSpaces)

	if cfg.SymbolName != "" {
		fd.SetDisplayName(cfg.SymbolName)
	}

	var cspecData *pcode.CspecData
	if cfg.CspecPath != "" {
		cs, csErr := pcode.ParseCspec(cfg.CspecPath)
		if csErr != nil {
			return nil, fmt.Errorf("build partial: cspec parse %q: %w", cfg.CspecPath, csErr)
		}
		cspecData = cs
	}

	// Same default evaluation model as Build: this creates the faithful stack
	// spacebase space (buildFaithfulStackSpace) that ActionSpacebase +
	// RuleLoadVarnode/RuleStoreVarnode in the "jumptable" group's stackptrflow /
	// stackvars phases consume to resolve the stack-routed switch selector.
	fd.SetDefaultModel(buildDefaultModel(engine, cspecData, fd, cfg.EntryPoint))

	branchInds := make([]*pcode.PcodeOp, 0, 1)
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() == pcode.CPUI_BRANCHIND {
			branchInds = append(branchInds, op)
		}
	}

	return &PartialResult{
		Funcdata:       fd,
		Graph:          graph,
		HeritageSpaces: summary.heritageSpaces,
		BranchInds:     branchInds,
		CspecData:      cspecData,
	}, nil
}
