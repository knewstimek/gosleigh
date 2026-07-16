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

	// Tolerant collection: a guard branch whose target leaves the loaded image
	// (e.g. a switch default block the single-function harness never maps) must
	// not discard the flow already recovered, so the guard CBRANCH still forms a
	// block boundary. Ghidra's truncatedFlow clones a flow that already handled
	// the bad target; the recovery clone reproduces that by tolerating it here.
	records, _, err := collectInstructionsTolerant(engine, cfg, nil, true)
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

	// Materialize an artificial-halt block for every guard branch whose target
	// lies outside the decoded set. Without it the guard CBRANCH keeps a single
	// out-edge and JumpBasic::analyzeGuards cannot recognize it as a guard, so the
	// switch variable's range is never constrained (getSize > maxtablesize) and
	// address emulation is never attempted -- exactly the state that suppresses
	// the "Could not emulate address calculation" warning. Re-point the guard's
	// terminating branch at the synthetic block so addCFGEdges wires the second
	// out-edge, giving analyzeGuards the two-successor shape it needs.
	// C++ parity: flow.cc FlowInfo materializes a bad-instruction block at an
	// undecodable target (newAddress -> artificialHalt); here only the throwaway
	// recovery clone needs it.
	for i := range records {
		fl := records[i].flow
		if !fl.hasUndecodedTarget {
			continue
		}
		tgt := fl.undecodedTarget
		if _, ok := blockByAddr[tgt]; ok {
			continue // target is a real decoded block; nothing to synthesize
		}
		srcbb := instToBlock[records[i].translation.Address]
		if srcbb == nil {
			continue
		}
		haltbb := graph.NewBlockBasicInGraph()
		haltop := fd.ArtificialHalt(tgt, pcode.PcodeOpBadInstruction)
		appendAliveOp(fd, haltbb, haltop)
		blockByAddr[tgt] = haltbb
		instToBlock[tgt] = haltbb
		// Deliberately NOT recorded in lastInBlock: the halt is a RETURN with no
		// out-edges, so addCFGEdges must skip it as an edge source.
		rec := lastInBlock[srcbb]
		rec.flow.directTarget = tgt
		rec.flow.hasDirect = true
		lastInBlock[srcbb] = rec
	}

	bindLoadStoreSpaces(fd, buildSpaceIndex(cfg.Entry.Space, summary))

	// The partial models pre-jumptable flow only: its BRANCHIND has no out-edges
	// (Ghidra's partial assumption, flow.cc:937), so no recovered tables feed edge
	// generation here.
	addCFGEdges(graph, blockByAddr, instToBlock, lastInBlock, nil)
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

// recoverLiveJumpTables drives Ghidra's jump-table recovery for the LIVE build:
// it builds ONE jumptable partial covering the function, runs the "jumptable"
// heritage action group over it once, then recovers the address table for every
// surviving BRANCHIND. Successful recoveries are returned keyed by BRANCHIND
// instruction offset so the caller (Build) can register them on the main
// Funcdata and seed the case bodies for decode.
//
// The returned map is EMPTY whenever recovery does not succeed (no BRANCHIND, a
// partial-build error, a heritage panic, or a JumpTable that recovers zero
// entries). An empty map means the caller changes nothing: the main fd's
// RecoverJumpTables demotes those BRANCHINDs to CALLIND exactly as before. This
// is the no-regression gate -- only functions whose indirect jump genuinely
// resolves into a table observe any behavioral change.
//
// Package boundary: the partial build lives in bridge (it needs the engine and
// the shared instruction-collection helpers); the heritage group, address
// recovery, and (later, in Build) AddJumpTable/TruncateIndirectJump live in
// pcode. bridge drives them, preserving the bridge -> pcode dependency.
//
// C++ parity: FlowInfo::recoverJumpTables (flow.cc:1427) constructs one partial
// Funcdata for the whole tablelist and calls Funcdata::recoverJumpTable
// (funcdata_block.cc:639) per BRANCHIND, which runs Funcdata::stageJumpTable
// (funcdata_block.cc:491): truncatedFlow + setCurrent("jumptable") + perform +
// jt->recoverAddresses(&partial). The heritage is done once (isJumptableRecoveryOn
// guard, funcdata_block.cc:494) and reused across the tablelist.
func recoverLiveJumpTables(engine *sla.Engine, cfg BuildConfig) (map[uint64]*pcode.JumpTable, map[uint64]string) {
	recovered := make(map[uint64]*pcode.JumpTable)
	// emulateFails carries, per BRANCHIND offset, the "Could not emulate address
	// calculation at <addr>" text produced when recovery on the partial reached
	// address emulation and aborted on an unreadable op. Build attaches it to the
	// main Funcdata at the BRANCHIND address, mirroring stageJumpTable's
	// warning(err.explain, op->getAddr()) (funcdata_block.cc:543).
	emulateFails := make(map[uint64]string)

	// Build the partial and run the "jumptable" heritage group under a recover
	// guard. Ghidra's stageJumpTable wraps the perform in try/catch(LowlevelError)
	// and returns fail_normal on error; a Go panic here is the analog, and it must
	// NOT abort the live Build -- a failed speculative recovery simply falls back
	// to the truncate path. So any panic/error yields an empty map.
	partial := func() *PartialResult {
		defer func() { _ = recover() }()
		p, err := BuildJumpTablePartial(engine, cfg)
		if err != nil {
			return nil
		}
		return p
	}()
	if partial == nil || len(partial.BranchInds) == 0 {
		return recovered, emulateFails
	}

	// One heritage pass over the partial SSA-forms every stack-routed selector ->
	// table -> BRANCHIND computation, matching stageJumpTable's single
	// perform(partial) reused across the tablelist.
	heritaged := func() bool {
		defer func() { _ = recover() }()
		db := pcode.NewActionDatabase()
		db.BuildUniversalAction(nil)
		db.BuildDefaultGroups()
		db.SetCurrent("jumptable").Perform(partial.Funcdata)
		return true
	}()
	if !heritaged {
		return recovered, emulateFails
	}

	for _, bop := range partial.BranchInds {
		var failMsg string
		jt := func() *pcode.JumpTable {
			defer func() { _ = recover() }()
			t := pcode.NewJumpTable(bop.Addr())
			t.SetIndirectOp(bop)
			err := t.RecoverAddresses(partial.Funcdata)
			// Capture the emulate-failure text whether or not recovery succeeded:
			// a table that reached emulation and failed there yields the same
			// warning Ghidra attaches, even though the address table came back empty.
			failMsg = t.EmulateFailMsg()
			if err != nil {
				return nil
			}
			if t.NumEntries() == 0 {
				return nil
			}
			return t
		}()
		if jt != nil {
			recovered[bop.Addr().Offset] = jt
		} else if failMsg != "" {
			emulateFails[bop.Addr().Offset] = failMsg
		}
	}
	return recovered, emulateFails
}
