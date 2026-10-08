package bridge

import (
	"errors"
	"fmt"
	"sort"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

type BuildConfig struct {
	// IndirectOverrides turns the CALLIND of an instruction (keyed by its
	// address offset) into a CALL to the given target.
	// C++ parity: Override::insertIndirectOverride (applied by FlowInfo).
	IndirectOverrides map[uint64]address.Address
	// ProtoOverrides are the prototypes forced onto call sites (keyed by
	// instruction offset). C++ parity: Override::insertProtoOverride.
	ProtoOverrides map[uint64]*pcode.HostFunction
	// DeadcodeDelays are dead-code delay overrides by space name.
	// C++ parity: Override::insertDeadcodeDelay.
	DeadcodeDelays map[string]int32

	Name            string
	Entry           address.Address
	End             address.Address
	MaxInstructions int
	// CspecPath is the optional path to a .cspec calling convention file.
	// When non-empty, the cspec is parsed and stored in Result.CspecData.
	CspecPath string
	// SymbolName overrides the display name on the resulting Funcdata when
	// non-empty. This allows callers to wire in a recovered symbol name
	// (e.g. from DWARF or a PE import table) without changing the internal
	// name used for address resolution.
	SymbolName string
	// EntryPoint marks the function as a program entry point decompiled under
	// the stack-based processEntry convention: register argument slots are not
	// recovered as parameters (live-on-entry argument registers render as
	// in_<reg>). Set this alongside PrintC.SetProcessEntry for the matching
	// signature annotation. C++ parity: entry points use the processEntry CC.
	EntryPoint bool

	// InjectedGlobals lists global symbols supplied by the analysis environment
	// (the way Ghidra's ScopeGhidra answers a symbol query into the global
	// scope). It is opt-in: when empty no global scope is attached and output is
	// byte-identical. When populated, each entry becomes a typelock/namelock
	// SymbolEntry in the Funcdata's global scope, so ActionConstantPtr can
	// promote a matching constant to a &symbol reference. This is the general
	// injection surface; future locked-FuncProto injection can layer onto the
	// same BuildConfig without disturbing it.
	InjectedGlobals []InjectedGlobal

	// InjectedPrototype is an opt-in locked function prototype supplied by the
	// analysis environment. It mirrors the fully-locked <prototype> Ghidra's
	// headless analyzer commits to the program database before the decompiler
	// core runs (model + modellock, typelock return, typelock/namelock params).
	// When nil, no prototype is attached and the core recovers the prototype
	// itself -- output stays byte-identical to the un-injected path. C++ parity:
	// a locked FuncProto decoded via FuncProto::decode/setPieces, consumed by
	// ActionPrototypeTypes (coreaction.cc:4620-4715).
	InjectedPrototype *InjectedPrototype

	// HostScope is the analysis environment's symbol database (function and
	// external-reference names). nil decompiles standalone, like the C++
	// console with no program symbols.
	HostScope pcode.HostScope

	// FlowOverrides are the host's instruction flow overrides (address ->
	// "BRANCH", "CALL", "CALL_RETURN" or "RETURN"), e.g. a tail JMP the
	// analysis marked CALL_RETURN.
	FlowOverrides map[uint64]string

	// Injections are the host-compiled call-fixup payloads, by call-site
	// address (Java compiles the cspec <callfixup> snippets).
	Injections map[uint64]HostInjection

	// HostComments are the function's comments as the host sends them
	// (Ghidra <commentdb>): type names "user1".."user3", "header", "warning",
	// "warningheader"; Addr is an offset in the entry space.
	HostComments []HostComment

	// TrackedRegs are register values known at the function entry (register
	// name -> value): the pspec <tracked_set> and the host program context.
	// C++ parity: ContextDatabase::getTrackedSet, consumed by ActionConstbase.
	TrackedRegs map[string]uint64

	// HostLocals are the host's name-locked stack symbols of this function
	// (stack offset -> name), as Java sends them in the function's localdb.
	HostLocals map[int64]string
}

// HostComment is one host-supplied comment. C++ parity: comment.hh Comment.
type HostComment struct {
	Type string
	Addr uint64
	Text string
}

var hostCommentTypes = map[string]uint32{
	"user1": pcode.CommentUser1, "user2": pcode.CommentUser2, "user3": pcode.CommentUser3,
	"header": pcode.CommentHeader, "warning": pcode.CommentWarning, "warningheader": pcode.CommentWarningHeader,
}

// InjectedProtoParam describes one register storage slot (a parameter or the
// return value) of an injected locked prototype. Storage is given as a register
// name so the bridge can resolve it against the engine's register table without
// the caller holding an address.Space. C++ parity: a locked ProtoParameter
// (address + size + type + name, typelock/namelock).
type InjectedProtoParam struct {
	// Name is documentary (e.g. "param_1"); Gosleigh derives parameter names.
	Name string
	// Register is the storage register name, e.g. "EAX", "ECX", "EDX", "R8D".
	Register string
	// Size is the storage width in bytes (e.g. 4 for a 32-bit register slot).
	Size int32
	// Type is the locked data type for this slot.
	Type pcode.Datatype
	// TypeLock/NameLock mirror the Ghidra symbol locks.
	TypeLock bool
	NameLock bool
	// Isolate mirrors the committed prototype's merge="false" attribute: when
	// true the recovered parameter Symbol is flagged isolate so it is never
	// speculatively merged with an accumulator (yielding a distinct return
	// carrier instead of parameter reuse). C++ parity: Symbol isolate dispflag.
	Isolate bool
}

// InjectedPrototype captures a fully-locked function prototype (model + return +
// parameters). Only the return (output lock) and parameter types (input type
// locks) drive core behavior in Gosleigh: the load-bearing effect is that an
// output type-lock forces a distinct return carrier onto each RETURN op
// (ActionPrototypeTypes locked-output path) instead of reusing an operand. The
// parameter storage map is reproduced by Gosleigh's register-parameter
// derivation, so the injected parameter types are stamped onto the recovered
// parameters (type-locked) rather than re-deriving the input map. C++ parity:
// FuncProto with isModelLocked/isOutputLocked/isInputLocked true.
type InjectedPrototype struct {
	// Model is documentary (e.g. "__fastcall"); the concrete model comes from the
	// cspec default evaluation model already attached to the Funcdata.
	Model string
	// ModelLock mirrors modellock="true".
	ModelLock bool
	// Return is the locked return slot; a nil Return.Type means no locked return.
	Return InjectedProtoParam
	// Params are the locked input parameters in ABI order.
	Params []InjectedProtoParam
}

// InjectedGlobal describes one environment-supplied global symbol to seed into
// the Funcdata's global scope. C++ parity: a Symbol/SymbolEntry that ScopeGhidra
// returns for a global-scope query (typelock/namelock preserved).
type InjectedGlobal struct {
	Name     string
	Space    *address.Space
	Offset   uint64
	Size     int32
	Type     pcode.Datatype
	TypeLock bool
	NameLock bool
}

type Result struct {
	Funcdata       *pcode.Funcdata
	Graph          *pcode.BlockGraph
	Instructions   []sla.InstructionTranslation
	HeritageSpaces []*address.Space
	Warnings       []string
	// CspecData is set when BuildConfig.CspecPath is non-empty.
	CspecData *pcode.CspecData
	// rebuild re-runs Build with indirect-call overrides (a decompiler restart).
	rebuild func(map[uint64]address.Address, map[uint64]*pcode.HostFunction, map[string]int32) (*Result, error)
}

type instructionRecord struct {
	translation sla.InstructionTranslation
	flow        instructionFlow
}

type instructionFlow struct {
	directTarget    address.Address
	fallthroughAddr address.Address
	hasDirect       bool
	hasFallthrough  bool
	terminates      bool
	conditional     bool
	// undecodedTarget records a BRANCH/CBRANCH direct target that lies outside
	// the decoded instruction set (e.g. a guard branch to a default block whose
	// bytes are not in the loaded image). hasDirect stays false for such a target
	// (the CFG cannot link to a decoded block), but the jump-table recovery
	// partial needs the address to synthesize an artificial-halt block so the
	// guard CBRANCH still has two out-edges -- the shape JumpBasic::analyzeGuards
	// requires. Ghidra reaches the same shape because FlowInfo materializes a
	// bad-instruction block at an undecodable target (flow.cc FlowInfo::newAddress
	// -> artificialHalt); Gosleigh only needs it on the throwaway recovery clone.
	undecodedTarget    address.Address
	hasUndecodedTarget bool
}

type edgeKey struct {
	from *pcode.BlockBasic
	to   *pcode.BlockBasic
}

type spaceSummary struct {
	constSpace     *address.Space
	uniqueSpace    *address.Space
	heritageSpaces []*address.Space
}

// analysisUniqueBase is where temporaries made during analysis start, past
// every temporary a translation uses. C++ parity: VarnodeBank::VarnodeBank
// (getUniqueStart(Translate::ANALYSIS) = 0x10000000).
const analysisUniqueBase = 0x10000000

func Build(engine *sla.Engine, cfg BuildConfig) (*Result, error) {
	if engine == nil {
		return nil, fmt.Errorf("build bridge: engine is nil")
	}
	if err := cfg.Entry.Validate(); err != nil {
		return nil, fmt.Errorf("build bridge: entry address: %w", err)
	}
	if cfg.End.IsInvalid() && cfg.MaxInstructions <= 0 {
		return nil, fmt.Errorf("build bridge: end address or max instructions is required")
	}

	records, warnings, err := collectInstructions(engine, cfg)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		if len(warnings) > 0 {
			return &Result{Warnings: warnings}, nil
		}
		return nil, fmt.Errorf("build bridge: no instructions translated")
	}

	// Phase 3b: live jump-table recovery driver. Ghidra's generateOps interleaves
	// raw-flow decode with jump-table recovery: after the initial fallthru pass it
	// runs recoverJumpTables, then for each recovered table newAddress()es every
	// case target and fallthru()s again to decode the case bodies (flow.cc:796-810).
	// Gosleigh mirrors this here, between the initial collection and block building
	// (which is generateBlocks, and must run after case bodies exist):
	//   1. If no BRANCHIND is present, this whole block is skipped -- byte-identical
	//      no-op for every non-switch function.
	//   2. Otherwise drive stageJumpTable over a partial (recoverLiveJumpTables).
	//      Only genuinely resolved tables come back; unresolved BRANCHINDs (e.g. a
	//      reloc-less dispatch) yield an empty map and fall through to the existing
	//      truncate path below, unchanged.
	//   3. On success, re-collect with the case targets seeded so the case bodies
	//      are decoded, and remember the seeds as extra block starts + edge sources.
	var recoveredTables map[uint64]*pcode.JumpTable
	var caseSeeds []address.Address
	// emulateFails maps a BRANCHIND instruction offset to the "Could not emulate
	// address calculation at <addr>" text produced when recovery on the partial
	// reached emulation and failed there (an unreadable jump table). Build attaches
	// it to the main Funcdata before truncation so the warning precedes the
	// "Treating indirect jump as call" comment, matching Ghidra's stageJumpTable ->
	// truncateIndirectJump order (funcdata_block.cc:543 then flow.cc:727).
	var emulateFails map[uint64]string
	if recordsHaveBranchInd(records) {
		tables, fails := recoverLiveJumpTables(engine, cfg)
		emulateFails = fails
		if len(tables) > 0 {
			// Normalize case targets into the code space the records use so block
			// lookups (blockByAddr) and worklist seeds share one AddrSpace pointer.
			codeSpace := records[0].translation.Address.Space
			for _, jt := range tables {
				for i := 0; i < jt.NumEntries(); i++ {
					caseSeeds = append(caseSeeds, address.Address{Space: codeSpace, Offset: jt.AddressByIndex(i).Offset})
				}
			}
			records2, _, cerr := collectInstructionsSeeded(engine, cfg, caseSeeds)
			if cerr == nil && len(records2) > 0 {
				recoveredTables = tables
				records = records2
			} else {
				// Re-collection failed (e.g. a case target hit undecodable bytes):
				// discard the recovery and fall back to the truncate path so output
				// stays exactly as before rather than a half-decoded switch.
				caseSeeds = nil
			}
		}
	}

	summary := summarizeSpaces(records, cfg.Entry.Space)
	// A processor space no instruction names (the registers of a thunk that
	// only jumps) is still heritaged: a locked callee puts its parameters
	// there. C++ parity: Heritage::buildInfoList walks every space.
	heritageSet := make(map[*address.Space]struct{}, len(summary.heritageSpaces))
	for _, sp := range summary.heritageSpaces {
		heritageSet[sp] = struct{}{}
	}
	for _, sp := range engine.Spaces() {
		if sp.Kind == address.SpaceKindProcessor {
			summary.collectHeritageSpace(sp, cfg.Entry.Space, heritageSet)
		}
	}
	fixFlowOverrideReturns(records, summary.constSpace)
	injectWarnings := applyInjections(records, cfg.Injections, summary.constSpace)
	fd := pcode.NewFuncdata(resolveName(cfg.Name), cfg.Entry, summary.uniqueSpace, analysisUniqueBase, summary.constSpace)
	fd.SetArchSpaces(engine.Spaces())
	fd.UserOps().RegisterNames(engine.UserOpNames())
	fd.SetRegisterNames(engine.RegisterNamesByLocation())
	if len(cfg.IndirectOverrides) != 0 {
		ov := make(map[uint64]address.Address, len(cfg.IndirectOverrides))
		for k, v := range cfg.IndirectOverrides {
			ov[k] = v
		}
		fd.SetIndirectOverrides(ov) // a restart keeps earlier overrides
	}
	if len(cfg.ProtoOverrides) != 0 {
		po := make(map[uint64]*pcode.HostFunction, len(cfg.ProtoOverrides))
		for k, v := range cfg.ProtoOverrides {
			po[k] = v
		}
		fd.SetProtoOverrides(po)
	}
	if len(cfg.DeadcodeDelays) != 0 {
		dd := make(map[string]int32, len(cfg.DeadcodeDelays))
		for k, v := range cfg.DeadcodeDelays {
			dd[k] = v
		}
		fd.SetDeadcodeDelays(dd)
	}
	if err := attachEnvironment(engine, fd, cfg, summary.heritageSpaces); err != nil {
		return nil, err
	}
	installLanedRegisters(engine, fd)
	installIncidentalCopy(engine, fd, summary.heritageSpaces)

	// Install the load-image read hook so downstream jump-table address
	// emulation (pcode.EmulateFunction.getLoadImageValue) can read section-mapped
	// table entries at their virtual addresses. The engine's backend exposes raw
	// image bytes; wrap them as a little-endian value (x86-64 is little-endian).
	// This is inert for functions without a recovered jump-table model.
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
	// Each recovered switch-case target begins a basic block. These addresses are
	// indirect (BRANCHIND) targets, so discoverBlockStarts -- which only follows
	// direct branches and fall-through -- never marks them; mark them explicitly.
	// C++ parity: FlowInfo::newAddress calls opMarkStartBasic on a seen target
	// (flow.cc:230), which collectEdges/generateBlocks turn into a block boundary.
	if len(caseSeeds) > 0 {
		known := make(map[address.Address]struct{}, len(records))
		for _, record := range records {
			known[record.translation.Address] = struct{}{}
		}
		for _, seed := range caseSeeds {
			if _, ok := known[seed]; ok {
				starts[seed] = true
			}
		}
	}
	blockByAddr := make(map[address.Address]*pcode.BlockBasic, len(starts))
	instToBlock := make(map[address.Address]*pcode.BlockBasic, len(records))
	lastInBlock := make(map[*pcode.BlockBasic]instructionRecord, len(starts))

	// splitTail links a block ending inside an instruction to the block
	// holding the rest of that instruction (CMOVcc lowers to
	// 'goto next if !cond; dst = src'). relTarget holds the destination of a
	// block ending in a relative (constant-space) branch.
	splitTail := make(map[*pcode.BlockBasic]*pcode.BlockBasic)
	relTarget := make(map[*pcode.BlockBasic]relLink)
	knownAddrs := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		knownAddrs[record.translation.Address] = struct{}{}
	}

	assignFlowTimes(records, cfg.Entry, recoveredTables)
	var current *pcode.BlockBasic
	for idx, record := range records {
		addr := record.translation.Address
		if len(record.translation.Ops) == 0 {
			continue // Aliased to the next instruction's block below
		}
		if starts[addr] || current == nil {
			current = graph.NewBlockBasicInGraph()
			blockByAddr[addr] = current
			if idx == 0 {
				current.SetFlag(pcode.BlockFlagEntryPoint)
			}
		}
		if current == nil {
			return nil, fmt.Errorf("build bridge: missing basic block for instruction %v", addr)
		}
		instToBlock[addr] = current

		// An op after a branch inside one instruction starts a new block.
		// C++ parity: FlowInfo marks the op following a branch startbasic.
		ops := record.translation.Ops
		bounds := splitInstruction(ops)
		segBlocks := make([]*pcode.BlockBasic, len(bounds))
		for si, b := range bounds {
			sub, rec := record.translation, record
			if len(bounds) > 1 || len(ops) != b[1] {
				sub.Ops = ops[b[0]:b[1]]
				rec = instructionRecord{translation: sub, flow: analyzeInstructionFlow(sub, cfg.Entry.Space, knownAddrs)}
			}
			if si > 0 {
				tail := graph.NewBlockBasicInGraph()
				splitTail[current] = tail
				current = tail
			}
			segBlocks[si] = current
			lastInBlock[current] = rec
			if err := addInstructionOps(fd, current, sub); err != nil {
				return nil, err
			}
		}
		for si, b := range bounds {
			if t, ok := relativeTargetIndex(ops, b[1]-1); ok {
				link := relLink{next: record.translation.Next}
				for sj, c := range bounds {
					if c[0] == t {
						link.seg = segBlocks[sj]
					}
				}
				relTarget[segBlocks[si]] = link
			}
		}
	}
	// Instructions were translated in worklist order; the alive list follows
	// p-code generation order as in C++ (assignFlowTimes set the times).
	fd.GetPcodeOpBank().SortAliveByTime()
	markNoReturnHalts(fd)
	for _, w := range injectWarnings {
		fd.WarningHeader(w)
	}
	for from, to := range zeroOpRedirect(records) {
		if b := blockByAddr[to]; b != nil {
			blockByAddr[from] = b
		}
		if b := instToBlock[to]; b != nil {
			instToBlock[from] = b
		}
	}

	// Faithful stack path: bind the target address space onto each LOAD/STORE
	// space-id constant (input 0) so loadStoreSpace/checkLoadStoreAddress can
	// resolve it. Ghidra encodes the AddrSpace pointer directly in that constant;
	// Gosleigh's lowering encodes the space index, so we map it back here. This is
	// only consumed by RuleLoadVarnode/RuleStoreVarnode/RuleLoadConstAddr in the
	// universal-action tree; the hand-ordered production driver does not run those
	// rules, so binding the space is inert there.
	bindLoadStoreSpaces(fd, buildSpaceIndex(cfg.Entry.Space, summary))

	// Register each recovered jump table on the main Funcdata, relinking it to the
	// main fd's BRANCHIND op (the recovery ran on a separate partial). This must
	// happen before addCFGEdges (which queries FindJumpTable to add switch edges)
	// and before fd.RecoverJumpTables (whose linkJumpTable now finds a complete
	// table and therefore does NOT truncate the recovered BRANCHIND).
	// C++ parity: Funcdata::recoverJumpTable relinks with jt->setIndirectOp(op)
	// after recovering on the partial (funcdata_block.cc:671) and pushes it onto
	// jumpvec (installJumpTable).
	if len(recoveredTables) > 0 {
		registerRecoveredTables(fd, recoveredTables)
	}

	graph.SetInitialRanges()
	addCFGEdges(graph, blockByAddr, instToBlock, lastInBlock, recoveredTables, splitTail, relTarget)
	graph.StructureLoops()
	fd.SetBasicBlocks(graph)
	fd.SetFlag(pcode.FuncBlocksGenerated)

	// Raw-flow jump-table recovery: try to recover a jump table for every
	// BRANCHIND, and demote (truncate) those that cannot be recovered to a
	// CALLIND call site plus an artificial return. This mirrors Ghidra's
	// FlowInfo::generateOps, which runs recoverJumpTables/truncateIndirectJump
	// during raw flow generation -- before any Action. Running it here (after the
	// block graph is built but before the universal-action tree in Decompile)
	// keeps the demotion ahead of heritage/parameter/return recovery, so those
	// passes model the indirect jump as a call exactly as Ghidra does. It is a
	// no-op for functions with no BRANCHIND.
	// C++ parity: flow.cc FlowInfo::generateOps / recoverJumpTables /
	// truncateIndirectJump.

	// Attach the "Could not emulate address calculation at <addr>" warning to each
	// BRANCHIND whose recovery on the partial reached emulation and failed there.
	// This runs BEFORE RecoverJumpTables (which truncates the BRANCHIND and adds
	// "Treating indirect jump as call"), so the two same-address comments keep the
	// insertion order the golden expects. Ghidra emits them in this order too:
	// stageJumpTable's catch warns first (funcdata_block.cc:543), then the
	// fail_normal path calls truncateIndirectJump (flow.cc:727).
	// A table the sanity check truncated warns from inside the jump-table
	// recovery (C++ JumpTable::sanityCheck on the partial Funcdata), hence
	// the jumptable prefix.
	for _, jt := range recoveredTables {
		if w := jt.SanityWarning(); w != "" {
			fd.WarningJumptable(w, jt.OpAddress())
		}
	}
	if len(emulateFails) > 0 {
		for _, op := range fd.GetPcodeOpBank().AliveOps() {
			if op == nil || op.Code() != pcode.CPUI_BRANCHIND {
				continue
			}
			if msg, ok := emulateFails[op.Addr().Offset]; ok {
				fd.Warning(msg, op.Addr())
			}
		}
	}

	fd.RecoverJumpTables()

	// Convert each recovered jump table's absolute address list into block
	// out-edge indices (and its default block) now that the switch CFG is final.
	// Ghidra does this at the tail of generateBlocks; the resolver stands in for
	// FlowInfo::target by returning an op in the case-target block. No-op unless a
	// table is registered, so non-switch functions are untouched.
	// C++ parity: funcdata_op.cc generateBlocks -> switchOverJumpTables.
	if fd.NumJumpTables() > 0 {
		resolver := func(addr address.Address) *pcode.PcodeOp {
			if b := blockByAddr[address.Address{Space: cfg.Entry.Space, Offset: addr.Offset}]; b != nil {
				return b.FirstOp()
			}
			for k, b := range blockByAddr {
				if k.Offset == addr.Offset {
					return b.FirstOp()
				}
			}
			return nil
		}
		if err := fd.SwitchOverJumpTables(resolver); err != nil {
			return nil, fmt.Errorf("build bridge: switch-over jump tables: %w", err)
		}
	}

	translations := make([]sla.InstructionTranslation, len(records))
	for i := range records {
		translations[i] = records[i].translation
	}

	result := &Result{
		Funcdata:       fd,
		Graph:          graph,
		Instructions:   translations,
		HeritageSpaces: summary.heritageSpaces,
		Warnings:       warnings,
		rebuild: func(ov map[uint64]address.Address, po map[uint64]*pcode.HostFunction, dd map[string]int32) (*Result, error) {
			next := cfg
			next.IndirectOverrides = ov
			next.ProtoOverrides = po
			next.DeadcodeDelays = dd
			return Build(engine, next)
		},
	}

	// Attach the analysis context to the Funcdata so the universal-action tree
	// (ActionHeritage etc.) can run self-contained. The hand-ordered decompile
	// driver still passes graph/spaces explicitly; this is additive.
	fd.SetAnalysisContext(graph, summary.heritageSpaces)

	// Wire recovered symbol name onto Funcdata when provided.
	// This sets the display name used by PrintC for the function declaration.
	if cfg.SymbolName != "" {
		fd.SetDisplayName(cfg.SymbolName)
	}

	// Seed environment-supplied global symbols into the Funcdata's global scope.
	// Opt-in: with no InjectedGlobals the global scope stays nil and every
	// downstream global-symbol query misses, keeping output byte-identical.
	// C++ parity: ScopeGhidra populates the global Scope on query response.
	if len(cfg.InjectedGlobals) > 0 {
		gs := pcode.NewGlobalScope()
		for _, ig := range cfg.InjectedGlobals {
			if ig.Space == nil || ig.Type == nil {
				continue
			}
			var flags uint32
			if ig.TypeLock {
				flags |= pcode.VarnodeTypeLock
			}
			if ig.NameLock {
				flags |= pcode.VarnodeNameLock
			}
			addr := address.Address{Space: ig.Space, Offset: ig.Offset}
			gs.AddSymbol(ig.Name, ig.Type, addr, ig.Size, flags)
		}
		fd.SetGlobalScope(gs)
	}

	// Parse cspec if provided. A parse failure is fatal: continuing without the
	// cspec silently drops the stack space and every prototype model, which
	// produced plausible-looking but wholly wrong output (x86win.cspec's
	// extrapop="unknown" went unnoticed this way).
	if cfg.CspecPath != "" {
		cs, csErr := pcode.ParseCspec(cfg.CspecPath)
		if csErr != nil {
			return nil, fmt.Errorf("cspec parse %q: %w", cfg.CspecPath, csErr)
		}
		result.CspecData = cs
	}

	// Attach the default evaluation prototype model (Architecture::defaultfp
	// equivalent) so the universal-action tree's ActionPrototypeTypes can create
	// a FuncProto + ScopeLocal. Since H8-debt-2 the tree is the production decompile
	// path (bridge.Decompile), so this default model IS the model production runs
	// with: its faithful stack spacebase space (set below when a cspec is supplied)
	// is consumed by ActionSpacebase + RuleLoadVarnode/RuleStoreVarnode during the
	// run. Callers must supply a cspec for stack-frame recovery (see Decompile).
	installModels(engine, result.CspecData, fd, cfg.EntryPoint)
	fd.ApplyHostSelfPrototype(fd.DefaultModel())
	installTrackedSet(engine, fd, cfg.TrackedRegs)

	// Attach an opt-in locked prototype supplied by the analysis environment.
	// Must run after SetDefaultModel so the locked FuncProto reuses the cspec
	// evaluation model. No-op when cfg.InjectedPrototype is nil (default path).
	if cfg.InjectedPrototype != nil {
		applyInjectedPrototype(engine, fd, cfg.InjectedPrototype)
	}

	return result, nil
}

// attachEnvironment installs what the analysis environment knows before any
// Varnode is created, so Varnode properties are set at creation as in C++: the
// host symbol database and the cspec <global> scope ranges. Only <global>
// ranges in the code space are resolved here (the register space is not known
// until the function is translated); a register entry such as x86 MXCSR is a
// known mismatch.
// C++ parity: Architecture::addToGlobalScope (the global scope exists before
// any function is decompiled).
func attachEnvironment(engine *sla.Engine, fd *pcode.Funcdata, cfg BuildConfig, spaces []*address.Space) error {
	fd.SetHostScope(cfg.HostScope)
	for _, c := range cfg.HostComments {
		if tp, ok := hostCommentTypes[c.Type]; ok && cfg.Entry.Space != nil {
			fd.AddHostComment(tp, address.Address{Space: cfg.Entry.Space, Offset: c.Addr}, c.Text)
		}
	}
	if cfg.HostLocals != nil {
		// Stack offsets are stored wrapped to the stack space width (the
		// pointer size of the entry space).
		mask := spaceHighest(cfg.Entry.Space)
		m := make(map[uint64]string, len(cfg.HostLocals))
		for off, name := range cfg.HostLocals {
			m[uint64(off)&mask] = name
		}
		fd.SetHostLocals(m)
	}
	if cfg.CspecPath == "" {
		return nil
	}
	cs, err := pcode.ParseCspec(cfg.CspecPath)
	if err != nil {
		return fmt.Errorf("cspec parse %q: %w", cfg.CspecPath, err)
	}
	ram := cfg.Entry.Space
	if ram == nil {
		return nil
	}
	var ranges []pcode.GlobalRange
	for _, r := range cs.GlobalRanges {
		if r.Space != ram.Name {
			continue
		}
		first, last := uint64(0), spaceHighest(ram)
		if r.First != nil {
			first = *r.First
		}
		if r.Last != nil {
			last = *r.Last
		}
		ranges = append(ranges, pcode.GlobalRange{Space: ram, First: first, Last: last})
	}
	// A <register> in <global> puts that register's storage in the global
	// scope, so it is a persistent variable printed by its name (MXCSR).
	// C++ parity: Architecture::decodeGlobal (register -> addRange).
	if engine != nil {
		xr := engine.XRefs()
		for _, name := range cs.GlobalRegisters {
			si, off, sz, ok := xr.RegisterByName(name)
			if !ok || sz <= 0 {
				continue
			}
			for _, space := range spaces {
				if space != nil && int64(space.Index) == si {
					ranges = append(ranges, pcode.GlobalRange{Space: space, First: off, Last: off + uint64(sz) - 1})
					break
				}
			}
		}
	}
	fd.SetGlobalRanges(ranges)
	return nil
}

// applyInjectedPrototype attaches a locked FuncProto built from the injected
// prototype spec. It sets the model lock, the output (return) type lock with
// explicit register storage, and records the locked parameter types by register
// offset. The core's ActionPrototypeTypes then forces a return carrier onto each
// RETURN (locked-output path), while ScopeLocal.BuildFromVarnodes stamps the
// locked parameter types onto the register parameters it recovers.
//
// The input lock flag is intentionally NOT set: Gosleigh recovers the register
// parameter storage map by ABI-slot derivation, which converges on exactly the
// storage a locked prototype encodes, so the derivation is allowed to run and the
// injected types are overlaid on its result. C++ instead skips deriveInputMap and
// creates the input varnodes from the ProtoParameter storage; the observable
// result (typed, ABI-ordered register parameters) is identical because the
// storage maps agree.
// C++ parity: FuncProto::setPieces + ActionPrototypeTypes::apply (coreaction.cc).
func applyInjectedPrototype(engine *sla.Engine, fd *pcode.Funcdata, spec *InjectedPrototype) {
	if engine == nil || fd == nil || spec == nil {
		return
	}
	model := fd.DefaultModel()
	fp := pcode.NewFuncProto(model)
	fp.SetModelLock(spec.ModelLock)

	xr := engine.XRefs()
	// resolveReg maps a register name to its (register-space address, natural
	// width). The register space pointer is recovered from the function's existing
	// varnodes by space index (the function references its argument registers, so
	// the register space is present by this point).
	resolveReg := func(name string) (address.Address, int32, bool) {
		si, off, sz, ok := xr.RegisterByName(name)
		if !ok {
			return address.Address{}, 0, false
		}
		space, _ := registerSpaceByIndex(fd, si)
		if space == nil {
			return address.Address{}, 0, false
		}
		return address.Address{Space: space, Offset: off}, int32(sz), true
	}

	// Locked return: explicit storage + type + output lock.
	if spec.Return.Type != nil {
		if addr, natSize, ok := resolveReg(spec.Return.Register); ok {
			size := spec.Return.Size
			if size <= 0 {
				size = natSize
			}
			fp.SetLockedReturn(addr, size, spec.Return.Type)
			fp.SetOutputLock(spec.Return.TypeLock)
		}
	}

	// Locked parameter types keyed by register byte offset. Only meaningful when
	// the parameter carries a type lock; a namelock/typelock=false slot leaves the
	// derived type in place. The name + namelock are recorded independently so
	// ScopeLocal.BuildFromVarnodes can create a namelocked parameter Symbol on the
	// recovered register parameter -- the merge Symbol guard needs that Symbol to
	// keep param_N distinct from an accumulator carrying a different Symbol.
	for _, p := range spec.Params {
		if addr, _, ok := resolveReg(p.Register); ok {
			if p.Type != nil && p.TypeLock {
				fp.SetLockedParamType(addr.Offset, p.Type)
			}
			if p.Name != "" {
				fp.SetLockedParamName(addr.Offset, p.Name, p.NameLock, p.Isolate)
			}
		}
	}

	fd.SetFuncProto(fp)
	if fd.GetScopeLocal() == nil {
		fd.SetScopeLocal(pcode.NewScopeLocal(model))
	}
}

// buildDefaultModel constructs the architecture evaluation prototype model the
// universal-action tree attaches to a function without a locked prototype. It is
// arch-aware: register parameter offsets and the integer return register are
// derived from the parsed cspec so register-based ABIs (x86-64 SysV RDI/RSI...,
// AArch64 x0/x1...) recover register parameters and the return value, not just
// x86-32 stack ABIs. When a cspec is supplied the faithful stack spacebase space
// is created up front (buildFaithfulStackSpace) and set as model.StackSpace, so
// ActionSpacebase + RuleLoadVarnode/RuleStoreVarnode recover stack locals during
// the run; when cspec is nil the StackSpace stays nil and no stack frame is
// recovered.
//
// When cspec is nil (cspec-less builds, e.g. the gcd tree regression guard) the
// RegParamOffsets stay empty and the return register falls back to x86 EAX
// (register space, offset 0, size 4), preserving the prior behavior exactly.
//
// C++ parity: Architecture::defaultfp / PrototypeModel construction from cspec.
func buildDefaultModel(engine *sla.Engine, cspec *pcode.CspecData, fd *pcode.Funcdata, entryPoint bool) *pcode.ProtoModel {
	return buildModel(engine, cspec, fd, entryPoint, nil)
}

// installTrackedSet resolves the tracked register values (name -> value) to
// register storage, in register-name order for determinism.
// installLanedRegisters hands the pspec vector registers to the function so
// storage of a laned size is recorded for ActionLaneDivide.
// C++ parity: Architecture::lanerecords consulted by Funcdata::checkForLanedRegister.
func installLanedRegisters(engine *sla.Engine, fd *pcode.Funcdata) {
	var recs []pcode.LanedRegister
	for _, spec := range engine.LanedRegisters() {
		var lr pcode.LanedRegister
		if lr.ParseSizes(spec.Size, spec.LaneSizes) == nil {
			recs = append(recs, lr)
		}
	}
	fd.SetLanedRegisters(recs)
}

// installIncidentalCopy hands the pspec incidental-copy registers to the
// function as storage ranges. C++ parity: Architecture::decodeIncidentalCopy
// (symboltab->setPropertyRange(Varnode::incidental_copy, range)).
func installIncidentalCopy(engine *sla.Engine, fd *pcode.Funcdata, spaces []*address.Space) {
	names := engine.IncidentalCopy()
	if len(names) == 0 {
		return
	}
	xr := engine.XRefs()
	var ranges []pcode.GlobalRange
	for _, name := range names {
		si, off, sz, ok := xr.RegisterByName(name)
		if !ok || sz <= 0 {
			continue
		}
		for _, space := range spaces {
			if space != nil && int64(space.Index) == si {
				ranges = append(ranges, pcode.GlobalRange{Space: space, First: off, Last: off + uint64(sz) - 1})
				break
			}
		}
	}
	fd.SetIncidentalCopyRanges(ranges)
}

func installTrackedSet(engine *sla.Engine, fd *pcode.Funcdata, regs map[string]uint64) {
	if len(regs) == 0 {
		return
	}
	names := make([]string, 0, len(regs))
	for n := range regs {
		names = append(names, n)
	}
	sort.Strings(names)
	xr := engine.XRefs()
	var set []pcode.TrackedContext
	for _, n := range names {
		si, off, sz, ok := xr.RegisterByName(n)
		if !ok {
			continue
		}
		sp, _ := registerSpaceByIndex(fd, si)
		if sp == nil {
			continue
		}
		mask := uint64(^uint64(0))
		if sz < 8 {
			mask = (uint64(1) << (8 * uint(sz))) - 1
		}
		set = append(set, pcode.TrackedReg(pcode.VarnodeData{Space: sp, Offset: off, Size: uint32(sz)}, regs[n]&mask))
	}
	fd.SetTrackedSet(set)
}

// installModels attaches the architecture's prototype models to fd: the
// default model (Architecture::defaultfp) and, when the cspec names one, the
// evaluation model for the current function (evalfp_current), which may be a
// merged model over named models. All models share one stack space.
// C++ parity: Architecture::decodeProtoEval / setDefaultModel /
// ProtoModelMerged::decode.
func installModels(engine *sla.Engine, cspec *pcode.CspecData, fd *pcode.Funcdata, entryPoint bool) {
	def := buildModel(engine, cspec, fd, entryPoint, nil)
	def.PrintInDecl = false // The default model's name is never printed
	fd.SetDefaultModel(def)
	named := map[string]*pcode.ProtoModel{def.Name: def}
	if cspec == nil {
		fd.SetModels(named)
		return
	}
	for _, p := range cspec.ExtraProtos {
		c := *cspec
		c.DefaultProto = p
		m := buildModel(engine, &c, fd, entryPoint, def.StackSpace)
		m.PrintInDecl = true
		named[p.Name] = m
	}
	// An alias copies its parent and prints its own name; a missing
	// __thiscall is an alias of the default model.
	// C++ parity: Architecture::createModelAlias and parseCompilerConfig.
	alias := func(name, parent string) {
		if pm := named[parent]; pm != nil && named[name] == nil {
			named[name] = pm.Alias(name)
		}
	}
	for _, a := range cspec.ModelAliases {
		alias(a.Name, a.Parent)
	}
	alias("__thiscall", def.Name)
	for _, rp := range cspec.ResolvePrototypes {
		var comps []*pcode.ProtoModel
		for _, n := range rp.Models {
			if m := named[n]; m != nil {
				comps = append(comps, m)
			}
		}
		if len(comps) == len(rp.Models) && len(comps) > 0 {
			named[rp.Name] = pcode.NewMergedModel(rp.Name, comps)
		}
	}
	fd.SetModels(named)
	if cspec.EvalCurrent == "" || cspec.EvalCurrent == def.Name {
		return
	}
	if eval := named[cspec.EvalCurrent]; eval != nil {
		fd.SetEvalCurrentModel(eval)
	}
}

// buildModel builds one prototype model from cspec.DefaultProto. A non-nil
// stack reuses an existing stack space so every model of the function agrees
// on it.
func buildModel(engine *sla.Engine, cspec *pcode.CspecData, fd *pcode.Funcdata, entryPoint bool, stack *address.Space) *pcode.ProtoModel {
	xr := engine.XRefs()
	// regLookup resolves register names to their register-space byte offset so
	// NewProtoModelFromCspec can populate RegParamOffsets from the cspec's
	// IntegerRegParams(). For x86-32 cdecl IntegerRegParams() is empty, so this is
	// a no-op and RegParamOffsets stays nil -- identical to prior behavior.
	regLookup := func(name string) (uint64, bool) {
		_, off, _, ok := xr.RegisterByName(name)
		return off, ok
	}
	model := pcode.NewProtoModelFromCspec(cspec, nil, regLookup)
	// Faithful stack path: create the stack spacebase space up front and register
	// the stack pointer as its base. This gives Funcdata.Spacebase (ActionSpacebase)
	// and RuleLoadVarnode/RuleStoreVarnode a real stack space to mark and write
	// into. It is set on the default evaluation model, which drives the
	// universal-action tree -- the production decompile path since H8-debt-2. The
	// bespoke ActionStackPtrFlow is no longer on the production path (it survives
	// only in legacy test harnesses pending Step 3 retirement).
	if cspec != nil {
		if stack != nil {
			model.StackSpace = stack
		} else if ss := buildFaithfulStackSpace(xr, cspec, fd); ss != nil {
			model.StackSpace = ss
		}
		// Build the faithful input parameter-storage model (ParamListStandard)
		// from the cspec <input> pentries. This drives FuncProto::deriveInputMap
		// (ActionInputPrototype) so stack parameters that only materialize after
		// ActionSpacebase are still recovered. Requires model.StackSpace so the
		// stack <pentry> resolves; built here after StackSpace is set.
		ptrSize := int32(cspec.PointerSize())
		regNames := engine.RegisterNamesByLocation()
		regName := func(sp *address.Space, off uint64, size int32) string {
			return regNames[fmt.Sprintf("%d:%d:%d", sp.Index, off, size)]
		}
		if specs := buildInputPentrySpecs(xr, cspec, model, fd); len(specs) > 0 {
			pl := pcode.NewParamListStandard(specs)
			pl.SetJoinContext(joinSpaceFor(fd), regName)
			in := cspec.DefaultProto.Input
			pl.SetModelRules(in.Rules, in.PointerMax, ptrSize, false)
			model.SetInputParams(pl)
		}
		if specs := buildOutputPentrySpecs(xr, cspec, fd); len(specs) > 0 {
			pl := pcode.NewParamListStandard(specs)
			pl.SetJoinContext(joinSpaceFor(fd), regName)
			pl.SetModelRules(cspec.DefaultProto.Output.Rules, 0, ptrSize, true)
			// A return list without a rule deciding the return storage kills
			// every return location. C++ parity: ParamListStandardOut::initialize.
			if pl.AutoKilledByCallLegacy() {
				model.AutoKilledByCall = true
			}
			model.SetOutputParams(pl)
		}
	}
	// Entry-point functions use the stack-based processEntry convention: register
	// argument slots stay known (RegParamOffsets) but are not recovered as named
	// parameters, so live-on-entry argument registers render as in_<reg>.
	model.EntryPoint = entryPoint
	model.WithEffectOffsets(func(name string) (uint64, int32, bool) {
		_, off, sz, ok := xr.RegisterByName(name)
		return off, int32(sz), ok
	})
	if cspec != nil {
		model.SetEffects(buildEffectList(xr, cspec, fd, model.StackSpace))
		model.LikelyTrash = buildLikelyTrash(xr, cspec, fd)
		// Parameter range from the stack <pentry> extents (base .. base+maxsize-1).
		// C++ parity: ParamListStandard::getRangeList.
		for _, pe := range cspec.InputPentries() {
			if pe.Addr != nil && pe.Addr.Space == "stack" && pe.MaxSize > 0 {
				base := uint64(pe.Addr.Offset)
				model.StackParamRanges = append(model.StackParamRanges, [2]uint64{base, base + uint64(pe.MaxSize) - 1})
			}
		}
	}

	// Wire the integer return register from the cspec default-proto <output> block
	// (EAX / RAX / x0 by arch) so guardReturns can recover the return value at the
	// correct location and width. Falls back to the x86 EAX scan below when no
	// cspec return register is available.
	if retName := cspec.IntegerReturnReg(); retName != "" {
		// Use the register's natural width (RegisterByName size) so the return slot
		// matches RAX (8) / EAX (4) / x0 (8) without per-arch hardcoding.
		if si, off, sz, ok := xr.RegisterByName(retName); ok {
			model.WithReturnReg(int(si), off, int32(sz))
			return model
		}
	}
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if sp.Kind == address.SpaceKindProcessor && sp.Name == "register" {
			model.WithReturnReg(int(sp.Index), 0, 4)
			break
		}
	}
	return model
}

// buildEffectList resolves the default prototype's <unaffected>/<killedbycall>
// storage, plus the global return address, into EffectRecords.
// C++ parity: fspec.cc ProtoModel::decode (effectlist from ELEM_UNAFFECTED,
// ELEM_KILLEDBYCALL, and glb->defaultReturnAddr when the model has no
// <returnaddress> of its own).
// buildLikelyTrash resolves the model's <likelytrash> registers.
// C++ parity: ProtoModel::decode (likelytrash), sorted as VarnodeData.
func buildLikelyTrash(xr *sla.XRefs, cspec *pcode.CspecData, fd *pcode.Funcdata) []pcode.VarnodeData {
	if cspec.DefaultProto == nil {
		return nil
	}
	var out []pcode.VarnodeData
	for _, r := range cspec.DefaultProto.LikelyTrash.Registers {
		si, off, sz, ok := xr.RegisterByName(r.Name)
		if !ok {
			continue
		}
		if sp, _ := registerSpaceByIndex(fd, si); sp != nil {
			out = append(out, pcode.VarnodeData{Space: sp, Offset: off, Size: uint32(sz)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return pcode.VarnodeDataLess(out[i], out[j]) })
	return out
}

func buildEffectList(xr *sla.XRefs, cspec *pcode.CspecData, fd *pcode.Funcdata, stack *address.Space) []pcode.EffectRecord {
	if cspec.DefaultProto == nil {
		return nil
	}
	spaceByName := func(name string) *address.Space {
		if stack != nil && stack.Name == name {
			return stack
		}
		if base := fd.BaseAddr().Space; base != nil && base.Name == name {
			return base
		}
		for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
			if sp := vn.Space(); sp != nil && sp.Name == name {
				return sp
			}
		}
		return nil
	}
	var out []pcode.EffectRecord
	add := func(list pcode.CspecRegList, kind pcode.EffectKind) {
		for _, r := range list.Registers {
			si, off, sz, ok := xr.RegisterByName(r.Name)
			if !ok {
				continue
			}
			if sp, _ := registerSpaceByIndex(fd, si); sp != nil {
				out = append(out, pcode.EffectRecord{Addr: address.Address{Space: sp, Offset: off}, Size: int32(sz), Type: kind})
			}
		}
		for _, v := range list.Varnodes {
			if sp := spaceByName(v.Space); sp != nil {
				out = append(out, pcode.EffectRecord{Addr: address.Address{Space: sp, Offset: uint64(v.Offset)}, Size: int32(v.Size), Type: kind})
			}
		}
	}
	add(cspec.DefaultProto.Unaffected, pcode.EffectUnaffected)
	add(cspec.DefaultProto.KilledByCall, pcode.EffectKilledByCall)
	// <output killedbycall="true">: each register output entry is killed by
	// the call (sized by the entry). C++ parity: fspec.cc
	// ParamListStandard::parsePentry (autoKilledByCall).
	if cspec.DefaultProto.Output.KilledByCall {
		for _, pe := range cspec.DefaultProto.Output.Pentries {
			if pe.Register == nil {
				continue // join / stack entries
			}
			si, off, sz, ok := xr.RegisterByName(pe.Register.Name)
			if !ok {
				continue
			}
			if sp, _ := registerSpaceByIndex(fd, si); sp != nil {
				size := int32(sz)
				if pe.MaxSize > 0 && int32(pe.MaxSize) < size {
					size = int32(pe.MaxSize)
				}
				out = append(out, pcode.EffectRecord{Addr: address.Address{Space: sp, Offset: off}, Size: size, Type: pcode.EffectKilledByCall})
			}
		}
	}
	if ra := cspec.ReturnAddress; ra != nil {
		if sp := spaceByName(ra.Space); sp != nil {
			out = append(out, pcode.EffectRecord{Addr: address.Address{Space: sp, Offset: uint64(ra.Offset)}, Size: int32(ra.Size), Type: pcode.EffectReturnAddress})
		}
	}
	return out
}

// buildFaithfulStackSpace constructs the stack spacebase space for the INC-1
// faithful path: it resolves the stack pointer register from the cspec, finds
// the register storage space among the function's varnodes, and registers the
// SP as the stack space's base. Returns nil when the SP register cannot be
// resolved (e.g. cspec-less builds), leaving StackSpace nil as before.
func buildFaithfulStackSpace(xr *sla.XRefs, cspec *pcode.CspecData, fd *pcode.Funcdata) *address.Space {
	spName := cspec.StackPointerReg
	if spName == "" {
		return nil
	}
	si, off, sz, ok := xr.RegisterByName(spName)
	if !ok || sz <= 0 {
		return nil
	}
	regSpace, maxIdx := registerSpaceByIndex(fd, si)
	if regSpace == nil {
		return nil
	}
	// The stack (spacebase) space takes an index above every real space so its
	// varnodes sort after register/unique temps in declaration output.
	// registerSpaceByIndex now excludes the const space (Index = 0xFFFF) from
	// maxIdx, so maxIdx is the highest real space index and `maxIdx + 1` no longer
	// overflows uint16 to 0 (which previously dropped the stack space below every
	// real space and reordered grid_score's `int iVar1;` declaration).
	// C++ parity: AddrSpaceManager::addSpacebase (architecture.cc:563) assigns the
	// spacebase space numSpaces() -- one past the last real space.
	// The spacebase space heritages one pass behind the space its base register
	// lives in, so the stack pointer is resolved before stack slots are heritaged.
	// C++ parity: architecture.cc Architecture::addSpacebase (line 565) passes
	// ptrdata.space->getDelay()+1 as the SpacebaseSpace delay.
	// The join space precedes the spacebase space (architecture.cc:634 inserts
	// fspec, iop and join after the processor spaces).
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		Index:    maxIdx + 2,
		AddrSize: uint8(sz),
		WordSize: 1,
		Delay:    regSpace.Delay + 1,
	}
	stackSpace.AddSpacebase(address.SpacebaseData{Space: regSpace, Offset: off, Size: int32(sz)})
	return stackSpace
}

// registerSpaceByIndex returns the address.Space pointer for the given space
// index from the function's existing varnodes, plus the maximum space index
// seen (so the synthetic stack space gets a non-colliding index).
func registerSpaceByIndex(fd *pcode.Funcdata, si int64) (*address.Space, uint16) {
	var found *address.Space
	maxIdx := uint16(0)
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		sp := vn.Space()
		if sp == nil {
			continue
		}
		// Exclude the const space from the max. Ghidra fixes the constant space at
		// index 0 (translate.cc:362 "constant space must be assigned index 0"), so
		// it is never the top ordinal; our const space carries Index = 0xFFFF, which
		// would overflow `maxIdx + 1` to 0 and drop the stack space below every real
		// space. The stack (spacebase) space is appended at load above all real
		// spaces (architecture.cc:563 addSpacebase uses numSpaces()), so it must
		// receive the real high index.
		if sp.Kind != address.SpaceKindConstant && sp.Index > maxIdx {
			maxIdx = sp.Index
		}
		if found == nil && int64(sp.Index) == si {
			found = sp
		}
	}
	return found, maxIdx
}

// buildInputPentrySpecs resolves the cspec default-proto <input> pentries into
// pcode.ParamEntrySpec records for NewParamListStandard. Register pentries are
// resolved to their register-space offset via xr.RegisterByName; the stack
// pentry uses model.StackSpace. Group ids are assigned in document order: each
// <group> shares one id, then top-level pentries (the stack entry) each take a
// fresh id -- matching the ParamListStandard::decode numgroup sequence for the
// x86/x64 ABIs.
// C++ parity: ParamListStandard::decode + parseGroup/parsePentry group ids.
func buildInputPentrySpecs(xr *sla.XRefs, cspec *pcode.CspecData, model *pcode.ProtoModel, fd *pcode.Funcdata) []pcode.ParamEntrySpec {
	if cspec == nil || cspec.DefaultProto == nil {
		return nil
	}
	var specs []pcode.ParamEntrySpec
	var group int32
	var regSpace *address.Space
	addPentry := func(pe pcode.CspecPentry, grp int32, grouped bool) bool {
		spec := pcode.ParamEntrySpec{
			MinSize: int32(pe.MinSize),
			MaxSize: int32(pe.MaxSize),
			Align:   int32(pe.Align),
			IsFloat: pe.Metatype == "float" || pe.Storage == "float",
			Grouped: grouped,
			GroupID: grp,
		}
		switch {
		case pe.Register != nil:
			si, off, _, ok := xr.RegisterByName(pe.Register.Name)
			if !ok {
				return false
			}
			if regSpace == nil {
				regSpace, _ = registerSpaceByIndex(fd, si)
			}
			if regSpace == nil {
				return false
			}
			spec.Space = regSpace
			spec.BigEndian = regSpace.BigEndian
			spec.AddressBase = off
		case pe.Addr != nil && pe.Addr.Space == "stack":
			if model.StackSpace == nil {
				return false
			}
			spec.Space = model.StackSpace
			spec.BigEndian = model.StackSpace.BigEndian
			spec.AddressBase = uint64(pe.Addr.Offset)
		default:
			return false // unsupported storage (e.g. join/hiddenret) -- skip
		}
		specs = append(specs, spec)
		return true
	}
	// Groups first (document order), each a shared group id.
	for _, g := range cspec.DefaultProto.Input.Groups {
		added := false
		for _, pe := range g.Pentries {
			if addPentry(pe, group, true) {
				added = true
			}
		}
		if added {
			group++
		}
	}
	// Then top-level pentries (the stack entry), each its own group.
	for _, pe := range cspec.DefaultProto.Input.Pentries {
		if addPentry(pe, group, false) {
			group++
		}
	}
	return specs
}

// joinSpaceFor installs and returns the function's join space, indexed just
// past the processor spaces. C++ parity: Architecture::restoreFromSpec.
func joinSpaceFor(fd *pcode.Funcdata) *address.Space {
	if js := fd.JoinSpace(); js != nil {
		return js
	}
	_, maxIdx := registerSpaceByIndex(fd, -1)
	js := address.JoinSpaceAt(maxIdx + 1)
	fd.SetJoinSpace(js, fd.BaseAddr().Space)
	return js
}

// buildOutputPentrySpecs resolves the cspec default-proto <output> pentries,
// each its own group in document order; a join pentry resolves its pieces
// (most significant first) to a join record.
// C++ parity: ParamListStandard::decode for the output list.
func buildOutputPentrySpecs(xr *sla.XRefs, cspec *pcode.CspecData, fd *pcode.Funcdata) []pcode.ParamEntrySpec {
	if cspec == nil || cspec.DefaultProto == nil {
		return nil
	}
	reg := func(name string) (address.VarnodeData, bool) {
		si, off, sz, ok := xr.RegisterByName(name)
		if !ok {
			return address.VarnodeData{}, false
		}
		sp, _ := registerSpaceByIndex(fd, si)
		if sp == nil {
			return address.VarnodeData{}, false
		}
		return address.VarnodeData{Space: sp, Offset: off, Size: int32(sz)}, true
	}
	var specs []pcode.ParamEntrySpec
	var group int32
	for _, pe := range cspec.DefaultProto.Output.Pentries {
		spec := pcode.ParamEntrySpec{
			MinSize: int32(pe.MinSize),
			MaxSize: int32(pe.MaxSize),
			Align:   int32(pe.Align),
			IsFloat: pe.Metatype == "float" || pe.Storage == "float",
			GroupID: group,
		}
		switch {
		case pe.Register != nil:
			v, ok := reg(pe.Register.Name)
			if !ok {
				continue
			}
			spec.Space = v.Space
			spec.BigEndian = v.Space.BigEndian
			spec.AddressBase = v.Offset
		case pe.Addr != nil && pe.Addr.Space == "join" && pe.Addr.Piece1 != "" && pe.Addr.Piece2 != "":
			hi, ok1 := reg(pe.Addr.Piece1)
			lo, ok2 := reg(pe.Addr.Piece2)
			if !ok1 || !ok2 {
				continue
			}
			js := joinSpaceFor(fd)
			rec := address.FindAddJoin(js, []address.VarnodeData{hi, lo}, 0)
			spec.Space = js
			spec.AddressBase = rec.Unified.Offset
			spec.Join = rec
		default:
			continue
		}
		specs = append(specs, spec)
		group++
	}
	return specs
}

// buildSpaceIndex builds an index -> address.Space map covering the spaces the
// function references (entry/ram, heritage spaces, constant, unique), used to
// resolve LOAD/STORE space-id constants back to their target space.
func buildSpaceIndex(entrySpace *address.Space, summary spaceSummary) map[uint16]*address.Space {
	byIndex := make(map[uint16]*address.Space)
	add := func(sp *address.Space) {
		if sp != nil {
			byIndex[sp.Index] = sp
		}
	}
	add(entrySpace)
	add(summary.constSpace)
	add(summary.uniqueSpace)
	for _, sp := range summary.heritageSpaces {
		add(sp)
	}
	return byIndex
}

// bindLoadStoreSpaces binds the resolved target space onto each LOAD/STORE
// space-id constant so loadStoreSpace can recover it.
func bindLoadStoreSpaces(fd *pcode.Funcdata, byIndex map[uint16]*address.Space) {
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		c := op.Code()
		if c != pcode.CPUI_LOAD && c != pcode.CPUI_STORE {
			continue
		}
		sel := op.Input(0)
		if sel == nil || !sel.IsConstant() {
			continue
		}
		if sp := byIndex[uint16(sel.Offset())]; sp != nil {
			pcode.BindSpaceConstant(sel, sp)
		}
	}
}

func BuildFuncdata(engine *sla.Engine, cfg BuildConfig) (*pcode.Funcdata, error) {
	result, err := Build(engine, cfg)
	if err != nil {
		return nil, err
	}
	return result.Funcdata, nil
}

func collectInstructions(engine *sla.Engine, cfg BuildConfig) ([]instructionRecord, []string, error) {
	return collectInstructionsSeeded(engine, cfg, nil)
}

// collectInstructionsSeeded is collectInstructions with extra worklist seed
// addresses. Build uses it to re-decode a switch's case bodies after jump-table
// recovery: the recovered case-target addresses are only reachable through the
// BRANCHIND, so a plain entry-rooted scan never sees them. Seeding them makes the
// worklist follow each case body to its terminator, exactly as Ghidra's
// generateOps calls newAddress(jt->getAddressByIndex(i)) + fallthru() for every
// recovered table entry (flow.cc:806-809). With nil seeds this is byte-identical
// to the original single-root collection.
func collectInstructionsSeeded(engine *sla.Engine, cfg BuildConfig, seeds []address.Address) ([]instructionRecord, []string, error) {
	return collectInstructionsTolerant(engine, cfg, seeds, false)
}

// collectInstructionsTolerant is collectInstructionsSeeded with an option to keep
// the recovered flow when a followed address cannot be decoded. With
// tolerateBadFlow=false (the live-build default) an undecodable address aborts the
// scan exactly as before, so main-path collection is byte-identical. With
// tolerateBadFlow=true (the jump-table recovery clone) an undecodable branch
// target or fall-through stops only that path and the already-decoded records are
// still flow-analyzed, so block boundaries at guard CBRANCHs form even when the
// guard's other edge leaves the loaded image.
func collectInstructionsTolerant(engine *sla.Engine, cfg BuildConfig, seeds []address.Address, tolerateBadFlow bool) ([]instructionRecord, []string, error) {
	limit := cfg.MaxInstructions
	if limit <= 0 {
		limit = int(^uint(0) >> 1)
	}

	known := make(map[address.Address]int)
	records := make([]instructionRecord, 0, min(limit, 16))

	// pending holds addresses yet to be scanned. We use a worklist so that
	// branch targets reachable only via a forward/unconditional branch are also
	// collected. The entry point is always the first item; recovered switch-case
	// seeds (if any) follow it so case bodies decode after the entry flow.
	//
	// C++ ref: FlowInfo::generate / FlowInfo::setRange in FlowInfo.cc collects
	// all reachable addresses by following branch targets recursively.
	pending := []address.Address{cfg.Entry}
	pendingSeen := map[address.Address]struct{}{cfg.Entry: {}}
	for _, s := range seeds {
		if s.IsInvalid() {
			continue
		}
		if _, ok := pendingSeen[s]; !ok {
			pendingSeen[s] = struct{}{}
			pending = append(pending, s)
		}
	}

	for len(pending) > 0 && len(records) < limit {
		cur := pending[0]
		pending = pending[1:]

		// Linear scan from cur until a hard terminator, range boundary, or limit.
		for len(records) < limit {
			if !cfg.End.IsInvalid() {
				if !sameSpace(cur, cfg.End) {
					return nil, nil, fmt.Errorf("build bridge: end address %v is not in entry space %v", cfg.End, cfg.Entry.Space)
				}
				if !cur.Less(cfg.End) {
					break
				}
			}
			if _, exists := known[cur]; exists {
				// Already collected via another path; stop this linear scan.
				break
			}

			translation, err := engine.TranslateInstructionAt(cur)
			if err != nil {
				if tolerateBadFlow && len(records) > 0 {
					// Recovery clone: an undecodable address (a guard branch target
					// outside the loaded image, or a fall-through past the end) does
					// not discard the flow already recovered. Stop this path and let
					// the outer worklist / final flow analysis proceed.
					break
				}
				var unimplErr *sla.UnimplError
				if errors.As(err, &unimplErr) {
					warn := fmt.Sprintf("unimplemented at %v: %v", cur, err)
					return records, []string{warn}, nil
				}
				return nil, nil, fmt.Errorf("build bridge: translate instruction at %v: %w", cur, err)
			}
			if t, ok := cfg.FlowOverrides[cur.Offset]; ok {
				translation = applyFlowOverride(translation, t)
			}
			// An overridden CALLIND is a direct CALL before the no-return
			// check, so a call through an import to ExitProcess halts.
			// C++ parity: FlowInfo::setupCallindSpecs (applyIndirect, then
			// queryCall and checkForFlowModification).
			translation = applyIndirectOverride(translation, cfg.IndirectOverrides)
			translation = haltAfterNoReturnCall(translation, cfg.HostScope)
			// An instruction may legitimately emit no p-code (NOP, multi-byte
			// NOP alignment padding). It is kept for flow; references to its
			// address resolve to the next instruction (zeroOpRedirect).
			// C++ parity: flow.cc FlowInfo::target falls through no-op instructions.
			if translation.Length <= 0 && translation.Next == cur {
				return nil, nil, fmt.Errorf("build bridge: instruction %v did not advance", cur)
			}

			records = append(records, instructionRecord{translation: translation})
			known[cur] = len(records) - 1

			if translation.Next == cur {
				break
			}

			// Enqueue any direct branch target for later worklist processing.
			// We enqueue now (before building knownAddrs) so that the target is
			// added even when this linear scan terminates early.
			if cfg.End.IsInvalid() {
				if target, ok := extractBranchTarget(translation, cfg.Entry.Space); ok {
					if _, seen := pendingSeen[target]; !seen {
						pendingSeen[target] = struct{}{}
						pending = append(pending, target)
					}
				}
			}

			// When no explicit End address is given, stop linear scan on an unconditional terminator
			// (RETURN, BRANCHIND, or BRANCH). Without this guard the scanner follows translation.Next
			// past the end of the function into uninitialised bytes, collecting garbage instructions
			// and corrupting the knownAddrs set used by resolveTarget.
			//
			// When End is set the caller defines the exact byte range to collect (e.g. bridge_test.go
			// BRK_BRK), so we honour the range boundary instead and let the loop continue.
			//
			// CBRANCH is excluded: its fall-through edge always points to the next sequential address,
			// so we must continue collecting that instruction.
			//
			// C++ ref: FlowInfo::setRange / FlowInfo::hasTerminator in FlowInfo.cc.
			if cfg.End.IsInvalid() && hasHardTerminator(translation) {
				break
			}
			cur = translation.Next
		}
	}

	if len(records) == 0 {
		return nil, nil, nil
	}

	knownAddrs := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		knownAddrs[record.translation.Address] = struct{}{}
	}
	for idx := range records {
		records[idx].flow = analyzeInstructionFlow(records[idx].translation, cfg.Entry.Space, knownAddrs)
	}

	return records, nil, nil
}

// extractBranchTarget returns the branch target address embedded in a BRANCH or
// CBRANCH op, if one exists. Used by the worklist to enqueue unreachable-by-
// linear-scan targets before knownAddrs is built.
func extractBranchTarget(translation sla.InstructionTranslation, entrySpace *address.Space) (address.Address, bool) {
	for _, raw := range translation.Ops {
		switch raw.OpCode {
		case pcode.CPUI_BRANCH, pcode.CPUI_CBRANCH:
			if len(raw.Inputs) == 0 {
				continue
			}
			input := raw.Inputs[0]
			if input.Space == nil {
				continue
			}
			if input.Space.Kind != address.SpaceKindConstant {
				return input.Address(), true
			}
			// A constant-space operand is a relative p-code op offset inside
			// the instruction (C++ FlowInfo::findRelTarget), not an address.
		}
	}
	return address.Address{}, false
}

func summarizeSpaces(records []instructionRecord, entrySpace *address.Space) spaceSummary {
	summary := spaceSummary{
		constSpace:  defaultConstSpace(),
		uniqueSpace: defaultUniqueSpace(entrySpace),
	}
	heritageSet := make(map[*address.Space]struct{})
	// The default data space is heritaged even when raw p-code reaches it
	// only through LOAD/STORE: RuleStoreVarnode later turns a store to a
	// constant address (FS:[0], ExceptionList) into a ram Varnode that
	// needs its guards. C++ parity: Heritage::buildInfoList walks every
	// space of the AddrSpaceManager.
	for _, record := range records {
		for _, op := range record.translation.Ops {
			for _, input := range op.Inputs {
				summary.observe(&input)
				summary.collectHeritageSpace(input.Space, entrySpace, heritageSet)
			}
			if op.Output != nil {
				summary.observe(op.Output)
				summary.collectHeritageSpace(op.Output.Space, entrySpace, heritageSet)
			}
		}
	}
	summary.collectHeritageSpace(entrySpace, entrySpace, heritageSet)
	return summary
}

func (s *spaceSummary) observe(vn *pcode.VarnodeData) {
	if vn == nil || vn.Space == nil {
		return
	}
	switch vn.Space.Kind {
	case address.SpaceKindConstant:
		s.constSpace = vn.Space
	case address.SpaceKindUnique:
		s.uniqueSpace = vn.Space
	}
}

func (s *spaceSummary) collectHeritageSpace(space *address.Space, entrySpace *address.Space, seen map[*address.Space]struct{}) {
	if space == nil {
		return
	}
	if space.Kind == address.SpaceKindConstant {
		return
	}
	if _, exists := seen[space]; exists {
		return
	}
	seen[space] = struct{}{}
	s.heritageSpaces = append(s.heritageSpaces, space)
}

func discoverBlockStarts(records []instructionRecord) map[address.Address]bool {
	starts := make(map[address.Address]bool, len(records))
	if len(records) == 0 {
		return starts
	}
	redirect := zeroOpRedirect(records)
	mark := func(a address.Address) {
		if to, ok := redirect[a]; ok {
			a = to
		}
		starts[a] = true
	}
	mark(records[0].translation.Address)

	known := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		known[record.translation.Address] = struct{}{}
	}

	for _, record := range records {
		if record.flow.hasDirect {
			if _, exists := known[record.flow.directTarget]; exists {
				mark(record.flow.directTarget)
			}
		}
		if nextStartsBlock(record.translation.Ops) {
			if _, exists := known[record.translation.Next]; exists {
				mark(record.translation.Next)
			}
		}
	}

	return starts
}

// nextStartsBlock reports whether the instruction after these ops begins a
// basic block: a relative branch jumps to the end of the instruction, or the
// last op kept is a branch, return or halt. A branch inside the instruction
// whose target is another of its ops leaves the following instruction in the
// same block as the instruction's tail.
// C++ parity: flow.cc FlowInfo::xrefControlFlow (startbasic after the loop).
func nextStartsBlock(ops []pcode.RawOp) bool {
	if len(ops) == 0 {
		return false
	}
	bounds := splitInstruction(ops)
	n := bounds[len(bounds)-1][1]
	for i := 0; i < n; i++ {
		if t, rel := relativeTargetIndex(ops, i); rel && t >= len(ops) {
			return true // isfallthru: explicit branch to the next instruction
		}
	}
	switch ops[n-1].OpCode {
	case pcode.CPUI_BRANCH, pcode.CPUI_CBRANCH, pcode.CPUI_BRANCHIND, pcode.CPUI_RETURN:
		return true
	}
	return false
}

// applyFlowOverride rewrites the instruction's primary branch op as the host
// override says, before flow is followed: CALL / CALL_RETURN turn a branch
// into a call (CALL_RETURN also appends a RETURN), BRANCH turns a call or
// return into a branch, RETURN turns an indirect branch or call into a return.
// The appended RETURN's constant input takes the function's constant space
// later (fixFlowOverrideReturns).
// C++ parity: funcdata_op.cc Funcdata::overrideFlow (findPrimaryBranch: the
// last branching op of the instruction).
func applyFlowOverride(tr sla.InstructionTranslation, kind string) sla.InstructionTranslation {
	idx := -1
	for i := len(tr.Ops) - 1; i >= 0; i-- {
		switch tr.Ops[i].OpCode {
		case pcode.CPUI_BRANCH, pcode.CPUI_BRANCHIND, pcode.CPUI_CBRANCH, pcode.CPUI_CALL, pcode.CPUI_CALLIND, pcode.CPUI_RETURN:
			idx = i
		}
		if idx >= 0 {
			break
		}
	}
	if idx < 0 {
		return tr
	}
	ops := append([]pcode.RawOp(nil), tr.Ops...)
	op := &ops[idx]
	switch kind {
	case "BRANCH":
		switch op.OpCode {
		case pcode.CPUI_CALL:
			op.OpCode = pcode.CPUI_BRANCH
		case pcode.CPUI_CALLIND, pcode.CPUI_RETURN:
			op.OpCode = pcode.CPUI_BRANCHIND
		}
	case "CALL", "CALL_RETURN":
		switch op.OpCode {
		case pcode.CPUI_BRANCH:
			op.OpCode = pcode.CPUI_CALL
		case pcode.CPUI_BRANCHIND, pcode.CPUI_RETURN:
			op.OpCode = pcode.CPUI_CALLIND
		case pcode.CPUI_CBRANCH:
			return tr // C++: "Do not currently support CBRANCH overrides"
		}
		if kind == "CALL_RETURN" {
			ret := pcode.RawOp{
				SeqNum: op.SeqNum,
				OpCode: pcode.CPUI_RETURN,
				Inputs: []pcode.VarnodeData{{Space: nil, Offset: 0, Size: 1}},
			}
			ret.SeqNum.Order = ops[len(ops)-1].SeqNum.Order + 1
			ret.SeqNum.Time = ops[len(ops)-1].SeqNum.Time + 1
			ops = append(ops, ret)
		}
	case "RETURN":
		if op.OpCode == pcode.CPUI_BRANCHIND || op.OpCode == pcode.CPUI_CALLIND {
			op.OpCode = pcode.CPUI_RETURN
		}
	}
	tr.Ops = ops
	return tr
}

// fixFlowOverrideReturns gives each RETURN op appended by applyFlowOverride
// the function's constant space for its zero input.
func fixFlowOverrideReturns(records []instructionRecord, constSpace *address.Space) {
	for i := range records {
		ops := records[i].translation.Ops
		for j := range ops {
			if ops[j].OpCode == pcode.CPUI_RETURN && len(ops[j].Inputs) == 1 && ops[j].Inputs[0].Space == nil {
				ops[j].Inputs[0].Space = constSpace
			}
		}
	}
}

// applyIndirectOverride rewrites an overridden CALLIND into a direct CALL.
// C++ parity: FlowInfo::setupCallindSpecs (Override::getIndirectOverride).
func applyIndirectOverride(tr sla.InstructionTranslation, ov map[uint64]address.Address) sla.InstructionTranslation {
	target, ok := ov[tr.Address.Offset]
	if !ok {
		return tr
	}
	ops := append([]pcode.RawOp(nil), tr.Ops...)
	for j := range ops {
		if ops[j].OpCode != pcode.CPUI_CALLIND || len(ops[j].Inputs) == 0 {
			continue
		}
		ops[j].Inputs = append([]pcode.VarnodeData(nil), ops[j].Inputs...)
		ops[j].OpCode = pcode.CPUI_CALL
		ops[j].Inputs[0].Space = target.Space
		ops[j].Inputs[0].Offset = target.Offset
	}
	tr.Ops = ops
	return tr
}

// zeroOpRedirect maps each instruction that emitted no p-code to the first
// following instruction (by fall-through) that did; a branch to a no-op lands
// on that instruction's first op.
// C++ parity: flow.cc FlowInfo::target (visits fall-thru addresses of no-ops).
func zeroOpRedirect(records []instructionRecord) map[address.Address]address.Address {
	byAddr := make(map[address.Address]*instructionRecord, len(records))
	for i := range records {
		byAddr[records[i].translation.Address] = &records[i]
	}
	out := map[address.Address]address.Address{}
	for _, r := range records {
		if len(r.translation.Ops) != 0 {
			continue
		}
		cur := r.translation.Next
		for steps := 0; steps < len(records); steps++ {
			nr, ok := byAddr[cur]
			if !ok {
				break
			}
			if len(nr.translation.Ops) != 0 {
				out[r.translation.Address] = cur
				break
			}
			cur = nr.translation.Next
		}
	}
	return out
}

func addInstructionOps(fd *pcode.Funcdata, block *pcode.BlockBasic, translation sla.InstructionTranslation) error {
	if fd == nil || block == nil {
		return fmt.Errorf("build bridge: funcdata or block is nil")
	}
	for _, raw := range translation.Ops {
		op := fd.GetPcodeOpBank().CreateWithSeq(len(raw.Inputs), raw.SeqNum)
		fd.OpSetOpcode(op, raw.OpCode)
		appendAliveOp(fd, block, op)

		for slot, input := range raw.Inputs {
			if slot == 0 && op.IsCodeRef() {
				// C++ parity: PcodeEmitFd::dump -- a branch / call destination
				// is a code reference annotation, not a read of memory.
				fd.OpSetInput(op, fd.NewCodeRef(input.Address()), 0)
				continue
			}
			vn := resolveInput(fd, input)
			fd.OpSetInput(op, vn, slot)
		}
		if raw.Output != nil {
			fd.NewVarnodeOut(int32(raw.Output.Size), raw.Output.Address(), op)
		}
	}
	return nil
}

func appendAliveOp(fd *pcode.Funcdata, block *pcode.BlockBasic, op *pcode.PcodeOp) {
	if fd == nil || block == nil || op == nil {
		return
	}
	if block.NumOps() == 0 {
		op.SetFlag(pcode.PcodeOpStartBasic)
	}
	op.SetParent(block)
	block.AddOp(op)
	fd.OpMarkAlive(op)
}

func resolveInput(fd *pcode.Funcdata, input pcode.VarnodeData) *pcode.Varnode {
	if input.Space != nil && input.Space.IsConstant() {
		return fd.NewConstant(int32(input.Size), input.Offset)
	}

	// Every read, a temporary included, stays free for heritage: a unique
	// offset reused at different sizes across instructions (a 4-byte and a
	// 1-byte temporary at the same offset) is normalized with SUBPIECE/PIECE
	// like a register, which changes the order rules see the data-flow in.
	// C++ parity: PcodeEmitFd::dump creates a fresh Varnode for every input.
	return fd.NewVarnode(int32(input.Size), input.Address())
}

func addCFGEdges(graph *pcode.BlockGraph, blockByAddr map[address.Address]*pcode.BlockBasic, instToBlock map[address.Address]*pcode.BlockBasic, lastInBlock map[*pcode.BlockBasic]instructionRecord, recoveredTables map[uint64]*pcode.JumpTable, splitTail map[*pcode.BlockBasic]*pcode.BlockBasic, relTarget map[*pcode.BlockBasic]relLink) {
	seen := make(map[edgeKey]struct{})
	// branchTarget resolves a block's branch destination: an op inside the
	// same instruction, the next instruction for a relative branch past the
	// last op, or a decoded instruction address.
	// C++ parity: FlowInfo::branchTarget / findRelTarget.
	branchTarget := func(block *pcode.BlockBasic, rec instructionRecord) *pcode.BlockBasic {
		if l, ok := relTarget[block]; ok {
			if l.seg != nil {
				return l.seg
			}
			return instToBlock[l.next]
		}
		if rec.flow.hasDirect {
			return blockByAddr[rec.flow.directTarget]
		}
		return nil
	}
	// Visit blocks in dead-list order. Ghidra builds CFG edges by walking the dead
	// op list (FlowInfo::collectEdges, flow.cc:906) and calling bblocks.addEdge in
	// that order (connectBasic, flow.cc:1021); FlowBlock::addInEdge appends without
	// sorting (block.cc:73). The dead list is p-code generation order, which
	// assignFlowTimes reproduced as op times, so a merge block's in-edges land
	// ordered by when flow generated each predecessor, not by its address.
	addrs := make([]address.Address, 0, len(blockByAddr))
	for addr := range blockByAddr {
		addrs = append(addrs, addr)
	}
	firstTime := func(addr address.Address) uint64 {
		if op := blockByAddr[addr].FirstOp(); op != nil {
			return op.Seq().Time
		}
		return ^uint64(0)
	}
	sort.Slice(addrs, func(i, j int) bool {
		ti, tj := firstTime(addrs[i]), firstTime(addrs[j])
		if ti != tj {
			return ti < tj
		}
		return addrs[i].Less(addrs[j])
	})
	for _, addr := range addrs {
		block := blockByAddr[addr]
		// Blocks split inside one instruction: each falls through to the next
		// piece, and a conditional piece also branches to its target.
		for tail := splitTail[block]; tail != nil; tail = splitTail[block] {
			rec := lastInBlock[block]
			if rec.flow.hasFallthrough {
				addEdge(graph, seen, block, tail)
			}
			if t := branchTarget(block, rec); t != nil {
				addEdge(graph, seen, block, t)
			}
			block = tail
		}
		record, exists := lastInBlock[block]
		if !exists {
			continue
		}
		// A BRANCHIND with a recovered jump table gets one out-edge per case
		// target. When there is no table (non-switch, or an unresolved BRANCHIND
		// bound for truncation) the map lookup misses and this is skipped, so the
		// block gets no edges here -- identical to the pre-3b behavior.
		// C++ parity: FlowInfo::collectEdges CPUI_BRANCHIND case (flow.cc:933-946),
		// which findJumpTable()s the op and adds an edge to target(getAddressByIndex(i)).
		if jt := recoveredTables[record.translation.Address.Offset]; jt != nil {
			// Mark the BRANCHIND parent as a switch head. Ghidra sets f_switch_out
			// when the BRANCHIND op is inserted into its block (BlockBasic::insertOp);
			// Gosleigh builds ops and edges separately, so the flag is stamped here,
			// where the recovered table is known. ruleBlockSwitch / isSwitchOut gate
			// switch structuring on this flag.
			// C++ parity: block.cc BlockBasic::insertOp setFlag(f_switch_out).
			block.SetFlag(pcode.BlockFlagSwitchOut)
			codeSpace := record.translation.Address.Space
			for i := 0; i < jt.NumEntries(); i++ {
				target := address.Address{Space: codeSpace, Offset: jt.AddressByIndex(i).Offset}
				addEdge(graph, seen, block, blockByAddr[target])
			}
			continue
		}
		target := branchTarget(block, record)
		if record.flow.conditional {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
			addEdge(graph, seen, block, target)
			continue
		}
		if target != nil {
			addEdge(graph, seen, block, target)
			continue
		}
		if record.flow.hasFallthrough {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
		}
	}
}

// relLink is the destination of a relative branch: seg when it lands on an
// op of the same instruction, else the next instruction.
type relLink struct {
	seg  *pcode.BlockBasic
	next address.Address
}

// relativeTargetIndex returns the op index a relative (constant-space)
// BRANCH/CBRANCH at ops[i] jumps to; len(ops) means the next instruction.
// C++ parity: FlowInfo::findRelTarget (target time = op time + offset).
func relativeTargetIndex(ops []pcode.RawOp, i int) (int, bool) {
	if i < 0 || i >= len(ops) {
		return 0, false
	}
	op := ops[i]
	if (op.OpCode != pcode.CPUI_BRANCH && op.OpCode != pcode.CPUI_CBRANCH) || len(op.Inputs) == 0 {
		return 0, false
	}
	in := op.Inputs[0]
	if in.Space == nil || in.Space.Kind != address.SpaceKindConstant {
		return 0, false
	}
	off := int64(in.Offset)
	if in.Size > 0 && in.Size < 8 {
		shift := 64 - 8*uint(in.Size)
		off = off << shift >> shift
	}
	t := i + int(off)
	if t < 0 || t > len(ops) {
		return 0, false
	}
	return t, true
}

// splitInstruction cuts an instruction's ops into basic-block pieces
// [start,end): after every branch that is not the last op and before every
// op a relative branch targets. Ops after a BRANCH/BRANCHIND/RETURN that no
// earlier relative branch reaches past are dropped.
// C++ parity: FlowInfo::processInstruction (opMarkStartBasic on relative
// targets, startbasic after branches, deleteRemainingOps).
func splitInstruction(ops []pcode.RawOp) [][2]int {
	n := len(ops)
	start := make([]bool, n+1)
	maxTarget := 0
	for i, op := range ops {
		if t, ok := relativeTargetIndex(ops, i); ok && t < n {
			start[t] = true
			if t > maxTarget {
				maxTarget = t
			}
		}
		if (op.OpCode == pcode.CPUI_BRANCH || op.OpCode == pcode.CPUI_BRANCHIND || op.OpCode == pcode.CPUI_RETURN) && i >= maxTarget {
			n = i + 1
			break
		}
		if op.OpCode == pcode.CPUI_BRANCH || op.OpCode == pcode.CPUI_CBRANCH {
			start[i+1] = true
		}
	}
	var segs [][2]int
	from := 0
	for i := 1; i < n; i++ {
		if start[i] {
			segs = append(segs, [2]int{from, i})
			from = i
		}
	}
	return append(segs, [2]int{from, n})
}

func addEdge(graph *pcode.BlockGraph, seen map[edgeKey]struct{}, from *pcode.BlockBasic, to *pcode.BlockBasic) {
	if graph == nil || from == nil || to == nil {
		return
	}
	key := edgeKey{from: from, to: to}
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	graph.AddEdge(&from.FlowBlock, &to.FlowBlock, 0)
}

func analyzeInstructionFlow(translation sla.InstructionTranslation, entrySpace *address.Space, known map[address.Address]struct{}) instructionFlow {
	flow := instructionFlow{}
	for _, raw := range translation.Ops {
		switch raw.OpCode {
		case pcode.CPUI_BRANCH:
			flow.terminates = true
			flow.hasFallthrough = false
			if target, ok := resolveTarget(translation, raw, entrySpace, known); ok {
				flow.directTarget = target
				flow.hasDirect = true
			} else if target, ok := extractBranchTarget(translation, entrySpace); ok {
				flow.undecodedTarget = target
				flow.hasUndecodedTarget = true
			}
		case pcode.CPUI_CBRANCH:
			flow.terminates = true
			flow.conditional = true
			flow.hasFallthrough = true
			flow.fallthroughAddr = translation.Next
			if target, ok := resolveTarget(translation, raw, entrySpace, known); ok {
				flow.directTarget = target
				flow.hasDirect = true
			} else if target, ok := extractBranchTarget(translation, entrySpace); ok {
				flow.undecodedTarget = target
				flow.hasUndecodedTarget = true
			}
		case pcode.CPUI_BRANCHIND, pcode.CPUI_RETURN:
			flow.terminates = true
			flow.hasFallthrough = false
		case pcode.CPUI_CALL, pcode.CPUI_CALLIND, pcode.CPUI_CALLOTHER:
			if !flow.terminates {
				flow.hasFallthrough = true
				flow.fallthroughAddr = translation.Next
			}
		}
	}

	if !flow.terminates && !flow.hasFallthrough && !translation.Next.IsInvalid() {
		flow.hasFallthrough = true
		flow.fallthroughAddr = translation.Next
	}
	return flow
}

func resolveTarget(translation sla.InstructionTranslation, raw pcode.RawOp, entrySpace *address.Space, known map[address.Address]struct{}) (address.Address, bool) {
	if len(raw.Inputs) == 0 {
		return address.Address{}, false
	}
	input := raw.Inputs[0]
	if input.Space == nil {
		return address.Address{}, false
	}
	if input.Space.Kind != address.SpaceKindConstant {
		target := input.Address()
		_, exists := known[target]
		return target, exists
	}
	// Relative branch: resolved inside the instruction (relTarget).
	return address.Address{}, false
}

func truncateConstantForSize(value uint64, size int32) uint64 {
	if size <= 0 {
		return value
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return value
	}
	return value & ((uint64(1) << bits) - 1)
}

func signBitForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return uint64(1) << 63
	}
	return uint64(1) << (bits - 1)
}

func allOnesForSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	bits := uint(size) * 8
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func addSignedOffset(base address.Address, delta int64) (address.Address, bool) {
	if base.Space == nil {
		return address.Address{}, false
	}
	if delta >= 0 {
		return address.Address{Space: base.Space, Offset: base.Offset + uint64(delta)}, true
	}
	magnitude := uint64(-delta)
	if magnitude > base.Offset {
		return address.Address{}, false
	}
	return address.Address{Space: base.Space, Offset: base.Offset - magnitude}, true
}

func sameSpace(left address.Address, right address.Address) bool {
	if left.Space == right.Space {
		return true
	}
	if left.Space == nil || right.Space == nil {
		return false
	}
	return left.Space.Index == right.Space.Index
}

func defaultConstSpace() *address.Space {
	return &address.Space{
		Name:      "const",
		Kind:      address.SpaceKindConstant,
		Index:     ^uint16(0),
		AddrSize:  8,
		WordSize:  1,
		BigEndian: false,
		Physical:  false,
	}
}

func defaultUniqueSpace(entrySpace *address.Space) *address.Space {
	addrSize := uint8(8)
	if entrySpace != nil && entrySpace.AddrSize != 0 {
		addrSize = entrySpace.AddrSize
	}
	return &address.Space{
		Name:      "unique",
		Kind:      address.SpaceKindUnique,
		Index:     ^uint16(0) - 1,
		AddrSize:  addrSize,
		WordSize:  1,
		BigEndian: false,
		Physical:  false,
	}
}

func resolveName(name string) string {
	if name == "" {
		return "bridge_func"
	}
	return name
}

func min(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

// recordsHaveBranchInd reports whether any collected instruction lowers to a
// CPUI_BRANCHIND raw op. It gates the whole live jump-table recovery driver:
// when false, Build takes the exact pre-3b path (no partial build, no heritage,
// no re-collection), guaranteeing a byte-identical no-op for every function
// without an indirect jump.
func recordsHaveBranchInd(records []instructionRecord) bool {
	for _, record := range records {
		for _, op := range record.translation.Ops {
			if op.OpCode == pcode.CPUI_BRANCHIND {
				return true
			}
		}
	}
	return false
}

// registerRecoveredTables binds each recovered jump table to the main
// Funcdata's BRANCHIND op (matched by instruction offset) and installs it. The
// recovery ran on a separate partial Funcdata, so the table currently points at
// the partial's op; SetIndirectOp relinks it to the live op, whose address is
// identical (same instruction). fd.FindJumpTable and fd.RecoverJumpTables both
// key off this live op afterward.
// C++ parity: Funcdata::recoverJumpTable's jt->setIndirectOp(op) relink
// (funcdata_block.cc:671) plus installJumpTable (jumpvec push_back).
func registerRecoveredTables(fd *pcode.Funcdata, recoveredTables map[uint64]*pcode.JumpTable) {
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() {
			continue
		}
		if op.Code() != pcode.CPUI_BRANCHIND {
			continue
		}
		if jt := recoveredTables[op.Addr().Offset]; jt != nil {
			jt.SetIndirectOp(op)
			fd.AddJumpTable(jt)
		}
	}
}

// hasHardTerminator reports whether translation contains an unconditional terminating op
// (RETURN, BRANCHIND, or BRANCH). CBRANCH is excluded because its fall-through edge
// continues to the next sequential instruction, which must still be collected.
// C++ ref: FlowInfo::hasTerminator / BasicBlock successor discovery in FlowInfo.cc.
func hasHardTerminator(translation sla.InstructionTranslation) bool {
	return !instructionFallsThrough(translation.Ops)
}

// instructionFallsThrough reports whether control can leave the instruction
// to the next one: a relative branch past its last op, or a last (kept) op
// that is not BRANCH/BRANCHIND/RETURN.
// C++ parity: FlowInfo::xrefControlFlow isfallthru.
func instructionFallsThrough(ops []pcode.RawOp) bool {
	bounds := splitInstruction(ops)
	n := bounds[len(bounds)-1][1]
	for i := 0; i < n; i++ {
		if t, ok := relativeTargetIndex(ops, i); ok && t == len(ops) {
			return true
		}
	}
	if n == 0 {
		return true
	}
	switch ops[n-1].OpCode {
	case pcode.CPUI_BRANCH, pcode.CPUI_BRANCHIND, pcode.CPUI_RETURN:
		return false
	}
	return true
}

// spaceHighest is the largest byte offset in the space.
// C++ parity: AddrSpace::getHighest.
func spaceHighest(spc *address.Space) uint64 {
	if spc.AddrSize == 0 || spc.AddrSize >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (8 * uint(spc.AddrSize))) - 1
}

// assignFlowTimes renumbers every raw op's SeqNum time with one counter in
// the order C++ generates p-code: FlowInfo::generateOps follows fall-through
// first, stacking branch targets (LIFO) and skipping instructions already
// seen, then decodes each recovered jump table's targets the same way.
// PcodeOpBank::create hands out times from that single counter, and later
// passes compare times across instructions (HighVariable::compareName,
// location order), so instruction-local indices would rank ops differently.
// C++ parity: FlowInfo::generateOps / fallthru / setFallthruBound /
// processInstruction / newAddress.
func assignFlowTimes(records []instructionRecord, entry address.Address, tables map[uint64]*pcode.JumpTable) {
	byAddr := make(map[address.Address]int, len(records))
	addrs := make([]address.Address, 0, len(records))
	for i, r := range records {
		byAddr[r.translation.Address] = i
		addrs = append(addrs, r.translation.Address)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	visited := make(map[address.Address]bool, len(records))
	var counter uint64
	var addrlist []address.Address
	var tablelist []uint64

	// nextVisited is the first visited instruction past addr (the fall-through
	// bound), or the zero Address when there is none.
	nextVisited := func(addr address.Address) (address.Address, bool) {
		k := sort.Search(len(addrs), func(i int) bool { return addr.Less(addrs[i]) })
		for ; k < len(addrs); k++ {
			if visited[addrs[k]] {
				return addrs[k], true
			}
		}
		return address.Address{}, false
	}
	newAddress := func(to address.Address) {
		if _, ok := byAddr[to]; !ok || visited[to] {
			return
		}
		addrlist = append(addrlist, to)
	}
	// processInstruction numbers the instruction's ops and reports fall-through.
	processInstruction := func(cur address.Address) bool {
		idx, ok := byAddr[cur]
		if !ok {
			return false
		}
		visited[cur] = true
		r := &records[idx]
		ops := r.translation.Ops
		for i := range ops {
			ops[i].SeqNum.Time = counter
			counter++
		}
		bounds := splitInstruction(ops)
		n := bounds[len(bounds)-1][1]
		for i := 0; i < n; i++ {
			switch ops[i].OpCode {
			case pcode.CPUI_BRANCH, pcode.CPUI_CBRANCH:
				if _, rel := relativeTargetIndex(ops, i); rel {
					continue
				}
				if in := ops[i].Inputs; len(in) > 0 && in[0].Space != nil {
					newAddress(in[0].Address())
				}
			case pcode.CPUI_BRANCHIND:
				if tables[cur.Offset] != nil {
					tablelist = append(tablelist, cur.Offset)
				}
			}
		}
		if !instructionFallsThrough(ops) || r.translation.Next.IsInvalid() {
			return false
		}
		addrlist = append(addrlist, r.translation.Next)
		return true
	}
	fallthru := func() {
		top := addrlist[len(addrlist)-1]
		if visited[top] {
			addrlist = addrlist[:len(addrlist)-1]
			return
		}
		bound, hasBound := nextVisited(top)
		for {
			cur := addrlist[len(addrlist)-1]
			addrlist = addrlist[:len(addrlist)-1]
			if !processInstruction(cur) || len(addrlist) == 0 {
				return
			}
			next := addrlist[len(addrlist)-1]
			if hasBound && !next.Less(bound) {
				if next == bound { // Hit the bound exactly
					addrlist = addrlist[:len(addrlist)-1]
					return
				}
				if visited[next] {
					addrlist = addrlist[:len(addrlist)-1]
					return
				}
				bound, hasBound = nextVisited(next)
			}
		}
	}
	addrlist = append(addrlist, entry)
	for len(addrlist) > 0 {
		fallthru()
	}
	for len(tablelist) > 0 {
		pending := tablelist
		tablelist = nil
		for _, off := range pending {
			jt := tables[off]
			for i := 0; i < jt.NumEntries(); i++ {
				newAddress(address.Address{Space: entry.Space, Offset: jt.AddressByIndex(i).Offset})
			}
			for len(addrlist) > 0 {
				fallthru()
			}
		}
	}
	// Anything flow never reached keeps program order after the rest.
	for _, a := range addrs {
		if !visited[a] {
			ops := records[byAddr[a]].translation.Ops
			for i := range ops {
				ops[i].SeqNum.Time = counter
				counter++
			}
		}
	}
}
