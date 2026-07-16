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

type varKey struct {
	space  *address.Space
	offset uint64
	size   uint32
}

type edgeKey struct {
	from *pcode.BlockBasic
	to   *pcode.BlockBasic
}

type spaceSummary struct {
	constSpace     *address.Space
	uniqueSpace    *address.Space
	uniqueBase     uint64
	heritageSpaces []*address.Space
}

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
	fd := pcode.NewFuncdata(resolveName(cfg.Name), cfg.Entry, summary.uniqueSpace, summary.uniqueBase, summary.constSpace)

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
	// instructionDefs is reset per instruction so that cross-instruction reads
	// always produce fresh free varnodes that Heritage can rename.
	// Within one instruction, writes are cached so later ops in the same
	// instruction can reference the written varnode (e.g. ZF = ECX_new == 0
	// after DEC ECX writes ECX_new).
	// C++ parity: Ghidra's SLEIGH builder creates fresh varnodes per read;
	// within-instruction writes are tracked but not propagated across instructions.
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
			return nil, fmt.Errorf("build bridge: missing basic block for instruction %v", addr)
		}
		instToBlock[addr] = current
		lastInBlock[current] = record

		// Fresh defs map per instruction: reads in one instruction must not
		// resolve to writes from a different instruction.
		instructionDefs = make(map[varKey]*pcode.Varnode)
		if err := addInstructionOps(fd, current, record.translation, instructionDefs); err != nil {
			return nil, err
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

	addCFGEdges(graph, blockByAddr, instToBlock, lastInBlock, recoveredTables)
	graph.FindSpanningTree()
	assignUnreachableIndices(graph)
	graph.CalcForwardDominator()
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

	// Parse cspec if provided. Store in result but do not apply -- callers
	// may apply after Heritage via pcode.ApplyCallingConvention.
	if cfg.CspecPath != "" {
		cs, csErr := pcode.ParseCspec(cfg.CspecPath)
		if csErr != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("cspec parse %q: %v", cfg.CspecPath, csErr))
		} else {
			result.CspecData = cs
		}
	}

	// Attach the default evaluation prototype model (Architecture::defaultfp
	// equivalent) so the universal-action tree's ActionPrototypeTypes can create
	// a FuncProto + ScopeLocal. Since H8-debt-2 the tree is the production decompile
	// path (bridge.Decompile), so this default model IS the model production runs
	// with: its faithful stack spacebase space (set below when a cspec is supplied)
	// is consumed by ActionSpacebase + RuleLoadVarnode/RuleStoreVarnode during the
	// run. Callers must supply a cspec for stack-frame recovery (see Decompile).
	fd.SetDefaultModel(buildDefaultModel(engine, result.CspecData, fd, cfg.EntryPoint))

	// Attach an opt-in locked prototype supplied by the analysis environment.
	// Must run after SetDefaultModel so the locked FuncProto reuses the cspec
	// evaluation model. No-op when cfg.InjectedPrototype is nil (default path).
	if cfg.InjectedPrototype != nil {
		applyInjectedPrototype(engine, fd, cfg.InjectedPrototype)
	}

	return result, nil
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
				fp.SetLockedParamName(addr.Offset, p.Name, p.NameLock)
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
		if ss := buildFaithfulStackSpace(xr, cspec, fd); ss != nil {
			model.StackSpace = ss
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
	stackSpace := &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		Index:    maxIdx + 1,
		AddrSize: uint8(sz),
		WordSize: 1,
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
			if len(translation.Ops) == 0 {
				return nil, nil, fmt.Errorf("build bridge: instruction %v has no raw ops", cur)
			}
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
			// Constant-space operand: interpret as relative offset from Next.
			if target, ok := addSignedOffset(translation.Next, int64(int8(input.Offset))); ok {
				return target, true
			}
			if entrySpace != nil {
				return address.Address{Space: entrySpace, Offset: input.Offset}, true
			}
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
		end := vn.Offset + uint64(vn.Size)
		if end > s.uniqueBase {
			s.uniqueBase = end
		}
	}
}

func (s *spaceSummary) collectHeritageSpace(space *address.Space, entrySpace *address.Space, seen map[*address.Space]struct{}) {
	if space == nil || space == entrySpace {
		return
	}
	switch space.Kind {
	case address.SpaceKindConstant, address.SpaceKindUnique:
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
	starts[records[0].translation.Address] = true

	known := make(map[address.Address]struct{}, len(records))
	for _, record := range records {
		known[record.translation.Address] = struct{}{}
	}

	for _, record := range records {
		if record.flow.hasDirect {
			if _, exists := known[record.flow.directTarget]; exists {
				starts[record.flow.directTarget] = true
			}
		}
		if record.flow.terminates {
			if _, exists := known[record.translation.Next]; exists {
				starts[record.translation.Next] = true
			}
		}
	}

	return starts
}

func addInstructionOps(fd *pcode.Funcdata, block *pcode.BlockBasic, translation sla.InstructionTranslation, defs map[varKey]*pcode.Varnode) error {
	if fd == nil || block == nil {
		return fmt.Errorf("build bridge: funcdata or block is nil")
	}
	for _, raw := range translation.Ops {
		op := fd.GetPcodeOpBank().CreateWithSeq(len(raw.Inputs), raw.SeqNum)
		fd.OpSetOpcode(op, raw.OpCode)
		appendAliveOp(fd, block, op)

		for slot, input := range raw.Inputs {
			vn := resolveInput(fd, input, defs)
			if shouldMaterializeConstant(raw.OpCode, slot, vn) {
				vn = materializeConstantInput(fd, block, raw.SeqNum.Address, vn)
			}
			fd.OpSetInput(op, vn, slot)
		}
		if raw.Output != nil {
			out := fd.NewVarnodeOut(int32(raw.Output.Size), raw.Output.Address(), op)
			defs[makeVarKey(*raw.Output)] = out
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

func resolveInput(fd *pcode.Funcdata, input pcode.VarnodeData, defs map[varKey]*pcode.Varnode) *pcode.Varnode {
	if input.Space != nil && input.Space.IsConstant() {
		return fd.NewConstant(int32(input.Size), input.Offset)
	}

	key := makeVarKey(input)
	if vn, exists := defs[key]; exists {
		return vn
	}

	vn := fd.NewVarnode(int32(input.Size), input.Address())
	// Do NOT store read varnodes in defs. If this location has not been written
	// yet (no output defined it), it is a function live-in that Heritage will
	// rename to an SSA input varnode. Storing the read would cause subsequent
	// reads of the same register to reuse the same varnode object, which breaks
	// Heritage's per-use renaming: Heritage marks the varnode active, renames
	// the first user, then clears active -- leaving other users with the old
	// pre-Heritage raw varnode.
	// C++ parity: Ghidra's SLEIGH builder creates a fresh varnode per read.
	return vn
}

func shouldMaterializeConstant(opcode pcode.OpCode, slot int, vn *pcode.Varnode) bool {
	if vn == nil || !vn.IsConstant() {
		return false
	}
	value := truncateConstantForSize(vn.Offset(), vn.Size())
	switch opcode {
	case pcode.CPUI_INT_SUB:
		return slot == 1 && value != 0 && value != 1
	case pcode.CPUI_INT_ADD:
		return value != allOnesForSize(vn.Size()) && value&signBitForSize(vn.Size()) != 0
	default:
		return false
	}
}

func materializeConstantInput(fd *pcode.Funcdata, block *pcode.BlockBasic, addr address.Address, constant *pcode.Varnode) *pcode.Varnode {
	copyOp := fd.NewOp(1, addr)
	fd.OpSetOpcode(copyOp, pcode.CPUI_COPY)
	appendAliveOp(fd, block, copyOp)
	fd.OpSetInput(copyOp, constant, 0)
	return fd.NewUniqueOut(constant.Size(), copyOp)
}

func addCFGEdges(graph *pcode.BlockGraph, blockByAddr map[address.Address]*pcode.BlockBasic, instToBlock map[address.Address]*pcode.BlockBasic, lastInBlock map[*pcode.BlockBasic]instructionRecord, recoveredTables map[uint64]*pcode.JumpTable) {
	seen := make(map[edgeKey]struct{})
	// Visit blocks in ascending source-op-address order. Ghidra builds CFG edges
	// by walking the dead op list in ascending address order (FlowInfo::collectEdges,
	// flow.cc:906) and calling bblocks.addEdge in that order (connectBasic,
	// flow.cc:1021); FlowBlock::addInEdge appends without sorting (block.cc:73). So a
	// merge block's in-edges land ordered by predecessor source-op address. Iterating
	// a Go map here instead would randomize predecessor order and permute phi input
	// slots run-to-run; sorting the keys ascending reproduces Ghidra's order exactly.
	addrs := make([]address.Address, 0, len(blockByAddr))
	for addr := range blockByAddr {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	for _, addr := range addrs {
		block := blockByAddr[addr]
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
		if record.flow.conditional {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
			addEdge(graph, seen, block, blockByAddr[record.flow.directTarget])
			continue
		}
		if record.flow.hasDirect {
			addEdge(graph, seen, block, blockByAddr[record.flow.directTarget])
			continue
		}
		if record.flow.hasFallthrough {
			addEdge(graph, seen, block, instToBlock[record.flow.fallthroughAddr])
		}
	}
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

func assignUnreachableIndices(graph *pcode.BlockGraph) {
	if graph == nil {
		return
	}
	maxIndex := int32(-1)
	for idx := 0; idx < graph.GetSize(); idx++ {
		block := graph.GetBlock(idx)
		if block.Index() > maxIndex {
			maxIndex = block.Index()
		}
	}
	for idx := 0; idx < graph.GetSize(); idx++ {
		block := graph.GetBlock(idx)
		if block.Index() >= 0 {
			continue
		}
		maxIndex++
		block.SetIndex(maxIndex)
	}
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

	candidates := make([]address.Address, 0, 5)
	if entrySpace != nil {
		candidates = append(candidates, address.Address{Space: entrySpace, Offset: input.Offset})
	}
	if translation.Address.Space != nil {
		candidates = append(candidates, address.Address{Space: translation.Address.Space, Offset: input.Offset})
	}
	if translation.Next.Space != nil {
		candidates = append(candidates, address.Address{Space: translation.Next.Space, Offset: input.Offset})
	}
	if target, ok := addSignedOffset(translation.Next, int64(int8(input.Offset))); ok {
		candidates = append(candidates, target)
	}
	if target, ok := addSignedOffset(translation.Address, int64(int8(input.Offset))); ok {
		candidates = append(candidates, target)
	}

	for _, candidate := range candidates {
		if _, exists := known[candidate]; exists {
			return candidate, true
		}
	}
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

func makeVarKey(vn pcode.VarnodeData) varKey {
	return varKey{space: vn.Space, offset: vn.Offset, size: vn.Size}
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
	for _, op := range translation.Ops {
		switch op.OpCode {
		case pcode.CPUI_RETURN, pcode.CPUI_BRANCHIND:
			return true
		case pcode.CPUI_BRANCH:
			// Unconditional branch: no fall-through.
			return true
		}
	}
	return false
}
