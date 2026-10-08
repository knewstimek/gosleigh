package pcode

import (
	"fmt"
	"hash/fnv"
	"sort"

	"gosleigh/pkg/address"
)

// Funcdata flags -- processing state bitmask.
// C++ parity: funcdata.hh Funcdata::Flags
const (
	FuncHighLevelOn        uint32 = 0x0001
	FuncBlocksGenerated    uint32 = 0x0002
	FuncBlocksUnreachable  uint32 = 0x0004
	FuncProcessingStarted  uint32 = 0x0008
	FuncProcessingComplete uint32 = 0x0010
	FuncTypeRecoveryOn     uint32 = 0x0020
	FuncTypeRecoveryStart  uint32 = 0x0040
	FuncNoCode             uint32 = 0x0080
	FuncUnimplPresent      uint32 = 0x0800
	FuncBadDataPresent     uint32 = 0x1000
	// FuncDoublePrecisOn enables the ActionParamDouble join path.
	// C++ parity: funcdata.hh Funcdata::double_precis_on (0x2000)
	FuncDoublePrecisOn uint32 = 0x2000
	// FuncTypeRecoveryExceeded is set once type propagation stops settling.
	// C++ parity: funcdata.hh Funcdata::typerecovery_exceeded (0x4000)
	FuncTypeRecoveryExceeded uint32 = 0x4000
)

// Funcdata is the central container for all data structures associated
// with decompiling a single function.
// C++ parity: funcdata.hh Funcdata
type Funcdata struct {
	// protoPartial lists the CONCAT roots RulePieceStructure registered for
	// Merge::groupPartials. C++ parity: Merge::protoPartial.
	protoPartial []*PcodeOp

	flags       uint32
	name        string
	displayName string
	baseAddr    address.Address
	size        int32

	// Core data stores
	vbank VarnodeBank
	obank PcodeOpBank

	// Constant space for NewConstant
	constSpace *address.Space

	// TypeOp registry (one per opcode, shared)
	typeOps []TypeOp

	// Phase watermarks (Varnode creation indices)
	cleanUpIndex   uint32
	highLevelIndex uint32
	castPhaseIndex uint32

	// Minimum laned size
	minLanedSize uint32

	// Calling convention and local variable scope (set by ApplyCallingConvention).
	// Both are nil until a cspec is attached.
	// C++ parity: Funcdata::proto, Funcdata::localmap
	funcProto  *FuncProto
	scopeLocal *ScopeLocal
	callSpecs  []*FuncCallSpecs

	// globalScope is the parent (global) symbol scope ScopeLocal defers to. It is
	// nil unless the loader/bridge injects environment-supplied global symbols
	// (e.g. __ImageBase); ActionConstantPtr queries it to promote a constant to a
	// global symbol pointer. C++ parity: Funcdata::localmap->getParent() (global).
	globalScope *GlobalScope
	// sizeLockTypes are the size-locked global Symbol types ActionNameVars
	// overrode (Scope::overrideSizeLockType), kept across a restart.
	sizeLockTypes map[address.Address]Datatype

	// defaultModel is the architecture evaluation prototype model (the C++
	// Architecture::defaultfp equivalent). The universal-action tree reads it in
	// ActionPrototypeTypes to attach a FuncProto + ScopeLocal when none is set,
	// mirroring how the C++ Funcdata is constructed with a prototype and
	// ActionPrototypeTypes::apply sets the model. The hand-ordered decompile
	// driver instead builds the model itself via ApplyCallingConvention.
	// C++ parity: Architecture::defaultfp / evalfp_current.
	defaultModel *ProtoModel

	// hostScope is the analysis environment's symbol database (nil when the
	// function is decompiled standalone). C++ parity: Architecture::symboltab
	// global scope (ScopeGhidra).
	hostScope HostScope

	// hostComments wait until the comments are first read.
	// C++ parity: CommentDatabaseGhidra cache.
	hostComments       []pendingComment
	commentCacheFilled bool

	// globalRanges is the global scope's storage (cspec <global>).
	globalRanges []GlobalRange
	// joinSpace holds storage split across pieces (EDX:EAX returns).
	// C++ parity: AddrSpaceManager::getJoinSpace.
	joinSpace *address.Space
	// codeSpace is the default code space. C++ parity: getDefaultCodeSpace.
	codeSpace *address.Space

	// evalCurrent is the model used to evaluate this function's own prototype
	// when it differs from the default (possibly a merged model).
	// C++ parity: Architecture::evalfp_current.
	evalCurrent *ProtoModel
	// models are the architecture's named prototype models.
	models map[string]*ProtoModel
	// hostLocals are the host's name-locked stack symbol names by offset.
	hostLocals map[uint64]string
	// hostIsolated are the stack offsets of locked parameters the host
	// serializes with merge="false".
	hostIsolated map[uint64]bool
	// symbolsLinked is set once ActionNameVars links every variable to a
	// Symbol. C++ parity: Funcdata::linkSymbol in ActionNameVars.
	symbolsLinked bool
	// unionMap holds the resolution of each edge reading or writing a
	// data-type that needs resolution. C++ parity: Funcdata::unionMap.
	unionMap map[resolveEdge]*ResolvedUnion
	// hostLocalTypes are the host's type-locked stack symbol types by offset.
	hostLocalTypes map[uint64]Datatype
	// registerNames maps "spaceIdx:offset:size" to a register name.
	// C++ parity: Translate::getRegisterName (used by buildVariableName).
	registerNames map[string]string
	// indirectOverrides are CALLIND sites (instruction offset) resolved to a
	// target during this run; rebuildRequested asks the driver to restart.
	// C++ parity: Override indirect overrides + Funcdata restartPending.
	indirectOverrides map[uint64]address.Address
	// deadcodeDelays are dead-code delay overrides by space name, installed
	// by Heritage::bumpDeadcodeDelay and kept across a restart.
	// C++ parity: Override::deadcodedelay.
	deadcodeDelays map[string]int32
	// protoOverrides are the prototypes forced onto call sites (instruction
	// offset). C++ parity: Override::protoover.
	protoOverrides   map[uint64]*HostFunction
	rebuildRequested bool
	multistageJumps  map[uint64]bool
	// trackedSet are the register values known at entry (ActionConstbase).
	trackedSet []constbaseTrackedContext

	// jumpTables tracks all recovered JumpTable objects for this function.
	// C++ parity: funcdata.hh Funcdata::jumpvec
	jumpTables []*JumpTable

	// actionState/blockState: driver flags and the basic/structured graphs.
	actionState funcdataActionState
	blockState  funcdataBlockState
	// laneAccess: laned register records (Funcdata::lanedMap).
	laneAccess *laneAccessData
	// merge: Funcdata::covermerge.
	merge *Merge

	// commentDB accumulates auto-generated warning comments (e.g. jump-table
	// recovery failures) so PrintC can render them as inline block comments. In
	// Ghidra the store is the global Architecture::commentdb keyed by function
	// address; Gosleigh decompiles one function at a time, so it lives here.
	// nil until the first warning is recorded, keeping output byte-identical for
	// functions with no warnings. C++ parity: Architecture::commentdb + funcdata.cc
	// Funcdata::warning.
	commentDB *CommentDatabase

	// graph and heritageSpaces let the universal-action tree run analysis actions
	// (ActionHeritage etc.) without external context. The hand-ordered decompile
	// driver passes these explicitly; the action-tree path reads them from here.
	// C++ parity: Funcdata owns bblocks and the heritage's address-space set.
	graph          *BlockGraph
	heritageSpaces []*address.Space
	// archSpaces are all of the architecture's address spaces.
	archSpaces []*address.Space
	// incidentalCopy holds the pspec <incidentalcopy> storage ranges.
	incidentalCopy []GlobalRange
	// heritage is the persistent SSA engine the universal-action tree reuses across
	// mainloop iterations so heritage is incremental (pass/globalDisjoint state is
	// retained). The hand-ordered decompile driver builds its own Heritage and does
	// not use this field. C++ parity: Funcdata::heritage member.
	heritage *Heritage

	// Architecture-adjacent services used by the op factories.
	// C++ parity: these live on Architecture (glb) in the C++ code; the Go
	// port attaches them to Funcdata so helpers like GetInternalString can
	// allocate typed user-ops without a full glb.
	typeFactory *TypeFactory
	userOps     *UserOpManage

	// internalStrings is the side-table Ghidra models via
	// stringManager->registerInternalStringData. Keys are the 64-bit hashes
	// passed through the BUILTIN_STRINGDATA CALLOTHER; values are the raw
	// payload plus the element data-type.
	internalStrings map[uint64]internalStringEntry

	// imageReader is the load-image read hook used by EmulateFunction during
	// jump-table address emulation (getLoadImageValue). It returns the raw
	// little-endian value of sz bytes at addr. In Ghidra this is
	// glb->loader->loadFill (emulateutil.cc:36); Gosleigh has no Architecture
	// glb, so bridge.Build installs a closure over the section-mapped backend.
	// A nil hook means image reads are unsupported and LOAD emulation fails,
	// preserving the pre-B2 behavior for callers (e.g. production) that never
	// set it. C++ parity: LoadImage::loadFill boundary.
	imageReader func(addr address.Address, sz int) (uint64, error)
}

// internalStringEntry mirrors the per-address registry entry the C++
// StringManager hands out when a constseq transform synthesizes a literal.
type internalStringEntry struct {
	addr     address.Address
	data     []byte
	charType Datatype
}

// NewFuncdata creates a Funcdata container for the named function.
// uniqSpace and uniqBase configure the unique/temp varnode allocator.
// constSpace is used for constant varnode creation.
// C++ parity: funcdata.cc Funcdata::Funcdata
func NewFuncdata(name string, addr address.Address, uniqSpace *address.Space, uniqBase uint64, constSpace *address.Space) *Funcdata {
	fd := &Funcdata{
		name:       name,
		baseAddr:   addr,
		constSpace: constSpace,
		typeOps:    RegisterTypeOps(),
	}
	// Initialize banks inline (avoid extra pointer indirection).
	// VarnodeBank needs the unique space for temp allocation.
	vb := NewVarnodeBank(uniqSpace, uniqBase)
	fd.vbank = *vb
	ob := NewPcodeOpBank()
	fd.obank = *ob
	return fd
}

// ---------------------------------------------------------------------------
// Getters
// ---------------------------------------------------------------------------

func (fd *Funcdata) Name() string                 { return fd.name }
func (fd *Funcdata) DisplayName() string          { return fd.displayName }
func (fd *Funcdata) SetDisplayName(n string)      { fd.displayName = n }
func (fd *Funcdata) BaseAddr() address.Address    { return fd.baseAddr }
func (fd *Funcdata) Size() int32                  { return fd.size }
func (fd *Funcdata) Flags() uint32                { return fd.flags }
func (fd *Funcdata) HasFlag(f uint32) bool        { return fd.flags&f != 0 }
func (fd *Funcdata) SetFlag(f uint32)             { fd.flags |= f }
func (fd *Funcdata) ClearFlag(f uint32)           { fd.flags &^= f }
func (fd *Funcdata) GetVarnodeBank() *VarnodeBank { return &fd.vbank }
func (fd *Funcdata) GetPcodeOpBank() *PcodeOpBank { return &fd.obank }

// SetImageReader installs the load-image read hook used by jump-table address
// emulation. See the imageReader field comment for parity notes.
func (fd *Funcdata) SetImageReader(r func(addr address.Address, sz int) (uint64, error)) {
	fd.imageReader = r
}

// ImageReader returns the installed load-image read hook, or nil.
func (fd *Funcdata) ImageReader() func(addr address.Address, sz int) (uint64, error) {
	return fd.imageReader
}

// GetFuncProto returns the calling convention prototype, or nil if not set.
// C++ parity: Funcdata::getFuncProto
func (fd *Funcdata) GetFuncProto() *FuncProto { return fd.funcProto }

// SetFuncProto attaches a calling convention prototype.
// C++ parity: Funcdata::getFuncProto (setter path)
func (fd *Funcdata) SetFuncProto(fp *FuncProto) { fd.funcProto = fp }

// GetScopeLocal returns the local variable scope, or nil if not set.
// C++ parity: Funcdata::getScopeLocal
func (fd *Funcdata) GetScopeLocal() *ScopeLocal { return fd.scopeLocal }

// SetModels installs the architecture's named prototype models.
// C++ parity: Architecture::protoModels.
func (fd *Funcdata) SetModels(m map[string]*ProtoModel) { fd.models = m }

// ModelByName returns a named prototype model, or nil (including for
// "unknown" and "").
// C++ parity: Architecture::getModel.
func (fd *Funcdata) ModelByName(name string) *ProtoModel {
	if name == "" || name == "unknown" {
		return nil
	}
	if m := fd.models[name]; m != nil {
		return m
	}
	// An unrecognized name gets a clone of the default model, printed under
	// that name. C++ parity: Architecture::createUnknownModel.
	if fd.defaultModel == nil || fd.models == nil {
		return nil
	}
	m := fd.defaultModel.Alias(name)
	fd.models[name] = m
	return m
}

// SetEvalCurrentModel sets the model that evaluates this function's own
// prototype. C++ parity: Architecture::evalfp_current.
func (fd *Funcdata) SetEvalCurrentModel(m *ProtoModel) { fd.evalCurrent = m }

// EvalCurrentModel returns evalfp_current, falling back to the default model.
func (fd *Funcdata) EvalCurrentModel() *ProtoModel {
	if fd.evalCurrent != nil {
		return fd.evalCurrent
	}
	return fd.defaultModel
}

// SetHostScope attaches the environment's symbol database. Call sites built
// afterwards resolve their callee names through it.
func (fd *Funcdata) SetHostScope(h HostScope) { fd.hostScope = h }

// HostScope returns the attached environment symbol database, or nil.
func (fd *Funcdata) HostScope() HostScope { return fd.hostScope }

// DefaultModel returns the architecture evaluation prototype model, or nil.
// C++ parity: Architecture::defaultfp (read via data.getArch()->defaultfp).
func (fd *Funcdata) DefaultModel() *ProtoModel { return fd.defaultModel }

// SetDefaultModel records the architecture evaluation prototype model so the
// universal-action tree (ActionPrototypeTypes) can attach a FuncProto when the
// function has no locked prototype.
func (fd *Funcdata) SetDefaultModel(m *ProtoModel) { fd.defaultModel = m }

// SetScopeLocal attaches a local variable scope.
func (fd *Funcdata) SetScopeLocal(sl *ScopeLocal) {
	fd.scopeLocal = sl
	if sl != nil && fd.hostLocals != nil {
		sl.ext().hostLocals = fd.hostLocals
	}
	if sl != nil && fd.hostLocalTypes != nil {
		sl.ext().hostLocalTypes = fd.hostLocalTypes
	}
	if sl != nil && fd.hostIsolated != nil {
		sl.ext().hostIsolated = fd.hostIsolated
	}
}

// SetHostLocals installs the host's name-locked stack symbols for this
// function, keyed by stack offset (wrapped to the stack space).
// C++ parity: the localdb symbols DecompileCallback sends with the function
// (namelock=true), which ScopeLocal::restructure keeps by name.
func (fd *Funcdata) SetHostLocals(m map[uint64]string) {
	fd.hostLocals = m
	if fd.scopeLocal != nil {
		fd.scopeLocal.ext().hostLocals = m
		fd.scopeLocal.ext().hostLocalTypes = fd.hostLocalTypes
		fd.scopeLocal.ext().hostIsolated = fd.hostIsolated
	}
}

// warning records an auto-generated warning comment in the comment database,
// indexed by its placement address (the emitter attempts to place it before the
// source expression mapping most closely to that address). The "WARNING: "
// prefix (or "WARNING (jumptable): " during jump-table recovery) matches Ghidra
// exactly, and PrintC wraps the body in "/* ... */".
// C++ parity: funcdata.cc Funcdata::warning (funcdata.cc:119).
func (fd *Funcdata) warning(txt string, ad address.Address) {
	if fd.commentDB == nil {
		fd.commentDB = &CommentDatabase{}
	}
	msg := "WARNING: "
	if fd.IsJumptableRecoveryOn() {
		msg = "WARNING (jumptable): "
	}
	msg += txt
	fd.commentDB.addCommentNoDuplicate(CommentWarning, fd.baseAddr, ad, msg)
}

// Warning is the exported entry the bridge staging driver uses to attach the
// "Could not emulate address calculation" comment -- produced during jump-table
// recovery on the throwaway partial clone -- onto the main Funcdata at the
// BRANCHIND address. The main Funcdata is not in jump-table recovery mode, so the
// "WARNING: " prefix matches the golden (not "WARNING (jumptable): ").
// C++ parity: Funcdata::stageJumpTable calls warning(err.explain, op->getAddr())
// on the original data (funcdata_block.cc:516,543).
func (fd *Funcdata) Warning(txt string, ad address.Address) { fd.warning(txt, ad) }

// WarningJumptable attaches a warning that jump-table recovery issued on its
// partial Funcdata, keeping the "WARNING (jumptable): " prefix that
// Funcdata::warning gives while isJumptableRecoveryOn.
// C++ parity: funcdata.cc Funcdata::warning (jumptable branch).
func (fd *Funcdata) WarningJumptable(txt string, ad address.Address) {
	if fd.commentDB == nil {
		fd.commentDB = &CommentDatabase{}
	}
	fd.commentDB.addCommentNoDuplicate(CommentWarning, fd.baseAddr, ad, "WARNING (jumptable): "+txt)
}

// GetGlobalScope returns the parent (global) symbol scope, or nil if none was
// injected. C++ parity: Funcdata::getScopeLocal()->getParent().
func (fd *Funcdata) GetGlobalScope() *GlobalScope { return fd.globalScope }

// SetGlobalScope attaches the parent (global) symbol scope.
func (fd *Funcdata) SetGlobalScope(g *GlobalScope) { fd.globalScope = g }

// NumCalls returns the number of CALL/CALLIND ops currently tracked.
// C++ parity: Funcdata::numCalls
func (fd *Funcdata) NumCalls() int {
	if fd == nil {
		return 0
	}
	fd.ensureCallSpecs()
	return len(fd.callSpecs)
}

// GetCallSpecs returns the i-th call-spec wrapper.
// C++ parity: Funcdata::getCallSpecs
func (fd *Funcdata) GetCallSpecs(i int) *FuncCallSpecs {
	if fd == nil {
		return nil
	}
	fd.ensureCallSpecs()
	if i < 0 || i >= len(fd.callSpecs) {
		return nil
	}
	return fd.callSpecs[i]
}

// callSpecsForOp returns the FuncCallSpecs bound to the given CALL/CALLIND op,
// or nil if none is tracked. C++ parity: Funcdata::getCallSpecs(PcodeOp*).
func (fd *Funcdata) callSpecsForOp(op *PcodeOp) *FuncCallSpecs {
	if fd == nil || op == nil {
		return nil
	}
	fd.ensureCallSpecs()
	for _, fc := range fd.callSpecs {
		if fc != nil && fc.op == op {
			return fc
		}
	}
	return nil
}

func (fd *Funcdata) ensureCallSpecs() {
	if fd == nil || fd.callSpecs != nil {
		return
	}
	for _, op := range fd.obank.AllOps() {
		if op == nil {
			continue
		}
		switch op.Code() {
		case CPUI_CALL, CPUI_CALLIND:
			fd.callSpecs = append(fd.callSpecs, newFuncCallSpecs(fd, op))
		}
	}
	// Calls go in dominance order so that earlier calls get evaluated first;
	// the order affects parameter analysis.
	// C++ parity: Funcdata::sortCallSpecs (compareCallspecs).
	sort.SliceStable(fd.callSpecs, func(i, j int) bool {
		a, b := fd.callSpecs[i].op, fd.callSpecs[j].op
		if pa, pb := a.Parent(), b.Parent(); pa != nil && pb != nil && pa.Index() != pb.Index() {
			return pa.Index() < pb.Index()
		}
		// The C++ SeqNum order is the op's position in its block; a Go
		// Seq().Order can lag behind ops inserted later.
		return opBlockUIndex(a) < opBlockUIndex(b)
	})
}

// rebuildCallSpecs drops the cached call-spec list and rebuilds it from the
// current op bank. Needed after a raw-flow mutation that adds a CALL/CALLIND op
// (e.g. TruncateIndirectJump demoting a BRANCHIND) so the newly created call
// site is tracked. Ghidra builds each FuncCallSpecs eagerly at the mutation
// site (FlowInfo::setupCallindSpecs pushes onto qlst); Gosleigh's list is lazy,
// so this forces a fresh scan.
func (fd *Funcdata) rebuildCallSpecs() {
	if fd == nil {
		return
	}
	fd.callSpecs = nil
	fd.ensureCallSpecs()
}

// StartProcessing marks the function as entering the main analysis phase.
// C++ parity: funcdata.hh Funcdata::startProcessing
func (fd *Funcdata) StartProcessing() {
	fd.SetFlag(FuncProcessingStarted)
	fd.ClearFlag(FuncProcessingComplete)
}

// StopProcessing marks the function as leaving analysis.
// C++ parity: funcdata.hh Funcdata::stopProcessing
func (fd *Funcdata) StopProcessing() {
	if !fd.IsJumptableRecoveryOn() {
		fd.issueDatatypeWarnings()
	}
	fd.SetFlag(FuncProcessingComplete)
}

// StartCleanUp marks the start of the clean-up phase.
// C++ parity: funcdata.hh Funcdata::startCleanUp
func (fd *Funcdata) StartCleanUp() {
	fd.SetFlag(FuncProcessingComplete)
}

// StartTypeRecovery enables type recovery if it is not already active.
// C++ parity: funcdata.hh Funcdata::startTypeRecovery
func (fd *Funcdata) StartTypeRecovery() bool {
	if !fd.HasFlag(FuncTypeRecoveryOn) {
		return false // Type recovery is not on
	}
	if fd.HasFlag(FuncTypeRecoveryStart) {
		return false // Already started
	}
	fd.SetFlag(FuncTypeRecoveryStart)
	return true
}

// SetTypeRecovery toggles the type recovery flag.
// C++ parity: funcdata.hh Funcdata::setTypeRecovery
func (fd *Funcdata) SetTypeRecovery(on bool) {
	if on {
		fd.SetFlag(FuncTypeRecoveryOn)
		return
	}
	fd.ClearFlag(FuncTypeRecoveryOn)
}

// SetAnalysisContext records the block graph and heritage spaces so the
// universal-action tree can run self-contained (bridge.Build calls this).
func (fd *Funcdata) SetAnalysisContext(graph *BlockGraph, heritageSpaces []*address.Space) {
	fd.graph = graph
	fd.heritageSpaces = heritageSpaces
}

// Graph returns the block graph attached by SetAnalysisContext (may be nil).
func (fd *Funcdata) Graph() *BlockGraph { return fd.graph }

// HeritageSpaces returns the heritage space set attached by SetAnalysisContext.
func (fd *Funcdata) HeritageSpaces() []*address.Space { return fd.heritageSpaces }

// OpHeritage performs SSA heritage construction over the register/default spaces
// using the attached analysis context. This is the action-tree entry point
// (ActionHeritage); the hand-ordered decompile driver instead calls NewHeritage
// directly with an explicit graph. The ProtoModel (when a FuncProto is attached)
// enables call-site INDIRECT guards; nil is leaf-safe.
//
// Stack slots are heritaged by the same Heritage() pass as everything else: the
// stack (spacebase) space is registered as a heritage space here, so its ranges go
// through the whole task pipeline -- refinement and guard normalization included.
// C++ parity: funcdata.hh Funcdata::opHeritage -> Heritage::heritage.
func (fd *Funcdata) OpHeritage() {
	if fd.graph == nil || len(fd.heritageSpaces) == 0 {
		return
	}
	var model *ProtoModel
	if fd.funcProto != nil {
		model = fd.funcProto.Model()
	}
	fd.registerStackHeritageSpace()
	// Reuse a persistent Heritage engine so the pass counter and globalDisjoint
	// cover survive across mainloop iterations -- this makes heritage incremental
	// (only newly freed varnodes are reprocessed) instead of re-placing every phi
	// on each pass, which previously forced a heritage-once guard and prevented the
	// tree from picking up later stack-slot SSA. C++ parity: Funcdata::opHeritage
	// drives the single persistent Heritage::heritage.
	if model == nil {
		model = fd.DefaultModel() // funcProto is attached later in the pipeline
	}
	if fd.heritage == nil {
		fd.heritage = NewHeritage(fd, fd.heritageSpaces).WithProtoModel(model)
	} else if fd.heritage.proto == nil {
		fd.heritage.proto = model
	}
	// Incremental heritage over every registered space (registers, defaults and the
	// stack): pass and globalDisjoint persist, so already-resolved varnodes are
	// skipped and only new free reads are placed. The stack is recovered faithfully
	// as a spacebase fixture -- ActionSpacebase (Funcdata.Spacebase) marks the
	// stack-pointer varnodes each mainloop pass and RuleLoadVarnode/RuleStoreVarnode
	// convert the accesses, so new stack slots keep showing up here pass after pass.
	fd.heritage.Heritage(fd.graph)
	fd.resolveStackSpace(model)
}

// registerStackHeritageSpace adds the stack (spacebase) space to the heritage
// space set. The bridge builds that set from the spaces raw p-code varnodes name,
// and stack varnodes only appear later in the mainloop (RuleLoadVarnode /
// RuleStoreVarnode), so the stack would otherwise never be heritaged at all.
// Ghidra has no such gap: Heritage::buildInfoList (heritage.cc:2650-2658) walks
// every space the AddrSpaceManager holds, and the stack spacebase space is one of
// them from load time. Runs before the Heritage engine is constructed, because
// NewHeritage snapshots the space list.
func (fd *Funcdata) registerStackHeritageSpace() {
	sp := fd.stackSpace()
	if sp == nil {
		return
	}
	for _, existing := range fd.heritageSpaces {
		if existing == sp {
			return
		}
	}
	fd.heritageSpaces = append(fd.heritageSpaces, sp)
}

// stackSpace returns the stack (spacebase) space this function was configured
// with, preferring the attached prototype's model over the architecture default.
func (fd *Funcdata) stackSpace() *address.Space {
	if fd.funcProto != nil {
		if m := fd.funcProto.Model(); m != nil && m.StackSpace != nil {
			return m.StackSpace
		}
	}
	if fd.defaultModel != nil {
		return fd.defaultModel.StackSpace
	}
	return nil
}

// resolveStackSpace records the resolved stack space on the proto model so
// ScopeLocal restructure can classify stack parameters and locals. It is a
// fallback for builds that never set model.StackSpace up front (bridge.go sets it
// from the cspec); stack SSA itself is done by Heritage() now that the stack space
// is a registered heritage space, exactly as in C++ where Heritage::buildInfoList
// covers every space including the spacebase.
func (fd *Funcdata) resolveStackSpace(model *ProtoModel) {
	if model == nil || model.StackSpace != nil {
		return
	}
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		sp := vn.Space()
		if sp.Kind == address.SpaceKindStack || sp.Name == "stack" {
			model.StackSpace = sp
			return
		}
	}
}

// CalcNZMask computes non-zero masks for all varnodes.
// C++ parity: funcdata.hh Funcdata::calcNZMask
func (fd *Funcdata) CalcNZMask() {
	type opNode struct {
		op   *PcodeOp
		slot int
	}
	alive := func() []*PcodeOp {
		out := make([]*PcodeOp, 0)
		for _, op := range fd.obank.AllOps() {
			if op != nil && !op.IsDead() {
				out = append(out, op)
			}
		}
		return out
	}()

	// Phase 1: DFS post-order. Compute each output's local nzmask from its inputs,
	// seeding leaf (unwritten) Varnodes. Loop back-edges of MULTIEQUALs are clipped
	// so the DFS terminates without depending on not-yet-computed cyclic values.
	for _, root := range alive {
		if root.HasFlag(PcodeOpMark) {
			continue
		}
		stack := []opNode{{root, 0}}
		root.SetFlag(PcodeOpMark)
		for len(stack) > 0 {
			node := &stack[len(stack)-1]
			if node.slot >= node.op.NumInput() {
				if outvn := node.op.Output(); outvn != nil {
					outvn.SetNZMask(node.op.getNZMaskLocal(true))
				}
				stack = stack[:len(stack)-1]
				continue
			}
			oldslot := node.slot
			node.slot++
			if node.op.Code() == CPUI_MULTIEQUAL && node.op.Parent() != nil &&
				node.op.Parent().isLoopIn(oldslot) {
				continue
			}
			vn := node.op.Input(oldslot)
			if vn == nil {
				continue
			}
			if !vn.IsWritten() {
				if vn.IsConstant() {
					vn.SetNZMask(vn.Offset())
				} else if vn.IsTypeLock() && vn.Type() != nil && vn.Type().Metatype() == TYPE_BOOL {
					vn.SetNZMask(1)
				} else if vn.IsSpaceBase() {
					// A spacebase input is treated as aligned.
					vn.SetNZMask(maskForSize(vn.Size()) &^ 0xff)
				} else {
					vn.SetNZMask(maskForSize(vn.Size()))
				}
			} else if def := vn.Def(); def != nil && !def.HasFlag(PcodeOpMark) {
				stack = append(stack, opNode{def, 0})
				def.SetFlag(PcodeOpMark)
			}
		}
	}

	// Phase 2: clear marks, seed worklist with MULTIEQUALs (the only ops whose
	// inputs may have been clipped), and propagate changes to fixpoint.
	worklist := make([]*PcodeOp, 0)
	for _, op := range alive {
		op.ClearFlag(PcodeOpMark)
		if op.Code() == CPUI_MULTIEQUAL {
			worklist = append(worklist, op)
		}
	}
	for len(worklist) > 0 {
		op := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		vn := op.Output()
		if vn == nil {
			continue
		}
		nzmask := op.getNZMaskLocal(false)
		if nzmask != vn.NZMask() {
			vn.SetNZMask(nzmask)
			for _, desc := range vn.DescendIter() {
				if desc != nil && !desc.IsDead() {
					worklist = append(worklist, desc)
				}
			}
		}
	}
}

// MapGlobals makes sure every persistent (global) storage range the function
// touches has a symbol in the global scope: the host's symbol when it has one,
// else a default-named one. Overlapping persistent Varnodes are grouped into
// one range; the symbol type is the covering Varnode's high type when one
// Varnode spans the whole range, else an undefined blob.
// Each persistent Varnode is then linked to its entry (C++ does this later,
// in Funcdata::linkSymbol, through the same scope query).
// TODO known mismatch: the inconsistent-use warning and the symbols for
// uncovered internal Varnodes (funcdata_varnode.cc:1730-1745) are not ported.
// C++ parity: funcdata_varnode.cc Funcdata::mapGlobals.
func (fd *Funcdata) MapGlobals() {
	if fd == nil {
		return
	}
	all := fd.vbank.AllVarnodes()
	inconsistentuse := false
	defer func() {
		if inconsistentuse {
			fd.warningHeader("Globals starting with '_' overlap smaller symbols at the same address")
		}
	}()
	for i := 0; i < len(all); {
		vn := all[i]
		i++
		if vn == nil || vn.IsFree() || !vn.IsPersist() || vn.IsAnnotation() {
			continue
		}
		if fd.globalScope.EntryFor(vn) != nil {
			continue
		}
		group := []*Varnode{vn}
		maxvn := vn
		addr := vn.Addr()
		end := addr.Offset + uint64(vn.Size())
		for i < len(all) {
			w := all[i]
			if w == nil || !w.IsPersist() || w.Space() != addr.Space || w.Offset() >= end {
				break
			}
			if w.IsFree() || w.IsAnnotation() {
				// C++ never sees a free Varnode here: clearDeadVarnodes destroyed it
				// (TODO known mismatch: Go keeps some, e.g. a lane-split original).
				i++
				continue
			}
			group = append(group, w)
			if e := w.Offset() + uint64(w.Size()); e > end {
				end = e
			}
			if w.Size() > maxvn.Size() {
				maxvn = w
			}
			i++
		}
		var ct Datatype
		if maxvn.Offset() == addr.Offset && addr.Offset+uint64(maxvn.Size()) == end {
			if hv := maxvn.High(); hv != nil && hv.Type() != nil {
				ct = hv.Type()
			} else {
				ct = maxvn.Type()
			}
		}
		if ct == nil || ct.Size() != int32(end-addr.Offset) {
			ct = sharedTypeFactory.GetBase(int32(end-addr.Offset), TYPE_UNKNOWN, "")
		}
		entry := fd.resolveGlobal(addr)
		if entry == nil {
			nm := defaultGlobalName(addr, ct)
			if rn := fd.registerNames[fmt.Sprintf("%d:%d:%d", addr.Space.Index, addr.Offset, ct.Size())]; rn != "" {
				nm = rn // C++ parity: buildVariableName persist branch (getRegisterName)
			}
			entry = fd.globalScope.AddSymbol(nm, ct, addr, ct.Size(), 0)
		} else if addr.Offset+uint64(ct.Size())-1 > entry.Addr().Offset+uint64(entry.Size())-1 {
			inconsistentuse = true
			// Interior Varnodes with no Symbol of their own get one.
			var uncovered []*Varnode
			for _, g := range group[1:] {
				if g.Offset() != addr.Offset && fd.globalScope.EntryFor(g) == nil {
					uncovered = append(uncovered, g)
				}
			}
			fd.coverVarnodes(entry, uncovered)
		}
		for _, g := range group {
			if e := fd.resolveGlobal(g.Addr()); e != nil {
				fd.globalScope.Attach(g, e)
			}
		}
	}
}

// coverVarnodes gives each interior Varnode of an over-wide global access a
// Symbol named after the overlapped one (DAT_00c0a010_1), unless some Symbol
// already holds it. Of the Varnodes at one address the biggest is used.
// C++ parity: Funcdata::coverVarnodes.
func (fd *Funcdata) coverVarnodes(entry *SymbolEntry, list []*Varnode) {
	for i, vn := range list {
		if i+1 < len(list) && list[i+1].Addr() == vn.Addr() {
			continue
		}
		if e := fd.resolveGlobal(vn.Addr()); e != nil && containsRange(e, vn.Offset(), vn.Size()) {
			continue
		}
		if fd.globalScope.QueryContainer(vn.Addr(), vn.Size(), address.Address{}) != nil {
			continue
		}
		diff := int64(vn.Offset() - entry.Addr().Offset)
		ct := vn.Type()
		if hv := vn.High(); hv != nil && hv.Type() != nil {
			ct = hv.Type()
		}
		if ct == nil {
			ct = sharedTypeFactory.GetBase(vn.Size(), TYPE_UNKNOWN, "")
		}
		fd.globalScope.AddSymbol(fmt.Sprintf("%s_%d", entry.Symbol().Name(), diff), ct, vn.Addr(), vn.Size(), 0)
	}
}

// MarkIndirectOnly flags an illegal input (an input not written directly)
// whose value only reaches INDIRECTs, so naming can treat it as noise.
// C++ parity: Funcdata::markIndirectOnly.
func (fd *Funcdata) MarkIndirectOnly() {
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn.IsInput() && !vn.IsDirectWrite() && fd.checkIndirectUse(vn) {
			vn.SetFlags(VarnodeIndirectOnly)
		}
	}
}

// checkIndirectUse reports whether vn flows only into INDIRECTs, following
// MULTIEQUALs and indirect-store INDIRECTs.
// C++ parity: Funcdata::checkIndirectUse.
func (fd *Funcdata) checkIndirectUse(vn *Varnode) bool {
	vlist := []*Varnode{vn}
	vn.SetMark()
	result := true
	for i := 0; i < len(vlist) && result; i++ {
		for _, op := range vlist[i].DescendIter() {
			switch op.Code() {
			case CPUI_INDIRECT:
				if !op.IsIndirectStore() {
					continue
				}
			case CPUI_MULTIEQUAL:
			default:
				result = false
			}
			if !result {
				break
			}
			if out := op.Output(); !out.IsMark() {
				out.SetMark()
				vlist = append(vlist, out)
			}
		}
	}
	for _, v := range vlist {
		v.ClearMark()
	}
	return result
}

// spacebaseStackSpace returns the function's stack space (the spacebase-kind
// space whose base register is the stack pointer), taken from the locked
// prototype model or the default evaluation model. Returns nil when no stack
// space has been wired (the flag-off default), which makes Spacebase a no-op.
func (fd *Funcdata) spacebaseStackSpace() *address.Space {
	if fd.funcProto != nil {
		if m := fd.funcProto.Model(); m != nil && m.StackSpace != nil {
			return m.StackSpace
		}
	}
	if fd.defaultModel != nil && fd.defaultModel.StackSpace != nil {
		return fd.defaultModel.StackSpace
	}
	return nil
}

// Spacebase marks the stack-pointer register Varnodes as spacebase bases so the
// LOAD/STORE rules (RuleLoadVarnode/RuleStoreVarnode via correctSpacebase) can
// convert stack-pointer-relative memory accesses into stack-space Varnodes.
//
// For each base register of the stack space: every non-free Varnode at that
// (space,offset,size) location gets the spacebase flag and the associated stack
// space bound; the pointer-to-spacebase data-type is set on the INPUT Varnode
// only; and an already-marked base defined by an INT_ADD has its uses split so
// dead-code can eliminate the residual add. Running each mainloop pass
// (ActionSpacebase) makes this incremental: newly created base Varnodes are
// picked up on the next pass.
//
// C++ parity: funcdata.cc Funcdata::spacebase.
func (fd *Funcdata) Spacebase() {
	if fd == nil {
		return
	}
	stackSpace := fd.spacebaseStackSpace()
	if stackSpace == nil {
		return
	}
	tf := fd.TypeFactory()
	for i := 0; i < stackSpace.NumSpacebase(); i++ {
		point := stackSpace.GetSpacebase(i)
		if point.Space == nil || point.Size == 0 {
			continue
		}
		// Snapshot: SplitUses appends new Varnodes at the same location while we
		// iterate. Newly created bases are marked on the next Spacebase pass.
		snapshot := append([]*Varnode(nil), fd.vbank.AllVarnodes()...)
		for _, vn := range snapshot {
			if vn == nil || vn.Space() != point.Space ||
				vn.Offset() != point.Offset || vn.Size() != point.Size {
				continue
			}
			if vn.IsFree() {
				continue
			}
			if vn.IsSpaceBase() {
				// Already marked: force a use-split once its def is an INT_ADD so
				// the residual base-pointer add can be removed by dead code.
				if op := vn.Def(); op != nil && op.Code() == CPUI_INT_ADD {
					fd.SplitUses(vn)
				}
				continue
			}
			// Mark all base registers (not just the input).
			BindSpacebase(vn, stackSpace)
			if vn.IsInput() && tf != nil {
				// Only set the pointer type on the input spacebase register.
				ct := tf.GetTypeSpacebase(stackSpace)
				ptr := tf.GetPointer(point.Size, ct, uint32(stackSpace.WordSize))
				// C++ funcdata.cc:264 uses updateType(ptr,true,true): the
				// pointer-to-spacebase type is LOCKED and overrides any earlier
				// lock. Without the lock ActionInferTypes::writeBack immediately
				// demotes the base register back to int, so no pointer ever
				// reaches RulePtrArith and PTRSUB/PTRADD are never formed.
				vn.UpdateTypeLock(ptr, true, true)
				// Record which space the spacebase points into. In C++ the space
				// is intrinsic to the data-type: getTypeSpacebase(id) builds a
				// TypeSpacebase whose `spaceid` member TypeSpacebase::getSubType
				// hands to getMap(). Gosleigh's TypeFactory.GetTypeSpacebase has
				// no such member, so the space travels through the
				// BindSpaceConstant side table instead -- the same channel
				// ActionConstantPtr already uses for the global spacebase. Without
				// it every stack Funcdata.ResolveSpacebaseSymbol query hit the
				// `spc == nil` guard and answered undefined1, which made
				// AddTreeState size a frame element at 1 byte and emit
				// PTRADD(sp,index,#1) instead of PTRADD(sp,index,#4).
				BindSpaceConstant(vn, stackSpace)
			}
		}
	}
}

// SplitUses duplicates a Varnode's defining op at each of its reads so every
// read becomes a distinct Varnode. Used by Spacebase to break a spacebase base
// with multiple descendants apart; dead code then removes the original op.
// No-op for ops with side effects is the caller's responsibility (only called
// on INT_ADD-defined spacebase Varnodes here).
// C++ parity: funcdata_varnode.cc Funcdata::splitUses.
func (fd *Funcdata) SplitUses(vn *Varnode) {
	if fd == nil || vn == nil {
		return
	}
	op := vn.Def()
	if op == nil {
		return
	}
	descend := vn.DescendIter()
	if len(descend) < 2 {
		return // zero or one descendant: nothing to split
	}
	for _, useop := range descend {
		slot := useop.GetSlot(vn)
		if slot < 0 {
			continue
		}
		newop := fd.NewOp(op.NumInput(), op.Addr())
		newvn := fd.NewVarnode(vn.Size(), vn.Addr())
		if t := vn.Type(); t != nil {
			SetVarnodeType(newvn, t)
		}
		fd.OpSetOutput(newop, newvn)
		fd.OpSetOpcode(newop, op.Code())
		for i := 0; i < op.NumInput(); i++ {
			fd.OpSetInput(newop, op.Input(i), i)
		}
		fd.OpSetInput(useop, newvn, slot)
		fd.OpInsertBefore(newop, op)
	}
	// Dead-code actions remove the now-unused original op.
}

// ApplyForceGoto applies force-goto overrides.
// C++ parity: funcdata.hh Funcdata::applyForceGoto
func (fd *Funcdata) ApplyForceGoto() {
	_ = fd
}

// SyncVarnodesWithSymbols pushes symbol data from the scope down onto the
// Varnodes that occupy the scope's address space. For each Varnode the scope
// either (a) returns a SymbolEntry that contains it -- in which case the
// entry's flags/data-type are pulled onto the Varnode, or (b) produces no
// match, in which case either the "in scope" flag set is applied or, when
// unmappedAliasCheck is requested, the Varnode is checked against the
// unmapped-unaliased heuristic.
//
// Returns true if any Varnode was observably modified.
// C++ parity: funcdata_varnode.cc Funcdata::syncVarnodesWithSymbols
func (fd *Funcdata) SyncVarnodesWithSymbols(lm *ScopeLocal, updateDatatypes bool, unmappedAliasCheck bool) bool {
	if fd == nil || lm == nil {
		return false
	}
	space := lm.SpaceID()
	if space == nil {
		return false
	}
	updateOccurred := false
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn == nil || vn.IsFree() {
			continue
		}
		if vn.Space() != space {
			continue
		}
		addr := vn.Addr()
		entry := lm.FindOverlap(addr, vn.Size())
		var ct Datatype
		var fl uint32
		if entry != nil {
			fl = entry.AllFlags()
			if entry.Size() >= vn.Size() {
				if updateDatatypes {
					ct = entry.GetSizedType(addr, vn.Size())
					if ct != nil {
						if base, ok := ct.(*Base); ok && base.Metatype() == TYPE_UNKNOWN {
							ct = nil
						}
					}
				}
			} else {
				// Overlapping but not containing: drop typelock/namelock to
				// avoid forcing a wrong type onto a wider register.
				fl &^= (VarnodeTypeLock | VarnodeNameLock)
			}
			lm.AttachEntryToVarnode(vn, entry)
		} else {
			if lm.InScope(addr, vn.Size(), vn.Addr()) {
				fl = VarnodeMapped | VarnodeAddrTied
			} else if unmappedAliasCheck {
				if lm.IsUnmappedUnaliased(vn) {
					fl = VarnodeNoLocalAlias
				} else {
					fl = 0
				}
			} else {
				fl = 0
			}
		}
		if fd.syncVarnodeFlags(vn, fl, ct) {
			updateOccurred = true
		}
	}
	return updateOccurred
}

// syncVarnodeFlags applies the subset of flag transitions that
// syncVarnodesWithSymbol makes: mapped/addrtied/addrforce/nolocalalias and a
// replacement data-type. The transitions mirror the mask computation in the
// C++ source so "addrtied can be cleared but not set" and "nolocalalias can
// be set but not cleared" hold.
// C++ parity: funcdata_varnode.cc Funcdata::syncVarnodesWithSymbol
func (fd *Funcdata) syncVarnodeFlags(vn *Varnode, fl uint32, ct Datatype) bool {
	if vn == nil {
		return false
	}
	mask := VarnodeMapped
	if fl&VarnodeAddrTied == 0 {
		mask |= VarnodeAddrTied | VarnodeAddrForce
	}
	if fl&VarnodeNoLocalAlias != 0 {
		mask |= VarnodeNoLocalAlias | VarnodeAddrForce
	}
	fl &= mask
	updated := false
	cur := vn.Flags() & mask
	if cur != fl {
		updated = true
		vn.SetFlags(fl)
		vn.ClearFlags((^fl) & mask)
	}
	// Varnode::updateType: a type-locked Varnode keeps its type.
	if ct != nil && !vn.IsTypeLock() && vn.Type() != ct {
		SetVarnodeType(vn, ct)
		updated = true
	}
	return updated
}

// RemoveUnreachableBlocks removes every block the entry cannot reach,
// optionally warning about each. checkexistence tests the dominators instead
// of trusting the cached unreachable flag.
// C++ parity: funcdata_block.cc Funcdata::removeUnreachableBlocks.
func (fd *Funcdata) RemoveUnreachableBlocks(issuewarning, checkexistence bool) bool {
	graph := fd.GetBasicBlocks()
	if checkexistence {
		found := false
		for i := 0; i < graph.GetSize(); i++ {
			blk := graph.GetBlock(i)
			if !blk.IsEntryPoint() && blk.ImmedDom() == nil {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	} else if !fd.HasFlag(FuncBlocksUnreachable) {
		return false
	}
	var entry *FlowBlock
	for i := 0; i < graph.GetSize(); i++ {
		if graph.GetBlock(i).IsEntryPoint() {
			entry = graph.GetBlock(i)
			break
		}
	}
	if entry == nil {
		return false
	}
	list := graph.collectReachable(entry, true)
	for _, bl := range list {
		bl.SetDead()
		if issuewarning {
			fd.warningHeader("Removing unreachable block (" + blockStartText(asBasic(bl)) + ")")
		}
	}
	for _, bl := range list {
		bb := asBasic(bl)
		for bb.SizeOut() > 0 {
			fd.branchRemoveInternal(bb, 0)
		}
	}
	for _, bl := range list {
		fd.blockRemoveInternal(asBasic(bl), true)
	}
	fd.StructureReset()
	return true
}

// blockStartText prints a block's start address as "space,0x...".
// C++ parity: BlockBasic::getStart + Address::printRaw.
func blockStartText(bb *BlockBasic) string {
	a := bb.startAddr()
	if a.Space == nil {
		return ""
	}
	return a.Space.Name + "," + PrintRawAddr(a) // C++ parity: Address::printRaw
}

// RemoveDoNothingBlock is implemented in funcdata_donothing.go.

// branchRemoveInternal severs the out-edge numbered num from bb, removing the
// branch instruction if the block had exactly two exits, and pruning the
// corresponding MULTIEQUAL inputs in the target block.
// C++ parity: funcdata_block.cc Funcdata::branchRemoveInternal.
func (fd *Funcdata) branchRemoveInternal(bb *BlockBasic, num int) {
	if bb.SizeOut() == 2 { // If there is no decision left
		fd.OpDestroy(bb.LastOp()) // Remove the branch instruction
	}
	bbout := asBasic(bb.OutEdge(num).Point)
	if bbout == nil {
		return
	}
	blocknum := bbout.GetInIndex(&bb.FlowBlock)
	fd.GetBasicBlocks().RemoveEdge(&bb.FlowBlock, &bbout.FlowBlock) // Sever (one) connection
	// Prune the pruned in-edge's slot from any MULTIEQUAL in the target.
	for _, op := range append([]*PcodeOp(nil), bbout.opSlice()...) {
		if op.Code() != CPUI_MULTIEQUAL {
			continue
		}
		fd.OpRemoveInput(op, blocknum)
		fd.opZeroMulti(op)
	}
}

// RemoveBranch removes out-edge num from bb (severing a redundant or determined
// branch) and recomputes block structure.
// C++ parity: funcdata_block.cc Funcdata::removeBranch.
func (fd *Funcdata) RemoveBranch(bb *BlockBasic, num int) {
	fd.branchRemoveInternal(bb, num)
	fd.StructureReset()
}

// ---------------------------------------------------------------------------
// Varnode creation
// C++ parity: funcdata_varnode.cc
// ---------------------------------------------------------------------------

// setVarnodeProperties stamps a freshly created Varnode with the boolean flags of
// the local-scope SymbolEntry that covers its storage (mapped, addrtied, ...). This
// is how a Varnode created at a mapped stack-slot address inherits addrtied: the
// flag is set unconditionally at creation, whereas SyncVarnodesWithSymbols can only
// CLEAR addrtied later (funcdata_varnode.cc:1078-1081). Without this, stack Varnodes
// created during the merge group (trim COPYs, phi outputs) -- after the symbols exist
// but never re-created by the mainloop -- stay non-addrtied, so mergeByDatatype's
// addr-tied guard cannot keep two distinct stack locals (and the registers merged into
// each) apart. Early in the pipeline the scope has no entries yet, so this is a no-op
// (matching C++, where queryProperties finds nothing before symbols are built).
// C++ parity: Funcdata::setVarnodeProperties (funcdata_varnode.cc:25) ->
// Varnode::setSymbolProperties (setFlags(entry->getAllFlags() & ~typelock)).
func (fd *Funcdata) setVarnodeProperties(vn *Varnode) {
	if vn == nil || vn.IsMapped() || vn.Space() == nil {
		return
	}
	// The property map marks storage copied to incidentally (the x87
	// stack); it applies at the Varnode's starting address.
	// C++ parity: Scope::queryProperties -> Database::getProperty.
	for _, r := range fd.incidentalCopy {
		if r.Space == vn.Space() && vn.Offset() >= r.First && vn.Offset() <= r.Last {
			vn.SetFlags(VarnodeIncidentalCopy)
			break
		}
	}
	if sl := fd.scopeLocal; sl != nil {
		if entry := sl.FindOverlap(vn.Addr(), vn.Size()); entry != nil {
			// A type-locked symbol forces its type onto the Varnode.
			// C++ parity: Varnode::setSymbolProperties -> SymbolEntry::updateType.
			if sym := entry.Symbol(); sym != nil && sym.IsTypeLocked() {
				if dt := entry.GetSizedType(vn.Addr(), vn.Size()); dt != nil {
					vn.UpdateTypeLock(dt, true, true)
				}
			} else if t, ok := fd.hostLocalTypes[vn.Offset()]; ok && t != nil && t.Size() == vn.Size() && vn.Space() == sl.SpaceID() {
				// The host's type-locked symbol stands where Gosleigh placed an
				// unlocked one; its type applies as the C++ symbol's would.
				vn.UpdateTypeLock(t, true, true)
			}
			vn.SetFlags(entry.AllFlags() &^ VarnodeTypeLock)
			return
		}
		// A host type-locked stack symbol exists in C++ from the start
		// (the prototype's ProtoStoreSymbol / the decoded scope); Gosleigh
		// builds the local symbols later, so its type is forced here.
		// C++ parity: Varnode::setSymbolProperties -> SymbolEntry::updateType.
		if vn.Space() == sl.SpaceID() {
			if t, ok := fd.hostLocalTypes[vn.Offset()]; ok && t != nil && t.Size() == vn.Size() {
				vn.UpdateTypeLock(t, true, true)
			}
		}
		// Inside the local scope but not covered by a symbol.
		// C++ parity: Scope::queryProperties (found just a scope).
		if vn.Space() == sl.SpaceID() && sl.inScopeRange(vn.Offset(), vn.Size()) {
			vn.SetFlags(VarnodeMapped | VarnodeAddrTied)
			return
		}
	}
	// Storage inside the global scope is a global variable: mapped, address
	// tied and persistent even without a symbol. An external-reference symbol
	// (an import slot) adds externref.
	// C++ parity: database.cc Scope::queryProperties (global finalscope
	// branch) + ExternRefSymbol flags (database.cc:783).
	if fd.inGlobalScope(vn.Addr(), vn.Size()) {
		fl := VarnodeMapped | VarnodeAddrTied | VarnodePersist
		if fd.hostScope != nil {
			if _, ok := fd.hostScope.QueryExternalRef(vn.Addr()); ok {
				fl |= VarnodeExternRef
			}
			// A symbol's storage properties carry over to the Varnode; with
			// no symbol containing it, the address's own properties do.
			// C++ parity: Scope::queryProperties (res->getAllFlags(), else
			// symboltab->getProperty(addr)).
			if e := fd.resolveGlobal(vn.Addr()); e != nil && e.Symbol() != nil &&
				vn.Offset() >= e.Addr().Offset && vn.Offset()+uint64(vn.Size()) <= e.Addr().Offset+uint64(e.Size()) {
				fl |= e.Symbol().Flags() & (VarnodeReadOnly | VarnodeVolatile)
			} else {
				fl |= fd.addrProperty(vn.Addr())
			}
		}
		vn.SetFlags(fl)
		// A type-locked host symbol forces its type onto the Varnode
		// (ExceptionList is a void *, so is whatever copies it).
		// C++ parity: Varnode::setSymbolProperties -> SymbolEntry::updateType.
		if fd.hostScope != nil {
			if e := fd.resolveGlobal(vn.Addr()); e != nil && e.Symbol() != nil &&
				e.Symbol().Flags()&VarnodeTypeLock != 0 {
				if ct := e.GetSizedType(vn.Addr(), vn.Size()); ct != nil && ct.Size() == vn.Size() {
					vn.UpdateTypeLock(ct, true, true) // an unknown type is never locked
				}
			}
		}
	}
}

// queryPropertyFlags returns the Varnode properties of a storage range: the
// local symbol's flags when the local scope holds one, else mapped|addrtied|
// persist for global-scope storage, else none.
// C++ parity: Scope::queryProperties as used by Heritage::guard.
func (fd *Funcdata) queryPropertyFlags(addr address.Address, size int32) uint32 {
	if sl := fd.scopeLocal; sl != nil {
		if entry := sl.FindOverlap(addr, size); entry != nil {
			return entry.AllFlags()
		}
		// Inside the local scope but not covered by a symbol.
		// C++ parity: Scope::queryProperties (found just a scope).
		if sl.inScopeRange(addr.Offset, size) && addr.Space == sl.SpaceID() {
			return VarnodeMapped | VarnodeAddrTied
		}
	}
	if fd.inGlobalScope(addr, size) {
		return VarnodeMapped | VarnodeAddrTied | VarnodePersist | fd.addrProperty(addr)
	}
	return fd.addrProperty(addr)
}

// addrProperty is the host's property map at addr (read-only, volatile).
// C++ parity: Database::getProperty.
func (fd *Funcdata) addrProperty(addr address.Address) uint32 {
	if h, ok := fd.hostScope.(HostProperties); ok {
		return h.Property(addr) & (VarnodeReadOnly | VarnodeVolatile)
	}
	return 0
}

// GlobalRange is one storage range of the global scope.
type GlobalRange struct {
	Space       *address.Space
	First, Last uint64
}

// SetIncidentalCopyRanges installs the storage the processor copies to
// incidentally; Varnodes starting there carry the incidental_copy property.
// C++ parity: Architecture::decodeIncidentalCopy.
func (fd *Funcdata) SetIncidentalCopyRanges(r []GlobalRange) { fd.incidentalCopy = r }

// SetGlobalRanges installs the global scope's storage ranges (cspec <global>).
// C++ parity: Architecture::addToGlobalScope.
func (fd *Funcdata) SetGlobalRanges(r []GlobalRange) { fd.globalRanges = r }

// SetJoinSpace installs the join and default code spaces.
func (fd *Funcdata) SetJoinSpace(join, code *address.Space) {
	fd.joinSpace = join
	fd.codeSpace = code
}

// JoinSpace is the join address space, or nil when none is configured.
func (fd *Funcdata) JoinSpace() *address.Space { return fd.joinSpace }

// inGlobalScope reports whether [addr, addr+size) lies inside a global range.
func (fd *Funcdata) inGlobalScope(addr address.Address, size int32) bool {
	last := addr.Offset + uint64(size) - 1
	for _, r := range fd.globalRanges {
		if r.Space == addr.Space && addr.Offset >= r.First && last <= r.Last && last >= addr.Offset {
			return true
		}
	}
	return false
}

// NewVarnode creates a free Varnode.
// C++ parity: Funcdata::newVarnode
func (fd *Funcdata) NewVarnode(size int32, loc address.Address) *Varnode {
	vn := fd.vbank.Create(size, loc)
	fd.setVarnodeProperties(vn)
	fd.checkForLanedRegister(size, loc)
	return vn
}

// NewVarnodeOut creates a Varnode as the defined output of an op.
// C++ parity: Funcdata::newVarnodeOut
func (fd *Funcdata) NewVarnodeOut(size int32, loc address.Address, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDef(size, loc, op)
	op.SetOutput(vn)
	fd.setVarnodeProperties(vn)
	fd.checkForLanedRegister(size, loc)
	return vn
}

// NewUniqueOut creates a temp Varnode (unique space) as output of an op.
// C++ parity: Funcdata::newUniqueOut
func (fd *Funcdata) NewUniqueOut(size int32, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDefUnique(size, op)
	op.SetOutput(vn)
	fd.checkForLanedRegister(size, vn.Addr())
	return vn
}

// NewConstant creates a constant Varnode.
// C++ parity: Funcdata::newConstant
func (fd *Funcdata) NewConstant(size int32, val uint64) *Varnode {
	loc := address.Address{Space: fd.constSpace, Offset: val}
	return fd.vbank.Create(size, loc)
}

// NewUnique creates a free temp Varnode in unique space, not attached as any
// op's output. C++ parity: Funcdata::newUnique.
func (fd *Funcdata) NewUnique(size int32) *Varnode {
	vn := fd.vbank.CreateUnique(size)
	fd.checkForLanedRegister(size, vn.Addr())
	return vn
}

// SetInputVarnode promotes a free Varnode to SSA function input.
// C++ parity: Funcdata::setInputVarnode
func (fd *Funcdata) SetInputVarnode(vn *Varnode) *Varnode {
	if vn.IsInput() {
		return vn
	}
	fd.vbank.SetInput(vn)
	fd.setVarnodeProperties(vn)
	// A register the convention preserves holds the caller's value for the
	// whole function. C++ parity: Funcdata::setInputVarnode (effect lookup).
	switch fd.funcProto.HasEffect(vn.Addr(), vn.Size()) {
	case EffectUnaffected:
		vn.SetFlags(VarnodeUnaffected)
	case EffectReturnAddress:
		vn.SetFlags(VarnodeUnaffected | VarnodeReturnAddress)
	}
	return vn
}

// DeleteVarnode removes a Varnode from the bank.
// The varnode must be free with no descendants.
// C++ parity: Funcdata::deleteVarnode
func (fd *Funcdata) DeleteVarnode(vn *Varnode) {
	fd.vbank.Destroy(vn)
}

// sortedInputVarnodes lists the input Varnodes by address, then size.
// C++ parity: VarnodeBank beginDef(Varnode::input) ordering.
func (fd *Funcdata) sortedInputVarnodes() []*Varnode {
	var out []*Varnode
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn.IsInput() {
			out = append(out, vn)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Size() < b.Size()
	})
	return out
}

// unjustifiedInputParam reports the container of an input range that a
// parameter holds improperly justified. C++ parity:
// FuncProto::unjustifiedInputParam (locked parameters first, then the model).
func (fd *Funcdata) unjustifiedInputParam(addr address.Address, size int32) (address.Address, int32, bool) {
	fp := fd.GetFuncProto()
	if fp == nil {
		return address.Address{}, 0, false
	}
	if !fp.dotdotdot && fd.hostScope != nil {
		if hf, ok := fd.hostScope.QueryFunction(fd.baseAddr); ok && hf.InputLocked {
			if len(hf.Params) == 0 {
				return address.Address{}, 0, false // a locked void input list
			}
			for _, p := range hf.Params {
				s, ok := fd.resolveHostParam(p)
				if !ok {
					continue
				}
				just := addressJustifiedContain(s.Addr, s.Size, addr, size, false)
				if just == 0 {
					return address.Address{}, 0, false // contained, properly justified
				}
				if just > 0 {
					return s.Addr, s.Size, true
				}
			}
			return address.Address{}, 0, false
		}
	}
	if m := fp.Model(); m != nil && m.InputParams != nil {
		return m.InputParams.unjustifiedContainer(addr, size)
	}
	return address.Address{}, 0, false
}

// adjustInputVarnodes replaces the inputs inside [addr, addr+sz) with
// SUBPIECEs of one new input covering the whole range. It reports false,
// changing nothing, where the C++ throws.
// C++ parity: Funcdata::adjustInputVarnodes.
func (fd *Funcdata) adjustInputVarnodes(addr address.Address, sz int32) bool {
	end := addr.Offset + uint64(sz) - 1
	var inlist []*Varnode
	for _, vn := range fd.sortedInputVarnodes() {
		if vn.Space() != addr.Space || vn.Offset() < addr.Offset || vn.Offset() > end {
			continue
		}
		if vn.Offset()+uint64(vn.Size())-1 > end {
			return false // Cannot properly adjust input varnodes
		}
		if addressJustifiedContain(addr, sz, vn.Addr(), vn.Size(), false) < 0 || sz <= vn.Size() {
			return false // Bad adjustment to input varnode
		}
		inlist = append(inlist, vn)
	}
	bg := fd.GetBasicBlocks()
	if bg == nil || bg.GetSize() == 0 {
		return false
	}
	entry, ok := bg.GetBlock(0).Concrete().(*BlockBasic)
	if !ok {
		return false
	}
	for i, vn := range inlist {
		sa := addressJustifiedContain(addr, sz, vn.Addr(), vn.Size(), false)
		subop := fd.NewOp(2, fd.baseAddr)
		fd.OpSetOpcode(subop, CPUI_SUBPIECE)
		fd.OpSetInput(subop, fd.NewConstant(4, uint64(sa)), 1)
		newvn := fd.NewVarnodeOut(vn.Size(), vn.Addr(), subop)
		// newvn must not be free, to take all of vn's descendants
		fd.OpInsertBegin(subop, entry)
		fd.TotalReplace(vn, newvn)
		fd.DeleteVarnode(vn) // the old input goes before the new one is made
		inlist[i] = newvn
	}
	invn := fd.SetInputVarnode(fd.NewVarnode(sz, addr))
	// Heritage ignores the new input (no "Heritage AFTER dead removal").
	invn.SetAddlFlags(VarnodeWriteMask)
	for _, v := range inlist {
		fd.OpSetInput(v.Def(), invn, 0)
	}
	return true
}

// FindVarnodeInput finds an input varnode matching the given size and location.
// C++ parity: Funcdata::findVarnodeInput
func (fd *Funcdata) FindVarnodeInput(size int32, loc address.Address) *Varnode {
	return fd.vbank.FindInput(size, loc)
}

// NumVarnodes returns the total number of varnodes.
func (fd *Funcdata) NumVarnodes() int {
	return fd.vbank.NumVarnodes()
}

// ---------------------------------------------------------------------------
// PcodeOp creation
// C++ parity: funcdata_op.cc
// ---------------------------------------------------------------------------

// NewOp creates a new PcodeOp with the given number of inputs.
// The op starts on the dead list.
// C++ parity: Funcdata::newOp
func (fd *Funcdata) NewOp(numInputs int, addr address.Address) *PcodeOp {
	return fd.obank.Create(numInputs, addr)
}

// OpSetOpcode assigns an opcode to a PcodeOp via the TypeOp registry.
// C++ parity: Funcdata::opSetOpcode
func (fd *Funcdata) OpSetOpcode(op *PcodeOp, opc OpCode) {
	if int(opc) < len(fd.typeOps) && fd.typeOps[opc] != nil {
		fd.obank.ChangeOpcode(op, fd.typeOps[opc])
	}
}

// OpSetOutput wires a Varnode as the output of a PcodeOp.
// If the op already has an output, it is unset first.
// If vn already has a def (another op claims to produce it), that op's output
// is unset before reassigning vn's def to op.
// C++ parity: Funcdata::opSetOutput (funcdata_op.cc:70)
func (fd *Funcdata) OpSetOutput(op *PcodeOp, vn *Varnode) {
	if vn == op.Output() {
		return // already set
	}
	// Unset old output of this op first.
	if op.Output() != nil {
		fd.OpUnsetOutput(op)
	}
	// If vn is already defined by another op, unset that op's output first.
	// This may call vbank.MakeFree(vn), setting vn to free state.
	if vn.Def() != nil {
		fd.OpUnsetOutput(vn.Def())
	}
	// Use vbank.SetDef to properly re-register vn as written in the varnode bank.
	// C++ parity: vbank.setDef(vn, op) in funcdata_op.cc:83 -- updates written tree.
	// Simple vn.SetDef(op) would leave vn in free state after MakeFree above.
	fd.vbank.SetDef(vn, op)
	fd.setVarnodeProperties(vn)
	op.SetOutput(vn)
}

// OpSetInput wires a Varnode as an input of a PcodeOp at the given slot.
// If the slot already holds a varnode, it is unset first (descend removed).
// Then the new varnode's descend list is updated to include op.
// C++ parity: Funcdata::opSetInput (funcdata_op.cc:104)
func (fd *Funcdata) OpSetInput(op *PcodeOp, vn *Varnode, slot int) {
	if vn == op.Input(slot) {
		return // Already set to this vn
	}
	// A constant has at most one reader (unless it is a spacebase): a shared
	// constant would carry one type for every use.
	if vn.IsConstant() && !vn.HasNoDescend() && !vn.IsSpaceBase() {
		cvn := fd.NewConstant(vn.Size(), vn.Offset())
		cvn.copySymbol(vn)
		// Gosleigh keeps space-id and INDIRECT-cause references in side
		// tables rather than in the constant's offset; carry them over.
		if spc := vn.GetSpaceFromConst(); spc != nil {
			BindSpaceConstant(cvn, spc)
		}
		if cause := vn.GetIndirectCause(); cause != nil {
			BindIndirectCause(cvn, cause)
		}
		vn = cvn
	}
	// Identical to C++: unset the old input before setting the new one.
	if old := op.Input(slot); old != nil {
		fd.OpUnsetInput(op, slot)
	}
	vn.AddDescend(op)
	op.SetInput(vn, slot)
}

// OpUnsetOutput disconnects the output Varnode from a PcodeOp.
// Clears the varnode's def link and the op's output pointer.
// If the varnode is bank-managed (VarnodeWritten), it is properly removed
// from or transitioned in the VarnodeBank while its def is still valid for
// sorting -- clearing def before removal would corrupt CompareDefLoc.
// C++ parity: Funcdata::opUnsetOutput
func (fd *Funcdata) OpUnsetOutput(op *PcodeOp) {
	vn := op.Output()
	if vn == nil {
		return
	}
	op.SetOutput(nil)
	if vn.IsWritten() {
		// Varnode is in VarnodeBank's defTree. Must remove/transition while
		// vn.def is still valid so CompareDefLoc can sort during removal.
		// The output becomes free but stays in the bank (clearDeadVarnodes
		// reclaims it). MakeFree clears def and VarnodeWritten.
		fd.vbank.MakeFree(vn)
		return
	}
	// Non-bank-managed varnode (free or directly assigned def): just clear.
	vn.SetDef(nil)
}

// OpUnsetInput disconnects an input Varnode from a PcodeOp at the given slot.
// Removes the op from the varnode's descend list and clears the slot.
// C++ parity: Funcdata::opUnsetInput
func (fd *Funcdata) OpUnsetInput(op *PcodeOp, slot int) {
	vn := op.Input(slot)
	if vn != nil {
		vn.EraseDescend(op)
		op.ClearInput(slot)
	}
}

// OpMarkAlive moves an op from dead to alive list.
// C++ parity: Funcdata::opMarkAlive (via PcodeOpBank::markAlive)
func (fd *Funcdata) OpMarkAlive(op *PcodeOp) {
	fd.obank.MarkAlive(op)
}

// OpMarkDead moves an op from alive to dead list.
// C++ parity: Funcdata::opMarkDead (via PcodeOpBank::markDead)
func (fd *Funcdata) OpMarkDead(op *PcodeOp) {
	fd.obank.MarkDead(op)
}

// OpDestroy destroys a PcodeOp and disconnects all its Varnodes.
// Removes the op from its parent basic block so it is no longer emitted.
// C++ parity: Funcdata::opDestroy
func (fd *Funcdata) OpDestroy(op *PcodeOp) {
	// Remove from parent basic block first so it is no longer iterable.
	// Ghidra: op->getParent()->removeOp(op)
	if p := op.Parent(); p != nil {
		p.RemoveOp(op)
	}
	// Disconnect output
	fd.OpUnsetOutput(op)
	// Disconnect all inputs
	for i := 0; i < op.NumInput(); i++ {
		fd.OpUnsetInput(op, i)
	}
	// obank.Destroy picks the alive/dead list by op.IsDead(), so remove from the
	// bank first, then mark the op dead. Without the flag, callers relying on the
	// action framework's op.IsDead() guard (e.g. after a rule destroys the op it
	// is processing and returns 1) would keep running rules on a freed op whose
	// inputs are now nil. C++ parity: Funcdata::opDestroy leaves the op dead.
	fd.obank.Destroy(op)
	op.SetFlag(PcodeOpDead)
}

// OpDestroyRecursive is the Go port of Funcdata::opDestroyRecursive in funcdata_op.cc.
func (fd *Funcdata) OpDestroyRecursive(op *PcodeOp) {
	scratch := []*PcodeOp{op}
	for pos := 0; pos < len(scratch); pos++ {
		cur := scratch[pos]
		for i := 0; i < cur.NumInput(); i++ {
			vn := cur.Input(i)
			if vn == nil || !vn.IsWritten() || vn.IsAutoLive() {
				continue
			}
			if vn.LoneDescend() == nil {
				continue
			}
			defOp := vn.Def()
			if defOp.IsCall() || defOp.IsIndirectSource() {
				continue
			}
			scratch = append(scratch, defOp)
		}
		fd.OpDestroy(cur)
	}
}

// DestroyVarnodeRecursive destroys a Varnode once it has no remaining readers,
// recursing into its defining op if that op becomes dead as a result.
// C++ parity: Funcdata::destroyVarnodeRecursive (funcdata_varnode.cc L543). The
// auto-live and "still has descendants" guard mirror the C++ pre-check so that
// the recursive walk never frees a Varnode that another op still observes.
func (fd *Funcdata) DestroyVarnodeRecursive(vn *Varnode) {
	if vn == nil {
		return
	}
	if vn.IsAutoLive() || !vn.HasNoDescend() {
		return
	}
	if !vn.IsWritten() {
		fd.vbank.Destroy(vn)
		return
	}
	fd.OpDestroyRecursive(vn.Def())
}

// OpInsertInput inserts a new input operand vn into op at slot, shifting the
// existing operands at slot..n down one position.
// C++ parity: Funcdata::opInsertInput (funcdata_op.cc L308). The helper is used
// by the bitfield absorb rewrites to append the ZPULL/SPULL (position,width)
// constants onto an existing one-operand op.
func (fd *Funcdata) OpInsertInput(op *PcodeOp, vn *Varnode, slot int) {
	if op == nil {
		return
	}
	op.InsertInput(slot)
	fd.OpSetInput(op, vn, slot)
}

// FindOp looks up a PcodeOp by its SeqNum.
// C++ parity: Funcdata::findOp
func (fd *Funcdata) FindOp(seq SeqNum) *PcodeOp {
	return fd.obank.FindOp(seq)
}

// NumOps returns the total number of PcodeOps.
func (fd *Funcdata) NumOps() int {
	return fd.obank.NumOps()
}

// ---------------------------------------------------------------------------
// Heritage support methods
// C++ parity: funcdata.hh Funcdata (heritage-related)
// ---------------------------------------------------------------------------

// OpInsertBegin creates an op and inserts it at the beginning of a basic block.
// The op is marked alive and its parent is set.
// C++ parity: Funcdata::opInsertBegin
func (fd *Funcdata) OpInsertBegin(op *PcodeOp, bb *BlockBasic) {
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	// MULTIEQUALs stay at the head of the block: any other op goes after
	// them. C++ parity: Funcdata::opInsertBegin.
	if op.Code() != CPUI_MULTIEQUAL {
		for _, o := range bb.opSlice() {
			if o.Code() != CPUI_MULTIEQUAL {
				bb.InsertOpBefore(op, o)
				return
			}
		}
		bb.InsertOpEnd(op)
		return
	}
	bb.InsertOpBegin(op)
}

// OpInsertEnd creates an op and inserts it at the end of a basic block.
// The op is marked alive and its parent is set. If the block already ends in a
// flow-break op (branch terminator), the new op is inserted just before it so
// the terminator stays last; otherwise the op is appended.
// C++ parity: Funcdata::opInsertEnd (funcdata_op.cc:435)
func (fd *Funcdata) OpInsertEnd(op *PcodeOp, bb *BlockBasic) {
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	if last := bb.LastOp(); last != nil && last.IsFlowBreak() {
		bb.InsertOpBefore(op, last)
	} else {
		bb.InsertOpEnd(op)
	}
}

// OpBoolNegate creates a CPUI_BOOL_NEGATE of vn (a fresh 1-byte unique output)
// and inserts it before/after op, returning the negated result Varnode.
// C++ parity: Funcdata::opBoolNegate (funcdata_op.cc:560).
func (fd *Funcdata) OpBoolNegate(vn *Varnode, op *PcodeOp, insertafter bool) *Varnode {
	negateop := fd.NewOp(1, op.Addr())
	fd.OpSetOpcode(negateop, CPUI_BOOL_NEGATE)
	resvn := fd.NewUniqueOut(1, negateop)
	fd.OpSetInput(negateop, vn, 0)
	if insertafter {
		fd.OpInsertAfter(negateop, op)
	} else {
		fd.OpInsertBefore(negateop, op)
	}
	return resvn
}

// OpInsertBefore inserts op immediately before follow in follow's basic block.
// The op is marked alive and its parent block is set.
// C++ parity: Funcdata::opInsertBefore
func (fd *Funcdata) OpInsertBefore(op *PcodeOp, follow *PcodeOp) {
	bb := follow.Parent()
	if bb == nil {
		return
	}
	// There should not be an INDIRECT immediately preceding op: a non-INDIRECT
	// goes in front of the INDIRECTs attached to follow.
	// C++ parity: Funcdata::opInsertBefore.
	if op.Code() != CPUI_INDIRECT {
		for prev := follow.PreviousOp(); prev != nil && prev.Code() == CPUI_INDIRECT; prev = prev.PreviousOp() {
			follow = prev
		}
	}
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpBefore(op, follow)
}

// OpInsertAfter inserts op immediately after prev in prev's basic block.
// The op is marked alive and its parent block is set.
// C++ parity: Funcdata::opInsertAfter
func (fd *Funcdata) OpInsertAfter(op *PcodeOp, prev *PcodeOp) {
	// After an INDIRECT, insert after the op causing the indirect effect.
	if prev.Code() == CPUI_INDIRECT {
		if targ := prev.Input(1).GetIndirectCause(); targ != nil && !targ.IsDead() {
			prev = targ
		}
	}
	bb := prev.Parent()
	if bb == nil {
		return
	}
	// A non-MULTIEQUAL never lands among the MULTIEQUALs heading a block.
	if op.Code() != CPUI_MULTIEQUAL {
		for next := prev.NextOp(); next != nil && next.Code() == CPUI_MULTIEQUAL; next = next.NextOp() {
			prev = next
		}
	}
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpAfter(op, prev)
}

// NewIndirectOp creates an INDIRECT op inserted immediately before callOp that
// models an unknown side-effect on the address range (sp, off, size).
// The INDIRECT output is a new SSA version of the location that MAY have been
// modified by the call; input[0] is a fresh free varnode (renamed during Heritage
// to the pre-call SSA value); input[1] is an IOP annotation varnode referring
// back to callOp (see NewVarnodeIop) -- this is the cause-op reference that
// Heritage::renameRecurse's "INDIRECTs and their op happen AT SAME TIME" check
// decodes (heritage.cc:2506-2517; ported in heritage.go renameRecurse).
// Both input[0] and output are marked ActiveHeritage for renaming.
//
// C++ parity: Funcdata::newIndirectOp (funcdata_op.cc:683)
func (fd *Funcdata) NewIndirectOp(callOp *PcodeOp, sp *address.Space, off uint64, size int32) *PcodeOp {
	addr := address.Address{Space: sp, Offset: off}
	in0 := fd.NewVarnode(size, addr)
	in0.SetActiveHeritage()
	op := fd.NewOp(2, callOp.Addr())
	out := fd.NewVarnodeOut(size, addr, op)
	out.SetActiveHeritage()
	fd.OpSetOpcode(op, CPUI_INDIRECT)
	fd.OpSetInput(op, in0, 0)
	fd.OpSetInput(op, fd.NewVarnodeIop(callOp), 1) // cause ref (funcdata_op.cc:695)
	fd.OpInsertBefore(op, callOp)
	return op
}

// NewIndirectCreation builds an INDIRECT before indeffect whose output at
// addr is created by indeffect, with no prior value flowing through. When the
// output cannot be the call's return value the zero input is marked
// indirect_creation as well (Varnode::isIndirectZero).
// C++ parity: funcdata_op.cc Funcdata::newIndirectCreation.
func (fd *Funcdata) NewIndirectCreation(indeffect *PcodeOp, addr address.Address, sz int32, possibleout bool) *PcodeOp {
	newin := fd.NewConstant(sz, 0)
	op := fd.NewOp(2, indeffect.Addr())
	op.SetFlag(PcodeOpIndirectCreation)
	out := fd.NewVarnodeOut(sz, addr, op)
	if !possibleout {
		newin.SetFlags(VarnodeIndirectCreation)
	}
	out.SetFlags(VarnodeIndirectCreation)
	fd.OpSetOpcode(op, CPUI_INDIRECT)
	fd.OpSetInput(op, newin, 0)
	fd.OpSetInput(op, fd.NewVarnodeIop(indeffect), 1)
	fd.OpInsertBefore(op, indeffect)
	return op
}

// C++ parity: Funcdata::markIndirectCreation
func (fd *Funcdata) MarkIndirectCreation(indop *PcodeOp, possibleOutput bool) {
	if indop == nil {
		return
	}
	outvn := indop.Output()
	in0 := indop.Input(0)
	indop.SetFlag(PcodeOpIndirectCreation)
	if in0 == nil || !in0.IsConstant() {
		panic("Indirect creation not properly formed")
	}
	if !possibleOutput {
		in0.SetFlags(VarnodeIndirectCreation)
	}
	if outvn != nil {
		outvn.SetFlags(VarnodeIndirectCreation)
	}
}

// C++ parity: funcdata_varnode.cc Funcdata::transferVarnodeProperties
// TransferVarnodeProperties carries the consumed-bit mask (shifted to the
// piece) and the directwrite/addrforce flags from vn to a piece of it.
// C++ parity: Funcdata::transferVarnodeProperties.
func (fd *Funcdata) TransferVarnodeProperties(src, dst *Varnode, bytePos int32) {
	newConsume := ^uint64(0) // bits shifted in above the precision stay set
	if bytePos < 8 {
		fill := uint64(0)
		if bytePos != 0 {
			fill = newConsume << (8 * uint(8-bytePos))
		}
		newConsume = ((src.Consumed() >> (8 * uint(bytePos))) | fill) & maskForSize(dst.Size())
	}
	dst.SetFlags(src.flags & (VarnodeDirectWrite | VarnodeAddrForce))
	dst.SetConsumed(newConsume)
}

// VarnodesBySpace returns all varnodes in the given address space.
func (fd *Funcdata) VarnodesBySpace(spc *address.Space) []*Varnode {
	return fd.vbank.BySpace(spc)
}

// VarnodesByRange returns all varnodes overlapping [addr, addr+size).
func (fd *Funcdata) VarnodesByRange(addr address.Address, size int32) []*Varnode {
	return fd.vbank.LocRange(addr, size)
}

// ConstSpace returns the constant address space.
func (fd *Funcdata) ConstSpace() *address.Space {
	return fd.constSpace
}

// ---------------------------------------------------------------------------
// Action support helpers
// C++ parity: funcdata_op.cc, funcdata_varnode.cc, funcdata_block.cc
// ---------------------------------------------------------------------------

// OpUninsert moves an op from the alive list to the dead list and removes it
// from its parent basic block. Does NOT unlink varnodes.
// C++ parity: Funcdata::opUninsert (funcdata_op.cc:164)
func (fd *Funcdata) OpUninsert(op *PcodeOp) {
	fd.obank.MarkDead(op)
	if p := op.Parent(); p != nil {
		p.RemoveOp(op)
		op.SetParent(nil)
	}
}

// TotalReplace replaces all uses (descendants) of oldvn with newvn.
// C++ parity: Funcdata::totalReplace (funcdata_varnode.cc)
func (fd *Funcdata) TotalReplace(oldvn, newvn *Varnode) {
	// Snapshot the descend list since we mutate it during iteration.
	uses := oldvn.DescendIter()
	for _, useOp := range uses {
		slot := useOp.GetSlot(oldvn)
		if slot < 0 {
			continue
		}
		fd.OpUnsetInput(useOp, slot)
		fd.OpSetInput(useOp, newvn, slot)
	}
}

// ClearDeadOps destroys all ops on the dead list.
// C++ parity: Funcdata::clearDeadOps = obank.destroyDead() (funcdata.hh:429)
func (fd *Funcdata) ClearDeadOps() {
	dead := fd.obank.DeadOps()
	for _, op := range dead {
		fd.obank.Destroy(op)
	}
}

// StructureReset recalculates loop structure and dominance on the basic block
// graph, then clears the structured hierarchy so ActionBlockStructure restarts.
// C++ parity: Funcdata::structureReset (funcdata_block.cc:704)
func (fd *Funcdata) StructureReset() {
	bg := fd.GetBasicBlocks()
	if bg == nil {
		return
	}
	fd.ClearFlag(FuncBlocksUnreachable)
	if roots := bg.StructureLoops(); len(roots) > 1 {
		fd.SetFlag(FuncBlocksUnreachable)
	}
	// Drop jump-tables whose BRANCHIND died with its block.
	alive := fd.jumpTables[:0]
	for _, jt := range fd.jumpTables {
		if op := jt.IndirectOp(); op != nil && op.IsDead() {
			fd.warningHeader("Recovered jumptable eliminated as dead code")
			continue
		}
		alive = append(alive, jt)
	}
	fd.jumpTables = alive
	// Clear the sblocks (structured hierarchy) so it rebuilds from scratch.
	fd.SetStructureGraph(NewBlockGraph())
	// The dominator tree heritage keeps is stale once blocks changed.
	// C++ parity: Funcdata::structureReset -> heritage.forceRestructure().
	if fd.heritage != nil {
		fd.heritage.ForceRestructure()
	}
}

// PushBranch moves a control-flow edge from one block to another. It is used to
// eliminate a switch guard artifact: the guard's non-switch edge is turned from
// a conditional into an unconditional branch and re-pointed at the BRANCHIND
// block, which absorbs it as an additional (default) switch destination.
// C++ parity: Funcdata::pushBranch (funcdata_block.cc:403).
func (fd *Funcdata) PushBranch(bb *BlockBasic, slot int, bbnew *BlockBasic) {
	cbranch := bb.LastOp()
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH || bb.SizeOut() != 2 {
		// C++ throws LowlevelError; the callers (foldInOneGuard) already
		// verified sizeOut==2 and a CBRANCH tail, so this is defensive.
		return
	}
	indop := bbnew.LastOp()
	if indop == nil || indop.Code() != CPUI_BRANCHIND {
		return
	}
	// Turn the conditional branch into an unconditional branch.
	fd.OpRemoveInput(cbranch, 1) // Remove the conditional variable
	fd.OpSetOpcode(cbranch, CPUI_BRANCH)
	bg := fd.GetBasicBlocks()
	if bg != nil {
		bg.MoveOutEdge(&bb.FlowBlock, slot, &bbnew.FlowBlock)
	}
	// The indirect branch handles its new incoming edge implicitly.
	fd.StructureReset()
}

// NodeJoinCreateBlock creates a new basic block (joinblock) that merges two
// conditional blocks with identical branch targets (exita and exitb).
// One edge from each of block1/block2 to exita and exitb is removed, and the
// remaining edges are retargeted to the new joinblock. Then block1->joinblock
// and block2->joinblock edges are added.
// C++ parity: Funcdata::nodeJoinCreateBlock (funcdata_block.cc:779)
func (fd *Funcdata) NodeJoinCreateBlock(
	block1, block2, exita, exitb *BlockBasic,
	fora_block1ishigh, forb_block1ishigh bool,
	addr address.Address,
) *BlockBasic {
	bg := fd.GetBasicBlocks()
	if bg == nil {
		return nil
	}

	newblock := bg.NewBlockBasicInGraph()
	newblock.SetFlag(BlockFlagJoinedBlock)
	newblock.SetInitialRange(addr, addr)

	var swapa, swapb *FlowBlock

	// Remove one edge to exita and one to exitb depending on which block is "high".
	if fora_block1ishigh {
		bg.RemoveEdge(&block1.FlowBlock, &exita.FlowBlock)
		swapa = &block2.FlowBlock
	} else {
		bg.RemoveEdge(&block2.FlowBlock, &exita.FlowBlock)
		swapa = &block1.FlowBlock
	}
	if forb_block1ishigh {
		bg.RemoveEdge(&block1.FlowBlock, &exitb.FlowBlock)
		swapb = &block2.FlowBlock
	} else {
		bg.RemoveEdge(&block2.FlowBlock, &exitb.FlowBlock)
		swapb = &block1.FlowBlock
	}

	// Move remaining edges from swapa->exita and swapb->exitb to newblock.
	bg.MoveOutEdge(swapa, swapa.GetOutIndex(&exita.FlowBlock), &newblock.FlowBlock)
	bg.MoveOutEdge(swapb, swapb.GetOutIndex(&exitb.FlowBlock), &newblock.FlowBlock)

	// Add block1->newblock and block2->newblock.
	bg.AddEdge(&block1.FlowBlock, &newblock.FlowBlock, 0)
	bg.AddEdge(&block2.FlowBlock, &newblock.FlowBlock, 0)

	fd.StructureReset()
	return newblock
}

// NodeSplit splits control-flow into a basic block, duplicating its p-code into
// a new block. Control-flow is modified so the new block takes over flow from
// one input edge to the original block. Only blocks with no out-flow are
// supported (the RETURN-block case ActionReturnSplit needs).
// C++ parity: Funcdata::nodeSplit (funcdata_block.cc:845)
func (fd *Funcdata) NodeSplit(b *BlockBasic, inedge int) {
	if fd == nil || b == nil {
		return
	}
	bg := fd.GetBasicBlocks()
	if bg == nil {
		return
	}
	if inedge < 0 || inedge >= b.SizeIn() {
		return
	}
	// C++ throws on these; here they gate the same preconditions.
	if b.SizeOut() != 0 || b.SizeIn() <= 1 {
		return
	}
	// Reject redundant in-edges (two edges from the same source), which would
	// desync the MULTIEQUAL slot removal in patchInputs.
	// C++ parity: nodeSplit's isMark() redundancy check (funcdata_block.cc:852).
	for i := 0; i < b.SizeIn(); i++ {
		inbl := b.InEdge(i).Point
		if inbl == nil {
			continue
		}
		if inbl.HasFlag(BlockFlagMark) {
			for j := 0; j < b.SizeIn(); j++ {
				if p := b.InEdge(j).Point; p != nil {
					p.ClearFlag(BlockFlagMark)
				}
			}
			return
		}
		inbl.SetFlag(BlockFlagMark)
	}
	for i := 0; i < b.SizeIn(); i++ {
		if inbl := b.InEdge(i).Point; inbl != nil {
			inbl.ClearFlag(BlockFlagMark)
		}
	}

	// Create the duplicate block and move the one in-edge to it.
	bprime := fd.nodeSplitBlockEdge(b, inedge)
	// Copy b's ops into bprime with faithful SSA surgery.
	cloner := newCloneBlockOps(fd)
	cloner.cloneBlock(b, bprime, inedge)

	fd.StructureReset()
}

// nodeSplitBlockEdge splits b along the given in-edge: a duplicate block bprime
// is created that inherits the same out-edges but only the one indicated in-edge
// (removed from b). Data-flow is not touched here (cloneBlockOps does that).
// C++ parity: Funcdata::nodeSplitBlockEdge (funcdata_block.cc:824).
func (fd *Funcdata) nodeSplitBlockEdge(b *BlockBasic, inedge int) *BlockBasic {
	bg := fd.GetBasicBlocks()
	a := b.InEdge(inedge).Point

	bprime := bg.NewBlockBasicInGraph()
	bprime.SetFlag(BlockFlagDuplicateBlock)
	bprime.copyRange(b) // Index/numDesc are recomputed by the following structureReset

	// switchEdge(a, b, bprime): retarget a's out-edge(s) to b onto bprime,
	// preserving the out-edge slot on a (so a's true/false ordering is kept) and
	// sliding b's remaining in-edges down in order.
	// C++ parity: BlockGraph::switchEdge (block.cc:1489).
	for i := 0; i < a.SizeOut(); i++ {
		if a.OutEdge(i).Point == &b.FlowBlock {
			a.ReplaceOutEdge(i, &bprime.FlowBlock)
		}
	}
	// bprime inherits b's out-edges (none in the supported case).
	for i := 0; i < b.SizeOut(); i++ {
		outEdge := b.OutEdge(i)
		bg.AddEdge(&bprime.FlowBlock, outEdge.Point, outEdge.Label)
	}
	return bprime
}

// CseFindInBlock finds a duplicate of op in basic block bl that reads vn,
// occurring before earliest.
// C++ parity: Funcdata::cseFindInBlock (funcdata_op.cc:1326)
func (fd *Funcdata) CseFindInBlock(op *PcodeOp, vn *Varnode, bl *BlockBasic, earliest *PcodeOp) *PcodeOp {
	for _, res := range vn.DescendIter() {
		if res == op {
			continue
		}
		if res.Parent() != bl {
			continue
		}
		if earliest != nil && opBlockUIndex(earliest) <= opBlockUIndex(res) {
			continue
		}
		out1 := op.Output()
		out2 := res.Output()
		if out2 == nil {
			continue
		}
		var r1, r2 [2]*Varnode
		if functionalEqualityLevel(out1, out2, r1[:], r2[:]) == 0 {
			return res
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Jump table accessors
// ---------------------------------------------------------------------------

// JumpTables returns the slice of recovered jump tables for this function.
// C++ parity: funcdata.hh Funcdata::numJumpTables / getJumpTable
func (fd *Funcdata) JumpTables() []*JumpTable {
	if fd == nil {
		return nil
	}
	return fd.jumpTables
}

// NumJumpTables returns the number of recovered jump tables.
// C++ parity: funcdata.hh Funcdata::numJumpTables
func (fd *Funcdata) NumJumpTables() int {
	if fd == nil {
		return 0
	}
	return len(fd.jumpTables)
}

// GetJumpTable returns the i-th jump table (or nil for out-of-range indices).
// C++ parity: funcdata.hh Funcdata::getJumpTable
func (fd *Funcdata) GetJumpTable(i int) *JumpTable {
	if fd == nil || i < 0 || i >= len(fd.jumpTables) {
		return nil
	}
	return fd.jumpTables[i]
}

// AddJumpTable appends jt to the function's jump table list.
// C++ parity: funcdata.hh Funcdata::installJumpTable (partial)
func (fd *Funcdata) AddJumpTable(jt *JumpTable) {
	if fd == nil || jt == nil {
		return
	}
	fd.jumpTables = append(fd.jumpTables, jt)
}

// FindJumpTable locates a jump table by the BRANCHIND PcodeOp it models.
// C++ parity: funcdata.hh Funcdata::findJumpTable
func (fd *Funcdata) FindJumpTable(op *PcodeOp) *JumpTable {
	if fd == nil || op == nil {
		return nil
	}
	for _, jt := range fd.jumpTables {
		if jt.IndirectOp() == op {
			return jt
		}
	}
	return nil
}

// ClearJumpTables drops all jump tables (used during full reprocessing).
// C++ parity: funcdata.cc Funcdata::clearJumpTables
func (fd *Funcdata) ClearJumpTables() {
	if fd == nil {
		return
	}
	fd.jumpTables = nil
}

// ---------------------------------------------------------------------------
// Type factory / user-op registry wiring
// C++ parity: Architecture glb->types / glb->userops (userop.hh, architecture.hh)
// ---------------------------------------------------------------------------

// TypeFactory returns the type factory for this function: the architecture's
// one factory, so a data-type built here is identical to the same data-type
// built anywhere else. C++ parity: Funcdata::glb->types.
func (fd *Funcdata) TypeFactory() *TypeFactory {
	if fd.typeFactory == nil {
		return sharedTypeFactory
	}
	return fd.typeFactory
}

// SetTypeFactory attaches an externally-built type factory, used when a host
// architecture pre-populates the core types.
func (fd *Funcdata) SetTypeFactory(tf *TypeFactory) { fd.typeFactory = tf }

// UserOps returns the lazily-constructed user-op manager for this function.
// C++ parity: Funcdata::glb->userops.
func (fd *Funcdata) UserOps() *UserOpManage {
	if fd.userOps == nil {
		fd.userOps = NewUserOpManage()
		// The default data space is the function's own (ram) space.
		if spc := fd.BaseAddr().Space; spc != nil && spc.AddrSize > 0 {
			fd.userOps.ptrSize = int32(spc.AddrSize)
			if spc.WordSize > 0 {
				fd.userOps.wordSize = uint32(spc.WordSize)
			}
		}
	}
	return fd.userOps
}

// SetUserOps attaches an externally-built user-op registry.
func (fd *Funcdata) SetUserOps(m *UserOpManage) { fd.userOps = m }

// GetInternalString stores the given string payload as a synthetic constant
// reachable through a BUILTIN_STRINGDATA CALLOTHER and returns a unique-space
// Varnode holding the encoded address. readOp is the op that will consume
// the returned Varnode -- the synthesized CALLOTHER is inserted immediately
// before it so the payload definition dominates every use.
// C++ parity: Funcdata::getInternalString (funcdata_varnode.cc ~L1432).
// TODO mismatch: the C++ path routes the payload through
// stringManager->registerInternalStringData and calls resVn->updateType. The
// Go Varnode does not yet carry a Datatype field, so updateType is omitted
// and the payload is held on the Funcdata itself keyed by FNV-1a hash.
func (fd *Funcdata) GetInternalString(buf []byte, ptrType Datatype, readOp *PcodeOp) *Varnode {
	if ptrType == nil || readOp == nil {
		return nil
	}
	if ptrType.Metatype() != TYPE_PTR {
		return nil
	}
	ptr, ok := ptrType.(*Pointer)
	if !ok {
		return nil
	}
	charType := ptr.Pointee()
	if checkCharacters(buf, int(charType.Size()), readOp.Addr().Space != nil && readOp.Addr().Space.BigEndian) < 0 {
		return nil // Not a legal encoding
	}
	hash := hashInternalString(readOp.Addr(), buf, charType)
	if hash == 0 {
		return nil
	}
	if fd.internalStrings == nil {
		fd.internalStrings = make(map[uint64]internalStringEntry)
	}
	payload := make([]byte, len(buf))
	copy(payload, buf)
	fd.internalStrings[hash] = internalStringEntry{
		addr:     readOp.Addr(),
		data:     payload,
		charType: charType,
	}
	fd.UserOps().RegisterBuiltin(BUILTIN_STRINGDATA, fd.TypeFactory())

	stringOp := fd.NewOp(2, readOp.Addr())
	fd.OpSetOpcode(stringOp, CPUI_CALLOTHER)
	stringOp.ClearFlag(PcodeOpCall)
	fd.OpSetInput(stringOp, fd.NewConstant(4, uint64(BUILTIN_STRINGDATA)), 0)
	fd.OpSetInput(stringOp, fd.NewConstant(8, hash), 1)
	resVn := fd.NewUniqueOut(ptrType.Size(), stringOp)
	resVn.UpdateTypeLock(ptrType, true, false)
	fd.OpInsertBefore(stringOp, readOp)
	return resVn
}

// InternalStringData returns the raw bytes and element type registered for a
// BUILTIN_STRINGDATA hash, or (nil, nil, false) if nothing was registered.
// Helper for printc and downstream rule code that must recover the payload.
func (fd *Funcdata) InternalStringData(hash uint64) ([]byte, Datatype, bool) {
	if fd == nil || fd.internalStrings == nil {
		return nil, nil, false
	}
	entry, ok := fd.internalStrings[hash]
	if !ok {
		return nil, nil, false
	}
	out := make([]byte, len(entry.data))
	copy(out, entry.data)
	return out, entry.charType, true
}

// hashInternalString produces the payload key used by GetInternalString.
// C++ parity: StringManager::registerInternalStringData uses a running hash
// over (address, bytes, element type id). The exact hashing scheme is not
// observable outside the decompiler, so the Go port uses FNV-1a over the
// same inputs -- any stable hash is sufficient as long as the Funcdata
// registers and recovers the payload with the same function.
func hashInternalString(addr address.Address, buf []byte, charType Datatype) uint64 {
	h := fnv.New64a()
	if addr.Space != nil {
		h.Write([]byte(addr.Space.Name))
	}
	var off [8]byte
	for i := 0; i < 8; i++ {
		off[i] = byte(addr.Offset >> (8 * i))
	}
	h.Write(off[:])
	h.Write(buf)
	if charType != nil {
		var id [8]byte
		cid := charType.ID()
		for i := 0; i < 8; i++ {
			id[i] = byte(cid >> (8 * i))
		}
		h.Write(id[:])
	}
	sum := h.Sum64()
	if sum == 0 {
		sum = 1 // reserve 0 as the failure sentinel
	}
	return sum
}

// SetRegisterNames installs the location-to-register-name map.
func (fd *Funcdata) SetRegisterNames(names map[string]string) { fd.registerNames = names }

// registerName returns the register name at (addr, size), or "".
// C++ parity: Translate::getRegisterName.
func (fd *Funcdata) registerName(vn *Varnode) string {
	if vn.Space() == nil {
		return ""
	}
	return fd.registerNames[fmt.Sprintf("%d:%d:%d", vn.Space().Index, vn.Offset(), vn.Size())]
}

// addIndirectOverride records a resolved indirect call and requests a rebuild.
func (fd *Funcdata) addIndirectOverride(at uint64, target address.Address) {
	if fd.indirectOverrides == nil {
		fd.indirectOverrides = make(map[uint64]address.Address)
	}
	if _, ok := fd.indirectOverrides[at]; ok {
		return
	}
	fd.indirectOverrides[at] = target
	fd.rebuildRequested = true
}

// addMultistageJump marks the BRANCHIND at off as needing a second recovery
// stage and requests a restart.
// C++ parity: Override::insertMultistageJump + Funcdata::setRestartPending.
func (fd *Funcdata) addMultistageJump(off uint64) {
	if fd.multistageJumps == nil {
		fd.multistageJumps = make(map[uint64]bool)
	}
	fd.multistageJumps[off] = true
	fd.rebuildRequested = true
}

// MultistageJumps returns the BRANCHINDs marked for a second recovery stage.
func (fd *Funcdata) MultistageJumps() map[uint64]bool { return fd.multistageJumps }

// SetMultistageJumps seeds the multistage marks a rebuilt function inherits.
func (fd *Funcdata) SetMultistageJumps(m map[uint64]bool) { fd.multistageJumps = m }

// SetIndirectOverrides seeds the overrides a rebuilt function inherits.
func (fd *Funcdata) SetIndirectOverrides(ov map[uint64]address.Address) {
	fd.indirectOverrides = ov
}

// IndirectOverrides returns the indirect-call overrides recorded so far.
func (fd *Funcdata) IndirectOverrides() map[uint64]address.Address { return fd.indirectOverrides }

// SetProtoOverrides installs the call-site prototypes a restart keeps.
func (fd *Funcdata) SetProtoOverrides(po map[uint64]*HostFunction) { fd.protoOverrides = po }

// ProtoOverrides returns the call-site prototypes forced so far.
func (fd *Funcdata) ProtoOverrides() map[uint64]*HostFunction { return fd.protoOverrides }

// RebuildRequested reports whether a new indirect override needs a restart.
func (fd *Funcdata) RebuildRequested() bool { return fd.rebuildRequested }

// issueDatatypeWarnings adds the type warnings collected while decoding the
// host's data-types to the function header.
// C++ parity: Funcdata::issueDatatypeWarnings.
func (fd *Funcdata) issueDatatypeWarnings() {
	if h, ok := fd.hostScope.(HostTypeWarnings); ok {
		for _, w := range h.DatatypeWarnings() {
			fd.warningHeader(w)
		}
	}
}
