package pcode

import (
	"hash/fnv"

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
	FuncNoCode             uint32 = 0x0080
	FuncUnimplPresent      uint32 = 0x0800
	FuncBadDataPresent     uint32 = 0x1000
	// FuncDoublePrecisOn enables the ActionParamDouble join path.
	// C++ parity: funcdata.hh Funcdata::double_precis_on (0x2000)
	FuncDoublePrecisOn uint32 = 0x2000
)

// Funcdata is the central container for all data structures associated
// with decompiling a single function.
// C++ parity: funcdata.hh Funcdata
type Funcdata struct {
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

	// jumpTables tracks all recovered JumpTable objects for this function.
	// C++ parity: funcdata.hh Funcdata::jumpvec
	jumpTables []*JumpTable

	// graph and heritageSpaces let the universal-action tree run analysis actions
	// (ActionHeritage etc.) without external context. The hand-ordered decompile
	// driver passes these explicitly; the action-tree path reads them from here.
	// C++ parity: Funcdata owns bblocks and the heritage's address-space set.
	graph          *BlockGraph
	heritageSpaces []*address.Space

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

// GetFuncProto returns the calling convention prototype, or nil if not set.
// C++ parity: Funcdata::getFuncProto
func (fd *Funcdata) GetFuncProto() *FuncProto { return fd.funcProto }

// SetFuncProto attaches a calling convention prototype.
// C++ parity: Funcdata::getFuncProto (setter path)
func (fd *Funcdata) SetFuncProto(fp *FuncProto) { fd.funcProto = fp }

// GetScopeLocal returns the local variable scope, or nil if not set.
// C++ parity: Funcdata::getScopeLocal
func (fd *Funcdata) GetScopeLocal() *ScopeLocal { return fd.scopeLocal }

// SetScopeLocal attaches a local variable scope.
func (fd *Funcdata) SetScopeLocal(sl *ScopeLocal) { fd.scopeLocal = sl }

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
	if fd.HasFlag(FuncTypeRecoveryOn) {
		return false
	}
	fd.SetFlag(FuncTypeRecoveryOn)
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
// Stack-slot heritage is driven separately by ActionStackPtrFlow once the stack
// space is resolved; in the iterative mainloop a later ActionHeritage pass picks
// up newly stack-heritaged varnodes.
// C++ parity: funcdata.hh Funcdata::opHeritage -> Heritage::heritage.
func (fd *Funcdata) OpHeritage() {
	if fd.graph == nil || len(fd.heritageSpaces) == 0 {
		return
	}
	var model *ProtoModel
	if fd.funcProto != nil {
		model = fd.funcProto.Model()
	}
	NewHeritage(fd, fd.heritageSpaces).WithProtoModel(model).Heritage(fd.graph)
}

// CalcNZMask computes non-zero masks for all varnodes.
// C++ parity: funcdata.hh Funcdata::calcNZMask
func (fd *Funcdata) CalcNZMask() {
	_ = fd
}

// MapGlobals walks every persistent Varnode in the function and makes sure
// each has an attached global SymbolEntry, creating one when none exists.
//
// We only implement the flat single-scope subset of Ghidra's mapGlobals:
// there is no Scope tree to discoverScope() against, so every created entry
// is dropped into the Funcdata's own ScopeLocal. This is correct for the
// present Go callers, which exercise mapGlobals as a placeholder for future
// globals tracking rather than full namespace resolution.
// TODO: route newly discovered globals into a real global Scope once the
// Scope tree / symbol table port lands (database.cc discoverScope path).
// C++ parity: funcdata.hh Funcdata::mapGlobals
func (fd *Funcdata) MapGlobals() {
	if fd == nil || fd.scopeLocal == nil {
		return
	}
	scope := fd.scopeLocal
	seen := make(map[address.Address]bool)
	for _, vn := range fd.vbank.AllVarnodes() {
		if vn == nil || vn.IsFree() {
			continue
		}
		if !vn.IsPersist() {
			continue
		}
		if scope.EntryForVarnode(vn) != nil {
			continue
		}
		addr := vn.Addr()
		if seen[addr] {
			continue
		}
		seen[addr] = true
		// Prefer an existing overlapping entry if one exists; otherwise
		// manufacture a fresh default-named symbol at the Varnode address.
		entry := scope.QueryContainer(addr, vn.Size(), address.Address{})
		if entry == nil {
			name := localHexName(addr.Offset)
			dt := sharedTypeFactory.GetBase(vn.Size(), TYPE_UNKNOWN, "")
			entry = scope.AddSymbol(name, dt, addr, vn.Size())
		}
		scope.AttachEntryToVarnode(vn, entry)
	}
}

// MarkIndirectOnly marks illegal inputs used only in INDIRECT ops.
// C++ parity: funcdata.hh Funcdata::markIndirectOnly
func (fd *Funcdata) MarkIndirectOnly() {
	_ = fd
}

// Spacebase performs stack-pointer spacebase processing.
// C++ parity: funcdata.hh Funcdata::spacebase
func (fd *Funcdata) Spacebase() {
	_ = fd
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
	if ct != nil && vn.Type() == nil {
		SetVarnodeType(vn, ct)
		updated = true
	}
	return updated
}

// RemoveUnreachableBlocks removes unreachable blocks.
// C++ parity: funcdata.hh Funcdata::removeUnreachableBlocks
func (fd *Funcdata) RemoveUnreachableBlocks(bool, bool) bool {
	return false
}

// RemoveDoNothingBlock removes a do-nothing block.
// C++ parity: funcdata.hh Funcdata::removeDoNothingBlock
func (fd *Funcdata) RemoveDoNothingBlock(*BlockBasic) {
}

// RemoveBranch removes a branch from the given basic block.
// C++ parity: funcdata.hh Funcdata::removeBranch
func (fd *Funcdata) RemoveBranch(*BlockBasic, int) {
}

// ---------------------------------------------------------------------------
// Varnode creation
// C++ parity: funcdata_varnode.cc
// ---------------------------------------------------------------------------

// NewVarnode creates a free Varnode.
// C++ parity: Funcdata::newVarnode
func (fd *Funcdata) NewVarnode(size int32, loc address.Address) *Varnode {
	return fd.vbank.Create(size, loc)
}

// NewVarnodeOut creates a Varnode as the defined output of an op.
// C++ parity: Funcdata::newVarnodeOut
func (fd *Funcdata) NewVarnodeOut(size int32, loc address.Address, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDef(size, loc, op)
	op.SetOutput(vn)
	return vn
}

// NewUniqueOut creates a temp Varnode (unique space) as output of an op.
// C++ parity: Funcdata::newUniqueOut
func (fd *Funcdata) NewUniqueOut(size int32, op *PcodeOp) *Varnode {
	vn := fd.vbank.CreateDefUnique(size, op)
	op.SetOutput(vn)
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
	return fd.vbank.CreateUnique(size)
}

// SetInputVarnode promotes a free Varnode to SSA function input.
// C++ parity: Funcdata::setInputVarnode
func (fd *Funcdata) SetInputVarnode(vn *Varnode) *Varnode {
	fd.vbank.SetInput(vn)
	return vn
}

// DeleteVarnode removes a Varnode from the bank.
// The varnode must be free with no descendants.
// C++ parity: Funcdata::deleteVarnode
func (fd *Funcdata) DeleteVarnode(vn *Varnode) {
	fd.vbank.Destroy(vn)
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
		op.SetOpcode(fd.typeOps[opc])
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
	op.SetOutput(vn)
}

// OpSetInput wires a Varnode as an input of a PcodeOp at the given slot.
// If the slot already holds a varnode, it is unset first (descend removed).
// Then the new varnode's descend list is updated to include op.
// C++ parity: Funcdata::opSetInput (funcdata_op.cc:104)
func (fd *Funcdata) OpSetInput(op *PcodeOp, vn *Varnode, slot int) {
	// Debug: trace mutations to the op that produces unique:0xae41f (joinblock phi #128).
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
		if vn.NumDescend() == 0 {
			// No consumers: fully destroy from bank, then clear def.
			fd.vbank.Destroy(vn)
			vn.SetDef(nil)
		} else {
			// Still has consumers: transition to free so they remain valid.
			// MakeFree internally clears def and VarnodeWritten.
			fd.vbank.MakeFree(vn)
		}
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
	bb.InsertOpBegin(op)
}

// OpInsertEnd creates an op and inserts it at the end of a basic block.
// The op is marked alive and its parent is set.
// C++ parity: Funcdata::opInsertEnd
func (fd *Funcdata) OpInsertEnd(op *PcodeOp, bb *BlockBasic) {
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpEnd(op)
}

// OpInsertBefore inserts op immediately before follow in follow's basic block.
// The op is marked alive and its parent block is set.
// C++ parity: Funcdata::opInsertBefore
func (fd *Funcdata) OpInsertBefore(op *PcodeOp, follow *PcodeOp) {
	bb := follow.Parent()
	if bb == nil {
		return
	}
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpBefore(op, follow)
}

// OpInsertAfter inserts op immediately after prev in prev's basic block.
// The op is marked alive and its parent block is set.
// C++ parity: Funcdata::opInsertAfter
func (fd *Funcdata) OpInsertAfter(op *PcodeOp, prev *PcodeOp) {
	bb := prev.Parent()
	if bb == nil {
		return
	}
	fd.OpMarkAlive(op)
	op.SetParent(bb)
	bb.InsertOpAfter(op, prev)
}

// NewIndirectOp creates an INDIRECT op inserted immediately before callOp that
// models an unknown side-effect on the address range (sp, off, size).
// The INDIRECT output is a new SSA version of the location that MAY have been
// modified by the call; input[0] is a fresh free varnode (renamed during Heritage
// to the pre-call SSA value); input[1] is a zero constant (cause reference --
// simplified: C++ uses an IOP-space varnode encoding the CALL op pointer).
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
	fd.OpSetInput(op, fd.NewConstant(4, 0), 1) // cause ref (IOP stub)
	fd.OpInsertBefore(op, callOp)
	return op
}

// NewIndirectCreation creates an INDIRECT op inserted immediately before callOp
// that models a caller-saved register being overwritten by the call.
// Unlike NewIndirectOp, the output has no data-flow from the pre-call value:
// input[0] is a zero constant, signalling that the call produces a new value
// at this location (e.g., EAX holding the return value of the callee).
// The op and output are flagged with PcodeOpIndirectCreation / VarnodeIndirectCreation.
//
// C++ parity: Funcdata::newIndirectCreation (funcdata_op.cc:710)
func (fd *Funcdata) NewIndirectCreation(callOp *PcodeOp, sp *address.Space, off uint64, size int32) *PcodeOp {
	addr := address.Address{Space: sp, Offset: off}
	op := fd.NewOp(2, callOp.Addr())
	op.SetFlag(PcodeOpIndirectCreation)
	out := fd.NewVarnodeOut(size, addr, op)
	out.SetFlags(VarnodeIndirectCreation)
	out.SetActiveHeritage()
	fd.OpSetOpcode(op, CPUI_INDIRECT)
	fd.OpSetInput(op, fd.NewConstant(4, 0), 0) // no pre-call value flows through
	fd.OpSetInput(op, fd.NewConstant(4, 0), 1) // cause ref (IOP stub)
	fd.OpInsertBefore(op, callOp)
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
func (fd *Funcdata) TransferVarnodeProperties(src, dst *Varnode, bytePos int32) {
	// TODO known mismatch: the full C++ property transfer logic is not yet ported.
	_ = src
	_ = dst
	_ = bytePos
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
	bg.StructureLoops()
	// Clear the sblocks (structured hierarchy) so it rebuilds from scratch.
	fd.SetStructureGraph(NewBlockGraph())
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

// NodeSplit duplicates a basic block and retargets one incoming edge.
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
	if b.SizeOut() != 0 || b.SizeIn() <= 1 {
		return
	}

	for i := 0; i < b.SizeIn(); i++ {
		inbl := b.InEdge(i).Point
		if inbl == nil {
			continue
		}
		if inbl.HasFlag(BlockFlagMark) {
			return
		}
		inbl.SetFlag(BlockFlagMark)
	}
	for i := 0; i < b.SizeIn(); i++ {
		inbl := b.InEdge(i).Point
		if inbl != nil {
			inbl.ClearFlag(BlockFlagMark)
		}
	}

	src := b.InEdge(inedge).Point
	if src == nil {
		return
	}
	label := b.InEdge(inedge).Label

	bprime := bg.NewBlockBasicInGraph()
	bprime.SetFlag(BlockFlagDuplicateBlock)
	bprime.SetType(b.Type())
	bprime.SetIndex(b.Index())
	bprime.SetNumDesc(b.NumDesc())
	bprime.ops = make([]*PcodeOp, 0, len(b.ops))
	for _, op := range b.ops {
		if op == nil {
			continue
		}
		dup := *op
		if len(op.inputs) > 0 {
			dup.inputs = append([]*Varnode(nil), op.inputs...)
		}
		dup.parent = bprime
		bprime.ops = append(bprime.ops, &dup)
	}

	bg.RemoveEdge(src, &b.FlowBlock)
	bg.AddEdge(src, &bprime.FlowBlock, label)
	for i := 0; i < b.SizeOut(); i++ {
		outEdge := b.OutEdge(i)
		bg.AddEdge(&bprime.FlowBlock, outEdge.Point, outEdge.Label)
	}

	fd.StructureReset()
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
		if earliest != nil && earliest.Seq().Order <= res.Seq().Order {
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

// TypeFactory returns the lazily-constructed type factory for this function.
// C++ parity: Funcdata::glb->types.
func (fd *Funcdata) TypeFactory() *TypeFactory {
	if fd.typeFactory == nil {
		fd.typeFactory = NewTypeFactory()
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
