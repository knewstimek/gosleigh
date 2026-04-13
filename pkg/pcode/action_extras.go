// Copyright 2026 The Gosleigh Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import "gosleigh/pkg/address"

// This file collects the small helpers that Actions upgraded from A1
// scaffold to A15 REAL depend on. The helpers are deliberately kept on
// top of the already-ported data structures so that the seven upgraded
// Actions can exercise real control-flow even in the (common) case where
// the underlying C++ state is empty. When the richer C++ pipes land, the
// individual helper bodies get replaced, not the Action call-sites.

// -----------------------------------------------------------------------------
// FuncCallSpecs extensions (fspec.hh / fspec.cc subset)
// -----------------------------------------------------------------------------

// IsDotdotdot reports whether the call-site has varargs tail parameters.
// C++ parity: FuncCallSpecs::isDotdotdot (via FuncProto::isDotdotdot)
// TODO known mismatch: dotdotdot flag is not yet tracked separately from the
// prototype model; we conservatively return false until FuncProto grows the
// flag as part of the full fspec port.
func (fc *FuncCallSpecs) IsDotdotdot() bool {
	if fc == nil {
		return false
	}
	return false
}

// GetSpacebase returns the stack space associated with the caller's frame.
// When this is non-nil the funclink input path will allocate a stackplaceholder.
// C++ parity: FuncCallSpecs::getSpacebase
func (fc *FuncCallSpecs) GetSpacebase() *address.Space {
	if fc == nil || fc.FuncProto.model == nil {
		return nil
	}
	return fc.FuncProto.model.StackSpace
}

// IsInputActive reports whether the input side is still in active recovery.
// C++ parity: FuncCallSpecs::isInputActive
// TODO known mismatch: active-input state lives on the (unported) ParamActive
// pipeline. Until that lands we treat unlocked calls as "not active" so the
// upgraded ActionParamDouble skips them in the outer walk.
func (fc *FuncCallSpecs) IsInputActive() bool {
	if fc == nil {
		return false
	}
	return fc.getActiveInputState() != nil
}

// GetActiveInput returns the temporary active-input trial container, if any.
// C++ parity: FuncCallSpecs::getActiveInput
func (fc *FuncCallSpecs) GetActiveInput() *ParamActive {
	if fc == nil {
		return nil
	}
	return fc.getActiveInputState()
}

// InitActiveInput sets up an empty ParamActive so inputs can be recovered.
// C++ parity: FuncCallSpecs::initActiveInput
func (fc *FuncCallSpecs) InitActiveInput() {
	if fc == nil {
		return
	}
	if fc.getActiveInputState() == nil {
		fc.setActiveInputState(NewParamActive(false))
	}
}

// InitActiveOutput sets up an empty ParamActive for return-value recovery.
// C++ parity: FuncCallSpecs::initActiveOutput
func (fc *FuncCallSpecs) InitActiveOutput() {
	if fc == nil {
		return
	}
	fc.FuncProto.SetActiveOutput(NewParamActive(false))
}

// CreatePlaceholder records that the stack pointer must be tracked through
// the call. The full C++ path inserts a synthetic INDIRECT so that Heritage
// keeps the pre-call SP version visible. For the Go port we mark the call
// op but leave the INDIRECT synthesis to the existing ActionFuncLinkOutOnly
// pipeline.
// C++ parity: FuncCallSpecs::createPlaceholder
// TODO known mismatch: INDIRECT insertion for stack-pointer tracking is not
// performed here; the upgraded ActionFuncLink preserves the call-site
// classification but the INDIRECT synthesis awaits the full fspec port.
func (fc *FuncCallSpecs) CreatePlaceholder(_ *Funcdata, _ *address.Space) {
	// Intentionally a no-op until the fspec placeholder path lands.
}

// Deindirect converts a CALLIND op into a direct CALL whose target is newfd.
// C++ parity: FuncCallSpecs::deindirect
// TODO known mismatch: the full C++ routine rewires data flow, updates the
// ParamList, and installs the callee's prototype. The Go port performs the
// opcode rewrite and drops the indirect target but does not yet port the
// prototype transfer -- callers must rely on ActionPrototypeTypes for that.
func (fc *FuncCallSpecs) Deindirect(data *Funcdata, newfd *Funcdata) {
	if fc == nil || data == nil || fc.op == nil {
		return
	}
	op := fc.op
	if op.Code() != CPUI_CALLIND {
		return
	}
	data.OpSetOpcode(op, CPUI_CALL)
	// Collapse input(0) to a zero constant of the same size: the old target
	// varnode is no longer load-bearing because the opcode is now direct.
	if in0 := op.Input(0); in0 != nil {
		zero := data.NewConstant(in0.Size(), 0)
		data.OpSetInput(op, zero, 0)
	}
	fc.fd = newfd
}

// ForceSet overwrites the per-call prototype with the one attached to a
// function-pointer datatype.
// C++ parity: FuncCallSpecs::forceSet
func (fc *FuncCallSpecs) ForceSet(_ *Funcdata, proto FuncProto) {
	if fc == nil {
		return
	}
	fc.FuncProto.Copy(&proto)
}

// CheckInputSplit reports whether the ABI permits splitting a CONCAT piece
// parameter into two consecutive trials.
// C++ parity: FuncCallSpecs::checkInputSplit -> FuncProto::checkInputSplit
// -> ParamListStandard::checkSplit (fspec.cc:1342).
//
// The C++ routine asks the ParamList to resolve both halves against its
// ParamEntry table; both halves must map to legal input entries. Gosleigh
// does not yet port ParamEntry, so we run the closest available query:
// for stack-space splits we require both halves to fall in the parameter
// area and respect the ProtoModel's ParamAlign. For register-space splits
// we answer false -- the full ParamEntry port will replace that branch.
func (fc *FuncCallSpecs) CheckInputSplit(loc address.Address, size int32, splitpoint int32) bool {
	if fc == nil || fc.FuncProto.model == nil {
		return false
	}
	if size <= 0 || splitpoint <= 0 || splitpoint >= size {
		return false
	}
	if loc.Space == nil || loc.Space.Kind != address.SpaceKindStack {
		// TODO known mismatch: register-space splits need ParamEntry.findEntry.
		return false
	}
	model := fc.FuncProto.model
	align := uint64(model.ParamAlign)
	if align == 0 {
		align = 1
	}
	// Lo piece is at loc, Hi piece is at loc + splitpoint (in byte units --
	// stack space has WordSize 1). Both halves must fit inside the parameter
	// area and start on a ParamAlign boundary.
	base := uint64(0)
	if model.ParamBaseOffset > 0 {
		base = uint64(model.ParamBaseOffset)
	}
	off1 := loc.Offset
	off2 := loc.Offset + uint64(splitpoint)
	if !model.IsParamOffset(off1) || !model.IsParamOffset(off2) {
		return false
	}
	if off1 < base || off2 < base {
		return false
	}
	if ((off1 - base) % align) != 0 {
		return false
	}
	if ((off2 - base) % align) != 0 {
		return false
	}
	return true
}

// CheckInputJoin reports whether two adjacent input slots can be merged into
// a double-precision whole parameter.
// C++ parity: FuncCallSpecs::checkInputJoin (fspec.cc:5349) ->
// FuncProto::checkInputJoin -> ParamListStandard::checkJoin (fspec.cc:1315).
//
// The Go port mirrors the C++ preflight: reject when the call is still
// classifying its inputs, require the ishislot flag to match the slot order,
// and require the declared trial sizes to match the varnode sizes at that
// slot. After that we defer to the same stack-vs-register discrimination as
// CheckInputSplit: stack halves must be contiguous and ParamAlign-aligned;
// register-space halves get a TODO.
func (fc *FuncCallSpecs) CheckInputJoin(slot1 int, ishislot bool, vn1 *Varnode, vn2 *Varnode) bool {
	if fc == nil || vn1 == nil || vn2 == nil || fc.FuncProto.model == nil {
		return false
	}
	// C++ returns false when input recovery is still active; coreaction.cc
	// only calls this from the !isInputActive branch so the guard normally
	// short-circuits false when the call-site has an in-flight ParamActive.
	if fc.IsInputActive() {
		return false
	}
	active := fc.getActiveInputState()
	if active == nil {
		return false
	}
	if slot1 < 0 || slot1+1 >= active.NumTrials() {
		return false
	}
	var hislot, loslot *ParamTrial
	if ishislot {
		hislot = active.TrialForInputVarnode(slot1)
		loslot = active.TrialForInputVarnode(slot1 + 1)
		if hislot == nil || loslot == nil {
			return false
		}
		if hislot.GetSize() != vn1.Size() || loslot.GetSize() != vn2.Size() {
			return false
		}
	} else {
		loslot = active.TrialForInputVarnode(slot1)
		hislot = active.TrialForInputVarnode(slot1 + 1)
		if hislot == nil || loslot == nil {
			return false
		}
		if loslot.GetSize() != vn1.Size() || hislot.GetSize() != vn2.Size() {
			return false
		}
	}
	hiaddr := hislot.GetAddress()
	hisize := hislot.GetSize()
	loaddr := loslot.GetAddress()
	losize := loslot.GetSize()
	return checkParamJoin(fc.FuncProto.model, hiaddr, hisize, loaddr, losize)
}

// checkParamJoin is the stack-space approximation of
// ParamListStandard::checkJoin used by CheckInputJoin.
// C++ parity: fspec.cc ParamListStandard::checkJoin (stack branch only).
func checkParamJoin(model *ProtoModel, hiaddr address.Address, hisize int32, loaddr address.Address, losize int32) bool {
	if model == nil {
		return false
	}
	if hisize <= 0 || losize <= 0 {
		return false
	}
	if hiaddr.Space == nil || loaddr.Space == nil {
		return false
	}
	if hiaddr.Space != loaddr.Space {
		return false
	}
	if hiaddr.Space.Kind != address.SpaceKindStack {
		// TODO known mismatch: register-space joins need ParamEntry.findEntry.
		return false
	}
	// Contiguity check. Endianness of the stack space decides which piece is
	// at the lower address.
	var lowAddr, highAddr address.Address
	var lowSize int32
	if hiaddr.Space.BigEndian {
		lowAddr = hiaddr
		lowSize = hisize
		highAddr = loaddr
	} else {
		lowAddr = loaddr
		lowSize = losize
		highAddr = hiaddr
	}
	if lowAddr.Offset+uint64(lowSize) != highAddr.Offset {
		return false
	}
	if !model.IsParamOffset(hiaddr.Offset) || !model.IsParamOffset(loaddr.Offset) {
		return false
	}
	align := uint64(model.ParamAlign)
	if align == 0 {
		align = 1
	}
	base := uint64(0)
	if model.ParamBaseOffset > 0 {
		base = uint64(model.ParamBaseOffset)
	}
	if hiaddr.Offset < base || loaddr.Offset < base {
		return false
	}
	if ((hiaddr.Offset - base) % align) != 0 {
		return false
	}
	if ((loaddr.Offset - base) % align) != 0 {
		return false
	}
	return true
}

// DoInputJoin records a successful input-join so later analysis passes pick
// up the merged varnode.
// C++ parity: FuncCallSpecs::doInputJoin (fspec.cc:5376). The C++ routine
// builds a join-space address via Architecture::constructJoinAddress before
// calling ParamActive::joinTrial. Gosleigh does not yet expose a join space,
// so we collapse the two trials at the low-address piece which preserves the
// slot mapping even though the synthetic address is not join-space.
// TODO known mismatch: join-space addresses are not synthesized; downstream
// code that inspects the joined trial's GetAddress() sees the low piece.
func (fc *FuncCallSpecs) DoInputJoin(slot1 int, ishislot bool) {
	if fc == nil {
		return
	}
	if fc.IsInputLocked() {
		return
	}
	active := fc.getActiveInputState()
	if active == nil {
		return
	}
	if slot1 < 0 || slot1+1 >= active.NumTrials() {
		return
	}
	trial1 := active.TrialForInputVarnode(slot1)
	trial2 := active.TrialForInputVarnode(slot1 + 1)
	if trial1 == nil || trial2 == nil {
		return
	}
	addr1 := trial1.GetAddress()
	addr2 := trial2.GetAddress()
	totalsz := trial1.GetSize() + trial2.GetSize()
	// Approximation of constructJoinAddress: pick the low piece.
	var joinaddr address.Address
	if ishislot {
		// slot1 is hi, slot1+1 is lo -- lo address goes first on little-endian.
		if addr1.Space != nil && addr1.Space.BigEndian {
			joinaddr = addr1
		} else {
			joinaddr = addr2
		}
	} else {
		if addr1.Space != nil && addr1.Space.BigEndian {
			joinaddr = addr2
		} else {
			joinaddr = addr1
		}
	}
	active.JoinTrial(int32(slot1), joinaddr, totalsz)
}

// fcActiveInputMap stores the per-FuncCallSpecs ParamActive for active-input
// recovery. A side map is used instead of adding a struct field so that
// funccallspec.go's declaration stays untouched for a clean merge.
// C++ parity: FuncCallSpecs::activeinput field (container only)
var fcActiveInputMap = map[*FuncCallSpecs]*ParamActive{}

// activeInput/accessors bridge the side map into methods. A linter-visible
// accessor-style pair is used so the helper is reachable without touching
// funccallspec.go's declaration list.
// C++ parity: FuncCallSpecs::activeinput (container-only)
func (fc *FuncCallSpecs) getActiveInputState() *ParamActive {
	if fc == nil {
		return nil
	}
	return fcActiveInputMap[fc]
}

// setActiveInputState stores the side-mapped ParamActive.
func (fc *FuncCallSpecs) setActiveInputState(p *ParamActive) {
	if fc == nil {
		return
	}
	if p == nil {
		delete(fcActiveInputMap, fc)
		return
	}
	fcActiveInputMap[fc] = p
}

// -----------------------------------------------------------------------------
// FuncProto extensions (fspec.hh / fspec.cc subset)
// -----------------------------------------------------------------------------

// fpTrashListMap stores the per-FuncProto likelyTrash override so that the
// funcproto.go declaration list stays untouched. The side-map pattern mirrors
// fcActiveInputMap above.
// C++ parity: FuncProto::likelytrash field (container only)
var fpTrashListMap = map[*FuncProto][]VarnodeData{}

// SetLikelyTrash installs the likelyTrash override list. Called by the
// compiler spec loader once the <likelytrash> section is ported.
// C++ parity: FuncProto::likelytrash write path (decodeLikelyTrash).
// TODO known mismatch: nothing wires this today; the compiler spec loader
// needs to call it after parsing <likelytrash> registers.
func (fp *FuncProto) SetLikelyTrash(entries []VarnodeData) {
	if fp == nil {
		return
	}
	if len(entries) == 0 {
		delete(fpTrashListMap, fp)
		return
	}
	fpTrashListMap[fp] = append([]VarnodeData(nil), entries...)
}

// TrashBegin returns the start of the trash-register list. The C++ routine
// falls back to the ProtoModel's list when the per-call override is empty;
// this Go port mirrors the fallback through the side map.
// C++ parity: FuncProto::trashBegin (fspec.cc:4260)
// TODO known mismatch: the ProtoModel side of the fallback still has no
// backing store, so the fallback path returns an empty slice until the
// compiler spec loader starts populating the map via SetLikelyTrash or its
// ProtoModel counterpart.
func (fp *FuncProto) TrashBegin() []VarnodeData {
	if fp == nil {
		return nil
	}
	if entries, ok := fpTrashListMap[fp]; ok {
		return entries
	}
	return nil
}

// TrashEnd is a marker companion to TrashBegin; Go iteration uses the slice
// length directly so this helper is kept only for documentation parity.
// C++ parity: FuncProto::trashEnd (fspec.cc:4269)
func (fp *FuncProto) TrashEnd() int {
	if fp == nil {
		return 0
	}
	return len(fpTrashListMap[fp])
}

// PossibleInputParam reports whether (addr,sz) could be a legal parameter
// slot under this prototype model.
// C++ parity: FuncProto::possibleInputParam
// TODO known mismatch: forwards to the stack-only IsParamVarnode check; the
// full register-classification path will land with ParamList.
func (fp *FuncProto) PossibleInputParam(addr address.Address, sz int32) bool {
	_ = sz
	if fp == nil || fp.model == nil {
		return false
	}
	if addr.Space != nil && addr.Space.Kind == address.SpaceKindStack {
		return fp.model.IsParamOffset(addr.Offset)
	}
	return false
}

// -----------------------------------------------------------------------------
// ScopeLocal extensions (database.hh Scope subset)
// -----------------------------------------------------------------------------

// scopeFunctionRegistry stores a per-scope lookup table from code address to
// Funcdata so that FindFunctionByAddress and QueryExternalRefFunction can
// return real results once the loader registers the process-wide function
// list. A side map is used instead of a ScopeLocal field to keep
// scopelocal.go's declaration list untouched.
// C++ parity: Scope::queryFunction indirect table (mapScope + stackFunction)
type scopeFunctionTable struct {
	direct   map[address.Address]*Funcdata
	external map[address.Address]*Funcdata
}

var scopeFunctionRegistry = map[*ScopeLocal]*scopeFunctionTable{}

func scopeFunctionEnsure(sl *ScopeLocal) *scopeFunctionTable {
	if sl == nil {
		return nil
	}
	tab, ok := scopeFunctionRegistry[sl]
	if !ok {
		tab = &scopeFunctionTable{
			direct:   map[address.Address]*Funcdata{},
			external: map[address.Address]*Funcdata{},
		}
		scopeFunctionRegistry[sl] = tab
	}
	return tab
}

// RegisterFunctionAt installs a direct address -> Funcdata mapping. The
// loader must call this for every recovered sibling function so that
// ActionDeindirect can resolve constant callees.
// C++ parity: Scope::addSymbolInternal for FunctionSymbol (data path only)
func (sl *ScopeLocal) RegisterFunctionAt(addr address.Address, fd *Funcdata) {
	if sl == nil || fd == nil {
		return
	}
	scopeFunctionEnsure(sl).direct[addr] = fd
}

// RegisterExternalFunctionAt installs an external-ref -> Funcdata mapping.
// C++ parity: Scope::addExternalRef (partial)
func (sl *ScopeLocal) RegisterExternalFunctionAt(addr address.Address, fd *Funcdata) {
	if sl == nil || fd == nil {
		return
	}
	scopeFunctionEnsure(sl).external[addr] = fd
}

// FindFunctionByAddress returns the Funcdata whose entry address matches the
// given code address. Used by ActionDeindirect when a CALLIND target resolves
// to a constant pointer into code.
// C++ parity: Scope::queryFunction (database.cc:1287)
// TODO known mismatch: the loader does not yet call RegisterFunctionAt so
// the direct map is empty in practice. Once the loader wires up the process
// function list this helper returns real hits without further code changes.
func (sl *ScopeLocal) FindFunctionByAddress(addr address.Address) *Funcdata {
	if sl == nil {
		return nil
	}
	tab, ok := scopeFunctionRegistry[sl]
	if !ok {
		return nil
	}
	return tab.direct[addr]
}

// QueryExternalRefFunction returns the Funcdata reached by following the
// external-reference at the given address.
// C++ parity: Scope::queryExternalRefFunction (database.cc:1416)
// TODO known mismatch: external-reference table is not yet populated; the
// side map is empty until the loader calls RegisterExternalFunctionAt.
func (sl *ScopeLocal) QueryExternalRefFunction(addr address.Address) *Funcdata {
	if sl == nil {
		return nil
	}
	tab, ok := scopeFunctionRegistry[sl]
	if !ok {
		return nil
	}
	return tab.external[addr]
}

// -----------------------------------------------------------------------------
// Funcdata extensions used by the upgraded actions
// -----------------------------------------------------------------------------

// IsDoublePrecisOn reports whether the architecture wants double-precision
// parameter recovery.
// C++ parity: Funcdata::isDoublePrecisOn (funcdata.hh:169)
func (fd *Funcdata) IsDoublePrecisOn() bool {
	if fd == nil {
		return false
	}
	return fd.HasFlag(FuncDoublePrecisOn)
}

// SetDoublePrecisRecovery toggles the double_precis_on flag on the owning
// Funcdata. Callers use this to enable the ActionParamDouble join path.
// C++ parity: Funcdata::setDoublePrecisRecovery (funcdata.hh:167)
func (fd *Funcdata) SetDoublePrecisRecovery(val bool) {
	if fd == nil {
		return
	}
	if val {
		fd.SetFlag(FuncDoublePrecisOn)
	} else {
		fd.ClearFlag(FuncDoublePrecisOn)
	}
}

// FindCoveredInput returns the input-flagged Varnode that completely covers
// the given (addr,size) range. Used by ActionLikelyTrash to pick trash
// candidates for each entry on the FuncProto trash list.
// C++ parity: Funcdata::findCoveredInput
func (fd *Funcdata) FindCoveredInput(size int32, loc address.Address) *Varnode {
	if fd == nil {
		return nil
	}
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || !vn.IsInput() {
			continue
		}
		if vn.Space() != loc.Space {
			continue
		}
		if vn.Offset() > loc.Offset {
			continue
		}
		if vn.Offset()+uint64(vn.Size()) < loc.Offset+uint64(size) {
			continue
		}
		return vn
	}
	return nil
}

// OpSwapInput exchanges the varnodes at slots a and b of op.
// C++ parity: Funcdata::opSwapInput
func (fd *Funcdata) OpSwapInput(op *PcodeOp, a, b int) {
	if fd == nil || op == nil || a == b {
		return
	}
	if a < 0 || b < 0 || a >= op.NumInput() || b >= op.NumInput() {
		return
	}
	va := op.Input(a)
	vb := op.Input(b)
	fd.OpSetInput(op, vb, a)
	fd.OpSetInput(op, va, b)
}

// -----------------------------------------------------------------------------
// Lane-access state used by ActionLaneDivide
// -----------------------------------------------------------------------------

// LaneAccessEntry is a (storage, register) pair iterated by LaneDivide.
// C++ parity: Funcdata::laneAccessMap value type
type LaneAccessEntry struct {
	Loc   VarnodeData
	Laned *LanedRegister
}

// laneAccessState is held in a side map because Funcdata's declaration list
// is frozen for this slice. A nil map is equivalent to "no lane access was
// ever recorded", which is the baseline for the Go port.
var laneAccessState = map[*Funcdata]*laneAccessData{}

type laneAccessData struct {
	entries      []LaneAccessEntry
	generated    bool
}

func laneState(fd *Funcdata) *laneAccessData {
	if fd == nil {
		return nil
	}
	s, ok := laneAccessState[fd]
	if !ok {
		s = &laneAccessData{}
		laneAccessState[fd] = s
	}
	return s
}

// BeginLaneAccess returns the currently recorded lane-access entries.
// C++ parity: Funcdata::beginLaneAccess / endLaneAccess (materialized here
// as a slice so Go range loops can drive the iteration).
// TODO known mismatch: the .sla loader does not yet populate the map; every
// call returns an empty slice, so ActionLaneDivide's 3-mode loop completes
// in zero passes. The control-flow structure is preserved so dropping real
// entries in later will exercise the full walk.
func (fd *Funcdata) BeginLaneAccess() []LaneAccessEntry {
	s := laneState(fd)
	if s == nil {
		return nil
	}
	return s.entries
}

// ClearLanedAccessMap drops any recorded lane entries.
// C++ parity: Funcdata::clearLanedAccessMap
func (fd *Funcdata) ClearLanedAccessMap() {
	s := laneState(fd)
	if s == nil {
		return
	}
	s.entries = nil
}

// SetLanedRegGenerated records that LaneDivide has run at least once.
// C++ parity: Funcdata::setLanedRegGenerated
func (fd *Funcdata) SetLanedRegGenerated() {
	s := laneState(fd)
	if s == nil {
		return
	}
	s.generated = true
}

// HasLanedRegGenerated reports whether LaneDivide has already executed.
// C++ parity: Funcdata::hasLanedRegGenerated
func (fd *Funcdata) HasLanedRegGenerated() bool {
	s := laneState(fd)
	if s == nil {
		return false
	}
	return s.generated
}

// processLaneVarnode stands in for the TransformManager lane-splitting entry
// point. When the full lane pipe lands this helper will build a
// TransformManager, call its lane APIs, and return whether a rewrite
// happened. For now it always reports "no rewrite" so the 3-mode walker in
// ActionLaneDivide matches the C++ "allVarnodesProcessed" exit condition.
// C++ parity: ActionLaneDivide::processVarnode
func processLaneVarnode(_ *Funcdata, _ *Varnode, _ *LanedRegister, _ int) bool {
	return false
}
