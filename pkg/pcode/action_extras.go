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

import (
	"sort"
	"sync"

	"gosleigh/pkg/address"
)

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
func (fc *FuncCallSpecs) IsDotdotdot() bool {
	return fc != nil && fc.FuncProto.dotdotdot
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
	return fc.inputActive
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
		// Call-site trials recover a subcall's parameters.
		// C++ parity: FuncCallSpecs constructor (activeinput(true)).
		active := NewParamActive(true)
		// Defer the trial decision when any parameter entry lives in a space
		// heritaged with a delay (the stack spacebase): those trials only become
		// visible after several heritage passes.
		// C++ parity: fspec.cc FuncCallSpecs::initActiveInput (5331-5339).
		if m := fc.FuncProto.model; m != nil && m.InputParams != nil {
			if m.InputParams.GetMaxDelay() > 0 {
				active.SetMaxPass(3)
			}
		}
		fc.setActiveInputState(active)
	}
	fc.inputActive = true
}

// InitActiveOutput sets up an empty ParamActive for return-value recovery.
// C++ parity: FuncCallSpecs::initActiveOutput
func (fc *FuncCallSpecs) InitActiveOutput() {
	if fc == nil {
		return
	}
	fc.FuncProto.SetActiveOutput(NewParamActive(true)) // C++ activeoutput(true)
}

// CreatePlaceholder appends a stack-relative LOAD as a fresh input to the
// CALL op so later analysis can recover the calling convention's stack
// position. The C++ path also stores the slot in setStackPlaceholderSlot so
// resolveSpacebaseRelative can drop it later. The Go port drives the LOAD
// insertion through OpStackLoad and tags the result varnode with the
// spacebase-placeholder flag so RuleLoadPlaceholderClear can delete it once
// the value is no longer needed.
// C++ parity: fspec.cc FuncCallSpecs::createPlaceholder (4849-4857)
func (fc *FuncCallSpecs) CreatePlaceholder(data *Funcdata, spacebase *address.Space) {
	if fc == nil || data == nil || fc.op == nil || spacebase == nil {
		return
	}
	slot := fc.op.NumInput()
	loadval := data.OpStackLoad(spacebase, 0, 1, fc.op, nil, false)
	if loadval == nil {
		return
	}
	data.OpInsertInput(fc.op, loadval, slot)
	fc.SetStackPlaceholderSlot(slot)
	loadval.SetSpacebasePlaceholder()
}

// SetStackPlaceholderSlot records the CALL input slot of the stack-pointer
// placeholder. C++ parity: FuncCallSpecs::setStackPlaceholderSlot (fspec.hh:1671).
func (fc *FuncCallSpecs) SetStackPlaceholderSlot(slot int) {
	fc.stackPlaceholderSlot = slot
	if fc.IsInputActive() {
		fc.GetActiveInput().SetPlaceholderSlot()
	}
}

// ClearStackPlaceholderSlot releases the placeholder slot.
// C++ parity: FuncCallSpecs::clearStackPlaceholderSlot (fspec.hh:1673).
func (fc *FuncCallSpecs) ClearStackPlaceholderSlot() {
	fc.stackPlaceholderSlot = -1
	if fc.IsInputActive() {
		fc.GetActiveInput().FreePlaceholderSlot()
	}
}

// HasEffect returns the call effect on the given storage, from the model.
// C++ parity: FuncProto::hasEffect (the per-prototype effectlist is unported,
// so the model's list is always used).
func (fp *FuncProto) HasEffect(addr address.Address, size int32) EffectKind {
	if fp == nil || fp.model == nil {
		return EffectUnknown
	}
	return fp.model.HasEffect(addr, size)
}

// GetStackPlaceholderSlot returns the placeholder slot, or -1.
func (fc *FuncCallSpecs) GetStackPlaceholderSlot() int { return fc.stackPlaceholderSlot }

// ResolveSpacebaseRelative fixes this call's stack offset from the placeholder,
// which RuleLoadVarnode has just turned into a COPY from a stack Varnode, and
// removes the placeholder when it served no other purpose.
// C++ parity: fspec.cc FuncCallSpecs::resolveSpacebaseRelative (4870-4903).
func (fc *FuncCallSpecs) ResolveSpacebaseRelative(data *Funcdata, phvn *Varnode) {
	refvn := phvn.Def().Input(0)
	spacebase := refvn.Space()
	if spacebase.Kind != address.SpaceKindStack {
		data.warningHeader("This function may have set the stack pointer")
	}
	fc.stackoffset = refvn.Offset()
	if fc.stackPlaceholderSlot >= 0 && fc.op.Input(fc.stackPlaceholderSlot) == phvn {
		fc.AbortSpacebaseRelative(data)
		return
	}
	if fc.resolveLockedStackOffset(phvn, spacebase) {
		return
	}
	data.warningHeader("Unresolved stack placeholder")
}

// AbortSpacebaseRelative removes any stack-pointer placeholder from the call.
// C++ parity: fspec.cc FuncCallSpecs::abortSpacebaseRelative (4910-4922).
func (fc *FuncCallSpecs) AbortSpacebaseRelative(data *Funcdata) {
	if fc.stackPlaceholderSlot < 0 {
		return
	}
	vn := fc.op.Input(fc.stackPlaceholderSlot)
	data.OpRemoveInput(fc.op, fc.stackPlaceholderSlot)
	fc.ClearStackPlaceholderSlot()
	// Remove the op producing the placeholder as well
	if vn.HasNoDescend() && vn.Space() != nil && vn.Space().Kind == address.SpaceKindUnique && vn.IsWritten() {
		data.OpDestroy(vn.Def())
	}
}

// deindirectExternal turns a CALLIND through an external-reference slot into a
// direct CALL of the named external function.
// C++ parity: FuncCallSpecs::deindirect with the external Funcdata shell
// returned by queryExternalRefFunction (entryaddress/name taken from it).
// TODO known mismatch: the callee's prototype is not transferred (the host
// supplies names only), so its parameters are still recovered from trials.
func (fc *FuncCallSpecs) deindirectExternal(data *Funcdata, name string, ref address.Address) {
	op := fc.op
	if op == nil || op.Code() != CPUI_CALLIND {
		return
	}
	fc.name = name
	fc.entryAddress = ref
	// The host describes the external function at its reference: restart with
	// the call made direct so its prototype applies from the start.
	if h := data.HostScope(); h != nil {
		if _, ok := h.QueryFunction(ref); ok {
			data.addIndirectOverride(op.Addr().Offset, ref)
		}
	}
	data.OpSetOpcode(op, CPUI_CALL)
	if in0 := op.Input(0); in0 != nil {
		data.OpSetInput(op, data.NewConstant(in0.Size(), 0), 0)
	}
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

// CheckInputSplit reports whether the model allows a parameter at loc to be
// split at splitpoint into two parameters.
// C++ parity: FuncProto::checkInputSplit -> ProtoModel::checkInputSplit.
func (fc *FuncCallSpecs) CheckInputSplit(loc address.Address, size int32, splitpoint int32) bool {
	if fc == nil || fc.FuncProto.model == nil || fc.FuncProto.model.InputParams == nil {
		return false
	}
	return fc.FuncProto.model.InputParams.checkSplit(loc, size, splitpoint)
}

// CheckInputJoin reports whether two adjacent input slots can be merged into
// one parameter. C++ parity: FuncCallSpecs::checkInputJoin (fspec.cc).
func (fc *FuncCallSpecs) CheckInputJoin(slot1 int, ishislot bool, vn1 *Varnode, vn2 *Varnode) bool {
	if fc.IsInputActive() {
		return false
	}
	active := fc.getActiveInputState()
	if active == nil || slot1 >= active.NumTrials() { // Not enough params
		return false
	}
	var hislot, loslot *ParamTrial
	if ishislot { // slot1 looks like the high slot
		hislot = active.TrialForInputVarnode(slot1)
		loslot = active.TrialForInputVarnode(slot1 + 1)
		if hislot == nil || loslot == nil || hislot.GetSize() != vn1.Size() || loslot.GetSize() != vn2.Size() {
			return false
		}
	} else {
		loslot = active.TrialForInputVarnode(slot1)
		hislot = active.TrialForInputVarnode(slot1 + 1)
		if hislot == nil || loslot == nil || loslot.GetSize() != vn1.Size() || hislot.GetSize() != vn2.Size() {
			return false
		}
	}
	model := fc.FuncProto.model
	if model == nil || model.InputParams == nil {
		return false
	}
	return model.InputParams.checkJoin(hislot.GetAddress(), hislot.GetSize(), loslot.GetAddress(), loslot.GetSize())
}

// DoInputJoin replaces two adjacent trials with their joined whole.
// C++ parity: FuncCallSpecs::doInputJoin (fspec.cc).
func (fc *FuncCallSpecs) DoInputJoin(data *Funcdata, slot1 int, ishislot bool) {
	if fc.IsInputLocked() {
		return // C++ throws: joining parameters on a locked prototype
	}
	active := fc.getActiveInputState()
	trial1 := active.TrialForInputVarnode(slot1)
	trial2 := active.TrialForInputVarnode(slot1 + 1)
	addr1, addr2 := trial1.GetAddress(), trial2.GetAddress()
	var joinaddr address.Address
	if ishislot {
		joinaddr = data.constructJoinAddress(addr1, trial1.GetSize(), addr2, trial2.GetSize())
	} else {
		joinaddr = data.constructJoinAddress(addr2, trial2.GetSize(), addr1, trial1.GetSize())
	}
	active.JoinTrial(int32(slot1), joinaddr, trial1.GetSize()+trial2.GetSize())
}
// activeInput/accessors bridge the side map into methods. A linter-visible
// accessor-style pair is used so the helper is reachable without touching
// funccallspec.go's declaration list.
// C++ parity: FuncCallSpecs::activeinput (container-only)
func (fc *FuncCallSpecs) getActiveInputState() *ParamActive {
	if fc == nil {
		return nil
	}
	return fc.activeInputState
}

// setActiveInputState stores the side-mapped ParamActive.
func (fc *FuncCallSpecs) setActiveInputState(p *ParamActive) {
	if fc == nil {
		return
	}
	fc.activeInputState = p
}

// -----------------------------------------------------------------------------
// FuncProto extensions (fspec.hh / fspec.cc subset)
// -----------------------------------------------------------------------------

// SetLikelyTrash installs the likelyTrash override list. Called by the
// compiler spec loader once the <likelytrash> section is ported.
// C++ parity: FuncProto::likelytrash write path (decodeLikelyTrash).
// TODO known mismatch: nothing wires this today; the compiler spec loader
// needs to call it after parsing <likelytrash> registers.
func (fp *FuncProto) SetLikelyTrash(entries []VarnodeData) {
	if fp == nil {
		return
	}
	fp.trashList = append([]VarnodeData(nil), entries...)
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
	if len(fp.trashList) == 0 && fp.model != nil {
		return fp.model.LikelyTrash
	}
	return fp.trashList
}

// TrashEnd is a marker companion to TrashBegin; Go iteration uses the slice
// length directly so this helper is kept only for documentation parity.
// C++ parity: FuncProto::trashEnd (fspec.cc:4269)
func (fp *FuncProto) TrashEnd() int {
	if fp == nil {
		return 0
	}
	return len(fp.trashList)
}

// PossibleInputParam reports whether (addr,sz) could be a legal parameter
// slot under this prototype. A locked prototype (not varargs) answers from
// its locked parameters alone: the storage must sit justified at the start
// of one of them, and a void-locked prototype takes none.
// C++ parity: FuncProto::possibleInputParam.
func (fp *FuncProto) PossibleInputParam(addr address.Address, sz int32) bool {
	if fp == nil || fp.model == nil {
		return false
	}
	if !fp.dotdotdot && fp.hostInputLocked {
		if len(fp.selfLocked) == 0 {
			return false // voidinputlock
		}
		for _, slot := range fp.selfLocked {
			if addrJustifiedContain(slot.Addr, slot.Size, addr, sz) == 0 {
				return true
			}
		}
		return false
	}
	// The model's input storage decides; a merged model accepts what any
	// component accepts (ParamListMerged is the union).
	// C++ parity: FuncProto::possibleInputParam -> ParamList::possibleParam.
	models := []*ProtoModel{fp.model}
	if fp.model.IsMerged() {
		models = fp.model.Merged
	}
	for _, m := range models {
		if m.InputParams != nil {
			if m.InputParams.possibleParam(addr, sz) {
				return true
			}
		} else if addr.Space != nil && addr.Space.Kind == address.SpaceKindStack && m.IsParamOffset(addr.Offset) {
			return true // cspec-less fallback: stack parameter area
		}
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

func scopeFunctionEnsure(sl *ScopeLocal) *scopeFunctionTable {
	if sl == nil {
		return nil
	}
	if sl.funcTable == nil {
		sl.funcTable = &scopeFunctionTable{
			direct:   map[address.Address]*Funcdata{},
			external: map[address.Address]*Funcdata{},
		}
	}
	return sl.funcTable
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
	if sl.funcTable == nil {
		return nil
	}
	return sl.funcTable.direct[addr]
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
	if sl.funcTable == nil {
		return nil
	}
	return sl.funcTable.external[addr]
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

type laneAccessData struct {
	// records are the architecture's laned registers sorted by whole size.
	// C++ parity: Architecture::lanerecords.
	records []LanedRegister
	// lanedMap holds storage created at a laned register size.
	// C++ parity: Funcdata::lanedMap.
	lanedMap  map[VarnodeData]*LanedRegister
	generated bool
}

func laneState(fd *Funcdata) *laneAccessData {
	if fd == nil {
		return nil
	}
	if fd.laneAccess == nil {
		fd.laneAccess = &laneAccessData{lanedMap: map[VarnodeData]*LanedRegister{}}
	}
	return fd.laneAccess
}

// SetLanedRegisters installs the architecture's laned register records,
// merging lane-size masks per whole size.
// C++ parity: Architecture::decodeProcessorSpec (lanerecords build).
func (fd *Funcdata) SetLanedRegisters(recs []LanedRegister) {
	s := laneState(fd)
	if s == nil {
		return
	}
	masks := map[int32]uint32{}
	for i := range recs {
		masks[recs[i].GetWholeSize()] |= recs[i].GetSizeBitMask()
	}
	s.records = s.records[:0]
	for sz, m := range masks {
		s.records = append(s.records, NewLanedRegisterWithMask(sz, m))
	}
	sort.Slice(s.records, func(i, j int) bool { return s.records[i].GetWholeSize() < s.records[j].GetWholeSize() })
	if len(s.records) > 0 {
		fd.minLanedSize = uint32(s.records[0].GetWholeSize())
	}
}

// checkForLanedRegister records storage whose size matches a laned
// register (the record is keyed by size only, as in C++).
// C++ parity: Funcdata::checkForLanedRegister / Architecture::getLanedRegister.
func (fd *Funcdata) checkForLanedRegister(sz int32, addr address.Address) {
	if fd.minLanedSize == 0 || uint32(sz) < fd.minLanedSize {
		return
	}
	s := laneState(fd)
	for i := range s.records {
		if s.records[i].GetWholeSize() == sz {
			s.lanedMap[VarnodeData{Space: addr.Space, Offset: addr.Offset, Size: uint32(sz)}] = &s.records[i]
			return
		}
	}
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
	entries := make([]LaneAccessEntry, 0, len(s.lanedMap))
	for loc, lr := range s.lanedMap {
		entries = append(entries, LaneAccessEntry{Loc: loc, Laned: lr})
	}
	// std::map order over VarnodeData: space index, offset, then size.
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].Loc, entries[j].Loc
		if a.Space.Index != b.Space.Index {
			return a.Space.Index < b.Space.Index
		}
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		return a.Size > b.Size
	})
	return entries
}

// ClearLanedAccessMap drops any recorded lane entries.
// C++ parity: Funcdata::clearLanedAccessMap
func (fd *Funcdata) ClearLanedAccessMap() {
	s := laneState(fd)
	if s == nil {
		return
	}
	s.lanedMap = map[VarnodeData]*LanedRegister{}
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

// collectLaneSizes walks vn's def and descendants for PIECE / SUBPIECE ops
// and registers any putative lane sizes that the LanedRegister allows.
// C++ parity: coreaction.cc ActionLaneDivide::collectLaneSizes ~L510
func collectLaneSizes(vn *Varnode, allowedLanes *LanedRegister, checkLanes *LanedRegister) {
	if vn == nil || allowedLanes == nil || checkLanes == nil {
		return
	}
	// Descendants: SUBPIECE consumers tell us that the big register was
	// split into pieces of a particular size.
	for _, op := range vn.DescendIter() {
		if op == nil || op.Code() != CPUI_SUBPIECE {
			continue
		}
		out := op.Output()
		if out == nil {
			continue
		}
		curSize := out.Size()
		if allowedLanes.AllowedLane(curSize) {
			checkLanes.AddLaneSize(curSize)
		}
	}
	// Definition: a PIECE producer tells us the big register was assembled
	// from smaller ones; the smaller of the two halves is the lane width.
	if vn.IsWritten() {
		def := vn.Def()
		if def != nil && def.Code() == CPUI_PIECE {
			in0 := def.Input(0)
			in1 := def.Input(1)
			if in0 != nil && in1 != nil {
				curSize := in0.Size()
				if in1.Size() < curSize {
					curSize = in1.Size()
				}
				if allowedLanes.AllowedLane(curSize) {
					checkLanes.AddLaneSize(curSize)
				}
			}
		}
	}
}

// processLaneVarnode mirrors ActionLaneDivide::processVarnode lane-discovery
// path. It runs collectLaneSizes (mode 0/1) or falls back to the default
// pointer-sized lane (mode 2), exactly per the C++ control flow.
//
// The actual rewrite -- LaneDivide::doTrace + apply -- requires the
// LaneDivide TransformManager subclass declared in subflow.hh L426, which is
// not yet ported. Until then this helper returns false so the outer 3-mode
// walker in ActionLaneDivide.Apply sees "no rewrite" and the lane access map
// is cleared cleanly. The discovery side runs real today so dropping in a
// LaneDivide port later only needs to consume `checkLanes`.
// C++ parity: coreaction.cc ActionLaneDivide::processVarnode ~L559
// TODO known mismatch: subflow.hh LaneDivide TransformManager subclass not
// ported; processVarnode never returns true even when checkLanes is non-empty.
func processLaneVarnode(data *Funcdata, vn *Varnode, lanedRegister *LanedRegister, mode int) bool {
	if data == nil || vn == nil || lanedRegister == nil {
		return false
	}
	var checkLanes LanedRegister
	if mode < 2 {
		collectLaneSizes(vn, lanedRegister, &checkLanes)
	} else {
		// Default lane size mirrors getArch()->types->getSizeOfPointer().
		ps := 4
		if fp := data.GetFuncProto(); fp != nil {
			if pm := fp.Model(); pm != nil && pm.PointerSize > 0 {
				ps = pm.PointerSize
			}
		}
		defaultSize := int32(ps)
		if defaultSize != 4 {
			defaultSize = 8
		}
		checkLanes.AddLaneSize(defaultSize)
	}
	allowDowncast := mode > 0
	for it, end := checkLanes.Begin(), checkLanes.End(); it.NotEqual(end); it.Next() {
		description := NewLaneDescriptionUniform(lanedRegister.GetWholeSize(), it.Value())
		laneDivide := NewLaneDivide(data, vn, description, allowDowncast)
		if laneDivide.DoTrace() {
			laneDivide.Apply()
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// Funcdata stack-relative pcode primitives (funcdata_op.cc subset)
// -----------------------------------------------------------------------------

// spacebaseRegisterMap caches the (stack space -> SP register VarnodeData)
// mapping injected by loaders/tests so NewSpacebasePtr can fabricate the
// stack-pointer Varnode without an AddrSpace::getSpacebase API on the Go
// address.Space type.
// C++ parity: AddrSpace::getSpacebase(0) container -- the per-space list of
// (size, base reg) entries that the C++ AddrSpace owns directly.
var (
	spacebaseRegisterMu  sync.RWMutex
	spacebaseRegisterMap = map[*address.Space]VarnodeData{}
)

// RegisterSpacebaseRegister wires the SP register location for the given
// stack-like address space. Loaders call this once per space at construction
// time; tests can call it manually before exercising NewSpacebasePtr.
// C++ parity: AddrSpace::setSpacebase
func RegisterSpacebaseRegister(stackSpace *address.Space, spReg VarnodeData) {
	if stackSpace == nil {
		return
	}
	spacebaseRegisterMu.Lock()
	defer spacebaseRegisterMu.Unlock()
	if spReg.Space == nil || spReg.Size == 0 {
		delete(spacebaseRegisterMap, stackSpace)
		return
	}
	spacebaseRegisterMap[stackSpace] = spReg
}

// spacebaseRegisterFor returns the registered SP location for stackSpace,
// or false if no loader registered one.
func spacebaseRegisterFor(stackSpace *address.Space) (VarnodeData, bool) {
	if stackSpace == nil {
		return VarnodeData{}, false
	}
	spacebaseRegisterMu.RLock()
	defer spacebaseRegisterMu.RUnlock()
	vd, ok := spacebaseRegisterMap[stackSpace]
	return vd, ok
}

// findExistingSpacebaseInput is the fallback used when no loader has
// pre-registered an SP location: it scans the function's existing input
// varnodes for one already flagged as a spacebase that points at the given
// stack space. This matches the case where ApplyCallingConvention has
// already created the SP varnode for the function entry.
func findExistingSpacebaseInput(fd *Funcdata, stackSpace *address.Space) (VarnodeData, bool) {
	if fd == nil || stackSpace == nil {
		return VarnodeData{}, false
	}
	bank := fd.GetVarnodeBank()
	if bank == nil {
		return VarnodeData{}, false
	}
	for _, vn := range bank.AllVarnodes() {
		if vn == nil || !vn.IsInput() || !vn.IsSpaceBase() {
			continue
		}
		// The matched input is a real register varnode, so it lives in a
		// processor-kind space; its associated stack space is the one the
		// Funcdata has bound to it.
		if vn.AssociatedSpacebase() != stackSpace {
			continue
		}
		return VarnodeData{
			Space:  vn.Space(),
			Offset: vn.Offset(),
			Size:   uint32(vn.Size()),
		}, true
	}
	return VarnodeData{}, false
}

// NewSpacebasePtr fabricates a fresh Varnode at the SP register's storage
// location. The C++ helper looks the location up via id->getSpacebase(0); the
// Go port routes through the side map (preferred) or the Funcdata's existing
// input scan as a fallback.
// C++ parity: funcdata.cc Funcdata::newSpacebasePtr ~L275
// TODO known mismatch: returns nil when neither path resolves; the caller
// (createStackRef / opStackLoad) treats this as "no rewrite" instead of
// throwing the LowlevelError the C++ version does.
func (fd *Funcdata) NewSpacebasePtr(id *address.Space) *Varnode {
	if fd == nil || id == nil {
		return nil
	}
	// C++ newSpacebasePtr reads the space's own spacebase record
	// (funcdata_varnode.cc: id->getSpacebase(0)). The side map and the input
	// scan are fallbacks for harness-built spaces that never registered one.
	var point VarnodeData
	var ok bool
	if sb := id.GetSpacebase(0); sb.Space != nil && sb.Size > 0 {
		point, ok = VarnodeData{Space: sb.Space, Offset: sb.Offset, Size: uint32(sb.Size)}, true
	}
	if !ok {
		point, ok = spacebaseRegisterFor(id)
	}
	if !ok {
		point, ok = findExistingSpacebaseInput(fd, id)
	}
	if !ok || point.Space == nil || point.Size == 0 {
		return nil
	}
	return fd.NewVarnode(int32(point.Size), address.Address{Space: point.Space, Offset: point.Offset})
}

// CreateStackRef builds a unique-space Varnode holding (SP + off) where SP
// is the spacebase of spc. The new INT_ADD op is inserted before or after
// the supplied insertion-point op.
// C++ parity: funcdata_op.cc Funcdata::createStackRef ~L459
// TODO known mismatch: the C++ helper also wraps the result in a SEGMENTOP
// when the space has a SegmentOp registered (x86 real-mode); Gosleigh has no
// SegmentOp registry yet, so the segment branch is omitted.
func (fd *Funcdata) CreateStackRef(spc *address.Space, off uint64, op *PcodeOp, stackptr *Varnode, insertafter bool) *Varnode {
	if fd == nil || spc == nil || op == nil {
		return nil
	}
	if stackptr == nil {
		stackptr = fd.NewSpacebasePtr(spc)
		if stackptr == nil {
			return nil
		}
	}
	addrsize := stackptr.Size()
	addop := fd.NewOp(2, op.Addr())
	fd.OpSetOpcode(addop, CPUI_INT_ADD)
	addout := fd.NewUniqueOut(addrsize, addop)
	fd.OpSetInput(addop, stackptr, 0)
	// byteToAddress: the C++ helper divides off by spc->getWordSize() before
	// the constant lands in the INT_ADD. WordSize 0 is illegal but defended
	// against in case a stub space slips through.
	wordSize := uint64(spc.WordSize)
	if wordSize > 1 {
		off /= wordSize
	}
	fd.OpSetInput(addop, fd.NewConstant(addrsize, off), 1)
	if insertafter {
		fd.OpInsertAfter(addop, op)
	} else {
		fd.OpInsertBefore(addop, firstOfIndirectRun(op))
	}
	return addout
}

// firstOfIndirectRun returns the first of the INDIRECT ops op causes that sit
// right before it (op itself when there are none). The effects of a call
// happen at the call, so an op meant to run "before the call" goes ahead of
// them; C++ creates such ops (stack placeholders) before heritage adds the
// INDIRECTs, Gosleigh may create them after.
func firstOfIndirectRun(op *PcodeOp) *PcodeOp {
	first := op
	for prev := op.PreviousOp(); prev != nil && prev.Code() == CPUI_INDIRECT && prev.NumInput() > 1 &&
		prev.Input(1).GetIndirectCause() == op; prev = prev.PreviousOp() {
		first = prev
	}
	return first
}

// OpStackLoad builds a LOAD op that reads sz bytes from (SP + off) in spc.
// The new LOAD is wired into the function's pcode list immediately after the
// stack-ref INT_ADD that CreateStackRef just produced (regardless of the
// caller-requested insertafter flag, which matches C++ exactly).
// C++ parity: funcdata_op.cc Funcdata::opStackLoad ~L541
// TODO known mismatch: the C++ helper passes spc->getContain() as the LOAD
// space-id input; Gosleigh's address.Space has no Contain field so we use
// spc itself (BindSpaceConstant pins the space identity onto the constant).
func (fd *Funcdata) OpStackLoad(spc *address.Space, off uint64, sz int32, op *PcodeOp, stackref *Varnode, insertafter bool) *Varnode {
	if fd == nil || spc == nil || op == nil || sz <= 0 {
		return nil
	}
	addout := fd.CreateStackRef(spc, off, op, stackref, insertafter)
	if addout == nil {
		return nil
	}
	loadop := fd.NewOp(2, op.Addr())
	fd.OpSetOpcode(loadop, CPUI_LOAD)
	// LOAD input(0) is a constant varnode whose space identity is tracked
	// by the side-map (BindSpaceConstant). Mirror the rules_loadstore.go
	// idiom: build a 4-byte zero constant and bind the space.
	spaceConst := fd.NewConstant(4, 0)
	BindSpaceConstant(spaceConst, spc)
	fd.OpSetInput(loadop, spaceConst, 0)
	fd.OpSetInput(loadop, addout, 1)
	res := fd.NewUniqueOut(sz, loadop)
	if def := addout.Def(); def != nil {
		fd.OpInsertAfter(loadop, def)
	} else {
		fd.OpInsertAfter(loadop, op)
	}
	return res
}

// SpacebaseConstant rewrites op.Input(slot) (a constant pointer) into a
// PTRSUB(spacebase, encoded-offset), plus an INT_ADD when the constant points
// inside the symbol and a ZEXT/SUBPIECE when the pointer size differs from
// the constant. A COPY is itself turned into the final op of the chain.
// C++ parity: Funcdata::spacebaseConstant.
func (fd *Funcdata) SpacebaseConstant(op *PcodeOp, slot int, sym *Symbol, entryStart address.Address, rampoint address.Address, origval uint64, origsize int32) bool {
	if fd == nil || op == nil || rampoint.Space == nil {
		return false
	}
	sz := int32(rampoint.Space.AddrSize)
	if sz <= 0 {
		sz = origsize
	}
	tf := fd.TypeFactory()
	if tf == nil {
		return false
	}
	sbType := tf.GetTypeSpacebase(rampoint.Space)
	ptrType := tf.GetPointer(sz, sbType, uint32(rampoint.Space.WordSize))

	// extra is the offset from the entry's start, in address units.
	var extra uint64
	if rampoint.Offset >= entryStart.Offset {
		extra = rampoint.Offset - entryStart.Offset
	}
	if rampoint.Space.WordSize > 1 {
		extra /= uint64(rampoint.Space.WordSize)
	}

	var addOp, extraOp, zextOp, subOp *PcodeOp
	isCopy := false
	if op.Code() == CPUI_COPY { // We replace COPY with final op of this calculation
		isCopy = true
		if sz < origsize {
			zextOp = op
		} else if origsize < sz { // PTRSUB, ADD, SUBPIECE all take 2 parameters
			subOp = op
		} else if extra != 0 {
			extraOp = op
		} else {
			addOp = op
		}
	}
	// setIn fills input i, growing a COPY being reused as a 2-input op.
	setIn := func(o *PcodeOp, vn *Varnode, i int) {
		if i >= o.NumInput() {
			fd.OpInsertInput(o, vn, i)
		} else {
			fd.OpSetInput(o, vn, i)
		}
	}
	// The spacebase is type-locked to the spacebase pointer, which keeps it
	// the propagation source re-typing the PTRSUB each InferTypes pass.
	sbVn := fd.NewConstant(sz, 0)
	BindSpaceConstant(sbVn, rampoint.Space)
	sbVn.UpdateTypeLock(ptrType, true, true)
	sbVn.SetFlags(VarnodeSpaceBase)
	if addOp == nil {
		addOp = fd.NewOp(2, op.Addr())
		fd.OpSetOpcode(addOp, CPUI_PTRSUB)
		fd.NewUniqueOut(sz, addOp)
		fd.OpInsertBefore(addOp, op)
	} else {
		fd.OpSetOpcode(addOp, CPUI_PTRSUB)
	}
	outvn := addOp.Output()
	// Make sure newconstant and extra preserve origval in address units
	newconst := fd.NewConstant(sz, origval-extra)
	newconst.SetAddlFlags(VarnodePtrCheck) // No longer need to check this constant as a pointer
	if rampoint.Space.IsTruncated() {
		addOp.SetPtrFlow()
	}
	setIn(addOp, sbVn, 0)
	setIn(addOp, newconst, 1)

	// The &symbol pointer takes the symbol's type; an UNKNOWN symbol type is
	// never locked.
	if sym != nil {
		if entrytype := sym.Type(); entrytype != nil {
			ptrentrytype := tf.GetPointerStripArray(sz, entrytype, uint32(rampoint.Space.WordSize))
			typelock := sym.IsTypeLocked()
			if typelock && entrytype.Metatype() == TYPE_UNKNOWN {
				typelock = false
			}
			outvn.UpdateTypeLock(ptrentrytype, typelock, false)
		}
	}
	if extra != 0 {
		if extraOp == nil {
			extraOp = fd.NewOp(2, op.Addr())
			fd.OpSetOpcode(extraOp, CPUI_INT_ADD)
			fd.NewUniqueOut(sz, extraOp)
			fd.OpInsertBefore(extraOp, op)
		} else {
			fd.OpSetOpcode(extraOp, CPUI_INT_ADD)
		}
		extconst := fd.NewConstant(sz, extra)
		extconst.SetAddlFlags(VarnodePtrCheck)
		setIn(extraOp, outvn, 0)
		setIn(extraOp, extconst, 1)
		outvn = extraOp.Output()
	}
	if sz < origsize { // The new constant is smaller than the original varnode, so we extend it
		if zextOp == nil {
			zextOp = fd.NewOp(1, op.Addr())
			fd.OpSetOpcode(zextOp, CPUI_INT_ZEXT)
			fd.NewUniqueOut(origsize, zextOp)
			fd.OpInsertBefore(zextOp, op)
		} else {
			fd.OpSetOpcode(zextOp, CPUI_INT_ZEXT)
		}
		setIn(zextOp, outvn, 0)
		outvn = zextOp.Output()
	} else if origsize < sz { // The new constant is bigger than the original varnode, truncate it
		if subOp == nil {
			subOp = fd.NewOp(2, op.Addr())
			fd.OpSetOpcode(subOp, CPUI_SUBPIECE)
			fd.NewUniqueOut(origsize, subOp)
			fd.OpInsertBefore(subOp, op)
		} else {
			fd.OpSetOpcode(subOp, CPUI_SUBPIECE)
		}
		setIn(subOp, outvn, 0)
		setIn(subOp, fd.NewConstant(4, 0), 1) // Take least significant piece
		outvn = subOp.Output()
	}
	if !isCopy {
		fd.OpSetInput(op, outvn, slot)
	}
	return true
}

// ResolveSpacebaseSymbol resolves the symbol containing byte offset off inside
// space spc and returns the symbol's data-type together with the byte offset
// within that symbol. It mirrors TypeSpacebase::getSubType (type.cc L3369):
// getMap()->queryContainer resolves the address-tied symbol; when none is found
// the C++ code returns undefined1 with newoff 0, which this reproduces. The
// global scope is queried first (getMap returns the global scope for a non
// localframe spacebase), then the local scope as a fallback -- matching the
// two-scope lookup ActionConstantPtr uses.
// C++ parity: type.cc TypeSpacebase::getSubType + getMap (L3357-3391).
// TODO known mismatch: Architecture::resolveConstant is approximated as the
// identity map (byte offset == address offset), the same simplification
// ActionConstantPtr.isPointer already makes.
// spacebaseEntry is the symbol containing addr, global scope first.
// C++ parity: TypeSpacebase::getMap()->queryContainer(addr,1,nullPoint).
func (fd *Funcdata) spacebaseEntry(addr address.Address) *SymbolEntry {
	if g := fd.GetGlobalScope(); g != nil {
		if e := g.QueryContainer(addr, 1, address.Address{}); e != nil {
			return e
		}
	}
	if sl := fd.GetScopeLocal(); sl != nil {
		return sl.QueryContainer(addr, 1, address.Address{})
	}
	return nil
}

// spacebaseSubTypeOps are TypeSpacebase::getSubType and
// nearestArrayedComponentBackward/Forward for the given space.
func (fd *Funcdata) spacebaseSubTypeOps(spc *address.Space) subTypeOps {
	sub := func(off int64) (Datatype, int64) { return fd.ResolveSpacebaseSymbol(spc, off) }
	return subTypeOps{
		sub: sub,
		// C++ parity: TypeSpacebase::nearestArrayedComponentBackward.
		back: func(off, max int64) (int64, int64, int64) {
			subType, newoff := sub(off)
			if subType == nil {
				return -1, 0, 0
			}
			distance, _, elSize := nearestArrayedComponentBackward(subType, newoff, max)
			if distance < 0 || distance > max {
				return -1, 0, 0
			}
			return distance, newoff, elSize
		},
		// C++ parity: TypeSpacebase::nearestArrayedComponentForward.
		fwd: func(off, max int64) (int64, int64, int64) {
			if spc == nil {
				return -1, 0, 0
			}
			ws := int64(spc.WordSize)
			if ws <= 0 {
				ws = 1
			}
			addr := address.Address{Space: spc, Offset: wrapSpaceOffset(spc, uint64(off/ws))}
			smallest := fd.spacebaseEntry(addr)
			var nextAddr address.Address
			if smallest == nil || smallest.Offset() != 0 {
				nextAddr = address.Address{Space: spc, Offset: wrapSpaceOffset(spc, addr.Offset+32)}
			} else {
				symbolType := smallest.Symbol().Type()
				structOff := int64(addr.Offset) - int64(smallest.Addr().Offset)
				if symbolType != nil {
					distance, _, elSize := nearestArrayedComponentForward(symbolType, structOff, max)
					if distance >= 0 {
						if distance > max {
							return -1, 0, 0
						}
						return distance, structOff, elSize
					}
				}
				sz := int64(smallest.Size()) / ws
				nextAddr = address.Address{Space: spc, Offset: wrapSpaceOffset(spc, uint64(int64(smallest.Addr().Offset)+sz))}
			}
			if nextAddr.Offset < addr.Offset {
				return -1, 0, 0 // Don't let the address wrap
			}
			smallest = fd.spacebaseEntry(nextAddr)
			if smallest == nil || smallest.Offset() != 0 || smallest.Symbol() == nil || smallest.Symbol().Type() == nil {
				return -1, 0, 0
			}
			newoff := int64(addr.Offset) - int64(smallest.Addr().Offset)
			distance, _, elSize := nearestArrayedComponentForward(smallest.Symbol().Type(), 0, max)
			if distance < 0 {
				return -1, 0, 0
			}
			distance -= newoff
			if distance > max {
				return -1, 0, 0
			}
			return distance, newoff, elSize
		},
	}
}

func (fd *Funcdata) ResolveSpacebaseSymbol(spc *address.Space, off int64) (Datatype, int64) {
	tf := fd.TypeFactory()
	undef1 := tf.GetBase(1, TYPE_UNKNOWN, "undefined")
	if spc == nil {
		return undef1, 0
	}
	ws := int64(spc.WordSize)
	if ws <= 0 {
		ws = 1
	}
	addrOff := off / ws                                                                 // byteToAddress
	probe := address.Address{Space: spc, Offset: wrapSpaceOffset(spc, uint64(addrOff))} // resolveConstant wraps
	var entry *SymbolEntry
	if g := fd.GetGlobalScope(); g != nil {
		entry = g.QueryContainer(probe, 1, address.Address{})
	}
	if entry == nil {
		if sl := fd.GetScopeLocal(); sl != nil {
			entry = sl.QueryContainer(probe, 1, address.Address{})
		}
	}
	if entry == nil {
		return undef1, 0 // C++ fallback: getBase(1,TYPE_UNKNOWN), newoff 0
	}
	sym := entry.Symbol()
	if sym == nil || sym.Type() == nil {
		return undef1, 0
	}
	within := (int64(probe.Offset) - int64(entry.Addr().Offset)) + int64(entry.Offset())
	return sym.Type(), within
}

// spacebasePtrsubMatching mirrors the TYPE_SPACEBASE branch of
// TypePointer::isPtrsubMatching (type.cc L1264-1273): a spacebase PTRSUB is a
// valid pointer subtraction when its offset resolves to the exact start of a
// symbol and any additional constant (extra) stays within that symbol (or the
// symbol has arrayed slack). Used by RulePtrsubUndo so a &symbol PTRSUB is not
// collapsed back to a raw constant.
// C++ parity: type.cc TypePointer::isPtrsubMatching (TYPE_SPACEBASE case).
func (fd *Funcdata) spacebasePtrsubMatching(spc *address.Space, ptr *Pointer, off, extra int64) bool {
	ws := int64(1)
	if ptr != nil && ptr.WordSize() > 0 {
		ws = int64(ptr.WordSize())
	}
	newoffByte := off * ws // addressToByteInt
	subType, within := fd.ResolveSpacebaseSymbol(spc, newoffByte)
	if subType == nil || within != 0 {
		return false
	}
	extraByte := extra * ws
	if extraByte < 0 || extraByte >= int64(subType.Size()) {
		// testForArraySlack: only arrayed sub-types have slack; the undefined1
		// / scalar symbols this path currently sees never do (TODO: port
		// nearestArrayedComponent* when struct/array globals are supported).
		if subType.Metatype() != TYPE_ARRAY {
			return false
		}
	}
	return true
}

// addrJustifiedContain is the endian-aware position of (addr2,sz2) inside
// (addr,sz), or -1 when it is not contained.
// C++ parity: Address::justifiedContain (forceleft false).
func addrJustifiedContain(addr address.Address, sz int32, addr2 address.Address, sz2 int32) int32 {
	if addr.Space != addr2.Space || addr2.Offset < addr.Offset {
		return -1
	}
	off1 := addr.Offset + uint64(sz-1)
	off2 := addr2.Offset + uint64(sz2-1)
	if off2 > off1 {
		return -1
	}
	if addr.Space != nil && addr.Space.BigEndian {
		return int32(off1 - off2)
	}
	return int32(addr2.Offset - addr.Offset)
}
