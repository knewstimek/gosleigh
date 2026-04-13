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
// C++ parity: FuncCallSpecs::checkInputSplit
// TODO known mismatch: the full C++ query consults ParamList::checkSplit.
// Gosleigh's ProtoModel does not yet expose that query so we conservatively
// answer false -- the upgraded ActionParamDouble therefore walks the pieces
// but never splits.
func (fc *FuncCallSpecs) CheckInputSplit(_ address.Address, _ int32, _ int32) bool {
	return false
}

// CheckInputJoin reports whether two adjacent input slots can be merged into
// a double-precision whole parameter.
// C++ parity: FuncCallSpecs::checkInputJoin
// TODO known mismatch: same ParamList::checkJoin gap as checkInputSplit.
func (fc *FuncCallSpecs) CheckInputJoin(_ int, _ bool, _ *Varnode, _ *Varnode) bool {
	return false
}

// DoInputJoin records a successful input-join so later analysis passes pick
// up the merged varnode.
// C++ parity: FuncCallSpecs::doInputJoin
func (fc *FuncCallSpecs) DoInputJoin(_ int, _ bool) {
	// No persistent state yet; matches CheckInputJoin always-false.
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

// TrashBegin returns the start of the trash-register list.
// C++ parity: FuncProto::trashBegin
// TODO known mismatch: trash-register list is not yet loaded from the .sla
// compiler specification; we return an empty slice so the upgraded
// ActionLikelyTrash walks zero candidates.
func (fp *FuncProto) TrashBegin() []VarnodeData {
	if fp == nil {
		return nil
	}
	return nil
}

// TrashEnd is a marker companion to TrashBegin; Go iteration uses the slice
// length directly so this helper is kept only for documentation parity.
// C++ parity: FuncProto::trashEnd
func (fp *FuncProto) TrashEnd() int {
	if fp == nil {
		return 0
	}
	return 0
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

// FindFunctionByAddress returns the Funcdata whose entry address matches the
// given code address. Used by ActionDeindirect when a CALLIND target resolves
// to a constant pointer into code.
// C++ parity: Scope::queryFunction
// TODO known mismatch: the global function table is not yet populated on the
// ScopeLocal side; we return nil so the deindirect walk falls through without
// modification, matching the behaviour of a missing symbol lookup in C++.
func (sl *ScopeLocal) FindFunctionByAddress(_ address.Address) *Funcdata {
	if sl == nil {
		return nil
	}
	return nil
}

// QueryExternalRefFunction returns the Funcdata reached by following the
// external-reference at the given address.
// C++ parity: Scope::queryExternalRefFunction
// TODO known mismatch: external-reference table is not yet modelled; returns
// nil so ActionDeindirect skips the external branch.
func (sl *ScopeLocal) QueryExternalRefFunction(_ address.Address) *Funcdata {
	if sl == nil {
		return nil
	}
	return nil
}

// -----------------------------------------------------------------------------
// Funcdata extensions used by the upgraded actions
// -----------------------------------------------------------------------------

// IsDoublePrecisOn reports whether the architecture wants double-precision
// parameter recovery.
// C++ parity: Funcdata::isDoublePrecisOn
// TODO known mismatch: Architecture::double_precis_port is not yet tracked;
// we answer false so the upgraded ActionParamDouble skips the
// double-precision fallback path until the flag lands.
func (fd *Funcdata) IsDoublePrecisOn() bool {
	if fd == nil {
		return false
	}
	return false
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
