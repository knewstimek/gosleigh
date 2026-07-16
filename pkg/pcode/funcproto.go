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
	"fmt"
	"gosleigh/pkg/address"
)

// FuncProto holds the calling convention information attached to a single
// function. It references a ProtoModel for ABI rules and records the
// high-level parameter/local variable assignments.
//
// C++ parity: funcdata.hh FuncProto (partial)
type FuncProto struct {
	model        *ProtoModel
	inputLocked  bool
	modelLocked  bool
	outputLocked bool

	// badJumpTable records that this call site was originally an indirect jump
	// whose jump table could not be recovered (truncated to a CALLIND). It hints
	// the switch-variable naming pass to use a special name.
	// C++ parity: fspec.hh FuncProto::isbadjumptable.
	badJumpTable bool
	// noReturn records that the call site never returns.
	// C++ parity: fspec.hh FuncProto no-return flag (setNoReturn/isNoReturn).
	noReturn bool

	// params holds the discovered parameter HighVariables in order.
	params []*HighVariable
	// output holds the recovered return HighVariable, if any.
	output *HighVariable

	// outputAddr/outputSize describe the storage of a locked/injected return
	// value independent of whether a varnode exists at that address yet. This is
	// the Gosleigh analog of ProtoParameter::getAddress()/getSize() for the
	// output: C++ reads outparam->getAddress() directly, while Gosleigh otherwise
	// derives the return storage from an existing HighVariable instance. When an
	// injected locked prototype supplies the return storage explicitly, the
	// locked-output path in ActionPrototypeTypes uses these fields.
	// C++ parity: FuncProto::getOutput() -> ProtoParameter address/size.
	outputAddr    address.Address
	outputSize    int32
	outputHasAddr bool

	// lockedParamTypes maps a register-space byte offset to the type an injected
	// locked prototype assigns to the parameter stored there. Gosleigh recovers
	// register parameters by ABI-slot derivation (ScopeLocal.BuildFromVarnodes),
	// which already converges on the same storage map a locked prototype encodes;
	// when a locked type is present for a slot, BuildFromVarnodes stamps it with a
	// type lock instead of the default TYPE_INT seed, so the injected prototype's
	// parameter types (not type inference) are authoritative. Empty/nil for every
	// non-injected function, so the default path is unchanged.
	// C++ parity: FuncProto locked input parameters carry ProtoParameter types.
	lockedParamTypes map[uint64]Datatype
	// lockedParamNames maps a register-space byte offset to the injected
	// prototype's naming metadata (display name + namelock) for the parameter
	// stored there. BuildFromVarnodes uses it to create a namelocked Symbol on the
	// recovered register parameter so the merge Symbol guard can keep it distinct
	// from an accumulator that maps to a different Symbol. Nil for every
	// non-injected function, so the default path is unchanged.
	// C++ parity: locked ProtoParameter carries a name and the namelock property.
	lockedParamNames map[uint64]lockedParamName
	// activeoutput holds the temporary active-return analysis state.
	activeoutput *ParamActive
	// locals holds the discovered local HighVariables in order.
	locals []*HighVariable
}

// NewFuncProto creates a FuncProto that uses the given ProtoModel.
// C++ parity: FuncProto::FuncProto
func NewFuncProto(model *ProtoModel) *FuncProto {
	return &FuncProto{model: model}
}

// Model returns the underlying calling convention model.
func (fp *FuncProto) Model() *ProtoModel { return fp.model }

// HasModel reports whether a calling convention model is attached.
// C++ parity: FuncProto::hasModel
func (fp *FuncProto) HasModel() bool {
	return fp != nil && fp.model != nil
}

// HasMatchingModel reports whether the attached model matches the provided one.
// C++ parity: FuncProto::hasMatchingModel
func (fp *FuncProto) HasMatchingModel(model *ProtoModel) bool {
	return fp != nil && fp.model == model
}

// SetModel attaches a calling convention model.
// C++ parity: FuncProto::setModel
func (fp *FuncProto) SetModel(model *ProtoModel) {
	if fp == nil {
		return
	}
	fp.model = model
}

// Copy copies the prototype state from another FuncProto.
// C++ parity: FuncProto::copy
func (fp *FuncProto) Copy(other *FuncProto) {
	if fp == nil || other == nil {
		return
	}
	fp.model = other.model
	fp.inputLocked = other.inputLocked
	fp.modelLocked = other.modelLocked
	fp.outputLocked = other.outputLocked
	fp.params = append([]*HighVariable(nil), other.params...)
	fp.output = other.output
	fp.outputAddr = other.outputAddr
	fp.outputSize = other.outputSize
	fp.outputHasAddr = other.outputHasAddr
	if other.lockedParamTypes != nil {
		fp.lockedParamTypes = make(map[uint64]Datatype, len(other.lockedParamTypes))
		for k, v := range other.lockedParamTypes {
			fp.lockedParamTypes[k] = v
		}
	}
	if other.lockedParamNames != nil {
		fp.lockedParamNames = make(map[uint64]lockedParamName, len(other.lockedParamNames))
		for k, v := range other.lockedParamNames {
			fp.lockedParamNames[k] = v
		}
	}
	fp.activeoutput = other.activeoutput
	fp.locals = append([]*HighVariable(nil), other.locals...)
}

// SetInternal records an internally synthesized prototype.
// TODO known mismatch: Ghidra's FuncProto::setInternal also tracks internal storage
// and extra callsite metadata; Gosleigh only records the model and return type.
// C++ parity: FuncProto::setInternal
func (fp *FuncProto) SetInternal(model *ProtoModel, vt Datatype) {
	if fp == nil {
		return
	}
	fp.model = model
	if vt == nil {
		fp.output = nil
		return
	}
	out := NewHighVariable("return")
	out.SetType(vt)
	fp.output = out
}

// ClearInput clears the currently classified input parameters.
// C++ parity: funcdata.hh FuncProto::clearInput
func (fp *FuncProto) ClearInput() {
	if fp == nil {
		return
	}
	fp.params = nil
	fp.inputLocked = false
}

// SetModelLock toggles the prototype model lock.
// C++ parity: funcdata.hh FuncProto::setModelLock
func (fp *FuncProto) SetModelLock(val bool) {
	if fp == nil {
		return
	}
	fp.modelLocked = val
}

// SetOutputLock toggles the output lock.
// C++ parity: funcdata.hh FuncProto::setOutputLock
func (fp *FuncProto) SetOutputLock(val bool) {
	if fp == nil {
		return
	}
	fp.outputLocked = val
}

// IsInputLocked reports whether the prototype input is locked.
// C++ parity: funcdata.hh FuncProto::isInputLocked
func (fp *FuncProto) IsInputLocked() bool {
	if fp == nil {
		return false
	}
	return fp.inputLocked
}

// SetInputLocked toggles the prototype input lock.
// C++ parity: funcdata.hh FuncProto::setInputLock
func (fp *FuncProto) SetInputLocked(val bool) {
	if fp == nil {
		return
	}
	fp.inputLocked = val
}

// IsModelLocked reports whether the prototype model is locked.
// C++ parity: FuncProto::isModelLocked
func (fp *FuncProto) IsModelLocked() bool {
	if fp == nil {
		return false
	}
	return fp.modelLocked
}

// IsOutputLocked reports whether the return value is locked.
// C++ parity: FuncProto::isOutputLocked
func (fp *FuncProto) IsOutputLocked() bool {
	if fp == nil {
		return false
	}
	return fp.outputLocked
}

// SetBadJumpTable toggles whether this call site looked like an unrecovered
// indirect jump.
// C++ parity: fspec.hh FuncProto::setBadJumpTable.
func (fp *FuncProto) SetBadJumpTable(val bool) {
	if fp == nil {
		return
	}
	fp.badJumpTable = val
}

// IsBadJumpTable reports whether this call site was a truncated indirect jump.
// C++ parity: fspec.hh FuncProto::isBadJumpTable.
func (fp *FuncProto) IsBadJumpTable() bool {
	return fp != nil && fp.badJumpTable
}

// SetNoReturn toggles whether the call site never returns.
// C++ parity: fspec.hh FuncProto::setNoReturn.
func (fp *FuncProto) SetNoReturn(val bool) {
	if fp == nil {
		return
	}
	fp.noReturn = val
}

// IsNoReturn reports whether the call site never returns.
// C++ parity: fspec.hh FuncProto::isNoReturn.
func (fp *FuncProto) IsNoReturn() bool {
	return fp != nil && fp.noReturn
}

// ClearUnlockedInput clears recovered parameters when the prototype is not locked.
// C++ parity: FuncProto::clearUnlockedInput
func (fp *FuncProto) ClearUnlockedInput() {
	if fp == nil || fp.inputLocked {
		return
	}
	fp.params = nil
}

// ClearUnlockedOutput clears a recovered return value when it is not locked.
// C++ parity: FuncProto::clearUnlockedOutput
func (fp *FuncProto) ClearUnlockedOutput() {
	if fp == nil || fp.outputLocked {
		return
	}
	fp.output = nil
}

// GetOutput returns the recovered return value, if any.
// C++ parity: FuncProto::getOutput
func (fp *FuncProto) GetOutput() *HighVariable {
	if fp == nil {
		return nil
	}
	return fp.output
}

// SetOutput records the recovered return value.
// C++ parity: FuncProto::setOutput
func (fp *FuncProto) SetOutput(hv *HighVariable) {
	if fp == nil {
		return
	}
	fp.output = hv
}

// SetLockedReturn records an injected locked return value: its storage address,
// size, and type. It seeds an output HighVariable carrying the type (so the
// existing output plumbing sees a typed return) and records the explicit storage
// so the locked-output path can materialize a return carrier without depending on
// a pre-existing varnode instance. The caller sets the output lock separately.
// C++ parity: FuncProto::setOutput(ProtoParameter) with an explicit address/type.
func (fp *FuncProto) SetLockedReturn(addr address.Address, size int32, vt Datatype) {
	if fp == nil || vt == nil {
		return
	}
	out := NewHighVariable("")
	out.SetType(vt)
	fp.output = out
	fp.outputAddr = addr
	fp.outputSize = size
	fp.outputHasAddr = true
}

// OutputStorage returns the explicit locked-return storage (address, size) when
// an injected prototype supplied it. The bool is false for the ordinary derived
// path, in which case the locked-output action falls back to a HighVariable
// instance address.
// C++ parity: ProtoParameter::getAddress()/getSize() for the output.
func (fp *FuncProto) OutputStorage() (address.Address, int32, bool) {
	if fp == nil || !fp.outputHasAddr {
		return address.Address{}, 0, false
	}
	return fp.outputAddr, fp.outputSize, true
}

// SetLockedParamType records the type an injected locked prototype assigns to the
// parameter stored at the given register-space byte offset.
// C++ parity: ProtoParameter::getType() for a locked input parameter.
func (fp *FuncProto) SetLockedParamType(regOffset uint64, vt Datatype) {
	if fp == nil || vt == nil {
		return
	}
	if fp.lockedParamTypes == nil {
		fp.lockedParamTypes = make(map[uint64]Datatype)
	}
	fp.lockedParamTypes[regOffset] = vt
}

// LockedParamType returns the injected locked type for the parameter at the given
// register-space byte offset, if any.
// C++ parity: ProtoParameter::getType() for a locked input parameter.
func (fp *FuncProto) LockedParamType(regOffset uint64) (Datatype, bool) {
	if fp == nil || fp.lockedParamTypes == nil {
		return nil, false
	}
	vt, ok := fp.lockedParamTypes[regOffset]
	return vt, ok
}

// lockedParamName carries the injected prototype's naming metadata for one
// register-parameter storage slot.
type lockedParamName struct {
	name     string
	nameLock bool
	isolate  bool
}

// SetLockedParamName records the injected prototype's display name and namelock
// property for the parameter stored at the given register-space byte offset.
// C++ parity: ProtoParameter name + Varnode::namelock for a locked parameter.
func (fp *FuncProto) SetLockedParamName(regOffset uint64, name string, nameLock bool, isolate bool) {
	if fp == nil || name == "" {
		return
	}
	if fp.lockedParamNames == nil {
		fp.lockedParamNames = make(map[uint64]lockedParamName)
	}
	fp.lockedParamNames[regOffset] = lockedParamName{name: name, nameLock: nameLock, isolate: isolate}
}

// LockedParamName returns the injected display name and namelock flag for the
// parameter at the given register-space byte offset, if any.
// C++ parity: ProtoParameter name + Varnode::namelock for a locked parameter.
func (fp *FuncProto) LockedParamName(regOffset uint64) (string, bool, bool, bool) {
	if fp == nil || fp.lockedParamNames == nil {
		return "", false, false, false
	}
	info, ok := fp.lockedParamNames[regOffset]
	return info.name, info.nameLock, info.isolate, ok
}

// GetActiveOutput returns the temporary active return analysis state.
// C++ parity: FuncProto::getActiveOutput
func (fp *FuncProto) GetActiveOutput() *ParamActive {
	if fp == nil {
		return nil
	}
	return fp.activeoutput
}

// SetActiveOutput records the temporary active return analysis state.
// C++ parity: FuncProto::setActiveOutput
func (fp *FuncProto) SetActiveOutput(active *ParamActive) {
	if fp == nil {
		return
	}
	fp.activeoutput = active
}

// ClearActiveOutput clears the temporary active return analysis state.
// C++ parity: FuncProto::clearActiveOutput
func (fp *FuncProto) ClearActiveOutput() {
	if fp == nil {
		return
	}
	fp.activeoutput = nil
}

// GetModelExtraPop returns the prototype model's extra-pop setting.
// TODO known mismatch: ProtoModel extra-pop tracking is not yet ported.
// C++ parity: FuncProto::getModelExtraPop
func (fp *FuncProto) GetModelExtraPop() int32 {
	_ = fp
	return 0
}

// HasThisPointer reports whether the prototype models an implicit this pointer.
// TODO known mismatch: Ghidra's this-pointer flags are not yet modeled.
// C++ parity: FuncProto::hasThisPointer
func (fp *FuncProto) HasThisPointer() bool {
	_ = fp
	return false
}

// PrepareThisPointer is a placeholder for this-pointer normalization.
// TODO known mismatch: Ghidra's FuncProto::updateThisPointer is not yet ported.
// C++ parity: FuncProto::updateThisPointer
func (fp *FuncProto) PrepareThisPointer() {}

// AddParam registers a parameter HighVariable (in ABI order).
func (fp *FuncProto) AddParam(hv *HighVariable) {
	if fp == nil || hv == nil {
		return
	}
	fp.params = append(fp.params, hv)
}

// AddLocal registers a local HighVariable.
func (fp *FuncProto) AddLocal(hv *HighVariable) {
	if fp == nil || hv == nil {
		return
	}
	fp.locals = append(fp.locals, hv)
}

// NumParams returns the number of classified parameters.
func (fp *FuncProto) NumParams() int {
	if fp == nil {
		return 0
	}
	return len(fp.params)
}

// NumLocals returns the number of classified locals.
func (fp *FuncProto) NumLocals() int {
	if fp == nil {
		return 0
	}
	return len(fp.locals)
}

// GetParam returns the i-th parameter HighVariable, or nil.
func (fp *FuncProto) GetParam(i int) *HighVariable {
	if fp == nil || i < 0 || i >= len(fp.params) {
		return nil
	}
	return fp.params[i]
}

// GetLocal returns the i-th local HighVariable, or nil.
func (fp *FuncProto) GetLocal(i int) *HighVariable {
	if fp == nil || i < 0 || i >= len(fp.locals) {
		return nil
	}
	return fp.locals[i]
}

// IsParamVarnode reports whether the given varnode is a stack-based parameter
// according to this function's calling convention.
// C++ parity: FuncProto::isParamVarnode
func (fp *FuncProto) IsParamVarnode(vn *Varnode) bool {
	if fp == nil || fp.model == nil || vn == nil {
		return false
	}
	if vn.Space() == nil {
		return false
	}
	// Must be in the stack address space.
	if fp.model.StackSpace != nil && vn.Space() != fp.model.StackSpace {
		return false
	} else if fp.model.StackSpace == nil && vn.Space().Kind != 0 {
		// Fallback: check by space name if StackSpace not set.
		if vn.Space().Name != "stack" {
			return false
		}
	}
	return fp.model.IsParamOffset(vn.Offset())
}

// GetParamName returns a human-readable name like "param_1", "param_2" etc.
// for the given parameter index (1-indexed to match Ghidra output).
// C++ parity: ParameterBasic::getName / FuncProto::getParamSymbol
func GetParamName(index int) string {
	return fmt.Sprintf("param_%d", index+1)
}

// GetLocalName returns a human-readable name like "local_0", "local_1" etc.
func GetLocalName(index int) string {
	return fmt.Sprintf("local_%d", index)
}

// ApplyCallingConvention classifies all stack varnodes in fd's varnode bank
// as either parameters or locals according to model, creates HighVariables
// for each group, and stores the result on fd's FuncProto and ScopeLocal.
//
// When model.ReturnRegSpaceIndex >= 0, it also anchors the integer return
// register to each RETURN op as an additional input. This prevents
// ActionDeadCode from eliminating stores to the return register (e.g. EAX
// in x86-32 cdecl) whose only consumer is the implicit function return.
//
// This is called after Heritage so SSA input varnodes are available.
// C++ parity: Funcdata::startProcessing / ScopeLocal::resetLocalWindow
func ApplyCallingConvention(fd *Funcdata, model *ProtoModel) {
	if fd == nil || model == nil {
		return
	}
	fp := NewFuncProto(model)
	fd.SetFuncProto(fp)

	sl := NewScopeLocal(model)
	fd.SetScopeLocal(sl)

	sl.BuildFromVarnodes(fd.GetVarnodeBank().AllVarnodes(), fp)

	// Anchor return register to RETURN ops so that stores to the return register
	// are not eliminated as dead by ActionDeadCode.
	// Without this, x86 EAX writes before RET have no visible consumer after SSA
	// construction (RETURN only reads the return address from the stack), so
	// ActionDeadCode prunes them and the if-branches disappear.
	// C++ parity: FuncProto::resolveReturnType / ParameterSymbol return slot
	if model.ReturnRegSpaceIndex < 0 || model.ReturnRegSize == 0 {
		return
	}
	// Strip the indirect branch target from all RETURN ops before anchoring the
	// return register. This severs the data-flow chain from the return address
	// load (e.g. EIP = *ESP on x86 RET) so ActionDeadCode can remove those ops.
	// C++ parity: ActionPrototypeTypes::apply() in coreaction.cc lines 4636-4646.
	stripReturnIndirectRef(fd)
	// H7 step3: the return value is wired by ApplyGuardReturnsLive (the faithful
	// Heritage::guardReturns + dominance rename), called from the decompile driver
	// once the block graph is available. (Formerly anchorReturnReg's SeqNum heuristic.)
}

// stripReturnIndirectRef replaces the indirect branch target (input[0]) of
// every RETURN op with a zero constant of the same size. In x86 cdecl the
// RET instruction reads the return address from the stack, which creates an
// EIP = *ESP data-flow edge. Severing that edge lets ActionDeadCode prune the
// epilogue assignments (ESP = ESP+4; EIP = *ESP) from the C output.
//
// C++ parity: ActionPrototypeTypes::apply() in coreaction.cc lines 4636-4646.
func stripReturnIndirectRef(fd *Funcdata) {
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		if op.NumInput() == 0 {
			continue
		}
		in0 := op.Input(0)
		if in0 == nil || in0.IsConstant() {
			// Already a constant -- nothing to do.
			continue
		}
		// Replace the indirect branch target with a zero constant of the same
		// size so that the data-flow chain it belongs to has no live consumers.
		zeroConst := fd.NewConstant(in0.Size(), 0)
		fd.OpUnsetInput(op, 0)
		fd.OpSetInput(op, zeroConst, 0)
	}
}

// applyReturnRecovery un-wires the return-register varnode from each RETURN op
// when the varnode's value is not exclusively consumed by that RETURN.
// This is the post-dead-code recovery step: after ActionDeadCode eliminates
// side-effect-free ops (e.g. overflow-flag computations from IMUL), the
// remaining consumers of the return-register varnode are the ground truth.
// If any consumer is not the RETURN op itself (transitively through transparent
// ops), the function has no meaningful return value and the wired input is removed.
//
// Must be called AFTER ActionDeadCode so that non-return consumers introduced
// by register-clobbering side-effects (e.g. OF flag from IMUL) have been pruned.
// C++ parity: ActionReturnRecovery::apply + Funcdata::ancestorOpUse
func applyReturnRecovery(fd *Funcdata) {
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		if op.NumInput() <= 1 {
			continue
		}
		// slot 1 is where the return-value wiring appends the return-register varnode.
		const retSlot = 1
		retVn := op.Input(retSlot)
		if retVn == nil || retVn.IsConstant() {
			continue
		}
		// Only check register-space varnodes. If copy propagation has substituted
		// the return-register varnode with a stack/unique varnode, that substitution
		// represents a legitimate data-flow (e.g. accumulator variable), not an
		// accidental register clobber. Checking non-register varnodes would
		// incorrectly mark loop accumulators (CountedLoop, SumList) as void.
		// C++ parity: Heritage::guardReturns inserts a fresh register varnode at RETURN,
		// which is immune to cross-space propagation; we approximate by space guard here.
		if sp := retVn.Space(); sp == nil || sp.Kind != address.SpaceKindProcessor {
			continue
		}
		if !ancestorOpUseReturn(retVn, op, retSlot, 5, make(map[*PcodeOp]bool)) {
			fd.OpUnsetInput(op, retSlot)
			op.SetNumInputs(retSlot)
		}
	}
}

// buildReturnOutput rewires a RETURN op to reflect the active return trials.
// C++ parity: ActionReturnRecovery::buildReturnOutput
func buildReturnOutput(active *ParamActive, retop *PcodeOp, data *Funcdata) {
	if active == nil || retop == nil || data == nil || retop.NumInput() == 0 {
		return
	}
	if retop.Input(0) == nil {
		return
	}
	newparam := make([]*Varnode, 0, active.NumTrials()+1)
	newparam = append(newparam, retop.Input(0))
	for i := 0; i < active.NumTrials(); i++ {
		curtrial := active.Trial(i)
		if curtrial == nil || !curtrial.IsUsed() {
			break
		}
		slot := int(curtrial.GetSlot())
		if slot >= retop.NumInput() {
			break
		}
		newparam = append(newparam, retop.Input(slot))
	}
	if len(newparam) <= 2 {
		data.OpSetAllInput(retop, newparam)
		return
	}
	if len(newparam) == 3 {
		lovn := newparam[1]
		hivn := newparam[2]
		if lovn == nil || hivn == nil {
			return
		}
		triallo := active.Trial(0)
		trialhi := active.Trial(1)
		if triallo == nil || trialhi == nil {
			return
		}
		joinaddr := trialhi.GetAddress()
		if triallo.GetAddress().Less(joinaddr) {
			joinaddr = triallo.GetAddress()
		}
		newop := data.NewOp(2, retop.Addr())
		data.OpSetOpcode(newop, CPUI_PIECE)
		newwhole := data.NewVarnodeOut(trialhi.GetSize()+triallo.GetSize(), joinaddr, newop)
		newwhole.SetAddlFlags(VarnodeWriteMask)
		data.OpInsertBefore(newop, retop)
		newparam[2] = newwhole
		newparam = newparam[:3]
		data.OpSetAllInput(retop, newparam)
		data.OpSetInput(newop, hivn, 0)
		data.OpSetInput(newop, lovn, 1)
		return
	}
	newparam = newparam[:1]
	offmatch := int32(0)
	var preexist *Varnode
	for i := 0; i < active.NumTrials(); i++ {
		curtrial := active.Trial(i)
		if curtrial == nil || !curtrial.IsUsed() {
			break
		}
		slot := int(curtrial.GetSlot())
		if slot >= retop.NumInput() {
			break
		}
		if preexist == nil {
			preexist = retop.Input(slot)
			offmatch = curtrial.GetOffset() + curtrial.GetSize()
			continue
		}
		if offmatch != curtrial.GetOffset() {
			break
		}
		offmatch += curtrial.GetSize()
		vn := retop.Input(slot)
		if preexist == nil || vn == nil {
			break
		}
		newop := data.NewOp(2, retop.Addr())
		data.OpSetOpcode(newop, CPUI_PIECE)
		addr := preexist.Addr()
		if vn != nil && vn.Addr().Less(addr) {
			addr = vn.Addr()
		}
		newout := data.NewVarnodeOut(preexist.Size()+vn.Size(), addr, newop)
		newout.SetAddlFlags(VarnodeWriteMask)
		data.OpSetInput(newop, vn, 0)
		data.OpSetInput(newop, preexist, 1)
		data.OpInsertBefore(newop, retop)
		preexist = newout
	}
	if preexist != nil {
		newparam = append(newparam, preexist)
	}
	data.OpSetAllInput(retop, newparam)
}

// onlyReturnUse reports whether ALL downstream consumers of vn lead exclusively
// to retOp at retSlot (transitively through MULTIEQUAL/SEXT/ZEXT/CAST).
// Visited tracks seen varnodes to break phi back-edge cycles; a cycle is treated
// as non-disqualifying because the back-edge itself is not a new consumer.
// C++ parity: Funcdata::onlyOpUse in funcdata_varnode.cc
func onlyReturnUse(vn *Varnode, retOp *PcodeOp, retSlot int, visited map[*Varnode]bool) bool {
	if vn == nil {
		return false
	}
	if visited[vn] {
		return true
	}
	visited[vn] = true
	for _, useOp := range vn.DescendIter() {
		if useOp == nil || useOp.IsDead() {
			continue
		}
		if useOp == retOp {
			// Acceptable only if this exact varnode occupies the anchored slot.
			if useOp.NumInput() > retSlot && useOp.Input(retSlot) == vn {
				continue
			}
			return false
		}
		switch useOp.Code() {
		case CPUI_MULTIEQUAL, CPUI_INT_SEXT, CPUI_INT_ZEXT, CPUI_CAST:
			out := useOp.Output()
			if out == nil {
				return false
			}
			if !onlyReturnUse(out, retOp, retSlot, visited) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ancestorOpUseReturn reports whether any upstream path from vn satisfies
// onlyReturnUse. For MULTIEQUAL, any single passing input is sufficient.
// For CALL/CALLIND, always false. For other defining ops, delegates to
// onlyReturnUse on vn. depth caps phi-chain recursion.
// C++ parity: Funcdata::ancestorOpUse in funcdata_varnode.cc
func ancestorOpUseReturn(vn *Varnode, retOp *PcodeOp, retSlot int, depth int, seenME map[*PcodeOp]bool) bool {
	if depth <= 0 || vn == nil {
		return false
	}
	if !vn.IsWritten() {
		return false
	}
	def := vn.Def()
	if def == nil || def.IsDead() {
		return false
	}
	switch def.Code() {
	case CPUI_MULTIEQUAL:
		if seenME[def] {
			return false
		}
		seenME[def] = true
		for i := 0; i < def.NumInput(); i++ {
			inp := def.Input(i)
			if inp != nil && ancestorOpUseReturn(inp, retOp, retSlot, depth-1, seenME) {
				delete(seenME, def)
				return true
			}
		}
		delete(seenME, def)
		return false
	case CPUI_CALL, CPUI_CALLIND:
		return false
	default:
		return onlyReturnUse(vn, retOp, retSlot, make(map[*Varnode]bool))
	}
}
