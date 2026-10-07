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

// deindirectHost converts this CALLIND into a direct call of the function the
// host describes at entry. The callee's prototype is merged into the call site
// when the current data-flow allows it (lateRestriction); otherwise the
// decompilation restarts with the call already direct (the indirect override
// is recorded either way, so a restart rebuilds the call as a CALL).
// The callee Funcdata C++ queries is the host's description of it, and a
// call-site prototype override (isOverride) has no host source.
// C++ parity: fspec.cc FuncCallSpecs::deindirect.
func (fc *FuncCallSpecs) deindirectHost(data *Funcdata, hp HostFunction, entry address.Address, name string) {
	op := fc.op
	fc.entryAddress = entry
	fc.name = name
	fc.hostProto = &hp
	data.OpSetInput(op, data.NewCodeRef(entry), 0)
	data.OpSetOpcode(op, CPUI_CALL)
	data.recordIndirectOverride(op.Addr().Offset, entry)
	if !hp.NoReturn {
		if newinput, newoutput, ok := fc.lateRestriction(data, &hp); ok {
			fc.commitNewInputs(data, newinput)
			fc.commitNewOutputs(data, newoutput)
			return
		}
	}
	data.rebuildRequested = true // Funcdata::setRestartPending
}

// lateRestriction checks whether this call site, still mid-recovery, can take
// the given locked prototype without losing data-flow, and if so converts to
// it. It passes back the CALL's new inputs (nil entries for stack parameters
// still to be loaded) and the outputs overlapping the new return value.
// C++ parity: fspec.cc FuncCallSpecs::lateRestriction.
func (fc *FuncCallSpecs) lateRestriction(data *Funcdata, hp *HostFunction) (newinput, newoutput []*Varnode, ok bool) {
	model := data.ModelByName(hp.Model)
	if model == nil {
		model = data.DefaultModel()
	}
	// A prototype without an explicit extrapop takes its model's (setModel);
	// a host function with no prototype is a shell on the default model.
	// C++ parity: fspec.cc FuncProto::decode.
	if hp.ExtraPop == ExtrapopUnknown && model != nil {
		hp.ExtraPop = model.GetExtraPop()
	}
	if !fc.HasModel() {
		fc.copyHostProto(data, hp, model)
		return nil, nil, true
	}
	if !fc.isCompatibleHost(hp, model) {
		return nil, nil, false
	}
	var params []ProtoSlot
	if hp.InputLocked {
		for _, p := range hp.Params {
			s, good := data.resolveHostParam(p)
			if !good {
				return nil, nil, false
			}
			params = append(params, s)
		}
		if newinput, ok = fc.transferLockedInput(params); !ok {
			return nil, nil, false
		}
	}
	if hp.OutputLocked && hp.Output != nil && (hp.Output.Type == nil || hp.Output.Type.Metatype() != TYPE_VOID) {
		if out, good := data.resolveHostParam(*hp.Output); good {
			newoutput = fc.transferLockedOutputParam(out)
		}
	}
	fc.copyHostProto(data, hp, model)
	return newinput, newoutput, true
}

// isCompatibleHost reports whether the host prototype can stand in for this
// call site's current one: same (or compatible) model, matching return when
// both are locked, matching extrapop when known, and matching no-return.
// Gosleigh's host prototypes carry no varargs, inject, effect or likelytrash
// overrides, so those comparisons hold trivially.
// C++ parity: fspec.cc FuncProto::isCompatible.
func (fc *FuncCallSpecs) isCompatibleHost(hp *HostFunction, model *ProtoModel) bool {
	if !fc.Model().IsCompatible(model) {
		return false
	}
	if hp.OutputLocked && fc.IsOutputLocked() && fc.lockedOut != nil && hp.Output != nil {
		if fc.lockedOut.Type != hp.Output.Type {
			return false
		}
	}
	if fc.GetExtraPop() != ExtrapopUnknown && fc.GetExtraPop() != hp.ExtraPop {
		return false
	}
	if fc.IsDotdotdot() {
		return false
	}
	return fc.IsNoReturn() == hp.NoReturn
}

// copyHostProto turns this call site's prototype into the host's.
// C++ parity: fspec.cc FuncProto::copy (from the callee's prototype).
func (fc *FuncCallSpecs) copyHostProto(data *Funcdata, hp *HostFunction, model *ProtoModel) {
	fc.SetModel(model)
	fc.SetExtraPop(hp.ExtraPop)
	fc.SetModelLock(data.ModelByName(hp.Model) != nil)
	fc.applyHostLocks(data, hp)
}

// transferLockedInput lists, in parameter order, the CALL input reusable for
// each locked parameter: the covering trial's Varnode, or nil for a stack
// parameter to be loaded through the stack placeholder.
// C++ parity: fspec.cc FuncCallSpecs::transferLockedInput.
func (fc *FuncCallSpecs) transferLockedInput(params []ProtoSlot) ([]*Varnode, bool) {
	newinput := []*Varnode{fc.op.Input(0)} // Always keep the call destination
	var stackref *Varnode
	for _, p := range params {
		reuse := fc.transferLockedInputParam(p)
		if reuse == 0 {
			return nil, false
		}
		if reuse > 0 {
			newinput = append(newinput, fc.op.Input(reuse))
			continue
		}
		if stackref == nil {
			stackref = fc.getSpacebaseRelative()
		}
		if stackref == nil {
			return nil, false
		}
		newinput = append(newinput, nil)
	}
	return newinput, true
}

// transferLockedInputParam returns the CALL input slot of the trial covering
// the parameter, -1 for a stack parameter with no trial, or 0 when the
// parameter cannot be built.
// C++ parity: fspec.cc FuncCallSpecs::transferLockedInputParam.
func (fc *FuncCallSpecs) transferLockedInputParam(p ProtoSlot) int {
	start := p.Addr
	last := start.Offset + uint64(p.Size) - 1
	if active := fc.getActiveInputState(); active != nil {
		for i := 0; i < active.NumTrials(); i++ {
			trial := active.Trial(i)
			taddr := trial.GetAddress()
			if taddr.Space != start.Space || start.Offset < taddr.Offset {
				continue
			}
			if taddr.Offset+uint64(trial.GetSize())-1 < last {
				continue
			}
			if trial.IsDefinitelyNotUsed() {
				return 0 // The trial has already been stripped
			}
			return int(trial.GetSlot())
		}
	}
	if start.Space != nil && start.Space.Kind == address.SpaceKindStack {
		return -1
	}
	return 0
}

// transferLockedOutputParam collects the CALL's outputs, and the outputs of
// the indirect creations before it, that contain or are contained by the
// return value.
// C++ parity: fspec.cc FuncCallSpecs::transferLockedOutputParam.
func (fc *FuncCallSpecs) transferLockedOutputParam(p ProtoSlot) []*Varnode {
	var res []*Varnode
	overlaps := func(vn *Varnode) bool {
		return addressJustifiedContain(p.Addr, p.Size, vn.Addr(), vn.Size(), false) >= 0 ||
			addressJustifiedContain(vn.Addr(), vn.Size(), p.Addr, p.Size, false) >= 0
	}
	if vn := fc.op.Output(); vn != nil && overlaps(vn) {
		res = append(res, vn)
	}
	for indop := fc.op.PreviousOp(); indop != nil && indop.Code() == CPUI_INDIRECT; indop = indop.PreviousOp() {
		if indop.IsIndirectCreation() && overlaps(indop.Output()) {
			res = append(res, indop.Output())
		}
	}
	return res
}

// getSpacebaseRelative returns the stack-pointer reference the placeholder
// LOAD reads, or nil.
// C++ parity: fspec.cc FuncCallSpecs::getSpacebaseRelative.
func (fc *FuncCallSpecs) getSpacebaseRelative() *Varnode {
	if fc.stackPlaceholderSlot < 0 || fc.stackPlaceholderSlot >= fc.op.NumInput() {
		return nil
	}
	vn := fc.op.Input(fc.stackPlaceholderSlot)
	if !vn.IsSpacebasePlaceholder() || !vn.IsWritten() || vn.Def().Code() != CPUI_LOAD {
		return nil
	}
	return vn.Def().Input(1)
}

// buildParam returns a Varnode exactly matching the parameter: a stack LOAD
// for a nil (stack) input, the input itself, or its truncation.
// C++ parity: fspec.cc FuncCallSpecs::buildParam.
func (fc *FuncCallSpecs) buildParam(data *Funcdata, vn *Varnode, p ProtoSlot, stackref *Varnode) *Varnode {
	op := fc.op
	if vn == nil {
		return data.OpStackLoad(p.Addr.Space, p.Addr.Offset, p.Size, op, stackref, false)
	}
	if vn.Size() == p.Size {
		return vn
	}
	newop := data.NewOp(2, op.Addr())
	data.OpSetOpcode(newop, CPUI_SUBPIECE)
	newout := data.NewUniqueOut(p.Size, newop)
	// A free input may already have its one descendant; read a fresh copy.
	if vn.IsFree() && !vn.IsConstant() && !vn.HasNoDescend() {
		vn = data.NewVarnode(vn.Size(), vn.Addr())
	}
	data.OpSetInput(newop, vn, 0)
	data.OpSetInput(newop, data.NewConstant(4, 0), 1)
	data.OpInsertBefore(newop, op)
	return newout
}

// commitNewInputs rebuilds the CALL inputs from the locked parameters and the
// gathered old inputs, re-registers them as active trials, keeps a stack
// placeholder only while no locked stack parameter can serve, and ends input
// recovery.
// C++ parity: fspec.cc FuncCallSpecs::commitNewInputs.
func (fc *FuncCallSpecs) commitNewInputs(data *Funcdata, newinput []*Varnode) {
	if !fc.IsInputLocked() {
		return
	}
	op := fc.op
	stackref := fc.getSpacebaseRelative()
	var placeholder *Varnode
	if fc.stackPlaceholderSlot >= 0 && fc.stackPlaceholderSlot < op.NumInput() {
		placeholder = op.Input(fc.stackPlaceholderSlot)
	}
	noplacehold := true
	fc.stackPlaceholderSlot = -1
	active := fc.getActiveInputState()
	if active == nil {
		active = NewParamActive(true)
		fc.setActiveInputState(active)
	}
	numPasses := active.NumPasses()
	active.Clear()
	for i, p := range fc.lockedIn {
		vn := fc.buildParam(data, newinput[1+i], p, stackref)
		newinput[1+i] = vn
		active.RegisterTrial(p.Addr, p.Size)
		active.Trial(i).MarkActive() // A parameter is not optional
		if noplacehold && p.Addr.Space != nil && p.Addr.Space.Kind == address.SpaceKindStack {
			// A locked stack parameter recovers the stack offset itself.
			vn.SetSpacebasePlaceholder()
			noplacehold = false
			placeholder = nil
		}
	}
	if placeholder != nil {
		newinput = append(newinput, placeholder)
		fc.stackPlaceholderSlot = len(newinput) - 1
	}
	data.OpSetAllInput(op, newinput)
	if !fc.IsDotdotdot() {
		fc.ClearActiveInput()
	} else if numPasses > 0 {
		active.FinishPass()
	}
}

// commitNewOutputs makes the CALL's output the locked return value: an
// existing exact match moves onto the CALL, otherwise a new output is made;
// every other overlapping output becomes a truncation of it, or is rebuilt
// by concatenating indirectly created pieces around it.
// Gosleigh has no assumedOutputExtension (no cspec output extensions on the
// supported ABIs), so a wider old output always takes the concatenation path.
// C++ parity: fspec.cc FuncCallSpecs::commitNewOutputs.
func (fc *FuncCallSpecs) commitNewOutputs(data *Funcdata, newoutput []*Varnode) {
	if !fc.IsOutputLocked() {
		return
	}
	op := fc.op
	param := fc.lockedOut
	if len(newoutput) > 0 && param != nil && param.Addr.Space != nil {
		if param.Size == 1 && param.Type != nil && param.Type.Metatype() == TYPE_BOOL && data.HasFlag(FuncTypeRecoveryOn) {
			op.SetFlag(PcodeOpCalculatedBool)
		}
		var exactMatch *Varnode
		for _, vn := range newoutput {
			if vn.Size() == param.Size {
				exactMatch = vn
				break
			}
		}
		var realOut *Varnode
		if exactMatch != nil {
			if indOp := exactMatch.Def(); indOp != op {
				data.OpSetOutput(op, exactMatch)
				data.opUnlink(indOp) // An indirect creation nothing needs any more
			}
			realOut = exactMatch
		} else {
			data.OpUnsetOutput(op)
			realOut = data.NewVarnodeOut(param.Size, param.Addr, op)
		}
		for _, oldOut := range newoutput {
			if oldOut == exactMatch {
				continue
			}
			indOp := oldOut.Def()
			if indOp == op {
				indOp = nil
			}
			if oldOut.Size() < param.Size {
				if indOp != nil {
					data.OpUninsert(indOp)
					data.OpSetOpcode(indOp, CPUI_SUBPIECE)
				} else {
					indOp = data.NewOp(2, op.Addr())
					data.OpSetOpcode(indOp, CPUI_SUBPIECE)
					data.OpSetOutput(indOp, oldOut)
				}
				overlap := oldOut.OverlapAddr(realOut.Addr(), realOut.Size())
				data.OpSetInput(indOp, realOut, 0)
				data.OpSetInput(indOp, data.NewConstant(4, uint64(overlap)), 1)
				data.OpInsertAfter(indOp, op)
				continue
			}
			if param.Size >= oldOut.Size() {
				continue
			}
			overlap := addressJustifiedContain(oldOut.Addr(), oldOut.Size(), param.Addr, param.Size, false)
			if indOp != nil {
				data.opUnlink(indOp)
			}
			mostSigSize := oldOut.Size() - overlap - realOut.Size()
			lastOp := op
			if overlap != 0 { // Less significant bytes below realOut
				loAddr := oldOut.Addr()
				if loAddr.Space.BigEndian {
					loAddr.Offset += uint64(oldOut.Size() - overlap)
				}
				newIndOp := data.NewIndirectCreation(op, loAddr, overlap, true)
				concatOp := data.NewOp(2, op.Addr())
				data.OpSetOpcode(concatOp, CPUI_PIECE)
				data.OpSetInput(concatOp, realOut, 0)
				data.OpSetInput(concatOp, newIndOp.Output(), 1)
				data.OpInsertAfter(concatOp, op)
				if mostSigSize != 0 {
					if loAddr.Space.BigEndian {
						data.NewVarnodeOut(overlap+realOut.Size(), realOut.Addr(), concatOp)
					} else {
						data.NewVarnodeOut(overlap+realOut.Size(), loAddr, concatOp)
					}
				}
				lastOp = concatOp
			}
			if mostSigSize != 0 { // More significant bytes above realOut
				hiAddr := oldOut.Addr()
				if !hiAddr.Space.BigEndian {
					hiAddr.Offset += uint64(realOut.Size() + overlap)
				}
				newIndOp := data.NewIndirectCreation(op, hiAddr, mostSigSize, true)
				concatOp := data.NewOp(2, op.Addr())
				data.OpSetOpcode(concatOp, CPUI_PIECE)
				data.OpSetInput(concatOp, newIndOp.Output(), 0)
				data.OpSetInput(concatOp, lastOp.Output(), 1)
				data.OpInsertAfter(concatOp, lastOp)
				lastOp = concatOp
			}
			data.OpSetOutput(lastOp, oldOut)
		}
	}
	fc.ClearActiveOutput()
}

// opUnlink detaches an op from its output, inputs and block.
// C++ parity: funcdata_op.cc Funcdata::opUnlink.
func (fd *Funcdata) opUnlink(op *PcodeOp) {
	fd.OpUnsetOutput(op)
	for i := 0; i < op.NumInput(); i++ {
		fd.OpUnsetInput(op, i)
	}
	if op.Parent() != nil {
		fd.OpUninsert(op)
	}
}

// recordIndirectOverride stores a resolved indirect call without asking for
// a restart, so a later restart still rebuilds the call as direct.
// C++ parity: Override::insertIndirectOverride.
func (fd *Funcdata) recordIndirectOverride(at uint64, target address.Address) {
	if fd.indirectOverrides == nil {
		fd.indirectOverrides = make(map[uint64]address.Address)
	}
	fd.indirectOverrides[at] = target
}
