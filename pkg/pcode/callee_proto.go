package pcode

import "gosleigh/pkg/address"

// ProtoSlot is one storage slot of a locked prototype: a parameter or the
// return value. A stack slot's offset is relative to the callee's stack
// pointer at entry. C++ parity: ProtoParameter (address, size, type).
type ProtoSlot struct {
	Addr    address.Address
	Size    int32
	Type    Datatype
	Name    string
	ThisPtr bool
}

// spaceByName finds one of the function's address spaces by name.
func (fd *Funcdata) spaceByName(name string) *address.Space {
	if name == "" {
		return nil
	}
	if st := fd.stackSpace(); st != nil && st.Name == name {
		return st
	}
	for _, sp := range fd.heritageSpaces {
		if sp != nil && sp.Name == name {
			return sp
		}
	}
	if sp := fd.baseAddr.Space; sp != nil && sp.Name == name {
		return sp
	}
	for _, vn := range fd.vbank.AllVarnodes() {
		if sp := vn.Space(); sp != nil && sp.Name == name {
			return sp
		}
	}
	return nil
}

func (fd *Funcdata) resolveHostParam(p HostParam) (ProtoSlot, bool) {
	sp := fd.spaceByName(p.Space)
	if sp == nil || p.Size <= 0 {
		return ProtoSlot{}, false
	}
	return ProtoSlot{Addr: address.Address{Space: sp, Offset: p.Offset}, Size: p.Size,
		Type: p.Type, Name: p.Name, ThisPtr: p.ThisPtr}, true
}

// applyHostLocks copies the host's locked parameter list and return into the
// call site. A lock is taken only when every slot resolves to storage.
// C++ parity: FuncProto::copy of a locked prototype (ActionDefaultParams).
func (fc *FuncCallSpecs) applyHostLocks(data *Funcdata, hp *HostFunction) {
	if hp.InputLocked {
		slots := make([]ProtoSlot, 0, len(hp.Params))
		ok := true
		for _, p := range hp.Params {
			s, good := data.resolveHostParam(p)
			if !good {
				ok = false
				break
			}
			slots = append(slots, s)
		}
		if ok {
			fc.lockedIn = slots
			fc.SetInputLocked(true)
		}
	}
	if hp.OutputLocked && hp.Output != nil {
		if hp.Output.Type != nil && hp.Output.Type.Metatype() == TYPE_VOID {
			fc.lockedOut = &ProtoSlot{Type: hp.Output.Type}
			fc.SetOutputLock(true)
		} else if s, ok := data.resolveHostParam(*hp.Output); ok {
			fc.lockedOut = &s
			fc.SetOutputLock(true)
		}
	}
	if hp.NoReturn {
		fc.SetNoReturn(true)
	}
}

// LockedParam returns the i-th locked parameter slot of the call.
func (fc *FuncCallSpecs) LockedParam(i int) (ProtoSlot, bool) {
	if i < 0 || i >= len(fc.lockedIn) {
		return ProtoSlot{}, false
	}
	return fc.lockedIn[i], true
}

// linkLockedInputs gives the CALL one input per locked parameter: the
// register itself, or a LOAD of the stack slot relative to the stack
// pointer at the call. The first stack load doubles as the stack
// placeholder. Returns false when no stack placeholder is needed any more.
// C++ parity: ActionFuncLink::funcLinkInput (inputlocked branch).
func (fc *FuncCallSpecs) linkLockedInputs(data *Funcdata, varargs bool) bool {
	op := fc.op
	active := fc.GetActiveInput()
	needPlaceholder := true
	setplaceholder := varargs
	for i, p := range fc.lockedIn {
		if active != nil {
			active.RegisterTrial(p.Addr, p.Size)
			active.Trial(active.NumTrials() - 1).MarkActive()
			if varargs {
				active.Trial(active.NumTrials() - 1).SetFixedPosition(int32(i))
			}
		}
		if p.Addr.Space != nil && p.Addr.Space.Kind == address.SpaceKindStack {
			loadval := data.OpStackLoad(p.Addr.Space, p.Addr.Offset, p.Size, op, nil, false)
			data.OpInsertInput(op, loadval, op.NumInput())
			if !setplaceholder {
				setplaceholder = true
				loadval.SetSpacebasePlaceholder()
				needPlaceholder = false
			}
			continue
		}
		data.OpInsertInput(op, data.NewVarnode(p.Size, p.Addr), op.NumInput())
	}
	return needPlaceholder
}

// linkLockedOutput gives the CALL its locked return value.
// TODO known mismatch: stack-located outputs and assumedOutputExtension are
// not ported (x86 returns are registers without extension).
// C++ parity: ActionFuncLink::funcLinkOutput (isOutputLocked branch).
func (fc *FuncCallSpecs) linkLockedOutput(data *Funcdata) {
	out := fc.lockedOut
	if out == nil || out.Type == nil || out.Type.Metatype() == TYPE_VOID || out.Addr.Space == nil {
		return
	}
	// A locked boolean return makes the CALL a boolean-valued op.
	// C++ parity: funcLinkOutput opMarkCalculatedBool (type recovery is on).
	if out.Type.Metatype() == TYPE_BOOL {
		fc.op.SetFlag(PcodeOpCalculatedBool)
	}
	if out.Addr.Space.Kind == address.SpaceKindStack {
		return
	}
	data.NewVarnodeOut(out.Size, out.Addr, fc.op)
}

// resolveLockedStackOffset derives the call's stack offset from a locked
// stack parameter's placeholder load.
// C++ parity: FuncCallSpecs::resolveSpacebaseRelative (isInputLocked branch).
func (fc *FuncCallSpecs) resolveLockedStackOffset(phvn *Varnode, spacebase *address.Space) bool {
	if !fc.IsInputLocked() || len(fc.lockedIn) == 0 {
		return false
	}
	slot := fc.op.GetSlot(phvn) - 1
	if slot < 0 || slot >= len(fc.lockedIn) {
		return false
	}
	off := fc.stackoffset - fc.lockedIn[slot].Addr.Offset
	fc.stackoffset = wrapSpaceOffset(spacebase, off)
	return true
}

// typeOpCall types call arguments and the return by the callee's locked
// prototype. C++ parity: typeop.cc TypeOpCall::getInputLocal/getOutputLocal.
type typeOpCall struct{ typeOpBase }

func (t *typeOpCall) InputTypeLocal(op *PcodeOp, slot int, tf *TypeFactory) Datatype {
	if fc := op.callSpec; slot > 0 && fc != nil && fc.IsInputLocked() {
		if p, ok := fc.LockedParam(slot - 1); ok && p.Type != nil &&
			p.Type.Metatype() != TYPE_VOID && p.Type.Size() <= op.Input(slot).Size() {
			return p.Type
		}
	}
	return t.typeOpBase.InputTypeLocal(op, slot, tf)
}

func (t *typeOpCall) OutputTypeLocal(op *PcodeOp, tf *TypeFactory) Datatype {
	if fc := op.callSpec; fc != nil && fc.IsOutputLocked() && fc.lockedOut != nil &&
		fc.lockedOut.Type != nil && fc.lockedOut.Type.Metatype() != TYPE_VOID {
		return fc.lockedOut.Type
	}
	return t.typeOpBase.OutputTypeLocal(op, tf)
}

// GetOutputToken must dispatch through typeOpCall's OutputTypeLocal.
// C++ parity: TypeOp::getOutputToken -> virtual getOutputLocal.
func (t *typeOpCall) GetOutputToken(op *PcodeOp, cs *CastStrategyC) Datatype {
	return t.OutputTypeLocal(op, cs.tlst)
}

// GetInputCast must dispatch through typeOpCall's InputTypeLocal.
func (t *typeOpCall) GetInputCast(op *PcodeOp, slot int, cs *CastStrategyC) Datatype {
	return baseGetInputCast(t, op, slot, cs)
}

// ApplyHostSelfPrototype locks the function's own prototype as the host
// stores it: the return value's storage and type, and each parameter's name
// and type (register parameters through the locked-parameter overlay, stack
// parameters as name- and type-locked frame symbols).
// C++ parity: the FunctionSymbol prototype DecompileCallback sends with the
// function (FuncProto::decode with input/output locks).
// TODO known mismatch: Go still derives the parameter list rather than
// creating it from the locked storage (ActionPrototypeTypes locked-input
// path), so a locked parameter the body never reads is not listed.
func (fd *Funcdata) ApplyHostSelfPrototype(model *ProtoModel) {
	if fd.hostScope == nil {
		return
	}
	hf, ok := fd.hostScope.QueryFunction(fd.baseAddr)
	if !ok || (!hf.InputLocked && !hf.OutputLocked) {
		return
	}
	fp := fd.GetFuncProto()
	if fp == nil {
		fp = NewFuncProto(model)
		fd.SetFuncProto(fp)
	}
	if hf.OutputLocked && hf.Output != nil && hf.Output.Type != nil {
		if sp := fd.spaceByName(hf.Output.Space); sp != nil {
			fp.SetLockedReturn(address.Address{Space: sp, Offset: hf.Output.Offset}, hf.Output.Size, hf.Output.Type)
			fp.SetOutputLock(true)
		}
	}
	if !hf.InputLocked {
		return
	}
	for _, p := range hf.Params {
		sp := fd.spaceByName(p.Space)
		if sp == nil {
			continue
		}
		if sp.Kind == address.SpaceKindStack {
			off := wrapSpaceOffset(sp, p.Offset)
			if fd.hostLocals == nil {
				fd.hostLocals = map[uint64]string{}
			}
			fd.hostLocals[off] = p.Name
			if p.Type != nil {
				if fd.hostLocalTypes == nil {
					fd.hostLocalTypes = map[uint64]Datatype{}
				}
				fd.hostLocalTypes[off] = p.Type
			}
			continue
		}
		if p.Type != nil {
			fp.SetLockedParamType(p.Offset, p.Type)
		}
		fp.SetLockedParamName(p.Offset, p.Name, true, false)
	}
	fd.SetHostLocals(fd.hostLocals)
}
