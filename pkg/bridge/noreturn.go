package bridge

import (
	"gosleigh/pkg/pcode"
	"gosleigh/pkg/sla"
)

// noReturnHaltValue is the constant input of an artificial halt RETURN.
// C++ parity: FlowInfo::artificialHalt (RETURN #1).
const noReturnHaltValue = 1

// haltAfterNoReturnCall ends the flow at a call whose callee never returns:
// an artificial halt RETURN is placed right after the CALL, so nothing falls
// through it (markNoReturnHalts flags it and records the warning).
// C++ parity: FlowInfo::checkForFlowModification (isNoReturn branch).
func haltAfterNoReturnCall(tr sla.InstructionTranslation, host pcode.HostScope) sla.InstructionTranslation {
	if host == nil {
		return tr
	}
	for i, op := range tr.Ops {
		if op.OpCode != pcode.CPUI_CALL || len(op.Inputs) == 0 || op.Inputs[0].Space == nil {
			continue
		}
		hf, ok := host.QueryFunction(op.Inputs[0].Address())
		if !ok || !hf.NoReturn {
			continue
		}
		halt := pcode.RawOp{SeqNum: op.SeqNum, OpCode: pcode.CPUI_RETURN,
			Inputs: []pcode.VarnodeData{{Space: nil, Offset: noReturnHaltValue, Size: 4}}}
		last := tr.Ops[len(tr.Ops)-1].SeqNum
		halt.SeqNum.Order = last.Order + 1
		halt.SeqNum.Time = last.Time + 1
		// Anything after the halt in this instruction (e.g. the RETURN a
		// CALL_RETURN override appended) is unreachable; C++ ends up with
		// the halt alone.
		ops := append([]pcode.RawOp(nil), tr.Ops[:i+1]...)
		tr.Ops = append(ops, halt)
		return tr
	}
	return tr
}

// markNoReturnHalts flags the halts haltAfterNoReturnCall inserted and adds
// the "Subroutine does not return" warning at each call.
// C++ parity: FlowInfo::artificialHalt (opMarkHalt noreturn) +
// checkForFlowModification's data.warning.
func markNoReturnHalts(fd *pcode.Funcdata) {
	for _, op := range fd.GetPcodeOpBank().AliveOps() {
		if op.Code() != pcode.CPUI_RETURN || op.NumInput() != 1 {
			continue
		}
		in := op.Input(0)
		if !in.IsConstant() || in.Offset() != noReturnHaltValue || in.Size() != 4 {
			continue
		}
		prev := op.PreviousOp()
		if prev == nil || prev.Code() != pcode.CPUI_CALL {
			continue
		}
		fd.OpMarkHalt(op, pcode.PcodeOpNoReturn)
		fd.Warning("Subroutine does not return", prev.Addr())
	}
}

// directExternalCall turns a call through an import slot (CALLIND of the
// slot's contents) into a direct CALL of the external function the host
// knows at the slot, so its prototype applies from the start.
// C++ reaches the same state through ActionDeindirect: FuncCallSpecs::
// deindirect installs an indirect override and, when the external's locked
// prototype does not fit the recovered trials, restarts the decompilation
// with the call already resolved. Gosleigh has no restart, so it resolves the
// call before flow.
func directExternalCall(tr sla.InstructionTranslation, host pcode.HostScope) sla.InstructionTranslation {
	if host == nil {
		return tr
	}
	for i, op := range tr.Ops {
		if op.OpCode != pcode.CPUI_CALLIND || len(op.Inputs) == 0 {
			continue
		}
		target := op.Inputs[0]
		var slot *pcode.VarnodeData
		for j := i - 1; j >= 0; j-- {
			d := tr.Ops[j]
			if d.Output == nil || *d.Output != target {
				continue
			}
			if d.OpCode == pcode.CPUI_COPY && len(d.Inputs) == 1 && d.Inputs[0].Space != nil && !d.Inputs[0].Space.IsConstant() {
				in := d.Inputs[0]
				slot = &in
			}
			break
		}
		if slot == nil {
			return tr
		}
		at := slot.Address()
		if _, ok := host.QueryExternalRef(at); !ok {
			return tr
		}
		if _, ok := host.QueryFunction(at); !ok {
			return tr
		}
		ops := append([]pcode.RawOp(nil), tr.Ops...)
		ops[i].OpCode = pcode.CPUI_CALL
		ops[i].Inputs = append([]pcode.VarnodeData(nil), op.Inputs...)
		ops[i].Inputs[0] = pcode.VarnodeData{Space: slot.Space, Offset: slot.Offset, Size: 1}
		tr.Ops = ops
		return tr
	}
	return tr
}
