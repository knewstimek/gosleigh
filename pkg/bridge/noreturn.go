package bridge

import (
	"errors"
	"fmt"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/sla"
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
		if op.Code() != pcode.CPUI_RETURN || op.NumInput() != 1 || op.HaltType() != 0 {
			continue // a translate halt after a call is already classed
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

// ErrTooManyInstructions is the flow exceeding BuildConfig.MaxInstructions
// while BuildConfig.ErrorTooManyInstructions is set.
var ErrTooManyInstructions = errors.New("Flow exceeded maximum allowable instructions")

// tooManyInstructionsError wraps ErrTooManyInstructions with the limit and
// how many of the collected paths ended at untranslatable bytes: many such
// halts usually mean the flow ran into junk bytes (obfuscation) rather than
// a genuinely large function.
func tooManyInstructionsError(limit int, records []instructionRecord) error {
	halts := 0
	for _, r := range records {
		if r.halt != 0 {
			halts++
		}
	}
	return fmt.Errorf("%w (limit %d; %d paths ended at undecodable bytes)", ErrTooManyInstructions, limit, halts)
}

// translateFailureHalt classes an instruction the engine could not translate.
// Ghidra decompiles through its Java host, whose getPcode turns every failure
// to produce p-code -- unknown bytes, unmapped memory, a disassembly conflict
// -- into an empty reply that the core raises as BadDataError; only p-code
// marked unimplemented raises UnimplError. Gosleigh reports failures to obtain
// a parser context (no bytes, no matching constructor state) as UnimplError
// too, so those are bad data here as well.
// C++ parity: GhidraTranslate::oneInstruction (ghidra_translate.cc:120) and
// DecompileCallback.getPcode.
func translateFailureHalt(err error) (uint32, string) {
	var badErr *sla.BadDataError
	if errors.As(err, &badErr) {
		return pcode.PcodeOpBadInstruction, "bad instruction"
	}
	var unimplErr *sla.UnimplError
	if errors.As(err, &unimplErr) && !errors.Is(err, sla.ErrObtainContextUnimplemented) {
		return pcode.PcodeOpUnimplemented, "unimplemented"
	}
	return pcode.PcodeOpBadInstruction, "bad instruction"
}

// haltTranslation is the one-byte instruction an artificial halt occupies in
// place of an untranslatable one.
// C++ parity: FlowInfo::processInstruction (step = 1) + artificialHalt.
func haltTranslation(at address.Address) sla.InstructionTranslation {
	return sla.InstructionTranslation{
		Address: at,
		Next:    at.Add(1),
		Length:  1,
		Ops: []pcode.RawOp{{SeqNum: pcode.SeqNum{Address: at}, OpCode: pcode.CPUI_RETURN,
			Inputs: []pcode.VarnodeData{{Space: nil, Offset: noReturnHaltValue, Size: 4}}}},
	}
}

// markTranslateHalts classes the halts haltTranslation stood in with and
// records Ghidra's warnings: one at each halt, one header per kind.
// C++ parity: FlowInfo::processInstruction (flow.cc:433-456).
func markTranslateHalts(fd *pcode.Funcdata, records []instructionRecord) {
	halts := map[address.Address]instructionRecord{}
	for _, r := range records {
		if r.halt != 0 {
			halts[r.translation.Address] = r
		}
	}
	if len(halts) == 0 {
		return
	}
	var bad, unimpl, oob bool
	for _, op := range fd.GetPcodeOpBank().AliveOps() {
		r, ok := halts[op.Addr()]
		if !ok || op.Code() != pcode.CPUI_RETURN {
			continue
		}
		flag := r.halt
		fd.OpMarkHalt(op, flag)
		if flag == pcode.PcodeOpMissing { // flow out of bounds (bounds.go)
			fd.Warning(r.note, op.Addr())
			if !oob {
				oob = true
				fd.WarningHeader("Function flows out of bounds")
			}
			continue
		}
		if flag == pcode.PcodeOpUnimplemented {
			fd.Warning("Unimplemented instruction - Truncating control flow here", op.Addr())
			if !unimpl {
				unimpl = true
				fd.SetFlag(pcode.FuncUnimplPresent) // Funcdata::followFlow
				fd.WarningHeader("Control flow encountered unimplemented instructions")
			}
			continue
		}
		fd.Warning("Bad instruction - Truncating control flow here", op.Addr())
		if !bad {
			bad = true
			fd.SetFlag(pcode.FuncBadDataPresent) // Funcdata::followFlow
			fd.WarningHeader("Control flow encountered bad instruction data")
		}
	}
}
