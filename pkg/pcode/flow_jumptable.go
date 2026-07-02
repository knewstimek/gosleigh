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
	"errors"

	"gosleigh/pkg/address"
)

// This file ports Ghidra's raw-flow jump-table recovery driver and its failure
// fallback. In Ghidra these run inside FlowInfo::generateOps (flow.cc:785),
// before generateBlocks and before any Action: every BRANCHIND that cannot be
// resolved into a jump table is demoted to a CALLIND (or RETURN) so that
// heritage, parameter, and return-value recovery treat it as a call site. The
// demotion MUST complete before the action tree runs so the pass order matches
// Ghidra (see bridge.Build).

// ArtificialHalt creates a special RETURN op modelling a truncated/missing flow
// point. The op is a RETURN with a single constant input (offset 1); when a
// non-zero halt flag is supplied the RETURN is additionally tagged as that
// class of halt.
// C++ parity: flow.cc FlowInfo::artificialHalt (flow.cc:592).
func (fd *Funcdata) ArtificialHalt(addr address.Address, flag uint32) *PcodeOp {
	haltop := fd.NewOp(1, addr)
	fd.OpSetOpcode(haltop, CPUI_RETURN)
	fd.OpSetInput(haltop, fd.NewConstant(4, 1), 0)
	if flag != 0 {
		fd.OpMarkHalt(haltop, flag)
	}
	return haltop
}

// OpMarkHalt tags a RETURN op as a special halt of the given class.
// C++ parity: funcdata_op.cc Funcdata::opMarkHalt (funcdata_op.cc:37).
func (fd *Funcdata) OpMarkHalt(op *PcodeOp, flag uint32) {
	if op.Code() != CPUI_RETURN {
		panic("Only RETURN pcode ops can be marked as halt")
	}
	flag &= (PcodeOpHalt | PcodeOpBadInstruction | PcodeOpUnimplemented | PcodeOpNoReturn | PcodeOpMissing)
	if flag == 0 {
		panic("Bad halt flag")
	}
	op.SetFlag(flag)
}

// RecoverJumpTables drives jump-table recovery for every BRANCHIND op currently
// in the function. Each BRANCHIND is passed to recoverJumpTable; if recovery
// fails the op is truncated (demoted) via TruncateIndirectJump. Recovered
// tables are appended to the function's jump-table list for ActionSwitchNorm.
//
// This is the Gosleigh analog of the generateOps loop that repeatedly calls
// FlowInfo::recoverJumpTables. Ghidra runs it during raw flow generation before
// blocks are structured; Gosleigh runs it from bridge.Build after the block
// graph is built but before the action tree, which is still ahead of every
// Action and therefore order-faithful for the demotion the downstream passes
// observe.
// C++ parity: flow.cc FlowInfo::recoverJumpTables (flow.cc:1427) and the
// generateOps drive loop (flow.cc:785).
func (fd *Funcdata) RecoverJumpTables() {
	if fd == nil {
		return
	}
	// Snapshot the BRANCHIND ops first: TruncateIndirectJump mutates the op
	// bank (changes opcode, inserts a RETURN), so we must not iterate the live
	// list while mutating it.
	var tablelist []*PcodeOp
	for _, op := range fd.obank.AliveOps() {
		if op != nil && op.Code() == CPUI_BRANCHIND {
			tablelist = append(tablelist, op)
		}
	}
	for _, op := range tablelist {
		jt, mode := fd.recoverJumpTable(op)
		if jt == nil {
			// Could not recover the table: treat the indirect jump as a call.
			fd.TruncateIndirectJump(op, mode)
		}
	}
}

// linkJumpTable searches for a previously recovered jump table bound to op.
// C++ parity: funcdata_block.cc Funcdata::linkJumpTable (funcdata_block.cc:426).
func (fd *Funcdata) linkJumpTable(op *PcodeOp) *JumpTable {
	for _, jt := range fd.JumpTables() {
		if jt != nil && jt.OpAddress() == op.Addr() {
			return jt
		}
	}
	return nil
}

// recoverJumpTable attempts to recover the destination table for a BRANCHIND
// using the existing jump-table machinery (JumpTable.RecoverAddresses). It
// returns the recovered table on success, or nil plus the failure mode.
//
// This is the faithful "try, then fall back" gate required by the port: a
// BRANCHIND is only demoted when recovery genuinely fails. In the current
// single-.text harness recovery always fails (no reloc/.rdata means the table
// address computation cannot be emulated and the BRANCHIND's parent block has
// no out-edges), which is exactly why Ghidra itself falls through to fail_normal
// on the same input ("Could not emulate address calculation" in the golden). A
// future reloc-aware loader that lets recovery succeed will keep the recovered
// table here instead of demoting it -- no unconditional truncation.
//
// C++ parity: funcdata_block.cc Funcdata::recoverJumpTable (funcdata_block.cc:639).
//
// Known simplification: Ghidra's earlyJumpTableFail (fail_callother detection
// via CALLOTHER-in-flow backtracking) and testForReturnAddress (fail_return)
// are not ported. They depend on the pre-heritage def chain, which Gosleigh does
// not materialize at raw-flow time (cross-instruction reads are fresh, undefined
// varnodes). The genuine recovery attempt below still runs, so the "attempt,
// don't unconditionally truncate" invariant holds; only the failure-mode
// classification is narrowed to fail_thunk / fail_normal, which is correct for
// every jump table the current corpus and single-.text harness produce.
func (fd *Funcdata) recoverJumpTable(op *PcodeOp) (*JumpTable, JumpTableRecoveryMode) {
	// Reuse a previously recovered, complete (non-override, non-partial) table.
	if jt := fd.linkJumpTable(op); jt != nil {
		if !jt.IsOverride() && !jt.IsPartial() && jt.NumEntries() != 0 {
			return jt, JumpTableSuccess
		}
	}

	// First-stage recovery on the current partial flow.
	jt := NewJumpTable(op.Addr())
	jt.SetIndirectOp(op)
	err := jt.RecoverAddresses(fd)
	if err == nil && jt.NumEntries() != 0 {
		fd.AddJumpTable(jt)
		return jt, JumpTableSuccess
	}
	if errors.Is(err, JumptableThunkError) {
		return nil, JumpTableFailThunk
	}
	return nil, JumpTableFailNormal
}

// setupCallindSpecs makes sure a FuncCallSpecs exists for a freshly demoted
// CALLIND op and returns it. Ghidra's FlowInfo::setupCallindSpecs constructs the
// FuncCallSpecs eagerly and pushes it onto qlst (applying any override); Gosleigh
// builds the call-spec list lazily by scanning CALL/CALLIND ops, so here we force
// a rebuild and return the spec bound to op.
// C++ parity: flow.cc FlowInfo::setupCallindSpecs (flow.cc:704).
func (fd *Funcdata) setupCallindSpecs(op *PcodeOp) *FuncCallSpecs {
	fd.rebuildCallSpecs()
	for i := 0; i < fd.NumCalls(); i++ {
		fc := fd.GetCallSpecs(i)
		if fc != nil && fc.op == op {
			return fc
		}
	}
	return nil
}

// TruncateIndirectJump converts a BRANCHIND whose jump table could not be
// recovered into a call (or, for the return failure mode, a return). This is the
// structural fallback that turns `goto *(...)` into a CALLIND call site plus an
// artificial return, letting downstream heritage/parameter/return recovery model
// the indirect jump as a call.
// C++ parity: flow.cc FlowInfo::truncateIndirectJump (flow.cc:727).
func (fd *Funcdata) TruncateIndirectJump(op *PcodeOp, mode JumpTableRecoveryMode) {
	if mode == JumpTableFailReturn {
		fd.OpSetOpcode(op, CPUI_RETURN) // Turn jump into return
		fd.emitActionMessage("WARNING: Treating indirect jump as return")
		return
	}

	fd.OpSetOpcode(op, CPUI_CALLIND) // Turn jump into call
	fc := fd.setupCallindSpecs(op)

	var returnType uint32
	noParams := false
	switch mode {
	case JumpTableFailThunk:
		returnType = 0
		noParams = false
	case JumpTableFailCallOther:
		returnType = PcodeOpNoReturn
		fc.SetNoReturn(true)
		fd.emitActionMessage("WARNING: Does not return")
		noParams = true
	default: // fail_normal
		returnType = 0
		noParams = false
		fc.SetBadJumpTable(true) // Consider using special name for switch variable
		fd.emitActionMessage("WARNING: Treating indirect jump as call")
	}

	if noParams && fc != nil && !fc.HasModel() {
		// Ghidra locks a void, parameter-less internal prototype here. Gosleigh
		// records the default model with a nil (void) return type; a dedicated
		// void Datatype is not yet wired, but this branch is only reached for the
		// (currently unclassified) fail_callother mode.
		fc.SetInternal(fd.DefaultModel(), nil)
		fc.SetInputLocked(true)
		fc.SetOutputLock(true)
	}

	// Create an artificial return immediately after the call. In Ghidra this is
	// opDeadInsertAfter into the dead list (blocks form later); Gosleigh already
	// has structured blocks at this seam, so OpInsertAfter places the RETURN
	// right after the CALLIND in the same basic block -- the equivalent result.
	truncop := fd.ArtificialHalt(op.Addr(), returnType)
	fd.OpInsertAfter(truncop, op)

	// The per-op "Could not emulate address calculation" / warning comments that
	// Ghidra attaches via its Comment database are not rendered by PrintC yet
	// (comment DB unported), so those inline comments are a known residual
	// output diff, separate from the structural demotion done here.
}
