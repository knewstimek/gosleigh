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
)

// FuncProto holds the calling convention information attached to a single
// function. It references a ProtoModel for ABI rules and records the
// high-level parameter/local variable assignments.
//
// C++ parity: funcdata.hh FuncProto (partial)
type FuncProto struct {
	model *ProtoModel

	// params holds the discovered parameter HighVariables in order.
	params []*HighVariable
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
	anchorReturnReg(fd, model)
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

// anchorReturnReg wires the return-register varnode that is live at each
// RETURN op into that op as an additional input.  The register is identified
// by (model.ReturnRegSpaceIndex, model.ReturnRegOffset, model.ReturnRegSize).
//
// Strategy (per RETURN op):
//  1. Prefer a written varnode defined in the SAME block as the RETURN op.
//     That varnode is guaranteed to be the live value at the return site.
//  2. Fall back to the written varnode with the latest SeqNum -- a good
//     approximation of "live at RETURN" when no same-block write exists
//     (e.g. a function with a single merge phi right before the exit block).
//
// A global "prefer any MULTIEQUAL" heuristic is wrong for loops: the
// loop-header phi (e.g. phi_eax at the loop condition block) would be chosen
// even though a later plain write (e.g. EAX = LOAD [EBP-8] in the exit block)
// is the actual return value.  Wiring the wrong phi as a RETURN input keeps it
// alive through DeadCode, preventing inlining of the increment expression.
//
// C++ parity: ActionPrototypeTypes::apply() resolves per-site live values via
// Heritage dominance; this per-RETURN selection approximates that behaviour.
func anchorReturnReg(fd *Funcdata, model *ProtoModel) {
	retSize := model.ReturnRegSize
	retOffset := model.ReturnRegOffset
	retSpaceIdx := model.ReturnRegSpaceIndex

	// Collect all written varnodes at the return-register location.
	var candidates []*Varnode
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil {
			continue
		}
		if int(vn.Space().Index) != retSpaceIdx {
			continue
		}
		if vn.Offset() != retOffset || vn.Size() != retSize {
			continue
		}
		if vn.IsWritten() && vn.Def() != nil {
			candidates = append(candidates, vn)
		}
	}
	if len(candidates) == 0 {
		return
	}

	// For each RETURN op, select the best candidate and wire it in.
	for _, op := range fd.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() || op.Code() != CPUI_RETURN {
			continue
		}
		retBlock := op.Parent()

		// Pass 1: prefer a candidate defined in the same block as this RETURN.
		// Among same-block candidates, pick the latest by SeqNum: the last write
		// in the block is the one still live when RETURN executes.
		var best *Varnode
		for _, vn := range candidates {
			if vn.Def().Parent() == retBlock {
				if best == nil || SeqNumLess(best.Def().Seq(), vn.Def().Seq()) {
					best = vn
				}
			}
		}
		// Pass 2: fall back to latest SeqNum among all candidates.
		// Handles functions where the return value is a phi merge in a
		// predecessor block (e.g. abs: phi_eax in the merge block before RETURN).
		if best == nil {
			for _, vn := range candidates {
				if best == nil || SeqNumLess(best.Def().Seq(), vn.Def().Seq()) {
					best = vn
				}
			}
		}
		if best == nil {
			continue
		}
		// Skip if best is already wired into this RETURN.
		alreadyWired := false
		for i := 0; i < op.NumInput(); i++ {
			if op.Input(i) == best {
				alreadyWired = true
				break
			}
		}
		if alreadyWired {
			continue
		}
		slot := op.NumInput()
		op.SetNumInputs(slot + 1)
		fd.OpSetInput(op, best, slot)
	}
}
