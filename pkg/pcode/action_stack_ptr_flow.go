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

// ActionStackPtrFlow converts LOAD(ram, INT_ADD(FP, offset)) patterns into
// COPY(stack_input_varnode) patterns, where FP is the function's frame pointer.
//
// The pattern matched for the frame pointer definition:
//   FP = COPY(INT_ADD(ESP_input, push_delta))  where push_delta < 0
//
// For x86-32 with PUSH EBP; MOV EBP,ESP:
//   push_delta = -4 (0xFFFFFFFC in 32-bit), so [EBP+8] = stack offset 4 = first param.
//
// After conversion, ScopeLocal.BuildFromVarnodes classifies the new stack-space
// input varnodes as parameters (offset >= ParamBaseOffset) or locals (large unsigned).
//
// A synthetic stack address space (SpaceKindStack, name "stack") is created when
// no existing stack space is found in the varnode bank.
//
// C++ parity: ActionStackPtrFlow::apply in coreaction.cc (simplified for x86-32)
type ActionStackPtrFlow struct {
	ActionBase
	// createdStackSpace is the synthetic stack address space built by Apply.
	// Nil until Apply runs and finds a frame-pointer pattern.
	createdStackSpace *address.Space
}

// NewActionStackPtrFlow constructs an ActionStackPtrFlow.
func NewActionStackPtrFlow(group string) *ActionStackPtrFlow {
	a := &ActionStackPtrFlow{}
	a.ActionBase = NewActionBase(a, ActionRuleOncePerFunc, "stackptrflow", group)
	return a
}

// StackSpace returns the stack address space created (or found) by Apply, or nil.
// The caller can use this to initialize ProtoModel.StackSpace before ApplyCallingConvention.
func (a *ActionStackPtrFlow) StackSpace() *address.Space {
	return a.createdStackSpace
}

// Clone derives a new ActionStackPtrFlow for the given group list.
func (a *ActionStackPtrFlow) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionStackPtrFlow(a.GetGroup())
}

// Reset clears the created stack space so Apply can re-run on a new function.
func (a *ActionStackPtrFlow) Reset(data *Funcdata) {
	a.createdStackSpace = nil
	a.ActionBase.Reset(data)
}

// Apply finds the frame pointer, creates stack-space input varnodes for each
// LOAD(ram, INT_ADD(FP, const)) access, and replaces each LOAD with COPY(stack_vn).
func (a *ActionStackPtrFlow) Apply(data *Funcdata) int {
	// Step 1: locate the frame pointer and its prologue push delta.
	fpVn, pushDelta, ok := findFramePointerDef(data)
	if !ok {
		return 0
	}

	// Step 2: ensure a stack address space exists.
	stackSpace := a.resolveStackSpace(data)

	// Step 3: replace each LOAD(ram, INT_ADD(FP, const)) with COPY(stack_input_vn).
	changed := 0
	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op.IsDead() || op.Code() != CPUI_LOAD {
			continue
		}
		if op.NumInput() < 2 || op.Output() == nil {
			continue
		}
		addrVn := op.Input(1)
		if addrVn == nil {
			continue
		}
		addOp := definedBy(addrVn, CPUI_INT_ADD)
		if addOp == nil || addOp.NumInput() < 2 {
			continue
		}
		// One input of INT_ADD must be the frame pointer; the other a constant.
		var accessConst *Varnode
		if addOp.Input(0) == fpVn && addOp.Input(1) != nil && addOp.Input(1).IsConstant() {
			accessConst = addOp.Input(1)
		} else if addOp.Input(1) == fpVn && addOp.Input(0) != nil && addOp.Input(0).IsConstant() {
			accessConst = addOp.Input(0)
		}
		if accessConst == nil {
			continue
		}

		// Compute stack offset: (frame-relative constant) + push_delta.
		// push_delta is negative (e.g. -4 for PUSH EBP), so [FP+8] -> offset 4.
		accessSigned := signExtendConst(accessConst)
		stackOffset := accessSigned + pushDelta

		// Encode as uint64. Negative offsets (locals) wrap as large unsigned values,
		// which IsLocalOffset() recognises as frame-negative slot addresses.
		var stackOffsetU uint64
		if stackOffset < 0 {
			// Sign-extended 32-bit representation: the pointer size of x86-32 is 4 bytes.
			// This matches Ghidra's ScopeLocal offset encoding for local variables.
			stackOffsetU = uint64(uint32(stackOffset))
		} else {
			stackOffsetU = uint64(stackOffset)
		}

		outSize := op.Output().Size()
		stackLoc := address.Address{Space: stackSpace, Offset: stackOffsetU}

		// Reuse an existing input varnode at this location when present.
		stackVn := data.GetVarnodeBank().FindInput(outSize, stackLoc)
		if stackVn == nil {
			stackVn = data.NewVarnode(outSize, stackLoc)
			data.SetInputVarnode(stackVn)
		}

		// Replace LOAD with COPY(stackVn). The old address operand chain
		// (INT_ADD → frame pointer) loses its consumer and becomes dead;
		// a subsequent ActionDeadCode pass will remove it.
		rewriteToCopy(data, op, stackVn)
		changed++
	}

	if changed > 0 {
		a.createdStackSpace = stackSpace
	}
	return changed
}

// resolveStackSpace returns an existing stack address space if one is already
// present in the varnode bank, otherwise creates a fresh synthetic space.
func (a *ActionStackPtrFlow) resolveStackSpace(data *Funcdata) *address.Space {
	if a.createdStackSpace != nil {
		return a.createdStackSpace
	}
	// Scan for an existing stack space in the current varnode bank.
	maxIdx := uint16(0)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		sp := vn.Space()
		if sp == nil {
			continue
		}
		if sp.Kind == address.SpaceKindStack || sp.Name == "stack" {
			return sp // reuse; do not create a duplicate
		}
		if sp.Index > maxIdx {
			maxIdx = sp.Index
		}
	}
	// No existing stack space: create one with an index above all real spaces.
	return &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		Index:    maxIdx + 1,
		AddrSize: 4,
		WordSize: 1,
	}
}

// findFramePointerDef locates the frame pointer varnode by scanning for the pattern:
//
//	FP = COPY(W)
//
// where W is defined by one of:
//   - INT_SUB(Z, push_size)   -- x86 Sleigh uses INT_SUB for PUSH (e.g. PUSH EBP)
//   - INT_ADD(Z, push_delta)  -- push_delta < 0 (alternative encoding)
//
// Z must be an input varnode (the function-entry stack pointer).
//
// Returns (fp_varnode, push_delta_signed, true) on success.
// push_delta_signed is negative (e.g. -4 for a 4-byte push on x86-32).
// C++ parity: ActionStackPtrFlow::checkCopyFrom in coreaction.cc
func findFramePointerDef(data *Funcdata) (*Varnode, int64, bool) {
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if !vn.IsWritten() {
			continue
		}
		copyOp := definedBy(vn, CPUI_COPY)
		if copyOp == nil || copyOp.NumInput() == 0 {
			continue
		}
		w := copyOp.Input(0)
		if w == nil {
			continue
		}

		// Case 1: W = INT_SUB(Z, push_amount) -- Sleigh x86 PUSH encoding.
		// Stack grows downward, so the delta is -push_amount.
		// The push_amount is not always in constant space (Sleigh may emit it as a
		// unique-space temp varnode). Use the frame pointer's own SIZE instead:
		// PUSH FP always decrements SP by exactly size-of-FP bytes.
		if subOp := definedBy(w, CPUI_INT_SUB); subOp != nil && subOp.NumInput() >= 2 {
			in0 := subOp.Input(0)
			if in0 != nil && in0.IsInput() && vn.Size() > 0 {
				// in1 is the push amount; we derive it from the FP register size.
				return vn, -int64(vn.Size()), true
			}
		}

		// Case 2: W = INT_ADD(Z, push_delta) -- alternative encoding with negative constant.
		if addOp := definedBy(w, CPUI_INT_ADD); addOp != nil && addOp.NumInput() >= 2 {
			var spIn, deltaConst *Varnode
			if addOp.Input(0) != nil && addOp.Input(0).IsInput() &&
				addOp.Input(1) != nil && addOp.Input(1).IsConstant() {
				spIn = addOp.Input(0)
				deltaConst = addOp.Input(1)
			} else if addOp.Input(1) != nil && addOp.Input(1).IsInput() &&
				addOp.Input(0) != nil && addOp.Input(0).IsConstant() {
				spIn = addOp.Input(1)
				deltaConst = addOp.Input(0)
			}
			if spIn != nil && deltaConst != nil {
				deltaSigned := signExtendConst(deltaConst)
				if deltaSigned < 0 {
					return vn, deltaSigned, true
				}
			}
		}
	}
	return nil, 0, false
}

// signExtendConst interprets a constant varnode's raw offset as a signed integer
// of the varnode's byte width, then zero-extends to int64.
func signExtendConst(vn *Varnode) int64 {
	raw := vn.Offset()
	size := vn.Size()
	if size == 0 || size >= 8 {
		return int64(raw)
	}
	bits := uint(size) * 8
	signBit := uint64(1) << (bits - 1)
	if raw&signBit != 0 {
		// Set all bits above position (bits-1) to replicate the sign bit.
		return int64(raw | (^uint64(0) << bits))
	}
	return int64(raw)
}
