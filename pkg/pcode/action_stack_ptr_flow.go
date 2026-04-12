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
	// stackSlots records each unique (offset, size) stack slot converted during Apply.
	// Callers use this to run slot-by-slot Heritage SSA after Apply completes.
	stackSlots []stackSlotKey
}

// stackSlotKey identifies a unique stack slot by its space offset and byte size.
type stackSlotKey struct {
	offset uint64
	size   int32
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

// StackSlots returns the list of (offset, size) pairs for each distinct stack slot
// converted during Apply. Callers use this to run slot-by-slot Heritage SSA.
// Returns nil if Apply has not been called or found no frame-pointer pattern.
func (a *ActionStackPtrFlow) StackSlots() []address.Address {
	if a.createdStackSpace == nil || len(a.stackSlots) == 0 {
		return nil
	}
	addrs := make([]address.Address, len(a.stackSlots))
	for i, slot := range a.stackSlots {
		addrs[i] = address.Address{Space: a.createdStackSpace, Offset: slot.offset}
	}
	return addrs
}

// StackSlotSizes returns corresponding byte sizes for each slot in StackSlots().
func (a *ActionStackPtrFlow) StackSlotSizes() []int32 {
	sizes := make([]int32, len(a.stackSlots))
	for i, slot := range a.stackSlots {
		sizes[i] = slot.size
	}
	return sizes
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
	a.stackSlots = nil
	a.ActionBase.Reset(data)
}

// Apply finds the frame pointer, creates stack-space varnodes for each
// LOAD(ram, INT_ADD(FP, const)) and STORE(ram, INT_ADD(FP, const), val) access.
//
// LOADs become COPY(stack_input_vn): the stack varnode is an INPUT so Heritage
// can later rename it via SSA.
//
// STOREs become COPY(val) with a new stack_out_vn as output: this makes the
// write visible to Heritage SSA renaming, which inserts MULTIEQUAL (phi) nodes
// at loop headers and propagates definitions through the CFG.
//
// Callers that want Heritage to cover the stack space must pass spf.StackSpace()
// to the Heritage constructor after this Apply completes.
//
// C++ parity: ActionStackPtrFlow::apply in coreaction.cc (simplified for x86-32).
// The C++ version runs before Heritage so Heritage handles stack SSA natively;
// Gosleigh replicates this by requiring callers to run Heritage after Apply.
func (a *ActionStackPtrFlow) Apply(data *Funcdata) int {
	// Step 1: locate the frame pointer and its prologue push delta.
	// Fall back to frameless detection when no EBP-style frame is found.
	// Frameless functions (e.g. MSVC /O1 leaf functions) access params via
	// [ESP+4], [ESP+8], ... without a PUSH EBP; MOV EBP,ESP prologue.
	fpVn, pushDelta, ok := findFramePointerDef(data)
	if !ok {
		fpVn, pushDelta, ok = findFramelessStackPointer(data)
		if !ok {
			return 0
		}
	}

	// Step 2: ensure a stack address space exists.
	stackSpace := a.resolveStackSpace(data)

	// stackOffset computes the normalised stack-space offset from a frame-relative
	// constant. push_delta is negative (e.g. -4 for PUSH EBP on x86-32), so
	// [FP+8] → offset 4 (first parameter), [FP-4] → 0xFFFFFFFC (first local).
	stackOffsetFor := func(accessConst *Varnode) (uint64, bool) {
		accessSigned := signExtendConst(accessConst)
		stackOffset := accessSigned + pushDelta
		// Encode as uint64. Negative locals wrap as large unsigned values which
		// IsLocalOffset() treats as frame-negative slot addresses.
		if stackOffset < 0 {
			// Sign-extend to 32-bit then zero-extend to 64-bit: matches Ghidra
			// ScopeLocal offset encoding for local variables on x86-32.
			return uint64(uint32(stackOffset)), true
		}
		return uint64(stackOffset), true
	}

	// resolveConst resolves a varnode to a constant, following one level of
	// COPY(const) indirection. Sleigh often emits offsets as COPY(const) into a
	// unique-space temp rather than as direct constants in the INT_ADD operand.
	resolveConst := func(vn *Varnode) *Varnode {
		if vn == nil {
			return nil
		}
		if vn.IsConstant() {
			return vn
		}
		// One-level COPY(const) through unique space.
		cpOp := definedBy(vn, CPUI_COPY)
		if cpOp != nil && cpOp.NumInput() > 0 && cpOp.Input(0) != nil && cpOp.Input(0).IsConstant() {
			return cpOp.Input(0)
		}
		return nil
	}

	// isFPAdd returns true when addrVn is defined by INT_ADD(FP, const) or
	// INT_ADD(const, FP), where the constant may be direct or via COPY(const).
	// Sleigh x86 typically emits frame-relative addresses as:
	//   unique_tmp = COPY(const_offset)   ; separate COPY for the displacement
	//   addr_tmp   = INT_ADD(EBP, unique_tmp)
	// so we follow one COPY indirection when the direct operand is not a constant.
	isFPAdd := func(addrVn *Varnode) (*Varnode, bool) {
		addOp := definedBy(addrVn, CPUI_INT_ADD)
		if addOp == nil || addOp.NumInput() < 2 {
			return nil, false
		}
		in0, in1 := addOp.Input(0), addOp.Input(1)
		if in0 == fpVn {
			if c := resolveConst(in1); c != nil {
				return c, true
			}
		}
		if in1 == fpVn {
			if c := resolveConst(in0); c != nil {
				return c, true
			}
		}
		return nil, false
	}

	changed := 0

	// Step 3: convert STORE(ram, INT_ADD(FP, const), val) into a COPY with a
	// stack-space output varnode. This makes the definition visible to Heritage SSA.
	// STORE layout: input0 = space annotation, input1 = pointer, input2 = value.
	//
	// We collect ops to transform first because modifying the op list while
	// iterating it is not safe.
	type storeRecord struct {
		op          *PcodeOp
		stackOffset uint64
		val         *Varnode
	}
	var storesToConvert []storeRecord

	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op.IsDead() || op.Code() != CPUI_STORE {
			continue
		}
		// STORE requires 3 inputs: annotation, pointer, value.
		if op.NumInput() < 3 {
			continue
		}
		ptrVn := op.Input(1)
		valVn := op.Input(2)
		if ptrVn == nil || valVn == nil {
			continue
		}
		accessConst, ok := isFPAdd(ptrVn)
		if !ok {
			continue
		}
		off, ok := stackOffsetFor(accessConst)
		if !ok {
			continue
		}
		storesToConvert = append(storesToConvert, storeRecord{op, off, valVn})
	}

	// seenSlot tracks (offset, size) pairs already recorded to avoid duplicates.
	type slotKey struct {
		offset uint64
		size   int32
	}
	seenSlot := make(map[slotKey]bool)
	recordSlot := func(off uint64, sz int32) {
		k := slotKey{off, sz}
		if !seenSlot[k] {
			seenSlot[k] = true
			a.stackSlots = append(a.stackSlots, stackSlotKey{off, sz})
		}
	}

	for _, rec := range storesToConvert {
		op := rec.op
		valVn := rec.val
		stackLoc := address.Address{Space: stackSpace, Offset: rec.stackOffset}
		size := valVn.Size()
		if size == 0 {
			size = 4 // default to pointer size on x86-32
		}

		// Build: stack_out_vn = COPY(valVn) to replace STORE.
		// STORE has no output; we introduce a new COPY op with a stack-space output.
		// The COPY is inserted before the STORE then the STORE is destroyed.
		newOp := data.NewOp(1, op.Addr())
		data.OpSetOpcode(newOp, CPUI_COPY)
		stackOutVn := data.NewVarnodeOut(size, stackLoc, newOp)
		// Mark the output as an active-heritage varnode so Heritage SSA renaming
		// treats it as a definition for this stack slot.
		stackOutVn.SetActiveHeritage()
		data.OpSetInput(newOp, valVn, 0)
		data.OpInsertBefore(newOp, op)

		// Disconnect and destroy the original STORE.
		data.OpDestroy(op)
		recordSlot(rec.stackOffset, size)
		changed++
	}

	// Step 4: replace each LOAD(ram, INT_ADD(FP, const)) with COPY(stack_input_vn).
	// Collect before iterating for the same reason as STOREs above.
	type loadRecord struct {
		op          *PcodeOp
		stackOffset uint64
		outSize     int32
	}
	var loadsToConvert []loadRecord

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
		accessConst, ok := isFPAdd(addrVn)
		if !ok {
			continue
		}
		off, ok := stackOffsetFor(accessConst)
		if !ok {
			continue
		}
		loadsToConvert = append(loadsToConvert, loadRecord{op, off, op.Output().Size()})
	}

	for _, rec := range loadsToConvert {
		op := rec.op
		stackLoc := address.Address{Space: stackSpace, Offset: rec.stackOffset}

		// Create a fresh input varnode per LOAD rather than reusing an existing one.
		// Heritage SSA renaming uses the IsActiveHeritage flag as a one-shot marker:
		// it clears the flag on the first use to avoid double-processing. If multiple
		// LOAD COPYs share the same input varnode, only the first gets renamed.
		// Each LOAD must therefore own an independent varnode so Heritage can rename
		// each one independently to its reaching definition.
		// C++ parity: Ghidra's collect/normalizeRead ensures each read is a distinct
		// varnode before setActiveHeritage is called in placeMultiequals.
		stackVn := data.NewVarnode(rec.outSize, stackLoc)
		data.SetInputVarnode(stackVn)
		// Mark as active-heritage so Heritage SSA rename replaces it with the
		// reaching definition for this stack slot.
		stackVn.SetActiveHeritage()

		// Replace LOAD with COPY(stackVn). The old address operand chain
		// (INT_ADD → frame pointer) loses its consumer and is removed by
		// a subsequent ActionDeadCode pass.
		rewriteToCopy(data, op, stackVn)
		recordSlot(rec.stackOffset, rec.outSize)
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

// findFramelessStackPointer detects a frameless function where the entry stack
// pointer register is used directly as a base for LOAD/STORE address computations.
// A frameless function (e.g. MSVC /O1 leaf function with no saved EBP) accesses
// parameters via [ESP+4], [ESP+8], etc. without a PUSH EBP; MOV EBP,ESP prologue.
//
// The heuristic scans all LOAD/STORE ops for INT_ADD(reg_input, positive_const)
// patterns. If exactly one register-space input varnode is found as such a base,
// it is returned as the "frame pointer" with pushDelta=0. With delta=0, the
// stackOffsetFor mapping in Apply gives: [ESP+4] -> offset 4, [ESP+8] -> offset 8,
// which the calling convention classifies as first/second parameter respectively.
//
// C++ parity: ActionStackPtrFlow full implementation uses TrackedSet to propagate
// the stack pointer through arbitrary transforms; here we use a single-base scan
// that covers the common frameless leaf-function pattern.
func findFramelessStackPointer(data *Funcdata) (*Varnode, int64, bool) {
	var candidate *Varnode

	for _, op := range data.GetPcodeOpBank().AllOps() {
		if op.IsDead() {
			continue
		}
		code := op.Code()
		if code != CPUI_LOAD && code != CPUI_STORE {
			continue
		}
		// Both LOAD and STORE have the address in input(1).
		if op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		addrVn := op.Input(1)
		addOp := definedBy(addrVn, CPUI_INT_ADD)
		if addOp == nil || addOp.NumInput() < 2 {
			continue
		}
		// Look for INT_ADD(reg_input, positive_const) -- direct or slot-swapped.
		in0, in1 := addOp.Input(0), addOp.Input(1)
		var regBase *Varnode
		if in0 != nil && in0.IsInput() && in0.Space() != nil &&
			in0.Space().Kind == address.SpaceKindProcessor &&
			in1 != nil && in1.IsConstant() && int64(in1.Offset()) > 0 {
			regBase = in0
		} else if in1 != nil && in1.IsInput() && in1.Space() != nil &&
			in1.Space().Kind == address.SpaceKindProcessor &&
			in0 != nil && in0.IsConstant() && int64(in0.Offset()) > 0 {
			regBase = in1
		}
		if regBase == nil {
			continue
		}
		if candidate == nil {
			candidate = regBase
		} else if candidate != regBase {
			// Multiple distinct register bases -- not a simple frameless fn.
			return nil, 0, false
		}
	}

	if candidate == nil {
		return nil, 0, false
	}
	return candidate, 0, true
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
