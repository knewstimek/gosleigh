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

	// Pointer width from the detected stack-pointer/frame varnode (RSP=8 on x64,
	// EBP/ESP=4 on x86-32). Drives the synthetic stack space width and the local
	// offset encoding below.
	ptrSize := fpVn.Size()
	if ptrSize <= 0 {
		ptrSize = 4
	}

	// Step 2: ensure a stack address space exists.
	stackSpace := a.resolveStackSpace(data, ptrSize)

	// Build the stack-pointer offset map from the detected base (fpVn at
	// entry-relative offset pushDelta) so that every stack-pointer-derived
	// varnode -- including ones produced by `sub rsp,N` after the base -- is
	// classified at its correct entry-relative offset. This replaces the prior
	// single-base FP matching and adds x64 frame support.
	offMap := buildStackOffsetMap(data, fpVn, pushDelta)

	// stackAddrOffset returns the encoded stack-space offset for a LOAD/STORE
	// address operand, or false if the address is not stack-pointer-relative.
	// Handles both a direct mapped base ([rsp]) and INT_ADD(base, const) ([rsp+k]),
	// with the constant either direct or via COPY(const).
	stackAddrOffset := func(addrVn *Varnode) (uint64, bool) {
		if d, ok := offMap[addrVn]; ok {
			return encodeStackSlotOffset(d, ptrSize), true
		}
		addOp := definedBy(addrVn, CPUI_INT_ADD)
		if addOp == nil || addOp.NumInput() < 2 {
			return 0, false
		}
		in0, in1 := addOp.Input(0), addOp.Input(1)
		if d, ok := offMap[in0]; ok {
			if c := resolveConstVarnode(in1); c != nil {
				return encodeStackSlotOffset(d+signExtendConst(c), ptrSize), true
			}
		}
		if d, ok := offMap[in1]; ok {
			if c := resolveConstVarnode(in0); c != nil {
				return encodeStackSlotOffset(d+signExtendConst(c), ptrSize), true
			}
		}
		return 0, false
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
		off, ok := stackAddrOffset(ptrVn)
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
		off, ok := stackAddrOffset(addrVn)
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
func (a *ActionStackPtrFlow) resolveStackSpace(data *Funcdata, ptrSize int32) *address.Space {
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
	// AddrSize follows the architecture pointer width (8 on x64, 4 on x86-32) so
	// the local/parameter offset threshold is computed against the right sign bit.
	if ptrSize <= 0 {
		ptrSize = 4
	}
	return &address.Space{
		Name:     "stack",
		Kind:     address.SpaceKindStack,
		Index:    maxIdx + 1,
		AddrSize: uint8(ptrSize),
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

// resolveConstVarnode resolves a varnode to a constant varnode, following one
// level of COPY(const) indirection. Sleigh often materializes a displacement as
// COPY(const) into a unique temp rather than as a direct constant operand.
func resolveConstVarnode(vn *Varnode) *Varnode {
	if vn == nil {
		return nil
	}
	if vn.IsConstant() {
		return vn
	}
	if cp := definedBy(vn, CPUI_COPY); cp != nil && cp.NumInput() > 0 &&
		cp.Input(0) != nil && cp.Input(0).IsConstant() {
		return cp.Input(0)
	}
	return nil
}

// buildStackOffsetMap propagates the entry-relative stack-pointer offset from a
// seed varnode (the detected frame base, at entry-SP-relative offset seedDelta)
// through COPY / INT_ADD(base,const) / INT_SUB(base,const) / MULTIEQUAL chains.
// The result maps each stack-pointer-derived varnode to its byte offset relative
// to the function-entry stack pointer.
//
// This generalizes both the x86-32 EBP frame (single base = EBP at delta -4) and
// the x64 RSP frame (rsp_input at 0 plus rsp_after = INT_SUB(rsp_input, framesize)
// at -framesize): MSVC x64 /Od spills register params before `sub rsp,N` (base =
// rsp_input) and accesses locals/params after it (base = rsp_after), so a single
// (base,delta) pair cannot describe both -- the map can.
//
// C++ parity: ActionStackPtrFlow propagates the stack pointer through arbitrary
// transforms via a TrackedSet; this is the const-offset subset of that.
func buildStackOffsetMap(data *Funcdata, seedVn *Varnode, seedDelta int64) map[*Varnode]int64 {
	m := map[*Varnode]int64{seedVn: seedDelta}
	for changed := true; changed; {
		changed = false
		for _, vn := range data.GetVarnodeBank().AllVarnodes() {
			if vn == nil {
				continue
			}
			if _, done := m[vn]; done {
				continue
			}
			op := vn.Def()
			if op == nil {
				continue
			}
			switch op.Code() {
			case CPUI_COPY:
				if op.NumInput() > 0 {
					if d, ok := m[op.Input(0)]; ok {
						m[vn] = d
						changed = true
					}
				}
			case CPUI_INT_ADD:
				if op.NumInput() >= 2 {
					in0, in1 := op.Input(0), op.Input(1)
					if d, ok := m[in0]; ok {
						if c := resolveConstVarnode(in1); c != nil {
							m[vn] = d + signExtendConst(c)
							changed = true
						}
					} else if d, ok := m[in1]; ok {
						if c := resolveConstVarnode(in0); c != nil {
							m[vn] = d + signExtendConst(c)
							changed = true
						}
					}
				}
			case CPUI_INT_SUB:
				// Only base - const (base in operand 0): stack pointer decrement.
				if op.NumInput() >= 2 {
					if d, ok := m[op.Input(0)]; ok {
						if c := resolveConstVarnode(op.Input(1)); c != nil {
							m[vn] = d - signExtendConst(c)
							changed = true
						}
					}
				}
			case CPUI_MULTIEQUAL:
				// A phi resolves to a stack offset only when every non-self input
				// is already mapped to the SAME offset (loop-carried SP that is not
				// re-adjusted in the body).
				off, agree, any := int64(0), true, false
				for i := 0; i < op.NumInput(); i++ {
					inp := op.Input(i)
					if inp == nil || inp == vn {
						continue
					}
					d, ok := m[inp]
					if !ok {
						agree = false
						break
					}
					if !any {
						off, any = d, true
					} else if d != off {
						agree = false
						break
					}
				}
				if agree && any {
					m[vn] = off
					changed = true
				}
			}
		}
	}
	return m
}

// encodeStackSlotOffset encodes an entry-relative signed stack offset into the
// uint64 stack-space offset ScopeLocal expects: small positive values stay as-is
// (parameter area); negative values (locals below the entry SP) wrap to a large
// unsigned value of the architecture pointer width, matching Ghidra's ScopeLocal
// local-offset encoding. The width matters because ScopeLocal's local/param
// threshold is the sign bit of the pointer width (0x80000000 for 4-byte pointers,
// 0x8000000000000000 for 8-byte): a 32-bit wrap on x64 (0xFFFFFFE8) falls below
// the 64-bit threshold and is misclassified as a parameter, not a local.
func encodeStackSlotOffset(signed int64, ptrSize int32) uint64 {
	if signed < 0 && ptrSize <= 4 {
		return uint64(uint32(signed))
	}
	// 8-byte pointers (and the non-negative case) use the full 64-bit value.
	return uint64(signed)
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
