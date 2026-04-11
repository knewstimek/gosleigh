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
	"sort"

	"gosleigh/pkg/address"
)

// stackSpaceKind returns the SpaceKind used for stack address spaces.
func stackSpaceKind() address.SpaceKind { return address.SpaceKindStack }

// ScopeLocal manages the mapping from low-level Varnodes to named high-level
// symbols (parameters and locals) within a single function scope.
//
// C++ parity: funcdata.hh ScopeLocal (partial)
type ScopeLocal struct {
	model *ProtoModel

	// paramByVn maps a stack input varnode to its HighVariable.
	paramByVn map[*Varnode]*HighVariable
	// localByVn maps a stack local varnode to its HighVariable.
	localByVn map[*Varnode]*HighVariable
}

// NewScopeLocal creates an empty ScopeLocal for the given calling convention.
// C++ parity: ScopeLocal::ScopeLocal
func NewScopeLocal(model *ProtoModel) *ScopeLocal {
	return &ScopeLocal{
		model:     model,
		paramByVn: make(map[*Varnode]*HighVariable),
		localByVn: make(map[*Varnode]*HighVariable),
	}
}

// ResetLocalWindow clears all symbol assignments.
// C++ parity: ScopeLocal::resetLocalWindow
func (sl *ScopeLocal) ResetLocalWindow() {
	if sl == nil {
		return
	}
	sl.paramByVn = make(map[*Varnode]*HighVariable)
	sl.localByVn = make(map[*Varnode]*HighVariable)
}

// BuildFromVarnodes scans all varnodes, classifies register-space and stack-space
// ones as params or locals, creates HighVariables for each, and populates both
// ScopeLocal and FuncProto.
//
// Naming convention:
//   - Register parameters (x86-64 ABI): register-space varnodes whose byte offset
//     matches a known IntegerRegParam slot -> param_0, param_1, ... in ABI order.
//   - Stack parameters: small positive stack offsets (>= paramBaseOffset) ->
//     param_N where N starts after register param count, sorted ascending by offset.
//   - Locals: large unsigned stack offsets (>= localThreshold, negative frame offsets)
//     -> local_0, local_1, ... sorted descending by offset.
//
// When RegParamOffsets is nil/empty (x86-32 stack-only ABI), the register param
// loop is a no-op and stack params are numbered from 0 -- identical to prior behavior.
//
// C++ parity: ScopeLocal::buildFromVarnodes / ScopeLocal::restructureHigh
func (sl *ScopeLocal) BuildFromVarnodes(varnodes []*Varnode, fp *FuncProto) {
	if sl == nil || sl.model == nil {
		return
	}

	// --- Register parameters (x86-64 SysV / Win64 ABI) ---
	// Collect register-space varnodes that match a known integer param register.
	// Each slot is tracked by param index so duplicates are collapsed and order
	// is determined by the ABI slot index (not varnode discovery order).
	type regParamSlot struct {
		vn  *Varnode
		idx int
	}
	var regParamSlots []regParamSlot
	seenRegIdx := make(map[int]bool)

	if len(sl.model.RegParamOffsets) > 0 {
		// Two-pass: first pick isinput=true varnodes (function live-ins),
		// then fall back to any written varnode if no input was found.
		// This prevents a written copy of the register (e.g. INT_ADD output
		// stored back into X0) from displacing the actual parameter input.
		// C++ parity: ScopeLocal uses Heritage input varnodes (isInput()) for param slots.
		type candidate struct {
			vn      *Varnode
			isInput bool
		}
		best := make(map[int]candidate) // paramIdx -> best candidate so far
		for _, vn := range varnodes {
			if vn == nil || vn.Space() == nil {
				continue
			}
			if !isRegisterSpace(vn) {
				continue
			}
			idx, ok := sl.model.IsRegParam(vn.Offset())
			if !ok {
				continue
			}
			cur, exists := best[idx]
			if !exists {
				best[idx] = candidate{vn, vn.IsInput()}
			} else if !cur.isInput && vn.IsInput() {
				// Upgrade to the input varnode -- it is the true function parameter.
				best[idx] = candidate{vn, true}
			}
		}
		for idx, c := range best {
			if seenRegIdx[idx] {
				continue
			}
			seenRegIdx[idx] = true
			regParamSlots = append(regParamSlots, regParamSlot{c.vn, idx})
		}
		// Sort by ABI index so param_0 always matches the first argument register.
		sort.Slice(regParamSlots, func(i, j int) bool {
			return regParamSlots[i].idx < regParamSlots[j].idx
		})
	}

	// Create HighVariables for register parameters.
	// Assign a concrete TYPE_INT type based on register size so the parameter is
	// rendered as "int" / "long" rather than "undefined%d".
	// C++ parity: Ghidra infers param types from the ABI model (ParameterSymbol);
	// Ghidra defaults to signed integer for register params (e.g. AArch64 X0 -> long).
	// TYPE_INT produces "int" (4 bytes) or "long" (8 bytes) via normalizedBaseType.
	regParamCount := len(regParamSlots)
	for _, slot := range regParamSlots {
		name := GetParamName(slot.idx)
		hv := NewHighVariable(name)
		hv.AddInstance(slot.vn)
		sl.paramByVn[slot.vn] = hv
		// Seed a concrete signed type onto the varnode so normalizedBaseType
		// renders it as "int" / "long" (not "undefined%d").
		// C++ parity: Ghidra uses TYPE_INT for register params when no explicit
		// type is known from the prototype; "long" = 8-byte signed on LP64.
		if slot.vn.Type() == nil {
			sz := slot.vn.Size()
			if sz <= 0 {
				sz = 4
			}
			SetVarnodeType(slot.vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
		}
		if fp != nil {
			fp.AddParam(hv)
		}
	}

	// --- Stack parameters and locals ---
	var paramEntries []stackEntry
	var localEntries []stackEntry

	for _, vn := range varnodes {
		if vn == nil || vn.Space() == nil {
			continue
		}
		// Only examine stack-space varnodes.
		if !isStackSpace(vn, sl.model) {
			continue
		}
		if sl.model.IsParamOffset(vn.Offset()) {
			// Input varnodes in the param range are parameters.
			// Also accept written varnodes in the param range -- after Heritage,
			// stack params often appear as both input and written.
			paramEntries = append(paramEntries, stackEntry{vn, vn.Offset()})
		} else if sl.model.IsLocalOffset(vn.Offset()) {
			localEntries = append(localEntries, stackEntry{vn, vn.Offset()})
		}
	}

	// Deduplicate by offset: keep only the first varnode seen per offset
	// (stack varnodes at the same offset are aliases; one name is enough).
	paramEntries = deduplicateByOffset(paramEntries)
	localEntries = deduplicateByOffset(localEntries)

	// Sort params ascending by offset: offset 8 < 16 < 24 -> param_N, param_N+1, ...
	sort.Slice(paramEntries, func(i, j int) bool {
		return paramEntries[i].offset < paramEntries[j].offset
	})

	// Sort locals descending by offset: 0xfffffffc > 0xfffffff8 -> local_0, local_1, ...
	// This matches Ghidra's frame layout where the first local below the frame pointer is local_0.
	sort.Slice(localEntries, func(i, j int) bool {
		return localEntries[i].offset > localEntries[j].offset
	})

	// Create HighVariables for stack params.
	// Stack param numbering starts AFTER register params so the combined
	// param_0..param_N sequence is contiguous and ABI-ordered.
	for i, e := range paramEntries {
		name := GetParamName(regParamCount + i)
		hv := NewHighVariable(name)
		hv.AddInstance(e.vn)
		sl.paramByVn[e.vn] = hv
		if fp != nil {
			fp.AddParam(hv)
		}
	}

	// Create HighVariables for locals.
	for i, e := range localEntries {
		name := GetLocalName(i)
		hv := NewHighVariable(name)
		hv.AddInstance(e.vn)
		sl.localByVn[e.vn] = hv
		if fp != nil {
			fp.AddLocal(hv)
		}
	}

	// Propagate float type from Varnode to HighVariable.
	// If any instance varnode of a HighVariable has TYPE_FLOAT type,
	// set the HighVariable type to float.
	// C++ parity: ScopeLocal::restructureHigh (float subset)
	for _, hv := range sl.localByVn {
		for _, inst := range hv.Instances() {
			dt := inst.TypeDefFacing()
			if dt != nil {
				if base, ok := dt.(*Base); ok && base.Metatype() == TYPE_FLOAT {
					hv.SetType(dt)
					break
				}
			}
		}
	}
	for _, hv := range sl.paramByVn {
		for _, inst := range hv.Instances() {
			dt := inst.TypeDefFacing()
			if dt != nil {
				if base, ok := dt.(*Base); ok && base.Metatype() == TYPE_FLOAT {
					hv.SetType(dt)
					break
				}
			}
		}
	}
}

// FindEntry returns the HighVariable associated with the given varnode, if any.
// C++ parity: ScopeLocal::findEntry
func (sl *ScopeLocal) FindEntry(vn *Varnode) *HighVariable {
	if sl == nil || vn == nil {
		return nil
	}
	if hv, ok := sl.paramByVn[vn]; ok {
		return hv
	}
	if hv, ok := sl.localByVn[vn]; ok {
		return hv
	}
	return nil
}

// isRegisterSpace reports whether vn lives in the register address space.
// In Ghidra's model, the register space is a processor-kind space named "register".
// We match by name because SpaceKindProcessor is also used for general RAM spaces.
// C++ parity: AddrSpace::getName() == "register" check in ScopeLocal
func isRegisterSpace(vn *Varnode) bool {
	if vn == nil || vn.Space() == nil {
		return false
	}
	return vn.Space().Name == "register"
}

// isStackSpace reports whether vn lives in the stack address space according
// to model. Uses SpaceKindStack kind or name=="stack" as fallback.
// C++ parity: Varnode::getSpaceFromConst / ScopeLocal::buildFromVarnodes
func isStackSpace(vn *Varnode, model *ProtoModel) bool {
	if vn == nil || vn.Space() == nil {
		return false
	}
	if model.StackSpace != nil {
		// Exact pointer match first.
		if vn.Space() == model.StackSpace {
			return true
		}
		// Name match as secondary (different pointer to same logical space).
		if vn.Space().Name == model.StackSpace.Name && model.StackSpace.Name != "" {
			return true
		}
	}
	// Fallback: match by SpaceKind or name.
	if vn.Space().Kind == stackSpaceKind() {
		return true
	}
	return vn.Space().Name == "stack"
}

// deduplicateByOffset removes duplicate stack entries that share the same offset.
// The first entry at each offset is kept (arbitrary but deterministic).
func deduplicateByOffset(entries []stackEntry) []stackEntry {
	if len(entries) == 0 {
		return entries
	}
	seen := make(map[uint64]struct{}, len(entries))
	out := entries[:0]
	for _, e := range entries {
		if _, exists := seen[e.offset]; exists {
			continue
		}
		seen[e.offset] = struct{}{}
		out = append(out, e)
	}
	return out
}

// stackEntry is a local helper type used in BuildFromVarnodes.
type stackEntry struct {
	vn     *Varnode
	offset uint64
}
