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
	"sort"

	"gosleigh/pkg/address"
)

// localHexName returns the Ghidra-style local variable name for a stack slot.
// Ghidra names stack locals using the absolute value of the signed frame offset
// in hex: offset 0xfffffff4 (-12) -> "local_c", 0xfffffff8 (-8) -> "local_8".
// Positive offsets (parameters) use this function only when the caller knows
// they are locals; callers must guard against parameter offsets beforehand.
// C++ parity: ScopeLocal uses frame-offset-based naming via Symbol::buildName.
func localHexName(offset uint64) string {
	// Interpret the offset as a signed 32-bit value to get the frame offset.
	// Stack addresses in x86-32 are 4 bytes; use int32 sign extension.
	signed := int32(uint32(offset))
	if signed < 0 {
		return fmt.Sprintf("local_%x", uint32(-signed))
	}
	// Positive offset: use as-is with "local_" prefix.
	// This should not normally occur since positive stack offsets are params.
	return fmt.Sprintf("local_%x", offset)
}

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
	// Entry-point functions (processEntry stack convention) keep the argument
	// register types seeded -- so ActionInferTypes still propagates a concrete
	// "long"/"int" width into the body -- but do NOT recover them as named
	// parameters: the renderer emits in_<reg> for these live-on-entry inputs.
	// Hence register args contribute 0 to the stack-parameter base index here.
	// C++ parity: an entry point gets the stack-only processEntry PrototypeModel,
	// so register args get no parameter index (index<0 -> in_<reg>).
	entryPoint := sl.model.EntryPoint
	regParamCount := len(regParamSlots)
	if entryPoint {
		regParamCount = 0
	}
	for _, slot := range regParamSlots {
		// An injected locked prototype may fix this parameter's type. Gosleigh's
		// ABI-slot derivation converges on the same register storage the locked
		// prototype encodes, so we stamp the locked type here (with a type lock so
		// ActionInferTypes leaves it authoritative) instead of the default TYPE_INT
		// seed. Non-injected functions have no locked types, so this is inert and
		// the default seeding below runs unchanged.
		// C++ parity: locked input ProtoParameter type overrides inference.
		if fp != nil {
			if lvt, ok := fp.LockedParamType(slot.vn.Offset()); ok {
				SetVarnodeType(slot.vn, lvt)
				slot.vn.SetFlags(VarnodeTypeLock)
			}
		}
		// Seed a concrete signed type onto the varnode so normalizedBaseType
		// renders it as "int" / "long" (not "undefined%d"). Done for entry-point
		// inputs too so the in_<reg> declaration and the return type infer "long".
		// C++ parity: Ghidra uses TYPE_INT for register params when no explicit
		// type is known from the prototype; "long" = 8-byte signed on LP64.
		if slot.vn.Type() == nil {
			sz := slot.vn.Size()
			if sz <= 0 {
				sz = 4
			}
			SetVarnodeType(slot.vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
		}
		if entryPoint {
			continue
		}
		name := GetParamName(slot.idx)
		hv := NewHighVariable(name)
		hv.AddInstance(slot.vn)
		sl.paramByVn[slot.vn] = hv
		if fp != nil {
			fp.AddParam(hv)
			// If an injected locked prototype named this register parameter, create a
			// matching Symbol and attach it to the input Varnode. This gives the
			// parameter HighVariable a mapped Symbol (namelocked when the prototype
			// namelocks the slot), which the merge Symbol guard (mergeTestRequired)
			// needs to keep a named parameter distinct from a same-typed accumulator
			// that maps to a different Symbol. Non-injected functions carry no locked
			// name, so this branch is inert and register params get no Symbol.
			// C++ parity: a locked ProtoParameter produces a ParameterSymbol whose
			// SymbolEntry is attached to the input Varnode (Funcdata::linkSymbol ->
			// Varnode::setSymbolEntry).
			if pname, nlock, isolate, ok := fp.LockedParamName(slot.vn.Offset()); ok {
				sym := NewSymbol(pname, slot.vn.Type())
				sym.SetCategory(SymbolFunctionParameter, slot.idx)
				if nlock {
					sym.SetFlags(VarnodeNameLock)
				}
				// A committed prototype serializes a parameter with merge="false"
				// (isolate) so it is never speculatively merged with an accumulator;
				// the merge Symbol/adjacency guard needs this to keep param_N distinct.
				// C++ parity: Symbol::setIsolated set from ATTRIB_MERGE=false decode.
				if isolate {
					sym.SetIsolated(true)
				}
				entry := NewSymbolEntry(sym, 0, slot.vn.Addr(), slot.vn.Size(), 0)
				sym.attachEntry(entry)
				slot.vn.SetSymbolEntry(entry)
			}
		}
	}

	// --- Stack parameters and locals ---
	// Group all stack varnodes by offset. Each unique offset gets one HighVariable;
	// all SSA versions at that offset (input, MULTIEQUAL output, COPY output) become
	// instances of the same HighVariable so they share the same C name.
	// C++ parity: ScopeLocal::restructureHigh -- Ghidra merges all SSA versions at the
	// same address into a single HighVariable with multiple instances.
	type offsetGroup struct {
		offset  uint64
		varnodes []*Varnode
	}
	paramGroups := make(map[uint64]*offsetGroup) // offset -> group
	localGroups := make(map[uint64]*offsetGroup)

	for _, vn := range varnodes {
		if vn == nil || vn.Space() == nil {
			continue
		}
		// Only examine stack-space varnodes.
		if !isStackSpace(vn, sl.model) {
			continue
		}
		off := vn.Offset()
		if sl.model.IsParamOffset(off) {
			if g, ok := paramGroups[off]; ok {
				g.varnodes = append(g.varnodes, vn)
			} else {
				paramGroups[off] = &offsetGroup{offset: off, varnodes: []*Varnode{vn}}
			}
		} else if sl.model.IsLocalOffset(off) {
			if g, ok := localGroups[off]; ok {
				g.varnodes = append(g.varnodes, vn)
			} else {
				localGroups[off] = &offsetGroup{offset: off, varnodes: []*Varnode{vn}}
			}
		}
	}

	// Collect and sort groups.
	paramList := make([]*offsetGroup, 0, len(paramGroups))
	for _, g := range paramGroups {
		paramList = append(paramList, g)
	}
	// Sort params ascending by offset: offset 8 < 16 < 24 -> param_N, param_N+1, ...
	sort.Slice(paramList, func(i, j int) bool {
		return paramList[i].offset < paramList[j].offset
	})

	localList := make([]*offsetGroup, 0, len(localGroups))
	for _, g := range localGroups {
		localList = append(localList, g)
	}
	// Sort locals descending by offset: 0xfffffffc > 0xfffffff8 -> local_0, local_1, ...
	// This matches Ghidra's frame layout where the first local below the frame pointer is local_0.
	sort.Slice(localList, func(i, j int) bool {
		return localList[i].offset > localList[j].offset
	})

	// Create HighVariables for stack params.
	// Stack param numbering starts AFTER register params so the combined
	// param_1..param_N sequence is contiguous and ABI-ordered.
	// All SSA versions at the same offset share one HighVariable.
	for i, g := range paramList {
		name := GetParamName(regParamCount + i)
		hv := NewHighVariable(name)
		// Add all SSA versions at this offset as instances of the same HighVariable.
		// C++ parity: ScopeLocal::restructureHigh merges all versions into one HighVariable.
		for _, vn := range g.varnodes {
			hv.AddInstance(vn)
			sl.paramByVn[vn] = hv
			// Set mapped+addrtied: stack-space varnodes are always address-tied because
			// they are identified by storage address, not by SSA number.
			// C++ parity: database.cc ScopeInternal::buildFrom sets symbol->flags |= addrtied
			// for any entry without a usepoint limitation; vn->setFlags(entry->getAllFlags())
			// propagates addrtied to the Varnode.
			vn.SetFlags(VarnodeMapped | VarnodeAddrTied)
		}
		if fp != nil {
			fp.AddParam(hv)
		}
		// Seed TYPE_INT for untyped stack params, matching register param treatment.
		// C++ parity: Ghidra assigns signed integer as default type for ABI stack slots;
		// ActionInferTypes then propagates this through INT_ADD/INT_MULT chains.
		for _, vn := range g.varnodes {
			if vn.Type() == nil {
				sz := vn.Size()
				if sz <= 0 {
					sz = 4
				}
				SetVarnodeType(vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
			}
		}
	}

	// Create HighVariables for locals.
	// All SSA versions at the same offset share one HighVariable.
	// Name: Ghidra hex-offset style "local_<hex>".
	// For negative frame offsets (locals below EBP/FP), the hex suffix is the
	// absolute value of the signed offset, e.g. 0xfffffff4 (-12) -> "local_c".
	// C++ parity: ScopeLocal uses SymbolEntry addresses; Ghidra names are set by
	// ScopeLocal::buildFromVarnodes via Symbol::buildName using the frame offset.
	// claimedHigh tracks which existing HighVariables have already been adopted by
	// an earlier offset group in this pass, so two distinct stack offsets never
	// collapse into one variable if a prior merge over-merged them.
	claimedHigh := make(map[*HighVariable]bool)
	for _, g := range localList {
		name := localHexName(g.offset)
		// Reuse the existing HighVariable the stack varnodes already belong to,
		// rather than creating a fresh one and re-adding only the stack varnodes.
		// By this point Heritage/merge (mergeAddrTied + mergeMarker) has coalesced
		// all SSA versions at this address into one HighVariable -- and crucially
		// also pulled in any register-backed value that flows through the loop phi
		// (e.g. the INT_ADD accumulator on the back-edge). Creating a new high and
		// stealing only the stack instances would orphan those register instances,
		// rendering the loop body as a dead temp (uVar2 = local_c + local_8) instead
		// of a write-back (local_c = local_c + local_8). C++ ActionInputPrototype
		// never recreates HighVariables; it only maps varnodes to Symbols and the
		// name is derived from the symbol. We approximate by naming the merged high.
		var hv *HighVariable
		for _, vn := range g.varnodes {
			if h := vn.High(); h != nil && !claimedHigh[h] {
				hv = h
				break
			}
		}
		if hv == nil {
			// No reusable high (pre-merge call, or all candidate highs already
			// claimed by another offset -- the latter guards against over-merge).
			hv = NewHighVariable(name)
		}
		hv.SetName(name)
		claimedHigh[hv] = true
		for _, vn := range g.varnodes {
			if vn.High() != hv {
				hv.AddInstance(vn)
			}
			sl.localByVn[vn] = hv
			// Locals are also address-tied (identified by frame address, not SSA number).
			// C++ parity: same as stack params above.
			vn.SetFlags(VarnodeMapped | VarnodeAddrTied)
		}
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
