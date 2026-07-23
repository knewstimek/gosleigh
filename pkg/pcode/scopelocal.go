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

// localHexName returns a hex-offset default name for a non-stack storage
// address. Only Funcdata::mapGlobals uses it, to manufacture a placeholder
// symbol for a persistent (global) Varnode that no Scope claims; the real
// Ghidra name for that case comes from the global symbol table, which Gosleigh
// has not ported yet. Stack slots must NOT use this -- see stackLocalName.
func localHexName(offset uint64) string {
	signed := int32(uint32(offset))
	if signed < 0 {
		return fmt.Sprintf("local_%x", uint32(-signed))
	}
	return fmt.Sprintf("local_%x", offset)
}

// stackLocalName returns the default display name for a stack slot at the given
// raw frame offset.
//
// This emulates the Ghidra *Java* naming layer, not the C++ decompiler core.
// The core (varmap.cc ScopeLocal::buildVariableName) names an unmapped stack
// slot "<typeprefix>Stack[X]_<hex>" -- "uStack_18" for offset -0x18, "uStackX_8"
// for offset +8, the 'X' flagging caller-allocated space. Those core names only
// survive into the final listing for slots that have no Program-DB stack
// variable; a slot that does have one reaches the decompiler already named by
// Java, and that Java name is what the goldens show (golden add_pt carries both
// kinds side by side: "local_res8"/"local_res10" for the DB-backed home-slot
// starts, "uStackX_c"/"uStackX_14" for the un-DB'd 4-byte upper halves).
//
// Ghidra 12.0.4 ghidra/program/model/symbol/SymbolUtilities.java
// getDefaultLocalName(Program, int stackOffset, int firstUseOffset):
//
//	boolean reservedArea = stackGrowsNegative ? (stackOffset >= 0) : (stackOffset < 0);
//	stackOffset = Math.abs(stackOffset);
//	String name = (reservedArea ? "local_res" : "local_") + Integer.toHexString(stackOffset);
//	if (firstUseOffset != 0) name += "_" + Integer.toString(firstUseOffset);
//
// The "reserved area" is the region the caller owns: on a negative-growth stack
// that is every non-negative offset -- the MS x64 home/shadow slots at +8, +0x10,
// +0x18, +0x20 and the stack-argument area beyond. Ghidra tags those "local_res"
// to distinguish them from true frame locals at negative offsets ("local_").
// Note the boundary is inclusive of 0, and that the prefix depends only on the
// sign, not on slot alignment.
//
// The firstUseOffset suffix is deliberately not emitted: Gosleigh never builds
// use-point-limited stack symbols, so the offset is always 0 here.
func stackLocalName(offset uint64, growsNegative bool) string {
	// Stack offsets arrive as the raw space offset with the frame displacement
	// encoded in two's complement. Frame displacements are far inside int32 for
	// both the 4-byte (x86-32) and 8-byte (x86-64, AARCH64) stack spaces, so a
	// single int32 sign-extension recovers the signed offset for either width.
	signed := int32(uint32(offset))
	reserved := signed >= 0
	if !growsNegative {
		reserved = signed < 0
	}
	mag := uint32(signed)
	if signed < 0 {
		mag = uint32(-signed)
	}
	if reserved {
		return fmt.Sprintf("local_res%x", mag)
	}
	return fmt.Sprintf("local_%x", mag)
}

// stackLocalName names a slot in this scope's stack space, honoring the
// architecture's stack growth direction.
func (sl *ScopeLocal) stackLocalName(offset uint64) string {
	growsNegative := true
	if e := sl.ext(); e != nil {
		growsNegative = e.stackGrows
	}
	return stackLocalName(offset, growsNegative)
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
		name := sl.stackLocalName(g.offset)
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

// registerStackParam records a late-recovered stack parameter Varnode/HighVariable
// pairing, applying the same bookkeeping BuildFromVarnodes performs for stack
// params: map the Varnode to the HighVariable, mark it mapped+addrtied (stack
// storage is identified by address, not SSA number), and seed a signed integer
// type when untyped so it renders as int/long rather than undefined.
// C++ parity: ScopeLocal::restructureHigh stack-slot HighVariable creation +
// vn->setFlags(addrtied) + default TYPE_INT seed.
func (sl *ScopeLocal) registerStackParam(vn *Varnode, hv *HighVariable) {
	if sl == nil || vn == nil || hv == nil {
		return
	}
	sl.paramByVn[vn] = hv
	vn.SetFlags(VarnodeMapped | VarnodeAddrTied)
	if vn.Type() == nil {
		sz := vn.Size()
		if sz <= 0 {
			sz = 4
		}
		SetVarnodeType(vn, sharedTypeFactory.GetBase(int32(sz), TYPE_INT, ""))
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
