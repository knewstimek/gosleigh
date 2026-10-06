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

// EffectKind describes how a CALL instruction affects a register or memory location.
// Used by Heritage.guardCalls to decide which INDIRECT op to insert.
// C++ parity: compiler.hh EffectRecord::EffectType constants
type EffectKind uint8

const (
	// EffectUnknown: effect is not known; insert a conservative INDIRECT guard
	// (value may or may not be modified).
	EffectUnknown EffectKind = iota
	// EffectKilledByCall: caller-saved register -- callee may freely overwrite it.
	// Heritage inserts INDIRECT_CREATION (new undefined SSA version).
	// C++ parity: EffectRecord::killedbycall
	EffectKilledByCall
	// EffectUnaffected: callee-saved register -- callee must preserve the value.
	// Heritage inserts nothing; the pre-call SSA version flows through.
	// C++ parity: EffectRecord::unaffected
	EffectUnaffected
	// EffectReturnAddress: the storage holds the call's return address.
	// C++ parity: EffectRecord::return_address
	EffectReturnAddress
)

// EffectRecord is one storage range whose call effect a model declares.
// C++ parity: fspec.hh EffectRecord.
type EffectRecord struct {
	Addr address.Address
	Size int32
	Type EffectKind
}

// effectLess orders records by space index, then offset.
// C++ parity: EffectRecord::compareByAddress.
func effectLess(a, b address.Address) bool {
	if a.Space != b.Space {
		return a.Space.Index < b.Space.Index
	}
	return a.Offset < b.Offset
}

// SetEffects installs the model's effect list, sorted for lookupEffect.
func (pm *ProtoModel) SetEffects(effects []EffectRecord) {
	sort.SliceStable(effects, func(i, j int) bool { return effectLess(effects[i].Addr, effects[j].Addr) })
	pm.Effects = effects
}

// LookupEffect classifies how a call affects [addr,addr+size): the effect of
// the last record at or below addr when it fully contains the range, else
// unknown. Internal (unique) storage is always unaffected.
// C++ parity: fspec.cc ProtoModel::lookupEffect (2472-2495).
func LookupEffect(efflist []EffectRecord, addr address.Address, size int32) EffectKind {
	if addr.Space != nil && addr.Space.Kind == address.SpaceKindUnique {
		return EffectUnaffected
	}
	// upper_bound: first record strictly greater than addr.
	i := sort.Search(len(efflist), func(i int) bool { return effectLess(addr, efflist[i].Addr) })
	if i == 0 {
		return EffectUnknown
	}
	hit := efflist[i-1]
	if hit.Size == 0 && hit.Addr.Space == addr.Space {
		return EffectUnaffected // A size of zero means the whole space is unaffected
	}
	if hit.Addr.Space != addr.Space || addr.Space.Kind == address.SpaceKindConstant {
		return EffectUnknown
	}
	// Address::overlap(0,hit,sz): distance of addr into hit, wrapped to the space.
	dist := wrapSpaceOffset(addr.Space, addr.Offset-hit.Addr.Offset)
	if dist >= uint64(hit.Size) || dist+uint64(size) > uint64(hit.Size) {
		return EffectUnknown
	}
	return hit.Type
}

// wrapSpaceOffset reduces an offset to the space's address width.
// C++ parity: AddrSpace::wrapOffset.
func wrapSpaceOffset(spc *address.Space, off uint64) uint64 {
	if spc == nil || spc.AddrSize == 0 || spc.AddrSize >= 8 {
		return off
	}
	return off & ((uint64(1) << (8 * uint(spc.AddrSize))) - 1)
}

// StackRanges returns the model's local and parameter ranges in the stack
// space, sorted by first offset, applying the C++ defaults when the cspec
// gives none.
// C++ parity: ProtoModel::defaultLocalRange / defaultParamRange (negative
// stack growth) merged as ScopeLocal::resetLocalWindow does.
func (pm *ProtoModel) StackRanges() [][2]uint64 {
	if pm == nil || pm.StackSpace == nil {
		return nil
	}
	highest := wrapSpaceOffset(pm.StackSpace, ^uint64(0))
	sz := pm.StackSpace.AddrSize
	var localSpan, paramLast uint64 = 99, 15
	if sz >= 4 {
		localSpan, paramLast = 999999, 511
	} else if sz >= 2 {
		localSpan, paramLast = 9999, 255
	}
	ranges := append([][2]uint64(nil), pm.StackParamRanges...)
	if len(ranges) == 0 {
		ranges = append(ranges, [2]uint64{0, paramLast})
	}
	ranges = append(ranges, [2]uint64{highest - localSpan, highest})
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	return ranges
}

// HasEffect returns the model's effect on the given storage.
// C++ parity: ProtoModel::hasEffect.
func (pm *ProtoModel) HasEffect(addr address.Address, size int32) EffectKind {
	if pm == nil {
		return EffectUnknown
	}
	return LookupEffect(pm.Effects, addr, size)
}

// ProtoModel is a lightweight representation of a calling convention prototype
// sufficient for ABI-aware variable naming. It does not replicate the full
// Ghidra PrototypeModel -- only the subset needed for param/local classification.
//
// C++ parity: compiler.hh PrototypeModel (partial)
type ProtoModel struct {
	// Name is the model name (e.g. "__stdcall").
	// C++ parity: ProtoModel::name.
	Name string

	// AutoKilledByCall: every potential output location is killed by a call
	// (<output killedbycall="true">).
	// C++ parity: ParamListStandard::autoKilledByCall via isAutoKilledByCall.
	AutoKilledByCall bool

	// ExtraPop is the stack-pointer change across a call beyond the pushed
	// parameters (ExtrapopUnknown when the callee decides, as with __stdcall).
	// C++ parity: ProtoModel::extrapop.
	ExtraPop int32

	// hasThis marks a model whose first input is an implicit this pointer.
	// C++ parity: ProtoModel::hasThis.
	hasThis bool

	// Effects is the sorted effect list (unaffected / killedbycall /
	// return_address storage). C++ parity: ProtoModel::effectlist.
	Effects []EffectRecord

	// Merged lists the component models of a merged (resolve) model.
	// C++ parity: ProtoModelMerged::modellist.
	Merged []*ProtoModel

	// PrintInDecl is false only for the architecture default model, whose name
	// is not printed in declarations. C++ parity: ProtoModel::isPrinted /
	// Architecture::setDefaultModel.
	PrintInDecl bool

	// StackParamRanges are the stack offset ranges [first,last] of the input
	// pentries; empty means the default parameter range.
	// C++ parity: ProtoModel::paramrange from input->getRangeList(stackspc).
	StackParamRanges [][2]uint64

	// StackSpace is the address space used for stack variables (SpaceKindStack or name=="stack").
	StackSpace *address.Space

	// ParamBaseOffset is the stack offset of the first parameter (e.g. 4 for x86 cdecl).
	ParamBaseOffset int64

	// ParamAlign is the stack alignment for parameters in bytes (e.g. 4 for x86 cdecl).
	ParamAlign int64

	// UnaffectedRegs are register names that are preserved across calls (callee-saved).
	UnaffectedRegs map[string]bool

	// KilledByCallRegs are register names that are not preserved across calls (caller-saved).
	KilledByCallRegs map[string]bool

	// RegParams is the ordered list of integer/pointer register parameter names,
	// derived from cspec IntegerRegParams(). Empty for x86-32 (stack-only ABI).
	RegParams []string

	// RegParamOffsets maps register-space byte offset to parameter index.
	// Used by ScopeLocal to classify register varnodes as named parameters.
	// Nil/empty for x86-32 (stack-only ABI); populated for x86-64 and similar ABIs.
	RegParamOffsets map[uint64]int

	// EntryPoint marks an entry-point function decompiled under the stack-based
	// processEntry convention. When set, register argument slots (RegParamOffsets)
	// are NOT recovered as named parameters: an entry point conventionally takes
	// no register C parameters, so a live-on-entry argument register read becomes
	// an irregular input rendered as in_<reg> instead of param_N. RegParamOffsets
	// stays populated so the renderer can still recognize which input registers
	// are argument registers (vs frame/callee-saved) when assigning in_<reg> names.
	// C++ parity: an entry point gets the stack-only processEntry PrototypeModel,
	// so register args get no parameter index -> ScopeInternal::buildVariableName
	// (database.cc:2470) emits in_<regname> for index<0 inputs.
	EntryPoint bool

	// PointerSize is the pointer size in bytes from the cspec data_organization.
	// 0 means unset; treat as 4.
	PointerSize int

	// LongSize is the size of the C "long" type in bytes from the cspec
	// data_organization.  0 means unset; treat as 8 (LP64).  Determines whether an
	// 8-byte signed integer declaration is spelled "long" (8, LP64) or "longlong"
	// (4, LLP64 / Windows x64).  C++ parity: TypeFactory::sizeOfLong.
	LongSize int

	// ReturnRegOffset is the byte offset of the integer return register in the
	// register address space. 0 for x86-32 (EAX) and x86-64 (RAX).
	// TODO: derive this from cspec <output> tag in NewProtoModelFromCspec.
	ReturnRegOffset uint64

	// ReturnRegSize is the size in bytes of the return register.
	// 0 means unset; ApplyCallingConvention treats 0 as no return-register anchoring.
	ReturnRegSize int32

	// ReturnRegSpaceIndex is the address-space index of the return register.
	// -1 means unset; ApplyCallingConvention skips return anchoring when -1.
	ReturnRegSpaceIndex int

	// KilledByCallOffsets maps register-space byte offset -> true for caller-saved
	// registers.  Populated by WithEffectOffsets.
	// C++ parity: EffectRecord set for PrototypeModel::killedByCall regions.
	KilledByCallOffsets map[uint64]bool

	// UnaffectedOffsets maps register-space byte offset -> true for callee-saved
	// registers.  Populated by WithEffectOffsets.
	// C++ parity: EffectRecord set for PrototypeModel::unaffected regions.
	UnaffectedOffsets map[uint64]bool

	// InputParams is the faithful port of PrototypeModel::input
	// (ParamListStandard): the ordered <pentry> storage model used by
	// FuncProto::deriveInputMap to recover the current function's formal input
	// list from Varnode trials. Built from the cspec <input> pentries by the
	// bridge (which owns the register/stack address spaces). Nil for cspec-less
	// builds; recovery then falls back to the register/stack heuristics.
	// C++ parity: PrototypeModel::input (compiler.hh).
	InputParams *ParamListStandard
}

// GetExtraPop returns the model's extrapop.
// C++ parity: ProtoModel::getExtraPop.
func (pm *ProtoModel) GetExtraPop() int32 { return pm.ExtraPop }

// HasThisPointer reports whether the model passes an implicit this pointer.
// C++ parity: ProtoModel::hasThisPointer.
func (pm *ProtoModel) HasThisPointer() bool { return pm != nil && pm.hasThis }

// SetInputParams attaches the faithful input parameter-storage model.
func (pm *ProtoModel) SetInputParams(pl *ParamListStandard) {
	if pm != nil {
		pm.InputParams = pl
	}
}

// RegLookupFunc is an optional callback for looking up a register's byte offset
// in the register address space by name. Returns (offset, true) on success.
// Used by NewProtoModelFromCspec to populate RegParamOffsets for register-based ABIs.
// Pass nil for architectures with stack-only calling conventions (e.g. x86-32 cdecl).
type RegLookupFunc func(name string) (offset uint64, ok bool)

// NewProtoModelFromCspec builds a ProtoModel from parsed CspecData and the
// address space map. stackSpace should be the stack address space (SpaceKindStack).
// regLookup is optional: when non-nil it is used to resolve register parameter
// offsets for ABIs that pass arguments in registers (x86-64, AArch64, etc.).
// Pass nil for stack-only calling conventions (x86-32 cdecl).
// C++ parity: Architecture::setPrimitiveMethods / PrototypeModel construction
func NewProtoModelFromCspec(cs *CspecData, stackSpace *address.Space, regLookup RegLookupFunc) *ProtoModel {
	pm := &ProtoModel{
		StackSpace:          stackSpace,
		ParamBaseOffset:     4, // default for x86 cdecl
		ParamAlign:          4,
		UnaffectedRegs:      make(map[string]bool),
		KilledByCallRegs:    make(map[string]bool),
		ReturnRegSpaceIndex: -1, // unset; caller must call WithReturnReg to enable anchoring
	}
	if cs == nil {
		return pm
	}
	pm.ParamBaseOffset = cs.StackParamBaseOffset()
	pm.ParamAlign = cs.StackParamAlign()
	pm.PointerSize = cs.PointerSize()
	pm.LongSize = cs.LongSize()

	if cs.DefaultProto != nil {
		pm.Name = cs.DefaultProto.Name
		pm.ExtraPop = int32(cs.DefaultProto.ExtraPop)
		pm.hasThis = cs.DefaultProto.ProtoModelHasThis()
		pm.AutoKilledByCall = cs.DefaultProto.Output.KilledByCall
		for _, reg := range cs.DefaultProto.Unaffected.Registers {
			pm.UnaffectedRegs[reg.Name] = true
		}
		for _, reg := range cs.DefaultProto.KilledByCall.Registers {
			pm.KilledByCallRegs[reg.Name] = true
		}
	}

	// Populate register parameter list and offset map when a register lookup is available.
	// For x86-32 cdecl (stack-only ABI), IntegerRegParams() returns nil and regLookup is nil,
	// so this block is a no-op -- preserving identical behavior for x86-32.
	regParams := cs.IntegerRegParams()
	if len(regParams) > 0 && regLookup != nil {
		pm.RegParams = regParams
		pm.RegParamOffsets = make(map[uint64]int, len(regParams))
		for i, name := range regParams {
			if offset, found := regLookup(name); found {
				pm.RegParamOffsets[offset] = i
			}
		}
	}

	return pm
}

// localThreshold returns the unsigned offset boundary that separates stack params
// from stack locals. For 32-bit pointer size the threshold is 0x80000000 (the
// sign bit of a 32-bit value). For 64-bit pointer size it is 0x8000000000000000.
// When PointerSize is 0 or 4 (x86-32 default), the 32-bit threshold is used --
// this preserves identical behavior for all existing x86-32 code paths.
func (pm *ProtoModel) localThreshold() uint64 {
	if pm == nil || pm.PointerSize <= 4 {
		return 0x80000000
	}
	return 0x8000000000000000
}

// IsParamOffset returns true if the given stack offset is in the parameter area.
// In x86 cdecl, parameters start at offset 4 (after the return address).
// A varnode is a parameter if its offset >= ParamBaseOffset and offset fits in
// the addressable range (i.e. is a small positive number, not a large unsigned
// offset that represents a negative stack value).
//
// C++ parity: ParamActive::isParamable / ProtoModel::assignMap
func (pm *ProtoModel) IsParamOffset(offset uint64) bool {
	if pm == nil {
		return false
	}
	// Stack locals are stored at large unsigned offsets (negative frame offsets).
	// Parameters are at small positive offsets. See localThreshold() for details.
	if offset >= pm.localThreshold() {
		return false
	}
	return int64(offset) >= pm.ParamBaseOffset
}

// IsLocalOffset returns true if the given stack offset represents a local variable.
// Locals are at negative frame offsets, stored as large unsigned values >= localThreshold.
// C++ parity: ScopeLocal analysis
func (pm *ProtoModel) IsLocalOffset(offset uint64) bool {
	if pm == nil {
		return false
	}
	return offset >= pm.localThreshold()
}

// IsRegParam returns the parameter index and true if the given register-space
// byte offset matches a known integer register parameter. Returns 0, false when
// the offset is not a register parameter (including when RegParamOffsets is nil).
// C++ parity: ProtoModel::assignMap register slot lookup
func (pm *ProtoModel) IsRegParam(regOffset uint64) (paramIdx int, ok bool) {
	if pm == nil || pm.RegParamOffsets == nil {
		return 0, false
	}
	idx, found := pm.RegParamOffsets[regOffset]
	return idx, found
}

// IsUnaffected reports whether the named register is callee-saved.
// C++ parity: PrototypeModel::isUnaffected
func (pm *ProtoModel) IsUnaffected(regName string) bool {
	if pm == nil {
		return false
	}
	return pm.UnaffectedRegs[regName]
}

// IsKilledByCall reports whether the named register is caller-saved.
// C++ parity: PrototypeModel::isKilledByCall
func (pm *ProtoModel) IsKilledByCall(regName string) bool {
	if pm == nil {
		return false
	}
	return pm.KilledByCallRegs[regName]
}

// WithEffectOffsets resolves killedbycall and unaffected register names to
// register-space byte offsets and populates KilledByCallOffsets / UnaffectedOffsets.
// The lookup function maps a register name to its (offset, size) in the register
// address space.  Call this before passing the ProtoModel to Heritage.WithProtoModel
// so that guardCalls can classify each heritaged register range.
//
// Registers not found via lookup are silently skipped (they will be treated as
// EffectUnknown, triggering a conservative INDIRECT guard).
//
// C++ parity: PrototypeModel effect-record construction (compiler.hh/cc)
func (pm *ProtoModel) WithEffectOffsets(lookup func(name string) (offset uint64, size int32, ok bool)) *ProtoModel {
	if pm == nil || lookup == nil {
		return pm
	}
	pm.KilledByCallOffsets = make(map[uint64]bool)
	pm.UnaffectedOffsets = make(map[uint64]bool)
	for name := range pm.KilledByCallRegs {
		if off, _, ok := lookup(name); ok {
			pm.KilledByCallOffsets[off] = true
		}
	}
	for name := range pm.UnaffectedRegs {
		if off, _, ok := lookup(name); ok {
			pm.UnaffectedOffsets[off] = true
		}
	}
	return pm
}

// EffectOnRegister returns the effect type for the register at the given
// register-space byte offset.  Used by Heritage.guardCalls.
// Returns EffectUnknown when the offset is not classified (offset maps not built).
// C++ parity: FuncCallSpecs::hasEffect / EffectRecord::contains
func (pm *ProtoModel) EffectOnRegister(offset uint64) EffectKind {
	if pm == nil {
		return EffectUnknown
	}
	if pm.KilledByCallOffsets != nil && pm.KilledByCallOffsets[offset] {
		return EffectKilledByCall
	}
	if pm.UnaffectedOffsets != nil && pm.UnaffectedOffsets[offset] {
		return EffectUnaffected
	}
	return EffectUnknown
}

// WithReturnReg sets the integer return register location on the ProtoModel.
// spaceIdx is the address-space index of the register space, offset is the
// byte offset of the register within that space, size is the byte width.
// For x86-32 cdecl, call WithReturnReg(regSpaceIdx, 0, 4) to anchor EAX.
// Returns pm for chaining.
// C++ parity: PrototypeModel return value slot (partial)
func (pm *ProtoModel) WithReturnReg(spaceIdx int, offset uint64, size int32) *ProtoModel {
	pm.ReturnRegSpaceIndex = spaceIdx
	pm.ReturnRegOffset = offset
	pm.ReturnRegSize = size
	return pm
}

// WithRegParams adds register parameter slots directly without requiring a
// regLookup callback. offsets is a slice of byte offsets within the register
// address space ordered by ABI parameter index (index 0 = first parameter).
// This is used for architectures where register param offsets are known at
// test time without a full cspec parse (e.g. AArch64 X0=16384, X1=16392).
// Returns pm for chaining.
func (pm *ProtoModel) WithRegParams(offsets []uint64) *ProtoModel {
	if pm.RegParamOffsets == nil {
		pm.RegParamOffsets = make(map[uint64]int, len(offsets))
	}
	for i, off := range offsets {
		pm.RegParamOffsets[off] = i
	}
	return pm
}
