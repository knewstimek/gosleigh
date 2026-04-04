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

// ProtoModel is a lightweight representation of a calling convention prototype
// sufficient for ABI-aware variable naming. It does not replicate the full
// Ghidra PrototypeModel -- only the subset needed for param/local classification.
//
// C++ parity: compiler.hh PrototypeModel (partial)
type ProtoModel struct {
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
}

// NewProtoModelFromCspec builds a ProtoModel from parsed CspecData and the
// address space map. stackSpace should be the stack address space (SpaceKindStack).
// C++ parity: Architecture::setPrimitiveMethods / PrototypeModel construction
func NewProtoModelFromCspec(cs *CspecData, stackSpace *address.Space) *ProtoModel {
	pm := &ProtoModel{
		StackSpace:       stackSpace,
		ParamBaseOffset:  4, // default for x86 cdecl
		ParamAlign:       4,
		UnaffectedRegs:   make(map[string]bool),
		KilledByCallRegs: make(map[string]bool),
	}
	if cs == nil {
		return pm
	}
	pm.ParamBaseOffset = cs.StackParamBaseOffset()
	pm.ParamAlign = cs.StackParamAlign()

	if cs.DefaultProto != nil {
		for _, reg := range cs.DefaultProto.Unaffected.Registers {
			pm.UnaffectedRegs[reg.Name] = true
		}
		for _, reg := range cs.DefaultProto.KilledByCall.Registers {
			pm.KilledByCallRegs[reg.Name] = true
		}
	}
	return pm
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
	// In x86-32 with 4-byte pointer size, the stack space is 32-bit addressable.
	// Stack locals are stored at large unsigned offsets (>= 0x80000000 when viewed
	// as uint64) because they are negative relative to the frame pointer.
	// Parameters are at small positive offsets (4, 8, 12, ...).
	// Threshold: treat offsets >= 0x80000000 as locals (negative frame offsets).
	const localThreshold = uint64(0x80000000)
	if offset >= localThreshold {
		return false
	}
	return int64(offset) >= pm.ParamBaseOffset
}

// IsLocalOffset returns true if the given stack offset represents a local variable.
// In x86-32, locals are at negative frame offsets, stored as large unsigned values.
// C++ parity: ScopeLocal analysis
func (pm *ProtoModel) IsLocalOffset(offset uint64) bool {
	if pm == nil {
		return false
	}
	const localThreshold = uint64(0x80000000)
	return offset >= localThreshold
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
