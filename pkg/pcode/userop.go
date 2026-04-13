// Copyright 2026 The Gosleigh Authors
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

// Package pcode -- user-defined p-code op registry.
// C++ parity: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/userop.hh
// and userop.cc. User-defined ops are invoked with CPUI_CALLOTHER; the first
// input is a constant id that selects the registered user-op description.
// The Go port models the minimum surface needed to hand out builtin ids and
// keep a small per-Funcdata/global registry so getInternalString and the
// constseq transforms can emit legal CALLOTHER sequences.
package pcode

import "sync"

// Builtin user-op constant ids.
// C++ parity: userop.cc const definitions of UserPcodeOp::BUILTIN_*. The
// values match the original bit pattern so encodings produced by this port
// line up with Ghidra when cross-checked.
const (
	BUILTIN_STRINGDATA     uint32 = 0x10000000
	BUILTIN_VOLATILE_READ  uint32 = 0x10000001
	BUILTIN_VOLATILE_WRITE uint32 = 0x10000002
	BUILTIN_MEMCPY         uint32 = 0x10000003
	BUILTIN_STRNCPY        uint32 = 0x10000004
	BUILTIN_WCSNCPY        uint32 = 0x10000005
)

// UserOpType is the encoded class type of a UserPcodeOp.
// C++ parity: enum UserPcodeOp::userop_type in userop.hh.
type UserOpType uint32

const (
	UserOpUnspecialized UserOpType = 1
	UserOpInjected      UserOpType = 2
	UserOpVolatileRead  UserOpType = 3
	UserOpVolatileWrite UserOpType = 4
	UserOpSegment       UserOpType = 5
	UserOpJumpAssist    UserOpType = 6
	UserOpStringData    UserOpType = 7
	UserOpDatatype      UserOpType = 8
)

// UserOpFlags is a bitmask of display flags on a UserPcodeOp.
// C++ parity: enum UserPcodeOp::userop_flags in userop.hh.
type UserOpFlags uint32

const (
	UserOpFlagAnnotationAssignment UserOpFlags = 1
	UserOpFlagNoOperator           UserOpFlags = 2
	UserOpFlagDisplayString        UserOpFlags = 4
)

// UserPcodeOp is a registered user-defined p-code operator. A CALLOTHER with
// input 0 equal to Index() dispatches to this description object.
// C++ parity: class UserPcodeOp in userop.hh.
type UserPcodeOp struct {
	name     string
	opType   UserOpType
	index    uint32
	flags    UserOpFlags
	outType  Datatype
	inTypes  []Datatype
}

// Name returns the low-level name of the operator.
// C++ parity: UserPcodeOp::getName.
func (u *UserPcodeOp) Name() string { return u.name }

// OpType returns the encoded class type.
// C++ parity: UserPcodeOp::getType.
func (u *UserPcodeOp) OpType() UserOpType { return u.opType }

// Index returns the constant id that selects this op in a CALLOTHER.
// C++ parity: UserPcodeOp::getIndex.
func (u *UserPcodeOp) Index() uint32 { return u.index }

// Flags returns the display flags for this op.
// C++ parity: UserPcodeOp::getDisplay.
func (u *UserPcodeOp) Flags() UserOpFlags { return u.flags }

// OutputLocal returns the declared output data-type or nil for unspecified.
// C++ parity: DatatypeUserOp::getOutputLocal.
func (u *UserPcodeOp) OutputLocal() Datatype { return u.outType }

// InputLocal returns the declared input data-type for the given slot or nil.
// C++ parity: DatatypeUserOp::getInputLocal.
func (u *UserPcodeOp) InputLocal(slot int) Datatype {
	if slot < 0 || slot >= len(u.inTypes) {
		return nil
	}
	return u.inTypes[slot]
}

// UserOpManage is the registry of CALLOTHER user-defined ops for a single
// Architecture. The Go port tracks:
//   - a slice indexed by CALLOTHER constant id for architecture-declared ops
//   - a map from builtin id to its lazily-registered description
//
// C++ parity: class UserOpManage in userop.hh and registerBuiltin/manuallyregister
// family in userop.cc.
type UserOpManage struct {
	mu       sync.Mutex
	byIndex  []*UserPcodeOp
	builtins map[uint32]*UserPcodeOp
}

// NewUserOpManage constructs an empty registry.
// C++ parity: UserOpManage::UserOpManage.
func NewUserOpManage() *UserOpManage {
	return &UserOpManage{
		builtins: make(map[uint32]*UserPcodeOp),
	}
}

// GetOp looks up a registered op by CALLOTHER index.
// C++ parity: UserOpManage::getOp.
func (m *UserOpManage) GetOp(index uint32) *UserPcodeOp {
	m.mu.Lock()
	defer m.mu.Unlock()
	if int(index) < len(m.byIndex) {
		return m.byIndex[index]
	}
	return m.builtins[index]
}

// RegisterBuiltin lazily registers a builtin user-op by its constant id and
// returns the description. Subsequent calls return the cached entry.
// C++ parity: UserOpManage::registerBuiltin (userop.cc ~L420). Only the four
// string-copy / string-data builtins are materialized here; the volatile ops
// and any architecture-driven user ops remain unimplemented and will be
// filled in alongside their consumers.
func (m *UserOpManage) RegisterBuiltin(id uint32, types *TypeFactory) *UserPcodeOp {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.builtins[id]; ok {
		return existing
	}
	op := buildBuiltinUserOp(id, types)
	if op != nil {
		m.builtins[id] = op
	}
	return op
}

// buildBuiltinUserOp materializes the DatatypeUserOp / InternalStringOp entry
// for one of the builtin ids handled by this port. Input/output data-types
// mirror the C++ factory in userop.cc.
// C++ parity: UserOpManage::registerBuiltin switch (userop.cc ~L425-L485).
func buildBuiltinUserOp(id uint32, types *TypeFactory) *UserPcodeOp {
	// Default pointer size / word size for the common 32-bit case. A full
	// port threads the architecture's default data space through here; the
	// minimal helper hard-codes 4/1 so the registry is usable before the
	// architecture plumbing lands. This is a documented mismatch.
	// TODO mismatch: builtin user-op data-types ignore the real pointer
	// size and word size of the owning architecture (C++ reads
	// glb->types->getSizeOfPointer() and getDefaultDataSpace()->getWordSize()).
	ptrSize := int32(4)
	wordSize := uint32(1)

	switch id {
	case BUILTIN_STRINGDATA:
		// C++: InternalStringOp takes a single annotation input (the hash)
		// and produces the encoded string payload. The Go registry stores
		// the declared name; the payload side-table lives on Funcdata.
		return &UserPcodeOp{
			name:   "stringdata",
			opType: UserOpStringData,
			index:  id,
			flags:  UserOpFlagDisplayString,
		}
	case BUILTIN_MEMCPY:
		if types == nil {
			return nil
		}
		voidT := types.GetVoid()
		ptrT := types.GetPointer(ptrSize, voidT, wordSize)
		intT := types.GetBase(4, TYPE_INT, "int")
		return &UserPcodeOp{
			name:    "builtin_memcpy",
			opType:  UserOpDatatype,
			index:   id,
			outType: ptrT,
			inTypes: []Datatype{ptrT, ptrT, intT},
		}
	case BUILTIN_STRNCPY:
		if types == nil {
			return nil
		}
		charT := types.GetBase(1, TYPE_INT, "char")
		ptrT := types.GetPointer(ptrSize, charT, wordSize)
		intT := types.GetBase(4, TYPE_INT, "int")
		return &UserPcodeOp{
			name:    "builtin_strncpy",
			opType:  UserOpDatatype,
			index:   id,
			outType: ptrT,
			inTypes: []Datatype{ptrT, ptrT, intT},
		}
	case BUILTIN_WCSNCPY:
		if types == nil {
			return nil
		}
		// wchar is assumed 2 bytes in the port until TypeFactory knows the
		// real wchar size (C++ reads glb->types->getSizeOfWChar()).
		// TODO mismatch: wchar size is hard-coded to 2.
		wcharT := types.GetBase(2, TYPE_INT, "wchar_t")
		ptrT := types.GetPointer(ptrSize, wcharT, wordSize)
		intT := types.GetBase(4, TYPE_INT, "int")
		return &UserPcodeOp{
			name:    "builtin_wcsncpy",
			opType:  UserOpDatatype,
			index:   id,
			outType: ptrT,
			inTypes: []Datatype{ptrT, ptrT, intT},
		}
	}
	return nil
}
