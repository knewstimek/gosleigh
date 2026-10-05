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

// FuncCallSpecs holds per-call prototype state.
// C++ parity: fspec.hh FuncCallSpecs (partial)
type FuncCallSpecs struct {
	FuncProto
	op *PcodeOp
	fd *Funcdata

	// effectiveExtraPop is the working extrapop for this call site: the
	// prototype's when known, otherwise solved by ActionStackPtrFlow.
	// C++ parity: FuncCallSpecs::effective_extrapop.
	effectiveExtraPop int32
	// stackoffset is the caller's stack-pointer offset at this call, relative
	// to the incoming stack pointer (spacebaseOffsetUnknown until resolved).
	// C++ parity: FuncCallSpecs::stackoffset.
	stackoffset uint64
	// stackPlaceholderSlot is the CALL input slot holding the stack-pointer
	// placeholder LOAD, or -1. C++ parity: FuncCallSpecs::stackPlaceholderSlot.
	stackPlaceholderSlot int
	// name/entryAddress identify the callee of a direct call.
	// C++ parity: FuncCallSpecs::name / entryaddress.
	name         string
	entryAddress address.Address
	// hostProto is the callee's prototype as reported by the host, standing
	// in for the callee Funcdata C++ links via queryFunction.
	hostProto *HostFunction
	// lockedIn / lockedOut are the callee's locked prototype slots (host
	// prototype with typelocked parameters / return), resolved to storage.
	// C++ parity: the ProtoParameters of a locked FuncProto (ProtoStoreSymbol).
	lockedIn  []ProtoSlot
	lockedOut *ProtoSlot
}

// HostScope is the analysis environment's symbol database, queried by the
// decompiler core for facts it cannot derive from the function body. A nil
// HostScope behaves like the standalone C++ core with no program loaded.
// C++ parity: the ScopeGhidra global scope (queryFunction, data symbols).
type HostScope interface {
	// QueryFunction describes the function starting at addr.
	QueryFunction(addr address.Address) (HostFunction, bool)
	// QueryExternalRef returns the name of the external function whose
	// reference (e.g. an import address table slot) lives at addr.
	// C++ parity: Scope::queryExternalRefFunction / ExternRefSymbol.
	QueryExternalRef(addr address.Address) (name string, ok bool)
}

// HostFunction is what the host reports about a function: its display name
// and the prototype facts the C++ core receives from FunctionPrototype
// (Java grabFromFunction): calling-convention name ("" or "unknown" when not
// known) and extrapop (purge + stackshift; ExtrapopUnknown when unknown).
type HostFunction struct {
	Name     string
	Model    string
	ExtraPop int32
	// NoReturn: the function never returns (FuncProto::isNoReturn).
	NoReturn bool
	// InputLocked: Params is the complete, typed parameter list.
	// OutputLocked: Output is the typed return (Output.Type void = void).
	// C++ parity: FuncProto::isInputLocked / isOutputLocked.
	InputLocked, OutputLocked bool
	Params                    []HostParam
	Output                    *HostParam
}

// HostParam is one storage slot of a host prototype: a register or a stack
// offset relative to the callee's stack pointer at entry, named by space.
type HostParam struct {
	Space   string
	Offset  uint64
	Size    int32
	Type    Datatype
	Name    string
	ThisPtr bool
}

// C++ parity: FuncCallSpecs::FuncCallSpecs + FlowInfo::queryCall/setFuncdata:
// a direct CALL records its entry address and takes the callee's display name
// from the global scope.
func newFuncCallSpecs(fd *Funcdata, op *PcodeOp) *FuncCallSpecs {
	fc := &FuncCallSpecs{
		FuncProto:            *NewFuncProto(nil),
		op:                   op,
		fd:                   fd,
		effectiveExtraPop:    ExtrapopUnknown,
		stackoffset:          spacebaseOffsetUnknown,
		stackPlaceholderSlot: -1,
	}
	op.callSpec = fc
	if op.Code() == CPUI_CALL && op.NumInput() > 0 && op.Input(0) != nil {
		if in0 := op.Input(0); !in0.IsConstant() {
			fc.entryAddress = in0.Addr()
			if fd != nil && fd.hostScope != nil {
				if hf, ok := fd.hostScope.QueryFunction(fc.entryAddress); ok {
					fc.name = hf.Name
					fc.hostProto = &hf
				}
			}
		}
	}
	return fc
}

// GetName returns the callee's display name ("" when unknown).
// C++ parity: FuncCallSpecs::getName.
func (fc *FuncCallSpecs) GetName() string { return fc.name }

// GetEntryAddress returns the callee entry address of a direct call.
// C++ parity: FuncCallSpecs::getEntryAddress.
func (fc *FuncCallSpecs) GetEntryAddress() address.Address { return fc.entryAddress }

// GetOp returns the CALL/CALLIND op this spec describes.
// C++ parity: FuncCallSpecs::getOp.
func (fc *FuncCallSpecs) GetOp() *PcodeOp { return fc.op }

// SetEffectiveExtraPop sets the working extrapop of this call site.
// C++ parity: FuncCallSpecs::setEffectiveExtraPop.
func (fc *FuncCallSpecs) SetEffectiveExtraPop(ep int32) { fc.effectiveExtraPop = ep }

// GetEffectiveExtraPop returns the working extrapop of this call site.
// C++ parity: FuncCallSpecs::getEffectiveExtraPop.
func (fc *FuncCallSpecs) GetEffectiveExtraPop() int32 { return fc.effectiveExtraPop }

// GetFuncdata returns the associated callee Funcdata, if any.
// TODO known mismatch: Gosleigh does not yet track callee Funcdata objects for calls.
// C++ parity: FuncCallSpecs::getFuncdata
func (fc *FuncCallSpecs) GetFuncdata() *Funcdata {
	if fc == nil {
		return nil
	}
	_ = fc.fd
	return nil
}

// InsertPcode inserts any upon-return p-code for this call site.
// TODO known mismatch: upon-return injection from pcodeinjectlib is not yet ported.
// C++ parity: FuncCallSpecs::insertPcode
func (fc *FuncCallSpecs) InsertPcode(_ *Funcdata) {}
