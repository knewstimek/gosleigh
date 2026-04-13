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

// FuncCallSpecs holds per-call prototype state.
// C++ parity: fspec.hh FuncCallSpecs (partial)
type FuncCallSpecs struct {
	FuncProto
	op *PcodeOp
	fd *Funcdata
}

// C++ parity: Funcdata::getCallSpecs / FuncCallSpecs::FuncCallSpecs
func newFuncCallSpecs(fd *Funcdata, op *PcodeOp) *FuncCallSpecs {
	return &FuncCallSpecs{
		FuncProto: *NewFuncProto(nil),
		op:        op,
		fd:        fd,
	}
}

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
