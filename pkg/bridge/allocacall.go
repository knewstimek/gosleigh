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

package bridge

import (
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// dropAllocaReturnStores removes the return address store of every call in a
// function that moves its stack pointer by a register (beyond Ghidra,
// Extensions.AllocaReturnStores).
//
// x86 CALL is "SP = SP - 8; *SP = inst_next; CALL dest". Ghidra removes the
// store as a dead stack write while SP is a constant offset from the frame
// base. After "sub rsp, rax" (alloca, chkstk probes) SP is base minus an
// unknown amount, the store stays a STORE through a pointer, and every call
// prints "*(undefined8 *)((longlong)&local_10 + -param_1) = 0x14000100c;".
//
// Functions without such a stack adjustment are left untouched: dropping the
// store there removes an op Ghidra deletes only later, which changes how
// blocks are structured (measured on the realexe goldens). A call to its own
// fall-through ("call $+5; pop") reads the slot and keeps its store.
func dropAllocaReturnStores(records []instructionRecord) {
	type retStore struct{ rec, op int }
	var stores []retStore
	var sp *pcode.VarnodeData
	for ri := range records {
		tr := &records[ri].translation
		if i := returnAddressStore(tr.Ops, tr.Next.Offset); i >= 0 {
			stores = append(stores, retStore{ri, i})
			if sp == nil {
				v := tr.Ops[i].Inputs[1]
				sp = &v
			}
		}
	}
	if sp == nil || !movesStackByRegister(records, *sp) {
		return
	}
	for _, s := range stores {
		tr := &records[s.rec].translation
		if tr.Ops[s.op].Inputs[1] != *sp {
			continue
		}
		// The translation's Ops may be shared with the instruction cache.
		ops := make([]pcode.RawOp, 0, len(tr.Ops)-1)
		ops = append(ops, tr.Ops[:s.op]...)
		tr.Ops = append(ops, tr.Ops[s.op+1:]...)
	}
}

// returnAddressStore is the index of the STORE of the fall-through address
// before the instruction's CALL or CALLIND, -1 if there is none.
func returnAddressStore(ops []pcode.RawOp, next uint64) int {
	call := -1
	for i, op := range ops {
		if op.OpCode == pcode.CPUI_CALL || op.OpCode == pcode.CPUI_CALLIND {
			call = i
			break
		}
	}
	if call < 0 {
		return -1
	}
	if op := ops[call]; op.OpCode == pcode.CPUI_CALL && len(op.Inputs) > 0 &&
		!isConstVarnode(op.Inputs[0]) && op.Inputs[0].Offset == next {
		return -1 // call $+N; pop: the caller reads its own return address
	}
	for i := call - 1; i >= 0; i-- {
		op := ops[i]
		if op.OpCode == pcode.CPUI_STORE && len(op.Inputs) == 3 &&
			op.Inputs[1].Space != nil && op.Inputs[1].Space.Kind != address.SpaceKindConstant &&
			isConstVarnode(op.Inputs[2]) && op.Inputs[2].Offset == next {
			return i
		}
	}
	return -1
}

// movesStackByRegister reports an "SP = SP +/- reg" anywhere in the function.
func movesStackByRegister(records []instructionRecord, sp pcode.VarnodeData) bool {
	for _, r := range records {
		for _, op := range r.translation.Ops {
			if (op.OpCode != pcode.CPUI_INT_SUB && op.OpCode != pcode.CPUI_INT_ADD) ||
				op.Output == nil || *op.Output != sp || len(op.Inputs) != 2 {
				continue
			}
			a, b := op.Inputs[0], op.Inputs[1]
			if a == sp && !isConstVarnode(b) || b == sp && !isConstVarnode(a) {
				return true
			}
		}
	}
	return false
}

func isConstVarnode(v pcode.VarnodeData) bool {
	return v.Space != nil && v.Space.Kind == address.SpaceKindConstant
}
