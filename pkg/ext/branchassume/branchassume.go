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

// Package branchassume fixes chosen conditional branches to one direction
// before flow is followed (Gosleigh extension, not in Ghidra: Ghidra's
// Funcdata::overrideFlow rejects CBRANCH overrides, and its users patch the
// branch bytes instead). The direction is the caller's knowledge -- an opaque
// predicate confirmed by disassembly or a runtime trace -- never inferred
// here, so a path is dropped only where the caller said so. The p-code is
// rewritten, so this works for every processor, and each rewritten branch
// gets a warning in the output.
package branchassume

import (
	"sort"
	"sync"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/sla"
)

// Direction is the path a conditional branch is assumed to take.
type Direction uint8

const (
	// Taken: the branch always jumps (as if patched to an unconditional jump).
	Taken Direction = iota + 1
	// Fallthrough: the branch never jumps (as if patched to no-ops).
	Fallthrough
)

// Hook is a bridge.InstructionHook for one decompilation.
type Hook struct {
	branches map[uint64]Direction
	reasons  map[uint64]string
	mu       sync.Mutex
	applied  map[uint64]bool
}

// New fixes the conditional branch of the instruction at each address.
func New(branches map[uint64]Direction) *Hook {
	return &Hook{branches: branches, reasons: map[uint64]string{}, applied: map[uint64]bool{}}
}

// SetReason replaces the default "caller assumption" in the warning at addr
// with why the caller knows the direction (e.g. the flags are constant).
func (h *Hook) SetReason(addr uint64, why string) { h.reasons[addr] = why }

// RewriteInstruction implements bridge.InstructionHook.
func (h *Hook) RewriteInstruction(tr sla.InstructionTranslation) (sla.InstructionTranslation, string) {
	dir, ok := h.branches[tr.Address.Offset]
	if !ok {
		return tr, ""
	}
	idx := primaryCBranch(tr)
	if idx < 0 {
		return tr, ""
	}
	h.mu.Lock()
	h.applied[tr.Address.Offset] = true
	h.mu.Unlock()
	why := h.reasons[tr.Address.Offset]
	if why == "" {
		why = "caller assumption, not analysis"
	}
	ops := append([]pcode.RawOp(nil), tr.Ops[:idx]...)
	if dir == Taken {
		jump := tr.Ops[idx]
		jump.OpCode = pcode.CPUI_BRANCH
		jump.Inputs = jump.Inputs[:1:1] // drop the condition
		ops = append(ops, jump)
		ops = append(ops, tr.Ops[idx+1:]...)
		tr.Ops = ops
		return tr, "Conditional branch assumed always taken (" + why + ")"
	}
	tr.Ops = append(ops, tr.Ops[idx+1:]...)
	return tr, "Conditional branch assumed never taken (" + why + ")"
}

// primaryCBranch is the index of the instruction's conditional branch to
// another instruction, -1 if there is none. A CBRANCH to a constant-space
// target only skips p-code within the instruction (CMOVcc and friends), so
// it is not the instruction's branch.
func primaryCBranch(tr sla.InstructionTranslation) int {
	for i := len(tr.Ops) - 1; i >= 0; i-- {
		op := tr.Ops[i]
		if op.OpCode != pcode.CPUI_CBRANCH || len(op.Inputs) < 2 || op.Inputs[0].Space == nil {
			continue
		}
		if op.Inputs[0].Space.Kind == address.SpaceKindConstant {
			continue
		}
		return i
	}
	return -1
}

// Unapplied lists the requested addresses no collected instruction matched:
// not reached by the flow, or not a conditional branch.
func (h *Hook) Unapplied() []uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []uint64
	for a := range h.branches {
		if !h.applied[a] {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
