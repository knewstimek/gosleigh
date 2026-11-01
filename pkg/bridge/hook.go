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
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/sla"
)

// InstructionHook is the extension point for behavior Ghidra does not have
// (Gosleigh extension, not in Ghidra): it sees every instruction's raw p-code
// right after the host flow overrides and before flow is followed, so a
// rewrite changes which paths are collected. The extensions live in pkg/ext;
// with no hooks configured the build is the plain Ghidra port.
type InstructionHook interface {
	// RewriteInstruction returns the instruction to use instead of tr, and a
	// warning to print at its address ("" for none). It must not modify tr's
	// Ops slice in place: the translation may be shared.
	RewriteInstruction(tr sla.InstructionTranslation) (sla.InstructionTranslation, string)
}

// applyInstructionHooks runs the hooks in order and joins their warnings.
func applyInstructionHooks(tr sla.InstructionTranslation, hooks []InstructionHook) (sla.InstructionTranslation, string) {
	note := ""
	for _, h := range hooks {
		var w string
		tr, w = h.RewriteInstruction(tr)
		if w != "" {
			if note != "" {
				note += "; "
			}
			note += w
		}
	}
	return tr, note
}

// markHookNotes prints the hooks' warnings at their instructions.
func markHookNotes(fd *pcode.Funcdata, records []instructionRecord) {
	for _, r := range records {
		if r.note != "" {
			fd.Warning(r.note, r.translation.Address)
		}
	}
}
