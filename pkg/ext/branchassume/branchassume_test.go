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

package branchassume_test

import (
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/bridge"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/ext/branchassume"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

// test ecx,ecx; jz junk; lea eax,[rcx+1]; ret; junk: 06 06 (invalid in 64-bit)
var opaque = []byte{0x85, 0xc9, 0x74, 0x04, 0x8d, 0x41, 0x01, 0xc3, 0x06, 0x06, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}

const entry, jz = 0x140001000, 0x140001002

func decompile(t *testing.T, h *branchassume.Hook) string {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: entry, Data: opaque}})
	if err != nil {
		t.Fatal(err)
	}
	fn := decomp.Function{Entry: entry, GhidraFormat: true}
	if h != nil {
		fn.InstructionHooks = []bridge.InstructionHook{h}
	}
	res, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	return res.C
}

func TestAssumedBranchDropsTheOtherPath(t *testing.T) {
	if c := decompile(t, nil); !strings.Contains(c, "halt_baddata();") {
		t.Fatalf("without the hook the junk path must still halt (plain Ghidra):\n%s", c)
	}

	h := branchassume.New(map[uint64]branchassume.Direction{jz: branchassume.Fallthrough, 0x140001100: branchassume.Taken})
	c := decompile(t, h)
	for _, want := range []string{"/* WARNING: Conditional branch assumed never taken", "return param_1 + 1;"} {
		if !strings.Contains(c, want) {
			t.Errorf("fallthrough: missing %q:\n%s", want, c)
		}
	}
	if strings.Contains(c, "halt_baddata") || strings.Contains(c, "if (") {
		t.Errorf("fallthrough: the junk path survived:\n%s", c)
	}
	if u := h.Unapplied(); len(u) != 1 || u[0] != 0x140001100 {
		t.Errorf("Unapplied = %#x, want [0x140001100]", u)
	}

	c = decompile(t, branchassume.New(map[uint64]branchassume.Direction{jz: branchassume.Taken}))
	if !strings.Contains(c, "assumed always taken") || !strings.Contains(c, "halt_baddata();") || strings.Contains(c, "param_1 + 1") {
		t.Errorf("taken: want only the jump target path:\n%s", c)
	}
}
