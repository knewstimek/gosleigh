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

package decomp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/bridge"
	"github.com/knewstimek/gosleigh/pkg/decomp"
)

// Flow leaving FlowBounds is not followed: the branch ends in halt_missing()
// with Ghidra's out-of-bounds warning and the rest decompiles.
// C++ parity: FlowInfo::newAddress / handleOutOfBounds / fillinBranchStubs.
func TestDecompileFlowBounds(t *testing.T) {
	// test ecx,ecx; jz +0x10 (past the bounds); lea eax,[rcx+1]; ret; pad; target: xor eax,eax; ret
	code := make([]byte, 0x30)
	copy(code, []byte{0x85, 0xc9, 0x74, 0x10, 0x8d, 0x41, 0x01, 0xc3})
	for i := 8; i < len(code); i++ {
		code[i] = 0xcc
	}
	copy(code[0x14:], []byte{0x31, 0xc0, 0xc3})
	prog := load(t, 64, code, 0x140001000)
	plain, err := prog.Decompile(decomp.Function{Entry: 0x140001000, GhidraFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.C, "halt_missing") {
		t.Fatalf("no bounds: the whole flow is followed:\n%s", plain.C)
	}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000, GhidraFormat: true,
		FlowBounds: []bridge.AddrRange{{Lo: 0x140001000, Hi: 0x140001010}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/* WARNING: Function flows out of bounds */",
		"/* WARNING: Function flow out of bounds: r0x000140001002 flows to r0x000140001014 */",
		"halt_missing();",
		"return param_1 + 1;",
	} {
		if !strings.Contains(res.C, want) {
			t.Errorf("missing %q in:\n%s", want, res.C)
		}
	}
}

// A flow longer than MaxInstructions fails instead of being cut short
// (a cut leaves branches to undecoded targets); one that fits decompiles.
// C++ parity: FlowInfo::processInstruction with error_toomanyinstructions.
func TestDecompileTooManyInstructions(t *testing.T) {
	// test ecx,ecx; jz +4; lea eax,[rcx+1]; ret; xor eax,eax; ret (6 instructions)
	code := []byte{0x85, 0xc9, 0x74, 0x04, 0x8d, 0x41, 0x01, 0xc3, 0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	prog := load(t, 64, code, 0x140001000)
	if _, err := prog.Decompile(decomp.Function{Entry: 0x140001000, MaxInstructions: 6}); err != nil {
		t.Fatalf("flow that fits the limit: %v", err)
	}
	_, err := prog.Decompile(decomp.Function{Entry: 0x140001000, MaxInstructions: 5})
	if !errors.Is(err, bridge.ErrTooManyInstructions) {
		t.Fatalf("err = %v, want ErrTooManyInstructions", err)
	}
}

// A path into undecodable bytes ends in halt_baddata(); the rest of the
// function still decompiles. Expected text measured with the Ghidra 12 core
// (tools/decomp_dbg.exe) on the same bytes.
func TestDecompileBadInstructionHalts(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
	}{
		// test ecx,ecx; jz bad; lea eax,[rcx+1]; ret; bad: 06 (push es, invalid in 64-bit)
		{"undecodable", []byte{0x85, 0xc9, 0x74, 0x04, 0x8d, 0x41, 0x01, 0xc3, 0x06, 0x06, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}},
		// test ecx,ecx; jz +0x1000 (outside the image); lea eax,[rcx+1]; ret
		// (Ghidra's Java host answers unmapped bytes as bad data too)
		{"unmapped", []byte{0x85, 0xc9, 0x0f, 0x84, 0x00, 0x10, 0x00, 0x00, 0x8d, 0x41, 0x01, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := load(t, 64, tc.code, 0x140001000).Decompile(decomp.Function{Entry: 0x140001000, GhidraFormat: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"/* WARNING: Control flow encountered bad instruction data */",
				"if (param_1 != 0) {\nreturn param_1 + 1;\n}",
				"/* WARNING: Bad instruction - Truncating control flow here */\nhalt_baddata();\n}",
			} {
				if !strings.Contains(res.C, want) {
					t.Errorf("missing %q in:\n%s", want, res.C)
				}
			}
			if len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], "bad instruction at ") {
				t.Errorf("warnings = %q, want the translate failure", res.Warnings)
			}
		})
	}
}
