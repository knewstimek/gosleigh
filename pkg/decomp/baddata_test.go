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
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/decomp"
)

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
