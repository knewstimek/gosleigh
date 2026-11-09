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

package analysis_test

import (
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/analysis"
	"github.com/knewstimek/gosleigh/pkg/decomp"
)

// R9 zeroed right after the call it was passed to, for a callee whose
// prototype is locked (it takes a stack parameter):
//
//	 0: sub rsp, 0x38
//	 4: mov ecx, 1 ; mov edx, 2 ; mov r8d, 3 ; lea r9, [rsp+0x30]
//	25: call f
//	30: mov [rsp+0x20], rax
//	35: xor r9d, r9d
//	38: mov r8b, 1 ; mov edx, 5 ; mov ecx, 4
//	51: call g
//	56: add rsp, 0x38 ; ret
//	f: jmp [rbx]                (no callee analysis answer)
//	g: mov eax, r9d ; add eax, [rsp+0x28] ; ret
//
// `xor r9d, r9d` reads the old R9, and the zero is g's argument, so Ghidra
// counts R9 as used by another call and drops it from the call to f.
func TestSelfCancelNoUse(t *testing.T) {
	prog, _ := loadCode(t, []byte{
		0x48, 0x83, 0xec, 0x38, 0xb9, 0x01, 0x00, 0x00, 0x00, 0xba, 0x02, 0x00, 0x00, 0x00,
		0x41, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x4c, 0x24, 0x30,
		0xe8, 0x22, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x45, 0x31, 0xc9,
		0x41, 0xb0, 0x01, 0xba, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x04, 0x00, 0x00, 0x00,
		0xe8, 0x0e, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x38, 0xc3, 0xcc, 0xcc, 0xcc,
		0xff, 0x23, 0xcc, 0xcc, 0xcc, 0xcc,
		0x44, 0x89, 0xc8, 0x03, 0x44, 0x24, 0x28, 0xc3,
	})
	decompile := func(selfCancel bool) string {
		fn := decomp.Function{Entry: base}
		analysis.NewEnhanced(prog).Apply(&fn)
		fn.Extensions.SelfCancelNoUse = selfCancel
		res, err := prog.Decompile(fn)
		if err != nil {
			t.Fatal(err)
		}
		return res.C
	}
	off, on := decompile(false), decompile(true)
	t.Logf("without:\n%s\nwith:\n%s", off, on)
	first := func(c string) string {
		i := strings.Index(c, "func_0x0000000140001040(")
		if i < 0 {
			return ""
		}
		return c[i : i+strings.Index(c[i:], ";")]
	}
	if strings.Count(first(on), ",") != 3 {
		t.Errorf("the call to f should keep its 4 register arguments: %q", first(on))
	}
	if first(off) == first(on) {
		t.Errorf("the test no longer reproduces the dropped R9 argument without the extension")
	}
}
