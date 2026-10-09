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
	"fmt"
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

func load(t *testing.T, bits int, code []byte, vma uint64) *decomp.Program {
	t.Helper()
	spec, err := specs.X86(bits, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: vma, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

func TestDecompileX64(t *testing.T) {
	// lea eax,[rcx+rdx]; ret ; padding
	code := []byte{0x8d, 0x04, 0x11, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	res, err := load(t, 64, code, 0x140001000).Decompile(decomp.Function{Entry: 0x140001000, GhidraFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "\nint FUN_140001000(int param_1,int param_2)\n\n{\nreturn param_1 + param_2;\n}\n"
	if res.C != want {
		t.Errorf("got:\n%q\nwant:\n%q", res.C, want)
	}
}

func TestDecompileX86Stack(t *testing.T) {
	// mov eax,[esp+4]; add eax,[esp+8]; ret
	code := []byte{0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	res, err := load(t, 32, code, 0x401000).Decompile(decomp.Function{Entry: 0x401000, GhidraFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	// The stack arguments are recovered through the cspec stack model.
	want := "\nint FUN_00401000(int param_1,int param_2)\n\n{\nreturn param_1 + param_2;\n}\n"
	if res.C != want {
		t.Errorf("got:\n%q\nwant:\n%q", res.C, want)
	}
}

// hostNames is the smallest HostScope: callee names by entry.
type hostNames map[uint64]string

func (h hostNames) QueryFunction(a address.Address) (pcode.HostFunction, bool) {
	n, ok := h[a.Offset]
	return pcode.HostFunction{Name: n, ExtraPop: pcode.ExtrapopUnknown}, ok
}

func (h hostNames) QueryExternalRef(address.Address) (string, bool) { return "", false }

func TestDecompileHostNames(t *testing.T) {
	// 0x140001000: sub rsp,0x28; call 0x140001010; add rsp,0x28; ret
	// 0x140001010: mov eax,7; ret
	code := make([]byte, 0x20)
	for i := range code {
		code[i] = 0xcc
	}
	copy(code, []byte{0x48, 0x83, 0xec, 0x28, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0xc3})
	copy(code[0x10:], []byte{0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3})
	prog := load(t, 64, code, 0x140001000)
	host := hostNames{0x140001000: "outer", 0x140001010: "inner"}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000, Host: host, GhidraFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{" outer(void)", "inner();"} {
		if !strings.Contains(res.C, s) {
			t.Errorf("output lacks %q:\n%s", s, res.C)
		}
	}
}

func TestLoadRejectsIncompleteSpec(t *testing.T) {
	if _, err := decomp.Load(decomp.Spec{ID: "empty"}, []decomp.Section{{Data: []byte{0xc3}}}); err == nil {
		t.Error("Load accepted a spec without sla/pspec/cspec")
	}
	spec, _ := specs.X86(64, specs.CompilerWindows)
	if _, err := decomp.Load(spec, nil); err == nil {
		t.Error("Load accepted no sections")
	}
}

func Example() {
	spec, _ := specs.X86(64, specs.CompilerWindows)
	code := []byte{0x8d, 0x04, 0x11, 0xc3} // lea eax,[rcx+rdx]; ret
	code = append(code, make([]byte, 12)...)
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x140001000, Data: code}})
	if err != nil {
		panic(err)
	}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000, Name: "add"})
	if err != nil {
		panic(err)
	}
	fmt.Print(res.C)
	// Output:
	// int add(int param_1, int param_2) {
	//     return param_1 + param_2;
	// }
}
