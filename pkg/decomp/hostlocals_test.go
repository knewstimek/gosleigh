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

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

// A typed host local is one locked variable: a structure on the stack is
// accessed through its members, and a host local the code never touches is
// not declared.
func TestDecompileHostLocalTypes(t *testing.T) {
	code := []byte{
		0x48, 0x83, 0xec, 0x28, // sub rsp,0x28
		0x48, 0x8d, 0x4c, 0x24, 0x20, // lea rcx,[rsp+0x20]
		0xe8, 0x12, 0x00, 0x00, 0x00, // call 0x140001020
		0x8b, 0x44, 0x24, 0x24, // mov eax,[rsp+0x24]
		0x48, 0x83, 0xc4, 0x28, // add rsp,0x28
		0xc3, // ret
	}
	for len(code) < 0x20 {
		code = append(code, 0xcc)
	}
	code = append(code, 0xc3)
	intDesc := &pcode.HostTypeDesc{Name: "int", Meta: "int", Size: 4}
	point := &pcode.HostTypeDesc{Name: "Point", Meta: "struct", Size: 8, ID: "Point",
		Fields: []pcode.HostFieldDesc{{Name: "x", Offset: 0, Type: intDesc}, {Name: "y", Offset: 4, Type: intDesc}}}
	res, err := load(t, 64, code, 0x140001000).Decompile(decomp.Function{
		Entry:          0x140001000,
		HostLocals:     map[int64]string{-8: "pt", -0x20: "unused"},
		HostLocalTypes: map[int64]*pcode.HostTypeDesc{-8: point, -0x20: intDesc},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Point pt;", "&pt", "return pt.y;"} {
		if !strings.Contains(res.C, want) {
			t.Errorf("output lacks %q:\n%s", want, res.C)
		}
	}
	if strings.Contains(res.C, "unused") {
		t.Errorf("an untouched host local is declared:\n%s", res.C)
	}
}

// goHost gives Go ABI0 prototypes: arguments by the model, the result in a
// stack slot after them (custom storage).
type goHost map[uint64]pcode.HostFunction

func (h goHost) QueryFunction(a address.Address) (pcode.HostFunction, bool) {
	hf, ok := h[a.Offset]
	return hf, ok
}

func (h goHost) QueryExternalRef(address.Address) (string, bool) { return "", false }

// A locked return in a stack slot is the callee's return value and, at a
// call site, the CALL's output once the caller's stack is heritaged.
func TestDecompileStackLocatedReturn(t *testing.T) {
	spec, err := specs.X86(32, specs.CompilerGolang)
	if err != nil {
		t.Fatal(err)
	}
	code := []byte{
		// 0x401000 add: mov eax,[esp+4]; add eax,[esp+8]; mov [esp+0xc],eax; ret
		0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0x89, 0x44, 0x24, 0x0c, 0xc3,
		0xcc, 0xcc, 0xcc,
		// 0x401010 caller: sub esp,0xc; mov dword [esp],1; mov dword [esp+4],2;
		// call add; mov eax,[esp+8]; add esp,0xc; ret
		0x83, 0xec, 0x0c,
		0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00,
		0xc7, 0x44, 0x24, 0x04, 0x02, 0x00, 0x00, 0x00,
		0xe8, 0xd9, 0xff, 0xff, 0xff,
		0x8b, 0x44, 0x24, 0x08,
		0x83, 0xc4, 0x0c,
		0xc3,
	}
	intT := pcode.ResolveHostType(&pcode.HostTypeDesc{Name: "int", Meta: "int", Size: 4})
	host := goHost{0x401000: {
		Name: "add", ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutputLocked: true,
		Params: []pcode.HostParam{{Name: "a", Type: intT, Size: 4}, {Name: "b", Type: intT, Size: 4}},
		Output: &pcode.HostParam{Type: intT, Size: 4, Space: "stack", Offset: 0xc},
	}}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x401000, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	callee, err := prog.Decompile(decomp.Function{Entry: 0x401000, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(callee.C, "int add(int a, int b)") || !strings.Contains(callee.C, "a + b") {
		t.Errorf("stack-located return not applied to the function:\n%s", callee.C)
	}
	caller, err := prog.Decompile(decomp.Function{Entry: 0x401010, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(caller.C, "= add(1,2);") && !strings.Contains(caller.C, "= add(1, 2);") {
		t.Errorf("the call's stack-located result is not its output:\n%s", caller.C)
	}
}
