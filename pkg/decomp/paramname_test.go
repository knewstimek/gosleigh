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
)

// hostProtos knows several functions' prototypes by entry.
type hostProtos map[uint64]pcode.HostFunction

func (h hostProtos) QueryFunction(a address.Address) (pcode.HostFunction, bool) {
	hf, ok := h[a.Offset]
	return hf, ok
}

func (h hostProtos) QueryExternalRef(address.Address) (string, bool) { return "", false }

// The function's float parameter arg_1 (XMM1) and a pointer passed twice to a
// callee whose locked parameter is also named arg_1:
//
//	   movss [rcx+0x10], xmm1
//	   push rbx ; sub rsp, 0x20
//	   mov rbx, [rcx+8]
//	   mov rcx, rbx ; call g
//	   mov rcx, rbx ; call g
//	   add rsp, 0x20 ; pop rbx ; ret
//	g: ret
//
// The pointer inherits the callee's parameter name, made unique against the
// function's own parameter symbols (ScopeInternal::makeNameUnique), so it is
// not printed as arg_1.
func TestInheritedNameAvoidsParams(t *testing.T) {
	code := []byte{
		0xf3, 0x0f, 0x11, 0x49, 0x10, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0x59, 0x08,
		0x48, 0x89, 0xd9, 0xe8, 0x0e, 0x00, 0x00, 0x00,
		0x48, 0x89, 0xd9, 0xe8, 0x06, 0x00, 0x00, 0x00,
		0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3, 0xc3,
	}
	ptr := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: &pcode.HostTypeDesc{Name: "void", Meta: "void", Size: 0}})
	flt := pcode.ResolveHostType(&pcode.HostTypeDesc{Name: "float", Meta: "float", Size: 4})
	void := pcode.ResolveHostType(&pcode.HostTypeDesc{Name: "void", Meta: "void", Size: 0})
	host := hostProtos{
		0x140001000: {Name: "f", ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutputLocked: true,
			Params: []pcode.HostParam{{Name: "__this", Type: ptr, Size: 8}, {Name: "arg_1", Type: flt, Size: 4}},
			Output: &pcode.HostParam{Type: void}},
		0x140001024: {Name: "g", ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutputLocked: true,
			Params: []pcode.HostParam{{Name: "arg_1", Type: ptr, Size: 8}},
			Output: &pcode.HostParam{Type: void}},
	}
	got := decompileX64Fn(t, code, decomp.Function{Host: host})
	t.Logf("\n%s", got)
	if !strings.Contains(got, "float arg_1") {
		t.Fatalf("the prototype was not applied")
	}
	if strings.Contains(got, "arg_1 = ") || strings.Contains(got, "g(arg_1)") {
		t.Errorf("the pointer passed to g took the parameter's name arg_1")
	}
}
