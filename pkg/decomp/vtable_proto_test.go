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
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// An IL2CPP-style virtual call through the object's class:
//
//	sub rsp, 0x28
//	mov rax, [rcx]          ; this->klass
//	mov r8, [rax+0x18]      ; klass->slot0.method (hidden MethodInfo*)
//	mov edx, 7
//	mov r9d, 5              ; scratch, not an argument of the slot's method
//	call [rax+0x10]         ; klass->slot0.methodPtr
//	add rsp, 0x28
//	ret
var vtableSlotCall = []byte{
	0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x01, 0x4c, 0x8b, 0x40, 0x18,
	0xba, 0x07, 0x00, 0x00, 0x00, 0x41, 0xb9, 0x05, 0x00, 0x00, 0x00,
	0xff, 0x50, 0x10, 0x48, 0x83, 0xc4, 0x28, 0xc3,
}

// vtableTypes builds the chain a host describes from IL2CPP metadata: the
// object points to its class, whose vtable slot holds a function pointer typed
// with the slot method's prototype (this, int, MethodInfo*) -> bool.
func vtableTypes() (objPtr *pcode.HostTypeDesc) {
	methodInfo := &pcode.HostTypeDesc{Name: "MethodInfo", Meta: "struct", Size: 8, ID: "MethodInfo",
		Fields: []pcode.HostFieldDesc{{Name: "methodPointer", Offset: 0, Type: &pcode.HostTypeDesc{Name: "undefined8", Meta: "unknown", Size: 8}}}}
	methodInfoPtr := &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: methodInfo}
	intT := &pcode.HostTypeDesc{Name: "int", Meta: "int", Size: 4}
	boolT := &pcode.HostTypeDesc{Name: "bool", Meta: "bool", Size: 1}
	obj := &pcode.HostTypeDesc{Name: "Foo_o", Meta: "struct", Size: 0x10, ID: "Foo_o"}
	objPtr = &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: obj}
	fn := &pcode.HostTypeDesc{Name: "Foo_Bar_fn", Meta: "code", Size: 1, Proto: &pcode.HostCodeProto{
		InputLocked: true, OutLocked: true, ExtraPop: pcode.ExtrapopUnknown,
		Params: []*pcode.HostTypeDesc{objPtr, intT, methodInfoPtr}, Ret: boolT,
	}}
	cls := &pcode.HostTypeDesc{Name: "Foo_c", Meta: "struct", Size: 0x20, ID: "Foo_c", Fields: []pcode.HostFieldDesc{
		{Name: "name", Offset: 0, Type: &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: &pcode.HostTypeDesc{Name: "char", Meta: "int", Size: 1, Char: true}}},
		{Name: "Bar_methodPtr", Offset: 0x10, Type: &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: fn}},
		{Name: "Bar_method", Offset: 0x18, Type: methodInfoPtr},
	}}
	obj.Fields = []pcode.HostFieldDesc{
		{Name: "klass", Offset: 0, Type: &pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: cls}},
		{Name: "value", Offset: 8, Type: intT},
	}
	return objPtr
}

// With this typed, the virtual call takes the slot's prototype
// (ActionDeindirect applies a typed function pointer's prototype), so r9 is
// not an argument and the call returns bool.
func TestVtableSlotPrototype(t *testing.T) {
	this := pcode.ResolveHostType(vtableTypes())
	host := hostProto{entry: 0x140001000, hf: pcode.HostFunction{
		Name: "caller", ExtraPop: pcode.ExtrapopUnknown, InputLocked: true,
		Params: []pcode.HostParam{{Name: "this", Type: this, Size: 8}},
	}}
	plain := decompileX64Fn(t, vtableSlotCall, decomp.Function{})
	t.Logf("untyped:\n%s", plain)
	got := decompileX64Fn(t, vtableSlotCall, decomp.Function{Host: host})
	t.Logf("typed:\n%s", got)
	if !strings.Contains(plain, ",5)") && !strings.Contains(plain, ", 5)") {
		t.Errorf("without types the scratch r9 should be taken as an argument (the test no longer shows the difference)")
	}
	if !strings.Contains(got, "Bar_methodPtr") || strings.Contains(got, ", 5)") || !strings.Contains(got, "Bar_method)") {
		t.Errorf("the call should go through the typed slot with (this, 7, method) only")
	}
}
