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

// externHost knows import slots by name only, the way a host reading a PE
// import table does: it has no function to describe at the slot address.
type externHost map[uint64]string

func (h externHost) QueryFunction(address.Address) (pcode.HostFunction, bool) {
	return pcode.HostFunction{}, false
}

func (h externHost) QueryExternalRef(a address.Address) (string, bool) {
	n, ok := h[a.Offset]
	return n, ok
}

// A call through an import slot keeps the imported function's name. The
// deindirected call usually needs a restart, after which the call site is
// rebuilt from the recorded override and must find the name again.
func TestDecompileExternalRefCallKeepsName(t *testing.T) {
	// 0x140001000: sub rsp,0x28
	// 0x140001004: mov ecx,5
	// 0x140001009: call qword ptr [rip+0xff1]   ; slot 0x140002000
	// 0x14000100f: add rsp,0x28
	// 0x140001013: ret
	code := make([]byte, 0x20)
	for i := range code {
		code[i] = 0xcc
	}
	copy(code, []byte{
		0x48, 0x83, 0xec, 0x28,
		0xb9, 0x05, 0x00, 0x00, 0x00,
		0xff, 0x15, 0xf1, 0x0f, 0x00, 0x00,
		0x48, 0x83, 0xc4, 0x28,
		0xc3,
	})
	// The slot holds what the file holds before the loader binds it: an RVA
	// into the import name table, not a code address.
	slot := []byte{0x40, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{
		{Name: ".text", VMA: 0x140001000, Data: code, Exec: true},
		{Name: ".idata", VMA: 0x140002000, Data: slot},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000, Host: externHost{0x140002000: "ExtFn"}, GhidraFormat: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.C, "ExtFn(5)") || strings.Contains(res.C, "func_0x") {
		t.Errorf("import call lost its name:\n%s", res.C)
	}
}
