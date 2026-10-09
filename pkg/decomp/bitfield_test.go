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

// flagsHost describes struct Flags { uint ready:1; uint mode:3; int level:4;
// uint rest:24; } and functions taking a Flags pointer (and an int).
type flagsHost map[uint64]pcode.HostFunction

func (h flagsHost) QueryFunction(a address.Address) (pcode.HostFunction, bool) {
	hf, ok := h[a.Offset]
	return hf, ok
}

func (h flagsHost) QueryExternalRef(address.Address) (string, bool) { return "", false }

func flagsPrototype(name string, withValue bool, ret pcode.Datatype) pcode.HostFunction {
	uintDesc := &pcode.HostTypeDesc{Name: "uint", Meta: "uint", Size: 4}
	intDesc := &pcode.HostTypeDesc{Name: "int", Meta: "int", Size: 4}
	flags := &pcode.HostTypeDesc{Name: "Flags", Meta: "struct", Size: 4, ID: "Flags", Fields: []pcode.HostFieldDesc{
		{Name: "ready", Offset: 0, Type: uintDesc, BitOffset: 0, BitSize: 1},
		{Name: "mode", Offset: 0, Type: uintDesc, BitOffset: 1, BitSize: 3},
		{Name: "level", Offset: 0, Type: intDesc, BitOffset: 4, BitSize: 4},
		{Name: "rest", Offset: 0, Type: uintDesc, BitOffset: 8, BitSize: 24},
	}}
	ptr := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "ptr", Size: 8, Elem: flags})
	intT := pcode.ResolveHostType(intDesc)
	hf := pcode.HostFunction{Name: name, ExtraPop: pcode.ExtrapopUnknown, InputLocked: true, OutputLocked: true,
		Params: []pcode.HostParam{{Name: "f", Type: ptr, Size: 8, NameLock: true}},
		Output: &pcode.HostParam{Type: ret, Size: ret.Size()}}
	if withValue {
		hf.Params = append(hf.Params, pcode.HostParam{Name: "v", Type: intT, Size: 4, NameLock: true})
	}
	return hf
}

// Bitfield writes and reads print as member accesses, the masks and shifts
// gone. C++ parity: RuleBitFieldStore / RuleBitFieldLoad with
// PrintC::emitBitFieldStore / opZpullOp.
func TestDecompileBitfields(t *testing.T) {
	intT := pcode.ResolveHostType(&pcode.HostTypeDesc{Name: "int", Meta: "int", Size: 4})
	voidT := pcode.ResolveHostType(&pcode.HostTypeDesc{Meta: "void"})
	code := []byte{
		// 0x140001000 set_mode(f, v): f->mode = v
		0x8b, 0x01, // mov eax,[rcx]
		0x83, 0xe2, 0x07, // and edx,7
		0x83, 0xe0, 0xf1, // and eax,0xfffffff1
		0x01, 0xd2, // add edx,edx
		0x09, 0xd0, // or eax,edx
		0x89, 0x01, // mov [rcx],eax
		0xc3,
		0xcc,
		// 0x140001010 get_mode(f): return f->mode
		0x8b, 0x01, // mov eax,[rcx]
		0xd1, 0xe8, // shr eax,1
		0x83, 0xe0, 0x07, // and eax,7
		0xc3,
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
		// 0x140001020 get_level(f): return f->level (signed)
		0x8b, 0x01, // mov eax,[rcx]
		0xc1, 0xe0, 0x18, // shl eax,24
		0xc1, 0xf8, 0x1c, // sar eax,28
		0xc3,
	}
	host := flagsHost{
		0x140001000: flagsPrototype("set_mode", true, voidT),
		0x140001010: flagsPrototype("get_mode", false, intT),
		0x140001020: flagsPrototype("get_level", false, intT),
	}
	prog := load(t, 64, code, 0x140001000)
	for _, c := range []struct {
		entry uint64
		want  string
	}{
		{0x140001000, "f->mode = v;"},
		{0x140001010, "f->mode"},
		{0x140001020, "f->level"},
	} {
		res, err := prog.Decompile(decomp.Function{Entry: c.entry, Host: host})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s", res.C)
		if !strings.Contains(res.C, c.want) {
			t.Errorf("0x%x: output lacks %q:\n%s", c.entry, c.want, res.C)
		}
	}
}
