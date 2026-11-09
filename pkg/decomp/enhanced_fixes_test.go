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
	"github.com/knewstimek/gosleigh/pkg/specs"
)

func decompileX64Fn(t *testing.T, code []byte, fn decomp.Function) string {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x140001000, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	fn.Entry = 0x140001000
	res, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	return res.C
}

// A byte switch whose index is computed twice:
//
//	movzx esi, dl
//	call f
//	lea eax, [rsi-0x80]
//	cmp eax, 0xd
//	ja  default
//	lea eax, [rsi-0x80]
//	movsxd rcx, eax
//	lea rdx, [table]
//	movsxd rcx, [rdx+rcx*4]
//	add rcx, rdx
//	jmp rcx
//	(14 x "mov eax, N; ret"), default: xor eax, eax; f: ret, table
//
// At flow time the guard does not match the second lea (two copies of
// zext(DL)), so zext(DL) with range 0x80..0x8d is the normalized value; after
// CSE the second lea is. Ghidra 12's core prints case 0x100..0x10d with "may not
// be properly labeled" (checked with the C++ decompiler on the same pattern in
// a real binary).
var byteSwitchTwoLeas = []byte{
	0x0f, 0xb6, 0xf2, 0xe8, 0x74, 0x00, 0x00, 0x00, 0x8d, 0x46, 0x80, 0x83, 0xf8, 0x0d, 0x77, 0x6a,
	0x8d, 0x46, 0x80, 0x48, 0x63, 0xc8, 0x48, 0x8d, 0x15, 0x63, 0x00, 0x00, 0x00, 0x48, 0x63, 0x0c,
	0x8a, 0x48, 0x01, 0xd1, 0xff, 0xe1, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x02, 0x00, 0x00,
	0x00, 0xc3, 0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x05,
	0x00, 0x00, 0x00, 0xc3, 0xb8, 0x06, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3,
	0xb8, 0x08, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x09, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x0a, 0x00, 0x00,
	0x00, 0xc3, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x0c, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x0d,
	0x00, 0x00, 0x00, 0xc3, 0xb8, 0x0e, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0xcc,
	0xa6, 0xff, 0xff, 0xff, 0xac, 0xff, 0xff, 0xff, 0xb2, 0xff, 0xff, 0xff, 0xb8, 0xff, 0xff, 0xff,
	0xbe, 0xff, 0xff, 0xff, 0xc4, 0xff, 0xff, 0xff, 0xca, 0xff, 0xff, 0xff, 0xd0, 0xff, 0xff, 0xff,
	0xd6, 0xff, 0xff, 0xff, 0xdc, 0xff, 0xff, 0xff, 0xe2, 0xff, 0xff, 0xff, 0xe8, 0xff, 0xff, 0xff,
	0xee, 0xff, 0xff, 0xff, 0xf4, 0xff, 0xff, 0xff,
}

func TestCurrentSwitchLabels(t *testing.T) {
	plain := decompileX64Fn(t, byteSwitchTwoLeas, decomp.Function{})
	t.Logf("plain:\n%s", plain)
	if !strings.Contains(plain, "case 0x100:") || !strings.Contains(plain, "may not be properly labeled") {
		t.Errorf("without the extension the labels should match Ghidra (case 0x100 + warning):\n%s", plain)
	}
	ext := decompileX64Fn(t, byteSwitchTwoLeas, decomp.Function{Extensions: pcode.Extensions{CurrentSwitchLabels: true}})
	t.Logf("extension:\n%s", ext)
	if !strings.Contains(ext, "case 0x80:") || !strings.Contains(ext, "case 0x8d:") ||
		strings.Contains(ext, "case 0x10") || strings.Contains(ext, "properly labeled") {
		t.Errorf("with CurrentSwitchLabels the labels should be 0x80..0x8d:\n%s", ext)
	}
}

// this (RCX) is homed and used as a base; the home slot's address is passed
// on (so it is one variable) and the slot is then read as a double:
//
//	   mov [rsp+8], rcx ; sub rsp, 0x28 ; mov eax, [rcx+0xd8] ; mov [rdx], eax
//	   lea rcx, [rsp+0x30] ; call g ; movsd xmm0, [rsp+0x30] ; addsd xmm0, xmm0
//	   add rsp, 0x28 ; ret
//	g: ret
//
// Ghidra 12's core types param_1 double (checked on the same pattern in a real
// binary with the C++ decompiler).
func TestNoFloatAddresses(t *testing.T) {
	code := []byte{
		0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0x8b, 0x81, 0xd8, 0x00, 0x00, 0x00,
		0x89, 0x02, 0x48, 0x8d, 0x4c, 0x24, 0x30, 0xe8, 0x10, 0x00, 0x00, 0x00,
		0xf2, 0x0f, 0x10, 0x44, 0x24, 0x30, 0xf2, 0x0f, 0x58, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xc3,
	}
	plain := decompileX64Fn(t, code, decomp.Function{})
	t.Logf("plain:\n%s", plain)
	ext := decompileX64Fn(t, code, decomp.Function{Extensions: pcode.Extensions{NoFloatAddresses: true}})
	t.Logf("extension:\n%s", ext)
	if !strings.Contains(plain, "double param_1") {
		t.Errorf("without the extension param_1 should be double as in Ghidra")
	}
	if strings.Contains(ext, "double param_1") || strings.Contains(ext, "bit_cast<longlong>(param_1)") {
		t.Errorf("with NoFloatAddresses param_1 should stay an integer")
	}
}

// Calls after a dynamic stack allocation:
//
//	   push rbp
//	   mov rbp, rsp
//	   sub rsp, rcx
//	   call f
//	   call f
//	   mov rsp, rbp
//	   pop rbp
//	   ret
//	f: ret
//
// RSP is the frame base minus an unknown amount, so Ghidra keeps each call's
// return address store: "*(undefined8 *)(... + -8) = 0x14000100c;".
var callsAfterAlloca = []byte{
	0x55, 0x48, 0x89, 0xe5, 0x48, 0x29, 0xcc,
	0xe8, 0x0a, 0x00, 0x00, 0x00,
	0xe8, 0x05, 0x00, 0x00, 0x00,
	0x48, 0x89, 0xec, 0x5d, 0xc3,
	0xc3,
}

func TestAllocaReturnStores(t *testing.T) {
	plain := decompileX64Fn(t, callsAfterAlloca, decomp.Function{})
	t.Logf("plain:\n%s", plain)
	if !strings.Contains(plain, "0x14000100c") || !strings.Contains(plain, "0x140001011") {
		t.Errorf("without the extension the return address stores should be kept as in Ghidra:\n%s", plain)
	}
	ext := decompileX64Fn(t, callsAfterAlloca, decomp.Function{Extensions: pcode.Extensions{AllocaReturnStores: true}})
	t.Logf("extension:\n%s", ext)
	if strings.Contains(ext, "0x14000100c") || strings.Contains(ext, "0x140001011") || strings.Count(ext, "func_0x0000000140001016()") != 2 {
		t.Errorf("with AllocaReturnStores both calls should stay and the stores should go:\n%s", ext)
	}
}

// Functions that do not move the stack pointer by a register are left as
// Ghidra prints them: the same calls without "sub rsp, rcx", and a call to its
// own fall-through after it (the program counter read "call next; pop rax").
func TestAllocaReturnStoresOnlyAlloca(t *testing.T) {
	noAlloca := append([]byte{}, callsAfterAlloca...)
	copy(noAlloca[4:7], []byte{0x90, 0x90, 0x90}) // sub rsp, rcx -> nops
	pcRead := []byte{0x48, 0x29, 0xcc, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xc3}
	for name, code := range map[string][]byte{"no alloca": noAlloca, "pc read": pcRead} {
		plain := decompileX64Fn(t, code, decomp.Function{})
		got := decompileX64Fn(t, code, decomp.Function{Extensions: pcode.Extensions{AllocaReturnStores: true}})
		if plain != got {
			t.Errorf("%s changed with AllocaReturnStores:\nplain:\n%s\nextension:\n%s", name, plain, got)
		}
	}
}
