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

// A float returned in XMM0: cvtdq2ps writes the register lane by lane, movss
// from memory zeroes the upper lanes, and movaps copies the whole register,
// with the paths meeting at one ret. Ghidra 12's core prints this as
// "void FUN(void)" (checked with the C++ decompiler on the same bytes).
//
//	   movd xmm0, edx
//	   cvtdq2ps xmm0, xmm0
//	   comiss xmm0, xmm2
//	   jbe  L
//	   movss xmm0, [rcx]
//	   comiss xmm0, xmm2
//	   ja   L2
//	   subss xmm0, xmm1
//	   mulss xmm0, xmm1
//	   jmp  E
//	L2: movaps xmm0, xmm2
//	   addss xmm0, xmm1
//	   jmp  E
//	L: movaps xmm0, xmm1
//	E: ret
var mixedXMM0Return = []byte{
	0x66, 0x0f, 0x6e, 0xc2, 0x0f, 0x5b, 0xc0, 0x0f, 0x2f, 0xc2, 0x76, 0x1c,
	0xf3, 0x0f, 0x10, 0x01, 0x0f, 0x2f, 0xc2, 0x77, 0x0a,
	0xf3, 0x0f, 0x5c, 0xc1, 0xf3, 0x0f, 0x59, 0xc1, 0xeb, 0x0c,
	0x0f, 0x28, 0xc2, 0xf3, 0x0f, 0x58, 0xc1, 0xeb, 0x03,
	0x0f, 0x28, 0xc1,
	0xc3, 0xcc, 0xcc, 0xcc, 0xcc,
}

func decompileX64(t *testing.T, code []byte, ext pcode.Extensions) string {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: 0x140001000, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := prog.Decompile(decomp.Function{Entry: 0x140001000, Extensions: ext})
	if err != nil {
		t.Fatal(err)
	}
	return res.C
}

// Ghidra loses this return value (the function prints as void); with
// NestedPieceTrials the value and the code computing it are kept.
func TestNestedPieceTrialsReturn(t *testing.T) {
	plain := decompileX64(t, mixedXMM0Return, pcode.Extensions{})
	t.Logf("plain:\n%s", plain)
	if !strings.HasPrefix(plain, "void ") {
		t.Errorf("without the extension the output should match Ghidra (void):\n%s", plain)
	}
	ext := decompileX64(t, mixedXMM0Return, pcode.Extensions{NestedPieceTrials: true})
	t.Logf("extension:\n%s", ext)
	if strings.HasPrefix(ext, "void ") || !strings.Contains(ext, "(*param_1 - fVar3) * fVar3") {
		t.Errorf("with NestedPieceTrials the XMM0 return should be recovered:\n%s", ext)
	}
}

// One path returns a float sum, the other returns the float parameter in
// XMM1 unchanged:
//
//	test edx, edx
//	jz   L
//	movss xmm0, [rcx]
//	addss xmm0, xmm1
//	ret
//	L: movaps xmm0, xmm1
//	ret
var floatOrPassThrough = []byte{
	0x85, 0xd2, 0x74, 0x09, 0xf3, 0x0f, 0x10, 0x01, 0xf3, 0x0f, 0x58, 0xc1, 0xc3,
	0x0f, 0x28, 0xc1, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc,
}

// Ghidra keeps all 8 bytes of XMM0_Qa: the C++ decompiler prints
// "ulonglong func(float *param_1, ulonglong param_2)" for these bytes.
// NarrowFloatReturns returns float.
func TestNarrowFloatReturns(t *testing.T) {
	plain := decompileX64(t, floatOrPassThrough, pcode.Extensions{})
	t.Logf("plain:\n%s", plain)
	if !strings.HasPrefix(plain, "ulonglong ") {
		t.Errorf("without the extension the output should match Ghidra (ulonglong):\n%s", plain)
	}
	ext := decompileX64(t, floatOrPassThrough, pcode.Extensions{NarrowFloatReturns: true})
	t.Logf("extension:\n%s", ext)
	if !strings.HasPrefix(ext, "float ") || strings.Contains(ext, "ulonglong") {
		t.Errorf("with NarrowFloatReturns the return should be float:\n%s", ext)
	}
}
