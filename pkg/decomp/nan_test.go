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

func decompileWith(t *testing.T, code []byte, fn decomp.Function) string {
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

// minss xmm0, xmm1 ; ret -- xmm0 = xmm0 < xmm1 ? xmm0 : xmm1, so a NaN in
// either operand yields xmm1.
var minssReturn = []byte{0xf3, 0x0f, 0x5d, 0xc1, 0xc3, 0xcc, 0xcc, 0xcc}

// Ghidra swaps !(a < b) into b <= a, which picks the other value for NaN
// (the C++ decompiler prints "if (param_2 <= param_1)" for these bytes);
// NaNExactCompares keeps the negation.
func TestNaNExactCompares(t *testing.T) {
	plain := decompileWith(t, minssReturn, decomp.Function{})
	t.Logf("plain:\n%s", plain)
	if strings.Contains(plain, "!(") {
		t.Errorf("without the extension the comparison is swapped, as in Ghidra:\n%s", plain)
	}
	ext := decompileWith(t, minssReturn, decomp.Function{Extensions: pcode.Extensions{NaNExactCompares: true}})
	t.Logf("extension:\n%s", ext)
	if !strings.Contains(ext, "!(") {
		t.Errorf("with NaNExactCompares the negation should stay:\n%s", ext)
	}
}

// comiss xmm0, xmm1 ; jbe L ; mov eax, 1 ; ret ; L: xor eax, eax ; ret
var comissBranch = []byte{
	0x0f, 0x2f, 0xc1, 0x76, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3, 0xcc, 0xcc,
}

// Ghidra's default nanignore ("compare") drops the NaN test of comiss (the
// C++ decompiler prints "if (param_2 < param_1)"); NaNIgnoreNone keeps it.
func TestNaNIgnoreNone(t *testing.T) {
	plain := decompileWith(t, comissBranch, decomp.Function{})
	t.Logf("plain:\n%s", plain)
	if strings.Contains(plain, "NAN(") {
		t.Errorf("the default should drop the NaN test, as in Ghidra:\n%s", plain)
	}
	kept := decompileWith(t, comissBranch, decomp.Function{NaNIgnore: pcode.NaNIgnoreNone})
	t.Logf("none:\n%s", kept)
	if !strings.Contains(kept, "NAN(") {
		t.Errorf("with NaNIgnoreNone the NaN test should stay:\n%s", kept)
	}
}

// shr ecx, 9 ; or ecx, 0x3f800000 ; movd xmm0, ecx ; addss xmm0, xmm1 ; ret
// -- integer bits used as a float (the random-float idiom); with cvtsi2ss
// xmm0, ecx in place of movd it is a numeric conversion.
var (
	movdBits = []byte{0xc1, 0xe9, 0x09, 0x81, 0xc9, 0x00, 0x00, 0x80, 0x3f,
		0x66, 0x0f, 0x6e, 0xc1, 0xf3, 0x0f, 0x58, 0xc1, 0xc3, 0xcc, 0xcc, 0xcc}
	cvtsi2ss = []byte{0xc1, 0xe9, 0x09, 0x81, 0xc9, 0x00, 0x00, 0x80, 0x3f,
		0xf3, 0x0f, 0x2a, 0xc1, 0xf3, 0x0f, 0x58, 0xc1, 0xc3, 0xcc, 0xcc, 0xcc}
)

func TestBitCastSyntax(t *testing.T) {
	ext := decomp.Function{Extensions: pcode.Extensions{BitCastSyntax: true}}
	plain := decompileWith(t, movdBits, decomp.Function{})
	bits := decompileWith(t, movdBits, ext)
	conv := decompileWith(t, cvtsi2ss, ext)
	t.Logf("plain:\n%s\nbits:\n%s\nconversion:\n%s", plain, bits, conv)
	if strings.Contains(plain, "bit_cast") {
		t.Errorf("without the extension the cast prints as in Ghidra")
	}
	if !strings.Contains(bits, "bit_cast<float>(") {
		t.Errorf("movd should print as bit_cast<float>:\n%s", bits)
	}
	if strings.Contains(conv, "bit_cast") {
		t.Errorf("a numeric conversion must stay a (float) cast:\n%s", conv)
	}
}

// comiss xmm0, xmm1 ; ja L ; mov eax, 1 ; ret ; L: xor eax, eax ; ret --
// ja is not taken for NaN, so NaN returns 1. Ghidra drops the NaN test from
// !NaN && !(a < b) && a != b and prints if (param_1 <= param_2), which
// returns 0 for NaN; NaNExactCompares prints !(param_2 < param_1), true for
// NaN.
var comissAbove = []byte{
	0x0f, 0x2f, 0xc1, 0x77, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0, 0xc3, 0xcc, 0xcc,
}

func TestNaNExactDroppedTest(t *testing.T) {
	ext := decomp.Function{Extensions: pcode.Extensions{NaNExactCompares: true}}
	// jbe is taken for NaN and param_2 < param_1 is false for NaN: already
	// exact, so the extension leaves it alone.
	for _, c := range []struct {
		name, plain, exact string
		code               []byte
	}{
		{"ja", "if (param_1 <= param_2)", "if (!(param_2 < param_1))", comissAbove},
		{"jbe", "if (param_2 < param_1)", "if (param_2 < param_1)", comissBranch},
	} {
		plain := decompileWith(t, c.code, decomp.Function{})
		exact := decompileWith(t, c.code, ext)
		t.Logf("%s plain:\n%s\nexact:\n%s", c.name, plain, exact)
		if !strings.Contains(plain, c.plain) {
			t.Errorf("%s: without the extension want %q as in Ghidra", c.name, c.plain)
		}
		if !strings.Contains(exact, c.exact) || strings.Contains(exact, "NAN(") {
			t.Errorf("%s: with NaNExactCompares want %q and no NaN test", c.name, c.exact)
		}
	}
}
