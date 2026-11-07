package analysis_test

import (
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/analysis"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

// f homes its RCX (as MSVC does) and passes it unchanged to g, which reads
// it before writing it.
//
//	f: mov [rsp+8], rcx
//	   sub rsp, 0x28
//	   call g
//	   add rsp, 0x28
//	   ret
//	g: mov eax, [rcx+0x8c]
//	   ret
var passThrough = []byte{
	0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x83,
	0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0x8b, 0x81, 0x8c, 0x00, 0x00, 0x00, 0xc3, 0xcc,
}

const base = 0x140001000

func load(t *testing.T) *decomp.Program {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: passThrough}})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

// Ghidra's core does not take a pass-through input as an argument, so f
// prints as f(void) calling g() (checked with the C++ decompiler on the same
// bytes); with the callee's read-before-write hint the argument and f's
// parameter are kept.
func TestCalleeReadsPassThrough(t *testing.T) {
	prog := load(t)
	plain, err := prog.Decompile(decomp.Function{Entry: base})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plain:\n%s", plain.C)
	if !strings.Contains(plain.C, "(void)") {
		t.Errorf("without the hint the output should match Ghidra (no parameter):\n%s", plain.C)
	}
	fn := decomp.Function{Entry: base}
	analysis.NewEnhanced(prog).Apply(&fn)
	hinted, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("enhanced:\n%s", hinted.C)
	if !strings.Contains(hinted.C, "(param_1)") {
		t.Errorf("with the hint the argument should be kept:\n%s", hinted.C)
	}
}

func TestScanIgnoresSelfXor(t *testing.T) {
	// g2: xor ecx, ecx ; mov eax, [rcx] ; ret -- RCX is set, not read.
	code := []byte{0x31, 0xc9, 0x8b, 0x01, 0xc3, 0xcc, 0xcc, 0xcc}
	spec, _ := specs.X86(64, specs.CompilerWindows)
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	r := analysis.NewCalleeReads(prog)
	for _, s := range r.CalleeReadsBeforeWrite(address.Address{Space: prog.CodeSpace(), Offset: base}) {
		if s.Offset < 0x10 && s.Offset+uint64(s.Size) > 0x8 { // RCX is register:0x8, 8 bytes
			t.Errorf("xor ecx, ecx counted as a read of RCX: %+v", s)
		}
	}
}

func TestScanIgnoresHomingStores(t *testing.T) {
	// A varargs prologue homes all four parameter registers:
	// mov [rsp+8], rcx ; mov [rsp+0x10], rdx ; mov [rsp+0x18], r8 ;
	// mov [rsp+0x20], r9 ; ret
	code := []byte{
		0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x89, 0x54, 0x24, 0x10,
		0x4c, 0x89, 0x44, 0x24, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0xc3, 0xcc,
	}
	spec, _ := specs.X86(64, specs.CompilerWindows)
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	if r := analysis.NewCalleeReads(prog).CalleeReadsBeforeWrite(address.Address{Space: prog.CodeSpace(), Offset: base}); len(r) != 0 {
		t.Errorf("homing stores counted as reads: %+v", r)
	}
}

func TestScanIgnoresHomingThroughCopy(t *testing.T) {
	// The prologue copies RSP and homes through the copy after RSP moves:
	// mov r11, rsp ; push rbx ; mov [r11+0x10], rdx ; mov [r11+0x18], r8 ;
	// mov [r11+0x20], r9 ; ret
	code := []byte{
		0x4c, 0x8b, 0xdc, 0x53, 0x49, 0x89, 0x53, 0x10, 0x4d, 0x89, 0x43, 0x18,
		0x4d, 0x89, 0x4b, 0x20, 0xc3, 0xcc,
	}
	spec, _ := specs.X86(64, specs.CompilerWindows)
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range analysis.NewCalleeReads(prog).CalleeReadsBeforeWrite(address.Address{Space: prog.CodeSpace(), Offset: base}) {
		// RDX 0x10, R8 0x80, R9 0x88 (8 bytes each) must not be reported;
		// RBX (pushed) is a callee-saved read and harmless.
		for _, reg := range []uint64{0x10, 0x80, 0x88} {
			if r.Offset < reg+8 && reg < r.Offset+uint64(r.Size) {
				t.Errorf("homing through a copy of RSP counted as a read: %+v", r)
			}
		}
	}
}

// f: sub rsp, 0x28 ; call g ; addss xmm0, xmm0 ; add rsp, 0x28 ; ret
// g: movss xmm0, [rcx] ; ret
var floatCallee = []byte{
	0x48, 0x83, 0xec, 0x28, 0xe8, 0x0f, 0x00, 0x00, 0x00, 0xf3, 0x0f, 0x58, 0xc0,
	0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xf3, 0x0f, 0x10, 0x01, 0xc3, 0xcc, 0xcc, 0xcc,
}

func TestCalleeFloatReturn(t *testing.T) {
	spec, _ := specs.X86(64, specs.CompilerWindows)
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: floatCallee}})
	if err != nil {
		t.Fatal(err)
	}
	r := analysis.NewCalleeReads(prog)
	if got := r.CalleeFloatReturn(address.Address{Space: prog.CodeSpace(), Offset: base + 24}); got != 4 {
		t.Errorf("g returns a float in XMM0: got size %d", got)
	}
	plain, err := prog.Decompile(decomp.Function{Entry: base})
	if err != nil {
		t.Fatal(err)
	}
	fn := decomp.Function{Entry: base}
	analysis.NewEnhanced(prog).Apply(&fn)
	hinted, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plain:%s%s", string(rune(10)), plain.C)
	t.Logf("enhanced:%s%s", string(rune(10)), hinted.C)
	if strings.Contains(hinted.C, "(float)") || strings.Contains(hinted.C, "bit_cast") {
		t.Errorf("the callee's float result should need no cast with the hint")
	}
}
