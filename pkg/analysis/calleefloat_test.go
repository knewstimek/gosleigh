package analysis_test

import (
	"strings"
	"testing"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/analysis"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/specs"
)

const (
	regRCX  = 0x8
	regXMM0 = 0x1200
)

func loadCode(t *testing.T, code []byte) (*decomp.Program, *analysis.CalleeReads) {
	t.Helper()
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	prog, err := decomp.Load(spec, []decomp.Section{{Name: ".text", VMA: base, Data: code}})
	if err != nil {
		t.Fatal(err)
	}
	return prog, analysis.NewCalleeReads(prog)
}

func at(prog *decomp.Program, off uint64) address.Address {
	return address.Address{Space: prog.CodeSpace(), Offset: base + off}
}

func covers(list []pcode.HostStorage, off uint64) bool {
	for _, s := range list {
		if s.Offset <= off && off < s.Offset+uint64(s.Size) {
			return true
		}
	}
	return false
}

// The first return is 0.0 (xorps), the other a converted int: every path
// is followed, and 0.0 agrees with the float of the other path.
//
//	   test ecx, ecx
//	   jne L
//	   xorps xmm0, xmm0
//	   ret
//	L: movd xmm0, ecx
//	   cvtdq2ps xmm0, xmm0
//	   ret
func TestCalleeFloatReturnAllPaths(t *testing.T) {
	prog, r := loadCode(t, []byte{
		0x85, 0xc9, 0x75, 0x04, 0x0f, 0x57, 0xc0, 0xc3,
		0x66, 0x0f, 0x6e, 0xc1, 0x0f, 0x5b, 0xc0, 0xc3,
	})
	if got := r.CalleeFloatReturn(at(prog, 0)); got != 4 {
		t.Errorf("got size %d, want 4", got)
	}
}

// f returns what g returns; g returns a float through a whole-register copy.
//
//	f: sub rsp, 0x28 ; call g ; add rsp, 0x28 ; ret
//	g: movss xmm6, [rcx] ; movaps xmm0, xmm6 ; ret
func TestCalleeFloatReturnThroughCall(t *testing.T) {
	prog, r := loadCode(t, []byte{
		0x48, 0x83, 0xec, 0x28, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc,
		0xf3, 0x0f, 0x10, 0x31, 0x0f, 0x28, 0xc6, 0xc3,
	})
	if got := r.CalleeFloatReturn(at(prog, 16)); got != 4 {
		t.Errorf("g: got size %d, want 4", got)
	}
	if got := r.CalleeFloatReturn(at(prog, 0)); got != 4 {
		t.Errorf("f: got size %d, want 4", got)
	}
}

// A void function whose last XMM0 write is float scratch read again later.
//
//	cvtsi2ss xmm0, ecx ; addss xmm1, xmm0 ; movss [rdx], xmm1 ; ret
func TestCalleeFloatReturnIgnoresScratch(t *testing.T) {
	prog, r := loadCode(t, []byte{
		0xf3, 0x0f, 0x2a, 0xc1, 0xf3, 0x0f, 0x58, 0xc8, 0xf3, 0x0f, 0x11, 0x0a, 0xc3,
	})
	if got := r.CalleeFloatReturn(at(prog, 0)); got != 0 {
		t.Errorf("got size %d, want 0 (void)", got)
	}
}

// g is float g(float), both in XMM0. Locking only its return must not hide
// the XMM0 argument (Heritage::guardCalls skips the call's output range).
//
//	f: sub rsp, 0x28 ; movss xmm0, [rcx] ; call g ; movss [rdx], xmm0
//	   add rsp, 0x28 ; ret
//	g: addss xmm0, xmm0 ; ret
func TestFloatArgumentOfFloatCallee(t *testing.T) {
	prog, _ := loadCode(t, []byte{
		0x48, 0x83, 0xec, 0x28, 0xf3, 0x0f, 0x10, 0x01, 0xe8, 0x0b, 0x00, 0x00, 0x00,
		0xf3, 0x0f, 0x11, 0x02, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xcc,
		0xf3, 0x0f, 0x58, 0xc0, 0xc3,
	})
	fn := decomp.Function{Entry: base}
	analysis.NewEnhanced(prog).Apply(&fn)
	res, err := prog.Decompile(fn)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("enhanced:%s%s", string(rune(10)), res.C)
	if !strings.Contains(res.C, "func_0x0000000140001018(*param_1)") {
		t.Errorf("the float argument in XMM0 is missing")
	}
}

// A call through an import slot targets data: with sections marked Exec the
// slot's bytes are not scanned (decoded as code they happened to "return"
// without reading any parameter register).
func TestCalleeAnalysesSkipData(t *testing.T) {
	spec, err := specs.X86(64, specs.CompilerWindows)
	if err != nil {
		t.Fatal(err)
	}
	code := []byte{0x0f, 0x57, 0xc9, 0x0f, 0x2e, 0xc1, 0xc3} // see TestCalleeNotInputsUntouched
	prog, err := decomp.Load(spec, []decomp.Section{
		{Name: ".text", VMA: base, Data: code, Exec: true},
		{Name: ".rdata", VMA: base + 0x1000, Data: code},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := analysis.NewCalleeReads(prog)
	if ni := r.CalleeNotInputs(at(prog, 0)); !covers(ni, regRCX) {
		t.Errorf("code: want RCX among not-inputs %+v", ni)
	}
	if ni := r.CalleeNotInputs(at(prog, 0x1000)); len(ni) != 0 {
		t.Errorf("data: want no answer, got %+v", ni)
	}
}

// Every path returns without touching RCX: it is not an input; XMM0 is read.
//
//	xorps xmm1, xmm1 ; ucomiss xmm0, xmm1 ; ret
func TestCalleeNotInputsUntouched(t *testing.T) {
	prog, r := loadCode(t, []byte{0x0f, 0x57, 0xc9, 0x0f, 0x2e, 0xc1, 0xc3})
	ni := r.CalleeNotInputs(at(prog, 0))
	if !covers(ni, regRCX) || covers(ni, regXMM0) {
		t.Errorf("want RCX and not XMM0 among %+v", ni)
	}
}

// Homing RCX makes slot 1 an integer slot: XMM0 is not an input, and RCX
// counts as read (R9 is not homed, so this is not a varargs prologue).
//
//	s: mov [rsp+8], rcx ; sub rsp, 0x28 ; call t ; add rsp, 0x28 ; ret
//	t: ret
func TestCalleeHomedSlotKind(t *testing.T) {
	prog, r := loadCode(t, []byte{
		0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x06, 0x00, 0x00, 0x00,
		0x48, 0x83, 0xc4, 0x28, 0xc3, 0xcc, 0xc3,
	})
	if ni := r.CalleeNotInputs(at(prog, 0)); !covers(ni, regXMM0) || covers(ni, regRCX) {
		t.Errorf("want XMM0 and not RCX among not-inputs %+v", ni)
	}
	if rd := r.CalleeReadsBeforeWrite(at(prog, 0)); !covers(rd, regRCX) {
		t.Errorf("homed RCX should count as read: %+v", rd)
	}
}
