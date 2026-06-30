package loader_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// TestX64RegParamOrder guards the x86-64 SysV register-parameter recovery and,
// critically, the parameter DECLARATION ORDER. SysV register offsets are the
// inverse of argument order (RDI=0x38 is arg0, RSI=0x30 is arg1), so a raw
// address sort emits the signature reversed (param_2, param_1). The asserted
// order is an ABI structural invariant (register args in calling-convention
// order), not an unverified golden guess. Runs the universal-action tree in
// NON-processEntry mode so register args become named parameters.
func TestX64RegParamOrder(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	sla := filepath.Join(dir, "../sla/testdata/x86-64-packed.sla")
	pspec := filepath.Join(dir, "../../testdata/sla/x86-64.pspec")
	cspec := filepath.Join(dir, "../../testdata/sla/x86-64-gcc.cspec")
	if _, err := os.Stat(sla); err != nil {
		t.Skipf("x86-64 sla missing: %v", err)
	}

	cases := []struct {
		name    string
		prog    []byte
		wantSig string
		wantHas string // a substring the body must contain
	}{
		// MOV RAX,RDI; ADD RAX,RSI; RET
		{"add2", []byte{0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3},
			"entry(long param_1,long param_2)", "param_1 + param_2"},
		// LEA RAX,[RDI+RSI]; ADD RAX,RDX; RET  (RDI,RSI,RDX = arg0,arg1,arg2)
		{"add3", []byte{0x48, 0x8D, 0x04, 0x37, 0x48, 0x01, 0xD0, 0xC3},
			"entry(long param_1,long param_2,long param_3)", "param_1 + param_2 + param_3"},
	}

	for _, c := range cases {
		engine, base, err := (&loader.EngineBuilder{SLAPath: sla, PspecPath: pspec, Bytes: c.prog}).Build()
		if err != nil {
			t.Fatalf("[%s] Build: %v", c.name, err)
		}
		result, err := bridge.Build(engine, bridge.BuildConfig{
			Name: "entry", Entry: base, MaxInstructions: 12, CspecPath: cspec,
		})
		if err != nil {
			t.Fatalf("[%s] bridge.Build: %v", c.name, err)
		}
		fd := result.Funcdata
		db := pcode.NewActionDatabase()
		db.BuildUniversalAction(nil)
		db.BuildDefaultGroups()
		db.SetCurrent("decompile").Perform(fd)
		out, err := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).SetGhidraFormat().Emit(fd)
		if err != nil {
			t.Fatalf("[%s] Emit: %v", c.name, err)
		}
		if !strings.Contains(out, c.wantSig) {
			t.Errorf("[%s] signature/order mismatch: want %q in:\n%s", c.name, c.wantSig, out)
		}
		if !strings.Contains(out, c.wantHas) {
			t.Errorf("[%s] body mismatch: want %q in:\n%s", c.name, c.wantHas, out)
		}
	}
}
