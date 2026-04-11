package loader_test

import (
	"path/filepath"
	"runtime"
	"testing"
	"fmt"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

func TestDebugAARCH64Ops(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok { t.Fatal("") }
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../../testdata/sla/AARCH64.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/AARCH64.pspec")

	// ADD X0, X0, X1; RET
	prog := []byte{
		0x00, 0x00, 0x01, 0x8B, // ADD X0, X0, X1
		0xC0, 0x03, 0x5F, 0xD6, // RET
	}

	engine, entryAddr, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil { t.Fatalf("EngineBuilder.Build: %v", err) }

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "aarch64_add_ret", Entry: entryAddr, MaxInstructions: 10})
	if err != nil { t.Fatalf("bridge.Build: %v", err) }

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)

	t.Logf("=== REGISTER NAMES ===")
	for k, v := range engine.RegisterNamesByLocation() {
		t.Logf("  %s -> %s", k, v)
	}

	t.Logf("=== ALL LIVE OPS ===")
	for _, op := range result.Funcdata.GetPcodeOpBank().AllOps() {
		if op == nil || op.IsDead() { continue }
		outStr := "nil"
		if out := op.Output(); out != nil {
			outStr = fmt.Sprintf("[spc=%v off=%d sz=%d numDesc=%d isFree=%v]",
				out.Space().Name, out.Offset(), out.Size(), out.NumDescend(), out.IsFree())
		}
		inputs := ""
		for i := 0; i < op.NumInput(); i++ {
			vn := op.Input(i)
			if vn == nil { inputs += " nil"; continue }
			inputs += fmt.Sprintf(" [%v:%d sz=%d in=%v const=%v nD=%d]",
				vn.Space().Name, vn.Offset(), vn.Size(), vn.IsInput(), vn.IsConstant(), vn.NumDescend())
		}
		t.Logf("  %v: %v -> %v in:%s", op.Seq(), op.Code(), outStr, inputs)
	}
}
