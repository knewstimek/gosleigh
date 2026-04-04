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

package loader_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// TestX86SimpleFunction exercises the full pipeline:
//
//	EngineBuilder.Build -> bridge.Build -> Heritage -> PrintC
//
// Bytes: ADD EAX,EBX (01 D8) + RET (C3).
// The test asserts that PrintC produces non-empty C output, which confirms
// that the Engine translates real x86 instructions end-to-end.
func TestX86SimpleFunction(t *testing.T) {
	// Locate files relative to this source file so the test works regardless
	// of the working directory chosen by 'go test'.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)

	// x86-packed.sla lives at pkg/sla/testdata/x86-packed.sla (one level up,
	// then into sla/testdata).
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")

	// x86.pspec lives at testdata/sla/x86.pspec relative to the repo root,
	// which is two levels above pkg/loader/.
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	prog := []byte{0x01, 0xD8, 0xC3} // ADD EAX,EBX; RET

	b := &loader.EngineBuilder{
		SLAPath:   slaPath,
		PspecPath: pspecPath,
		Bytes:     prog,
	}
	engine, entryAddr, err := b.Build()
	if err != nil {
		t.Fatalf("EngineBuilder.Build: %v", err)
	}

	// Use MaxInstructions to bound translation (entry to entry+3 is too tight
	// if addresses don't align; MaxInstructions=10 is a safe ceiling).
	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            "test_add_ret",
		Entry:           entryAddr,
		MaxInstructions: 10,
	})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}
	if result == nil {
		t.Fatal("bridge.Build returned nil result")
	}
	if len(result.Instructions) == 0 {
		t.Fatal("bridge returned no instructions")
	}
	if result.Funcdata == nil {
		t.Fatal("bridge returned nil funcdata")
	}
	if result.Graph == nil {
		t.Fatal("bridge returned nil graph")
	}

	// Heritage (SSA construction).
	heritage := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
	heritage.Heritage(result.Graph)

	// Batch-A analysis actions.
	pool := pcode.NewBatchAActionPool("batch-a", "analysis")
	if res := pool.Perform(result.Funcdata); res < 0 {
		t.Fatalf("BatchAActionPool.Perform returned %d", res)
	}
	if res := pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata); res != 0 {
		t.Fatalf("ActionBlockStructure.Apply returned %d", res)
	}
	if res := pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata); res != 0 {
		t.Fatalf("ActionFinalStructure.Apply returned %d", res)
	}

	// PrintC emission.
	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output")
	}
	t.Logf("emitted C:\n%s", output)
}
