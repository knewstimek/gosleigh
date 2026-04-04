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

// TestMIPS32SimpleFunction exercises the full MIPS32 LE E2E pipeline:
//
//	EngineBuilder.Build -> bridge.Build -> Heritage -> PrintC
//
// Bytes: ADDU $v0, $a0, $a1 (21 10 85 00) + JR $ra (08 00 E0 03).
// MIPS32 is little-endian; all instructions are 4-byte LE words.
// Verifies that MIPS32 instructions produce non-empty PrintC output end-to-end.
// Unknown pspec context variables are skipped gracefully.
func TestMIPS32SimpleFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)

	// mips32le.sla lives at testdata/sla/ in the repo root (two levels above pkg/loader/).
	slaPath := filepath.Join(dir, "../../testdata/sla/mips32le.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/mips32le.pspec")

	// ADDU $v0, $a0, $a1; JR $ra
	prog := []byte{
		0x21, 0x10, 0x85, 0x00, // ADDU $v0, $a0, $a1 (0x00851021 LE)
		0x08, 0x00, 0xE0, 0x03, // JR $ra (0x03E00008 LE)
	}

	engine, entryAddr, err := (&loader.EngineBuilder{
		SLAPath:   slaPath,
		PspecPath: pspecPath,
		Bytes:     prog,
	}).Build()
	if err != nil {
		t.Fatalf("EngineBuilder.Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            "mips32_addu_jr",
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

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

	output, err := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for MIPS32 function")
	}
	t.Logf("MIPS32 simple function C output:\n%s", output)
}
