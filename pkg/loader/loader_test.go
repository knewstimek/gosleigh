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

// TestX86CallerFunction exercises the full pipeline with a function that contains a CALL:
//
//	PUSH EBP (55) + MOV EBP,ESP (89 E5) + CALL rel32 (E8 10 00 00 00) + POP EBP (5D) + RET (C3)
//
// Verifies that CALL is treated as a non-terminating instruction with fallthrough,
// producing >= 5 instructions, >= 1 CFG block, and non-empty PrintC output.
func TestX86CallerFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; CALL +0x10; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0xE8, 0x10, 0x00, 0x00, 0x00, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "caller", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 5 {
		t.Fatalf("expected >= 5 instructions, got %d", len(result.Instructions))
	}
	if result.Graph.GetSize() < 1 {
		t.Fatalf("expected >= 1 CFG block, got %d", result.Graph.GetSize())
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for caller function")
	}
	t.Logf("PrintC output:\n%s", output)
}

// TestX86CountedLoop exercises the full pipeline with a counted loop:
//
//	MOV ECX,3 + DEC ECX + JNE -3 + RET
//
// Verifies that backward branch (JNE) produces >= 2 CFG blocks and that
// PrintC emits non-empty C output for a loop-containing function.
func TestX86CountedLoop(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	prog := []byte{0xB9, 0x03, 0x00, 0x00, 0x00, 0x49, 0x75, 0xFD, 0xC3}
	// 0x00: MOV ECX,3
	// 0x05: DEC ECX
	// 0x06: JNE -3 (to 0x05)
	// 0x08: RET

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "loop", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 3 {
		t.Fatalf("expected >= 3 instructions, got %d", len(result.Instructions))
	}
	if result.Graph.GetSize() < 2 {
		t.Fatalf("expected >= 2 CFG blocks, got %d", result.Graph.GetSize())
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if output == "" {
		t.Fatal("PrintC Emit returned empty string for loop function")
	}
	t.Logf("PrintC output:\n%s", output)
}

// TestX86IfElse exercises the full pipeline with an abs() function containing
// a diamond (if-else) CFG:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / TEST EAX,EAX / JNS +4 / NEG EAX / JMP +0 / POP EBP / RET
//
// Verifies that a conditional forward branch (JNS) produces >= 3 CFG blocks
// (entry -> taken-path AND entry -> NEG -> merge -> exit) and that
// PrintC emits non-empty C output for an if-else-containing function.
func TestX86IfElse(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; TEST EAX,EAX; JNS +4; NEG EAX; JMP +0; POP EBP; RET
	bytes := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x85, 0xC0, 0x79, 0x04, 0xF7, 0xD8, 0xEB, 0x00, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: bytes}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "abs", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	// Diamond CFG: entry -> JNS-taken (skip NEG) AND entry -> NEG -> merge -> exit
	if result.Graph.GetSize() < 3 {
		t.Fatalf("expected >= 3 CFG blocks for if-else diamond, got %d", result.Graph.GetSize())
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for if-else function")
	}
	t.Logf("PrintC output:\n%s", output)
}

// TestX86MultiplyFunction exercises the full pipeline with a multiply function:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / IMUL EAX,[EBP+0xC] / POP EBP / RET
//
// Verifies that two-byte opcode prefix (0x0F) instructions are decoded and
// that PrintC emits non-empty C output for a function using IMUL.
func TestX86MultiplyFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; IMUL EAX,[EBP+0xC]; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x0F, 0xAF, 0x45, 0x0C, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "multiply", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if result.Graph == nil {
		t.Fatal("expected non-nil CFG graph")
	}
	if len(result.Instructions) < 4 {
		t.Fatalf("expected >= 4 instructions, got %d", len(result.Instructions))
	}

	pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
	pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
	pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
	pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for multiply function")
	}
	t.Logf("PrintC output:\n%s", output)
}
