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

// TestX86IndirectCallFunction exercises the full pipeline with a function
// containing an indirect CALL via register (CALL EAX):
//
//	PUSH EBP (55) + MOV EBP,ESP (89 E5) + MOV EAX,[EBP+8] (8B 45 08) +
//	CALL EAX (FF D0) + POP EBP (5D) + RET (C3)
//
// Verifies that indirect CALL (CALLIND p-code) is decoded and that
// Heritage+PrintC produces non-empty C output.
func TestX86IndirectCallFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; CALL EAX; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0xFF, 0xD0, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "indirect_call", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
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
		t.Fatal("PrintC.Emit returned empty output for indirect_call function")
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

// TestX86ComplexFunction exercises the full pipeline with a max() function that
// combines CMP + JGE (conditional branch) + conditional MOV:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / CMP EAX,[EBP+0xC] / JGE +2 / MOV EAX,[EBP+0xC] / POP EBP / RET
//
// Verifies that CMP+JGE produces >= 2 CFG blocks and that PrintC emits non-empty C output.
func TestX86ComplexFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// max(int a, int b): PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; CMP EAX,[EBP+0xC]; JGE +2; MOV EAX,[EBP+0xC]; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x3B, 0x45, 0x0C, 0x7D, 0x02, 0x8B, 0x45, 0x0C, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "max", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 5 {
		t.Fatalf("expected >= 5 instructions, got %d", len(result.Instructions))
	}
	// CMP+JGE creates at least 2 basic blocks.
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
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for complex function")
	}
	t.Logf("Complex C output:\n%s", output)
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

// TestX86DivideFunction exercises the full pipeline with a divide function:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / CDQ / IDIV [EBP+0xC] / POP EBP / RET
//
// Verifies that CDQ and IDIV (with memory operand) are decoded and translated,
// producing >= 4 instructions and non-empty PrintC output.
func TestX86DivideFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; CDQ; IDIV [EBP+0xC]; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x99, 0xF7, 0x7D, 0x0C, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "divide", Entry: base, MaxInstructions: 20})
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
		t.Fatal("PrintC.Emit returned empty output for divide function")
	}
	t.Logf("Divide C output:\n%s", output)
}

// TestX86Add3Function exercises the full pipeline with a 3-argument add function
// that uses PUSH/POP EBX (callee-saved register convention):
//
//	PUSH EBP / MOV EBP,ESP / PUSH EBX / MOV EBX,[EBP+8] /
//	ADD EBX,[EBP+12] / ADD EBX,[EBP+16] / MOV EAX,EBX / POP EBX / POP EBP / RET
//
// Verifies that PUSH/POP general-purpose registers (EBX) are decoded and
// that the full Heritage+PrintC pipeline produces non-empty C output.
func TestX86Add3Function(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// int add3(int a, int b, int c):
	//   0x00: PUSH EBP        (55)
	//   0x01: MOV EBP,ESP     (89 E5)
	//   0x03: PUSH EBX        (53)
	//   0x04: MOV EBX,[EBP+8] (8B 5D 08)
	//   0x07: ADD EBX,[EBP+12](03 5D 0C)
	//   0x0A: ADD EBX,[EBP+16](03 5D 10)
	//   0x0D: MOV EAX,EBX     (89 D8)
	//   0x0F: POP EBX         (5B)
	//   0x10: POP EBP         (5D)
	//   0x11: RET             (C3)
	prog := []byte{0x55, 0x89, 0xE5, 0x53, 0x8B, 0x5D, 0x08, 0x03, 0x5D, 0x0C, 0x03, 0x5D, 0x10, 0x89, 0xD8, 0x5B, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "add3", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 6 {
		t.Fatalf("expected >= 6 instructions, got %d", len(result.Instructions))
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
		t.Fatal("PrintC.Emit returned empty output for add3 function")
	}
	t.Logf("add3 C output:\n%s", output)
}

// TestX86LocalVarFunction exercises the full pipeline with a function that
// uses a stack-allocated local variable:
//
//	PUSH EBP / MOV EBP,ESP / SUB ESP,4 / MOV EAX,[EBP+8] /
//	SHL EAX,1 / MOV [EBP-4],EAX / MOV EAX,[EBP-4] /
//	MOV ESP,EBP / POP EBP / RET
//
// Verifies that SUB ESP (stack frame allocation), MOV [EBP-4] (local var
// store/load), and SHL EAX,1 are decoded and that the full Heritage+PrintC
// pipeline produces non-empty C output.
func TestX86LocalVarFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// double_it(int x): int local = x * 2; return local;
	//   0x00: PUSH EBP        (55)
	//   0x01: MOV EBP,ESP     (89 E5)
	//   0x03: SUB ESP,4       (83 EC 04)
	//   0x06: MOV EAX,[EBP+8] (8B 45 08)
	//   0x09: SHL EAX,1       (D1 E0)
	//   0x0B: MOV [EBP-4],EAX (89 45 FC)
	//   0x0E: MOV EAX,[EBP-4] (8B 45 FC)
	//   0x11: MOV ESP,EBP     (89 EC)
	//   0x13: POP EBP         (5D)
	//   0x14: RET             (C3)
	prog := []byte{0x55, 0x89, 0xE5, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x08, 0xD1, 0xE0, 0x89, 0x45, 0xFC, 0x8B, 0x45, 0xFC, 0x89, 0xEC, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "double_it", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 6 {
		t.Fatalf("expected >= 6 instructions, got %d", len(result.Instructions))
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
		t.Fatal("PrintC.Emit returned empty output for local var function")
	}
	t.Logf("double_it C output:\n%s", output)
}

// TestX86ClampFunction exercises the full pipeline with a 3-branch clamp function:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / CMP EAX,[EBP+0C] / JGE +3 /
//	MOV EAX,[EBP+0C] / CMP EAX,[EBP+10] / JLE +3 / MOV EAX,[EBP+10] / POP EBP / RET
//
// Verifies 3-branch clamp pattern (CMP+JGE, CMP+JLE) producing >= 4 CFG blocks
// and non-empty PrintC output.
func TestX86ClampFunction(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Dir(filepath.Dir(thisFile))
	slaPath := filepath.Join(projectRoot, "sla", "testdata", "x86-packed.sla")
	pspecPath := filepath.Join(projectRoot, "..", "testdata", "sla", "x86.pspec")

	// clamp(int x, int lo, int hi):
	//   0x00: PUSH EBP           (55)
	//   0x01: MOV EBP,ESP        (89 E5)
	//   0x03: MOV EAX,[EBP+8]   (8B 45 08)
	//   0x06: CMP EAX,[EBP+0C]  (3B 45 0C)
	//   0x09: JGE +3             (7D 03)
	//   0x0B: MOV EAX,[EBP+0C]  (8B 45 0C)
	//   0x0E: CMP EAX,[EBP+10]  (3B 45 10)
	//   0x11: JLE +3             (7E 03)
	//   0x13: MOV EAX,[EBP+10]  (8B 45 10)
	//   0x16: POP EBP            (5D)
	//   0x17: RET                (C3)
	prog := []byte{
		0x55, 0x89, 0xE5,
		0x8B, 0x45, 0x08,
		0x3B, 0x45, 0x0C,
		0x7D, 0x03,
		0x8B, 0x45, 0x0C,
		0x3B, 0x45, 0x10,
		0x7E, 0x03,
		0x8B, 0x45, 0x10,
		0x5D, 0xC3,
	}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "clamp", Entry: base, MaxInstructions: 30})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if len(result.Instructions) < 6 {
		t.Fatalf("expected >= 6 instructions, got %d", len(result.Instructions))
	}
	// CMP+JGE and CMP+JLE produce at least 4 basic blocks.
	if result.Graph.GetSize() < 4 {
		t.Fatalf("expected >= 4 CFG blocks for 3-branch clamp, got %d", result.Graph.GetSize())
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
		t.Fatal("PrintC.Emit returned empty output for clamp function")
	}
	t.Logf("clamp C output:\n%s", output)
}

// TestX86BitshiftFunction exercises the full pipeline with a bitshift function:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / SHL EAX,2 / POP EBP / RET
//
// Verifies that SHL (imm8) is decoded and translated, producing >= 4 instructions
// and non-empty PrintC output.
func TestX86BitshiftFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; SHL EAX,2; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0xC1, 0xE0, 0x02, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "shl2", Entry: base, MaxInstructions: 20})
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
		t.Fatal("PrintC.Emit returned empty output for bitshift function")
	}
	t.Logf("Bitshift C output:\n%s", output)
}

// TestX86BranchlessMaxFunction exercises the full pipeline with a branchless max:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8] / MOV ECX,[EBP+0Ch]
//	CMP EAX,ECX / CMOVL EAX,ECX / POP EBP / RET
//
// Verifies that CMOVL (0F 4C) is decoded and the branchless conditional move
// produces non-empty PrintC output.
func TestX86BranchlessMaxFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// bytes: PUSH EBP; MOV EBP,ESP; MOV EAX,[EBP+8]; MOV ECX,[EBP+0Ch];
	//        CMP EAX,ECX; CMOVL EAX,ECX; POP EBP; RET
	prog := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x4D, 0x0C, 0x3B, 0xC1, 0x0F, 0x4C, 0xC1, 0x5D, 0xC3}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "branchless_max", Entry: base, MaxInstructions: 20})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if result.Graph == nil {
		t.Fatal("expected non-nil CFG graph")
	}
	if len(result.Instructions) < 6 {
		t.Fatalf("expected >= 6 instructions, got %d", len(result.Instructions))
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
		t.Fatal("PrintC.Emit returned empty output for branchless_max function")
	}
	t.Logf("BranchlessMax C output:\n%s", output)
}

// TestX86ClassifySignFunction exercises the full pipeline with a 3-path sign classifier:
//
//	PUSH EBP / MOV EBP,ESP / MOV EAX,[EBP+8]
//	CMP EAX,0 / JE zero_path
//	CMP EAX,0 / JG positive_path
//	MOV EAX,-1 / JMP end       ; negative path
//	XOR EAX,EAX / JMP end      ; zero path
//	MOV EAX,1                  ; positive path
//	POP EBP / RET
//
// Verifies that CMP imm8 (0x83 /7) and JE/JG branches decode correctly and
// the 3-way branch produces non-empty PrintC output.
func TestX86ClassifySignFunction(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	// Layout (byte offsets):
	//  0: 55                    PUSH EBP
	//  1: 89 E5                 MOV EBP, ESP
	//  3: 8B 45 08              MOV EAX, [EBP+8]
	//  6: 83 F8 00              CMP EAX, 0
	//  9: 74 0C                 JE  +12 -> byte 23 (zero_path: XOR EAX,EAX)
	// 11: 83 F8 00              CMP EAX, 0
	// 14: 7F 0B                 JG  +11 -> byte 27 (positive_path: MOV EAX,1)
	// 16: B8 FF FF FF FF        MOV EAX, -1   (negative path)
	// 21: EB 09                 JMP +9  -> byte 32 (POP EBP)
	// 23: 31 C0                 XOR EAX, EAX  (zero_path)
	// 25: EB 05                 JMP +5  -> byte 32 (POP EBP)
	// 27: B8 01 00 00 00        MOV EAX, 1    (positive_path)
	// 32: 5D                    POP EBP
	// 33: C3                    RET
	prog := []byte{
		0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08,
		0x83, 0xF8, 0x00, 0x74, 0x0C,
		0x83, 0xF8, 0x00, 0x7F, 0x0B,
		0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xEB, 0x09,
		0x31, 0xC0, 0xEB, 0x05,
		0xB8, 0x01, 0x00, 0x00, 0x00,
		0x5D, 0xC3,
	}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{Name: "classify_sign", Entry: base, MaxInstructions: 30})
	if err != nil {
		t.Fatalf("bridge.Build: %v", err)
	}

	if result.Graph == nil {
		t.Fatal("expected non-nil CFG graph")
	}
	if len(result.Instructions) < 8 {
		t.Fatalf("expected >= 8 instructions, got %d", len(result.Instructions))
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
		t.Fatal("PrintC.Emit returned empty output for classify_sign function")
	}
	t.Logf("ClassifySign C output:\n%s", output)
}
