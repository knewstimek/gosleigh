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

// TestELFLoader verifies that LoadELF32TextSection correctly reads the .text
// section from the generated ELF32 fixture.
func TestELFLoader(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	elfPath := filepath.Join(dir, "../../testdata/elfs/simple_add.elf")

	data, baseAddr, err := loader.LoadELF32TextSection(elfPath)
	if err != nil {
		t.Fatalf("LoadELF32TextSection: %v", err)
	}
	if len(data) != 11 {
		t.Fatalf("expected 11 bytes, got %d", len(data))
	}
	if data[0] != 0x55 {
		t.Fatalf("expected data[0] == 0x55 (PUSH EBP), got 0x%02x", data[0])
	}
	t.Logf("loaded %d bytes from .text at VMA 0x%x", len(data), baseAddr)
}

// TestX86ELFDecompile exercises the full pipeline using a real ELF32 binary:
//
//	LoadELF32TextSection -> EngineBuilder.Build -> bridge.Build -> Heritage -> PrintC
//
// The fixture encodes: push ebp; mov ebp,esp; mov eax,[ebp+8]; add eax,[ebp+0xC]; pop ebp; ret
// The test asserts that PrintC produces non-empty C output from the ELF-loaded bytes.
func TestX86ELFDecompile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)

	elfPath := filepath.Join(dir, "../../testdata/elfs/simple_add.elf")
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	data, baseAddr, err := loader.LoadELF32TextSection(elfPath)
	if err != nil {
		t.Fatalf("LoadELF32TextSection: %v", err)
	}

	engine, entryAddr, err := (&loader.EngineBuilder{
		SLAPath:   slaPath,
		PspecPath: pspecPath,
		Bytes:     data,
		BaseAddr:  baseAddr,
	}).Build()
	if err != nil {
		t.Fatalf("EngineBuilder.Build: %v", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            "simple_add",
		Entry:           entryAddr,
		MaxInstructions: 20,
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

	heritage := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
	heritage.Heritage(result.Graph)

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

	output, err := pcode.NewPrintC().Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for ELF-loaded function")
	}
	t.Logf("emitted C from ELF:\n%s", output)
}
