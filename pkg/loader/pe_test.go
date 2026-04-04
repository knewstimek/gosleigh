// Copyright 2026 The Gosleigh Authors. Apache 2.0.

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

// TestPELoader verifies that LoadPE32TextSection correctly reads the .text
// section from the generated PE32 fixture.
func TestPELoader(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	pePath := filepath.Join(dir, "../../testdata/elfs/simple_add.exe")

	data, vma, err := loader.LoadPE32TextSection(pePath)
	if err != nil {
		t.Fatalf("LoadPE32TextSection: %v", err)
	}
	if len(data) != 13 {
		t.Fatalf("expected 13 bytes, got %d", len(data))
	}
	if data[0] != 0x55 {
		t.Fatalf("expected data[0] == 0x55 (PUSH EBP), got 0x%02x", data[0])
	}
	if vma != 0x00401000 {
		t.Fatalf("expected vma == 0x00401000, got 0x%x", vma)
	}
	t.Logf("loaded %d bytes from .text at VMA 0x%x", len(data), vma)
}

// TestX86PEDecompile exercises the full pipeline using a real PE32 binary:
//
//	LoadPE32TextSection -> EngineBuilder.Build -> bridge.Build -> Heritage -> PrintC
//
// The fixture encodes: push ebp; mov ebp,esp; mov eax,[ebp+8]; add eax,[ebp+0xC]; pop ebp; ret; nop; nop
// The test asserts that PrintC produces non-empty C output from the PE-loaded bytes.
func TestX86PEDecompile(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)

	pePath := filepath.Join(dir, "../../testdata/elfs/simple_add.exe")
	slaPath := filepath.Join(dir, "../sla/testdata/x86-packed.sla")
	pspecPath := filepath.Join(dir, "../../testdata/sla/x86.pspec")

	data, baseAddr, err := loader.LoadPE32TextSection(pePath)
	if err != nil {
		t.Fatalf("LoadPE32TextSection: %v", err)
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
		Name:            "simple_add_pe",
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

	output, err := pcode.NewPrintC().SetRegisterNames(engine.RegisterNamesByLocation()).Emit(result.Funcdata)
	if err != nil {
		t.Fatalf("PrintC.Emit: %v", err)
	}
	if strings.TrimSpace(output) == "" {
		t.Fatal("PrintC.Emit returned empty output for PE-loaded function")
	}
	t.Logf("emitted C from PE:\n%s", output)
}
