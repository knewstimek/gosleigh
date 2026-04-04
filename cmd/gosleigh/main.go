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

// Command gosleigh is the CLI entry point for the Gosleigh Sleigh runtime.
//
// Usage:
//
//	gosleigh translate [flags]
//
// Subcommand: translate
//
//	--sla    path to .sla file (required)
//	--pspec  path to .pspec file (optional; sets context defaults)
//	--binary path to raw binary image (optional)
//	--offset byte offset into binary at which the image VMA starts (default 0)
//	--size   number of bytes to map from binary (default 0 = all)
//	--entry  entry address offset within the default address space (default 0)
//	--output output format: "c" or "json" (default "c")
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: gosleigh <subcommand> [flags]\n")
		fmt.Fprintf(os.Stderr, "subcommands: translate\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "translate":
		if err := runTranslate(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "translate: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q; try: translate\n", os.Args[1])
		os.Exit(1)
	}
}

// runTranslate implements the `translate` subcommand.
func runTranslate(args []string) error {
	fs := flag.NewFlagSet("translate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	slaPath := fs.String("sla", "", "path to .sla file (required)")
	pspecPath := fs.String("pspec", "", "path to .pspec file (optional)")
	binaryPath := fs.String("binary", "", "path to raw binary image (optional)")
	offsetFlag := fs.Uint64("offset", 0, "byte offset into binary where image VMA starts")
	sizeFlag := fs.Uint64("size", 0, "bytes to map from binary (0 = all)")
	entryFlag := fs.Uint64("entry", 0, "entry address offset within the default address space")
	outputFlag := fs.String("output", "c", "output format: c or json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *slaPath == "" {
		fs.Usage()
		return fmt.Errorf("--sla is required")
	}

	outputFmt := strings.ToLower(*outputFlag)
	if outputFmt != "c" && outputFmt != "json" {
		return fmt.Errorf("--output must be c or json, got %q", *outputFlag)
	}

	// Build the engine via the loader pipeline.
	b := &loader.EngineBuilder{
		SLAPath:    *slaPath,
		PspecPath:  *pspecPath,
		BinaryPath: *binaryPath,
		BaseAddr:   *entryFlag,
		BaseOffset: *offsetFlag,
		ReadSize:   *sizeFlag,
	}
	engine, entryAddr, err := b.Build()
	if err != nil {
		return fmt.Errorf("build engine: %w", err)
	}

	// Translate starting at the entry address.
	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            "gosleigh_func",
		Entry:           entryAddr,
		MaxInstructions: 4096,
	})
	if err != nil {
		return fmt.Errorf("bridge.Build: %w", err)
	}
	if result == nil || len(result.Instructions) == 0 {
		return fmt.Errorf("no instructions translated")
	}

	// Heritage (SSA construction).
	heritage := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
	heritage.Heritage(result.Graph)

	// Batch-A analysis actions (mirrors bridge_test.go pipeline).
	pool := pcode.NewBatchAActionPool("batch-a", "analysis")
	if res := pool.Perform(result.Funcdata); res < 0 {
		return fmt.Errorf("batch action pool returned %d", res)
	}
	if res := pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata); res != 0 {
		return fmt.Errorf("ActionBlockStructure.Apply returned %d", res)
	}
	if res := pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata); res != 0 {
		return fmt.Errorf("ActionFinalStructure.Apply returned %d", res)
	}

	switch outputFmt {
	case "json":
		return emitJSON(result)
	default:
		return emitC(result.Funcdata)
	}
}

// emitC prints the decompiled C output to stdout.
func emitC(fd *pcode.Funcdata) error {
	output, err := pcode.NewPrintC().Emit(fd)
	if err != nil {
		return fmt.Errorf("PrintC.Emit: %w", err)
	}
	fmt.Print(output)
	return nil
}

// instructionJSON is the JSON shape for a single translated instruction.
type instructionJSON struct {
	Address string `json:"address"`
	Length  int    `json:"length"`
	OpsCount int   `json:"ops_count"`
}

// translateResultJSON is the top-level JSON output shape.
type translateResultJSON struct {
	Instructions []instructionJSON `json:"instructions"`
	BlockCount   int               `json:"block_count"`
	Warnings     []string          `json:"warnings,omitempty"`
}

// emitJSON prints a JSON summary of translated instructions to stdout.
func emitJSON(result *bridge.Result) error {
	out := translateResultJSON{
		Instructions: make([]instructionJSON, len(result.Instructions)),
		BlockCount:   0,
		Warnings:     result.Warnings,
	}
	if result.Graph != nil {
		out.BlockCount = result.Graph.GetSize()
	}
	for i, instr := range result.Instructions {
		out.Instructions[i] = instructionJSON{
			Address:  instr.Address.String(),
			Length:   instr.Length,
			OpsCount: len(instr.Ops),
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
