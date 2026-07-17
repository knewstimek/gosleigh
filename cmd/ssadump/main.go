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

// Command ssadump runs the Gosleigh production decompile pipeline
// (loader.EngineBuilder -> bridge.Build -> bridge.Decompile, the same path
// cmd/gosleigh and the golden-diag tests use) against one function of a
// GenGoldens-schema golden JSON file, then prints the final SSA p-code in the
// same textual convention as C++ Ghidra's `print raw` console command
// (pkg/pcode/ssadump.go DumpSSA).
//
// This is the Gosleigh-side half of tools/ssadiff/: pair its output with a
// tools/decomp_dbg.exe `print raw` capture (tools/ssadiff/run_cpp.py) and
// tools/ssadiff/ssadiff.py aligns and diffs the two op-by-op.
//
// Usage:
//
//	go run ./cmd/ssadump --golden testdata/x64_corpus/x64_goldens.json --func sum_to_n
//	go run ./cmd/ssadump --golden testdata/x64_corpus2/x64_goldens.json --func umulhi --print-c
//
// Run from the repository root: the default --sla/--pspec/--cspec flags are
// relative to it (they match the x64 Windows ABI corpus used by
// pkg/loader/x64_corpus_diag_test.go and x64_corpus2_diag_test.go).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// goldenEntry mirrors one function entry in a GenGoldens-schema JSON file
// (testdata/x64_corpus/x64_goldens.json, x64_corpus2/x64_goldens.json, ...).
type goldenEntry struct {
	Name  string `json:"name"`
	Entry int64  `json:"entry"`
	Bytes string `json:"bytes"`
	C     string `json:"c"`
}

type goldenFile struct {
	Functions []goldenEntry `json:"functions"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ssadump: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("ssadump", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	goldenPath := fs.String("golden", "testdata/x64_corpus/x64_goldens.json", "path to a GenGoldens-schema golden JSON file")
	funcName := fs.String("func", "", "function name to dump (required, must match a \"name\" entry in --golden)")
	slaPath := fs.String("sla", "pkg/sla/testdata/x86-64-packed.sla", "path to the .sla file")
	pspecPath := fs.String("pspec", "testdata/sla/x86-64.pspec", "path to the .pspec file")
	cspecPath := fs.String("cspec", "testdata/sla/x86-64-win.cspec", "path to the .cspec file")
	maxInstructions := fs.Int("max-instructions", 200, "instruction translation cap")
	printC := fs.Bool("print-c", false, "also print the decompiled C output before the SSA dump")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *funcName == "" {
		fs.Usage()
		return fmt.Errorf("--func is required")
	}

	raw, err := os.ReadFile(*goldenPath)
	if err != nil {
		return fmt.Errorf("read golden %s: %w", *goldenPath, err)
	}
	var gf goldenFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		return fmt.Errorf("unmarshal golden %s: %w", *goldenPath, err)
	}

	var entry *goldenEntry
	for i := range gf.Functions {
		if gf.Functions[i].Name == *funcName {
			entry = &gf.Functions[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("function %q not found in %s", *funcName, *goldenPath)
	}

	prog, err := hexToBytes(entry.Bytes)
	if err != nil {
		return fmt.Errorf("decode bytes for %s: %w", *funcName, err)
	}

	engine, base, err := (&loader.EngineBuilder{
		SLAPath:   *slaPath,
		PspecPath: *pspecPath,
		Bytes:     prog,
	}).Build()
	if err != nil {
		return fmt.Errorf("build engine: %w", err)
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            entry.Name,
		Entry:           base,
		MaxInstructions: *maxInstructions,
		CspecPath:       *cspecPath,
		SymbolName:      entry.Name,
	})
	if err != nil {
		return fmt.Errorf("bridge.Build: %w", err)
	}

	cOut, err := bridge.Decompile(engine, result, bridge.DecompileConfig{GhidraFormat: true})
	if err != nil {
		return fmt.Errorf("bridge.Decompile: %w", err)
	}

	if *printC {
		fmt.Println("--- print C ---")
		fmt.Println(cOut)
	}

	fmt.Println(pcode.DumpSSA(result.Funcdata, engine.RegisterNamesByLocation()))
	return nil
}

// hexToBytes decodes a hex string (as stored in GenGoldens-schema "bytes"
// fields) into raw bytes.
func hexToBytes(h string) ([]byte, error) {
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %d", len(h))
	}
	out := make([]byte, len(h)/2)
	for i := range out {
		var b byte
		for j := 0; j < 2; j++ {
			c := h[i*2+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("bad hex char %q", c)
			}
		}
		out[i] = b
	}
	return out, nil
}
