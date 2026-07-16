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

// Command goldengap runs the Gosleigh decompile pipeline over every function
// in a Ghidra golden JSON file (see testdata/x64_corpus2/GenGoldens.java for
// the golden schema) and prints {name, output, error} JSON for each function.
//
// This is the "run" step of tools/goldengap/goldengap.py: the Python driver
// generates the golden JSON (MSVC compile -> Ghidra headless decompile) and
// this binary supplies the Gosleigh side of the diff. It reuses the exact
// pipeline already exercised by pkg/loader/x64_corpus2_diag_test.go
// (EngineBuilder.Build -> bridge.Build -> bridge.Decompile) so the CLI and
// the in-repo diagnostic tests measure the same thing. No pkg/ engine code
// is touched by this command.
//
// Usage:
//
//	go run ./cmd/goldengap -goldens testdata/x64_auto/x64_goldens.json \
//	    -sla pkg/sla/testdata/x86-64-packed.sla \
//	    -pspec testdata/sla/x86-64.pspec \
//	    -cspec testdata/sla/x86-64-win.cspec \
//	    -out testdata/x64_auto/gosleigh_out.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
)

// goldenEntry mirrors one function in a GenGoldens.java-produced golden JSON:
// name, entry offset, body bytes (hex), and Ghidra's decompiled C. Same
// schema as x64CorpusEntry in pkg/loader/x64_corpus_diag_test.go.
type goldenEntry struct {
	Name  string `json:"name"`
	Entry int64  `json:"entry"`
	Bytes string `json:"bytes"`
	C     string `json:"c"`
}

type goldenFile struct {
	Functions []goldenEntry `json:"functions"`
}

// funcResult is this CLI's output shape for one function: the Gosleigh
// decompile output, or a non-empty Error when any pipeline stage failed.
// The Error prefixes (BYTES-ERR/BUILD-ERR/BRIDGE-ERR/EMIT-ERR/PANIC) mirror
// the log tags used by the pkg/loader x64_corpus2 diagnostic test so a
// mismatch report can tell a hard engine failure apart from a semantic gap.
type funcResult struct {
	Name   string `json:"name"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

type resultFile struct {
	Functions []funcResult `json:"functions"`
}

func main() {
	goldensPath := flag.String("goldens", "", "path to golden JSON (GenGoldens.java schema, required)")
	slaPath := flag.String("sla", "pkg/sla/testdata/x86-64-packed.sla", "path to .sla file")
	pspecPath := flag.String("pspec", "testdata/sla/x86-64.pspec", "path to .pspec file")
	cspecPath := flag.String("cspec", "testdata/sla/x86-64-win.cspec", "path to .cspec file")
	outPath := flag.String("out", "", "output JSON path (default: stdout)")
	maxInstr := flag.Int("max-instructions", 200, "max instructions per function")
	flag.Parse()

	if *goldensPath == "" {
		fmt.Fprintln(os.Stderr, "goldengap: -goldens is required")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*goldensPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goldengap: read goldens: %v\n", err)
		os.Exit(1)
	}
	var gf goldenFile
	if err := json.Unmarshal(raw, &gf); err != nil {
		fmt.Fprintf(os.Stderr, "goldengap: unmarshal goldens: %v\n", err)
		os.Exit(1)
	}

	out := resultFile{Functions: make([]funcResult, 0, len(gf.Functions))}
	for _, fn := range gf.Functions {
		out.Functions = append(out.Functions, decompileOne(fn, *slaPath, *pspecPath, *cspecPath, *maxInstr))
	}

	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "goldengap: marshal results: %v\n", err)
		os.Exit(1)
	}
	if *outPath == "" {
		fmt.Println(string(enc))
		return
	}
	if err := os.WriteFile(*outPath, enc, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "goldengap: write out: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "goldengap: wrote %d functions to %s\n", len(out.Functions), *outPath)
}

// decompileOne mirrors the pkg/loader x64_corpus2 diagnostic test's pipeline
// (EngineBuilder.Build -> bridge.Build -> bridge.Decompile) for a single
// golden function. The deferred recover matches that test's per-function
// panic guard so one bad function does not abort the whole batch.
func decompileOne(fn goldenEntry, slaPath, pspecPath, cspecPath string, maxInstr int) (res funcResult) {
	res.Name = fn.Name
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprintf("PANIC: %v", r)
		}
	}()

	prog, err := hex.DecodeString(fn.Bytes)
	if err != nil {
		res.Error = fmt.Sprintf("BYTES-ERR: %v", err)
		return
	}

	engine, base, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath, Bytes: prog}).Build()
	if err != nil {
		res.Error = fmt.Sprintf("BUILD-ERR: %v", err)
		return
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name: fn.Name, Entry: base, MaxInstructions: maxInstr,
		CspecPath: cspecPath, SymbolName: fn.Name,
	})
	if err != nil {
		res.Error = fmt.Sprintf("BRIDGE-ERR: %v", err)
		return
	}

	out, err := bridge.Decompile(engine, result, bridge.DecompileConfig{GhidraFormat: true})
	if err != nil {
		res.Error = fmt.Sprintf("EMIT-ERR: %v", err)
		return
	}
	res.Output = out
	return
}
