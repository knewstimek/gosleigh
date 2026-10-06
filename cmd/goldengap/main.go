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
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"gosleigh/pkg/address"
	"gosleigh/pkg/bridge"
	"gosleigh/pkg/loader"
	"gosleigh/pkg/pcode"
)

// goldenEntry mirrors one function in a GenGoldens.java-produced golden JSON:
// name, entry offset, body bytes (hex), and Ghidra's decompiled C. Same
// schema as x64CorpusEntry in pkg/loader/x64_corpus_diag_test.go.
type goldenEntry struct {
	Name string `json:"name"`
	// Display is the name the host gives the core for this function
	// (transformed / namespace-qualified); empty falls back to Name.
	Display string `json:"display"`
	Entry   int64  `json:"entry"`
	Bytes   string `json:"bytes"`
	C       string `json:"c"`
	// Locals are the host's stack-frame locals (realexe GenSample), served
	// as the function's name-locked local symbols.
	Locals []struct {
		Offset int64  `json:"offset"`
		Name   string `json:"name"`
	} `json:"locals"`
	// Tracked are the host's register values at the entry.
	Tracked []struct {
		Reg string `json:"reg"`
		Val int64  `json:"val"`
	} `json:"tracked"`
	// FlowOverrides are the host's instruction flow overrides in the body.
	FlowOverrides []struct {
		Addr uint64 `json:"addr"`
		Type string `json:"type"`
	} `json:"flowoverrides"`
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
	pePath := flag.String("pe", "", "map this PE's sections at their linked VMAs and decompile each golden at its absolute entry (golden bytes are ignored)")
	symbolsPath := flag.String("symbols", "", "host symbol table JSON (functions/externals, tools/realexe/GenSample.java) served as the HostScope")
	flag.StringVar(&captureDir, "host-captures", "", "directory of per-function decompiler savefiles (<entry %08x>.xml, tools/realexe capture): their global data symbols extend the HostScope")
	index := flag.Int("index", -1, "decompile only the golden at this index (-1 = all); lets a driver isolate each function in its own process")
	memLimitMB := flag.Uint64("mem-limit-mb", 0, "exit with status 3 once the Go heap exceeds this many MB (0 = no limit)")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to this file")
	indices := flag.String("indices", "", "comma-separated golden indices; streams one JSON line per function to stdout as each finishes (a driver shards work across processes and recovers from a hang)")
	flag.Parse()
	if *cpuProfile != "" {
		if f, err := os.Create(*cpuProfile); err == nil {
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		}
	}

	if *memLimitMB > 0 {
		go memWatchdog(*memLimitMB << 20)
	}
	if v := os.Getenv("GOLDENGAP_STALL"); v != "" {
		// Diagnostic: after v seconds dump every goroutine's stack and exit,
		// to see where a non-converging decompilation spins.
		secs, _ := strconv.Atoi(v)
		go func() {
			time.Sleep(time.Duration(secs) * time.Second)
			buf := make([]byte, 1<<20)
			os.Stderr.Write(buf[:runtime.Stack(buf, true)])
			os.Exit(4)
		}()
	}

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

	var sections []loader.PESection
	if *pePath != "" {
		if sections, err = loader.LoadPESections(*pePath); err != nil {
			fmt.Fprintf(os.Stderr, "goldengap: %v\n", err)
			os.Exit(1)
		}
	}

	fns := gf.Functions
	if *index >= 0 {
		if *index >= len(fns) {
			fmt.Fprintf(os.Stderr, "goldengap: -index %d out of range (%d goldens)\n", *index, len(fns))
			os.Exit(1)
		}
		fns = fns[*index : *index+1]
	}

	var host pcode.HostScope
	if *symbolsPath != "" {
		h, err := loadHostSymbols(*symbolsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "goldengap: %v\n", err)
			os.Exit(1)
		}
		host = h
	}

	if *indices != "" {
		w := bufio.NewWriter(os.Stdout)
		for _, f := range strings.Split(*indices, ",") {
			i, err := strconv.Atoi(f)
			if err != nil || i < 0 || i >= len(gf.Functions) {
				continue
			}
			fn := gf.Functions[i]
			b := &loader.EngineBuilder{SLAPath: *slaPath, PspecPath: *pspecPath}
			if sections != nil {
				b.BaseAddr, b.Sections = uint64(fn.Entry), sections
			}
			start := time.Now()
			res := decompileOne(fn, b, *cspecPath, *maxInstr, host)
			line, _ := json.Marshal(struct {
				Index int     `json:"index"`
				Secs  float64 `json:"secs"`
				funcResult
			}{i, time.Since(start).Seconds(), res})
			w.Write(append(line, '\n'))
			w.Flush()
		}
		return
	}

	out := resultFile{Functions: make([]funcResult, 0, len(fns))}
	for _, fn := range fns {
		b := &loader.EngineBuilder{SLAPath: *slaPath, PspecPath: *pspecPath}
		if sections != nil {
			b.BaseAddr, b.Sections = uint64(fn.Entry), sections
		}
		out.Functions = append(out.Functions, decompileOne(fn, b, *cspecPath, *maxInstr, host))
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

// hostLocals returns nil when the golden carries no localdb at all, and a
// (possibly empty) map when it does: the host then names every frame slot it
// knows, and the core names the rest.
func hostLocals(fn goldenEntry) map[int64]string {
	if fn.Locals == nil {
		return nil
	}
	m := make(map[int64]string, len(fn.Locals))
	for _, l := range fn.Locals {
		m[l.Offset] = l.Name
	}
	return m
}

// hostSymbols serves a dumped Ghidra program symbol table as the decompiler's
// HostScope, the way DecompileCallback answers the C++ core's queries.
type hostSymbols struct {
	funcs map[uint64]pcode.HostFunction
	exts  map[uint64]string
}

func loadHostSymbols(path string) (*hostSymbols, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read symbols: %w", err)
	}
	var f struct {
		Functions []struct {
			Entry     uint64 `json:"entry"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			CC        string `json:"cc"`
			ExtraPop  *int32 `json:"extrapop"`
			NoReturn  bool   `json:"noreturn"`
		} `json:"functions"`
		Externals []struct {
			Addr uint64 `json:"addr"`
			Name string `json:"name"`
		} `json:"externals"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse symbols: %w", err)
	}
	h := &hostSymbols{funcs: make(map[uint64]pcode.HostFunction, len(f.Functions)), exts: make(map[uint64]string, len(f.Externals))}
	for _, fn := range f.Functions {
		name := fn.Name
		// TODO known mismatch: C++ prints the namespace only when it is not
		// the calling function's own (PrintC::pushSymbolScope, minimal
		// strategy); this always qualifies.
		if fn.Namespace != "" {
			name = fn.Namespace + "::" + name
		}
		hf := pcode.HostFunction{Name: name, Model: fn.CC, ExtraPop: pcode.ExtrapopUnknown, NoReturn: fn.NoReturn}
		if fn.ExtraPop != nil {
			hf.ExtraPop = *fn.ExtraPop
		}
		h.funcs[fn.Entry] = hf
	}
	for _, e := range f.Externals {
		h.exts[e.Addr] = e.Name
	}
	return h, nil
}

func (h *hostSymbols) QueryFunction(addr address.Address) (pcode.HostFunction, bool) {
	hf, ok := h.funcs[addr.Offset]
	return hf, ok
}

func (h *hostSymbols) QueryExternalRef(addr address.Address) (string, bool) {
	n, ok := h.exts[addr.Offset]
	return n, ok
}

// memWatchdog kills the process once the Go heap passes limit bytes. Real
// binaries can drive the engine into unbounded growth (rule oscillation that
// keeps allocating), which no in-process recover can stop; the driver runs one
// function per process and records exit status 3 as a memory blow-up.
func memWatchdog(limit uint64) {
	var ms runtime.MemStats
	for range time.Tick(200 * time.Millisecond) {
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > limit {
			fmt.Fprintf(os.Stderr, "goldengap: heap %d MB exceeds limit\n", ms.HeapAlloc>>20)
			os.Exit(3)
		}
	}
}

// decompileOne mirrors the pkg/loader x64_corpus2 diagnostic test's pipeline
// (EngineBuilder.Build -> bridge.Build -> bridge.Decompile) for a single
// golden function. The deferred recover matches that test's per-function
// panic guard so one bad function does not abort the whole batch. When b has
// no Sections, the golden body bytes are mapped at base 0 (isolated harness).
func decompileOne(fn goldenEntry, b *loader.EngineBuilder, cspecPath string, maxInstr int, host pcode.HostScope) (res funcResult) {
	res.Name = fn.Name
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprintf("PANIC: %v", r)
			if os.Getenv("GOLDENGAP_TRACE") != "" {
				res.Error += "\n" + string(debug.Stack())
			}
		}
	}()

	if b.Sections == nil {
		prog, err := hex.DecodeString(fn.Bytes)
		if err != nil {
			res.Error = fmt.Sprintf("BYTES-ERR: %v", err)
			return
		}
		b.Bytes = prog
	}

	engine, base, err := b.Build()
	if err != nil {
		res.Error = fmt.Sprintf("BUILD-ERR: %v", err)
		return
	}

	result, err := bridge.Build(engine, bridge.BuildConfig{
		Name: fn.Name, Entry: base, MaxInstructions: maxInstr,
		CspecPath: cspecPath, SymbolName: displayName(fn), HostScope: withCapture(host, fn, base.Space),
		HostLocals: hostLocals(fn), FlowOverrides: flowOverrides(fn), TrackedRegs: trackedRegs(fn),
		HostComments: captureComments(fn),
		Injections:   captureInjections(fn, host, base.Space),
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

func displayName(fn goldenEntry) string {
	if fn.Display != "" {
		return fn.Display
	}
	return fn.Name
}

func flowOverrides(fn goldenEntry) map[uint64]string {
	if len(fn.FlowOverrides) == 0 {
		return nil
	}
	m := make(map[uint64]string, len(fn.FlowOverrides))
	for _, f := range fn.FlowOverrides {
		m[f.Addr] = f.Type
	}
	return m
}

func trackedRegs(fn goldenEntry) map[string]uint64 {
	if len(fn.Tracked) == 0 {
		return nil
	}
	m := make(map[string]uint64, len(fn.Tracked))
	for _, t := range fn.Tracked {
		m[t.Reg] = uint64(t.Val)
	}
	return m
}
