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

// Package decomp is the library entry point of the Gosleigh decompiler: load a
// language spec and an image once, then decompile functions by entry address.
//
// It wires the same pipeline the golden harnesses measure (loader.EngineBuilder
// -> bridge.Build -> bridge.Decompile; cmd/goldengap runs through this package)
// and owns the caller contract those layers leave open: a cspec is always
// supplied (stack-frame recovery depends on it) and the pspec tracked_set
// reaches the core as tracked registers. It plays the role of the Ghidra
// host's DecompileAt request (ghidra_process.cc DecompileAt); what the host
// knows about the program (symbols, prototypes, flow overrides) comes in
// through Function.
//
// Decompile runs in the calling goroutine and cannot be cancelled. The engine
// can grow without bound on some real functions, so a long-lived host should
// run it in a separate process with a memory and time limit.
package decomp

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/bridge"
	"github.com/knewstimek/gosleigh/pkg/loader"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/sla"
)

// DefaultMaxInstructions bounds flow following when Function.MaxInstructions
// is zero. It matches the realexe measurement driver.
const DefaultMaxInstructions = 20000

// Spec is one Ghidra language + compiler combination: the compiled .sla, the
// processor spec and the compiler spec. Package specs embeds the x86 ones.
type Spec struct {
	// ID names the combination, e.g. "x86:LE:64:default:windows".
	ID    string
	SLA   []byte
	Pspec []byte
	Cspec []byte
}

// Section is one loaded image range at its virtual address.
type Section struct {
	Name string
	VMA  uint64
	Data []byte
}

// Program is a spec plus a loaded image, ready to decompile functions. Each
// Decompile builds a fresh engine over the shared, cached .sla decode.
type Program struct {
	spec     Spec
	sections []loader.PESection
	code     *address.Space
	tracked  []sla.PspecContextEntry
}

// Load validates spec and maps sections. The sections are retained, not
// copied.
func Load(spec Spec, sections []Section) (*Program, error) {
	if len(spec.SLA) == 0 || len(spec.Pspec) == 0 || len(spec.Cspec) == 0 {
		return nil, fmt.Errorf("decomp: spec %q needs sla, pspec and cspec", spec.ID)
	}
	if len(sections) == 0 {
		return nil, fmt.Errorf("decomp: no image sections")
	}
	pspec, err := sla.ParsePspecBytes(spec.Pspec)
	if err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	if _, err := pcode.ParseCspecBytes(spec.Cspec); err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	p := &Program{spec: spec, tracked: pspec.TrackedSet}
	for _, s := range sections {
		p.sections = append(p.sections, loader.PESection{Name: s.Name, VMA: s.VMA, Bytes: s.Data})
	}
	if p.code, err = p.builder(0).CodeSpace(); err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	return p, nil
}

// CodeSpace is the default code space every decompilation of p addresses
// into; a HostScope compares and builds addresses in it.
func (p *Program) CodeSpace() *address.Space { return p.code }

func (p *Program) builder(entry uint64) *loader.EngineBuilder {
	return &loader.EngineBuilder{SLABytes: p.spec.SLA, PspecBytes: p.spec.Pspec, BaseAddr: entry, Sections: p.sections}
}

// Function describes one function to decompile and what the host knows
// about it.
type Function struct {
	// Entry is the function's entry offset in CodeSpace.
	Entry uint64
	// Name is the function's name; empty uses the host's name for Entry, then
	// Ghidra's default FUN_<entry>.
	Name string
	// DisplayName overrides the printed name (e.g. namespace-qualified).
	DisplayName string
	// MaxInstructions bounds flow following (0 = DefaultMaxInstructions).
	MaxInstructions int

	// Host answers the core's symbol queries (callee names, prototypes,
	// external references). nil decompiles with no program symbols.
	Host pcode.HostScope
	// FlowOverrides are instruction flow overrides by address ("BRANCH",
	// "CALL", "CALL_RETURN", "RETURN").
	FlowOverrides map[uint64]string
	// TrackedRegs are register values known at the entry (register name ->
	// value), added to the pspec tracked_set; an entry here wins.
	TrackedRegs map[string]uint64
	// HostLocals are name-locked stack symbols (stack offset -> name).
	HostLocals map[int64]string
	// HostComments are the function's comments (Ghidra <commentdb>).
	HostComments []bridge.HostComment
	// Injections are host-compiled call-fixup payloads by call-site address.
	Injections map[uint64]bridge.HostInjection

	// GhidraFormat selects Ghidra's exact layout instead of the indented one.
	GhidraFormat bool
}

// Result is the decompiled function.
type Result struct {
	C string
	// Warnings are the bridge's translation warnings (undecodable bytes, flow
	// that left the loaded image); core warnings are rendered inside C.
	Warnings []string
}

// ErrPanic marks a decompilation that panicked inside the engine: an engine
// defect on this input, not a caller error.
var ErrPanic = errors.New("decompiler panic")

// Decompile decompiles fn.
func (p *Program) Decompile(fn Function) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			err = fmt.Errorf("%w at 0x%x: %v\n%s", ErrPanic, fn.Entry, r, debug.Stack())
		}
	}()

	engine, entry, err := p.builder(fn.Entry).Build()
	if err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}

	name := fn.Name
	if name == "" && fn.Host != nil {
		if hf, ok := fn.Host.QueryFunction(entry); ok {
			name = hf.Name
		}
	}
	if name == "" {
		// Ghidra's default function name (SymbolUtilities.getDefaultFunctionName):
		// at least 8 hex digits, so FUN_005c83d0 and FUN_143495c00.
		name = fmt.Sprintf("FUN_%08x", fn.Entry)
	}
	display := fn.DisplayName
	if display == "" {
		display = name
	}
	maxInstr := fn.MaxInstructions
	if maxInstr <= 0 {
		maxInstr = DefaultMaxInstructions
	}

	built, err := bridge.Build(engine, bridge.BuildConfig{
		Name:            name,
		SymbolName:      display,
		Entry:           entry,
		MaxInstructions: maxInstr,
		CspecBytes:      p.spec.Cspec,
		HostScope:       fn.Host,
		FlowOverrides:   fn.FlowOverrides,
		TrackedRegs:     p.trackedRegs(fn.TrackedRegs),
		HostLocals:      fn.HostLocals,
		HostComments:    fn.HostComments,
		Injections:      fn.Injections,
	})
	if err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	c, err := bridge.Decompile(engine, built, bridge.DecompileConfig{GhidraFormat: fn.GhidraFormat})
	if err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	return &Result{C: c, Warnings: built.Warnings}, nil
}

func (p *Program) trackedRegs(host map[string]uint64) map[string]uint64 {
	if len(p.tracked) == 0 && len(host) == 0 {
		return nil
	}
	m := make(map[string]uint64, len(p.tracked)+len(host))
	for _, e := range p.tracked {
		m[e.Name] = e.Value
	}
	for k, v := range host {
		m[k] = v
	}
	return m
}
