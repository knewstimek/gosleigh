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
	// Exec marks a section holding code. Optional: when no section is
	// marked, every section counts as code (see Program.IsExec).
	Exec bool
}

// Program is a spec plus a loaded image, ready to decompile functions. Each
// Decompile builds a fresh engine over the shared, cached .sla decode.
type Program struct {
	spec     Spec
	sections []loader.PESection
	code     *address.Space
	tracked  []sla.PspecContextEntry
	// execKnown: some section is marked Exec (IsExec).
	execKnown bool
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
		p.sections = append(p.sections, loader.PESection{Name: s.Name, VMA: s.VMA, Bytes: s.Data, Exec: s.Exec})
		p.execKnown = p.execKnown || s.Exec
	}
	if p.code, err = p.builder(0).CodeSpace(); err != nil {
		return nil, fmt.Errorf("decomp: %w", err)
	}
	return p, nil
}

// IsExec reports whether addr lies in a section holding code. Without any
// section marked Exec it is true for every loaded address, so a host that
// does not mark sections loses nothing. Analyses that read a callee's
// instructions use it to skip a call through an import slot, whose bytes are
// a pointer, not code.
func (p *Program) IsExec(addr uint64) bool {
	for _, s := range p.sections {
		if addr >= s.VMA && addr-s.VMA < uint64(len(s.Bytes)) {
			return s.Exec || !p.execKnown
		}
	}
	return false
}

// CodeSpace is the default code space every decompilation of p addresses
// into; a HostScope compares and builds addresses in it.
func (p *Program) CodeSpace() *address.Space { return p.code }

// NewEngine builds a Sleigh engine over p's image, for analyses that read
// instructions outside a decompile (pkg/analysis). Each engine keeps its own
// instruction cache; the .sla decode is shared.
// The returned address is entry in the engine's code space.
func (p *Program) NewEngine(entry uint64) (*sla.Engine, address.Address, error) {
	return p.builder(entry).Build()
}

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
	// InstructionHooks are Gosleigh extensions beyond Ghidra (pkg/ext, e.g.
	// branchassume) applied before flow is followed; none for plain Ghidra.
	InstructionHooks []bridge.InstructionHook
	// FlowBounds limits flow to the function's extent (offsets in the entry's
	// space): flow leaving it ends in halt_missing() with Ghidra's
	// out-of-bounds warning. None = the whole space, as Ghidra decompiles.
	FlowBounds []bridge.AddrRange
	// Extensions switches on core behavior beyond Ghidra; the zero value
	// decompiles as Ghidra does. See DIFFERENCES.md.
	Extensions pcode.Extensions
	// NaNIgnore is Ghidra's nanignore option: which NaN tests are dropped.
	// The zero value is Ghidra's default ("compare"); pcode.NaNIgnoreNone
	// keeps them, so float comparisons stay exact for NaN.
	NaNIgnore pcode.NaNIgnore
	// CalleeReads tells which registers a callee reads before writing them
	// (analysis.CalleeReads); with it, the caller's input passed unchanged to
	// such a callee is kept as an argument. nil = Ghidra. See DIFFERENCES.md.
	CalleeReads pcode.HostCalleeReads
	// TrackedRegs are register values known at the entry (register name ->
	// value), added to the pspec tracked_set; an entry here wins.
	TrackedRegs map[string]uint64
	// HostLocals are name-locked stack symbols (stack offset -> name).
	HostLocals map[int64]string
	// HostLocalTypes are the types of stack symbols (stack offset -> type),
	// type-locked as a typed symbol of Ghidra's local scope is.
	HostLocalTypes map[int64]*pcode.HostTypeDesc
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
		HostLocalTypes:  fn.HostLocalTypes,
		HostComments:    fn.HostComments,
		Injections:      fn.Injections,

		// Ghidra's default: a flow over the limit fails the function.
		ErrorTooManyInstructions: true,
		InstructionHooks:         fn.InstructionHooks,
		FlowBounds:               fn.FlowBounds,
		Extensions:               fn.Extensions,
		CalleeReads:              fn.CalleeReads,
		NaNIgnore:                fn.NaNIgnore,
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
