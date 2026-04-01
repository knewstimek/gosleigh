package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

type builderCaptureRawEmitter struct {
	ops []pcode.RawOp
	err error
}

func (e *builderCaptureRawEmitter) EmitRaw(op pcode.RawOp) error {
	if e.err != nil {
		return e.err
	}
	e.ops = append(e.ops, cloneRawOp(op))
	return nil
}

func (e *builderCaptureRawEmitter) Ops() []pcode.RawOp {
	return cloneRawOps(e.ops)
}

func TestSleighBuilderDispatchesDirectivesAndTracksLabelScope(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceCtx := NewParserContext(address.Address{Space: ram, Offset: 0x4000}, nil)
	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.SetDelaySlot(0)
	sourceCtx.BaseState.Length = 4
	targetCtx := NewParserContext(address.Address{Space: ram, Offset: 0x401000}, nil)
	targetCtx.SetParserState(ParseStatePcode)
	targetCtx.BaseState.SetConstructor(ConstructorBoundary{
		NamedSections: []NamedSectionBoundary{{
			SectionID: 2,
			Template: ConstructTplBoundary{
				Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_INT_ADD),
					Opcode:   pcode.CPUI_INT_ADD.String(),
				}},
			},
		}},
	})
	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(sourceCtx.GetAddr(), sourceCtx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}
	if err := cache.SetParserContext(targetCtx.GetAddr(), targetCtx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}
	runtime := RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1},
		SpacesByIndex: map[int64]*address.Space{
			1: ram,
			2: &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1},
		},
	}
	events := make([]string, 0, 5)
	b := NewSleighBuilder(runtime, 10, 7, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, "dump:"+op.Opcode)
			if state.SectionID != -1 && state.SectionID != 2 {
				t.Fatalf("unexpected dump section: got %d want -1 or 2", state.SectionID)
			}
			return nil
		},
		OnLabel: func(labelID uint64, state BuilderState) error {
			events = append(events, "label")
			if labelID != 13 {
				t.Fatalf("unexpected label id: got %d want 13", labelID)
			}
			if state.SectionID != -1 {
				t.Fatalf("unexpected label section: got %d want -1", state.SectionID)
			}
			return nil
		},
		OnBuild: func(op OpTplBoundary, operandIndex int64, sectionID int64, state BuilderState) error {
			events = append(events, "build")
			if operandIndex != 1 || sectionID != -1 {
				t.Fatalf("unexpected build args: operand=%d section=%d", operandIndex, sectionID)
			}
			if state.SectionID != -1 {
				t.Fatalf("unexpected build state section: got %d want -1", state.SectionID)
			}
			return nil
		},
		OnDelaySlot: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, "delay")
			if state.SectionID != -1 {
				t.Fatalf("unexpected delay state section: got %d want -1", state.SectionID)
			}
			return nil
		},
	})
	b.State.SetDisassemblyCache(cache)
	b.State.Walker = sourceWalker

	construct := ConstructTplBoundary{
		NumLabels: 3,
		Ops: []OpTplBoundary{
			{OpcodeID: int64(pcode.CPUI_COPY), Opcode: "COPY"},
			{
				OpcodeID: int64(pcode.CPUI_PTRADD),
				Opcode:   "LABELBUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 3},
				}},
			},
			{
				OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
				Opcode:   "BUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 1},
				}},
			},
			{OpcodeID: int64(pcode.CPUI_INDIRECT), Opcode: "DELAY_SLOT"},
			{
				OpcodeID: int64(pcode.CPUI_PTRSUB),
				Opcode:   "CROSSBUILD",
				Inputs: []VarnodeTplBoundary{
					{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x401000},
					},
					{Offset: ConstBoundary{Kind: ConstKindReal, Value: 2}},
				},
			},
		},
	}

	if err := b.Build(construct, -1); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if got := b.Pcode.LabelBase; got != 10 {
		t.Fatalf("unexpected label base after build: got %d want 10", got)
	}
	if got := b.Pcode.LabelCount; got != 13 {
		t.Fatalf("unexpected label count after build: got %d want 13", got)
	}
	if got := b.State.SectionID; got != 7 {
		t.Fatalf("unexpected section after build: got %d want 7", got)
	}
	if len(events) != 4 {
		t.Fatalf("unexpected event count: got %d want 4", len(events))
	}
}

func TestBuilderStateDisassemblyCacheBridge(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x401000}
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStatePcode)

	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	state := BuilderState{Cache: cache}
	if !state.HasPcodeParserContext(addr) {
		t.Fatal("expected cached pcode parser context")
	}
	got, err := state.RequirePcodeParserContext(addr)
	if err != nil {
		t.Fatalf("RequirePcodeParserContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("unexpected parser context bridge: got=%p want=%p", got, ctx)
	}
}

func TestSleighBuilderReturnsExplicitUnimplementedForMissingHooks(t *testing.T) {
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_MULTIEQUAL), Opcode: "BUILD", Inputs: []VarnodeTplBoundary{{Offset: ConstBoundary{Kind: ConstKindReal, Value: 0}}}}},
	}

	err := b.Build(construct, -1)
	if err == nil {
		t.Fatal("Build() returned nil for BUILD without hook")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("Build() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("Build() error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "BUILD" {
		t.Fatalf("Build() unimplemented explain mismatch: got %q want %q", uerr.Explain, "BUILD")
	}
	if uerr.HasInstructionLength {
		t.Fatalf("Build() unimplemented error should not carry instruction length")
	}
}

func TestSleighBuilderRejectsNonRealLabelInput(t *testing.T) {
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{
		OnLabel: func(labelID uint64, state BuilderState) error { return nil },
	})
	op := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_PTRADD),
		Opcode:   "LABELBUILD",
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindCurSpace},
		}},
	}

	err := b.SetLabel(op)
	if err == nil {
		t.Fatal("SetLabel() returned nil for non-real label input")
	}
}

func TestSleighBuilderRecursesWalkerBuildsMainSection(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	walkerCtx := NewParserContext(address.Address{Space: ram, Offset: 0x4000}, nil)
	walker := NewParserWalker(walkerCtx)
	walker.BaseState()
	walker.Point.EnsureOperand(0).SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
			}},
		},
	})

	events := make([]string, 0, 1)
	b := NewSleighBuilder(RuntimeContext{}, 4, -1, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, op.Opcode)
			if state.SectionID != -1 {
				t.Fatalf("unexpected dump section: got %d want -1", state.SectionID)
			}
			return nil
		},
	})
	b.State.Walker = walker

	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
			Opcode:   "BUILD",
			Inputs: []VarnodeTplBoundary{{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			}},
		}},
	}

	if err := b.Build(construct, -1); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if len(events) != 1 || events[0] != pcode.CPUI_COPY.String() {
		t.Fatalf("unexpected recursive build events: %#v", events)
	}
	if got := b.Pcode.LabelBase; got != 4 {
		t.Fatalf("unexpected label base after recursive build: got %d want 4", got)
	}
	if got := b.Pcode.LabelCount; got != 4 {
		t.Fatalf("unexpected label count after recursive build: got %d want 4", got)
	}
}

func TestSleighBuilderRecursesWalkerBuildsNamedSection(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	walkerCtx := NewParserContext(address.Address{Space: ram, Offset: 0x5000}, nil)
	walker := NewParserWalker(walkerCtx)
	walker.BaseState()
	child := walker.Point.EnsureOperand(0)
	child.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
			}},
		},
		NamedSections: []NamedSectionBoundary{{
			SectionID: 7,
			Template: ConstructTplBoundary{
				Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_INT_ADD),
					Opcode:   pcode.CPUI_INT_ADD.String(),
				}},
			},
		}},
	})

	events := make([]string, 0, 1)
	b := NewSleighBuilder(RuntimeContext{}, 2, 7, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, op.Opcode)
			if state.SectionID != 7 {
				t.Fatalf("unexpected dump section: got %d want 7", state.SectionID)
			}
			return nil
		},
	})
	b.State.Walker = walker

	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
			Opcode:   "BUILD",
			Inputs: []VarnodeTplBoundary{{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			}},
		}},
	}

	if err := b.Build(construct, 7); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if len(events) != 1 || events[0] != pcode.CPUI_INT_ADD.String() {
		t.Fatalf("unexpected named-section build events: %#v", events)
	}
	if got := b.Pcode.LabelBase; got != 2 {
		t.Fatalf("unexpected label base after named build: got %d want 2", got)
	}
	if got := b.Pcode.LabelCount; got != 2 {
		t.Fatalf("unexpected label count after named build: got %d want 2", got)
	}
}

func TestSleighBuilderBuildEmptyRecursesSubtableOperands(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	walkerCtx := NewParserContext(address.Address{Space: ram, Offset: 0x6000}, nil)
	walkerCtx.SetSymbolTable(&SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID: 1,
				Body: SymbolBodyBoundary{
					Subtable: &SubtableBoundary{},
				},
			},
			{
				ID: 2,
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    1,
					},
				},
			},
		},
	})
	walker := NewParserWalker(walkerCtx)
	walker.BaseState()
	child := walker.Point.EnsureOperand(0)
	child.SetConstructor(ConstructorBoundary{
		OperandSymbolIDs: []uint64{2},
	})
	child.EnsureOperand(0).SetConstructor(ConstructorBoundary{
		NamedSections: []NamedSectionBoundary{{
			SectionID: 7,
			Template: ConstructTplBoundary{
				Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_INT_ADD),
					Opcode:   pcode.CPUI_INT_ADD.String(),
				}},
			},
		}},
	})

	events := make([]string, 0, 1)
	b := NewSleighBuilder(RuntimeContext{}, 0, 7, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, op.Opcode)
			return nil
		},
	})
	b.State.Walker = walker
	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
			Opcode:   "BUILD",
			Inputs: []VarnodeTplBoundary{{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			}},
		}},
	}

	if err := b.Build(construct, 7); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if len(events) != 1 || events[0] != pcode.CPUI_INT_ADD.String() {
		t.Fatalf("unexpected buildEmpty recursion events: %#v", events)
	}
}

func TestRawLabelResolverResolvesRelativeOffsets(t *testing.T) {
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	ops := []pcode.RawOp{
		{
			OpCode: pcode.CPUI_COPY,
			Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 11, Size: 1}},
		},
		{OpCode: pcode.CPUI_COPY},
		{OpCode: pcode.CPUI_COPY},
	}
	resolver := NewRawLabelResolver()
	resolver.AddRelativeRef(0)
	resolver.AddLabel(11, 2)

	if err := resolver.Resolve(ops); err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got := ops[0].Inputs[0].Offset; got != 2 {
		t.Fatalf("unexpected relative label offset: got %d want 2", got)
	}
}

func TestDisassemblyCacheRawOpsRoundTrip(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x7000}
	cache := NewDisassemblyCache()
	source := []pcode.RawOp{
		{
			OpCode: pcode.CPUI_COPY,
			Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}},
		},
	}
	if err := cache.SetRawOps(addr, source); err != nil {
		t.Fatalf("SetRawOps() error: %v", err)
	}
	source[0].Inputs[0].Offset = 0x77

	got, ok := cache.GetRawOps(addr)
	if !ok {
		t.Fatal("GetRawOps() missing cached entry")
	}
	if got[0].Inputs[0].Offset != 0x10 {
		t.Fatalf("GetRawOps() did not isolate stored data: got 0x%x", got[0].Inputs[0].Offset)
	}
	got[0].Inputs[0].Offset = 0x88
	again, ok := cache.GetRawOps(addr)
	if !ok {
		t.Fatal("GetRawOps() missing cached entry on second read")
	}
	if again[0].Inputs[0].Offset != 0x10 {
		t.Fatalf("cached raw ops were mutated by caller: got 0x%x", again[0].Inputs[0].Offset)
	}
	if !cache.DeleteRawOps(addr) {
		t.Fatal("DeleteRawOps() did not report deleted entry")
	}
	if _, ok := cache.GetRawOps(addr); ok {
		t.Fatal("GetRawOps() returned deleted entry")
	}
}

func TestDisassemblyCacheRawBuildOwnsLoweredBuffers(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0x8700}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	output := pcode.VarnodeData{Space: ram, Offset: 0x30, Size: 4}
	inputs := []pcode.VarnodeData{{Space: ram, Offset: 0x10, Size: 4}}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Output: &output,
		Inputs: inputs,
	}}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_COPY),
		Opcode:   pcode.CPUI_COPY.String(),
	}
	if err := cache.AppendRawBuild(instruction, source, lowered, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}

	// Mutate caller-owned buffers after staging. Cached state must remain unchanged.
	output.Offset = 0x99
	inputs[0].Offset = 0x88
	lowered[0].Inputs[0].Offset = 0x77
	if lowered[0].Output != nil {
		lowered[0].Output.Offset = 0x66
	}

	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if emitted[0].Output == nil {
		t.Fatal("unexpected nil emitted output")
	}
	if got := emitted[0].Output.Offset; got != 0x30 {
		t.Fatalf("unexpected emitted output offset: got 0x%x want 0x30", got)
	}
	if got := emitted[0].Inputs[0].Offset; got != 0x10 {
		t.Fatalf("unexpected emitted input offset: got 0x%x want 0x10", got)
	}

	// Captured sink emission is a copy of committed cache data.
	emitted[0].Output.Offset = 0x123
	emitted[0].Inputs[0].Offset = 0x456
	again, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing entry after emit")
	}
	if again[0].Output == nil {
		t.Fatal("unexpected nil cached output")
	}
	if got := again[0].Output.Offset; got != 0x30 {
		t.Fatalf("cached output mutated by captured sink emission: got 0x%x want 0x30", got)
	}
	if got := again[0].Inputs[0].Offset; got != 0x10 {
		t.Fatalf("cached input mutated by captured sink emission: got 0x%x want 0x10", got)
	}
}

func TestDisassemblyCacheRawBuildIssuedOpsReferenceOwnedPool(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0x8703}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	output := pcode.VarnodeData{Space: ram, Offset: 0x30, Size: 4}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Output: &output,
		Inputs: []pcode.VarnodeData{
			{Space: ram, Offset: 0x10, Size: 4},
			{Space: ram, Offset: 0x20, Size: 4},
		},
	}}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_COPY),
		Opcode:   pcode.CPUI_COPY.String(),
	}
	if err := cache.AppendRawBuild(instruction, source, lowered, 0); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}

	state := cache.rawBuild
	if state == nil || len(state.issued) != 1 || len(state.varnodes) != 3 {
		t.Fatalf("unexpected raw build ownership shape: issued=%d varnodes=%d", len(state.issued), len(state.varnodes))
	}
	issued := state.issued[0]
	if len(issued.Inputs) != 2 || issued.Output == nil {
		t.Fatalf("unexpected issued varnode references: inputs=%d output=%p", len(issued.Inputs), issued.Output)
	}
	if &issued.Inputs[0] != &state.varnodes[0] {
		t.Fatalf("issued input[0] does not reference owned pool: got %p want %p", &issued.Inputs[0], &state.varnodes[0])
	}
	if &issued.Inputs[1] != &state.varnodes[1] {
		t.Fatalf("issued input[1] does not reference owned pool: got %p want %p", &issued.Inputs[1], &state.varnodes[1])
	}
	if issued.Output != &state.varnodes[2] {
		t.Fatalf("issued output does not reference owned pool: got %p want %p", issued.Output, &state.varnodes[2])
	}

	state.varnodes[0].Offset = 0x55
	if got := state.issued[0].Inputs[0].Offset; got != 0x55 {
		t.Fatalf("issued input does not track owned pool mutation: got 0x%x want 0x55", got)
	}
}

func TestDisassemblyCacheBeginRawBuildReusesReleasedPoolAcrossInstructions(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	firstInstruction := address.Address{Space: ram, Offset: 0x8701}
	secondInstruction := address.Address{Space: ram, Offset: 0x8702}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(firstInstruction, 2); err != nil {
		t.Fatalf("BeginRawBuild(first) error: %v", err)
	}
	firstOutput := pcode.VarnodeData{Space: ram, Offset: 0x30, Size: 4}
	firstLowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Output: &firstOutput,
		Inputs: []pcode.VarnodeData{
			{Space: ram, Offset: 0x10, Size: 4},
			{Space: ram, Offset: 0x20, Size: 4},
		},
	}}
	firstSource := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_COPY),
		Opcode:   pcode.CPUI_COPY.String(),
	}
	if err := cache.AppendRawBuild(firstInstruction, firstSource, firstLowered, 0); err != nil {
		t.Fatalf("AppendRawBuild(first) error: %v", err)
	}
	firstState := cache.rawBuild
	if firstState == nil || len(firstState.issued) == 0 || len(firstState.varnodes) == 0 {
		t.Fatal("raw build state for first instruction was not populated")
	}
	firstIssuedPtr := &firstState.issued[0]
	firstPoolPtr := &firstState.varnodes[0]
	if err := cache.ResolveRawBuild(firstInstruction); err != nil {
		t.Fatalf("ResolveRawBuild(first) error: %v", err)
	}
	_ = mustEmitRawBuildToCapture(t, cache, firstInstruction)

	if err := cache.BeginRawBuild(secondInstruction, 1); err != nil {
		t.Fatalf("BeginRawBuild(second) error: %v", err)
	}
	secondLowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x40, Size: 4}},
	}}
	if err := cache.AppendRawBuild(secondInstruction, firstSource, secondLowered, 0); err != nil {
		t.Fatalf("AppendRawBuild(second) error: %v", err)
	}
	secondState := cache.rawBuild
	if secondState == nil || len(secondState.issued) == 0 || len(secondState.varnodes) == 0 {
		t.Fatal("raw build state for second instruction was not populated")
	}
	if got := &secondState.issued[0]; got != firstIssuedPtr {
		t.Fatalf("issued backing storage was not reused: got %p want %p", got, firstIssuedPtr)
	}
	if got := &secondState.varnodes[0]; got != firstPoolPtr {
		t.Fatalf("varnode backing storage was not reused: got %p want %p", got, firstPoolPtr)
	}
}

func TestDisassemblyCacheRawBuildRebindsIssuedRefsAfterPoolExpansion(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x8704}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}

	relativeSource := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	const labelBase = uint64(31)
	if err := cache.AppendRawBuild(instruction, relativeSource, []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}, labelBase); err != nil {
		t.Fatalf("AppendRawBuild(relative) error: %v", err)
	}

	// Force varnode pool expansion after a relative ref has already been issued.
	wideInputs := make([]pcode.VarnodeData, 130)
	for i := range wideInputs {
		wideInputs[i] = pcode.VarnodeData{Space: ram, Offset: uint64(i), Size: 4}
	}
	if err := cache.AppendRawBuild(instruction, OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_COPY),
		Opcode:   pcode.CPUI_COPY.String(),
	}, []pcode.RawOp{{
		OpCode: pcode.CPUI_COPY,
		Inputs: wideInputs,
	}}, 0); err != nil {
		t.Fatalf("AppendRawBuild(expand) error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) == 0 || len(emitted[0].Inputs) == 0 {
		t.Fatalf("unexpected emitted shape: %+v", emitted)
	}
	if got := emitted[0].Inputs[0].Offset; got != 2 {
		t.Fatalf("relative branch was not patched after pool expansion: got %d want 2", got)
	}
}

func TestDisassemblyCacheBeginRawBuildClearsResolverStateOnReuse(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	firstInstruction := address.Address{Space: ram, Offset: 0x8711}
	secondInstruction := address.Address{Space: ram, Offset: 0x8712}
	cache := NewDisassemblyCache()
	relativeSource := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	relativeLowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(21)

	if err := cache.BeginRawBuild(firstInstruction, 1); err != nil {
		t.Fatalf("BeginRawBuild(first) error: %v", err)
	}
	if err := cache.AppendRawBuild(firstInstruction, relativeSource, relativeLowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild(first) error: %v", err)
	}
	if err := cache.AddRawBuildLabel(firstInstruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel(first) error: %v", err)
	}
	if err := cache.ResolveRawBuild(firstInstruction); err != nil {
		t.Fatalf("ResolveRawBuild(first) error: %v", err)
	}
	_ = mustEmitRawBuildToCapture(t, cache, firstInstruction)

	if err := cache.BeginRawBuild(secondInstruction, 1); err != nil {
		t.Fatalf("BeginRawBuild(second) error: %v", err)
	}
	if err := cache.ResolveRawBuild(secondInstruction); err != nil {
		t.Fatalf("ResolveRawBuild(second empty) retained stale refs: %v", err)
	}
	if err := cache.AppendRawBuild(secondInstruction, relativeSource, relativeLowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild(second) error: %v", err)
	}
	if err := cache.ResolveRawBuild(secondInstruction); err == nil {
		t.Fatal("ResolveRawBuild(second) unexpectedly succeeded with no label definition")
	}
}

func TestDisassemblyCacheResolveRawBuildPatchesOwnedPoolOnly(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x8710}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(13)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	lowered[0].Inputs[0].Offset = 0x44
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("unexpected resolved relative offset: got %d want 1", got)
	}
	if got := lowered[0].Inputs[0].Offset; got != 0x44 {
		t.Fatalf("caller-lowered input unexpectedly patched in-place: got 0x%x want 0x44", got)
	}
}

func TestSleighBuilderCacheOwnedRawEmissionResolvesRelativeLabel(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x8800}
	cache := NewDisassemblyCache()
	runtime := RuntimeContext{
		Instruction:   instruction,
		CurrentSpace:  ram,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{
			int64(ram.Index):        ram,
			int64(constSpace.Index): constSpace,
		},
	}
	b := NewSleighBuilder(runtime, 9, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			ctx := LoweringContext{
				Instruction:   state.Runtime.Instruction,
				CurrentSpace:  state.Runtime.CurrentSpace,
				ConstantSpace: state.Runtime.ConstantSpace,
				SpacesByIndex: state.Runtime.SpacesByIndex,
			}
			return lowerOpTpl(op, ctx, state.SectionID, order)
		},
	})
	b.State.SetDisassemblyCache(cache)

	construct := ConstructTplBoundary{
		NumLabels: 1,
		Ops: []OpTplBoundary{
			{
				OpcodeID: int64(pcode.CPUI_BRANCH),
				Opcode:   pcode.CPUI_BRANCH.String(),
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constSpace.Index)},
					Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 1},
				}},
			},
			{
				OpcodeID: int64(pcode.CPUI_PTRADD),
				Opcode:   "LABELBUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
				}},
			},
		},
	}

	if err := b.Build(construct, -1); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if got := b.Pcode.rawBuildDepth; got != 0 {
		t.Fatalf("unexpected raw build depth after Build(): got %d want 0", got)
	}
	emitted, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing cache-owned builder emission")
	}
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("unexpected relative label patch: got %d want 1", got)
	}
	emitted[0].Inputs[0].Offset = 0xdead
	again, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing cache-owned builder emission on second read")
	}
	if got := again[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("cache-owned builder emission was mutated by caller: got %d want 1", got)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after commit")
	}
}

func TestSleighBuilderCacheOwnedRawEmissionCleansStagingOnResolveError(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x9900}
	cache := NewDisassemblyCache()
	runtime := RuntimeContext{
		Instruction:   instruction,
		CurrentSpace:  ram,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{
			int64(ram.Index):        ram,
			int64(constSpace.Index): constSpace,
		},
	}
	b := NewSleighBuilder(runtime, 3, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			ctx := LoweringContext{
				Instruction:   state.Runtime.Instruction,
				CurrentSpace:  state.Runtime.CurrentSpace,
				ConstantSpace: state.Runtime.ConstantSpace,
				SpacesByIndex: state.Runtime.SpacesByIndex,
			}
			return lowerOpTpl(op, ctx, state.SectionID, order)
		},
	})
	b.State.SetDisassemblyCache(cache)

	construct := ConstructTplBoundary{
		NumLabels: 0,
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_BRANCH),
			Opcode:   pcode.CPUI_BRANCH.String(),
			Inputs: []VarnodeTplBoundary{{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(constSpace.Index)},
				Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 1},
			}},
		}},
	}

	err := b.Build(construct, -1)
	if err == nil {
		t.Fatal("Build() returned nil for unresolved cache-owned relative label")
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() returned committed ops after resolve failure")
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not canceled after resolve failure")
	}
}

func TestDisassemblyCacheEmitRawBuildToRequiresResolvedPhaseForRelativeLabels(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xaa00}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(5)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	err := cache.EmitRawBuildTo(instruction, &captureRawEmitter{})
	if !errors.Is(err, ErrRawBuildUnresolved) {
		t.Fatalf("EmitRawBuildTo() unresolved error mismatch: got %v", err)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() unexpectedly contains committed ops after unresolved EmitRawBuildTo()")
	}
	if got, rawErr := cache.RawBuildLength(instruction); rawErr != nil || got != 1 {
		t.Fatalf("staging was not preserved after unresolved EmitRawBuildTo(): len=%d err=%v", got, rawErr)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("EmitRawBuildTo() resolved relative reference mismatch: got %d want 1", got)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed by EmitRawBuildTo()")
	}
}

func TestDisassemblyCacheResolveRawBuildThenEmitRawBuildTo(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xab00}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(7)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() error: %v", err)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("ResolveRawBuild() unexpectedly emitted cached raw ops")
	}
	if got, err := cache.RawBuildLength(instruction); err != nil || got != 1 {
		t.Fatalf("ResolveRawBuild() did not preserve staging length: len=%d err=%v", got, err)
	}
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("unexpected resolved relative offset: got %d want 1", got)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after resolve+emit")
	}
}

func TestSleighBuilderLeaveRawBuildResolveThenEmit(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xac00}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(4)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}

	b := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return nil, nil
		},
	})
	b.State.SetDisassemblyCache(cache)
	b.Pcode.rawInstruction = instruction
	b.Pcode.rawBuildDepth = 1

	if err := b.leaveRawBuild(true, nil); err != nil {
		t.Fatalf("leaveRawBuild() error: %v", err)
	}
	if got := b.Pcode.rawBuildDepth; got != 0 {
		t.Fatalf("unexpected raw build depth after leaveRawBuild(): got %d want 0", got)
	}
	emitted, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing cache-owned builder emission after leaveRawBuild")
	}
	if len(emitted) != 1 {
		t.Fatalf("unexpected emitted op count: got %d want 1", len(emitted))
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("unexpected relative label patch after leaveRawBuild: got %d want 1", got)
	}
	emitted[0].Inputs[0].Offset = 0xbeef
	again, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing cache-owned builder emission after leaveRawBuild second read")
	}
	if got := again[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("cache-owned builder emission after leaveRawBuild was mutated by caller: got %d want 1", got)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after leaveRawBuild resolve+emit")
	}
}

func TestSleighBuilderLeaveRawBuildResolveThenEmitToHookSink(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xac10}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(6)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	capture := &builderCaptureRawEmitter{}
	b := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return nil, nil
		},
		RawEmitter: capture,
	})
	b.State.SetDisassemblyCache(cache)
	b.Pcode.rawInstruction = instruction
	b.Pcode.rawBuildDepth = 1

	if err := b.leaveRawBuild(true, nil); err != nil {
		t.Fatalf("leaveRawBuild() error: %v", err)
	}
	got := capture.Ops()
	if len(got) != 1 || len(got[0].Inputs) != 1 || got[0].Inputs[0].Offset != 1 {
		t.Fatalf("hook sink emission mismatch after leaveRawBuild: %+v", got)
	}
	got[0].Inputs[0].Offset = 0xbeef
	stored, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing cache-owned builder emission after hook sink path")
	}
	if len(stored) != 1 || len(stored[0].Inputs) != 1 || stored[0].Inputs[0].Offset != 1 {
		t.Fatalf("cache-owned builder emission mismatch after hook sink path: %+v", stored)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after leaveRawBuild resolve+emit hook sink path")
	}
}

func TestSleighBuilderLeaveRawBuildCancelsOnHookSinkError(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0xac20}
	cache := NewDisassemblyCache()
	if err := cache.BeginRawBuild(instruction, 1); err != nil {
		t.Fatalf("BeginRawBuild() error: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{Space: constSpace, Offset: 0, Size: 1}},
	}}
	const labelBase = uint64(8)
	if err := cache.AppendRawBuild(instruction, source, lowered, labelBase); err != nil {
		t.Fatalf("AppendRawBuild() error: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, labelBase); err != nil {
		t.Fatalf("AddRawBuildLabel() error: %v", err)
	}
	sinkErr := errors.New("sink failure")
	capture := &builderCaptureRawEmitter{err: sinkErr}
	b := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return nil, nil
		},
		RawEmitter: capture,
	})
	b.State.SetDisassemblyCache(cache)
	b.Pcode.rawInstruction = instruction
	b.Pcode.rawBuildDepth = 1

	err := b.leaveRawBuild(true, nil)
	if !errors.Is(err, sinkErr) {
		t.Fatalf("leaveRawBuild() error mismatch: got %v want %v", err, sinkErr)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() returned committed ops after hook sink failure")
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not canceled after hook sink failure")
	}
}

func TestSleighBuilderCacheOwnedRawEmissionCancelsOnLowerRawFailure(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0xad00}
	cache := NewDisassemblyCache()
	lowerErr := errors.New("lower failure")
	b := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return nil, lowerErr
		},
	})
	b.State.SetDisassemblyCache(cache)
	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
		}},
	}

	err := b.Build(construct, -1)
	if !errors.Is(err, lowerErr) {
		t.Fatalf("Build() error mismatch: got %v want %v", err, lowerErr)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("GetRawOps() returned committed ops after lower failure")
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not canceled after lower failure")
	}
}

func TestSleighBuilderAppendCrossBuildInfraErrorIsPlain(t *testing.T) {
	// Mirrors C++ parity: infrastructure failures in appendCrossBuild are
	// LowlevelError (not UnimplError) and must NOT be rewritten by
	// wrapTranslateUnimplError.
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	err := b.AppendCrossBuild(OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_PTRSUB),
		Opcode:   "CROSSBUILD",
		Inputs: []VarnodeTplBoundary{
			{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			},
			{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			},
		},
	}, -1)
	if err == nil {
		t.Fatal("AppendCrossBuild() returned nil, want error")
	}
	var uerr *UnimplError
	if errors.As(err, &uerr) {
		t.Fatalf("AppendCrossBuild() infrastructure error should not be *UnimplError, got %v", err)
	}
}

func TestSleighBuilderResolveBuildNamedSectionWithoutWalkerReturnsTypedUnimpl(t *testing.T) {
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{
		ResolveBuild: func(op OpTplBoundary, operandIndex int64, sectionID int64, state BuilderState) (*ConstructTplBoundary, int64, bool, error) {
			return nil, 7, false, nil
		},
	})
	err := b.AppendBuild(OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
		Opcode:   "BUILD",
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
		}},
	}, -1)
	if err == nil {
		t.Fatal("AppendBuild() returned nil for named-section ResolveBuild fallback without walker state")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("AppendBuild() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("AppendBuild() error type = %T, want *UnimplError", err)
	}
	if uerr.Explain == "" {
		t.Fatal("AppendBuild() returned typed unimplemented error without explain text")
	}
}

func TestSleighBuilderDelaySlotInfraErrorIsPlain(t *testing.T) {
	// Mirrors C++ parity: infrastructure failures in delaySlot are
	// LowlevelError (not UnimplError) and must NOT be rewritten by
	// wrapTranslateUnimplError.
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	err := b.DelaySlot(OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_INDIRECT),
		Opcode:   "DELAY_SLOT",
	})
	if err == nil {
		t.Fatal("DelaySlot() returned nil, want error")
	}
	var uerr *UnimplError
	if errors.As(err, &uerr) {
		t.Fatalf("DelaySlot() infrastructure error should not be *UnimplError, got %v", err)
	}
}
