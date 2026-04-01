package sla

import (
	"errors"
	"strings"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestSleighBuilderDelaySlotRecursesCachedParserContexts(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceAddr := address.Address{Space: ram, Offset: 0x4000}
	firstTargetAddr := address.Address{Space: ram, Offset: 0x4004}
	secondTargetAddr := address.Address{Space: ram, Offset: 0x4008}

	sourceCtx := NewParserContext(sourceAddr, nil)
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.SetDelaySlot(8)
	sourceCtx.BaseState.Length = 4
	sourceCtx.BaseState.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
			}},
		},
	})

	firstTarget := NewParserContext(firstTargetAddr, nil)
	firstTarget.SetParserState(ParseStatePcode)
	firstTarget.BaseState.Length = 4
	firstTarget.BaseState.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
			}},
		},
	})

	secondTarget := NewParserContext(secondTargetAddr, nil)
	secondTarget.SetParserState(ParseStatePcode)
	secondTarget.BaseState.Length = 4
	secondTarget.BaseState.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_INT_ADD),
				Opcode:   pcode.CPUI_INT_ADD.String(),
			}},
		},
	})

	cache := NewDisassemblyCache()
	for _, item := range []struct {
		addr address.Address
		ctx  *ParserContext
	}{
		{sourceAddr, sourceCtx},
		{firstTargetAddr, firstTarget},
		{secondTargetAddr, secondTarget},
	} {
		if err := cache.SetParserContext(item.addr, item.ctx); err != nil {
			t.Fatalf("SetParserContext() error: %v", err)
		}
	}

	events := make([]string, 0, 2)
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			events = append(events, op.Opcode)
			return nil
		},
	})
	b.State.SetDisassemblyCache(cache)
	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()
	b.State.Walker = sourceWalker

	construct := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_INDIRECT),
			Opcode:   "DELAY_SLOT",
		}},
	}

	if err := b.Build(construct, -1); err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if len(events) != 2 || events[0] != pcode.CPUI_COPY.String() || events[1] != pcode.CPUI_INT_ADD.String() {
		t.Fatalf("unexpected recursive delay-slot events: %#v", events)
	}
	if b.State.Walker != sourceWalker {
		t.Fatal("expected source walker to be restored after delay-slot recursion")
	}
}

func TestSleighBuilderDelaySlotLeavesInnerWalkerForUnimplRewrite(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceAddr := address.Address{Space: ram, Offset: 0x6000}
	targetAddr := address.Address{Space: ram, Offset: 0x6004}

	sourceCtx := NewParserContext(sourceAddr, nil)
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.SetDelaySlot(4)
	sourceCtx.BaseState.Length = 4
	sourceCtx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "outer"},
			{Text: " "},
			{Text: "slot"},
		},
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_INDIRECT),
				Opcode:   "DELAY_SLOT",
			}},
		},
	})

	targetCtx := NewParserContext(targetAddr, nil)
	targetCtx.SetParserState(ParseStatePcode)
	targetCtx.BaseState.Length = 4
	targetCtx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "inner"},
			{Text: " "},
			{Text: "slot"},
		},
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				Opcode: "BUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
				}},
			}},
		},
	})

	cache := NewDisassemblyCache()
	for _, item := range []struct {
		addr address.Address
		ctx  *ParserContext
	}{
		{sourceAddr, sourceCtx},
		{targetAddr, targetCtx},
	} {
		if err := cache.SetParserContext(item.addr, item.ctx); err != nil {
			t.Fatalf("SetParserContext() error: %v", err)
		}
	}

	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	b.State.SetDisassemblyCache(cache)
	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()
	b.State.Walker = sourceWalker

	err := b.DelaySlot(OpTplBoundary{OpcodeID: int64(pcode.CPUI_INDIRECT), Opcode: "DELAY_SLOT"})
	if err == nil {
		t.Fatal("DelaySlot() unexpectedly succeeded")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("DelaySlot() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	if b.State.Walker == sourceWalker {
		t.Fatal("DelaySlot() restored the outer walker before unimplemented rewrite could inspect the inner state")
	}
	if b.State.Walker == nil || b.State.Walker.ParserContext() != targetCtx {
		t.Fatalf("DelaySlot() walker context mismatch after failure: got %#v want target context", b.State.Walker)
	}

	wrapped := wrapTranslateUnimplError(err, b, 8)
	msg := wrapped.Error()
	if !strings.Contains(msg, "ram:0x6004: inner  slot") {
		t.Fatalf("DelaySlot() rewrite did not use the failing delay-slot walker: %q", msg)
	}
	if strings.Contains(msg, "ram:0x6000: outer  slot") {
		t.Fatalf("DelaySlot() rewrite unexpectedly used the outer walker: %q", msg)
	}
}

func TestSleighBuilderDelaySlotRejectsMissingCachedContext(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceAddr := address.Address{Space: ram, Offset: 0x5000}
	sourceCtx := NewParserContext(sourceAddr, nil)
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.SetDelaySlot(4)
	sourceCtx.BaseState.Length = 4
	sourceCtx.BaseState.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
			}},
		},
	})

	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(sourceAddr, sourceCtx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	b.State.SetDisassemblyCache(cache)
	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()
	b.State.Walker = sourceWalker

	err := b.DelaySlot(OpTplBoundary{OpcodeID: int64(pcode.CPUI_INDIRECT), Opcode: "DELAY_SLOT"})
	if err == nil {
		t.Fatal("DelaySlot() returned nil without cached target contexts")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("DelaySlot() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("DelaySlot() error type = %T, want *UnimplError", err)
	}
}

func TestSleighBuilderDelaySlotRejectsMissingWalkerOrCache(t *testing.T) {
	b := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	err := b.DelaySlot(OpTplBoundary{OpcodeID: int64(pcode.CPUI_INDIRECT), Opcode: "DELAY_SLOT"})
	if err == nil {
		t.Fatal("DelaySlot() returned nil without walker/cache")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("DelaySlot() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("DelaySlot() error type = %T, want *UnimplError", err)
	}
}
