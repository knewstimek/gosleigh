package sla

import (
	"errors"
	"strings"
	"testing"

	"gosleigh/pkg/address"
)

func TestSleighBuilderCrossBuildLeavesInnerWalkerForUnimplRewrite(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	sourceAddr := address.Address{Space: ram, Offset: 0x4000}
	targetAddr := address.Address{Space: ram, Offset: 0x4010}

	sourceCtx := NewParserContext(sourceAddr, nil)
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "outer"},
			{Text: " "},
			{Text: "cross"},
		},
	})
	targetCtx := NewParserContext(targetAddr, nil)
	targetCtx.SetParserState(ParseStatePcode)
	targetCtx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "inner"},
			{Text: " "},
			{Text: "cross"},
		},
		NamedSections: []NamedSectionBoundary{{
			SectionID: 2,
			Template: ConstructTplBoundary{
				Ops: []OpTplBoundary{{
					Opcode: "BUILD",
					Inputs: []VarnodeTplBoundary{{
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
					}},
				}},
			},
		}},
	})

	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(targetAddr, targetCtx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()
	b := NewSleighBuilder(RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{1: ram},
	}, 0, -1, BuilderHooks{})
	b.State.SetDisassemblyCache(cache)
	b.State.Walker = sourceWalker

	op := OpTplBoundary{
		Opcode: "CROSSBUILD",
		Inputs: []VarnodeTplBoundary{
			{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x4010},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 8},
			},
			{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 2},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 8},
			},
		},
	}

	err := b.AppendCrossBuild(op, -1)
	if err == nil {
		t.Fatal("AppendCrossBuild() unexpectedly succeeded")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("AppendCrossBuild() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	if b.State.Walker == sourceWalker {
		t.Fatal("AppendCrossBuild() restored the outer walker before unimplemented rewrite could inspect the inner state")
	}
	if b.State.Walker == nil || b.State.Walker.ParserContext() != targetCtx {
		t.Fatalf("AppendCrossBuild() walker context mismatch after failure: got %#v want target context", b.State.Walker)
	}

	wrapped := wrapTranslateUnimplError(err, b, 4)
	msg := wrapped.Error()
	if !strings.Contains(msg, "ram:0x4000: inner  cross") {
		t.Fatalf("AppendCrossBuild() rewrite did not use the failing crossbuild walker: %q", msg)
	}
	if strings.Contains(msg, "ram:0x4000: outer  cross") {
		t.Fatalf("AppendCrossBuild() rewrite unexpectedly used the outer walker: %q", msg)
	}
}

func TestSleighBuilderCrossBuildRejectsMissingCache(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceCtx := NewParserContext(address.Address{Space: ram, Offset: 0x4000}, nil)
	sourceWalker := NewParserWalker(sourceCtx)
	sourceWalker.BaseState()

	b := NewSleighBuilder(RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1},
		SpacesByIndex: map[int64]*address.Space{1: ram},
	}, 0, -1, BuilderHooks{})
	b.State.Walker = sourceWalker

	op := OpTplBoundary{
		OpcodeID: int64(0),
		Opcode:   "CROSSBUILD",
		Inputs: []VarnodeTplBoundary{
			{
				Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x401000},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 8},
			},
			{
				Offset: ConstBoundary{Kind: ConstKindReal, Value: 2},
				Size:   ConstBoundary{Kind: ConstKindReal, Value: 8},
			},
		},
	}

	err := b.AppendCrossBuild(op, -1)
	if err == nil {
		t.Fatal("AppendCrossBuild() returned nil without a cache")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("AppendCrossBuild() error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("AppendCrossBuild() error type = %T, want *UnimplError", err)
	}
}
