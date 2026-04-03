package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
)

func newResolveHandlesTestContext() (*ParserContext, *address.Space, *address.Space) {
	cur := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 0, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 1, AddrSize: 8, WordSize: 1}
	ctx := NewParserContext(address.Address{Space: cur, Offset: 0x1000}, constSpace)
	ctx.SetNaddr(address.Address{Space: cur, Offset: 0x1004})
	ctx.SetN2addr(address.Address{Space: cur, Offset: 0x1008})
	ctx.SetRefAddr(address.Address{Space: cur, Offset: 0x2000})
	ctx.SetDestAddr(address.Address{Space: cur, Offset: 0x3000})
	return ctx, cur, constSpace
}

func TestResolveHandlesUsesFixedHandleHook(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	var calls int
	err := ResolveHandles(ctx, ResolveHandlesHooks{
		ResolveFixedHandle: func(walker *ParserWalker) (FixedHandle, bool, error) {
			calls++
			if walker == nil || walker.GetOperand() != 0 {
				t.Fatalf("unexpected walker state: %#v", walker)
			}
			return FixedHandle{Space: curSpace, Size: 4, OffsetOffset: 0x44}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("fixed handle hook called %d times, want 1", calls)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("parser state = %v, want pcode", ctx.GetParserState())
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace {
		t.Fatalf("child handle space = %v, want %v", child.Handle.Space, curSpace)
	}
	if child.Handle.Size != 4 || child.Handle.OffsetOffset != 0x44 {
		t.Fatalf("child handle = %#v, want size=4 offset=0x44", child.Handle)
	}
	if child.Handle.OffsetSpace != nil {
		t.Fatalf("child handle offset space = %v, want nil", child.Handle.OffsetSpace)
	}
}

func TestResolveHandlesUsesExpressionValueHook(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	var calls int
	err := ResolveHandles(ctx, ResolveHandlesHooks{
		ResolveExpressionValue: func(walker *ParserWalker) (uint64, bool, error) {
			calls++
			if walker == nil || walker.GetOperand() != 0 {
				t.Fatalf("unexpected walker state: %#v", walker)
			}
			return 0x1234, true, nil
		},
	})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expression hook called %d times, want 1", calls)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace {
		t.Fatalf("child handle space = %v, want const space", child.Handle.Space)
	}
	if child.Handle.OffsetOffset != 0x1234 || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want const offset 0x1234 and size 0", child.Handle)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("parser state = %v, want pcode", ctx.GetParserState())
	}
}

func TestResolveHandlesUsesOperandBoundaryDefiningExpression(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 1,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:              0,
			DefiningExpression: &PatternExprBoundary{ElementID: elemPlusExp, Attrs: map[uint32]packedAttribute{}, Children: []PatternExprBoundary{patternConst(1), patternConst(2)}},
		}},
	}}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 3 || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want const value 3", child.Handle)
	}
}

func TestResolveHandlesUsesValueMapBoundaryFixedHandle(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemValueMapSymHead,
			Body: SymbolBodyBoundary{Pattern: &PatternSymbolBoundary{
				Expression: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 1)}},
				ValueTable: []int64{0x11, 0x22},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x22 || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want valuemap entry 0x22", child.Handle)
	}
}

func TestResolveHandlesUsesNameBoundaryFixedHandle(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemNameSymHead,
			Body: SymbolBodyBoundary{Pattern: &PatternSymbolBoundary{
				Expression: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 0x2a)}},
				NameTable:  []string{"ignored-for-handle"},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x2a || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want namesymbol value 0x2a in const space", child.Handle)
	}
}

func TestResolveHandlesUsesEpsilonBoundaryFixedHandle(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemEpsilonSymHead,
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0 || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want epsilon fixed handle (const,0,size=0)", child.Handle)
	}
}

func TestResolveHandlesUsesOperandBoundaryFixedHandle(t *testing.T) {
	ctx, curSpace, constSpace := newResolveHandlesTestContext()
	tmpSpace := &address.Space{Name: "tmp", Kind: address.SpaceKindUnique, Index: 9, AddrSize: 8, WordSize: 1}
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemOperandSymHead,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index: 0,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})
	leaf := ctx.BaseState.EnsureOperand(0)
	source := leaf.EnsureOperand(0)
	source.Handle = FixedHandle{
		Space:        curSpace,
		Size:         8,
		OffsetSpace:  constSpace,
		OffsetOffset: 0x4455,
		OffsetSize:   4,
		TempSpace:    tmpSpace,
		TempOffset:   0x77,
	}

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle != source.Handle {
		t.Fatalf("child handle = %#v, want copied operand-symbol handle %#v", child.Handle, source.Handle)
	}
}

func TestResolveHandlesOperandBoundaryMissingHandleReturnsUnimplemented(t *testing.T) {
	ctx, _, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemOperandSymHead,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index: 3,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})
	ctx.BaseState.EnsureOperand(0)

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error for missing operand handle")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain == "" {
		t.Fatalf("expected non-empty unimplemented explain text")
	}
}

func TestResolveHandlesUnsupportedBoundarySymbolFallsBackToHook(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: 999,
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})
	var hookCalls int
	err := ResolveHandles(ctx, ResolveHandlesHooks{
		ResolveFixedHandle: func(walker *ParserWalker) (FixedHandle, bool, error) {
			hookCalls++
			return FixedHandle{Space: curSpace, Size: 4, OffsetOffset: 0x999}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if hookCalls != 1 {
		t.Fatalf("ResolveFixedHandle hook call count = %d, want 1", hookCalls)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace || child.Handle.Size != 4 || child.Handle.OffsetOffset != 0x999 {
		t.Fatalf("child handle = %#v, want hook-provided fixed handle", child.Handle)
	}
}

func TestResolveHandlesUsesBoundaryFlowDestSymbolFixedHandle(t *testing.T) {
	ctx, curSpace, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			Name:          "inst_dest",
			ID:            2,
			HeaderElement: 999,
			BodyElement:   1000,
			Body: SymbolBodyBoundary{
				Opaque: &OpaqueSymbolBody{AttributeCount: 1},
			},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x3000 || child.Handle.Size != uint32(curSpace.AddrSize) {
		t.Fatalf("child handle = %#v, want flowdest fixed handle (const,0x3000,size=%d)", child.Handle, curSpace.AddrSize)
	}
	if child.Handle.OffsetSpace != nil || child.Handle.OffsetSize != 0 || child.Handle.TempSpace != nil || child.Handle.TempOffset != 0 {
		t.Fatalf("child handle = %#v, want static flowdest fixed-handle fields", child.Handle)
	}
}

func TestResolveHandlesUsesBoundaryFlowRefSymbolFixedHandle(t *testing.T) {
	ctx, curSpace, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			Name:          "inst_ref",
			ID:            2,
			HeaderElement: 999,
			BodyElement:   1000,
			Body: SymbolBodyBoundary{
				Opaque: &OpaqueSymbolBody{AttributeCount: 1},
			},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x2000 || child.Handle.Size != uint32(curSpace.AddrSize) {
		t.Fatalf("child handle = %#v, want flowref fixed handle (const,0x2000,size=%d)", child.Handle, curSpace.AddrSize)
	}
	if child.Handle.OffsetSpace != nil || child.Handle.OffsetSize != 0 || child.Handle.TempSpace != nil || child.Handle.TempOffset != 0 {
		t.Fatalf("child handle = %#v, want static flowref fixed-handle fields", child.Handle)
	}
}

func TestResolveHandlesKnownNameSymbolNamedInstDestDoesNotUseFlowHeuristic(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			Name:          "inst_dest",
			ID:            2,
			HeaderElement: elemNameSymHead,
			BodyElement:   elemNameSym,
			Body: SymbolBodyBoundary{Pattern: &PatternSymbolBoundary{
				Expression: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 0x2a)}},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x2a || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want namesymbol fixed handle (const,0x2a,size=0)", child.Handle)
	}
}

func TestResolveHandlesUsesBoundaryVarnodeSymbolFixedHandle(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: int64(curSpace.Index),
				Offset:     0x55,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("parser state = %v, want pcode", ctx.GetParserState())
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace || child.Handle.OffsetOffset != 0x55 || child.Handle.Size != 4 {
		t.Fatalf("child handle = %#v, want static varnode tuple (space,0x55,size=4)", child.Handle)
	}
	if child.Handle.OffsetSpace != nil || child.Handle.OffsetSize != 0 {
		t.Fatalf("child handle = %#v, want non-dynamic static varnode handle", child.Handle)
	}
	if child.Handle.TempSpace != nil || child.Handle.TempOffset != 0 {
		t.Fatalf("child handle = %#v, want cleared temp fields for static varnode handle", child.Handle)
	}
}

func TestResolveHandlesUsesBoundaryVarnodeListSymbolFixedHandle(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemVarListSymHead,
			Body: SymbolBodyBoundary{VarnodeList: &VarnodeListSymbolBoundary{
				Selector: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 1)}},
				Table: []VarnodeListEntryBoundary{
					{HasVarnodeSymbolID: false},
					{HasVarnodeSymbolID: true, VarnodeSymbolID: 3},
				},
			}},
		},
		{
			ID:            3,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: int64(curSpace.Index),
				Offset:     0xaa,
				Size:       8,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace || child.Handle.OffsetOffset != 0xaa || child.Handle.Size != 8 {
		t.Fatalf("child handle = %#v, want static varnodelist-selected varnode tuple", child.Handle)
	}
	if child.Handle.OffsetSpace != nil || child.Handle.TempSpace != nil || child.Handle.OffsetSize != 0 || child.Handle.TempOffset != 0 {
		t.Fatalf("child handle = %#v, want non-dynamic static varnodelist handle", child.Handle)
	}
}

func TestResolveHandlesBoundaryVarnodeSymbolUnknownSpaceReturnsUnimplemented(t *testing.T) {
	ctx, _, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: 99,
				Offset:     0x1234,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error for unknown varnode space index")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "varnode symbol space index 99 is unavailable" {
		t.Fatalf("ResolveHandles unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestResolveHandlesBoundaryVarnodeListNullEntryReturnsUnimplemented(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemVarListSymHead,
			Body: SymbolBodyBoundary{VarnodeList: &VarnodeListSymbolBoundary{
				Selector: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 0)}},
				Table: []VarnodeListEntryBoundary{
					{HasVarnodeSymbolID: false},
					{HasVarnodeSymbolID: true, VarnodeSymbolID: 3},
				},
			}},
		},
		{
			ID:            3,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: int64(curSpace.Index),
				Offset:     0x44,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error for null varnode list entry")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "varnode list entry 0 is null" {
		t.Fatalf("ResolveHandles unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestResolveHandlesBoundaryVarnodeListSelectorOutOfRangeReturnsUnimplemented(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0, HasDefiningSymbolID: true, DefiningSymbolID: 2}},
		},
		{
			ID:            2,
			HeaderElement: elemVarListSymHead,
			Body: SymbolBodyBoundary{VarnodeList: &VarnodeListSymbolBoundary{
				Selector: &PatternExprBoundary{ElementID: elemIntB, Attrs: map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 2)}},
				Table: []VarnodeListEntryBoundary{
					{HasVarnodeSymbolID: true, VarnodeSymbolID: 3},
				},
			}},
		},
		{
			ID:            3,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: int64(curSpace.Index),
				Offset:     0x77,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error for out-of-range varnode list selector")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "varnode list selector index 2 is out of range" {
		t.Fatalf("ResolveHandles unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestResolveHandlesUsesMainSectionResultForPropagation(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	child := ctx.BaseState.EnsureOperand(0)
	child.SetSectionID(7)
	child.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Result: &HandleTplBoundary{
				Space:      ConstBoundary{Kind: ConstKindCurSpace},
				Size:       ConstBoundary{Kind: ConstKindReal, Value: 4},
				PtrSpace:   ConstBoundary{Kind: ConstKindReal, Value: 0},
				PtrOffset:  ConstBoundary{Kind: ConstKindReal, Value: 0x88},
				PtrSize:    ConstBoundary{Kind: ConstKindReal, Value: 0},
				TempSpace:  ConstBoundary{Kind: ConstKindReal, Value: 0},
				TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			},
		},
		NamedSections: []NamedSectionBoundary{
			{
				SectionID: 7,
				Template: ConstructTplBoundary{
					Result: &HandleTplBoundary{
						Space:      ConstBoundary{Kind: ConstKindCurSpace},
						Size:       ConstBoundary{Kind: ConstKindReal, Value: 4},
						PtrSpace:   ConstBoundary{Kind: ConstKindReal, Value: 0},
						PtrOffset:  ConstBoundary{Kind: ConstKindReal, Value: 0x99},
						PtrSize:    ConstBoundary{Kind: ConstKindReal, Value: 0},
						TempSpace:  ConstBoundary{Kind: ConstKindReal, Value: 0},
						TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0},
					},
				},
			},
		},
	})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("parser state = %v, want pcode", ctx.GetParserState())
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace {
		t.Fatalf("child handle space = %v, want %v", child.Handle.Space, curSpace)
	}
	if child.Handle.Size != 4 || child.Handle.OffsetOffset != 0x88 {
		t.Fatalf("child handle = %#v, want size=4 offset=0x88", child.Handle)
	}
}

// Tests that propagateConstructorResult correctly passes child operand handles
// to RuntimeContext.Handles so that HandleTpl::fix() can reference them via
// ConstTpl::handle with v_space/v_offset/v_size selectors.
// Mirrors C++ semantics.cc HandleTpl::fix() -> walker.getFixedHandle(index).
func TestResolveHandlesPropagationReferencesChildHandle(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()

	// Root constructor has one operand (symbol id 1).
	// The operand resolves to a VarnodeSymbol producing a known handle.
	// The root constructor's export (MainSection.Result) references handle 0.
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: int64(curSpace.Index),
				Offset:     0xBB,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		OperandSymbolIDs: []uint64{1},
		MainSection: &ConstructTplBoundary{
			Result: &HandleTplBoundary{
				// Export the child handle's space, offset, size via handle references.
				Space:     ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
				Size:      ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSize},
				PtrSpace:  ConstBoundary{Kind: ConstKindReal, Value: 0},
				PtrOffset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
				PtrSize:   ConstBoundary{Kind: ConstKindReal, Value: 0},
				TempSpace: ConstBoundary{Kind: ConstKindReal, Value: 0},
				TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0},
			},
		},
	})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	// The root handle should now carry the child operand's resolved varnode.
	root := ctx.BaseState.Handle
	if root.Space != curSpace {
		t.Fatalf("root handle space = %v, want %v", root.Space, curSpace)
	}
	if root.OffsetOffset != 0xBB {
		t.Fatalf("root handle offset = %#x, want 0xBB", root.OffsetOffset)
	}
	if root.Size != 4 {
		t.Fatalf("root handle size = %d, want 4", root.Size)
	}
}

func TestResolveHandlesSpacesByIndexUsedForVarnodeSymbol(t *testing.T) {
	ctx, _, _ := newResolveHandlesTestContext()
	regSpace := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 5, AddrSize: 4, WordSize: 1}
	ctx.SpacesByIndex = map[int64]*address.Space{
		5: regSpace,
	}
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemVarnodeSymHead,
			Body: SymbolBodyBoundary{Varnode: &VarnodeSymbolBoundary{
				SpaceIndex: 5,
				Offset:     0x10,
				Size:       4,
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != regSpace || child.Handle.OffsetOffset != 0x10 || child.Handle.Size != 4 {
		t.Fatalf("child handle = %#v, want register varnode (space=register,0x10,size=4)", child.Handle)
	}
}

func TestResolveHandlesMissingHooksReturnsUnimplemented(t *testing.T) {
	ctx, _, _ := newResolveHandlesTestContext()
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "operand 0 has no hook resolution" {
		t.Fatalf("ResolveHandles unimplemented explain mismatch: got %q", uerr.Explain)
	}
	if uerr.HasInstructionLength {
		t.Fatalf("ResolveHandles unimplemented error should not carry instruction length")
	}
	if ctx.GetParserState() == ParseStatePcode {
		t.Fatalf("parser state promoted to pcode on failure")
	}
}

// TestResolveHandlesUsesContextSymbolBoundaryFixedHandle verifies the automatic
// path for ContextSymbol::getFixedHandle() (slghsymbol.cc).
// ContextSymbol inherits ValueSymbol::getFixedHandle: it evaluates its pattern
// expression and returns a constant-space handle with the result as offset.
// The pattern is stored in ContextSymbolBoundary.Pattern (not Body.Pattern).
func TestResolveHandlesUsesContextSymbolBoundaryFixedHandle(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemContextSymHead,
			Body: SymbolBodyBoundary{Context: &ContextSymbolBoundary{
				Low:  0,
				High: 3,
				Flow: false,
				Pattern: &PatternSymbolBoundary{
					// Pattern expression evaluates to 7 (constant).
					// Mirrors ContextSymbol storing its ValueSymbol pattern expression.
					Expression: &PatternExprBoundary{
						ElementID: elemIntB,
						Attrs:     map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 7)},
					},
				},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("parser state = %v, want pcode", ctx.GetParserState())
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	// ContextSymbol::getFixedHandle returns constant-space handle with pattern value as offset.
	if child.Handle.Space != constSpace {
		t.Fatalf("child handle space = %v, want const space", child.Handle.Space)
	}
	if child.Handle.OffsetOffset != 7 {
		t.Fatalf("child handle OffsetOffset = %d, want 7 (pattern constant value)", child.Handle.OffsetOffset)
	}
	if child.Handle.Size != 0 {
		t.Fatalf("child handle Size = %d, want 0 (ValueSymbol::getFixedHandle sets size=0)", child.Handle.Size)
	}
	if child.Handle.OffsetSpace != nil {
		t.Fatalf("child handle OffsetSpace = %v, want nil", child.Handle.OffsetSpace)
	}
}

// TestResolveHandlesContextSymbolNilPatternFallsBackToHook verifies that a
// ContextSymbol with no pattern expression gracefully falls back to the hook
// path rather than panicking. This guards the nil-pattern fallback branch in
// resolveBoundarySymbolFixedHandle for elemContextSymHead.
func TestResolveHandlesContextSymbolNilPatternFallsBackToHook(t *testing.T) {
	ctx, curSpace, _ := newResolveHandlesTestContext()
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemContextSymHead,
			Body: SymbolBodyBoundary{Context: &ContextSymbolBoundary{
				Low:     0,
				High:    3,
				Pattern: nil, // no pattern -- must not panic
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	var hookCalled bool
	err := ResolveHandles(ctx, ResolveHandlesHooks{
		ResolveFixedHandle: func(walker *ParserWalker) (FixedHandle, bool, error) {
			hookCalled = true
			return FixedHandle{Space: curSpace, Size: 4, OffsetOffset: 0xcc}, true, nil
		},
	})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	if !hookCalled {
		t.Fatalf("hook was not called for context symbol with nil pattern")
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != curSpace || child.Handle.Size != 4 || child.Handle.OffsetOffset != 0xcc {
		t.Fatalf("child handle = %#v, want hook-provided fixed handle", child.Handle)
	}
}

// TestResolveHandlesUsesValueMapSymbolPatternAndValueTable verifies the
// automatic path for ValueMapSymbol::getFixedHandle() (slghsymbol.cc).
// ValueMapSymbol evaluates its pattern expression as a selector index and
// returns ValueTable[index] as the constant-space handle offset.
// This test complements TestResolveHandlesUsesValueMapBoundaryFixedHandle by
// exercising explicit pattern + table lookup tracing through the auto path.
func TestResolveHandlesUsesValueMapSymbolPatternAndValueTable(t *testing.T) {
	ctx, _, constSpace := newResolveHandlesTestContext()
	// selector = 0; ValueTable[0] = 0x55
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemValueMapSymHead,
			Body: SymbolBodyBoundary{Pattern: &PatternSymbolBoundary{
				Expression: &PatternExprBoundary{
					ElementID: elemIntB,
					Attrs:     map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 0)},
				},
				ValueTable: []int64{0x55, 0x66, 0x77},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err != nil {
		t.Fatalf("ResolveHandles failed: %v", err)
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok {
		t.Fatalf("child state was not created")
	}
	if child.Handle.Space != constSpace || child.Handle.OffsetOffset != 0x55 || child.Handle.Size != 0 {
		t.Fatalf("child handle = %#v, want valuemap[0]=0x55 in const space", child.Handle)
	}
}

// TestResolveHandlesValueMapOutOfRangeReturnsUnimplemented verifies that when
// the selector evaluates to an out-of-range ValueTable index the result is a
// typed UnimplError rather than a panic or a silent wrong value.
func TestResolveHandlesValueMapOutOfRangeReturnsUnimplemented(t *testing.T) {
	ctx, _, _ := newResolveHandlesTestContext()
	// selector = 5; ValueTable has only 3 entries
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{
		{
			ID: 1,
			Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
				Index:               0,
				HasDefiningSymbolID: true,
				DefiningSymbolID:    2,
			}},
		},
		{
			ID:            2,
			HeaderElement: elemValueMapSymHead,
			Body: SymbolBodyBoundary{Pattern: &PatternSymbolBoundary{
				Expression: &PatternExprBoundary{
					ElementID: elemIntB,
					Attrs:     map[uint32]packedAttribute{attrVal: patternIntAttr(attrVal, 5)},
				},
				ValueTable: []int64{0x11, 0x22, 0x33},
			}},
		},
	}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{1}})

	err := ResolveHandles(ctx, ResolveHandlesHooks{})
	if err == nil {
		t.Fatalf("ResolveHandles succeeded, want unimplemented error for out-of-range valuemap index")
	}
	if !errors.Is(err, ErrResolveHandlesUnimplemented) {
		t.Fatalf("error = %v, want ErrResolveHandlesUnimplemented", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "valuemap index 5 is out of range" {
		t.Fatalf("unimplemented explain = %q, want \"valuemap index 5 is out of range\"", uerr.Explain)
	}
}
