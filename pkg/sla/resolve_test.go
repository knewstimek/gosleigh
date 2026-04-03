package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
)

func TestResolveRejectsNilContext(t *testing.T) {
	if _, err := Resolve(nil, ResolveHooks{}); err == nil {
		t.Fatal("Resolve() accepted nil context")
	}
}

func TestResolveBuildsShellStateAndReservations(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, constSpace)
	ctx.SetContextWords([]uint64{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc})
	ctx.SetDelaySlot(7)
	ctx.SetParserState(ParseStatePcode)
	ctx.BaseState = NewConstructState()
	ctx.BaseState.Length = 99
	ctx.BaseState.Children = []*ConstructState{{ConstructorID: 77, Parent: ctx.BaseState, OperandIndex: 0}}

	fillCalled := false
	loadContextCalled := false
	rootCalled := false
	childCalled := false

	result, err := Resolve(ctx, ResolveHooks{
		LoadFill: func(ctx *ParserContext) error {
			fillCalled = true
			ctx.SetInstructionBytes([]byte{0x11, 0x22, 0x33, 0x44})
			return nil
		},
		LoadContext: func(ctx *ParserContext) error {
			loadContextCalled = true
			ctx.SetContextWords([]uint64{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
			return nil
		},
		ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
			switch frame.Depth {
			case 0:
				rootCalled = true
					return ResolveOutcome{
						Constructor: &ConstructorBoundary{
							ConstructorID:    10,
							MinimumLength:    4,
							ContextCommits:   []ContextCommitBoundary{{SymbolID: 1, Number: 2, Mask: 3, Flow: true}},
							OperandSymbolIDs: []uint64{11},
						},
						Offset:     0,
						Length:     4,
						DelaySlot:  3,
						Commits:    []ContextCommitBoundary{{SymbolID: 4, Number: 5, Mask: 6, Flow: false}},
						HasRefAddr: true,
						RefAddr:    address.Address{Space: ram, Offset: 0x4444},
					}, nil
				case 1:
					childCalled = true
				return ResolveOutcome{
					Constructor: &ConstructorBoundary{
						ConstructorID: 20,
						MinimumLength: 1,
					},
					Offset: 4,
					Length: 1,
				}, nil
			default:
				return ResolveOutcome{}, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if !fillCalled {
		t.Fatal("Resolve() did not call fill hook")
	}
	if !loadContextCalled {
		t.Fatal("Resolve() did not call load context hook")
	}
	if !rootCalled || !childCalled {
		t.Fatalf("Resolve() did not call resolve hook for both depths: root=%v child=%v", rootCalled, childCalled)
	}
	if ctx.GetParserState() != ParseStateDisassembly {
		t.Fatalf("Resolve() parser state = %v, want disassembly", ctx.GetParserState())
	}
	if ctx.GetDelaySlot() != 3 {
		t.Fatalf("Resolve() delay slot = %d, want 3", ctx.GetDelaySlot())
	}
	if ctx.GetLength() != 4 {
		t.Fatalf("Resolve() length = %d, want 4", ctx.GetLength())
	}
	if got := ctx.GetNaddr(); got != ctx.GetAddr().Add(4) {
		t.Fatalf("Resolve() naddr = %v, want %v", got, ctx.GetAddr().Add(4))
	}
	if got := ctx.GetRefAddr(); got != (address.Address{Space: ram, Offset: 0x4444}) {
		t.Fatalf("Resolve() refaddr = %v, want %v", got, address.Address{Space: ram, Offset: 0x4444})
	}
	if got := ctx.GetDestAddr(); got != (address.Address{Space: ram, Offset: 0x4444}) {
		t.Fatalf("Resolve() destaddr = %v, want %v", got, address.Address{Space: ram, Offset: 0x4444})
	}
	if result == nil || result.Walker == nil {
		t.Fatal("Resolve() did not return walker state")
	}
	if len(result.CommitReservations) != 2 {
		t.Fatalf("Resolve() reservations = %d, want 2", len(result.CommitReservations))
	}
	if commits := ctx.PendingCommits(); len(commits) != 2 {
		t.Fatalf("Resolve() queued commits = %d, want 2", len(commits))
	} else {
		if commits[0].Number != 2 || commits[0].Value != 0 {
			t.Fatalf("unexpected first queued commit: %+v", commits[0])
		}
		if commits[1].Number != 5 || commits[1].Value != 6 {
			t.Fatalf("unexpected second queued commit: %+v", commits[1])
		}
	}
	if commits := ctx.PendingCommits(); len(commits) != 2 {
		t.Fatalf("Resolve() pending commits = %d, want 2", len(commits))
	}
	if got := ctx.BaseState.ConstructorID; got != 10 {
		t.Fatalf("root constructor id = %d, want 10", got)
	}
	if len(ctx.BaseState.Children) != 1 {
		t.Fatalf("root child count = %d, want 1", len(ctx.BaseState.Children))
	}
	if got := ctx.BaseState.Children[0].ConstructorID; got != 20 {
		t.Fatalf("child constructor id = %d, want 20", got)
	}
}

func TestResolveOutcomeCanSplitRefAndDestAddresses(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1100}, constSpace)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30, 0x40})
	ctx.SetContextWords([]uint64{0x01})

	_, err := Resolve(ctx, ResolveHooks{
		ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
			if frame.Depth != 0 {
				return ResolveOutcome{}, nil
			}
			return ResolveOutcome{
				Constructor: &ConstructorBoundary{ConstructorID: 1, MinimumLength: 4},
				Length:      4,
				HasRefAddr:  true,
				RefAddr:     address.Address{Space: ram, Offset: 0x2200},
				HasDestAddr: true,
				DestAddr:    address.Address{Space: ram, Offset: 0x3300},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if got := ctx.GetRefAddr(); got != (address.Address{Space: ram, Offset: 0x2200}) {
		t.Fatalf("Resolve() split refaddr = %v, want %v", got, address.Address{Space: ram, Offset: 0x2200})
	}
	if got := ctx.GetDestAddr(); got != (address.Address{Space: ram, Offset: 0x3300}) {
		t.Fatalf("Resolve() split destaddr = %v, want %v", got, address.Address{Space: ram, Offset: 0x3300})
	}
}

// TestResolveLeafOperandOffset is a regression test for the bug where leaf
// operand ConstructState entries were allocated without initializing their
// Offset field, causing token-field evaluation (getPatternInstructionBytes) to
// always read from byte 0 (the opcode) instead of the correct
// instruction-relative offset.
//
// C++ reference: Sleigh::resolve() sets walker.setOffset(off) immediately after
// pos.allocateOperand(), where off = walker.getOffset(sym->getOffsetBase()) +
// sym->getRelativeOffset(). This must happen for leaf (non-subtable) operands
// as well as subtable operands.
func TestResolveLeafOperandOffset(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}

	// Simulate a 2-byte instruction: opcode at byte 0, immediate at byte 1.
	// The root constructor has one operand with OffsetBase=-1 (constructor-relative)
	// and RelativeOffset=1 (byte 1), MinimumLength=1.
	// The leaf operand returns nil Constructor (no subtable).
	rootCtor := &ConstructorBoundary{
		ConstructorID: 42,
		MinimumLength: 2,
		OperandSymbolIDs: []uint64{100},
	}
	leafSym := &OperandSymbolBoundary{
		Index:          0,
		OffsetBase:     -1, // constructor-relative
		RelativeOffset: 1,  // byte 1 = immediate field
		MinimumLength:  1,
	}
	symTable := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   100,
				Name: "imm",
				Body: SymbolBodyBoundary{Operand: leafSym},
			},
		},
	}

	ctx := NewParserContext(address.Address{Space: ram, Offset: 0}, constSpace)
	ctx.SetSymbolTable(symTable)
	ctx.SetInstructionBytes([]byte{0xA9, 0x42}) // opcode, immediate

	var leafState *ConstructState
	_, err := Resolve(ctx, ResolveHooks{
		ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
			if frame.Depth == 0 {
				return ResolveOutcome{
					Constructor: rootCtor,
					Offset:      0,
					Length:      2,
				}, nil
			}
			// Leaf operand: record state for inspection, return no subtable.
			leafState = frame.State
			return ResolveOutcome{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if leafState == nil {
		t.Fatal("leaf operand frame.State was not captured")
	}
	// The leaf ConstructState must carry Offset=1 (byte 1, the immediate field),
	// not 0 (the opcode byte). If this is 0, token-field evaluation reads 0xA9
	// instead of 0x42.
	if leafState.Offset != 1 {
		t.Errorf("leaf operand Offset = %d, want 1 (immediate byte); got opcode byte instead", leafState.Offset)
	}
	if leafState.Length != 1 {
		t.Errorf("leaf operand Length = %d, want 1 (MinimumLength)", leafState.Length)
	}
}

func TestResolveRequiresSymbolHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x2000}, nil)
	_, err := Resolve(ctx, ResolveHooks{})
	if err == nil {
		t.Fatal("Resolve() accepted missing symbol hook")
	}
	if !errors.Is(err, ErrResolveUnimplemented) {
		t.Fatalf("Resolve() error does not wrap ErrResolveUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("Resolve() error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "resolve symbol hook" {
		t.Fatalf("Resolve() unimplemented explain mismatch: got %q", uerr.Explain)
	}
	if uerr.HasInstructionLength {
		t.Fatalf("Resolve() unimplemented error should not carry instruction length")
	}
}
