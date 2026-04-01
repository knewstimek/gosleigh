package sla

import (
	"testing"

	"gosleigh/pkg/address"
)

func TestParserWalkerChangeResetsAndAllocatesOperands(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x401000}, nil)
	walker := NewParserWalker(ctx)
	walker.BaseState()

	change := NewParserWalkerChange(walker)
	child, err := change.AllocateOperand(0)
	if err != nil {
		t.Fatalf("AllocateOperand() error: %v", err)
	}
	if child == nil || child.Parent != ctx.BaseState || child.OperandIndex != 0 {
		t.Fatalf("unexpected allocated child: %+v", child)
	}

	if err := change.SetOffset(0x20); err != nil {
		t.Fatalf("SetOffset() error: %v", err)
	}
	if err := change.SetCurrentLength(4); err != nil {
		t.Fatalf("SetCurrentLength() error: %v", err)
	}
	if err := change.SetConstructor(ConstructorBoundary{ConstructorID: 7}); err != nil {
		t.Fatalf("SetConstructor() error: %v", err)
	}
	if child.Offset != 0x20 || child.Length != 4 || child.ConstructorID != 7 {
		t.Fatalf("unexpected child mutation: %+v", child)
	}

	if err := change.DeallocateState(); err != nil {
		t.Fatalf("DeallocateState() error: %v", err)
	}
	if walker.Point != ctx.BaseState {
		t.Fatal("expected walker to return to root state")
	}
}

func TestParserWalkerChangeCalcCurrentLengthUsesChildExtent(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x401000}, nil)
	walker := NewParserWalker(ctx)
	walker.BaseState()
	walker.Point.Offset = 1
	walker.Point.Length = 1
	child := walker.Point.EnsureOperand(0)
	child.Offset = 3
	child.Length = 2

	change := NewParserWalkerChange(walker)
	got, err := change.CalcCurrentLength()
	if err != nil {
		t.Fatalf("CalcCurrentLength() error: %v", err)
	}
	if got != 4 {
		t.Fatalf("unexpected calculated length: got %d want 4", got)
	}
}

func TestParserWalkerChangeCommitReservations(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x401000}, nil)
	walker := NewParserWalker(ctx)
	walker.BaseState()
	change := NewParserWalkerChange(walker)
	change.ReserveCommit(ContextCommitBoundary{SymbolID: 7, Number: 3, Mask: 0xff, Flow: true})
	change.ReserveCommit(ContextCommitBoundary{SymbolID: 8, Number: 4, Mask: 0x0f, Flow: false})

	commits := change.CommitReservations()
	if len(commits) != 2 {
		t.Fatalf("unexpected commit count: got %d", len(commits))
	}
	if commits[0].SymbolID != 7 || !commits[0].Flow {
		t.Fatalf("unexpected first commit reservation: %+v", commits[0])
	}
	commits[0].SymbolID = 99
	if change.CommitReservations()[0].SymbolID != 7 {
		t.Fatal("CommitReservations() did not return a copy")
	}

	change.ClearCommitReservations()
	if got := change.CommitReservations(); len(got) != 0 {
		t.Fatalf("expected cleared commit reservations, got %d", len(got))
	}
}
