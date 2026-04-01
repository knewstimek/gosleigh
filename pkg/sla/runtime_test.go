package sla

import (
	"testing"

	"gosleigh/pkg/address"
)

func TestResolveHandleTplPreservesDynamicOffsetForUnstarredExport(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 4, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 4, AddrSize: 8, WordSize: 1},
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: unique},
		Handles: []FixedHandle{{
			Space:        ram,
			Size:         4,
			OffsetSpace:  register,
			OffsetOffset: 0x44,
			OffsetSize:   8,
			TempSpace:    unique,
			TempOffset:   0x200,
		}},
	}
	tpl := HandleTplBoundary{
		Space:     ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Size:      ConstBoundary{Kind: ConstKindReal, Value: 4},
		PtrSpace:  ConstBoundary{Kind: ConstKindReal, Value: 0},
		PtrOffset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
	}

	hand, err := ResolveHandleTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("ResolveHandleTpl() error: %v", err)
	}
	if hand.Space != ram || hand.Size != 4 {
		t.Fatalf("unexpected resolved handle header: %+v", hand)
	}
	if hand.OffsetSpace != register || hand.OffsetOffset != 0x44 || hand.OffsetSize != 8 {
		t.Fatalf("unexpected dynamic pointer fields: %+v", hand)
	}
	if hand.TempSpace != unique || hand.TempOffset != 0x200 {
		t.Fatalf("unexpected dynamic temp fields: %+v", hand)
	}
}

func TestResolveHandleTplCollapsesConstantPointerToStaticOffset(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 4, WordSize: 4, Physical: true}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: constant, 3: unique},
	}
	tpl := HandleTplBoundary{
		Space:      ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
		Size:       ConstBoundary{Kind: ConstKindReal, Value: 4},
		PtrSpace:   ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
		PtrOffset:  ConstBoundary{Kind: ConstKindReal, Value: 0x20},
		PtrSize:    ConstBoundary{Kind: ConstKindReal, Value: 8},
		TempSpace:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
		TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0x300},
	}

	hand, err := ResolveHandleTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("ResolveHandleTpl() error: %v", err)
	}
	if hand.OffsetSpace != nil {
		t.Fatalf("expected static offset, got dynamic handle: %+v", hand)
	}
	if hand.OffsetOffset != 0x80 {
		t.Fatalf("unexpected collapsed byte offset: got 0x%x", hand.OffsetOffset)
	}
	if hand.TempSpace != nil || hand.TempOffset != 0 {
		t.Fatalf("unexpected temp storage on collapsed handle: %+v", hand)
	}
}

func TestResolveHandleTplKeepsDynamicPointerStateForStarredExport(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 4, WordSize: 1, Physical: true}
	register := &address.Space{Name: "register", Kind: address.SpaceKindProcessor, Index: 2, AddrSize: 8, WordSize: 1}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 4, AddrSize: 8, WordSize: 1},
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: register, 3: unique},
	}
	tpl := HandleTplBoundary{
		Space:      ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
		Size:       ConstBoundary{Kind: ConstKindReal, Value: 4},
		PtrSpace:   ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
		PtrOffset:  ConstBoundary{Kind: ConstKindReal, Value: 0x44},
		PtrSize:    ConstBoundary{Kind: ConstKindReal, Value: 8},
		TempSpace:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
		TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0x200},
	}

	hand, err := ResolveHandleTpl(tpl, ctx)
	if err != nil {
		t.Fatalf("ResolveHandleTpl() error: %v", err)
	}
	if hand.Space != ram || hand.OffsetSpace != register || hand.OffsetOffset != 0x44 {
		t.Fatalf("unexpected dynamic handle target: %+v", hand)
	}
	if hand.OffsetSize != 8 || hand.TempSpace != unique || hand.TempOffset != 0x200 {
		t.Fatalf("unexpected dynamic handle runtime storage: %+v", hand)
	}
}

func TestPropagateConstructorResultWritesParentHandle(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 4, WordSize: 1, Physical: true}
	constant := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	parent := FixedHandle{}
	ctx := RuntimeContext{
		CurrentSpace:  ram,
		ConstantSpace: constant,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: constant},
		ParentHandle:  &parent,
	}
	tpl := ConstructTplBoundary{
		Result: &HandleTplBoundary{
			Space:     ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
			Size:      ConstBoundary{Kind: ConstKindReal, Value: 4},
			PtrSpace:  ConstBoundary{Kind: ConstKindReal, Value: 0},
			PtrOffset: ConstBoundary{Kind: ConstKindReal, Value: 0x88},
		},
	}

	if err := PropagateConstructorResult(tpl, &ctx); err != nil {
		t.Fatalf("PropagateConstructorResult() error: %v", err)
	}
	if parent.Space != ram || parent.Size != 4 || parent.OffsetSpace != nil || parent.OffsetOffset != 0x88 {
		t.Fatalf("unexpected propagated parent handle: %+v", parent)
	}
}
