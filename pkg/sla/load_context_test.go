package sla

import (
	"errors"
	"testing"

	"gosleigh/pkg/address"
)

func TestLoadContextStoresLocalWords(t *testing.T) {
	space := testLoadContextSpace("ram", address.SpaceKindProcessor, 4)
	ctx := NewParserContext(address.Address{Space: space, Offset: 0x401000}, nil)
	ctx.SetContextWords([]uint64{1, 2})

	var seenAddr address.Address
	var seenCurrent []uint64
	if err := ctx.LoadContext(LoadContextHooks{
		LoadContextWords: func(addr address.Address, current []uint64) ([]uint64, error) {
			seenAddr = addr
			seenCurrent = append([]uint64(nil), current...)
			current[0] = 0xff
			return []uint64{0x10, 0x20, 0x30}, nil
		},
	}); err != nil {
		t.Fatalf("LoadContext returned error: %v", err)
	}

	if seenAddr != ctx.GetAddr() {
		t.Fatalf("LoadContext address mismatch: got %v want %v", seenAddr, ctx.GetAddr())
	}
	if len(seenCurrent) != 2 || seenCurrent[0] != 1 || seenCurrent[1] != 2 {
		t.Fatalf("LoadContext current words mismatch: got %v", seenCurrent)
	}
	if len(ctx.ContextWords) != 3 || ctx.ContextWords[0] != 0x10 || ctx.ContextWords[2] != 0x30 {
		t.Fatalf("LoadContext stored wrong words: got %v", ctx.ContextWords)
	}
}

func TestAddCommitCapturesMaskedValueAndClear(t *testing.T) {
	space := testLoadContextSpace("ram", address.SpaceKindProcessor, 1)
	ctx := NewParserContext(address.Address{Space: space, Offset: 0x1000}, nil)
	ctx.SetContextWords([]uint64{0xabcd, 0x1234})
	point := NewConstructState()

	if err := ctx.AddCommit(ContextCommitBoundary{
		SymbolID: 7,
		Number:   1,
		Mask:     0x00f0,
		Flow:     true,
	}, point); err != nil {
		t.Fatalf("AddCommit returned error: %v", err)
	}

	commits := ctx.PendingCommits()
	if len(commits) != 1 {
		t.Fatalf("PendingCommits length mismatch: got %d want 1", len(commits))
	}
	commit := commits[0]
	if commit.SymbolID != 7 || commit.Number != 1 || commit.Mask != 0x00f0 || !commit.Flow {
		t.Fatalf("stored commit metadata mismatch: %+v", commit)
	}
	if commit.Value != (0x1234 & 0x00f0) {
		t.Fatalf("stored commit value mismatch: got 0x%x", commit.Value)
	}
	if commit.Point != point {
		t.Fatalf("stored commit point mismatch")
	}

	ctx.ClearCommits()
	if commits := ctx.PendingCommits(); len(commits) != 0 {
		t.Fatalf("ClearCommits left pending commits: %v", commits)
	}
}

func TestApplyCommitsUsesHookBoundaryAndConstantSpaceNormalization(t *testing.T) {
	currentSpace := testLoadContextSpace("ram", address.SpaceKindProcessor, 4)
	constSpace := testLoadContextSpace("const", address.SpaceKindConstant, 1)
	ctx := NewParserContext(address.Address{Space: currentSpace, Offset: 0x2000}, constSpace)
	ctx.SetContextWords([]uint64{0x55, 0x1234})
	point := NewConstructState()

	if err := ctx.AddCommit(ContextCommitBoundary{
		SymbolID: 9,
		Number:   1,
		Mask:     0x00ff,
		Flow:     false,
	}, point); err != nil {
		t.Fatalf("AddCommit returned error: %v", err)
	}

	resolved := 0
	applied := 0
	if err := ctx.ApplyCommits(ApplyCommitsHooks{
		ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
			resolved++
			if req.Context != ctx {
				t.Fatalf("ResolveCommitAddress context mismatch")
			}
			if req.Walker == nil || req.Walker.Point != ctx.BaseState {
				t.Fatalf("ResolveCommitAddress walker not positioned at base state")
			}
			if req.Commit.Point != point {
				t.Fatalf("ResolveCommitAddress point mismatch")
			}
			return address.Address{Space: constSpace, Offset: 3}, nil
		},
		ApplyCommit: func(req ApplyCommitRequest) error {
			applied++
			if req.CommitAddr.Space != currentSpace || req.CommitAddr.Offset != 12 {
				t.Fatalf("normalized commit address mismatch: got %v", req.CommitAddr)
			}
			if !req.HasNext {
				t.Fatalf("ApplyCommit should carry end address for non-flow commit")
			}
			if req.NextAddr.Space != currentSpace || req.NextAddr.Offset != 13 {
				t.Fatalf("next address mismatch: got %v", req.NextAddr)
			}
			if req.Commit.Value != 0x34 {
				t.Fatalf("commit value mismatch: got 0x%x want 0x34", req.Commit.Value)
			}
			if req.Commit.Mask != 0x00ff || req.Commit.Number != 1 || req.Commit.Flow {
				t.Fatalf("commit metadata mismatch: %+v", req.Commit)
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("ApplyCommits returned error: %v", err)
	}
	if resolved != 1 || applied != 1 {
		t.Fatalf("hook counts mismatch: resolved=%d applied=%d", resolved, applied)
	}
}

func TestApplyCommitsUsesOperandPointHandle(t *testing.T) {
	currentSpace := testLoadContextSpace("ram", address.SpaceKindProcessor, 1)
	ctx := NewParserContext(address.Address{Space: currentSpace, Offset: 0x5000}, nil)
	ctx.SetContextWords([]uint64{0x44})
	point := NewConstructState()
	child := point.EnsureOperand(2)
	child.Handle = FixedHandle{Space: currentSpace, OffsetOffset: 0x1234, Size: 4}

	if err := ctx.AddCommit(ContextCommitBoundary{
		SymbolID: 77,
		Number:   0,
		Mask:     0xff,
		Flow:     true,
	}, point); err != nil {
		t.Fatalf("AddCommit returned error: %v", err)
	}

	applied := 0
	if err := ctx.ApplyCommits(ApplyCommitsHooks{
		LookupOperandIndex: func(symbolID uint64) (int, bool) {
			if symbolID != 77 {
				t.Fatalf("unexpected symbol id: %d", symbolID)
			}
			return 2, true
		},
		ApplyCommit: func(req ApplyCommitRequest) error {
			applied++
			if req.CommitAddr.Space != currentSpace || req.CommitAddr.Offset != 0x1234 {
				t.Fatalf("operand commit address mismatch: got %v", req.CommitAddr)
			}
			if req.HasNext {
				t.Fatalf("flow commit should not compute next address")
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("ApplyCommits returned error: %v", err)
	}
	if applied != 1 {
		t.Fatalf("ApplyCommit call count = %d, want 1", applied)
	}
}

func TestApplyCommitsUsesOperandSymbolBoundaryWithoutLookupHook(t *testing.T) {
	currentSpace := testLoadContextSpace("ram", address.SpaceKindProcessor, 1)
	ctx := NewParserContext(address.Address{Space: currentSpace, Offset: 0x3000}, nil)
	ctx.SetContextWords([]uint64{0x44})
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 9,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{Index: 0}},
	}}})
	ctx.BaseState.Children = []*ConstructState{{
		Parent: ctx.BaseState,
		Handle: FixedHandle{Space: currentSpace, OffsetOffset: 0x55},
	}}

	if err := ctx.AddCommit(ContextCommitBoundary{
		SymbolID: 9,
		Number:   0,
		Mask:     0xff,
		Flow:     true,
	}, ctx.BaseState); err != nil {
		t.Fatalf("AddCommit returned error: %v", err)
	}

	applied := 0
	if err := ctx.ApplyCommits(ApplyCommitsHooks{
		ApplyCommit: func(req ApplyCommitRequest) error {
			applied++
			if req.CommitAddr.Space != currentSpace || req.CommitAddr.Offset != 0x55 {
				t.Fatalf("operand-symbol commit address mismatch: got %v", req.CommitAddr)
			}
			if req.HasNext {
				t.Fatal("flow commit should not carry next address")
			}
			return nil
		},
	}); err != nil {
		t.Fatalf("ApplyCommits returned error: %v", err)
	}
	if applied != 1 {
		t.Fatalf("ApplyCommit call count mismatch: got %d want 1", applied)
	}
}

func TestApplyCommitsRequiresHooks(t *testing.T) {
	space := testLoadContextSpace("ram", address.SpaceKindProcessor, 1)
	ctx := NewParserContext(address.Address{Space: space, Offset: 0x3000}, nil)

	applyErr := ctx.ApplyCommits(ApplyCommitsHooks{})
	if !errors.Is(applyErr, ErrApplyCommitsUnimplemented) {
		t.Fatalf("ApplyCommits error mismatch: got %v", applyErr)
	}
	var applyUnimpl *UnimplError
	if !errors.As(applyErr, &applyUnimpl) {
		t.Fatalf("ApplyCommits error type = %T, want *UnimplError", applyErr)
	}
	if applyUnimpl.Explain != "commit address resolution is nil" {
		t.Fatalf("ApplyCommits unimplemented explain mismatch: got %q", applyUnimpl.Explain)
	}

	loadErr := ctx.LoadContext(LoadContextHooks{})
	if !errors.Is(loadErr, ErrLoadContextUnimplemented) {
		t.Fatalf("LoadContext error mismatch: got %v", loadErr)
	}
	var loadUnimpl *UnimplError
	if !errors.As(loadErr, &loadUnimpl) {
		t.Fatalf("LoadContext error type = %T, want *UnimplError", loadErr)
	}
	if loadUnimpl.Explain != "load hook is nil" {
		t.Fatalf("LoadContext unimplemented explain mismatch: got %q", loadUnimpl.Explain)
	}
}

func testLoadContextSpace(name string, kind address.SpaceKind, wordSize uint8) *address.Space {
	return &address.Space{
		Name:      name,
		Kind:      kind,
		Index:     1,
		AddrSize:  8,
		WordSize:  wordSize,
		BigEndian: false,
		Physical:  true,
	}
}
