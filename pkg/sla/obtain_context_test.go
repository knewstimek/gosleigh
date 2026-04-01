package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gosleigh/pkg/address"
)

func TestObtainContextCreatesAndCachesParserContext(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	addr := address.Address{Space: ram, Offset: 0x401000}
	cache := NewDisassemblyCache()

	ctx, err := ObtainContext(cache, ObtainContextRequest{
		Address:       addr,
		TargetState:   ParseStateUninitialized,
		ConstantSpace: constSpace,
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if ctx == nil {
		t.Fatal("ObtainContext() returned nil context")
	}
	if got, ok := cache.GetParserContext(addr); !ok || got != ctx {
		t.Fatalf("expected cached parser context, got ok=%v ctx=%p want=%p", ok, got, ctx)
	}
	if ctx.GetParserState() != ParseStateUninitialized {
		t.Fatalf("unexpected parser state: got %d want %d", ctx.GetParserState(), ParseStateUninitialized)
	}
	if ctx.GetConstSpace() != constSpace {
		t.Fatalf("unexpected const space: got %p want %p", ctx.GetConstSpace(), constSpace)
	}
}

func TestObtainContextUsesDisassemblyCacheReusePath(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x401100}
	cache := NewDisassemblyCache()

	resolveCalls := 0
	got, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStateDisassembly,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				resolveCalls++
				ctx.SetParserState(ParseStateDisassembly)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainContext() returned nil parser context")
	}
	if resolveCalls != 1 {
		t.Fatalf("Resolve hook call count = %d, want 1", resolveCalls)
	}

	cached, ok := cache.GetParserContext(addr)
	if !ok || cached != got {
		t.Fatalf("GetParserContext() did not return obtained parser context: ok=%v got=%p want=%p", ok, cached, got)
	}
}

func TestObtainContextPromotesToPcodeWithHooks(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x402000}
	cache := NewDisassemblyCache()
	ctx := NewParserContext(addr, nil)
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	resolveCalled := false
	resolveHandlesCalled := false
	got, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStatePcode,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				resolveCalled = true
				ctx.SetParserState(ParseStateDisassembly)
				return nil
			},
			ResolveHandles: func(ctx *ParserContext) error {
				resolveHandlesCalled = true
				ctx.SetParserState(ParseStatePcode)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("expected cached parser context, got %p want %p", got, ctx)
	}
	if !resolveCalled || !resolveHandlesCalled {
		t.Fatalf("unexpected hook calls: resolve=%v resolveHandles=%v", resolveCalled, resolveHandlesCalled)
	}
	if ctx.GetParserState() != ParseStatePcode {
		t.Fatalf("unexpected parser state: got %d want %d", ctx.GetParserState(), ParseStatePcode)
	}
}

func TestObtainContextReusesExistingSufficientState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x403000}
	cache := NewDisassemblyCache()
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStatePcode)
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	resolveCalled := false
	resolveHandlesCalled := false
	got, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStateDisassembly,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				resolveCalled = true
				return nil
			},
			ResolveHandles: func(ctx *ParserContext) error {
				resolveHandlesCalled = true
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("expected cached parser context, got %p want %p", got, ctx)
	}
	if resolveCalled || resolveHandlesCalled {
		t.Fatalf("expected no promotion hooks for sufficient state: resolve=%v resolveHandles=%v", resolveCalled, resolveHandlesCalled)
	}
}

func TestObtainContextSameAddressReuseDoesNotRePromote(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x403100}
	cache := NewDisassemblyCache()

	resolveCalled := 0
	resolveHandlesCalled := 0
	first, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStatePcode,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				resolveCalled++
				ctx.SetParserState(ParseStateDisassembly)
				return nil
			},
			ResolveHandles: func(ctx *ParserContext) error {
				resolveHandlesCalled++
				ctx.SetParserState(ParseStatePcode)
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("first ObtainContext() error: %v", err)
	}
	second, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStateDisassembly,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				resolveCalled++
				return nil
			},
			ResolveHandles: func(ctx *ParserContext) error {
				resolveHandlesCalled++
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("second ObtainContext() error: %v", err)
	}
	if second != first {
		t.Fatalf("same-address reuse returned different parser context: got=%p want=%p", second, first)
	}
	if resolveCalled != 1 || resolveHandlesCalled != 1 {
		t.Fatalf("unexpected promotion hook calls on same-address reuse: resolve=%d resolveHandles=%d", resolveCalled, resolveHandlesCalled)
	}
}

func TestObtainContextClearsStaleN2OnUninitializedReuse(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x403200}
	cache := NewDisassemblyCache()

	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStateUninitialized)
	ctx.SetN2addr(address.Address{Space: ram, Offset: 0x404000})
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	got, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStateUninitialized,
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("expected cached parser context, got %p want %p", got, ctx)
	}
	if !got.GetN2addr().IsInvalid() {
		t.Fatalf("expected stale n2addr to be cleared for uninitialized reuse, got %v", got.GetN2addr())
	}
}

func TestObtainContextNormalizesMismatchedCachedAddress(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	keyAddr := address.Address{Space: ram, Offset: 0x403300}
	staleAddr := address.Address{Space: ram, Offset: 0x470000}
	cache := NewDisassemblyCache()

	ctx := NewParserContext(staleAddr, nil)
	ctx.SetParserState(ParseStatePcode)
	ctx.SetN2addr(address.Address{Space: ram, Offset: 0x470004})
	if err := cache.SetParserContext(keyAddr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	got, err := ObtainContext(cache, ObtainContextRequest{
		Address:     keyAddr,
		TargetState: ParseStateUninitialized,
	})
	if err != nil {
		t.Fatalf("ObtainContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("expected cached parser context, got %p want %p", got, ctx)
	}
	if got.GetAddr() != keyAddr {
		t.Fatalf("cached parser context address mismatch after normalization: got %v want %v", got.GetAddr(), keyAddr)
	}
	if got.GetParserState() != ParseStateUninitialized {
		t.Fatalf("expected parser state reset to uninitialized for mismatched cache entry, got %d", got.GetParserState())
	}
	if !got.GetN2addr().IsInvalid() {
		t.Fatalf("expected n2addr to be cleared for mismatched cache entry, got %v", got.GetN2addr())
	}
}

func TestObtainContextRejectsMissingPromotionHooks(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x404000}
	cache := NewDisassemblyCache()
	if err := cache.SetParserContext(addr, NewParserContext(addr, nil)); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	_, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStatePcode,
	})
	if err == nil {
		t.Fatal("ObtainContext() returned nil without promotion hooks")
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("ObtainContext() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("ObtainContext() error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "disassembly promotion requires a resolve hook" {
		t.Fatalf("ObtainContext() unimplemented explain mismatch: got %q", uerr.Explain)
	}
	if uerr.HasInstructionLength {
		t.Fatalf("ObtainContext() unimplemented error should not carry instruction length")
	}
}

func TestObtainContextNormalizesResolveSentinelErrorToTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x405000}
	cache := NewDisassemblyCache()

	_, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStateDisassembly,
		Hooks: ObtainContextHooks{
			Resolve: func(ctx *ParserContext) error {
				return fmt.Errorf("%w: resolve parity gap", ErrObtainContextUnimplemented)
			},
		},
	})
	if err == nil {
		t.Fatal("ObtainContext() returned nil for resolve sentinel error")
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("ObtainContext() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("ObtainContext() error type = %T, want *UnimplError", err)
	}
	if !strings.Contains(uerr.Explain, "resolve parity gap") {
		t.Fatalf("ObtainContext() unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestObtainContextNormalizesResolveHandlesSentinelErrorToTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x405100}
	cache := NewDisassemblyCache()

	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStateDisassembly)
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	_, err := ObtainContext(cache, ObtainContextRequest{
		Address:     addr,
		TargetState: ParseStatePcode,
		Hooks: ObtainContextHooks{
			ResolveHandles: func(ctx *ParserContext) error {
				return fmt.Errorf("%w: resolve-handles parity gap", ErrObtainContextUnimplemented)
			},
		},
	})
	if err == nil {
		t.Fatal("ObtainContext() returned nil for resolve-handles sentinel error")
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("ObtainContext() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("ObtainContext() error type = %T, want *UnimplError", err)
	}
	if !strings.Contains(uerr.Explain, "resolve-handles parity gap") {
		t.Fatalf("ObtainContext() unimplemented explain mismatch: got %q", uerr.Explain)
	}
}
