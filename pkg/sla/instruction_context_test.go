package sla

import (
	"errors"
	"fmt"
	"testing"

	"gosleigh/pkg/address"
)

func TestObtainPcodeContextAppliesCommitsAfterCachedPcodeLookup(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x5000}
	cache := NewDisassemblyCache()
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStatePcode)
	ctx.SetContextWords([]uint64{0x34})
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}
	if err := ctx.AddCommit(ContextCommitBoundary{SymbolID: 7, Number: 0, Mask: 0xff, Flow: false}, ctx.BaseState); err != nil {
		t.Fatalf("AddCommit() error: %v", err)
	}

	applied := 0
	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{Address: addr},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return address.Address{Space: ram, Offset: 0x5000}, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				applied++
				if req.Context != ctx {
					t.Fatal("ApplyCommit received unexpected context")
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got != ctx {
		t.Fatalf("ObtainPcodeContext() got %p want %p", got, ctx)
	}
	if applied != 1 {
		t.Fatalf("ApplyCommit count = %d, want 1", applied)
	}
}

func TestObtainPcodeContextPromotesThenAppliesCommits(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x6000}
	cache := NewDisassemblyCache()

	resolveCalled := false
	resolveHandlesCalled := false
	applyCalled := false
	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address: addr,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					resolveCalled = true
					ctx.SetContextWords([]uint64{0x12})
					ctx.SetParserState(ParseStateDisassembly)
					return ctx.AddCommit(ContextCommitBoundary{SymbolID: 3, Number: 0, Mask: 0xff, Flow: true}, ctx.BaseState)
				},
				ResolveHandles: func(ctx *ParserContext) error {
					resolveHandlesCalled = true
					ctx.SetParserState(ParseStatePcode)
					return nil
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return address.Address{Space: ram, Offset: 0x6000}, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				applyCalled = true
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil || got.GetParserState() != ParseStatePcode {
		t.Fatalf("unexpected parser state after ObtainPcodeContext(): %v", got)
	}
	if !resolveCalled || !resolveHandlesCalled || !applyCalled {
		t.Fatalf("unexpected hook calls: resolve=%v resolveHandles=%v apply=%v", resolveCalled, resolveHandlesCalled, applyCalled)
	}
}

func TestObtainPcodeContextCarriesFlowAddressesFromResolve(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x6800}
	cache := NewDisassemblyCache()

	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address:       base,
			ConstantSpace: constSpace,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					_, err := Resolve(ctx, ResolveHooks{
						LoadFill: func(ctx *ParserContext) error {
							ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30, 0x40})
							return nil
						},
						LoadContext: func(ctx *ParserContext) error {
							ctx.SetContextWords([]uint64{0x99})
							return nil
						},
						ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
							if frame.Depth != 0 {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve depth %d", frame.Depth)
							}
							return ResolveOutcome{
								Constructor: &ConstructorBoundary{ConstructorID: 6, MinimumLength: 4},
								Offset:      0,
								Length:      4,
								HasDestAddr: true,
								DestAddr:    address.Address{Space: ram, Offset: 0x6ff0},
							}, nil
						},
					})
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					ctx.SetParserState(ParseStatePcode)
					return nil
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainPcodeContext() returned nil context")
	}
	if got.GetParserState() != ParseStatePcode {
		t.Fatalf("unexpected parser state: got %d want %d", got.GetParserState(), ParseStatePcode)
	}
	if got.GetRefAddr() != (address.Address{Space: ram, Offset: 0x6ff0}) {
		t.Fatalf("unexpected refaddr: got %v want %v", got.GetRefAddr(), address.Address{Space: ram, Offset: 0x6ff0})
	}
	if got.GetDestAddr() != (address.Address{Space: ram, Offset: 0x6ff0}) {
		t.Fatalf("unexpected destaddr: got %v want %v", got.GetDestAddr(), address.Address{Space: ram, Offset: 0x6ff0})
	}
}

func TestObtainPcodeContextRequiresApplyCommitHooks(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	addr := address.Address{Space: ram, Offset: 0x7000}
	cache := NewDisassemblyCache()
	ctx := NewParserContext(addr, nil)
	ctx.SetParserState(ParseStatePcode)
	ctx.SetContextWords([]uint64{1})
	if err := ctx.AddCommit(ContextCommitBoundary{SymbolID: 1, Number: 0, Mask: 1, Flow: true}, ctx.BaseState); err != nil {
		t.Fatalf("AddCommit() error: %v", err)
	}
	if err := cache.SetParserContext(addr, ctx); err != nil {
		t.Fatalf("SetParserContext() error: %v", err)
	}

	_, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{Address: addr},
	})
	if !errors.Is(err, ErrApplyCommitsUnimplemented) {
		t.Fatalf("ObtainPcodeContext() error = %v, want ErrApplyCommitsUnimplemented", err)
	}
}

func TestObtainPcodeContextPrefetchesFallthroughDisassemblyForN2(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x8000}
	cache := NewDisassemblyCache()

	resolveLengths := map[uint64]int{
		0x8000: 4,
		0x8004: 2,
	}
	resolveCalls := map[uint64]int{}
	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address:       base,
			ConstantSpace: constSpace,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					_, err := Resolve(ctx, ResolveHooks{
						LoadFill: func(ctx *ParserContext) error {
							ctx.SetInstructionBytes([]byte{0x11, 0x22, 0x33, 0x44})
							return nil
						},
						LoadContext: func(ctx *ParserContext) error {
							ctx.SetContextWords([]uint64{0x12})
							return nil
						},
						ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
							if frame.Depth != 0 {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve depth %d", frame.Depth)
							}
							length, ok := resolveLengths[frame.Context.GetAddr().Offset]
							if !ok {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve address %v", frame.Context.GetAddr())
							}
								resolveCalls[frame.Context.GetAddr().Offset]++
								return ResolveOutcome{
									Constructor: &ConstructorBoundary{ConstructorID: 1, MinimumLength: int64(length)},
									Offset:      0,
									Length:      length,
								}, nil
						},
					})
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					return ResolveHandles(ctx, ResolveHandlesHooks{})
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainPcodeContext() returned nil context")
	}
	if got.GetNaddr() != (address.Address{Space: ram, Offset: 0x8004}) {
		t.Fatalf("unexpected naddr: got %v want %v", got.GetNaddr(), address.Address{Space: ram, Offset: 0x8004})
	}
	if got.GetN2addr() != (address.Address{Space: ram, Offset: 0x8006}) {
		t.Fatalf("unexpected n2addr: got %v want %v", got.GetN2addr(), address.Address{Space: ram, Offset: 0x8006})
	}
	if resolveCalls[0x8000] != 1 || resolveCalls[0x8004] != 1 {
		t.Fatalf("unexpected resolve calls: base=%d fallthrough=%d", resolveCalls[0x8000], resolveCalls[0x8004])
	}
	nextCtx, ok := cache.GetParserContext(address.Address{Space: ram, Offset: 0x8004})
	if !ok || nextCtx == nil {
		t.Fatal("expected fallthrough parser context to be cached")
	}
	if nextCtx.GetParserState() != ParseStateDisassembly {
		t.Fatalf("unexpected fallthrough parser state: got %d want %d", nextCtx.GetParserState(), ParseStateDisassembly)
	}
}

func TestObtainPcodeContextDerivesN2LazilyFromAdjacentDisassembly(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x8800}
	cache := NewDisassemblyCache()

	resolveLengths := map[uint64]int{
		0x8800: 4,
		0x8804: 2,
	}
	resolveCalls := map[uint64]int{}
	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address:       base,
			ConstantSpace: constSpace,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					_, err := Resolve(ctx, ResolveHooks{
						LoadFill: func(ctx *ParserContext) error {
							ctx.SetInstructionBytes([]byte{0x11, 0x22, 0x33, 0x44})
							return nil
						},
						LoadContext: func(ctx *ParserContext) error {
							ctx.SetContextWords([]uint64{0x12})
							return nil
						},
						ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
							if frame.Depth != 0 {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve depth %d", frame.Depth)
							}
							length, ok := resolveLengths[frame.Context.GetAddr().Offset]
							if !ok {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve address %v", frame.Context.GetAddr())
							}
							resolveCalls[frame.Context.GetAddr().Offset]++
							return ResolveOutcome{
								Constructor: &ConstructorBoundary{ConstructorID: 7, MinimumLength: int64(length)},
								Offset:      0,
								Length:      length,
							}, nil
						},
					})
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					return ResolveHandles(ctx, ResolveHandlesHooks{})
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainPcodeContext() returned nil context")
	}
	if resolveCalls[0x8800] != 1 {
		t.Fatalf("unexpected base resolve calls before n2 read: got %d want 1", resolveCalls[0x8800])
	}
	if resolveCalls[0x8804] != 0 {
		t.Fatalf("fallthrough should not be resolved eagerly before GetN2addr(): got %d want 0", resolveCalls[0x8804])
	}
	if nextCtx, ok := cache.GetParserContext(address.Address{Space: ram, Offset: 0x8804}); ok && nextCtx != nil && nextCtx.GetParserState() >= ParseStateDisassembly {
		t.Fatalf("fallthrough context should not be disassembly-ready before GetN2addr(), state=%d", nextCtx.GetParserState())
	}

	n2 := got.GetN2addr()
	wantN2 := address.Address{Space: ram, Offset: 0x8806}
	if n2 != wantN2 {
		t.Fatalf("unexpected n2addr after lazy derivation: got %v want %v", n2, wantN2)
	}
	if resolveCalls[0x8804] != 1 {
		t.Fatalf("fallthrough resolve should happen lazily on GetN2addr(): got %d want 1", resolveCalls[0x8804])
	}
}

func TestObtainPcodeContextLeavesN2UnsetWhenFallthroughDecodeUnavailable(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x9000}
	cache := NewDisassemblyCache()

	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address: base,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					_, err := Resolve(ctx, ResolveHooks{
						LoadFill: func(ctx *ParserContext) error {
							ctx.SetInstructionBytes([]byte{0xaa, 0xbb, 0xcc, 0xdd})
							return nil
						},
						LoadContext: func(ctx *ParserContext) error {
							ctx.SetContextWords([]uint64{0x34})
							return nil
						},
						ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
							if frame.Depth != 0 {
								return ResolveOutcome{}, fmt.Errorf("unexpected resolve depth %d", frame.Depth)
							}
							if frame.Context.GetAddr() != base {
								return ResolveOutcome{}, fmt.Errorf("missing fallthrough decode source for %v", frame.Context.GetAddr())
							}
							return ResolveOutcome{
								Constructor: &ConstructorBoundary{ConstructorID: 2, MinimumLength: 4},
								Offset:      0,
								Length:      4,
							}, nil
						},
					})
					return err
				},
				ResolveHandles: func(ctx *ParserContext) error {
					return ResolveHandles(ctx, ResolveHandlesHooks{})
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainPcodeContext() returned nil context")
	}
	if !got.GetN2addr().IsInvalid() {
		t.Fatalf("expected unresolved n2addr when fallthrough decode is unavailable, got %v", got.GetN2addr())
	}
	fallthroughAddr := address.Address{Space: ram, Offset: 0x9004}
	if nextCtx, ok := cache.GetParserContext(fallthroughAddr); ok && nextCtx != nil && nextCtx.GetParserState() >= ParseStateDisassembly {
		t.Fatalf("unexpected disassembly-ready fallthrough context in cache: state=%d", nextCtx.GetParserState())
	}
}

func TestObtainPcodeContextPrefetchUsesLengthBasedFallthroughOverStaleNaddr(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0xa000}
	cache := NewDisassemblyCache()

	baseCtx := NewParserContext(base, nil)
	baseCtx.SetParserState(ParseStatePcode)
	baseCtx.BaseState.Length = 4
	baseCtx.SetNaddr(address.Address{Space: ram, Offset: 0xa080}) // stale value from prior translation pass
	baseCtx.SetN2addr(address.Address{Space: ram, Offset: 0xa0f0})
	if err := cache.SetParserContext(base, baseCtx); err != nil {
		t.Fatalf("SetParserContext(base) error: %v", err)
	}

	next := address.Address{Space: ram, Offset: 0xa004}
	nextCtx := NewParserContext(next, nil)
	nextCtx.BaseState.Length = 2
	nextCtx.SetNaddr(address.Address{Space: ram, Offset: 0xa006})
	nextCtx.SetParserState(ParseStateDisassembly)
	if err := cache.SetParserContext(next, nextCtx); err != nil {
		t.Fatalf("SetParserContext(next) error: %v", err)
	}

	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{Address: base},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got != baseCtx {
		t.Fatalf("ObtainPcodeContext() got %p want %p", got, baseCtx)
	}
	wantN2 := address.Address{Space: ram, Offset: 0xa006}
	if got.GetN2addr() != wantN2 {
		t.Fatalf("unexpected n2addr: got %v want %v", got.GetN2addr(), wantN2)
	}
}

func TestObtainPcodeContextClearsStaleN2WhenPrefetchCannotDecodeFallthrough(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0xb000}
	cache := NewDisassemblyCache()

	baseCtx := NewParserContext(base, nil)
	baseCtx.SetParserState(ParseStatePcode)
	baseCtx.BaseState.Length = 4
	baseCtx.SetNaddr(address.Address{Space: ram, Offset: 0xb080})
	baseCtx.SetN2addr(address.Address{Space: ram, Offset: 0xb0f0})
	if err := cache.SetParserContext(base, baseCtx); err != nil {
		t.Fatalf("SetParserContext(base) error: %v", err)
	}

	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{Address: base},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got != baseCtx {
		t.Fatalf("ObtainPcodeContext() got %p want %p", got, baseCtx)
	}
	if !got.GetN2addr().IsInvalid() {
		t.Fatalf("expected stale n2addr to be cleared when fallthrough decode is unavailable, got %v", got.GetN2addr())
	}
}

func TestObtainPcodeContextPrefetchUsesRequestConstantSpaceWhenContextHasNone(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0xc000}
	cache := NewDisassemblyCache()

	baseCtx := NewParserContext(base, nil)
	baseCtx.SetParserState(ParseStatePcode)
	baseCtx.BaseState.Length = 4
	if err := cache.SetParserContext(base, baseCtx); err != nil {
		t.Fatalf("SetParserContext(base) error: %v", err)
	}

	next := address.Address{Space: ram, Offset: 0xc004}
	resolveSeen := false
	got, err := ObtainPcodeContext(cache, ObtainPcodeContextRequest{
		Context: ObtainContextRequest{
			Address:       base,
			ConstantSpace: constSpace,
			Hooks: ObtainContextHooks{
				Resolve: func(ctx *ParserContext) error {
					if ctx.GetAddr() != next {
						return fmt.Errorf("unexpected prefetch resolve address %v", ctx.GetAddr())
					}
					resolveSeen = true
					if ctx.GetConstSpace() != constSpace {
						return fmt.Errorf("prefetch const space mismatch: got %p want %p", ctx.GetConstSpace(), constSpace)
					}
					ctx.BaseState.Length = 2
					ctx.SetParserState(ParseStateDisassembly)
					ctx.SetNaddr(next.Add(2))
					return nil
				},
			},
		},
		Commits: ApplyCommitsHooks{
			ResolveCommitAddress: func(req ResolveCommitAddressRequest) (address.Address, error) {
				return base, nil
			},
			ApplyCommit: func(req ApplyCommitRequest) error {
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got != baseCtx {
		t.Fatalf("ObtainPcodeContext() got %p want %p", got, baseCtx)
	}
	if resolveSeen {
		t.Fatal("expected lazy n2 derivation to defer fallthrough resolve until GetN2addr()")
	}
	wantN2 := address.Address{Space: ram, Offset: 0xc006}
	if got.GetN2addr() != wantN2 {
		t.Fatalf("unexpected n2addr: got %v want %v", got.GetN2addr(), wantN2)
	}
	if !resolveSeen {
		t.Fatal("expected GetN2addr() to trigger lazy fallthrough resolve")
	}
}

func TestObtainPcodeContextPrefetchUsesTranslatePayloadLoaderRoute(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0xd000}
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{
				ConstructorID: 0,
				MinimumLength: 4,
				MainSection: &ConstructTplBoundary{
					Ops: []OpTplBoundary{},
				},
			},
		},
	}
	loaderCalls := map[uint64]int{}
	input := TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls[addr.Offset]++
				switch addr {
				case base:
					return MatchInput{Instruction: []byte{0x11, 0x22, 0x33, 0x44}}, true, nil
				case base.Add(4):
					return MatchInput{Instruction: []byte{0x55, 0x66, 0x77, 0x88}}, true, nil
				default:
					return MatchInput{}, false, nil
				}
			},
		},
		Lowering: LoweringContext{
			Instruction:   base,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
	}

	got, err := ObtainPcodeContext(cache, translatePcodeContextRequest(subtable, input, base))
	if err != nil {
		t.Fatalf("ObtainPcodeContext() error: %v", err)
	}
	if got == nil {
		t.Fatal("ObtainPcodeContext() returned nil context")
	}
	if got.GetParserState() != ParseStatePcode {
		t.Fatalf("unexpected parser state: got %d want %d", got.GetParserState(), ParseStatePcode)
	}
	if got.GetNaddr() != base.Add(4) {
		t.Fatalf("unexpected naddr: got %v want %v", got.GetNaddr(), base.Add(4))
	}
	if got.GetN2addr() != base.Add(8) {
		t.Fatalf("unexpected n2addr: got %v want %v", got.GetN2addr(), base.Add(8))
	}
	if loaderCalls[base.Offset] == 0 {
		t.Fatalf("payload loader did not serve base address %v", base)
	}
	if loaderCalls[base.Add(4).Offset] == 0 {
		t.Fatalf("payload loader did not serve fallthrough address %v", base.Add(4))
	}
	nextCtx, ok := cache.GetParserContext(base.Add(4))
	if !ok || nextCtx == nil {
		t.Fatal("expected fallthrough parser context to be cached")
	}
	if nextCtx.GetParserState() < ParseStateDisassembly {
		t.Fatalf("unexpected fallthrough parser state: got %d want >= %d", nextCtx.GetParserState(), ParseStateDisassembly)
	}
}
