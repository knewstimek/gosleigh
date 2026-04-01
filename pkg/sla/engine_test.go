package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestEngineTranslateInstructionAtUsesBackendAddressLoader(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x401000}

	subtable := testEngineCopySubtable()
	loaderCalls := map[uint64]int{}
	engine, err := NewEngine(EngineConfig{
		Symbols: testEngineSymbolTableWithStandardRoot(subtable),
		LoweringTemplate: LoweringContext{
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls[addr.Offset]++
				switch addr {
				case base:
					return MatchInput{Instruction: []byte{0x10, 0x20, 0x30, 0x40}}, true, nil
				case base.Add(4):
					return MatchInput{Instruction: []byte{0x50, 0x60, 0x70, 0x80}}, true, nil
				default:
					return MatchInput{}, false, nil
				}
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() returned unexpected error: %v", err)
	}

	got, err := engine.TranslateInstructionAt(base)
	if err != nil {
		t.Fatalf("TranslateInstructionAt() returned unexpected error: %v", err)
	}
	if got.Address != base {
		t.Fatalf("translated address mismatch: got %v want %v", got.Address, base)
	}
	if got.Length != 4 {
		t.Fatalf("translated length mismatch: got %d want 4", got.Length)
	}
	if got.Next != base.Add(4) {
		t.Fatalf("translated next mismatch: got %v want %v", got.Next, base.Add(4))
	}
	if len(got.Ops) != 1 || got.Ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected translated ops: %+v", got.Ops)
	}
	if loaderCalls[base.Offset] == 0 {
		t.Fatalf("backend loader was not called for base address %v", base)
	}
	if loaderCalls[base.Add(4).Offset] == 0 {
		t.Fatalf("backend loader was not called for fallthrough address %v", base.Add(4))
	}

	pcodeCtx, ok := engine.DisassemblyCache().GetPcodeParserContext(base)
	if !ok || pcodeCtx == nil {
		t.Fatal("expected pcode parser context to be cached for base instruction")
	}
	if pcodeCtx.GetN2addr() != base.Add(8) {
		t.Fatalf("unexpected prefetched n2addr: got %v want %v", pcodeCtx.GetN2addr(), base.Add(8))
	}
}

func TestEngineTranslateInstructionAtUsesSplitLoadHooksWithoutPayloadLoader(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x401200}

	subtable := testEngineCopySubtable()
	loaderCalls := 0
	loadFillCalls := map[uint64]int{}
	loadContextCalls := map[uint64]int{}
	engine, err := NewEngine(EngineConfig{
		Symbols: testEngineSymbolTableWithStandardRoot(subtable),
		LoweringTemplate: LoweringContext{
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls++
				return MatchInput{}, false, nil
			},
			LoadFill: func(ctx *ParserContext) error {
				if ctx == nil {
					return fmt.Errorf("split load-fill hook received nil parser context")
				}
				loadFillCalls[ctx.GetAddr().Offset]++
				switch ctx.GetAddr() {
				case base:
					ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30, 0x40})
				case base.Add(4):
					ctx.SetInstructionBytes([]byte{0x50, 0x60, 0x70, 0x80})
				default:
					return fmt.Errorf("split load-fill hook saw unexpected address %v", ctx.GetAddr())
				}
				return nil
			},
			LoadContext: func(ctx *ParserContext) error {
				if ctx == nil {
					return fmt.Errorf("split load-context hook received nil parser context")
				}
				loadContextCalls[ctx.GetAddr().Offset]++
				ctx.SetContextWords([]uint64{0x55})
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() returned unexpected error: %v", err)
	}

	got, err := engine.TranslateInstructionAt(base)
	if err != nil {
		t.Fatalf("TranslateInstructionAt() returned unexpected error: %v", err)
	}
	if loaderCalls != 0 {
		t.Fatalf("payload loader was unexpectedly called with split load hooks: calls=%d", loaderCalls)
	}
	if loadFillCalls[base.Offset] == 0 {
		t.Fatalf("split load-fill hook was not called for base address %v", base)
	}
	if loadFillCalls[base.Add(4).Offset] == 0 {
		t.Fatalf("split load-fill hook was not called for fallthrough address %v", base.Add(4))
	}
	if loadContextCalls[base.Offset] == 0 {
		t.Fatalf("split load-context hook was not called for base address %v", base)
	}
	if loadContextCalls[base.Add(4).Offset] == 0 {
		t.Fatalf("split load-context hook was not called for fallthrough address %v", base.Add(4))
	}
	if got.Address != base {
		t.Fatalf("translated address mismatch: got %v want %v", got.Address, base)
	}
	if got.Length != 4 {
		t.Fatalf("translated length mismatch: got %d want 4", got.Length)
	}
	if got.Next != base.Add(4) {
		t.Fatalf("translated next mismatch: got %v want %v", got.Next, base.Add(4))
	}
	if len(got.Ops) != 1 || got.Ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected translated ops: %+v", got.Ops)
	}

	pcodeCtx, ok := engine.DisassemblyCache().GetPcodeParserContext(base)
	if !ok || pcodeCtx == nil {
		t.Fatal("expected pcode parser context to be cached for base instruction")
	}
	if pcodeCtx.GetN2addr() != base.Add(8) {
		t.Fatalf("unexpected prefetched n2addr: got %v want %v", pcodeCtx.GetN2addr(), base.Add(8))
	}
}

func TestEngineTranslateInstructionAtUsesEntryAddressAsRootInstruction(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x401100}
	staleRoot := address.Address{Space: ram, Offset: 0x499900}

	engine, err := NewEngine(EngineConfig{
		Symbols: testEngineSymbolTableWithStandardRoot(testEngineCopySubtable()),
		LoweringTemplate: LoweringContext{
			Instruction:     staleRoot,
			RootInstruction: staleRoot,
			CurrentSpace:    ram,
			UniqueSpace:     unique,
			ConstantSpace:   constSpace,
			SpacesByIndex:   map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				if addr == base {
					return MatchInput{Instruction: []byte{0x44, 0x55, 0x66, 0x77}}, true, nil
				}
				return MatchInput{}, false, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() returned unexpected error: %v", err)
	}

	got, err := engine.TranslateInstructionAt(base)
	if err != nil {
		t.Fatalf("TranslateInstructionAt() returned unexpected error: %v", err)
	}
	if len(got.Ops) != 1 {
		t.Fatalf("unexpected translated raw-op count: got %d want 1", len(got.Ops))
	}
	if got.Ops[0].SeqNum.Address != base {
		t.Fatalf("raw-op seqnum address mismatch: got %v want %v", got.Ops[0].SeqNum.Address, base)
	}
	if got.Ops[0].SeqNum.Address == staleRoot {
		t.Fatalf("stale template root instruction leaked into runtime translation: %v", staleRoot)
	}
	stored, ok := engine.DisassemblyCache().GetRawOps(base)
	if !ok {
		t.Fatal("GetRawOps() missing engine-owned raw ops at entry address")
	}
	if len(stored) != 1 || stored[0].SeqNum.Address != base {
		t.Fatalf("engine raw-op cache root mismatch: %+v", stored)
	}
	if _, ok := engine.DisassemblyCache().GetRawOps(staleRoot); ok {
		t.Fatalf("GetRawOps() unexpectedly retained raw ops under stale template root %v", staleRoot)
	}
}

func TestEngineTranslateInstructionAtRunsResolveLoadFillHookWithSplitAuthority(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	base := address.Address{Space: ram, Offset: 0x402000}

	loadFillCalls := 0
	engine, err := NewEngine(EngineConfig{
		RootSubtable: testEngineCopySubtable(),
		LoweringTemplate: LoweringContext{
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				if addr == base {
					return MatchInput{Instruction: []byte{0x00, 0x11, 0x22, 0x33}}, true, nil
				}
				return MatchInput{}, false, nil
			},
				Resolve: ResolveHooks{
					LoadFill: func(ctx *ParserContext) error {
						loadFillCalls++
						if ctx == nil {
							return fmt.Errorf("resolve load-fill hook received nil parser context")
						}
						return nil
					},
				},
			},
	})
	if err != nil {
		t.Fatalf("NewEngine() returned unexpected error: %v", err)
	}

	got, err := engine.TranslateInstructionAt(base)
	if err != nil {
		t.Fatalf("TranslateInstructionAt() returned unexpected error: %v", err)
	}
	if len(got.Ops) != 1 || got.Ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected translated ops: %+v", got.Ops)
	}
	if loadFillCalls == 0 {
		t.Fatal("resolve load-fill hook was not called")
	}
}

func TestEngineTranslateInstructionAtUsesMetadataAlignmentWhenUnset(t *testing.T) {
	metadataRam := address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	metadataUnique := address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	metadata := &Metadata{
		Align:        4,
		DefaultSpace: "ram",
		Spaces:       []address.Space{metadataRam, metadataUnique},
	}
	misaligned := address.Address{Space: &metadata.Spaces[0], Offset: 0x1001}

	engine, err := NewEngine(EngineConfig{
		RootSubtable: testEngineCopySubtable(),
		Metadata:     metadata,
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				return MatchInput{Instruction: []byte{0xaa, 0xbb, 0xcc, 0xdd}}, true, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() returned unexpected error: %v", err)
	}

	_, err = engine.TranslateInstructionAt(misaligned)
	if err == nil {
		t.Fatal("TranslateInstructionAt() unexpectedly succeeded on metadata-misaligned address")
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("TranslateInstructionAt() error type mismatch: got %T want *UnimplError", err)
	}
	if !strings.Contains(err.Error(), "Instruction address not aligned") {
		t.Fatalf("alignment error text mismatch: %v", err)
	}
}

func TestNewEngineRejectsMissingStandardRootSubtable(t *testing.T) {
	_, err := NewEngine(EngineConfig{})
	if err == nil {
		t.Fatal("NewEngine() unexpectedly succeeded without an explicit root subtable or discoverable standard root")
	}
	if !strings.Contains(err.Error(), "standard \"instruction\" root symbol was not found in global scope") {
		t.Fatalf("unexpected NewEngine() error text: %v", err)
	}
}

func TestFindInstructionRootSubtableUsesGlobalInstructionSymbol(t *testing.T) {
	standardRoot := testEngineCopySubtable()
	nonGlobalRoot := &SubtableBoundary{ConstructorCount: 2}
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:    "instruction",
				ID:      1,
				ScopeID: 1,
				Body:    SymbolBodyBoundary{Subtable: nonGlobalRoot},
			},
			{
				Name:    "instruction",
				ID:      2,
				ScopeID: 0,
				Body:    SymbolBodyBoundary{Subtable: standardRoot},
			},
		},
	}

	got, ok := FindInstructionRootSubtable(symbols)
	if !ok {
		t.Fatal("FindInstructionRootSubtable() unexpectedly failed to find global instruction root")
	}
	if got != standardRoot {
		t.Fatalf("FindInstructionRootSubtable() returned wrong root: got %p want %p", got, standardRoot)
	}
}

func TestFindInstructionRootSubtableRejectsAbsentInstructionSymbol(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:    "register",
				ID:      1,
				ScopeID: 0,
				Body:    SymbolBodyBoundary{Subtable: testEngineCopySubtable()},
			},
		},
	}

	got, ok := FindInstructionRootSubtable(symbols)
	if ok || got != nil {
		t.Fatalf("FindInstructionRootSubtable() unexpectedly succeeded for absent instruction symbol: root=%p ok=%v", got, ok)
	}
}

func TestFindInstructionRootSubtableRejectsInstructionWrongKind(t *testing.T) {
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				Name:    "instruction",
				ID:      1,
				ScopeID: 0,
				Body: SymbolBodyBoundary{
					UserOp: &UserOpBoundary{Index: 9},
				},
			},
		},
	}

	got, ok := FindInstructionRootSubtable(symbols)
	if ok || got != nil {
		t.Fatalf("FindInstructionRootSubtable() unexpectedly succeeded for non-subtable instruction body: root=%p ok=%v", got, ok)
	}
}

func TestNewEngineFromBoundariesDerivesStandardRootAndMetadata(t *testing.T) {
	metadataRam := address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	metadataUnique := address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	metadata := &Metadata{
		Align:        4,
		DefaultSpace: "ram",
		Spaces:       []address.Space{metadataRam, metadataUnique},
	}
	boundaries := &Boundaries{
		Metadata:    metadata,
		SymbolTable: testEngineSymbolTableWithStandardRoot(testEngineCopySubtable()),
	}
	misaligned := address.Address{Space: &metadata.Spaces[0], Offset: 0x5001}

	engine, err := NewEngineFromBoundaries(boundaries, EngineConfig{
		Backend: EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				return MatchInput{Instruction: []byte{0xde, 0xad, 0xbe, 0xef}}, true, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngineFromBoundaries() returned unexpected error: %v", err)
	}

	_, err = engine.TranslateInstructionAt(misaligned)
	if err == nil {
		t.Fatal("TranslateInstructionAt() unexpectedly succeeded on metadata-misaligned address")
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("TranslateInstructionAt() error type mismatch: got %T want *UnimplError", err)
	}
	if !strings.Contains(err.Error(), "Instruction address not aligned") {
		t.Fatalf("alignment error text mismatch: %v", err)
	}
}

func TestNewEngineFromMetadataSymbolsDerivesInstructionRootAndMetadata(t *testing.T) {
	metadataRam := address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	metadataUnique := address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	metadata := &Metadata{
		Align:        4,
		DefaultSpace: "ram",
		Spaces:       []address.Space{metadataRam, metadataUnique},
	}
	misaligned := address.Address{Space: &metadata.Spaces[0], Offset: 0x6001}

	engine, err := NewEngineFromMetadataSymbols(
		metadata,
		testEngineSymbolTableWithStandardRoot(testEngineCopySubtable()),
		EngineBackendAdapter{
			LoadMatchInput: func(addr address.Address) (MatchInput, bool, error) {
				return MatchInput{Instruction: []byte{0xfa, 0xce, 0xb0, 0x0c}}, true, nil
			},
		},
		EngineConfig{},
	)
	if err != nil {
		t.Fatalf("NewEngineFromMetadataSymbols() returned unexpected error: %v", err)
	}

	_, err = engine.TranslateInstructionAt(misaligned)
	if err == nil {
		t.Fatal("TranslateInstructionAt() unexpectedly succeeded on metadata-misaligned address")
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("TranslateInstructionAt() error type mismatch: got %T want *UnimplError", err)
	}
	if !strings.Contains(err.Error(), "Instruction address not aligned") {
		t.Fatalf("alignment error text mismatch: %v", err)
	}
}

func testEngineCopySubtable() *SubtableBoundary {
	return &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 4,
			MainSection: &ConstructTplBoundary{
				Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_COPY),
					Opcode:   pcode.CPUI_COPY.String(),
					Output: &VarnodeTplBoundary{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x18},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					},
					Inputs: []VarnodeTplBoundary{{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x24},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					}},
				}},
			},
		}},
	}
}

func testEngineSymbolTableWithStandardRoot(root *SubtableBoundary) *SymbolTableBoundary {
	return &SymbolTableBoundary{
		Symbols: []SymbolBoundary{{
			Name:    "instruction",
			ID:      1,
			ScopeID: 0,
			Body: SymbolBodyBoundary{
				Subtable: root,
			},
		}},
	}
}
