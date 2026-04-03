package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestResolveConstructorAndTranslateSubtable(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	ctx := LoweringContext{
		Instruction:   address.Address{Space: ram, Offset: 0x401000},
		CurrentSpace:  ram,
		UniqueSpace:   unique,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
	}
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{
				ConstructorID: 0,
				MinimumLength: 4,
				MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_COPY),
					Opcode:   pcode.CPUI_COPY.String(),
					Output: &VarnodeTplBoundary{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					},
					Inputs: []VarnodeTplBoundary{{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					}},
				}}},
			},
			{
				ConstructorID: 1,
				MinimumLength: 4,
				MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_INT_ADD),
					Opcode:   pcode.CPUI_INT_ADD.String(),
					Output: &VarnodeTplBoundary{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x30},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					},
					Inputs: []VarnodeTplBoundary{
						{
							Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
							Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x40},
							Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
						},
						{
							Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
							Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x44},
							Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
						},
					},
				}}},
			},
		},
		Decision: &DecisionNodeBoundary{
			Number:   2,
			Context:  false,
			StartBit: 0,
			Size:     2,
			Children: []DecisionNodeBoundary{
				{Pairs: []DecisionPairBoundary{{ConstructorID: 0, Pattern: &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}}}}},
				{Pairs: []DecisionPairBoundary{{ConstructorID: 1, Pattern: &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}}}}},
			},
		},
	}

	constructor, err := ResolveConstructor(subtable, MatchInput{Instruction: []byte{0x40}})
	if err != nil {
		t.Fatalf("ResolveConstructor() returned unexpected error: %v", err)
	}
	if constructor.MainSection == nil || constructor.MainSection.Ops[0].OpcodeID != int64(pcode.CPUI_INT_ADD) {
		t.Fatal("ResolveConstructor() selected the wrong constructor")
	}
	ops, err := TranslateSubtable(subtable, TranslateInput{
		Match:    MatchInput{Instruction: []byte{0x40}},
		Lowering: ctx,
		Cache:    cache,
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 1 || ops[0].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("unexpected translated ops: %+v", ops)
	}
	pcodeCtx, ok := cache.GetPcodeParserContext(ctx.Instruction)
	if !ok {
		t.Fatal("TranslateSubtable() did not cache the pcode parser context")
	}
	if got := pcodeCtx.GetNaddr(); got != ctx.Instruction.Add(4) {
		t.Fatalf("unexpected next address after translation: got %v want %v", got, ctx.Instruction.Add(4))
	}
}

func TestMatchPatternBlockUsesBigEndianPacking(t *testing.T) {
	block := PatternBlockBoundary{
		Offset:      0,
		NonZeroSize: 1,
		MaskWords:   []PatternMaskWordBoundary{{Mask: 0xff00000000000000, Val: 0x1200000000000000}},
	}
	if !matchPatternBlock(block, []byte{0x12, 0x34}, 0) {
		t.Fatal("matchPatternBlock() did not follow Ghidra big-endian packed-byte semantics")
	}
}

func TestResolveConstructorUsesInstructionOffset(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{ConstructorID: 0}, {ConstructorID: 1}},
		Decision: &DecisionNodeBoundary{
			Context:  false,
			StartBit: 0,
			Size:     8,
			Children: make([]DecisionNodeBoundary, 256),
		},
	}
	subtable.Decision.Children[0x22] = DecisionNodeBoundary{Pairs: []DecisionPairBoundary{{ConstructorID: 1, Pattern: &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}}}}}
	constructor, err := ResolveConstructor(subtable, MatchInput{Instruction: []byte{0x11, 0x22}, InstructionOffset: 1})
	if err != nil {
		t.Fatalf("ResolveConstructor() returned unexpected error: %v", err)
	}
	if constructor.ConstructorID != 1 {
		t.Fatalf("ResolveConstructor() ignored instruction offset: got constructor id %d", constructor.ConstructorID)
	}
}

func TestTranslateSubtableNamedSection(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	sectionID := int64(7)
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 4,
			NamedSections: []NamedSectionBoundary{{
				SectionID: sectionID,
				Template: ConstructTplBoundary{Ops: []OpTplBoundary{{
					OpcodeID: int64(pcode.CPUI_COPY),
					Opcode:   pcode.CPUI_COPY.String(),
					Output: &VarnodeTplBoundary{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x88},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					},
					Inputs: []VarnodeTplBoundary{{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x44},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
					}},
				}}},
			}},
		}},
		Decision: &DecisionNodeBoundary{Pairs: []DecisionPairBoundary{{ConstructorID: 0, Pattern: &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}}}}},
	}
	ops, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   address.Address{Space: ram, Offset: 0x5000},
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Section: &sectionID,
		Cache:   NewDisassemblyCache(),
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 1 || ops[0].Output == nil || ops[0].Output.Offset != 0x88 {
		t.Fatalf("unexpected named section translation result: %+v", ops)
	}
}

func TestCombinePatternParityFalseWhenContextFails(t *testing.T) {
	pattern := &DisjointPatternBoundary{
		ElementID: elemCombinePat,
		Children: []DisjointPatternBoundary{
			{
				ElementID: elemInstructPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 0,
				},
			},
			{
				ElementID: elemContextPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 1,
					MaskWords: []PatternMaskWordBoundary{{
						Mask: 0xff00000000000000,
						Val:  0x7f00000000000000,
					}},
				},
			},
		},
	}

	matched, err := matchPattern(pattern, MatchInput{
		Instruction: []byte{0x00},
		Context:     []byte{0x80},
	})
	if err != nil {
		t.Fatalf("matchPattern() returned unexpected error: %v", err)
	}
	if matched {
		t.Fatal("CombinePattern parity mismatch: expected false when context pattern fails")
	}
}

func TestCombinePatternParityTrueWhenInstructionAndContextMatch(t *testing.T) {
	pattern := &DisjointPatternBoundary{
		ElementID: elemCombinePat,
		Children: []DisjointPatternBoundary{
			{
				ElementID: elemInstructPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 0,
				},
			},
			{
				ElementID: elemContextPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 1,
					MaskWords: []PatternMaskWordBoundary{{
						Mask: 0xff00000000000000,
						Val:  0x8000000000000000,
					}},
				},
			},
		},
	}

	matched, err := matchPattern(pattern, MatchInput{
		Instruction: []byte{0x00},
		Context:     []byte{0x80},
	})
	if err != nil {
		t.Fatalf("matchPattern() returned unexpected error: %v", err)
	}
	if !matched {
		t.Fatal("CombinePattern parity mismatch: expected true when instruction and context patterns match")
	}
}

func TestTranslateSubtableRuntimeBuildUsesResolvedOperandConstructor(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	cache := NewDisassemblyCache()
	instruction := address.Address{Space: ram, Offset: 0x6000}

	childSubtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 1,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
				Output: &VarnodeTplBoundary{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				},
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				}},
			}}},
		}},
	}
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   1,
				Name: "child",
				Body: SymbolBodyBoundary{
					Subtable: childSubtable,
				},
			},
			{
				ID:   2,
				Name: "op0",
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						RelativeOffset:      0,
						OffsetBase:          -1,
						MinimumLength:       1,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    1,
					},
				},
			},
		},
	}
	root := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID:    0,
			MinimumLength:    2,
			OperandSymbolIDs: []uint64{2},
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
				Opcode:   "BUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
				}},
			}}},
		}},
	}

	ops, err := TranslateSubtable(root, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache:   cache,
		Symbols: symbols,
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error for BUILD recursion: %v", err)
	}
	if len(ops) != 1 || ops[0].OpCode != pcode.CPUI_COPY {
		t.Fatalf("unexpected translated ops from BUILD recursion: %+v", ops)
	}
	ctx, ok := cache.GetPcodeParserContext(instruction)
	if !ok {
		t.Fatal("TranslateSubtable() did not cache the root parser context")
	}
	child, ok := ctx.BaseState.Child(0)
	if !ok || child == nil || child.Constructor == nil || child.Constructor.ConstructorID != 1 {
		t.Fatalf("TranslateSubtable() did not resolve the BUILD operand constructor: %+v", child)
	}
}

func TestTranslateSubtableResolvesRelativeLabelReference(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7000}
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{
				{
					OpcodeID: int64(pcode.CPUI_BRANCH),
					Opcode:   pcode.CPUI_BRANCH.String(),
					Inputs: []VarnodeTplBoundary{{
						Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
						Offset: ConstBoundary{Kind: ConstKindRelative, Value: 0},
						Size:   ConstBoundary{Kind: ConstKindReal, Value: 1},
					}},
				},
				{
					OpcodeID: int64(pcode.CPUI_PTRADD),
					Opcode:   "LABELBUILD",
					Inputs: []VarnodeTplBoundary{{
						Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
					}},
				},
			}},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}
	ops, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache: cache,
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 1 || ops[0].OpCode != pcode.CPUI_BRANCH {
		t.Fatalf("unexpected translated ops: %+v", ops)
	}
	if len(ops[0].Inputs) != 1 {
		t.Fatalf("expected one branch input, got %d", len(ops[0].Inputs))
	}
	if ops[0].Inputs[0].Offset != 1 {
		t.Fatalf("relative label patch mismatch: got %d want %d", ops[0].Inputs[0].Offset, 1)
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not closed after TranslateSubtable() success")
	}
}

func TestTranslateSubtableRawBuildResolveEmitGap(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7080}
	cache := NewDisassemblyCache()

	if err := cache.BeginRawBuild(instruction, 2); err != nil {
		t.Fatalf("BeginRawBuild() setup failed: %v", err)
	}
	source := OpTplBoundary{
		OpcodeID: int64(pcode.CPUI_BRANCH),
		Opcode:   pcode.CPUI_BRANCH.String(),
		Inputs: []VarnodeTplBoundary{{
			Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
			Offset: ConstBoundary{Kind: ConstKindRelative, Value: 9},
			Size:   ConstBoundary{Kind: ConstKindReal, Value: 1},
		}},
	}
	lowered := []pcode.RawOp{{
		OpCode: pcode.CPUI_BRANCH,
		Inputs: []pcode.VarnodeData{{
			Space:  constSpace,
			Offset: 0,
			Size:   1,
		}},
	}}
	if err := cache.AppendRawBuild(instruction, source, lowered, 0); err != nil {
		t.Fatalf("AppendRawBuild() setup failed: %v", err)
	}
	if err := cache.AddRawBuildLabel(instruction, 9); err != nil {
		t.Fatalf("AddRawBuildLabel() setup failed: %v", err)
	}
	if err := cache.ResolveRawBuild(instruction); err != nil {
		t.Fatalf("ResolveRawBuild() setup failed: %v", err)
	}
	// C++ PcodeCacher only exposes resolveRelatives() and emit().
	// Sink capture verifies the authoritative emit() path also closes staging.
	emitted := mustEmitRawBuildToCapture(t, cache, instruction)
	if len(emitted) != 1 || len(emitted[0].Inputs) != 1 {
		t.Fatalf("unexpected emitted shape after ResolveRawBuild()/EmitRawBuildTo(): %+v", emitted)
	}
	if got := emitted[0].Inputs[0].Offset; got != 1 {
		t.Fatalf("relative label patch mismatch after ResolveRawBuild()/EmitRawBuildTo(): got %d want 1", got)
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not closed after ResolveRawBuild()/EmitRawBuildTo()")
	}
}

func TestTranslateSubtableFailsOnMissingRelativeLabel(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7100}
	cache := NewDisassemblyCache()
	if err := cache.SetRawOps(instruction, []pcode.RawOp{{OpCode: pcode.CPUI_COPY}}); err != nil {
		t.Fatalf("SetRawOps() setup failed: %v", err)
	}
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_BRANCH),
				Opcode:   pcode.CPUI_BRANCH.String(),
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 3},
					Offset: ConstBoundary{Kind: ConstKindRelative, Value: 9},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 1},
				}},
			}}},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}
	_, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache: cache,
	})
	if err == nil {
		t.Fatal("TranslateSubtable() succeeded without a referenced label definition")
	}
	if !strings.Contains(err.Error(), "relative label id") {
		t.Fatalf("unexpected missing-label error: %v", err)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatal("TranslateSubtable() left stale raw ops after raw-build failure")
	}
	if _, rawErr := cache.RawBuildLength(instruction); rawErr == nil {
		t.Fatal("raw build staging was not canceled after TranslateSubtable() failure")
	}
}

func TestTranslateSubtableRejectsUnalignedInstructionAddress(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7003}
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{
				Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}},
			},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}
	_, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Alignment: 4,
		Cache:     NewDisassemblyCache(),
	})
	if err == nil {
		t.Fatal("TranslateSubtable() succeeded for an unaligned instruction address")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("alignment error type mismatch: got %T want *UnimplError", err)
	}
	if !terr.HasInstructionLength || terr.InstructionLength != 0 {
		t.Fatalf("alignment instruction length mismatch: has=%v len=%d", terr.HasInstructionLength, terr.InstructionLength)
	}
	want := fmt.Sprintf("Instruction address not aligned: %v", instruction)
	if terr.Error() != want {
		t.Fatalf("alignment explain mismatch: got %q want %q", terr.Error(), want)
	}
}

func TestTranslateLoadFillMissingAddressPayloadWithoutHookReturnsTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1000}
	ctx := NewParserContext(base.Add(4), nil)

	err := translateLoadFill(ctx, MatchInput{}, false, false)
	if err == nil {
		t.Fatal("translateLoadFill() unexpectedly succeeded without payload or hook")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("translateLoadFill() error type mismatch: got %T want *UnimplError", err)
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("translateLoadFill() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	if !strings.Contains(err.Error(), "requires an instruction payload or load-fill hook") {
		t.Fatalf("translateLoadFill() explain mismatch: %v", err)
	}
}

func TestTranslateLoadContextMissingAddressPayloadWithoutHookReturnsTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1100}
	ctx := NewParserContext(base.Add(8), nil)

	err := translateLoadContext(ctx, MatchInput{}, false, false)
	if err == nil {
		t.Fatal("translateLoadContext() unexpectedly succeeded without payload or hook")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("translateLoadContext() error type mismatch: got %T want *UnimplError", err)
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("translateLoadContext() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	if !strings.Contains(err.Error(), "requires a context payload or load-context hook") {
		t.Fatalf("translateLoadContext() explain mismatch: %v", err)
	}
}

func TestTranslateResolveHooksLoadFillUsesAddressPayloadWithoutUserHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1300}
	adjacent := base.Add(4)
	ctx := NewParserContext(adjacent, nil)

	input := TranslateInput{
		Match: MatchInput{
			Instruction: []byte{0xaa},
		},
		Payloads: TranslatePayloadSource{
			ByAddress: map[address.Address]MatchInput{
				adjacent: {Instruction: []byte{0xbb, 0xcc}},
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadFill == nil {
		t.Fatal("translateResolveHooks() did not install load-fill hook")
	}
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("load-fill hook returned error for address payload: %v", err)
	}
	if len(ctx.InstructionBytes) != 2 || ctx.InstructionBytes[0] != 0xbb || ctx.InstructionBytes[1] != 0xcc {
		t.Fatalf("address payload instruction bytes mismatch: %+v", ctx.InstructionBytes)
	}
}

func TestTranslateResolveHooksLoadContextUsesAddressPayloadWithoutUserHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1400}
	adjacent := base.Add(8)
	ctx := NewParserContext(adjacent, nil)

	input := TranslateInput{
		Match: MatchInput{
			Context: []byte{0x10},
		},
		Payloads: TranslatePayloadSource{
			ByAddress: map[address.Address]MatchInput{
				adjacent: {Context: []byte{0x12, 0x34}},
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadContext == nil {
		t.Fatal("translateResolveHooks() did not install load-context hook")
	}
	if err := hooks.LoadContext(ctx); err != nil {
		t.Fatalf("load-context hook returned error for address payload: %v", err)
	}
	if len(ctx.ContextWords) != 1 || ctx.ContextWords[0] != 0x1234000000000000 {
		t.Fatalf("address payload context words mismatch: %+v", ctx.ContextWords)
	}
}

func TestTranslateResolveHooksLoadFillUsesLookupPayloadWithoutUserHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1410}
	adjacent := base.Add(2)
	ctx := NewParserContext(adjacent, nil)

	input := TranslateInput{
		Match: MatchInput{
			Instruction: []byte{0xaa},
		},
		Payloads: TranslatePayloadSource{
			Lookup: func(addr address.Address) (MatchInput, bool) {
				if addr != adjacent {
					return MatchInput{}, false
				}
				return MatchInput{Instruction: []byte{0xde, 0xad}}, true
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadFill == nil {
		t.Fatal("translateResolveHooks() did not install load-fill hook")
	}
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("load-fill hook returned error for lookup payload: %v", err)
	}
	if len(ctx.InstructionBytes) != 2 || ctx.InstructionBytes[0] != 0xde || ctx.InstructionBytes[1] != 0xad {
		t.Fatalf("lookup payload instruction bytes mismatch: %+v", ctx.InstructionBytes)
	}
}

func TestTranslateResolveHooksLoadFillPrefersPayloadLoader(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1420}
	adjacent := base.Add(4)
	ctx := NewParserContext(adjacent, nil)
	loaderCalls := 0

	input := TranslateInput{
		Match: MatchInput{
			Instruction: []byte{0xaa},
		},
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls++
				if addr != adjacent {
					return MatchInput{}, false, nil
				}
				return MatchInput{Instruction: []byte{0xfa, 0xce}}, true, nil
			},
			Lookup: func(addr address.Address) (MatchInput, bool) {
				if addr != adjacent {
					return MatchInput{}, false
				}
				return MatchInput{Instruction: []byte{0xde, 0xad}}, true
			},
			ByAddress: map[address.Address]MatchInput{
				adjacent: {Instruction: []byte{0xbb}},
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadFill == nil {
		t.Fatal("translateResolveHooks() did not install load-fill hook")
	}
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("load-fill hook returned error for payload loader: %v", err)
	}
	if loaderCalls != 1 {
		t.Fatalf("payload loader call count mismatch: got %d want 1", loaderCalls)
	}
	if len(ctx.InstructionBytes) != 2 || ctx.InstructionBytes[0] != 0xfa || ctx.InstructionBytes[1] != 0xce {
		t.Fatalf("payload loader instruction bytes mismatch: %+v", ctx.InstructionBytes)
	}
}

func TestTranslateResolveHooksLoadContextPropagatesPayloadLoaderError(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1430}
	adjacent := base.Add(8)
	ctx := NewParserContext(adjacent, nil)
	expected := errors.New("payload backend unavailable")

	input := TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				return MatchInput{}, false, expected
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadContext == nil {
		t.Fatal("translateResolveHooks() did not install load-context hook")
	}
	err := hooks.LoadContext(ctx)
	if err == nil {
		t.Fatal("load-context hook unexpectedly succeeded when payload loader failed")
	}
	if !errors.Is(err, expected) {
		t.Fatalf("load-context hook error mismatch: got %v want wrapped %v", err, expected)
	}
}

func TestTranslateResolveHooksSkipsPayloadFallbackWhenExplicitLoadHooksPresent(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1438}
	adjacent := base.Add(8)
	ctx := NewParserContext(adjacent, nil)
	loaderCalls := 0
	loadFillCalls := 0
	loadContextCalls := 0

	input := TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls++
				return MatchInput{Instruction: []byte{0xaa}, Context: []byte{0xbb}}, true, nil
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
		Resolve: ResolveHooks{
			LoadFill: func(ctx *ParserContext) error {
				loadFillCalls++
				if ctx == nil {
					return fmt.Errorf("explicit load-fill hook received nil parser context")
				}
				ctx.SetInstructionBytes([]byte{0x11})
				return nil
			},
			LoadContext: func(ctx *ParserContext) error {
				loadContextCalls++
				if ctx == nil {
					return fmt.Errorf("explicit load-context hook received nil parser context")
				}
				ctx.SetContextWords([]uint64{0x2200000000000000})
				return nil
			},
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("explicit load-fill hook failed: %v", err)
	}
	if err := hooks.LoadContext(ctx); err != nil {
		t.Fatalf("explicit load-context hook failed: %v", err)
	}
	if loaderCalls != 0 {
		t.Fatalf("payload loader should not be called when explicit load hooks are present: calls=%d", loaderCalls)
	}
	if loadFillCalls != 1 || loadContextCalls != 1 {
		t.Fatalf("explicit load hook call mismatch: loadFill=%d loadContext=%d", loadFillCalls, loadContextCalls)
	}
	if len(ctx.InstructionBytes) != 1 || ctx.InstructionBytes[0] != 0x11 {
		t.Fatalf("explicit load-fill output mismatch: %+v", ctx.InstructionBytes)
	}
	if len(ctx.ContextWords) != 1 || ctx.ContextWords[0] != 0x2200000000000000 {
		t.Fatalf("explicit load-context output mismatch: %+v", ctx.ContextWords)
	}
}

func TestTranslateResolveHooksUsesPayloadFallbackOnlyForMissingPhase(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x143c}
	adjacent := base.Add(4)
	ctx := NewParserContext(adjacent, nil)
	loaderCalls := 0
	loadFillCalls := 0

	input := TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls++
				if addr != adjacent {
					return MatchInput{}, false, nil
				}
				return MatchInput{Instruction: []byte{0xaa}, Context: []byte{0x44}}, true, nil
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
		Resolve: ResolveHooks{
			LoadFill: func(ctx *ParserContext) error {
				loadFillCalls++
				if ctx == nil {
					return fmt.Errorf("explicit load-fill hook received nil parser context")
				}
				ctx.SetInstructionBytes([]byte{0x55})
				return nil
			},
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("explicit load-fill hook failed: %v", err)
	}
	if err := hooks.LoadContext(ctx); err != nil {
		t.Fatalf("fallback load-context hook failed: %v", err)
	}
	if loadFillCalls != 1 {
		t.Fatalf("explicit load-fill hook call mismatch: got %d want 1", loadFillCalls)
	}
	if loaderCalls != 1 {
		t.Fatalf("payload loader should be called once for the missing load-context phase: calls=%d", loaderCalls)
	}
	if len(ctx.InstructionBytes) != 1 || ctx.InstructionBytes[0] != 0x55 {
		t.Fatalf("explicit load-fill output should not be overridden by payload fallback: %+v", ctx.InstructionBytes)
	}
	if len(ctx.ContextWords) != 1 || ctx.ContextWords[0] != 0x4400000000000000 {
		t.Fatalf("fallback load-context output mismatch: %+v", ctx.ContextWords)
	}
}

func TestTranslateResolveHooksReusesAddressPayloadAcrossFallbackPhases(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1448}
	adjacent := base.Add(8)
	ctx := NewParserContext(adjacent, nil)
	loaderCalls := 0

	input := TranslateInput{
		Payloads: TranslatePayloadSource{
			Loader: func(addr address.Address) (MatchInput, bool, error) {
				loaderCalls++
				if addr != adjacent {
					return MatchInput{}, false, nil
				}
				return MatchInput{Instruction: []byte{0x12, 0x34}, Context: []byte{0x56}}, true, nil
			},
		},
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if err := hooks.LoadFill(ctx); err != nil {
		t.Fatalf("fallback load-fill hook failed: %v", err)
	}
	if err := hooks.LoadContext(ctx); err != nil {
		t.Fatalf("fallback load-context hook failed: %v", err)
	}
	if loaderCalls != 1 {
		t.Fatalf("payload loader lookup should be reused across fallback phases: calls=%d", loaderCalls)
	}
	if len(ctx.InstructionBytes) != 2 || ctx.InstructionBytes[0] != 0x12 || ctx.InstructionBytes[1] != 0x34 {
		t.Fatalf("fallback load-fill output mismatch: %+v", ctx.InstructionBytes)
	}
	if len(ctx.ContextWords) != 1 || ctx.ContextWords[0] != 0x5600000000000000 {
		t.Fatalf("fallback load-context output mismatch: %+v", ctx.ContextWords)
	}
}

func TestTranslateResolveHooksLoadFillBaseAddressWithoutSeededMatchReturnsTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	base := address.Address{Space: ram, Offset: 0x1440}
	ctx := NewParserContext(base, nil)

	input := TranslateInput{
		Lowering: LoweringContext{
			Instruction: base,
		},
	}
	hooks := translateResolveHooks(&SubtableBoundary{}, input)
	if hooks.LoadFill == nil {
		t.Fatal("translateResolveHooks() did not install load-fill hook")
	}
	err := hooks.LoadFill(ctx)
	if err == nil {
		t.Fatal("load-fill hook unexpectedly succeeded without seeded base payload")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("load-fill hook error type mismatch: got %T want *UnimplError", err)
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("load-fill hook error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
}

func TestPrepareDelaySlotContextsMissingLengthReturnsTypedUnimpl(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x1200}
	delayAddr := instruction.Add(1)

	cache := NewDisassemblyCache()
	delayCtx := NewParserContext(delayAddr, constSpace)
	delayCtx.SetParserState(ParseStatePcode)
	delayCtx.BaseState.Length = 0
	if err := cache.SetParserContext(delayAddr, delayCtx); err != nil {
		t.Fatalf("SetParserContext() setup failed: %v", err)
	}

	rootCtx := NewParserContext(instruction, constSpace)
	rootCtx.SetDelaySlot(1)
	rootCtx.BaseState.Length = 1

	input := TranslateInput{
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
	}

	_, err := prepareDelaySlotContexts(cache, &SubtableBoundary{}, input, rootCtx)
	if err == nil {
		t.Fatal("prepareDelaySlotContexts() unexpectedly succeeded with unresolved delay-slot length")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("prepareDelaySlotContexts() error type mismatch: got %T want *UnimplError", err)
	}
	if !errors.Is(err, ErrObtainContextUnimplemented) {
		t.Fatalf("prepareDelaySlotContexts() error does not wrap ErrObtainContextUnimplemented: %v", err)
	}
	if !strings.Contains(err.Error(), "delay-slot parser context") || !strings.Contains(err.Error(), "has no resolved length") {
		t.Fatalf("prepareDelaySlotContexts() explain mismatch: %v", err)
	}
}

func TestPrepareDelaySlotContextsUsesAddressPayloadWithoutCustomHooks(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x1250}
	delayAddr := instruction.Add(1)

	rootCtx := NewParserContext(instruction, constSpace)
	rootCtx.SetDelaySlot(1)
	rootCtx.BaseState.Length = 1
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{
				ConstructorID: 0,
				MinimumLength: 2,
				MainSection: &ConstructTplBoundary{
					Ops: []OpTplBoundary{},
				},
			},
		},
	}
	input := TranslateInput{
		Match: MatchInput{
			Instruction: []byte{0x10},
		},
		Payloads: TranslatePayloadSource{
			ByAddress: map[address.Address]MatchInput{
				delayAddr: {
					Instruction: []byte{0x20},
				},
			},
		},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
	}

	fallOffset, err := prepareDelaySlotContexts(cache, subtable, input, rootCtx)
	if err != nil {
		t.Fatalf("prepareDelaySlotContexts() failed with address payload source: %v", err)
	}
	if fallOffset != 3 {
		t.Fatalf("prepareDelaySlotContexts() fall offset mismatch: got %d want 3", fallOffset)
	}
	if got := rootCtx.GetNaddr(); got != instruction.Add(3) {
		t.Fatalf("prepareDelaySlotContexts() naddr mismatch: got %v want %v", got, instruction.Add(3))
	}
	delayCtx, ok := cache.GetParserContext(delayAddr)
	if !ok || delayCtx == nil {
		t.Fatal("delay parser context was not cached")
	}
	if delayCtx.GetParserState() < ParseStateDisassembly {
		t.Fatalf("delay parser context parse state mismatch: got %d want >= disassembly", delayCtx.GetParserState())
	}
	if len(delayCtx.InstructionBytes) != 1 || delayCtx.InstructionBytes[0] != 0x20 {
		t.Fatalf("delay parser context instruction bytes mismatch: %+v", delayCtx.InstructionBytes)
	}
}

func TestPrepareDelaySlotContextsUsesPayloadLoaderWithoutSeededBaseMatch(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x1260}
	delayAddr := instruction.Add(1)

	rootCtx := NewParserContext(instruction, constSpace)
	rootCtx.SetDelaySlot(1)
	rootCtx.BaseState.Length = 1
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{
				ConstructorID: 0,
				MinimumLength: 2,
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
				if addr != delayAddr {
					return MatchInput{}, false, nil
				}
				return MatchInput{Instruction: []byte{0x33}}, true, nil
			},
		},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
	}

	fallOffset, err := prepareDelaySlotContexts(cache, subtable, input, rootCtx)
	if err != nil {
		t.Fatalf("prepareDelaySlotContexts() failed with payload loader source: %v", err)
	}
	if fallOffset != 3 {
		t.Fatalf("prepareDelaySlotContexts() fall offset mismatch: got %d want 3", fallOffset)
	}
	if got := rootCtx.GetNaddr(); got != instruction.Add(3) {
		t.Fatalf("prepareDelaySlotContexts() naddr mismatch: got %v want %v", got, instruction.Add(3))
	}
	if loaderCalls[delayAddr.Offset] == 0 {
		t.Fatalf("expected payload loader call for delay address %v", delayAddr)
	}
	delayCtx, ok := cache.GetParserContext(delayAddr)
	if !ok || delayCtx == nil {
		t.Fatal("delay parser context was not cached")
	}
	if delayCtx.GetParserState() < ParseStateDisassembly {
		t.Fatalf("delay parser context parse state mismatch: got %d want >= disassembly", delayCtx.GetParserState())
	}
	if len(delayCtx.InstructionBytes) != 1 || delayCtx.InstructionBytes[0] != 0x33 {
		t.Fatalf("delay parser context instruction bytes mismatch: %+v", delayCtx.InstructionBytes)
	}
}

func TestTranslateSubtableCachesOwnedRawOps(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	addr := address.Address{Space: ram, Offset: 0x7200}
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
				Output: &VarnodeTplBoundary{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x30},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				},
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x10},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				}},
			}}},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}
	ops, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   addr,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache: cache,
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("unexpected raw-op count: got %d want 1", len(ops))
	}
	ops[0].Inputs[0].Offset = 0xdead
	stored, ok := cache.GetRawOps(addr)
	if !ok {
		t.Fatal("GetRawOps() missing stored translation output")
	}
	if len(stored) != 1 || len(stored[0].Inputs) != 1 {
		t.Fatalf("unexpected stored raw-ops shape: %+v", stored)
	}
	if stored[0].Inputs[0].Offset == 0xdead {
		t.Fatalf("raw-op cache ownership mismatch: cache data was mutated by caller")
	}
}

func TestTranslateSubtableUsesRootInstructionForSinkBackedEmission(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7210}
	root := address.Address{Space: ram, Offset: 0x7000}
	cache := NewDisassemblyCache()
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID: 0,
			MinimumLength: 1,
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_COPY),
				Opcode:   pcode.CPUI_COPY.String(),
				Output: &VarnodeTplBoundary{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 2},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x38},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				},
				Inputs: []VarnodeTplBoundary{{
					Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: 1},
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x14},
					Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
				}},
			}}},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}

	ops, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:     instruction,
			RootInstruction: root,
			CurrentSpace:    ram,
			UniqueSpace:     unique,
			ConstantSpace:   constSpace,
			SpacesByIndex:   map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache: cache,
	})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("unexpected raw-op count: got %d want 1", len(ops))
	}
	if ops[0].SeqNum.Address != root {
		t.Fatalf("returned raw-op root mismatch: got %v want %v", ops[0].SeqNum.Address, root)
	}
	stored, ok := cache.GetRawOps(root)
	if !ok {
		t.Fatal("GetRawOps() missing sink-backed raw ops at root instruction")
	}
	if len(stored) != 1 || stored[0].SeqNum.Address != root {
		t.Fatalf("sink-backed cache root mismatch: %+v", stored)
	}
	if _, ok := cache.GetRawOps(instruction); ok {
		t.Fatalf("GetRawOps() unexpectedly retained sink-backed raw ops under parser context address %v", instruction)
	}
}

func TestTranslateSubtableDelaySlotNestedUniqueOffsetAndRootSeqAddressParity(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x8123}
	root := address.Address{Space: ram, Offset: 0x8000}
	delayAddr := instruction.Add(1)
	uniqueMask := uint64(0xff)

	dynamicInput := VarnodeTplBoundary{
		Space:  ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldSpace},
		Offset: ConstBoundary{Kind: ConstKindHandle, HandleIndex: 0, Selector: handleFieldOffset},
		Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
	}
	patternForByte := func(b byte) *DisjointPatternBoundary {
		return &DisjointPatternBoundary{
			ElementID: elemInstructPat,
			Block: &PatternBlockBoundary{
				Offset:      0,
				NonZeroSize: 1,
				MaskWords: []PatternMaskWordBoundary{{
					Mask: 0xff00000000000000,
					Val:  uint64(b) << 56,
				}},
			},
		}
	}
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{
				ConstructorID:    0,
				MinimumLength:    1,
				OperandSymbolIDs: []uint64{1},
				MainSection: &ConstructTplBoundary{
					DelaySlot: 1,
					Ops: []OpTplBoundary{
						{
							OpcodeID: int64(pcode.CPUI_COPY),
							Opcode:   pcode.CPUI_COPY.String(),
							Output: &VarnodeTplBoundary{
								Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
								Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x100},
								Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
							},
							Inputs: []VarnodeTplBoundary{dynamicInput},
						},
						{
							OpcodeID: int64(pcode.CPUI_INDIRECT),
							Opcode:   "DELAY_SLOT",
						},
						{
							OpcodeID: int64(pcode.CPUI_COPY),
							Opcode:   pcode.CPUI_COPY.String(),
							Output: &VarnodeTplBoundary{
								Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
								Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x104},
								Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
							},
							Inputs: []VarnodeTplBoundary{dynamicInput},
						},
					},
				},
			},
			{
				ConstructorID:    1,
				MinimumLength:    1,
				OperandSymbolIDs: []uint64{1},
				MainSection: &ConstructTplBoundary{
					Ops: []OpTplBoundary{
						{
							OpcodeID: int64(pcode.CPUI_COPY),
							Opcode:   pcode.CPUI_COPY.String(),
							Output: &VarnodeTplBoundary{
								Space:  ConstBoundary{Kind: ConstKindSpaceID, SpaceIndex: int64(ram.Index)},
								Offset: ConstBoundary{Kind: ConstKindReal, Value: 0x108},
								Size:   ConstBoundary{Kind: ConstKindReal, Value: 4},
							},
							Inputs: []VarnodeTplBoundary{dynamicInput},
						},
					},
				},
			},
		},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{
				{ConstructorID: 0, Pattern: patternForByte(0x10)},
				{ConstructorID: 1, Pattern: patternForByte(0x20)},
			},
		},
	}

		operandSubtable := &SubtableBoundary{
			Constructors: []ConstructorBoundary{{
				ConstructorID: 2,
				MinimumLength: 1,
				MainSection: &ConstructTplBoundary{
					Result: &HandleTplBoundary{
						Space:      ConstBoundary{Kind: ConstKindCurSpace},
						Size:       ConstBoundary{Kind: ConstKindReal, Value: 4},
						PtrSpace:   ConstBoundary{Kind: ConstKindFlowRef},
						PtrOffset:  ConstBoundary{Kind: ConstKindReal, Value: 0x88},
						PtrSize:    ConstBoundary{Kind: ConstKindReal, Value: 8},
						TempSpace:  ConstBoundary{Kind: ConstKindFlowRef},
						TempOffset: ConstBoundary{Kind: ConstKindReal, Value: 0x20},
					},
				},
			}},
		}
	symbols := &SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   1,
				Name: "op0",
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						RelativeOffset:      0,
						OffsetBase:          -1,
						MinimumLength:       1,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    2,
					},
				},
			},
			{
				ID:   2,
				Name: "child",
				Body: SymbolBodyBoundary{
					Subtable: operandSubtable,
				},
			},
		},
	}
		ops, err := TranslateSubtable(subtable, TranslateInput{
			Match: MatchInput{Instruction: []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
			Payloads: TranslatePayloadSource{
				ByAddress: map[address.Address]MatchInput{
					instruction: {Instruction: []byte{0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
					delayAddr:   {Instruction: []byte{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
				},
			},
			Lowering: LoweringContext{
				Instruction:     instruction,
				RootInstruction: root,
				CurrentSpace:    ram,
				UniqueSpace:     unique,
				ConstantSpace:   constSpace,
				UniqueBase:      0x7000,
				UniqueMask:      uniqueMask,
				SpacesByIndex:   map[int64]*address.Space{int64(ram.Index): ram, int64(unique.Index): unique, int64(constSpace.Index): constSpace},
			},
			Resolve: ResolveHooks{
				ResolveSymbol: func(frame ResolveFrame) (ResolveOutcome, error) {
					out, err := resolveTranslateFrame(subtable, frame)
					if err != nil {
						return ResolveOutcome{}, err
					}
					out.HasRefAddr = true
					out.RefAddr = address.Address{Space: unique, Offset: 0x9900}
					return out, nil
				},
			},
			Symbols: symbols,
			Cache:   NewDisassemblyCache(),
		})
	if err != nil {
		t.Fatalf("TranslateSubtable() returned unexpected error: %v", err)
	}
	if len(ops) != 6 {
		t.Fatalf("unexpected nested translation op count: got %d want 6", len(ops))
	}
	wantOpcodes := []pcode.OpCode{
		pcode.CPUI_LOAD, pcode.CPUI_COPY,
		pcode.CPUI_LOAD, pcode.CPUI_COPY,
		pcode.CPUI_LOAD, pcode.CPUI_COPY,
	}
	for i := range wantOpcodes {
		if ops[i].OpCode != wantOpcodes[i] {
			t.Fatalf("opcode[%d] mismatch: got %v want %v", i, ops[i].OpCode, wantOpcodes[i])
		}
	}

	outerUniqueBits := (instruction.Offset & uniqueMask) << 8
	innerUniqueBits := (delayAddr.Offset & uniqueMask) << 8
	wantOuterTemp := uint64(0x20) | outerUniqueBits
	wantInnerTemp := uint64(0x20) | innerUniqueBits
	wantOuterPointer := uint64(0x88) | outerUniqueBits
	wantInnerPointer := uint64(0x88) | innerUniqueBits

	loadChecks := []struct {
		opIndex      int
		wantTemp     uint64
		wantPtr      uint64
	}{
		{opIndex: 0, wantTemp: wantOuterTemp, wantPtr: wantOuterPointer},
		{opIndex: 2, wantTemp: wantInnerTemp, wantPtr: wantInnerPointer},
		{opIndex: 4, wantTemp: wantOuterTemp, wantPtr: wantOuterPointer},
	}
	for _, check := range loadChecks {
		op := ops[check.opIndex]
		if op.Output == nil {
			t.Fatalf("LOAD op %d has nil output", check.opIndex)
		}
		if op.Output.Space != unique || op.Output.Offset != check.wantTemp || op.Output.Size != 4 {
			t.Fatalf("LOAD op %d temp mismatch: got %+v want space=%v off=0x%x size=4", check.opIndex, op.Output, unique, check.wantTemp)
		}
		if len(op.Inputs) != 2 {
			t.Fatalf("LOAD op %d input count mismatch: got %d want 2", check.opIndex, len(op.Inputs))
		}
		if op.Inputs[1].Space != unique || op.Inputs[1].Offset != check.wantPtr || op.Inputs[1].Size != 8 {
			t.Fatalf("LOAD op %d pointer mismatch: got %+v want space=%v off=0x%x size=8", check.opIndex, op.Inputs[1], unique, check.wantPtr)
		}
	}

	for i, loadIndex := range []int{0, 2, 4} {
		copyOp := ops[loadIndex+1]
		loadOp := ops[loadIndex]
		if len(copyOp.Inputs) != 1 || loadOp.Output == nil || copyOp.Inputs[0] != *loadOp.Output {
			t.Fatalf("COPY op %d does not consume preceding dynamic temp output", i)
		}
	}

	for i := range ops {
		if ops[i].SeqNum.Address != root {
			t.Fatalf("SeqNum.Address[%d] mismatch: got %v want %v", i, ops[i].SeqNum.Address, root)
		}
	}
}

func TestTranslateBuildTailUsesSinkBackedBuilderEmission(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7240}
	cache := NewDisassemblyCache()
	builder := NewSleighBuilder(RuntimeContext{
		Instruction:   instruction,
		CurrentSpace:  ram,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{
			int64(ram.Index):        ram,
			int64(constSpace.Index): constSpace,
		},
	}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return []pcode.RawOp{{
				OpCode: pcode.CPUI_COPY,
				Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x55, Size: 4}},
			}}, nil
		},
	})
	builder.State.SetDisassemblyCache(cache)
	section := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
		}},
	}
	got, err := translateBuildTail(builder, section, -1)
	if err != nil {
		t.Fatalf("translateBuildTail() returned unexpected error: %v", err)
	}
	if len(got) != 1 || len(got[0].Inputs) != 1 || got[0].Inputs[0].Offset != 0x55 {
		t.Fatalf("translateBuildTail() sink-backed emission mismatch: %+v", got)
	}
	got[0].Inputs[0].Offset = 0xdead
	stored, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing sink-backed commit")
	}
	if len(stored) != 1 || len(stored[0].Inputs) != 1 || stored[0].Inputs[0].Offset != 0x55 {
		t.Fatalf("sink-backed cache ownership mismatch: %+v", stored)
	}
	if _, err := cache.RawBuildLength(instruction); err == nil {
		t.Fatal("raw build staging was not closed after sink-backed translate build tail")
	}
}

func TestTranslateBuildTailChainsAndRestoresExistingRawEmitter(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7248}
	cache := NewDisassemblyCache()
	existingSink := &translateCaptureRawEmitter{}
	builder := NewSleighBuilder(RuntimeContext{
		Instruction:   instruction,
		CurrentSpace:  ram,
		ConstantSpace: constSpace,
		SpacesByIndex: map[int64]*address.Space{
			int64(ram.Index):        ram,
			int64(constSpace.Index): constSpace,
		},
	}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return []pcode.RawOp{{
				OpCode: pcode.CPUI_COPY,
				Inputs: []pcode.VarnodeData{{Space: ram, Offset: 0x66, Size: 4}},
			}}, nil
		},
		RawEmitter: existingSink,
	})
	builder.State.SetDisassemblyCache(cache)
	section := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
		}},
	}

	got, err := translateBuildTail(builder, section, -1)
	if err != nil {
		t.Fatalf("translateBuildTail() returned unexpected error: %v", err)
	}
	if len(got) != 1 || len(got[0].Inputs) != 1 || got[0].Inputs[0].Offset != 0x66 {
		t.Fatalf("translateBuildTail() capture mismatch with existing sink: %+v", got)
	}
	existing := existingSink.Ops()
	if len(existing) != 1 || len(existing[0].Inputs) != 1 || existing[0].Inputs[0].Offset != 0x66 {
		t.Fatalf("translateBuildTail() did not preserve existing sink emission: %+v", existing)
	}
	if builder.Hooks.RawEmitter != existingSink {
		t.Fatal("translateBuildTail() did not restore pre-existing builder raw emitter")
	}
	got[0].Inputs[0].Offset = 0xdead
	stored, ok := cache.GetRawOps(instruction)
	if !ok {
		t.Fatal("GetRawOps() missing sink-backed commit with existing sink")
	}
	if len(stored) != 1 || len(stored[0].Inputs) != 1 || stored[0].Inputs[0].Offset != 0x66 {
		t.Fatalf("cache-owned commit mismatch with existing sink chain: %+v", stored)
	}
}

func TestTranslateBuildTailRequiresCacheBackedLowerRawHook(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0x7250}
	cache := NewDisassemblyCache()
	if err := cache.SetRawOps(instruction, []pcode.RawOp{{OpCode: pcode.CPUI_INT_ADD}}); err != nil {
		t.Fatalf("SetRawOps() setup failed: %v", err)
	}
	builder := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		Dump: func(op OpTplBoundary, state BuilderState) error {
			return nil
		},
	})
	builder.State.SetDisassemblyCache(cache)
	section := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
		}},
	}

	_, err := translateBuildTail(builder, section, -1)
	if err == nil {
		t.Fatal("translateBuildTail() unexpectedly succeeded without cache-backed LowerRaw hook")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("translateBuildTail() error type mismatch without LowerRaw hook: %v", err)
	}
	if !strings.Contains(err.Error(), "cache-backed raw emission hook is required") {
		t.Fatalf("translateBuildTail() error mismatch without LowerRaw hook: %v", err)
	}
	stored, ok := cache.GetRawOps(instruction)
	if !ok || len(stored) != 1 || stored[0].OpCode != pcode.CPUI_INT_ADD {
		t.Fatalf("stale cache setup unexpectedly changed after hook-gate failure: %+v", stored)
	}
}

func TestTranslateBuildTailRequiresDisassemblyCacheForCacheOwnedEmission(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	instruction := address.Address{Space: ram, Offset: 0x7260}

	builder := NewSleighBuilder(RuntimeContext{Instruction: instruction}, 0, -1, BuilderHooks{
		LowerRaw: func(op OpTplBoundary, state BuilderState, order uint64) ([]pcode.RawOp, error) {
			return []pcode.RawOp{{
				OpCode: pcode.CPUI_COPY,
			}}, nil
		},
	})
	section := ConstructTplBoundary{
		Ops: []OpTplBoundary{{
			OpcodeID: int64(pcode.CPUI_COPY),
			Opcode:   pcode.CPUI_COPY.String(),
		}},
	}

	_, err := translateBuildTail(builder, section, -1)
	if err == nil {
		t.Fatal("translateBuildTail() unexpectedly succeeded without a disassembly cache")
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("translateBuildTail() error type mismatch without disassembly cache: %v", err)
	}
	if !strings.Contains(err.Error(), "cache-backed raw emission requires a disassembly cache") {
		t.Fatalf("translateBuildTail() error mismatch without disassembly cache: %v", err)
	}
}

func TestTranslateSubtableRewritesTypedUnimplAcrossBuildTail(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	unique := &address.Space{Name: "unique", Kind: address.SpaceKindUnique, Index: 2, AddrSize: 8, WordSize: 1}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}
	instruction := address.Address{Space: ram, Offset: 0x7300}
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{
			ConstructorID:   0,
			MinimumLength:   2,
			FirstWhitespace: 1,
			PrintPieces: []PrintPieceBoundary{
				{Text: "buildfail"},
				{Text: " "},
				{OperandIndex: 0, IsOperandRef: true},
			},
			MainSection: &ConstructTplBoundary{Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_MULTIEQUAL),
				Opcode:   "BUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
				}},
			}}},
		}},
		Decision: &DecisionNodeBoundary{
			Pairs: []DecisionPairBoundary{{
				ConstructorID: 0,
				Pattern:       &DisjointPatternBoundary{ElementID: elemInstructPat, Block: &PatternBlockBoundary{Offset: 0, NonZeroSize: 0}},
			}},
		},
	}
	_, err := TranslateSubtable(subtable, TranslateInput{
		Match: MatchInput{Instruction: []byte{0x00}},
		Lowering: LoweringContext{
			Instruction:   instruction,
			CurrentSpace:  ram,
			UniqueSpace:   unique,
			ConstantSpace: constSpace,
			SpacesByIndex: map[int64]*address.Space{1: ram, 2: unique, 3: constSpace},
		},
		Cache: NewDisassemblyCache(),
	})
	if err == nil {
		t.Fatal("TranslateSubtable() unexpectedly succeeded on unresolved BUILD operand")
	}
	var terr *UnimplError
	if !errors.As(err, &terr) {
		t.Fatalf("TranslateSubtable() error type mismatch: got %T want *UnimplError", err)
	}
	if !errors.Is(err, ErrBuilderUnimplemented) {
		t.Fatalf("TranslateSubtable() unimplemented error does not wrap ErrBuilderUnimplemented: %v", err)
	}
	if !terr.HasInstructionLength || terr.InstructionLength != 2 {
		t.Fatalf("TranslateSubtable() instruction length mismatch: has=%v len=%d want=2", terr.HasInstructionLength, terr.InstructionLength)
	}
	if !strings.Contains(terr.Error(), "Instruction not implemented in pcode:\n ") {
		t.Fatalf("TranslateSubtable() missing oneInstruction() prefix rewrite: %q", terr.Error())
	}
	if !strings.Contains(terr.Error(), "ram:0x7300: buildfail") {
		t.Fatalf("TranslateSubtable() rewritten explain missing constructor print: %q", terr.Error())
	}
}

func TestWrapTranslateUnimplErrorBuildsOneInstructionExplain(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x9000}, nil)
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "add"},
			{Text: " "},
			{Text: "r0, "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	child := ctx.BaseState.EnsureOperand(0)
	child.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "r1"},
		},
	})
	walker := NewParserWalker(ctx)
	walker.BaseState()
	builder := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	builder.State.Walker = walker

	cause := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	wrapped := wrapTranslateUnimplError(cause, builder, 7)
	terr, ok := wrapped.(*UnimplError)
	if !ok {
		t.Fatalf("wrapTranslateUnimplError() returned %T, want *UnimplError", wrapped)
	}
	if !terr.HasInstructionLength || terr.InstructionLength != 7 {
		t.Fatalf("instruction length mismatch: has=%v len=%d want=7", terr.HasInstructionLength, terr.InstructionLength)
	}
	if !errors.Is(wrapped, ErrBuilderUnimplemented) {
		t.Fatalf("wrapped error does not unwrap to ErrBuilderUnimplemented: %v", wrapped)
	}
	if !strings.Contains(wrapped.Error(), "Instruction not implemented in pcode:\n ") {
		t.Fatalf("missing C++ oneInstruction() prefix in wrapped error: %q", wrapped.Error())
	}
	if !strings.Contains(wrapped.Error(), "ram:0x9000: add  r0, r1") {
		t.Fatalf("unexpected mnemonic/body split in wrapped error: %q", wrapped.Error())
	}
	if strings.Contains(wrapped.Error(), "operand print gap") {
		t.Fatalf("unexpected operand gap marker for resolved operand child: %q", wrapped.Error())
	}
}

func TestWrapTranslateUnimplErrorPrintsValueSymbolOperandWhenAvailable(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x9008}, nil)
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		OperandSymbolIDs: []uint64{
			1,
		},
		PrintPieces: []PrintPieceBoundary{
			{Text: "mov"},
			{Text: " "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	ctx.BaseState.EnsureOperand(0)
	ctx.SetSymbolTable(&SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   1,
				Name: "op0",
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    2,
					},
				},
			},
			{
				ID:            2,
				Name:          "imm",
				HeaderElement: elemValueSymHead,
				Body: SymbolBodyBoundary{
					Pattern: &PatternSymbolBoundary{
						Expression: &PatternExprBoundary{
							ElementID: elemIntB,
							Attrs: map[uint32]packedAttribute{
								attrVal: patternIntAttr(attrVal, 0x2a),
							},
						},
					},
				},
			},
		},
	})
	walker := NewParserWalker(ctx)
	walker.BaseState()
	builder := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	builder.State.Walker = walker

	cause := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	wrapped := wrapTranslateUnimplError(cause, builder, 4)
	msg := wrapped.Error()
	if strings.Contains(msg, "<op0?>") {
		t.Fatalf("value symbol operand still rendered as placeholder: %q", msg)
	}
	if !strings.Contains(msg, "ram:0x9008: mov  0x2a") {
		t.Fatalf("value symbol operand print mismatch: %q", msg)
	}
}

func TestWrapTranslateUnimplErrorPrintsVarnodeSymbolOperand(t *testing.T) {
	// Mirrors VarnodeSymbol::print() which outputs getName().
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x9020}, nil)
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		OperandSymbolIDs: []uint64{
			1,
		},
		PrintPieces: []PrintPieceBoundary{
			{Text: "ldr"},
			{Text: " "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	ctx.BaseState.EnsureOperand(0)
	ctx.SetSymbolTable(&SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   1,
				Name: "op0",
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    2,
					},
				},
			},
			{
				ID:            2,
				Name:          "SP",
				HeaderElement: elemVarnodeSymHead,
				Body: SymbolBodyBoundary{
					Varnode: &VarnodeSymbolBoundary{},
				},
			},
		},
	})
	walker := NewParserWalker(ctx)
	walker.BaseState()
	builder := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	builder.State.Walker = walker

	cause := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	wrapped := wrapTranslateUnimplError(cause, builder, 4)
	msg := wrapped.Error()
	if !strings.Contains(msg, "ram:0x9020: ldr  SP") {
		t.Fatalf("varnode symbol operand print mismatch: %q", msg)
	}
}

func TestWrapTranslateUnimplErrorPrintsValueSymbolOperandWithoutPrebuiltChildState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x9009}, nil)
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		OperandSymbolIDs: []uint64{
			1,
		},
		PrintPieces: []PrintPieceBoundary{
			{Text: "mov"},
			{Text: " "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	ctx.SetSymbolTable(&SymbolTableBoundary{
		Symbols: []SymbolBoundary{
			{
				ID:   1,
				Name: "op0",
				Body: SymbolBodyBoundary{
					Operand: &OperandSymbolBoundary{
						Index:               0,
						HasDefiningSymbolID: true,
						DefiningSymbolID:    2,
					},
				},
			},
			{
				ID:            2,
				Name:          "imm",
				HeaderElement: elemValueSymHead,
				Body: SymbolBodyBoundary{
					Pattern: &PatternSymbolBoundary{
						Expression: &PatternExprBoundary{
							ElementID: elemIntB,
							Attrs: map[uint32]packedAttribute{
								attrVal: patternIntAttr(attrVal, 0x2b),
							},
						},
					},
				},
			},
		},
	})
	walker := NewParserWalker(ctx)
	walker.BaseState()
	builder := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	builder.State.Walker = walker

	cause := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	wrapped := wrapTranslateUnimplError(cause, builder, 4)
	msg := wrapped.Error()
	if strings.Contains(msg, "<op0?>") {
		t.Fatalf("value symbol operand still rendered as placeholder without prebuilt child state: %q", msg)
	}
	if !strings.Contains(msg, "ram:0x9009: mov  0x2b") {
		t.Fatalf("value symbol operand print mismatch without prebuilt child state: %q", msg)
	}
}

func TestFormatConstructorPrintBodySkipsFirstWhitespacePiece(t *testing.T) {
	root := NewConstructState()
	root.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "mn"},
			{Text: " "},
			{Text: "dst, "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	child := root.EnsureOperand(0)
	child.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "src"},
		},
	})

	mnemonic, mnemonicGap := formatConstructorPrint(root, constructorPrintMnemonic, 0)
	body, bodyGap := formatConstructorPrint(root, constructorPrintBody, 0)
	if mnemonic != "mn" {
		t.Fatalf("mnemonic split mismatch: got %q want %q", mnemonic, "mn")
	}
	if body != "dst, src" {
		t.Fatalf("body split mismatch: got %q want %q", body, "dst, src")
	}
	if mnemonicGap || bodyGap {
		t.Fatalf("unexpected operand gap flags: mnemonic=%v body=%v", mnemonicGap, bodyGap)
	}
}

func TestFlowThruIndexMnemonicBodyDelegation(t *testing.T) {
	// Mirrors C++ flowthruindex behavior: a root constructor whose single print
	// piece is an operand ref pointing to a subtable child delegates mnemonic/body
	// printing to that child.
	root := NewConstructState()
	root.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		// Single operand ref => FlowThruIndex = 0 (computed by SetConstructor)
		PrintPieces: []PrintPieceBoundary{
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	child := root.EnsureOperand(0)
	child.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "mov"},
			{Text: " "},
			{Text: "r0, r1"},
		},
	})

	mnemonic, mnemonicGap := formatConstructorPrint(root, constructorPrintMnemonic, 0)
	body, bodyGap := formatConstructorPrint(root, constructorPrintBody, 0)
	if mnemonic != "mov" {
		t.Fatalf("flowthru mnemonic mismatch: got %q want %q", mnemonic, "mov")
	}
	if body != "r0, r1" {
		t.Fatalf("flowthru body mismatch: got %q want %q", body, "r0, r1")
	}
	if mnemonicGap || bodyGap {
		t.Fatalf("unexpected gap flags: mnemonic=%v body=%v", mnemonicGap, bodyGap)
	}

	// printAll should NOT use flowthru; it prints the operand normally
	// which recurses into child's full print (all pieces).
	all, allGap := formatConstructorPrint(root, constructorPrintAll, 0)
	if all != "mov r0, r1" {
		t.Fatalf("printAll through flowthru mismatch: got %q want %q", all, "mov r0, r1")
	}
	if allGap {
		t.Fatalf("unexpected gap flag in printAll")
	}
}

func TestFlowThruIndexNonSubtableFallsThrough(t *testing.T) {
	// When flowthruindex is set but the operand is NOT a subtable (no child
	// constructor), the C++ code falls through to normal piece-by-piece print.
	root := NewConstructState()
	root.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	// No child set => operand 0 has no constructor => not a subtable

	mnemonic, mnemonicGap := formatConstructorPrint(root, constructorPrintMnemonic, 0)
	// Should fall through and produce a placeholder since operand is unresolved.
	if mnemonic == "" {
		t.Fatal("expected non-empty result for non-subtable flowthru fallthrough")
	}
	if !mnemonicGap {
		t.Fatal("expected gap flag for unresolved operand in non-subtable flowthru")
	}
}

func TestFlowThruChainedDelegation(t *testing.T) {
	// Two levels of flowthru: root -> mid -> leaf
	root := NewConstructState()
	root.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	mid := root.EnsureOperand(0)
	mid.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	leaf := mid.EnsureOperand(0)
	leaf.SetConstructor(ConstructorBoundary{
		FirstWhitespace: 1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "nop"},
			{Text: " "},
		},
	})

	mnemonic, _ := formatConstructorPrint(root, constructorPrintMnemonic, 0)
	if mnemonic != "nop" {
		t.Fatalf("chained flowthru mnemonic mismatch: got %q want %q", mnemonic, "nop")
	}
	body, _ := formatConstructorPrint(root, constructorPrintBody, 0)
	if body != "" {
		t.Fatalf("chained flowthru body mismatch: got %q want %q", body, "")
	}
}

func TestWrapTranslateUnimplErrorLeavesUnresolvedOperandPlaceholder(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x9010}, nil)
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		PrintPieces: []PrintPieceBoundary{
			{Text: "jmp "},
			{OperandIndex: 0, IsOperandRef: true},
		},
	})
	walker := NewParserWalker(ctx)
	walker.BaseState()
	builder := NewSleighBuilder(RuntimeContext{}, 0, -1, BuilderHooks{})
	builder.State.Walker = walker

	cause := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	wrapped := wrapTranslateUnimplError(cause, builder, 3)
	msg := wrapped.Error()
	if !strings.Contains(msg, "<op0?>") {
		t.Fatalf("missing unresolved operand placeholder: %q", msg)
	}
	if strings.Contains(msg, "operand print gap") {
		t.Fatalf("unexpected Go-only operand gap marker: %q", msg)
	}
}

func TestWrapTranslateUnimplErrorLeavesImplementedFailuresUntouched(t *testing.T) {
	original := fmt.Errorf("builder failed on malformed constructor")
	got := wrapTranslateUnimplError(original, nil, 5)
	if got != original {
		t.Fatalf("non-unimplemented failure was unexpectedly wrapped: got %T", got)
	}
}

func TestWrapTranslateUnimplErrorDoesNotPromoteBySubstring(t *testing.T) {
	original := fmt.Errorf("this path is unimplemented but not typed")
	got := wrapTranslateUnimplError(original, nil, 5)
	if got != original {
		t.Fatalf("substring-only error was unexpectedly wrapped: got %T", got)
	}
}

func TestWrapTranslateUnimplErrorDoesNotPromoteBuilderSentinelWithoutTypedError(t *testing.T) {
	original := fmt.Errorf("%w: BUILD", ErrBuilderUnimplemented)
	got := wrapTranslateUnimplError(original, nil, 5)
	if got != original {
		t.Fatalf("builder sentinel-only error was unexpectedly wrapped: got %T", got)
	}
}

func TestWrapTranslateUnimplErrorDoesNotUnwrapNestedTypedError(t *testing.T) {
	inner := newUnimplError(ErrBuilderUnimplemented, "directive BUILD unresolved")
	original := fmt.Errorf("outer wrapper: %w", inner)
	got := wrapTranslateUnimplError(original, nil, 5)
	if got != original {
		t.Fatalf("wrapped typed error was unexpectedly rewritten: got %T", got)
	}
	if inner.Error() != "directive BUILD unresolved" {
		t.Fatalf("inner typed error was unexpectedly mutated: %q", inner.Error())
	}
	if inner.HasInstructionLength {
		t.Fatalf("inner typed error unexpectedly gained instruction length: %+v", inner)
	}
}

func TestWrapTranslateUnimplErrorRewritesExistingTypedError(t *testing.T) {
	original := &UnimplError{
		Explain:              "Instruction not implemented in pcode:\\n ram:0x1234: test",
		InstructionLength:    6,
		HasInstructionLength: true,
		Cause:                fmt.Errorf("%w: BUILD", ErrBuilderUnimplemented),
	}
	got := wrapTranslateUnimplError(original, nil, 10)
	terr, ok := got.(*UnimplError)
	if !ok {
		t.Fatalf("wrapTranslateUnimplError() returned %T, want *UnimplError", got)
	}
	if terr != original {
		t.Fatalf("typed unimplemented error pointer mismatch: got %p want %p", terr, original)
	}
	want := "Instruction not implemented in pcode:\\n ram:0x1234: test"
	if terr.Error() != want {
		t.Fatalf("rewritten explain mismatch: got %q want %q", terr.Error(), want)
	}
	if !terr.HasInstructionLength || terr.InstructionLength != 10 {
		t.Fatalf("rewritten instruction length mismatch: has=%v len=%d want=10", terr.HasInstructionLength, terr.InstructionLength)
	}
	if !errors.Is(terr, ErrBuilderUnimplemented) {
		t.Fatalf("rewritten typed error lost builder unimplemented cause: %v", terr)
	}
}

func TestWrapTranslateUnimplErrorRewritesNonBuilderTypedUnimplemented(t *testing.T) {
	original := newUnimplError(ErrResolveHandlesUnimplemented, "parser context is nil")
	got := wrapTranslateUnimplError(original, nil, 5)
	terr, ok := got.(*UnimplError)
	if !ok {
		t.Fatalf("wrapTranslateUnimplError() returned %T, want *UnimplError", got)
	}
	if terr != original {
		t.Fatalf("typed unimplemented error pointer mismatch: got %p want %p", terr, original)
	}
	want := "parser context is nil"
	if terr.Error() != want {
		t.Fatalf("rewritten explain mismatch: got %q want %q", terr.Error(), want)
	}
	if !terr.HasInstructionLength || terr.InstructionLength != 5 {
		t.Fatalf("rewritten instruction length mismatch: has=%v len=%d want=5", terr.HasInstructionLength, terr.InstructionLength)
	}
	if !errors.Is(terr, ErrResolveHandlesUnimplemented) {
		t.Fatalf("rewritten typed error lost original unimplemented cause: %v", terr)
	}
}

func TestBuildUnimplementedConstructReturnsUnimplErrorWithZeroLength(t *testing.T) {
	// Mirrors PcodeBuilder::build(nullptr) -> throw UnimplError("", 0).
	// When a child constructor has no main section (getTempl() returns nullptr),
	// Build() must return *UnimplError with empty explain and InstructionLength=0.
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetParserState(ParseStatePcode)
	ctx.BaseState.Length = 4
	// Constructor with no MainSection -- simulates getTempl() returning nullptr
	ctx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		// MainSection intentionally nil
	})
	// Add a child that has a constructor but no main section
	child := &ConstructState{}
	child.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		// MainSection intentionally nil
	})
	ctx.BaseState.Children = []*ConstructState{child}

	walker := NewParserWalker(ctx)
	walker.BaseState()
	b := NewSleighBuilder(RuntimeContext{Instruction: address.Address{Space: ram, Offset: 0x1000}}, 0, -1, BuilderHooks{})
	b.State.Walker = walker

	// BUILD operand 0 will find child with constructor but no main section
	op := OpTplBoundary{
		Opcode: "BUILD",
		Inputs: []VarnodeTplBoundary{{
			Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
		}},
	}
	err := b.AppendBuild(op, -1)
	if err == nil {
		t.Fatal("AppendBuild() returned nil for constructor with no main section")
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("AppendBuild() error type = %T, want *UnimplError", err)
	}
	if !uerr.HasInstructionLength {
		t.Fatal("unimpl error missing HasInstructionLength flag")
	}
	if uerr.InstructionLength != 0 {
		t.Fatalf("unimpl error instruction length = %d, want 0", uerr.InstructionLength)
	}
}

func TestWrapTranslateUnimplErrorIgnoresDelaySlotInfraError(t *testing.T) {
	// Mirrors C++ parity: delaySlot infrastructure failures are LowlevelError,
	// NOT UnimplError, so wrapTranslateUnimplError must pass them through
	// without rewriting explain/instruction_length.
	infraErr := fmt.Errorf("Could not obtain cached delay slot instruction at ram:0x5004")
	wrapped := wrapTranslateUnimplError(infraErr, nil, 8)
	if wrapped != infraErr {
		t.Fatalf("wrapTranslateUnimplError rewrote infrastructure error: got %v, want %v", wrapped, infraErr)
	}
	var uerr *UnimplError
	if errors.As(wrapped, &uerr) {
		t.Fatalf("infrastructure error was promoted to *UnimplError: %v", wrapped)
	}
}

func TestWrapTranslateUnimplErrorIgnoresCrossBuildInfraError(t *testing.T) {
	// Mirrors C++ parity: crossbuild infrastructure failures are LowlevelError,
	// NOT UnimplError, so wrapTranslateUnimplError must pass them through.
	infraErr := fmt.Errorf("Could not obtain cached crossbuild instruction at ram:0x9000")
	wrapped := wrapTranslateUnimplError(infraErr, nil, 4)
	if wrapped != infraErr {
		t.Fatalf("wrapTranslateUnimplError rewrote infrastructure error: got %v, want %v", wrapped, infraErr)
	}
}

func TestDelaySlotBuildFailurePropagatesAsUnimplError(t *testing.T) {
	// When build() inside delaySlot fails with *UnimplError (e.g. unimplemented
	// constructor), the error must propagate as *UnimplError so that
	// wrapTranslateUnimplError at the TranslateSubtable boundary can rewrite it.
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	sourceAddr := address.Address{Space: ram, Offset: 0x7000}
	targetAddr := address.Address{Space: ram, Offset: 0x7004}

	sourceCtx := NewParserContext(sourceAddr, nil)
	sourceCtx.SetParserState(ParseStatePcode)
	sourceCtx.SetDelaySlot(4)
	sourceCtx.BaseState.Length = 4
	sourceCtx.BaseState.SetConstructor(ConstructorBoundary{
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				OpcodeID: int64(pcode.CPUI_INDIRECT),
				Opcode:   "DELAY_SLOT",
			}},
		},
	})

	// Target constructor has a child with no main section -> build(nullptr)
	targetCtx := NewParserContext(targetAddr, nil)
	targetCtx.SetParserState(ParseStatePcode)
	targetCtx.BaseState.Length = 4
	targetChild := &ConstructState{}
	targetChild.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		// MainSection nil -> triggers UnimplError("",0)
	})
	targetCtx.BaseState.SetConstructor(ConstructorBoundary{
		FirstWhitespace: -1,
		MainSection: &ConstructTplBoundary{
			Ops: []OpTplBoundary{{
				Opcode: "BUILD",
				Inputs: []VarnodeTplBoundary{{
					Offset: ConstBoundary{Kind: ConstKindReal, Value: 0},
				}},
			}},
		},
	})
	targetCtx.BaseState.Children = []*ConstructState{targetChild}

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
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("DelaySlot() build failure error type = %T, want *UnimplError", err)
	}
	// The *UnimplError should carry instruction_length=0 from the inner build(nullptr)
	if !uerr.HasInstructionLength {
		t.Fatal("inner build UnimplError missing HasInstructionLength")
	}
	if uerr.InstructionLength != 0 {
		t.Fatalf("inner build UnimplError instruction length = %d, want 0", uerr.InstructionLength)
	}
}

// TestWrapTranslateUnimplErrorRewritesUnimplError verifies that wrapTranslateUnimplError
// rewrites explain and instructionLength on *UnimplError in place, mirroring
// the C++ catch(UnimplError&) branch in Sleigh::oneInstruction().
func TestWrapTranslateUnimplErrorRewritesUnimplError(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 3, AddrSize: 8, WordSize: 1}

	// Build a minimal walker so formatTranslateUnimplExplain can produce text.
	instruction := address.Address{Space: ram, Offset: 0x9000}
	ctx := NewParserContext(instruction, constSpace)
	ctx.SetParserState(ParseStatePcode)
	ctx.BaseState.Length = 4
	ctx.BaseState.Constructor = &ConstructorBoundary{
		ConstructorID:   0,
		FirstWhitespace: 1,
		PrintPieces:     []PrintPieceBoundary{{IsOperandRef: false, Text: "NOP"}, {IsOperandRef: false, Text: " "}},
	}
	walker := NewParserWalker(ctx)
	walker.BaseState()

	builder := &SleighBuilder{}
	builder.State.Walker = walker

	original := newUnimplError(ErrBuilderUnimplemented, "original explain")
	fallOffset := 8

	result := wrapTranslateUnimplError(original, builder, fallOffset)

	// Must return the same *UnimplError pointer (rewritten in place), not a new wrapper.
	got, ok := result.(*UnimplError)
	if !ok {
		t.Fatalf("wrapTranslateUnimplError() returned %T, want *UnimplError", result)
	}
	if got != original {
		t.Fatal("wrapTranslateUnimplError() did not rewrite the original *UnimplError in place")
	}
	// instructionLength must be updated to fallOffset.
	if !got.HasInstructionLength {
		t.Fatal("wrapTranslateUnimplError() did not set HasInstructionLength")
	}
	if got.InstructionLength != fallOffset {
		t.Fatalf("wrapTranslateUnimplError() InstructionLength = %d, want %d", got.InstructionLength, fallOffset)
	}
	// explain must include the walker context text.
	if !strings.Contains(got.Explain, "Instruction not implemented in pcode:") {
		t.Fatalf("wrapTranslateUnimplError() Explain missing preamble: %q", got.Explain)
	}
}

// TestWrapTranslateUnimplErrorPassesThroughPlainError verifies that a plain
// infrastructure error (non-*UnimplError) is returned unchanged, mirroring
// C++ LowlevelError which is NOT caught by catch(UnimplError&).
func TestWrapTranslateUnimplErrorPassesThroughPlainError(t *testing.T) {
	plain := fmt.Errorf("infrastructure failure: disk read error")
	result := wrapTranslateUnimplError(plain, nil, 4)
	if result != plain {
		t.Fatalf("wrapTranslateUnimplError() did not pass plain error through unchanged: got %v", result)
	}
	// Must not be promoted to *UnimplError.
	if _, ok := result.(*UnimplError); ok {
		t.Fatal("wrapTranslateUnimplError() promoted plain error to *UnimplError, must not")
	}
}

// TestWrapTranslateUnimplErrorPassesThroughWrappedNonUnimplError verifies that
// an error wrapping a non-*UnimplError (e.g. fmt.Errorf with %w) also passes
// through unchanged. The C++ catch(UnimplError&) only matches exact type, not
// derived or wrapped types.
func TestWrapTranslateUnimplErrorPassesThroughWrappedNonUnimplError(t *testing.T) {
	inner := errors.New("unexpected condition")
	wrapped := fmt.Errorf("outer: %w", inner)
	result := wrapTranslateUnimplError(wrapped, nil, 4)
	if result != wrapped {
		t.Fatalf("wrapTranslateUnimplError() did not pass wrapped error through unchanged: got %v", result)
	}
	if _, ok := result.(*UnimplError); ok {
		t.Fatal("wrapTranslateUnimplError() promoted wrapped error to *UnimplError, must not")
	}
	// errors.Is chain must remain intact.
	if !errors.Is(result, inner) {
		t.Fatal("wrapTranslateUnimplError() broke the wrapped error chain")
	}
}
