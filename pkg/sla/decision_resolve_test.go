package sla

import (
	"strings"
	"testing"

	"gosleigh/pkg/address"
)

func TestResolveSubtableDecisionUsesInstructionBits(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{ConstructorID: 22},
			{ConstructorID: 11},
		},
		Decision: &DecisionNodeBoundary{
			StartBit: 0,
			Size:     8,
			Children: make([]DecisionNodeBoundary, 256),
		},
	}
	subtable.Decision.Children[0x44] = DecisionNodeBoundary{
		Pairs: []DecisionPairBoundary{{
			ConstructorID: 11,
			Pattern: &DisjointPatternBoundary{
				ElementID: elemInstructPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 0,
				},
			},
		}},
	}

	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x44})
	ctx.BaseState.Offset = 1

	walker := NewParserWalker(ctx)
	walker.BaseState()

	constructor, err := ResolveSubtableDecision(subtable, walker)
	if err != nil {
		t.Fatalf("ResolveSubtableDecision() error: %v", err)
	}
	if constructor.ConstructorID != 11 {
		t.Fatalf("ResolveSubtableDecision() chose constructor %d, want 11", constructor.ConstructorID)
	}
}

func TestResolveSubtableDecisionUsesContextBits(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{ConstructorID: 7}},
		Decision: &DecisionNodeBoundary{
			Context:  true,
			StartBit: 0,
			Size:     8,
			Children: make([]DecisionNodeBoundary, 256),
		},
	}
	subtable.Decision.Children[0x7a] = DecisionNodeBoundary{
		Pairs: []DecisionPairBoundary{{
			ConstructorID: 7,
			Pattern: &DisjointPatternBoundary{
				ElementID: elemContextPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 0,
				},
			},
		}},
	}

	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x2000}, nil)
	ctx.SetContextWords([]uint64{0x7a00000000000000})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	constructor, err := ResolveSubtableDecision(subtable, walker)
	if err != nil {
		t.Fatalf("ResolveSubtableDecision() error: %v", err)
	}
	if constructor.ConstructorID != 7 {
		t.Fatalf("ResolveSubtableDecision() chose constructor %d, want 7", constructor.ConstructorID)
	}
}

func TestResolveDecisionNodeReturnsFirstMatchingConstructor(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{ConstructorID: 9},
			{ConstructorID: 7},
		},
	}
	node := &DecisionNodeBoundary{
		Pairs: []DecisionPairBoundary{
			{
				ConstructorID: 7,
				Pattern: &DisjointPatternBoundary{
					ElementID: elemInstructPat,
					Block: &PatternBlockBoundary{
						Offset:      0,
						NonZeroSize: 1,
						MaskWords: []PatternMaskWordBoundary{{
							Mask: 0xff000000,
							Val:  0x55000000,
						}},
					},
				},
			},
			{
				ConstructorID: 9,
				Pattern: &DisjointPatternBoundary{
					ElementID: elemInstructPat,
					Block: &PatternBlockBoundary{
						Offset:      0,
						NonZeroSize: 0,
					},
				},
			},
		},
	}

	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x3000}, nil)
	ctx.SetInstructionBytes([]byte{0x55, 0x00, 0x00, 0x00})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	constructor, err := ResolveDecisionNode(subtable, node, walker)
	if err != nil {
		t.Fatalf("ResolveDecisionNode() error: %v", err)
	}
	if constructor.ConstructorID != 7 {
		t.Fatalf("ResolveDecisionNode() chose constructor %d, want first match 7", constructor.ConstructorID)
	}
}

func TestResolveDecisionNodeErrorsWhenNoPatternMatches(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{{ConstructorID: 3}},
	}
	node := &DecisionNodeBoundary{
		Pairs: []DecisionPairBoundary{{
			ConstructorID: 3,
			Pattern: &DisjointPatternBoundary{
				ElementID: elemInstructPat,
				Block: &PatternBlockBoundary{
					Offset:      0,
					NonZeroSize: 1,
					MaskWords: []PatternMaskWordBoundary{{
						Mask: 0xff000000,
						Val:  0x66000000,
					}},
				},
			},
		}},
	}

	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x4000}, nil)
	ctx.SetInstructionBytes([]byte{0x55, 0x00, 0x00, 0x00})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	_, err := ResolveDecisionNode(subtable, node, walker)
	if err == nil {
		t.Fatal("ResolveDecisionNode() succeeded unexpectedly")
	}
	if !strings.Contains(err.Error(), "unable to resolve constructor") {
		t.Fatalf("ResolveDecisionNode() error = %q, want unable to resolve constructor", err)
	}
}

func TestResolveDecisionNodeMatchesPersisted32BitPatternWords(t *testing.T) {
	subtable := &SubtableBoundary{
		Constructors: []ConstructorBoundary{
			{ConstructorID: 0},
			{ConstructorID: 1},
		},
	}
	node := &DecisionNodeBoundary{
		Pairs: []DecisionPairBoundary{
			{
				ConstructorID: 0,
				Pattern: &DisjointPatternBoundary{
					ElementID: elemInstructPat,
					Block: &PatternBlockBoundary{
						Offset:      0,
						NonZeroSize: 1,
						MaskWords: []PatternMaskWordBoundary{{
							Mask: 0xff000000,
							Val:  0xea000000,
						}},
					},
				},
			},
			{
				ConstructorID: 1,
				Pattern: &DisjointPatternBoundary{
					ElementID: elemInstructPat,
					Block: &PatternBlockBoundary{
						Offset:      0,
						NonZeroSize: 1,
						MaskWords: []PatternMaskWordBoundary{{
							Mask: 0xff000000,
							Val:  0xa9000000,
						}},
					},
				},
			},
		},
	}

	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	tests := []struct {
		name  string
		bytes []byte
		want  uint64
	}{
		{name: "NOP", bytes: []byte{0xea, 0x00, 0x00, 0x00}, want: 0},
		{name: "LDA_imm", bytes: []byte{0xa9, 0x42, 0x00, 0x00}, want: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := NewParserContext(address.Address{Space: ram, Offset: 0x5000}, nil)
			ctx.SetInstructionBytes(tc.bytes)

			walker := NewParserWalker(ctx)
			walker.BaseState()

			constructor, err := ResolveDecisionNode(subtable, node, walker)
			if err != nil {
				t.Fatalf("ResolveDecisionNode() error: %v", err)
			}
			if constructor.ConstructorID != tc.want {
				t.Fatalf("ResolveDecisionNode() chose constructor %d, want %d", constructor.ConstructorID, tc.want)
			}
		})
	}
}
