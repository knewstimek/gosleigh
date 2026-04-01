package sla

import (
	"testing"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

func TestParserContextPackingAndAddressAccessors(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	constSpace := &address.Space{Name: "const", Kind: address.SpaceKindConstant, Index: 2, AddrSize: 8, WordSize: 1}

	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, constSpace)
	ctx.SetNaddr(address.Address{Space: ram, Offset: 0x1004})
	ctx.SetN2addr(address.Address{Space: ram, Offset: 0x1008})
	ctx.SetRefAddr(address.Address{Space: ram, Offset: 0x1010})
	ctx.SetDestAddr(address.Address{Space: ram, Offset: 0x1020})
	ctx.SetInstructionBytes([]byte{0x11, 0x22, 0x33, 0x44})
	ctx.SetContextWords([]uint64{0x0102030405060708})
	ctx.BaseState.Offset = 1

	walker := NewParserWalker(ctx)
	walker.BaseState()

	if got := walker.GetAddr(); got != (address.Address{Space: ram, Offset: 0x1000}) {
		t.Fatalf("unexpected addr: %+v", got)
	}
	if got := walker.GetNaddr(); got != (address.Address{Space: ram, Offset: 0x1004}) {
		t.Fatalf("unexpected naddr: %+v", got)
	}
	if got := walker.GetN2addr(); got != (address.Address{Space: ram, Offset: 0x1008}) {
		t.Fatalf("unexpected n2addr: %+v", got)
	}
	if got := walker.GetRefAddr(); got != (address.Address{Space: ram, Offset: 0x1010}) {
		t.Fatalf("unexpected refaddr: %+v", got)
	}
	if got := walker.GetDestAddr(); got != (address.Address{Space: ram, Offset: 0x1020}) {
		t.Fatalf("unexpected destaddr: %+v", got)
	}
	if got := walker.GetCurSpace(); got != ram {
		t.Fatalf("unexpected current space: %+v", got)
	}
	if got := walker.GetConstSpace(); got != constSpace {
		t.Fatalf("unexpected const space: %+v", got)
	}

	instrBytes, err := walker.GetInstructionBytes(0, 2)
	if err != nil {
		t.Fatalf("GetInstructionBytes() error: %v", err)
	}
	if instrBytes != 0x2233 {
		t.Fatalf("unexpected instruction bytes: got 0x%x", instrBytes)
	}

	instrBits, err := walker.GetInstructionBits(0, 8)
	if err != nil {
		t.Fatalf("GetInstructionBits() error: %v", err)
	}
	if instrBits != 0x22 {
		t.Fatalf("unexpected instruction bits: got 0x%x", instrBits)
	}

	ctxBytes, err := walker.GetContextBytes(0, 4)
	if err != nil {
		t.Fatalf("GetContextBytes() error: %v", err)
	}
	if ctxBytes != 0x01020304 {
		t.Fatalf("unexpected context bytes: got 0x%x", ctxBytes)
	}

	ctxBits, err := walker.GetContextBits(0, 16)
	if err != nil {
		t.Fatalf("GetContextBits() error: %v", err)
	}
	if ctxBits != 0x0102 {
		t.Fatalf("unexpected context bits: got 0x%x", ctxBits)
	}
}

func TestParserWalkerConstructorRelativeOffsetsAndSections(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x2000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30, 0x40})

	root := ctx.BaseState
	root.Offset = 1
	root.Length = 2
	root.ConstructorID = 7
	root.SetSectionID(5)

	child := root.EnsureOperand(0)
	child.Offset = 2
	child.Length = 1
	child.ConstructorID = 11
	child.SetSectionID(9)

	walker := NewParserWalker(ctx)
	walker.BaseState()

	off, err := walker.Point.OperandOffset(0)
	if err != nil {
		t.Fatalf("OperandOffset() error: %v", err)
	}
	if off != 3 {
		t.Fatalf("unexpected operand offset: got %d", off)
	}

	rootBytes, err := walker.GetInstructionBytes(0, 1)
	if err != nil {
		t.Fatalf("GetInstructionBytes() error: %v", err)
	}
	if rootBytes != 0x20 {
		t.Fatalf("unexpected root instruction byte: got 0x%x", rootBytes)
	}

	section, ok := walker.CurrentSection()
	if !ok || section != 5 {
		t.Fatalf("unexpected root section: got %d ok=%v", section, ok)
	}

	if err := walker.PushOperand(0); err != nil {
		t.Fatalf("PushOperand() error: %v", err)
	}
	childSection, ok := walker.CurrentSection()
	if !ok || childSection != 9 {
		t.Fatalf("unexpected child section: got %d ok=%v", childSection, ok)
	}

	childBytes, err := walker.GetInstructionBytes(0, 1)
	if err != nil {
		t.Fatalf("GetInstructionBytes() error: %v", err)
	}
	if childBytes != 0x30 {
		t.Fatalf("unexpected child instruction byte: got 0x%x", childBytes)
	}

	walker.PopOperand()
	if walker.Point != root {
		t.Fatalf("expected to return to root state")
	}
}

func TestParserWalkerOutOfBandState(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x3000}, nil)
	root := ctx.BaseState
	root.Offset = 1
	root.Length = 2
	child := root.EnsureOperand(0)
	child.Offset = 2
	child.Length = 1

	other := NewParserWalker(ctx)
	other.BaseState()
	if err := other.PushOperand(0); err != nil {
		t.Fatalf("PushOperand() error: %v", err)
	}

	temp := NewConstructState()
	walker := NewParserWalker(ctx)
	if err := walker.SetOutOfBandState(root, 0, temp, other); err != nil {
		t.Fatalf("SetOutOfBandState() error: %v", err)
	}
	if walker.Point != temp {
		t.Fatalf("expected walker point to use temp state")
	}
	if temp.Offset != 2 || temp.Length != 2 {
		t.Fatalf("unexpected out-of-band state: %+v", temp)
	}
}

func TestParserWalkerOutOfBandStateConstructorRelativeWithoutChild(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x3000}, nil)
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 7,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:          0,
			RelativeOffset: 3,
			OffsetBase:     -1,
			MinimumLength:  1,
		}},
	}}})
	root := ctx.BaseState
	root.Offset = 0x40
	root.Length = 5
	root.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{7}})

	other := NewParserWalker(ctx)
	other.BaseState()

	temp := NewConstructState()
	walker := NewParserWalker(ctx)
	if err := walker.SetOutOfBandState(root, 0, temp, other); err != nil {
		t.Fatalf("SetOutOfBandState() error: %v", err)
	}
	if temp.Offset != 0x43 || temp.Length != 5 {
		t.Fatalf("unexpected constructor-relative out-of-band state: %+v", temp)
	}
}

func TestParserWalkerOutOfBandStateMissingChildForNonRelativeOperand(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x3000}, nil)
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 7,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:          0,
			RelativeOffset: 0,
			OffsetBase:     0,
			MinimumLength:  1,
		}},
	}}})
	root := ctx.BaseState
	root.Offset = 0x10
	root.Length = 2
	root.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{7}})

	other := NewParserWalker(ctx)
	other.BaseState()

	temp := NewConstructState()
	walker := NewParserWalker(ctx)
	if err := walker.SetOutOfBandState(root, 0, temp, other); err == nil {
		t.Fatal("SetOutOfBandState() succeeded without child state for non-relative operand")
	}
}

func TestConstructStateTemplateSelection(t *testing.T) {
	state := NewConstructState()
	main := ConstructTplBoundary{
		Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_COPY), Opcode: pcode.CPUI_COPY.String()}},
	}
	named := ConstructTplBoundary{
		Ops: []OpTplBoundary{{OpcodeID: int64(pcode.CPUI_INT_ADD), Opcode: pcode.CPUI_INT_ADD.String()}},
	}
	state.SetConstructor(ConstructorBoundary{
		MainSection: &main,
		NamedSections: []NamedSectionBoundary{{
			SectionID: 7,
			Template:  named,
		}},
	})

	selected, ok := state.TemplateForSection(-1)
	if !ok || selected == nil || len(selected.Ops) != 1 || selected.Ops[0].Opcode != pcode.CPUI_COPY.String() {
		t.Fatalf("unexpected main template selection: ok=%v selected=%+v", ok, selected)
	}

	selected, ok = state.TemplateForSection(7)
	if !ok || selected == nil || len(selected.Ops) != 1 || selected.Ops[0].Opcode != pcode.CPUI_INT_ADD.String() {
		t.Fatalf("unexpected named template selection: ok=%v selected=%+v", ok, selected)
	}

	if _, ok := state.TemplateForSection(9); ok {
		t.Fatal("expected missing named section to return false")
	}
}
