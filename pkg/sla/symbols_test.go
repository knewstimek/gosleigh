package sla

import "testing"

func TestDecodeBoundariesPayload(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrAlign, 4)
	payload.writeUnsigned(attrUniqBase, 0x2000)
	payload.writeUnsigned(attrNumSections, 1)
	payload.openElement(elemSourceFiles)
	payload.openElement(elemSourceFile)
	payload.writeString(attrName, "core.sinc")
	payload.writeSigned(attrIndex, 0)
	payload.closeElement(elemSourceFile)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 2)
	payload.writeSigned(attrSymbolSize, 3)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemUserOpHead)
	payload.writeString(attrName, "syscall")
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemUserOpHead)
	payload.openElement(elemValueSymHead)
	payload.writeString(attrName, "imm")
	payload.writeUnsigned(attrID, 2)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemValueSymHead)
	payload.openElement(elemSubtableSymHead)
	payload.writeString(attrName, "instruction")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 1)
	payload.closeElement(elemSubtableSymHead)
	payload.openElement(elemUserOp)
	payload.writeUnsigned(attrID, 0)
	payload.writeSigned(attrIndex, 7)
	payload.closeElement(elemUserOp)
	payload.openElement(elemValueSym)
	payload.writeUnsigned(attrID, 2)
	payload.openElement(elemPlusExp)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 1)
	payload.closeElement(elemIntB)
	payload.openElement(elemMinusExp)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 2)
	payload.closeElement(elemIntB)
	payload.closeElement(elemMinusExp)
	payload.closeElement(elemPlusExp)
	payload.closeElement(elemValueSym)
	payload.openElement(elemSubtableSym)
	payload.writeUnsigned(attrID, 1)
	payload.writeSigned(attrNumCT, 1)
	payload.openElement(elemConstructor)
	payload.writeUnsigned(attrParent, 1)
	payload.writeSigned(attrFirst, 0)
	payload.writeSigned(attrLength, 4)
	payload.writeSigned(attrSource, 0)
	payload.writeSigned(attrLine, 77)
	payload.openElement(elemOper)
	payload.writeUnsigned(attrID, 11)
	payload.closeElement(elemOper)
	payload.openElement(elemPrint)
	payload.writeString(attrPiece, "mov")
	payload.closeElement(elemPrint)
	payload.openElement(elemOpPrint)
	payload.writeSigned(attrID, 0)
	payload.closeElement(elemOpPrint)
	payload.openElement(elemContextOp)
	payload.writeSigned(attrI, 1)
	payload.writeSigned(attrShift, 2)
	payload.writeUnsigned(attrMask, 3)
	payload.openElement(elemOperandExp)
	payload.writeSigned(attrIndex, 0)
	payload.closeElement(elemOperandExp)
	payload.closeElement(elemContextOp)
	payload.openElement(elemCommit)
	payload.writeUnsigned(attrID, 1)
	payload.writeSigned(attrNumber, 0)
	payload.writeUnsigned(attrMask, 1)
	payload.writeBool(attrFlow, true)
	payload.closeElement(elemCommit)
	payload.openElement(elemConstructTpl)
	payload.writeSigned(attrDelay, 2)
	payload.writeSigned(attrLabels, 1)
	payload.openElement(elemHandleTpl)
	payload.writeConstReal(0)
	payload.writeConstReal(4)
	payload.writeConstReal(0)
	payload.writeConstReal(0x20)
	payload.writeConstReal(4)
	payload.writeConstReal(0)
	payload.writeConstReal(0x30)
	payload.closeElement(elemHandleTpl)
	payload.openElement(elemOpTpl)
	payload.writeSigned(attrCode, 19)
	payload.openElement(elemVarnodeTpl)
	payload.writeConstSpaceID(1)
	payload.writeConstReal(0x10)
	payload.writeConstReal(4)
	payload.closeElement(elemVarnodeTpl)
	payload.openElement(elemVarnodeTpl)
	payload.writeConstHandle(0, 1, 0)
	payload.writeConstRelative(8)
	payload.writeConstReal(4)
	payload.closeElement(elemVarnodeTpl)
	payload.closeElement(elemOpTpl)
	payload.closeElement(elemConstructTpl)
	payload.openElement(elemConstructTpl)
	payload.writeSigned(attrSection, 0)
	payload.openElement(elemNull)
	payload.closeElement(elemNull)
	payload.openElement(elemOpTpl)
	payload.writeSigned(attrCode, 20)
	payload.openElement(elemNull)
	payload.closeElement(elemNull)
	payload.openElement(elemVarnodeTpl)
	payload.writeConstStart()
	payload.writeConstNext()
	payload.writeConstReal(8)
	payload.closeElement(elemVarnodeTpl)
	payload.closeElement(elemOpTpl)
	payload.closeElement(elemConstructTpl)
	payload.closeElement(elemConstructor)
	payload.openElement(elemDecision)
	payload.writeSigned(attrNumber, 1)
	payload.writeBool(attrContext, false)
	payload.writeSigned(attrStartBit, 3)
	payload.writeSigned(attrSize, 2)
	payload.openElement(elemPair)
	payload.writeSigned(attrID, 0)
	payload.openElement(elemOrPat)
	payload.openElement(elemInstructPat)
	payload.openElement(elemPatBlock)
	payload.writeSigned(attrOff, 0)
	payload.writeSigned(attrNonZero, 1)
	payload.openElement(elemMaskWord)
	payload.writeUnsigned(attrMask, 0xff)
	payload.writeUnsigned(attrVal, 0x90)
	payload.closeElement(elemMaskWord)
	payload.closeElement(elemPatBlock)
	payload.closeElement(elemInstructPat)
	payload.closeElement(elemOrPat)
	payload.closeElement(elemPair)
	payload.closeElement(elemDecision)
	payload.closeElement(elemSubtableSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	if len(boundaries.SourceFiles) != 1 {
		t.Fatalf("unexpected sourcefile count: got %d", len(boundaries.SourceFiles))
	}
	if boundaries.SourceFiles[0].Name != "core.sinc" {
		t.Fatalf("unexpected sourcefile name: got %q", boundaries.SourceFiles[0].Name)
	}
	if len(boundaries.SymbolTable.Scopes) != 2 {
		t.Fatalf("unexpected scope count: got %d", len(boundaries.SymbolTable.Scopes))
	}
	if len(boundaries.SymbolTable.Symbols) != 3 {
		t.Fatalf("unexpected symbol count: got %d", len(boundaries.SymbolTable.Symbols))
	}
	if boundaries.SymbolTable.Symbols[0].Body.UserOp == nil || boundaries.SymbolTable.Symbols[0].Body.UserOp.Index != 7 {
		t.Fatal("userop boundary did not decode expected index")
	}
	if boundaries.SymbolTable.Symbols[1].Body.Pattern == nil || boundaries.SymbolTable.Symbols[1].Body.Pattern.Expression == nil {
		t.Fatal("value symbol pattern expression boundary missing")
	}
	if boundaries.SymbolTable.Symbols[1].Body.Pattern.Expression.ElementID != elemPlusExp {
		t.Fatalf("unexpected value symbol root expression: got %d", boundaries.SymbolTable.Symbols[1].Body.Pattern.Expression.ElementID)
	}
	subtable := boundaries.SymbolTable.Symbols[2].Body.Subtable
	if subtable == nil {
		t.Fatal("subtable boundary missing")
	}
	if subtable.ConstructorCount != 1 {
		t.Fatalf("unexpected constructor count: got %d", subtable.ConstructorCount)
	}
	if len(subtable.Constructors) != 1 {
		t.Fatalf("unexpected decoded constructors: got %d", len(subtable.Constructors))
	}
	constructor := subtable.Constructors[0]
	if constructor.ParentSymbolID != 1 {
		t.Fatalf("unexpected constructor parent id: got %d", constructor.ParentSymbolID)
	}
	if constructor.LineNumber != 77 {
		t.Fatalf("unexpected constructor line: got %d", constructor.LineNumber)
	}
	if len(constructor.OperandSymbolIDs) != 1 || constructor.OperandSymbolIDs[0] != 11 {
		t.Fatalf("unexpected constructor operand ids: got %v", constructor.OperandSymbolIDs)
	}
	if len(constructor.PrintPieces) != 2 {
		t.Fatalf("unexpected printpiece count: got %d", len(constructor.PrintPieces))
	}
	if constructor.PrintPieces[1].OperandIndex != 0 || !constructor.PrintPieces[1].IsOperandRef {
		t.Fatal("constructor opprint boundary did not decode operand reference")
	}
	if len(constructor.ContextOps) != 1 {
		t.Fatalf("unexpected context op count: got %d", len(constructor.ContextOps))
	}
	ctxOp := constructor.ContextOps[0]
	// Raw SLA attrI=1 (C++ 32-bit word index 1, odd = lower half of Go uint64[0]).
	// decodeContextOp converts: goNum = 1/2 = 0; shift and mask are unchanged for odd words.
	if ctxOp.Num != 0 || ctxOp.Shift != 2 || ctxOp.Mask != 3 {
		t.Fatalf("unexpected context op num/shift/mask: %+v", ctxOp)
	}
	if ctxOp.Expression == nil || ctxOp.Expression.ElementID != elemOperandExp {
		t.Fatalf("unexpected context op expression: %+v", ctxOp.Expression)
	}
	if len(constructor.ContextCommits) != 1 || !constructor.ContextCommits[0].Flow {
		t.Fatalf("unexpected context commit boundaries: %+v", constructor.ContextCommits)
	}
	if constructor.MainSection == nil {
		t.Fatal("constructor main section was not decoded")
	}
	if constructor.MainSection.DelaySlot != 2 || constructor.MainSection.NumLabels != 1 {
		t.Fatalf("unexpected main section metadata: delay=%d labels=%d", constructor.MainSection.DelaySlot, constructor.MainSection.NumLabels)
	}
	if constructor.MainSection.Result == nil {
		t.Fatal("constructor main section result handle missing")
	}
	if len(constructor.MainSection.Ops) != 1 {
		t.Fatalf("unexpected main section op count: got %d", len(constructor.MainSection.Ops))
	}
	if constructor.MainSection.Ops[0].Output == nil || constructor.MainSection.Ops[0].Inputs[0].Offset.Kind != ConstKindRelative {
		t.Fatal("main section varnode template boundary not decoded as expected")
	}
	if len(constructor.NamedSections) != 1 || constructor.NamedSections[0].SectionID != 0 {
		t.Fatalf("unexpected named sections: got %+v", constructor.NamedSections)
	}
	if constructor.NamedSections[0].Template.Result != nil {
		t.Fatal("named section result should decode null handle")
	}
	if subtable.Decision == nil {
		t.Fatal("decision boundary missing")
	}
	if len(subtable.Decision.Pairs) != 1 {
		t.Fatalf("unexpected decision pair count: got %d", len(subtable.Decision.Pairs))
	}
	if subtable.Decision.Pairs[0].Pattern == nil || subtable.Decision.Pairs[0].Pattern.ElementID != elemOrPat {
		t.Fatalf("unexpected decision pattern boundary: %+v", subtable.Decision.Pairs[0].Pattern)
	}
	if len(subtable.Decision.Pairs[0].Pattern.Children) != 1 || subtable.Decision.Pairs[0].Pattern.Children[0].Block == nil {
		t.Fatal("decision disjoint pattern block missing")
	}
}

func TestDecodeOperandSymbolBoundaryPreservesOperandMetadata(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 2)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemValueSymHead)
	payload.writeString(attrName, "base")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemValueSymHead)
	payload.openElement(elemOperandSymHead)
	payload.writeString(attrName, "op0")
	payload.writeUnsigned(attrID, 2)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemOperandSymHead)
	payload.openElement(elemValueSym)
	payload.writeUnsigned(attrID, 1)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 5)
	payload.closeElement(elemIntB)
	payload.closeElement(elemValueSym)
	payload.openElement(elemOperandSym)
	payload.writeUnsigned(attrID, 2)
	payload.writeUnsigned(attrSubSym, 1)
	payload.writeSigned(attrOff, 3)
	payload.writeSigned(attrBase, -1)
	payload.writeSigned(attrMinLen, 2)
	payload.writeBool(attrCode, true)
	payload.writeSigned(attrIndex, 0)
	payload.openElement(elemOperandExp)
	payload.writeSigned(attrIndex, 0)
	payload.closeElement(elemOperandExp)
	payload.openElement(elemPlusExp)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 1)
	payload.closeElement(elemIntB)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 2)
	payload.closeElement(elemIntB)
	payload.closeElement(elemPlusExp)
	payload.closeElement(elemOperandSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	operand := boundaries.SymbolTable.Symbols[1].Body.Operand
	if operand == nil {
		t.Fatal("operand symbol boundary missing")
	}
	if operand.Index != 0 || operand.RelativeOffset != 3 || operand.OffsetBase != -1 || operand.MinimumLength != 2 {
		t.Fatalf("unexpected operand metadata: %+v", operand)
	}
	if !operand.CodeAddress {
		t.Fatal("operand code-address flag missing")
	}
	if !operand.HasDefiningSymbolID || operand.DefiningSymbolID != 1 {
		t.Fatalf("unexpected operand defining symbol id: %+v", operand)
	}
	if operand.LocalExpression == nil || operand.LocalExpression.ElementID != elemOperandExp {
		t.Fatalf("unexpected operand local expression: %+v", operand.LocalExpression)
	}
	if operand.DefiningExpression == nil || operand.DefiningExpression.ElementID != elemPlusExp {
		t.Fatalf("unexpected operand defining expression: %+v", operand.DefiningExpression)
	}
}

func TestDecodeValueMapSymbolBoundaryPreservesValueTable(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemValueMapSymHead)
	payload.writeString(attrName, "vm")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemValueMapSymHead)
	payload.openElement(elemValueMapSym)
	payload.writeUnsigned(attrID, 1)
	payload.openElement(elemIntB)
	payload.writeSigned(attrVal, 0)
	payload.closeElement(elemIntB)
	payload.openElement(elemValueTab)
	payload.writeSigned(attrVal, 0x11)
	payload.closeElement(elemValueTab)
	payload.openElement(elemValueTab)
	payload.writeSigned(attrVal, 0x22)
	payload.closeElement(elemValueTab)
	payload.closeElement(elemValueMapSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	pattern := boundaries.SymbolTable.Symbols[0].Body.Pattern
	if pattern == nil {
		t.Fatal("valuemap boundary missing")
	}
	if len(pattern.ValueTable) != 2 || pattern.ValueTable[0] != 0x11 || pattern.ValueTable[1] != 0x22 {
		t.Fatalf("unexpected valuemap table: %+v", pattern.ValueTable)
	}
}

func TestDecodeVarnodeSymbolBoundaryPreservesFixedData(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemVarnodeSymHead)
	payload.writeString(attrName, "r0")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemVarnodeSymHead)
	payload.openElement(elemVarnodeSym)
	payload.writeUnsigned(attrID, 1)
	payload.writeSigned(attrSpace, 1)
	payload.writeUnsigned(attrOff, 0x1234)
	payload.writeSigned(attrSize, 4)
	payload.closeElement(elemVarnodeSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	if len(boundaries.SymbolTable.Symbols) != 1 {
		t.Fatalf("unexpected symbol count: got %d", len(boundaries.SymbolTable.Symbols))
	}
	varnode := boundaries.SymbolTable.Symbols[0].Body.Varnode
	if varnode == nil {
		t.Fatal("varnode boundary missing")
	}
	if varnode.SpaceIndex != 1 || varnode.Offset != 0x1234 || varnode.Size != 4 {
		t.Fatalf("unexpected varnode boundary: %+v", varnode)
	}
}

func TestDecodeVarnodeListSymbolBoundaryPreservesSelectorAndTable(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 3)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemVarnodeSymHead)
	payload.writeString(attrName, "r0")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemVarnodeSymHead)
	payload.openElement(elemVarListSymHead)
	payload.writeString(attrName, "regs")
	payload.writeUnsigned(attrID, 2)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemVarListSymHead)
	payload.openElement(elemVarnodeSymHead)
	payload.writeString(attrName, "r1")
	payload.writeUnsigned(attrID, 3)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemVarnodeSymHead)
	payload.openElement(elemVarnodeSym)
	payload.writeUnsigned(attrID, 1)
	payload.writeSigned(attrSpace, 1)
	payload.writeUnsigned(attrOff, 0x10)
	payload.writeSigned(attrSize, 4)
	payload.closeElement(elemVarnodeSym)
	payload.openElement(elemVarnodeSym)
	payload.writeUnsigned(attrID, 3)
	payload.writeSigned(attrSpace, 1)
	payload.writeUnsigned(attrOff, 0x20)
	payload.writeSigned(attrSize, 4)
	payload.closeElement(elemVarnodeSym)
	payload.openElement(elemVarListSym)
	payload.writeUnsigned(attrID, 2)
	payload.openElement(elemOperandExp)
	payload.writeSigned(attrIndex, 0)
	payload.closeElement(elemOperandExp)
	payload.openElement(elemVar)
	payload.writeUnsigned(attrID, 1)
	payload.closeElement(elemVar)
	payload.openElement(elemNull)
	payload.closeElement(elemNull)
	payload.openElement(elemVar)
	payload.writeUnsigned(attrID, 3)
	payload.closeElement(elemVar)
	payload.openElement(elemPrint)
	payload.writeString(attrPiece, "ignored_non_var_slot")
	payload.closeElement(elemPrint)
	payload.closeElement(elemVarListSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	sym, ok := boundaries.SymbolTable.FindSymbol(2)
	if !ok {
		t.Fatal("varlist symbol not found")
	}
	varlist := sym.Body.VarnodeList
	if varlist == nil {
		t.Fatal("varlist boundary missing")
	}
	if varlist.Selector == nil || varlist.Selector.ElementID != elemOperandExp {
		t.Fatalf("unexpected varlist selector: %+v", varlist.Selector)
	}
	indexAttr, ok := varlist.Selector.Attrs[attrIndex]
	if !ok || indexAttr.Type != attributeValueInt || indexAttr.Int != 0 {
		t.Fatalf("unexpected varlist selector attrs: %+v", varlist.Selector.Attrs)
	}
	if len(varlist.Table) != 4 {
		t.Fatalf("unexpected varlist table length: got %d", len(varlist.Table))
	}
	if !varlist.Table[0].HasVarnodeSymbolID || varlist.Table[0].VarnodeSymbolID != 1 {
		t.Fatalf("unexpected first varlist entry: %+v", varlist.Table[0])
	}
	if varlist.Table[1].HasVarnodeSymbolID {
		t.Fatalf("unexpected second varlist entry: %+v", varlist.Table[1])
	}
	if !varlist.Table[2].HasVarnodeSymbolID || varlist.Table[2].VarnodeSymbolID != 3 {
		t.Fatalf("unexpected third varlist entry: %+v", varlist.Table[2])
	}
	if varlist.Table[3].HasVarnodeSymbolID {
		t.Fatalf("unexpected fourth varlist entry: %+v", varlist.Table[3])
	}
}

func TestDecodeBoundariesPayloadPreservesUnknownFlowLikeSymbolAsOpaque(t *testing.T) {
	// slaformat.hh and SymbolTable::decodeSymbolHeader() define no flow symbol head/body element ids.
	// If a producer emits unknown flow-like tags, keep boundary ids opaque instead of guessing semantics.
	const (
		elemUnknownFlowHead = 200
		elemUnknownFlowBody = 201
	)

	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemUnknownFlowHead)
	payload.writeString(attrName, "inst_dest")
	payload.writeUnsigned(attrID, 1)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemUnknownFlowHead)
	payload.openElement(elemUnknownFlowBody)
	payload.writeUnsigned(attrID, 1)
	payload.closeElement(elemUnknownFlowBody)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload() returned unexpected error: %v", err)
	}
	if len(boundaries.SymbolTable.Symbols) != 1 {
		t.Fatalf("unexpected symbol count: got %d", len(boundaries.SymbolTable.Symbols))
	}
	sym := boundaries.SymbolTable.Symbols[0]
	if sym.Name != "inst_dest" {
		t.Fatalf("unexpected symbol name: got %q", sym.Name)
	}
	if sym.HeaderElement != elemUnknownFlowHead || sym.BodyElement != elemUnknownFlowBody {
		t.Fatalf("unexpected preserved flow-like boundary ids: header=%d body=%d", sym.HeaderElement, sym.BodyElement)
	}
	if sym.Body.Opaque == nil {
		t.Fatal("unknown flow-like symbol body should be preserved as opaque")
	}
	if sym.Body.UserOp != nil || sym.Body.Subtable != nil || sym.Body.Pattern != nil || sym.Body.Operand != nil || sym.Body.Varnode != nil || sym.Body.VarnodeList != nil {
		t.Fatalf("unknown flow-like symbol body should not be decoded as typed content: %+v", sym.Body)
	}
}

func TestDecodeBoundariesPayloadRejectsBodyHeaderMismatch(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemUserOpHead)
	payload.writeString(attrName, "bad")
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemUserOpHead)
	payload.openElement(elemSubtableSym)
	payload.writeUnsigned(attrID, 0)
	payload.writeSigned(attrNumCT, 0)
	payload.closeElement(elemSubtableSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	_, err := DecodeBoundariesPayload(payload.bytes())
	if err == nil {
		t.Fatal("DecodeBoundariesPayload() returned nil for mismatched symbol body")
	}
}

func (e *packedTestEncoder) writeConstReal(value uint64) {
	e.openElement(elemConstReal)
	e.writeUnsigned(attrVal, value)
	e.closeElement(elemConstReal)
}

func (e *packedTestEncoder) writeConstHandle(index int64, selector int64, plus uint64) {
	e.openElement(elemConstHandle)
	e.writeSigned(attrVal, index)
	e.writeSigned(attrS, selector)
	if plus != 0 {
		e.writeUnsigned(attrPlus, plus)
	}
	e.closeElement(elemConstHandle)
}

func (e *packedTestEncoder) writeConstSpaceID(spaceIndex int64) {
	e.openElement(elemConstSpaceID)
	e.writeSigned(attrSpace, spaceIndex)
	e.closeElement(elemConstSpaceID)
}

func (e *packedTestEncoder) writeConstRelative(value uint64) {
	e.openElement(elemConstRelative)
	e.writeUnsigned(attrVal, value)
	e.closeElement(elemConstRelative)
}

func (e *packedTestEncoder) writeConstStart() {
	e.openElement(elemConstStart)
	e.closeElement(elemConstStart)
}

func (e *packedTestEncoder) writeConstNext() {
	e.openElement(elemConstNext)
	e.closeElement(elemConstNext)
}

func TestDecodeContextSymbolBoundaryPreservesAttributes(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0x1000)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeSigned(attrSize, 4)
	payload.writeSigned(attrDelay, 1)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemContextSymHead)
	payload.writeString(attrName, "phase")
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemContextSymHead)
	// ContextSym body
	payload.openElement(elemContextSym)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrVarnode, 42)
	payload.writeSigned(attrLow, 0)
	payload.writeSigned(attrHigh, 3)
	payload.writeBool(attrFlow, true)
	// Child: pattern expression (context field)
	payload.openElement(elemContextField)
	payload.writeBool(attrSignBit, false)
	payload.writeSigned(attrStartBit, 0)
	payload.writeSigned(attrEndBit, 3)
	payload.writeSigned(attrStartByte, 0)
	payload.writeSigned(attrEndByte, 0)
	payload.writeSigned(attrShift, 4)
	payload.closeElement(elemContextField)
	payload.closeElement(elemContextSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload failed: %v", err)
	}
	if len(boundaries.SymbolTable.Symbols) != 1 {
		t.Fatalf("expected 1 symbol, got %d", len(boundaries.SymbolTable.Symbols))
	}
	sym := boundaries.SymbolTable.Symbols[0]
	if sym.Name != "phase" {
		t.Fatalf("expected name phase, got %q", sym.Name)
	}
	if sym.Body.Context == nil {
		t.Fatal("expected ContextSymbolBoundary, got nil")
	}
	ctx := sym.Body.Context
	if !ctx.HasVarnodeSymbolID || ctx.VarnodeSymbolID != 42 {
		t.Fatalf("expected varnode symbol id 42, got %d (has=%v)", ctx.VarnodeSymbolID, ctx.HasVarnodeSymbolID)
	}
	if ctx.Low != 0 || ctx.High != 3 {
		t.Fatalf("expected low=0 high=3, got low=%d high=%d", ctx.Low, ctx.High)
	}
	if !ctx.Flow {
		t.Fatal("expected flow=true")
	}
	if ctx.Pattern == nil || ctx.Pattern.Expression == nil {
		t.Fatal("expected pattern expression")
	}
	if ctx.Pattern.Expression.ElementID != elemContextField {
		t.Fatalf("expected context field expression, got element %d", ctx.Pattern.Expression.ElementID)
	}
	// Body.Pattern should be nil since it is now stored in Body.Context
	if sym.Body.Pattern != nil {
		t.Fatal("ContextSymbol should not populate Body.Pattern")
	}
}

func TestDecodeEpsilonSymbolBoundaryNotOpaque(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSourceFiles)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.openElement(elemSymbolTable)
	payload.writeSigned(attrScopeSize, 1)
	payload.writeSigned(attrSymbolSize, 1)
	payload.openElement(elemScope)
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrParent, 0)
	payload.closeElement(elemScope)
	payload.openElement(elemEpsilonSymHead)
	payload.writeString(attrName, "eps")
	payload.writeUnsigned(attrID, 0)
	payload.writeUnsigned(attrScope, 0)
	payload.closeElement(elemEpsilonSymHead)
	// EpsilonSym body -- no attributes beyond ID (mirrors EpsilonSymbol::decode)
	payload.openElement(elemEpsilonSym)
	payload.writeUnsigned(attrID, 0)
	payload.closeElement(elemEpsilonSym)
	payload.closeElement(elemSymbolTable)
	payload.closeElement(elemSleigh)

	boundaries, err := DecodeBoundariesPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeBoundariesPayload failed: %v", err)
	}
	if len(boundaries.SymbolTable.Symbols) != 1 {
		t.Fatalf("expected 1 symbol, got %d", len(boundaries.SymbolTable.Symbols))
	}
	sym := boundaries.SymbolTable.Symbols[0]
	if sym.Name != "eps" {
		t.Fatalf("expected name eps, got %q", sym.Name)
	}
	// EpsilonSymbol should be decoded as Pattern, not Opaque
	if sym.Body.Pattern == nil {
		t.Fatal("epsilon symbol should be decoded as Pattern boundary, not opaque")
	}
	if sym.Body.Opaque != nil {
		t.Fatal("epsilon symbol should not fall through to opaque")
	}
}
