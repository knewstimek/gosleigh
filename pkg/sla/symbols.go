package sla

import "fmt"

// SourceFile maps constructor source indices back to original SLEIGH source filenames.
type SourceFile struct {
	Index int64
	Name  string
}

// SymbolTableBoundary is the shallow decoded form of the <symbol_table> subtree.
type SymbolTableBoundary struct {
	Scopes  []SymbolScopeBoundary
	Symbols []SymbolBoundary
}

// SymbolScopeBoundary is the persisted parent relation between SLEIGH symbol scopes.
type SymbolScopeBoundary struct {
	ID       uint64
	ParentID uint64
}

// SymbolBoundary is a shell/body-paired view of one persisted SLEIGH symbol.
type SymbolBoundary struct {
	Name          string
	ID            uint64
	ScopeID       uint64
	HeaderElement uint32
	BodyElement   uint32
	Body          SymbolBodyBoundary
}

// SymbolBodyBoundary preserves the body-specific boundary information we care about before full semantics decode.
type SymbolBodyBoundary struct {
	UserOp      *UserOpBoundary
	Subtable    *SubtableBoundary
	Pattern     *PatternSymbolBoundary
	Context     *ContextSymbolBoundary
	Operand     *OperandSymbolBoundary
	Varnode     *VarnodeSymbolBoundary
	VarnodeList *VarnodeListSymbolBoundary
	Opaque      *OpaqueSymbolBody
}

// UserOpBoundary is the minimal persisted content of a user-defined p-code op symbol.
type UserOpBoundary struct {
	Index int64
}

// ContextSymbolBoundary preserves the ContextSymbol-specific metadata from slghsymbol.cc.
// ContextSymbol inherits ValueSymbol (and thus shares PatternExpression for getFixedHandle),
// but additionally carries varnode, low/high bit range, and flow flag used by buildXrefs.
type ContextSymbolBoundary struct {
	VarnodeSymbolID    uint64 // References the VarnodeSymbol backing this context register
	HasVarnodeSymbolID bool
	Low                int64 // Low bit in the context register (ContextSymbol::low)
	High               int64 // High bit in the context register (ContextSymbol::high)
	Flow               bool  // Flow flag (ContextSymbol::flow)
	Pattern            *PatternSymbolBoundary
}

// PatternSymbolBoundary is the shallow decoded form of a symbol body backed by a PatternExpression tree.
type PatternSymbolBoundary struct {
	Expression *PatternExprBoundary
	ValueTable []int64
	NameTable  []string
	Opaque     *OpaqueSymbolBody
}

// OperandSymbolBoundary preserves the operand-specific metadata needed by OperandValue and resolveHandles.
type OperandSymbolBoundary struct {
	Index                int64
	RelativeOffset       int64
	OffsetBase           int64
	MinimumLength        int64
	CodeAddress          bool
	DefiningSymbolID     uint64
	HasDefiningSymbolID  bool
	LocalExpression      *PatternExprBoundary
	DefiningExpression   *PatternExprBoundary
}

// VarnodeSymbolBoundary preserves static varnode location data for fixed-handle reconstruction.
type VarnodeSymbolBoundary struct {
	// Mirrors VarnodeSymbol::decode(): preserve serialized space index before AddrSpace resolution.
	SpaceIndex int64
	Offset     uint64
	Size       int64
}

// VarnodeListEntryBoundary preserves one var/null slot from a varlist table.
type VarnodeListEntryBoundary struct {
	VarnodeSymbolID    uint64
	HasVarnodeSymbolID bool
}

// VarnodeListSymbolBoundary preserves selector and ordered varnode table slots.
type VarnodeListSymbolBoundary struct {
	// Mirrors VarnodeListSymbol::decode(): selector expression is first, then ordered var/null slots.
	Selector *PatternExprBoundary
	// Table stores raw symbol ids/nulls; checkTableFill-style validation is deferred to semantic decode.
	Table    []VarnodeListEntryBoundary
}

// OpaqueSymbolBody records a symbol body we intentionally keep opaque for now.
type OpaqueSymbolBody struct {
	AttributeCount  int
	ChildElementIDs []uint32
}

// SubtableBoundary captures the persisted constructor list and decision tree for a subtable symbol.
type SubtableBoundary struct {
	ConstructorCount int64
	Constructors     []ConstructorBoundary
	Decision         *DecisionNodeBoundary
}

// ConstructorBoundary is a shallow persisted view of one constructor body.
type ConstructorBoundary struct {
	ConstructorID    uint64
	ParentSymbolID   uint64
	FirstWhitespace  int64
	FlowThruIndex    int64 // >=0 when printpiece has exactly one operand ref and no markup; mirrors C++ Constructor::flowthruindex
	MinimumLength    int64
	SourceFileIndex  int64
	LineNumber       int64
	OperandSymbolIDs []uint64
	PrintPieces      []PrintPieceBoundary
	ContextOps       []PatternExprBoundary
	ContextCommits   []ContextCommitBoundary
	MainSection      *ConstructTplBoundary
	NamedSections    []NamedSectionBoundary
}

// NamedSectionBoundary couples a named p-code section id to its decoded ConstructTpl boundary.
type NamedSectionBoundary struct {
	SectionID int64
	Template  ConstructTplBoundary
}

// ContextCommitBoundary is the shallow decoded form of one <commit> node.
type ContextCommitBoundary struct {
	SymbolID uint64
	Number   int64
	Mask     uint64
	Flow     bool
}

// PrintPieceBoundary keeps constructor print pieces without interpreting later formatting semantics.
type PrintPieceBoundary struct {
	Text         string
	OperandIndex int64
	IsOperandRef bool
}

// DecisionNodeBoundary is the persisted constructor-dispatch tree shape.
type DecisionNodeBoundary struct {
	Number   int64
	Context  bool
	StartBit int64
	Size     int64
	Pairs    []DecisionPairBoundary
	Children []DecisionNodeBoundary
}

// DecisionPairBoundary links one constructor id to one persisted disjoint-pattern subtree.
type DecisionPairBoundary struct {
	ConstructorID uint64
	Pattern       *DisjointPatternBoundary
}

// Boundaries is the current decoded document shape up through symbol table and constructor boundaries.
type Boundaries struct {
	Metadata    *Metadata
	SourceFiles []SourceFile
	SymbolTable *SymbolTableBoundary
}

func (t *SymbolTableBoundary) FindSymbol(id uint64) (*SymbolBoundary, bool) {
	if t == nil {
		return nil, false
	}
	for i := range t.Symbols {
		if t.Symbols[i].ID == id {
			return &t.Symbols[i], true
		}
	}
	return nil, false
}

func (t *SymbolTableBoundary) FindOperandSymbol(id uint64) (*OperandSymbolBoundary, bool) {
	sym, ok := t.FindSymbol(id)
	if !ok || sym.Body.Operand == nil {
		return nil, false
	}
	return sym.Body.Operand, true
}

func (t *SymbolTableBoundary) FindOperandForConstructor(constructor *ConstructorBoundary, index int) (*OperandSymbolBoundary, bool) {
	if t == nil || constructor == nil || index < 0 || index >= len(constructor.OperandSymbolIDs) {
		return nil, false
	}
	return t.FindOperandSymbol(constructor.OperandSymbolIDs[index])
}

func DecodeBoundariesPayload(payload []byte) (*Boundaries, error) {
	root, err := decodeRootElement(payload)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeMetadata(root)
	if err != nil {
		return nil, err
	}
	boundaries := &Boundaries{Metadata: metadata}
	if sourcefiles, err := decodeSourceFiles(root); err != nil {
		return nil, err
	} else {
		boundaries.SourceFiles = sourcefiles
	}
	if symbolTable, err := decodeSymbolTable(root); err != nil {
		return nil, err
	} else {
		boundaries.SymbolTable = symbolTable
	}
	return boundaries, nil
}

func decodeSourceFiles(root *packedElement) ([]SourceFile, error) {
	elem, err := findChild(*root, elemSourceFiles)
	if err != nil {
		return nil, err
	}
	result := make([]SourceFile, 0, len(elem.Children))
	for _, child := range elem.Children {
		if child.ID != elemSourceFile {
			continue
		}
		name, err := requiredStringAttr(child.Attrs, attrName)
		if err != nil {
			return nil, fmt.Errorf("read sourcefile name: %w", err)
		}
		index, err := requiredIntAttr(child.Attrs, attrIndex)
		if err != nil {
			return nil, fmt.Errorf("read sourcefile index: %w", err)
		}
		result = append(result, SourceFile{Index: index, Name: name})
	}
	return result, nil
}

func decodeSymbolTable(root *packedElement) (*SymbolTableBoundary, error) {
	tableElem, err := findChild(*root, elemSymbolTable)
	if err != nil {
		return nil, err
	}
	scopeSize, err := requiredIntAttr(tableElem.Attrs, attrScopeSize)
	if err != nil {
		return nil, fmt.Errorf("read symbol table scope size: %w", err)
	}
	symbolSize, err := requiredIntAttr(tableElem.Attrs, attrSymbolSize)
	if err != nil {
		return nil, fmt.Errorf("read symbol table symbol size: %w", err)
	}
	children := tableElem.Children
	if len(children) < int(scopeSize+symbolSize) {
		return nil, fmt.Errorf("symbol table children shorter than scopes and headers")
	}
	result := &SymbolTableBoundary{
		Scopes:  make([]SymbolScopeBoundary, 0, scopeSize),
		Symbols: make([]SymbolBoundary, 0, symbolSize),
	}
	for i := 0; i < int(scopeSize); i++ {
		scope, err := decodeSymbolScope(children[i])
		if err != nil {
			return nil, err
		}
		result.Scopes = append(result.Scopes, scope)
	}
	byID := make(map[uint64]*SymbolBoundary, symbolSize)
	headerStart := int(scopeSize)
	for i := 0; i < int(symbolSize); i++ {
		symbol, err := decodeSymbolHeader(children[headerStart+i])
		if err != nil {
			return nil, err
		}
		result.Symbols = append(result.Symbols, symbol)
		byID[symbol.ID] = &result.Symbols[len(result.Symbols)-1]
	}
	for _, child := range children[headerStart+int(symbolSize):] {
		id, err := requiredUintAttr(child.Attrs, attrID)
		if err != nil {
			return nil, fmt.Errorf("read symbol body id: %w", err)
		}
		symbol := byID[id]
		if symbol == nil {
			return nil, fmt.Errorf("symbol body references unknown id %d", id)
		}
		if expected := expectedBodyElement(symbol.HeaderElement); expected != 0 && child.ID != expected {
			return nil, fmt.Errorf("symbol body mismatch for id %d: got %d want %d", id, child.ID, expected)
		}
		symbol.BodyElement = child.ID
		body, err := decodeSymbolBody(child)
		if err != nil {
			return nil, fmt.Errorf("decode symbol %q body: %w", symbol.Name, err)
		}
		symbol.Body = body
	}
	return result, nil
}

func decodeSymbolScope(elem packedElement) (SymbolScopeBoundary, error) {
	if elem.ID != elemScope {
		return SymbolScopeBoundary{}, fmt.Errorf("unexpected symbol scope element %d", elem.ID)
	}
	id, err := requiredUintAttr(elem.Attrs, attrID)
	if err != nil {
		return SymbolScopeBoundary{}, fmt.Errorf("read scope id: %w", err)
	}
	parentID, err := requiredUintAttr(elem.Attrs, attrParent)
	if err != nil {
		return SymbolScopeBoundary{}, fmt.Errorf("read scope parent: %w", err)
	}
	return SymbolScopeBoundary{ID: id, ParentID: parentID}, nil
}

func decodeSymbolHeader(elem packedElement) (SymbolBoundary, error) {
	name, err := requiredStringAttr(elem.Attrs, attrName)
	if err != nil {
		return SymbolBoundary{}, fmt.Errorf("read symbol header name: %w", err)
	}
	id, err := requiredUintAttr(elem.Attrs, attrID)
	if err != nil {
		return SymbolBoundary{}, fmt.Errorf("read symbol header id: %w", err)
	}
	scopeID, err := requiredUintAttr(elem.Attrs, attrScope)
	if err != nil {
		return SymbolBoundary{}, fmt.Errorf("read symbol header scope: %w", err)
	}
	return SymbolBoundary{
		Name:          name,
		ID:            id,
		ScopeID:       scopeID,
		HeaderElement: elem.ID,
	}, nil
}

func decodeSymbolBody(elem packedElement) (SymbolBodyBoundary, error) {
	switch elem.ID {
	case elemUserOp:
		index, err := requiredIntAttr(elem.Attrs, attrIndex)
		if err != nil {
			return SymbolBodyBoundary{}, fmt.Errorf("read userop index: %w", err)
		}
		return SymbolBodyBoundary{UserOp: &UserOpBoundary{Index: index}}, nil
	case elemSubtableSym:
		subtable, err := decodeSubtable(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{Subtable: subtable}, nil
	case elemOperandSym:
		operand, err := decodeOperandSymbolBody(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{Operand: operand}, nil
	// Mirrors VarnodeSymbol::decode() in slghsymbol.cc.
	case elemVarnodeSym:
		varnode, err := decodeVarnodeSymbolBody(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{Varnode: varnode}, nil
	// Mirrors VarnodeListSymbol::decode() in slghsymbol.cc.
	case elemVarListSym:
		varlist, err := decodeVarnodeListSymbolBody(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{VarnodeList: varlist}, nil
	// Mirrors ContextSymbol::decode() in slghsymbol.cc -- context symbols carry
	// additional varnode/low/high/flow attributes beyond the base PatternExpression.
	case elemContextSym:
		ctx, err := decodeContextSymbolBody(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{Context: ctx}, nil
	case elemValueSym, elemValueMapSym, elemNameSym, elemStartSym, elemEndSym, elemNext2Sym:
		pattern, err := decodePatternSymbolBody(elem)
		if err != nil {
			return SymbolBodyBoundary{}, err
		}
		return SymbolBodyBoundary{Pattern: pattern}, nil
	default:
		childIDs := make([]uint32, 0, len(elem.Children))
		for _, child := range elem.Children {
			childIDs = append(childIDs, child.ID)
		}
		return SymbolBodyBoundary{Opaque: &OpaqueSymbolBody{AttributeCount: len(elem.Attrs), ChildElementIDs: childIDs}}, nil
	}
}

func decodeVarnodeSymbolBody(elem packedElement) (*VarnodeSymbolBoundary, error) {
	spaceIndex, err := requiredIntAttr(elem.Attrs, attrSpace)
	if err != nil {
		return nil, fmt.Errorf("read varnode symbol space index: %w", err)
	}
	offset, err := requiredUintAttr(elem.Attrs, attrOff)
	if err != nil {
		return nil, fmt.Errorf("read varnode symbol offset: %w", err)
	}
	size, err := requiredIntAttr(elem.Attrs, attrSize)
	if err != nil {
		return nil, fmt.Errorf("read varnode symbol size: %w", err)
	}
	return &VarnodeSymbolBoundary{
		SpaceIndex: spaceIndex,
		Offset:     offset,
		Size:       size,
	}, nil
}

func decodeVarnodeListSymbolBody(elem packedElement) (*VarnodeListSymbolBoundary, error) {
	if len(elem.Children) == 0 {
		return nil, fmt.Errorf("varlist symbol selector expression missing")
	}
	selector, err := decodePatternExpression(elem.Children[0])
	if err != nil {
		return nil, fmt.Errorf("read varlist symbol selector expression: %w", err)
	}
	result := &VarnodeListSymbolBoundary{
		Selector: selector,
		Table:    make([]VarnodeListEntryBoundary, 0, len(elem.Children)-1),
	}
	for _, child := range elem.Children[1:] {
		entry := VarnodeListEntryBoundary{}
		if child.ID == elemVar {
			id, err := requiredUintAttr(child.Attrs, attrID)
			if err != nil {
				return nil, fmt.Errorf("read varlist table var symbol id: %w", err)
			}
			entry.VarnodeSymbolID = id
			entry.HasVarnodeSymbolID = true
		}
		result.Table = append(result.Table, entry)
	}
	return result, nil
}

func decodePatternSymbolBody(elem packedElement) (*PatternSymbolBoundary, error) {
	result := &PatternSymbolBoundary{}
	if len(elem.Children) == 0 {
		switch elem.ID {
		case elemStartSym:
			result.Expression = &PatternExprBoundary{ElementID: elemStartExp, Attrs: make(map[uint32]packedAttribute)}
		case elemEndSym:
			result.Expression = &PatternExprBoundary{ElementID: elemEndExp, Attrs: make(map[uint32]packedAttribute)}
		case elemNext2Sym:
			result.Expression = &PatternExprBoundary{ElementID: elemNext2Exp, Attrs: make(map[uint32]packedAttribute)}
		}
		return result, nil
	}
	expr, err := decodePatternExpression(elem.Children[0])
	if err != nil {
		childIDs := make([]uint32, 0, len(elem.Children))
		for _, child := range elem.Children {
			childIDs = append(childIDs, child.ID)
		}
		result.Opaque = &OpaqueSymbolBody{AttributeCount: len(elem.Attrs), ChildElementIDs: childIDs}
		return result, nil
	}
	result.Expression = expr
	for _, child := range elem.Children[1:] {
		switch child.ID {
		case elemValueTab:
			value, err := requiredIntAttr(child.Attrs, attrVal)
			if err != nil {
				return nil, fmt.Errorf("read valuemap table value: %w", err)
			}
			result.ValueTable = append(result.ValueTable, value)
		case elemNameTab:
			if attr, ok := findAttr(child.Attrs, attrName); ok && attr.Type == attributeValueString {
				result.NameTable = append(result.NameTable, attr.Text)
			} else {
				result.NameTable = append(result.NameTable, "\t")
			}
		}
	}
	return result, nil
}

// decodeContextSymbolBody mirrors ContextSymbol::decode() in slghsymbol.cc.
// Attributes varnode/low/high/flow are read first, then the child PatternExpression.
func decodeContextSymbolBody(elem packedElement) (*ContextSymbolBoundary, error) {
	result := &ContextSymbolBoundary{}
	if attr, ok := findAttr(elem.Attrs, attrVarnode); ok && attr.Type == attributeValueUint {
		result.VarnodeSymbolID = attr.Uint
		result.HasVarnodeSymbolID = true
	}
	low, err := requiredIntAttr(elem.Attrs, attrLow)
	if err != nil {
		return nil, fmt.Errorf("read context symbol low: %w", err)
	}
	result.Low = low
	high, err := requiredIntAttr(elem.Attrs, attrHigh)
	if err != nil {
		return nil, fmt.Errorf("read context symbol high: %w", err)
	}
	result.High = high
	result.Flow = optionalBoolAttr(elem.Attrs, attrFlow)
	// Decode the inner pattern expression (same as ValueSymbol base).
	pattern, err := decodePatternSymbolBody(elem)
	if err != nil {
		return nil, fmt.Errorf("read context symbol pattern: %w", err)
	}
	result.Pattern = pattern
	return result, nil
}

func decodeOperandSymbolBody(elem packedElement) (*OperandSymbolBoundary, error) {
	index, err := requiredIntAttr(elem.Attrs, attrIndex)
	if err != nil {
		return nil, fmt.Errorf("read operand symbol index: %w", err)
	}
	relativeOffset, err := requiredIntAttr(elem.Attrs, attrOff)
	if err != nil {
		return nil, fmt.Errorf("read operand symbol relative offset: %w", err)
	}
	offsetBase, err := requiredIntAttr(elem.Attrs, attrBase)
	if err != nil {
		return nil, fmt.Errorf("read operand symbol offset base: %w", err)
	}
	minimumLength, err := requiredIntAttr(elem.Attrs, attrMinLen)
	if err != nil {
		return nil, fmt.Errorf("read operand symbol minimum length: %w", err)
	}
	result := &OperandSymbolBoundary{
		Index:          index,
		RelativeOffset: relativeOffset,
		OffsetBase:     offsetBase,
		MinimumLength:  minimumLength,
	}
	if attr, ok := findAttr(elem.Attrs, attrSubSym); ok && attr.Type == attributeValueUint {
		result.DefiningSymbolID = attr.Uint
		result.HasDefiningSymbolID = true
	}
	if attr, ok := findAttr(elem.Attrs, attrCode); ok && attr.Type == attributeValueBool {
		result.CodeAddress = attr.Bool
	}
	if len(elem.Children) == 0 {
		return result, nil
	}
	localExpr, err := decodePatternExpression(elem.Children[0])
	if err != nil {
		return nil, fmt.Errorf("read operand symbol local expression: %w", err)
	}
	result.LocalExpression = localExpr
	if len(elem.Children) > 1 {
		defExpr, err := decodePatternExpression(elem.Children[1])
		if err != nil {
			return nil, fmt.Errorf("read operand symbol defining expression: %w", err)
		}
		result.DefiningExpression = defExpr
	}
	return result, nil
}

func decodeSubtable(elem packedElement) (*SubtableBoundary, error) {
	constructorCount, err := requiredIntAttr(elem.Attrs, attrNumCT)
	if err != nil {
		return nil, fmt.Errorf("read subtable constructor count: %w", err)
	}
	result := &SubtableBoundary{ConstructorCount: constructorCount}
	for _, child := range elem.Children {
		switch child.ID {
		case elemConstructor:
			constructor, err := decodeConstructor(child)
			if err != nil {
				return nil, err
			}
			constructor.ConstructorID = uint64(len(result.Constructors))
			result.Constructors = append(result.Constructors, constructor)
		case elemDecision:
			decision, err := decodeDecisionNode(child)
			if err != nil {
				return nil, err
			}
			result.Decision = decision
		}
	}
	return result, nil
}

func decodeConstructor(elem packedElement) (ConstructorBoundary, error) {
	parentSymbolID, err := requiredUintAttr(elem.Attrs, attrParent)
	if err != nil {
		return ConstructorBoundary{}, fmt.Errorf("read constructor parent: %w", err)
	}
	firstWhitespace, err := requiredIntAttr(elem.Attrs, attrFirst)
	if err != nil {
		return ConstructorBoundary{}, fmt.Errorf("read constructor first whitespace: %w", err)
	}
	minimumLength, err := requiredIntAttr(elem.Attrs, attrLength)
	if err != nil {
		return ConstructorBoundary{}, fmt.Errorf("read constructor length: %w", err)
	}
	sourceIndex, err := requiredIntAttr(elem.Attrs, attrSource)
	if err != nil {
		return ConstructorBoundary{}, fmt.Errorf("read constructor source index: %w", err)
	}
	lineNumber, err := requiredIntAttr(elem.Attrs, attrLine)
	if err != nil {
		return ConstructorBoundary{}, fmt.Errorf("read constructor line: %w", err)
	}
	result := ConstructorBoundary{
		ParentSymbolID:  parentSymbolID,
		FirstWhitespace: firstWhitespace,
		FlowThruIndex:   -1,
		MinimumLength:   minimumLength,
		SourceFileIndex: sourceIndex,
		LineNumber:      lineNumber,
	}
	for _, child := range elem.Children {
		switch child.ID {
		case elemOper:
			operandID, err := requiredUintAttr(child.Attrs, attrID)
			if err != nil {
				return ConstructorBoundary{}, fmt.Errorf("read constructor operand id: %w", err)
			}
			result.OperandSymbolIDs = append(result.OperandSymbolIDs, operandID)
		case elemPrint:
			text, err := requiredStringAttr(child.Attrs, attrPiece)
			if err != nil {
				return ConstructorBoundary{}, fmt.Errorf("read constructor print piece: %w", err)
			}
			result.PrintPieces = append(result.PrintPieces, PrintPieceBoundary{Text: text})
		case elemOpPrint:
			operandIndex, err := requiredIntAttr(child.Attrs, attrID)
			if err != nil {
				return ConstructorBoundary{}, fmt.Errorf("read constructor opprint operand index: %w", err)
			}
			result.PrintPieces = append(result.PrintPieces, PrintPieceBoundary{OperandIndex: operandIndex, IsOperandRef: true})
		case elemContextOp:
			if len(child.Children) > 0 {
				expr, err := decodePatternExpression(child.Children[0])
				if err == nil {
					result.ContextOps = append(result.ContextOps, *expr)
				}
			}
		case elemCommit:
			commit, err := decodeContextCommit(child)
			if err != nil {
				return ConstructorBoundary{}, err
			}
			result.ContextCommits = append(result.ContextCommits, commit)
		case elemConstructTpl:
			tpl, err := decodeConstructTpl(child)
			if err != nil {
				return ConstructorBoundary{}, err
			}
			if tpl.SectionID == nil {
				result.MainSection = tpl
			} else {
				result.NamedSections = append(result.NamedSections, NamedSectionBoundary{SectionID: *tpl.SectionID, Template: *tpl})
			}
		}
	}
	// Mirrors C++ Constructor::decode(): if printpiece has exactly one entry that
	// is an operand reference, set flowthruindex to that operand.
	// C++ condition: (printpiece.size()==1)&&(printpiece[0][0]=='\n')
	if len(result.PrintPieces) == 1 && result.PrintPieces[0].IsOperandRef {
		result.FlowThruIndex = result.PrintPieces[0].OperandIndex
	}
	return result, nil
}

func decodeContextCommit(elem packedElement) (ContextCommitBoundary, error) {
	symbolID, err := requiredUintAttr(elem.Attrs, attrID)
	if err != nil {
		return ContextCommitBoundary{}, fmt.Errorf("read commit symbol id: %w", err)
	}
	number, err := requiredIntAttr(elem.Attrs, attrNumber)
	if err != nil {
		return ContextCommitBoundary{}, fmt.Errorf("read commit number: %w", err)
	}
	mask, err := requiredUintAttr(elem.Attrs, attrMask)
	if err != nil {
		return ContextCommitBoundary{}, fmt.Errorf("read commit mask: %w", err)
	}
	flow, err := requiredBoolAttr(elem.Attrs, attrFlow)
	if err != nil {
		return ContextCommitBoundary{}, fmt.Errorf("read commit flow: %w", err)
	}
	return ContextCommitBoundary{SymbolID: symbolID, Number: number, Mask: mask, Flow: flow}, nil
}

func decodeDecisionNode(elem packedElement) (*DecisionNodeBoundary, error) {
	number, err := requiredIntAttr(elem.Attrs, attrNumber)
	if err != nil {
		return nil, fmt.Errorf("read decision number: %w", err)
	}
	context, err := requiredBoolAttr(elem.Attrs, attrContext)
	if err != nil {
		return nil, fmt.Errorf("read decision context flag: %w", err)
	}
	startBit, err := requiredIntAttr(elem.Attrs, attrStartBit)
	if err != nil {
		return nil, fmt.Errorf("read decision startbit: %w", err)
	}
	size, err := requiredIntAttr(elem.Attrs, attrSize)
	if err != nil {
		return nil, fmt.Errorf("read decision size: %w", err)
	}
	result := &DecisionNodeBoundary{Number: number, Context: context, StartBit: startBit, Size: size}
	for _, child := range elem.Children {
		switch child.ID {
		case elemPair:
			pair, err := decodeDecisionPair(child)
			if err != nil {
				return nil, err
			}
			result.Pairs = append(result.Pairs, pair)
		case elemDecision:
			subnode, err := decodeDecisionNode(child)
			if err != nil {
				return nil, err
			}
			result.Children = append(result.Children, *subnode)
		}
	}
	return result, nil
}

func decodeDecisionPair(elem packedElement) (DecisionPairBoundary, error) {
	constructorID, err := requiredIntAttr(elem.Attrs, attrID)
	if err != nil {
		return DecisionPairBoundary{}, fmt.Errorf("read decision pair constructor id: %w", err)
	}
	var pattern *DisjointPatternBoundary
	if len(elem.Children) > 0 {
		decoded, err := decodePatternTree(elem.Children[0])
		if err != nil {
			return DecisionPairBoundary{}, err
		}
		pattern = decoded
	}
	return DecisionPairBoundary{ConstructorID: uint64(constructorID), Pattern: pattern}, nil
}

func expectedBodyElement(headerElement uint32) uint32 {
	switch headerElement {
	case elemUserOpHead:
		return elemUserOp
	case elemEpsilonSymHead:
		return elemEpsilonSym
	case elemValueSymHead:
		return elemValueSym
	case elemValueMapSymHead:
		return elemValueMapSym
	case elemNameSymHead:
		return elemNameSym
	case elemVarnodeSymHead:
		return elemVarnodeSym
	case elemContextSymHead:
		return elemContextSym
	case elemVarListSymHead:
		return elemVarListSym
	case elemOperandSymHead:
		return elemOperandSym
	case elemStartSymHead:
		return elemStartSym
	case elemEndSymHead:
		return elemEndSym
	case elemNext2SymHead:
		return elemNext2Sym
	case elemSubtableSymHead:
		return elemSubtableSym
	default:
		return 0
	}
}
