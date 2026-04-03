package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

const walkerMaxDepth = 32

// ParseState mirrors the coarse ParserContext state from the original C++.
type ParseState uint8

const (
	ParseStateUninitialized ParseState = iota
	ParseStateDisassembly
	ParseStatePcode
)

// ConstructState is the minimal tree node needed to model parser walk state.
type ConstructState struct {
	ConstructorID uint64
	SectionID     *int64
	Constructor   *ConstructorBoundary
	Handle        FixedHandle
	Parent        *ConstructState
	Children      []*ConstructState
	OperandIndex  int
	Offset        uint64
	Length        int
}

// NewConstructState allocates an empty state node.
func NewConstructState() *ConstructState {
	return &ConstructState{OperandIndex: -1}
}

// SetSectionID records the selected section for this constructor state.
func (s *ConstructState) SetSectionID(id int64) {
	s.SectionID = &id
}

// ClearSectionID removes any selected section.
func (s *ConstructState) ClearSectionID() {
	s.SectionID = nil
}

// SetConstructor stores the constructor boundary for this state.
func (s *ConstructState) SetConstructor(constructor ConstructorBoundary) {
	copy := constructor
	// Ensure FlowThruIndex is correctly derived from PrintPieces.
	// Mirrors C++ Constructor::decode(): flowthruindex = operand index when
	// there is exactly one print piece and it is an operand reference.
	if len(copy.PrintPieces) == 1 && copy.PrintPieces[0].IsOperandRef {
		copy.FlowThruIndex = copy.PrintPieces[0].OperandIndex
	} else if copy.FlowThruIndex >= 0 && !(len(copy.PrintPieces) == 1 && copy.PrintPieces[0].IsOperandRef) {
		// Caller set an inconsistent FlowThruIndex; reset to -1.
		copy.FlowThruIndex = -1
	}
	s.Constructor = &copy
}

// TemplateForSection selects the main or named section stored on this state.
func (s *ConstructState) TemplateForSection(sectionID int64) (*ConstructTplBoundary, bool) {
	if s == nil || s.Constructor == nil {
		return nil, false
	}
	if sectionID < 0 {
		if s.Constructor.MainSection == nil {
			return nil, false
		}
		return s.Constructor.MainSection, true
	}
	for i := range s.Constructor.NamedSections {
		if s.Constructor.NamedSections[i].SectionID == sectionID {
			section := s.Constructor.NamedSections[i].Template
			return &section, true
		}
	}
	return nil, false
}

// SectionValue returns the selected section id if one has been recorded.
func (s *ConstructState) SectionValue() (int64, bool) {
	if s == nil || s.SectionID == nil {
		return 0, false
	}
	return *s.SectionID, true
}

// ConstructorOffset computes a constructor-relative offset from the state base.
func (s *ConstructState) ConstructorOffset(relative uint64) uint64 {
	if s == nil {
		return relative
	}
	return s.Offset + relative
}

// Child returns a child operand state if it already exists.
func (s *ConstructState) Child(index int) (*ConstructState, bool) {
	if s == nil || index < 0 || index >= len(s.Children) {
		return nil, false
	}
	child := s.Children[index]
	if child == nil {
		return nil, false
	}
	return child, true
}

// EnsureOperand returns a child operand state, creating it when necessary.
func (s *ConstructState) EnsureOperand(index int) *ConstructState {
	if s == nil || index < 0 {
		return nil
	}
	if index >= len(s.Children) {
		grown := make([]*ConstructState, index+1)
		copy(grown, s.Children)
		s.Children = grown
	}
	child := s.Children[index]
	if child == nil {
		child = NewConstructState()
		child.Parent = s
		child.OperandIndex = index
		s.Children[index] = child
	}
	return child
}

// OperandOffset returns the end offset of the requested operand subtree.
func (s *ConstructState) OperandOffset(index int) (uint64, error) {
	child, ok := s.Child(index)
	if !ok {
		return 0, fmt.Errorf("operand %d is not available", index)
	}
	return child.Offset + uint64(child.Length), nil
}

// ParserContext mirrors the original C++ parser context in reduced form.
type ParserContext struct {
	Addr             address.Address
	NAddr            address.Address
	N2Addr           address.Address
	RefAddr          address.Address
	DestAddr         address.Address
	InstructionBytes []byte
	ContextWords     []uint64
	ConstSpace       *address.Space
	Symbols          *SymbolTableBoundary
	ParserState      ParseState
	DelaySlot        int
	BaseState        *ConstructState
	// SpacesByIndex maps space index to AddrSpace for HandleTpl resolution.
	// Populated by the caller (e.g. translate layer) so that
	// runtimeContextForWalker can pass it through to RuntimeContext.
	SpacesByIndex map[int64]*address.Space
	// Mirrors ParserContext::getN2addr() lazy derivation from context.cc.
	// When N2Addr is invalid, this callback can derive inst_next2 on demand.
	n2Resolver  func() (address.Address, bool)
	n2Resolving bool
}

// NewParserContext allocates a minimal context with an empty constructor root.
func NewParserContext(addr address.Address, constSpace *address.Space) *ParserContext {
	ctx := &ParserContext{
		Addr:        addr,
		ConstSpace:  constSpace,
		ParserState: ParseStateUninitialized,
		BaseState:   NewConstructState(),
	}
	return ctx
}

// Initialize resets the constructor tree root and constant space.
func (ctx *ParserContext) Initialize(constSpace *address.Space) {
	ctx.ConstSpace = constSpace
	if ctx.BaseState == nil {
		ctx.BaseState = NewConstructState()
	}
}

func (ctx *ParserContext) SetSymbolTable(symbols *SymbolTableBoundary) {
	ctx.Symbols = symbols
}

func (ctx *ParserContext) GetSymbolTable() *SymbolTableBoundary {
	return ctx.Symbols
}

func (ctx *ParserContext) SetAddr(addr address.Address) {
	ctx.Addr = addr
	ctx.N2Addr = address.Address{}
	ctx.n2Resolver = nil
	ctx.n2Resolving = false
}

func (ctx *ParserContext) SetNaddr(addr address.Address) {
	ctx.NAddr = addr
}

func (ctx *ParserContext) SetN2addr(addr address.Address) {
	ctx.N2Addr = addr
	ctx.n2Resolving = false
	// Reset any previously bound lazy callback when the cached value changes.
	ctx.n2Resolver = nil
}

func (ctx *ParserContext) SetN2addrResolver(resolve func() (address.Address, bool)) {
	ctx.n2Resolver = resolve
	ctx.n2Resolving = false
}

func (ctx *ParserContext) SetRefAddr(addr address.Address) {
	ctx.RefAddr = addr
}

func (ctx *ParserContext) SetDestAddr(addr address.Address) {
	ctx.DestAddr = addr
}

func (ctx *ParserContext) SetParserState(state ParseState) {
	ctx.ParserState = state
}

func (ctx *ParserContext) GetParserState() ParseState {
	return ctx.ParserState
}

func (ctx *ParserContext) SetDelaySlot(val int) {
	ctx.DelaySlot = val
}

func (ctx *ParserContext) GetDelaySlot() int {
	return ctx.DelaySlot
}

func (ctx *ParserContext) SetInstructionBytes(data []byte) {
	if data == nil {
		ctx.InstructionBytes = nil
		return
	}
	ctx.InstructionBytes = append([]byte(nil), data...)
}

func (ctx *ParserContext) SetContextWords(words []uint64) {
	if words == nil {
		ctx.ContextWords = nil
		return
	}
	ctx.ContextWords = append([]uint64(nil), words...)
}

// SetContextWord mirrors ParserContext::setContextWord() in context.hh.
// Applies val under mask to the i-th context word:
//
//	context[i] = (context[i] & ^mask) | (mask & val)
func (ctx *ParserContext) SetContextWord(i int, val, mask uint64) {
	if i < 0 || i >= len(ctx.ContextWords) {
		return
	}
	ctx.ContextWords[i] = (ctx.ContextWords[i] &^ mask) | (mask & val)
}

func (ctx *ParserContext) GetAddr() address.Address {
	return ctx.Addr
}

func (ctx *ParserContext) GetNaddr() address.Address {
	return ctx.NAddr
}

// GetN2addr returns the address of the instruction after the next (inst_next2).
// Mirrors ParserContext::getN2addr() in context.cc: lazy derivation from the
// next instruction's disassembly length.
//
// C++ throws LowlevelError("inst_next2 not available in this context") when
// translate is null or parsestate is uninitialized. Go returns an invalid
// (zero) address instead, letting the caller decide how to handle the gap.
func (ctx *ParserContext) GetN2addr() address.Address {
	if ctx == nil {
		return address.Address{}
	}
	if ctx.N2Addr.IsInvalid() && ctx.n2Resolver != nil && !ctx.n2Resolving {
		ctx.n2Resolving = true
		derived, ok := ctx.n2Resolver()
		ctx.n2Resolving = false
		if ok && !derived.IsInvalid() {
			ctx.N2Addr = derived
			ctx.n2Resolver = nil
		}
	}
	return ctx.N2Addr
}

// GetN2addrE returns the inst_next2 address or a typed *UnimplError.
// Mirrors the error path of ParserContext::getN2addr() in context.cc:
//
//	if (translate == 0 || parsestate == uninitialized)
//	    throw LowlevelError("inst_next2 not available in this context");
//
// Unlike GetN2addr(), this method reports unavailability explicitly so callers
// can use errors.As(*UnimplError) to distinguish "not yet resolved" from a
// valid invalid address.
func (ctx *ParserContext) GetN2addrE() (address.Address, error) {
	if ctx == nil || ctx.ParserState == ParseStateUninitialized {
		return address.Address{}, newUnimplError(
			ErrBuilderUnimplemented,
			"inst_next2 not available in this context",
		)
	}
	return ctx.GetN2addr(), nil
}

func (ctx *ParserContext) GetRefAddr() address.Address {
	return ctx.RefAddr
}

func (ctx *ParserContext) GetDestAddr() address.Address {
	return ctx.DestAddr
}

func (ctx *ParserContext) GetCurSpace() *address.Space {
	return ctx.Addr.Space
}

func (ctx *ParserContext) GetConstSpace() *address.Space {
	return ctx.ConstSpace
}

func (ctx *ParserContext) GetLength() int {
	if ctx == nil || ctx.BaseState == nil {
		return 0
	}
	return ctx.BaseState.Length
}

// ParserWalker mirrors the original C++ ParserWalker with a reduced, shell-only state.
type ParserWalker struct {
	constContext *ParserContext
	crossContext *ParserContext
	Point        *ConstructState
	Depth        int
	Breadcrumb   [walkerMaxDepth]int
}

// NewParserWalker creates a walker for one parser context.
func NewParserWalker(ctx *ParserContext) *ParserWalker {
	return &ParserWalker{constContext: ctx}
}

// NewCrossParserWalker creates a walker with an optional cross-build context.
func NewCrossParserWalker(ctx, cross *ParserContext) *ParserWalker {
	return &ParserWalker{constContext: ctx, crossContext: cross}
}

// ParserContext returns the primary parser context.
func (w *ParserWalker) ParserContext() *ParserContext {
	return w.constContext
}

// BaseState resets the walk to the root constructor state.
func (w *ParserWalker) BaseState() {
	if w == nil || w.constContext == nil {
		w.Point = nil
		w.Depth = 0
		w.Breadcrumb[0] = 0
		return
	}
	w.Point = w.constContext.BaseState
	w.Depth = 0
	w.Breadcrumb[0] = 0
}

// IsState reports whether the walker currently points at a constructor state.
func (w *ParserWalker) IsState() bool {
	return w != nil && w.Point != nil
}

// PushOperand moves the walk to the requested child operand, creating a shell node if needed.
func (w *ParserWalker) PushOperand(index int) error {
	if w == nil || w.Point == nil {
		return fmt.Errorf("walker has no active state")
	}
	if w.Depth+1 >= len(w.Breadcrumb) {
		return fmt.Errorf("walker depth exceeds %d", walkerMaxDepth)
	}
	child := w.Point.EnsureOperand(index)
	if child == nil {
		return fmt.Errorf("operand %d is invalid", index)
	}
	w.Point = child
	w.Depth++
	w.Breadcrumb[w.Depth] = index
	return nil
}

// PopOperand returns the walker to its parent constructor state.
func (w *ParserWalker) PopOperand() {
	if w == nil || w.Point == nil {
		return
	}
	w.Point = w.Point.Parent
	if w.Depth > 0 {
		w.Depth--
	}
}

// GetOperand returns the current operand index.
func (w *ParserWalker) GetOperand() int {
	if w == nil || w.Depth < 0 {
		return 0
	}
	return w.Breadcrumb[w.Depth]
}

// GetParentHandle returns the resolved handle of the current constructor state.
func (w *ParserWalker) GetParentHandle() *FixedHandle {
	if w == nil || w.Point == nil {
		return nil
	}
	return &w.Point.Handle
}

// GetFixedHandle returns the resolved handle for the requested child operand.
func (w *ParserWalker) GetFixedHandle(index int) (*FixedHandle, error) {
	if w == nil || w.Point == nil {
		return nil, fmt.Errorf("walker has no active state")
	}
	child, ok := w.Point.Child(index)
	if !ok {
		return nil, fmt.Errorf("operand %d is not available", index)
	}
	return &child.Handle, nil
}

// GetCurSpace returns the current instruction space, preferring the cross-build context when present.
func (w *ParserWalker) GetCurSpace() *address.Space {
	if w == nil {
		return nil
	}
	if w.crossContext != nil && w.crossContext.GetCurSpace() != nil {
		return w.crossContext.GetCurSpace()
	}
	if w.constContext == nil {
		return nil
	}
	return w.constContext.GetCurSpace()
}

// GetConstSpace returns the constant space, preferring the cross-build context when present.
func (w *ParserWalker) GetConstSpace() *address.Space {
	if w == nil {
		return nil
	}
	if w.crossContext != nil && w.crossContext.GetConstSpace() != nil {
		return w.crossContext.GetConstSpace()
	}
	if w.constContext == nil {
		return nil
	}
	return w.constContext.GetConstSpace()
}

// GetAddr returns the current instruction address, preferring the cross-build context when present.
func (w *ParserWalker) GetAddr() address.Address {
	if w != nil && w.crossContext != nil {
		return w.crossContext.GetAddr()
	}
	if w == nil || w.constContext == nil {
		return address.Address{}
	}
	return w.constContext.GetAddr()
}

// GetNaddr returns the next instruction address.
func (w *ParserWalker) GetNaddr() address.Address {
	if w != nil && w.crossContext != nil {
		return w.crossContext.GetNaddr()
	}
	if w == nil || w.constContext == nil {
		return address.Address{}
	}
	return w.constContext.GetNaddr()
}

// GetN2addr returns the instruction-after-next address.
func (w *ParserWalker) GetN2addr() address.Address {
	if w != nil && w.crossContext != nil {
		return w.crossContext.GetN2addr()
	}
	if w == nil || w.constContext == nil {
		return address.Address{}
	}
	return w.constContext.GetN2addr()
}

// GetRefAddr returns the reference address used by p-code snippets.
func (w *ParserWalker) GetRefAddr() address.Address {
	if w != nil && w.crossContext != nil {
		return w.crossContext.GetRefAddr()
	}
	if w == nil || w.constContext == nil {
		return address.Address{}
	}
	return w.constContext.GetRefAddr()
}

// GetDestAddr returns the destination address used by overridden calls.
func (w *ParserWalker) GetDestAddr() address.Address {
	if w != nil && w.crossContext != nil {
		return w.crossContext.GetDestAddr()
	}
	if w == nil || w.constContext == nil {
		return address.Address{}
	}
	return w.constContext.GetDestAddr()
}

// GetLength returns the active constructor length.
func (w *ParserWalker) GetLength() int {
	if w == nil || w.constContext == nil {
		return 0
	}
	return w.constContext.GetLength()
}

// SetOutOfBandState mirrors the C++ out-of-band walker setup in shell form.
func (w *ParserWalker) SetOutOfBandState(parent *ConstructState, index int, temp *ConstructState, other *ParserWalker) error {
	if w == nil {
		return fmt.Errorf("walker is nil")
	}
	if parent == nil || temp == nil || other == nil || other.Point == nil {
		return fmt.Errorf("out-of-band state requires parent, temp, other walker and active state")
	}
	cur := other.Point
	for cur != nil && cur != parent {
		cur = cur.Parent
	}
	if cur == nil {
		return fmt.Errorf("parent state is not on the current walk path")
	}

	offset, err := outOfBandOperandOffset(other.ParserContext(), cur, index)
	if err != nil {
		return err
	}
	*temp = ConstructState{
		ConstructorID: cur.ConstructorID,
		SectionID:     cur.SectionID,
		Constructor:   cur.Constructor,
		Handle:        FixedHandle{},
		Parent:        nil,
		Children:      nil,
		OperandIndex:  index,
		Offset:        offset,
		Length:        cur.Length,
	}
	w.Point = temp
	w.Depth = 0
	w.Breadcrumb[0] = 0
	return nil
}

func outOfBandOperandOffset(ctx *ParserContext, parent *ConstructState, index int) (uint64, error) {
	if parent == nil {
		return 0, fmt.Errorf("out-of-band state requires parent state")
	}
	operand, ok := findOutOfBandOperandBoundary(ctx, parent, index)
	if ok {
		// Mirrors ParserWalker::setOutOfBandState in context.cc:
		// constructor-relative operands can be evaluated before child branches exist.
		if operand.OffsetBase < 0 {
			offset := int64(parent.Offset) + operand.RelativeOffset
			if offset < 0 {
				return 0, fmt.Errorf("constructor-relative operand %d produced negative offset %d", index, offset)
			}
			return uint64(offset), nil
		}
	}
	child, ok := parent.Child(index)
	if !ok {
		return 0, fmt.Errorf("operand %d child state is not available", index)
	}
	return child.Offset, nil
}

func findOutOfBandOperandBoundary(ctx *ParserContext, parent *ConstructState, index int) (*OperandSymbolBoundary, bool) {
	if ctx == nil || ctx.GetSymbolTable() == nil || parent == nil || parent.Constructor == nil {
		return nil, false
	}
	return ctx.GetSymbolTable().FindOperandForConstructor(parent.Constructor, index)
}

// CurrentSection returns the section selected by the current constructor state.
func (w *ParserWalker) CurrentSection() (int64, bool) {
	if w == nil || w.Point == nil {
		return 0, false
	}
	return w.Point.SectionValue()
}

// SetCurrentSection records a selected section on the current constructor state.
func (w *ParserWalker) SetCurrentSection(id int64) error {
	if w == nil || w.Point == nil {
		return fmt.Errorf("walker has no active state")
	}
	w.Point.SetSectionID(id)
	return nil
}

func packWindowBE(data []byte, offset, width int) (uint64, error) {
	if offset < 0 || width < 0 {
		return 0, fmt.Errorf("invalid packed window offset=%d width=%d", offset, width)
	}
	if width > 8 {
		return 0, fmt.Errorf("packed width %d exceeds 8-byte shell limit", width)
	}
	if offset+width > len(data) {
		return 0, fmt.Errorf("packed window exceeds available data")
	}
	var result uint64
	for i := 0; i < width; i++ {
		result <<= 8
		result |= uint64(data[offset+i])
	}
	return result, nil
}

func packBitsBE(data []byte, baseOffset, startBit, size int) (uint64, error) {
	if size < 0 || size > 64 {
		return 0, fmt.Errorf("invalid bit width %d", size)
	}
	if size == 0 {
		return 0, nil
	}
	byteOffset := baseOffset + (startBit / 8)
	bitOffset := startBit % 8
	byteSize := ((bitOffset + size - 1) / 8) + 1
	if byteSize > 8 {
		return 0, fmt.Errorf("packed bit window exceeds 8-byte shell limit")
	}
	packed, err := packWindowBE(data, byteOffset, byteSize)
	if err != nil {
		return 0, err
	}
	packed <<= uint((8 * (8 - byteSize)) + bitOffset)
	packed >>= uint((8 * 8) - size)
	return packed, nil
}

func packContextBytesBE(words []uint64, byteoff, width int) (uint64, error) {
	if byteoff < 0 || width < 0 {
		return 0, fmt.Errorf("invalid context window offset=%d width=%d", byteoff, width)
	}
	if width > 8 {
		return 0, fmt.Errorf("context width %d exceeds 8-byte shell limit", width)
	}
	wordIndex := byteoff / 8
	if wordIndex < 0 || wordIndex >= len(words) {
		return 0, fmt.Errorf("context window exceeds available data")
	}
	byteOffset := byteoff % 8
	res := words[wordIndex]
	res <<= uint(byteOffset * 8)
	res >>= uint((8 - width) * 8)
	remaining := width - 8 + byteOffset
	if remaining > 0 {
		nextIndex := wordIndex + 1
		if nextIndex >= len(words) {
			return 0, fmt.Errorf("context window crosses past the available words")
		}
		res2 := words[nextIndex]
		res2 >>= uint((8 - remaining) * 8)
		res |= res2
	}
	return res, nil
}

func packContextBitsBE(words []uint64, startBit, size int) (uint64, error) {
	if size < 0 || size > 64 {
		return 0, fmt.Errorf("invalid context bit width %d", size)
	}
	if size == 0 {
		return 0, nil
	}
	wordIndex := startBit / 64
	if wordIndex < 0 || wordIndex >= len(words) {
		return 0, fmt.Errorf("context bit window exceeds available data")
	}
	bitOffset := startBit % 64
	res := words[wordIndex]
	res <<= uint(bitOffset)
	res >>= uint(64 - size)
	remaining := size - 64 + bitOffset
	if remaining > 0 {
		nextIndex := wordIndex + 1
		if nextIndex >= len(words) {
			return 0, fmt.Errorf("context bit window crosses past the available words")
		}
		res2 := words[nextIndex]
		res2 >>= uint(64 - remaining)
		res |= res2
	}
	return res, nil
}

// GetInstructionBytes returns packed instruction bytes at the constructor-relative offset.
func (w *ParserWalker) GetInstructionBytes(byteoff, width int) (uint64, error) {
	if w == nil || w.constContext == nil || w.Point == nil {
		return 0, fmt.Errorf("walker has no active instruction state")
	}
	return packWindowBE(w.constContext.InstructionBytes, int(w.Point.Offset)+byteoff, width)
}

// GetInstructionBits returns packed instruction bits at the constructor-relative offset.
func (w *ParserWalker) GetInstructionBits(startBit, size int) (uint64, error) {
	if w == nil || w.constContext == nil || w.Point == nil {
		return 0, fmt.Errorf("walker has no active instruction state")
	}
	return packBitsBE(w.constContext.InstructionBytes, int(w.Point.Offset), startBit, size)
}

// GetContextBytes returns packed context bytes from the local context array.
func (w *ParserWalker) GetContextBytes(byteoff, width int) (uint64, error) {
	if w == nil || w.constContext == nil {
		return 0, fmt.Errorf("walker has no active context")
	}
	return packContextBytesBE(w.constContext.ContextWords, byteoff, width)
}

// GetContextBits returns packed context bits from the local context array.
func (w *ParserWalker) GetContextBits(startBit, size int) (uint64, error) {
	if w == nil || w.constContext == nil {
		return 0, fmt.Errorf("walker has no active context")
	}
	return packContextBitsBE(w.constContext.ContextWords, startBit, size)
}
