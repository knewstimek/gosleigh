package sla

import (
	"errors"
	"fmt"
	"math/bits"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

var ErrLoweringUnimplemented = errors.New("lowering semantics are unimplemented")

const (
	handleFieldSpace      = 0
	handleFieldOffset     = 1
	handleFieldSize       = 2
	handleFieldOffsetPlus = 3
)

// HandleReference is the lowered form of a resolved FixedHandle-like value.
type HandleReference struct {
	Space       *address.Space
	Size        uint32
	OffsetSpace *address.Space
	Offset      uint64
	OffsetSize  uint32
	TempSpace   *address.Space
	TempOffset  uint64
}

// DirectiveHooks carries runtime callbacks for ConstructTpl control directives.
type DirectiveHooks struct {
	OnLabel      func(labelID uint64) error
	OnBuild      func(op OpTplBoundary, sectionID int64, ctx LoweringContext) ([]pcode.RawOp, error)
	OnDelaySlot  func(op OpTplBoundary, ctx LoweringContext) ([]pcode.RawOp, error)
	OnCrossBuild func(op OpTplBoundary, ctx LoweringContext) ([]pcode.RawOp, error)
}

// LoweringContext provides the minimum runtime state needed to turn ConstructTpl into raw p-code ops.
type LoweringContext struct {
	Instruction     address.Address
	// RootInstruction is the sink-visible address for raw ops. When unset,
	// raw lowering falls back to Instruction.
	RootInstruction address.Address
	CurrentSpace    *address.Space
	ConstantSpace   *address.Space
	UniqueSpace     *address.Space
	UniqueBase      uint64
	UniqueMask      uint64
	NextOffset      uint64
	HasNext         bool
	Next2Offset     uint64
	HasNext2        bool
	SpacesByIndex   map[int64]*address.Space
	Handles         []HandleReference
	LabelBase       uint64
	Directives      DirectiveHooks
}

// NewLoweringContext builds a minimal lowering context from decoded metadata and an instruction address.
func NewLoweringContext(metadata *Metadata, instruction address.Address) LoweringContext {
	ctx := LoweringContext{
		Instruction:     instruction,
		RootInstruction: instruction,
		SpacesByIndex:   make(map[int64]*address.Space),
	}
	if metadata != nil {
		ctx.UniqueBase = metadata.UniqueBase
		ctx.UniqueMask = metadata.UniqueMask
		for i := range metadata.Spaces {
			space := &metadata.Spaces[i]
			ctx.SpacesByIndex[int64(space.Index)] = space
			if ctx.UniqueSpace == nil && space.Kind == address.SpaceKindUnique {
				ctx.UniqueSpace = space
			}
			if ctx.CurrentSpace == nil && space.Name == metadata.DefaultSpace {
				ctx.CurrentSpace = space
			}
		}
	}
	if instruction.Space != nil {
		ctx.CurrentSpace = instruction.Space
		ctx.SpacesByIndex[int64(instruction.Space.Index)] = instruction.Space
	}
	if ctx.ConstantSpace == nil {
		ctx.ConstantSpace = &address.Space{
			Name:      "const",
			Kind:      address.SpaceKindConstant,
			Index:     ^uint16(0),
			AddrSize:  8,
			WordSize:  1,
			BigEndian: false,
			Physical:  false,
			Delay:     0,
		}
	}
	return ctx
}

func (ctx LoweringContext) runtimeContext() RuntimeContext {
	return RuntimeContextFromLowering(ctx)
}

// LowerConstructTpl converts one decoded ConstructTpl boundary into executable raw p-code ops.
func LowerConstructTpl(tpl ConstructTplBoundary, ctx LoweringContext) ([]pcode.RawOp, error) {
	if err := ctx.Instruction.Validate(); err != nil {
		return nil, fmt.Errorf("lower construct tpl: instruction address: %w", err)
	}
	sectionID := int64(-1)
	if tpl.SectionID != nil {
		sectionID = *tpl.SectionID
	}
	ops := make([]pcode.RawOp, 0, len(tpl.Ops))
	nextOrder := uint64(0)
	for i, op := range tpl.Ops {
		lowered, err := lowerOpTpl(op, ctx, sectionID, nextOrder)
		if err != nil {
			return nil, fmt.Errorf("lower construct tpl op %d: %w", i, err)
		}
		nextOrder += uint64(len(lowered))
		for j, raw := range lowered {
			if err := raw.Validate(); err != nil {
				return nil, fmt.Errorf("validate lowered op %d.%d: %w", i, j, err)
			}
			ops = append(ops, raw)
		}
	}
	return ops, nil
}

func lowerOpTpl(op OpTplBoundary, ctx LoweringContext, sectionID int64, order uint64) ([]pcode.RawOp, error) {
	if directive := specialDirective(op.OpcodeID); directive != "" {
		return lowerDirective(directive, op, ctx, sectionID)
	}
	emitAddr, err := ctx.rawEmissionAddress()
	if err != nil {
		return nil, fmt.Errorf("lower raw emission address: %w", err)
	}
	opcode, err := lowerOpcode(op.OpcodeID)
	if err != nil {
		return nil, err
	}
	preOps := make([]pcode.RawOp, 0, len(op.Inputs)+1)
	postOps := make([]pcode.RawOp, 0, 1)
	raw := pcode.RawOp{OpCode: opcode}
	if op.Output != nil {
		output, pre, post, err := lowerVarnodeForOp(*op.Output, ctx, true)
		if err != nil {
			return nil, fmt.Errorf("lower output: %w", err)
		}
		preOps = append(preOps, pre...)
		raw.Output = output
		postOps = append(postOps, post...)
	}
	for i, input := range op.Inputs {
		lowered, pre, _, err := lowerVarnodeForOp(input, ctx, false)
		if err != nil {
			return nil, fmt.Errorf("lower input %d: %w", i, err)
		}
		preOps = append(preOps, pre...)
		raw.Inputs = append(raw.Inputs, *lowered)
	}
	ops := make([]pcode.RawOp, 0, len(preOps)+1+len(postOps))
	ops = append(ops, preOps...)
	ops = append(ops, raw)
	ops = append(ops, postOps...)
	for i := range ops {
		// Mirrors sleigh.cc: oneInstruction() resolves templates with the active
		// walker, then PcodeCacher::emit(baseaddr, ...) stamps every raw op with
		// the root instruction address passed into the translation entry point.
		ops[i].SeqNum = pcode.SeqNum{
			Address: emitAddr,
			Time:    order + uint64(i),
			Order:   order + uint64(i),
		}
	}
	return ops, nil
}

func (ctx LoweringContext) rawEmissionAddress() (address.Address, error) {
	if err := ctx.RootInstruction.Validate(); err == nil {
		return ctx.RootInstruction, nil
	}
	if err := ctx.Instruction.Validate(); err == nil {
		return ctx.Instruction, nil
	}
	return address.Address{}, fmt.Errorf("root instruction and instruction addresses are both invalid")
}

func lowerOpcode(id int64) (pcode.OpCode, error) {
	if directive := specialDirective(id); directive != "" {
		return 0, fmt.Errorf("special directive %s must not be lowered as a raw opcode", directive)
	}
	if id <= 0 || id > int64(pcode.CPUI_MAX) {
		return 0, fmt.Errorf("unsupported executable opcode id %d", id)
	}
	return pcode.OpCode(id), nil
}

func specialDirective(id int64) string {
	switch pcode.OpCode(id) {
	case pcode.CPUI_MULTIEQUAL:
		return "BUILD"
	case pcode.CPUI_INDIRECT:
		return "DELAY_SLOT"
	case pcode.CPUI_PTRADD:
		return "LABELBUILD"
	case pcode.CPUI_PTRSUB:
		return "CROSSBUILD"
	default:
		return ""
	}
}

func lowerDirective(name string, op OpTplBoundary, ctx LoweringContext, sectionID int64) ([]pcode.RawOp, error) {
	switch name {
	case "LABELBUILD":
		return lowerLabelDirective(op, ctx)
	case "BUILD":
		if ctx.Directives.OnBuild != nil {
			return ctx.Directives.OnBuild(op, sectionID, ctx)
		}
		return nil, fmt.Errorf("special directive BUILD is unimplemented in raw lowering")
	case "DELAY_SLOT":
		if ctx.Directives.OnDelaySlot != nil {
			return ctx.Directives.OnDelaySlot(op, ctx)
		}
		return nil, fmt.Errorf("special directive DELAY_SLOT is unimplemented in raw lowering")
	case "CROSSBUILD":
		if ctx.Directives.OnCrossBuild != nil {
			return ctx.Directives.OnCrossBuild(op, ctx)
		}
		return nil, fmt.Errorf("special directive CROSSBUILD is unimplemented in raw lowering")
	default:
		return nil, fmt.Errorf("unknown special directive %q", name)
	}
}

func lowerLabelDirective(op OpTplBoundary, ctx LoweringContext) ([]pcode.RawOp, error) {
	if len(op.Inputs) != 1 {
		return nil, fmt.Errorf("LABELBUILD expects exactly one input, got %d", len(op.Inputs))
	}
	if ctx.Directives.OnLabel == nil {
		return nil, fmt.Errorf("special directive LABELBUILD requires a label runtime hook")
	}
	labelIndex, err := lowerScalarConst(op.Inputs[0].Offset, ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve LABELBUILD label index: %w", err)
	}
	if err := ctx.Directives.OnLabel(ctx.LabelBase + labelIndex); err != nil {
		return nil, err
	}
	return nil, nil
}

func lowerVarnodeTpl(vn VarnodeTplBoundary, ctx LoweringContext) (*pcode.VarnodeData, error) {
	dynamic, err := isDynamicVarnodeTpl(vn, ctx)
	if err != nil {
		return nil, fmt.Errorf("lower varnode dynamic check: %w", err)
	}
	if dynamic {
		// C++ counterpart: SleighBuilder::dump() handles dynamic varnodes by
		// synthesizing LOAD/STORE around the main op, not by direct lowering.
		return nil, newUnimplError(ErrLoweringUnimplemented, "dynamic varnode requires op-level LOAD/STORE expansion")
	}
	return lowerVarnodeTplConcrete(vn, ctx)
}

func lowerVarnodeTplConcrete(vn VarnodeTplBoundary, ctx LoweringContext) (*pcode.VarnodeData, error) {
	space, err := lowerSpaceConst(vn.Space, ctx)
	if err != nil {
		return nil, fmt.Errorf("lower varnode space: %w", err)
	}
	offset, err := lowerOffsetConst(vn.Offset, ctx)
	if err != nil {
		return nil, fmt.Errorf("lower varnode offset: %w", err)
	}
	sizeValue, err := lowerScalarConst(vn.Size, ctx)
	if err != nil {
		return nil, fmt.Errorf("lower varnode size: %w", err)
	}
	if sizeValue == 0 || sizeValue > uint64(^uint32(0)) {
		return nil, fmt.Errorf("invalid lowered varnode size %d", sizeValue)
	}
	return &pcode.VarnodeData{Space: space, Offset: offset, Size: uint32(sizeValue)}, nil
}

func lowerVarnodeForOp(vn VarnodeTplBoundary, ctx LoweringContext, asOutput bool) (*pcode.VarnodeData, []pcode.RawOp, []pcode.RawOp, error) {
	dynamic, hand, err := dynamicHandleForVarnode(vn, ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if !dynamic {
		out, err := lowerVarnodeTplConcrete(vn, ctx)
		return out, nil, nil, err
	}
	temp, err := lowerVarnodeTplConcrete(vn, ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	applyDynamicUniqueOffset(temp, ctx)
	pointer, spaceSelector, err := lowerDynamicPointerVarnode(vn, ctx, hand)
	if err != nil {
		return nil, nil, nil, err
	}
	pointerAddOps, pointer, err := lowerDynamicPointerAddOps(vn, ctx, hand, pointer)
	if err != nil {
		return nil, nil, nil, err
	}
	if asOutput {
		store := pcode.RawOp{
			OpCode: pcode.CPUI_STORE,
			Inputs: []pcode.VarnodeData{spaceSelector, pointer, *temp},
		}
		post := append(pointerAddOps, store)
		return temp, nil, post, nil
	}
	load := pcode.RawOp{
		OpCode: pcode.CPUI_LOAD,
		Output: temp,
		Inputs: []pcode.VarnodeData{spaceSelector, pointer},
	}
	pre := append(pointerAddOps, load)
	return temp, pre, nil, nil
}

func dynamicHandleForVarnode(vn VarnodeTplBoundary, ctx LoweringContext) (bool, HandleReference, error) {
	if vn.Offset.Kind != ConstKindHandle {
		return false, HandleReference{}, nil
	}
	index := vn.Offset.HandleIndex
	if index < 0 || index >= int64(len(ctx.Handles)) {
		return false, HandleReference{}, fmt.Errorf("handle index %d out of range", index)
	}
	hand := ctx.Handles[index]
	if hand.OffsetSpace == nil {
		return false, HandleReference{}, nil
	}
	return true, hand, nil
}

func lowerDynamicPointerVarnode(vn VarnodeTplBoundary, ctx LoweringContext, hand HandleReference) (pcode.VarnodeData, pcode.VarnodeData, error) {
	if hand.Space == nil || hand.OffsetSpace == nil {
		return pcode.VarnodeData{}, pcode.VarnodeData{}, newUnimplError(ErrLoweringUnimplemented, "dynamic varnode handle is missing pointer spaces")
	}
	if hand.OffsetSize == 0 {
		return pcode.VarnodeData{}, pcode.VarnodeData{}, newUnimplError(ErrLoweringUnimplemented, "dynamic varnode handle has zero pointer size")
	}
	offsetPlusLow16, hasOffsetPlus := dynamicOffsetPlusLow16(vn)
	if vn.Offset.Selector != handleFieldOffset && vn.Offset.Selector != handleFieldOffsetPlus {
		return pcode.VarnodeData{}, pcode.VarnodeData{}, newUnimplError(ErrLoweringUnimplemented, fmt.Sprintf("dynamic varnode selector %d is unsupported", vn.Offset.Selector))
	}
	ptrOffset := hand.Offset
	if hand.OffsetSpace.IsConstant() {
		mask := calcMask(hand.OffsetSize)
		ptrOffset &= mask
		if hasOffsetPlus && offsetPlusLow16 != 0 {
			ptrOffset = (ptrOffset + offsetPlusLow16) & mask
		}
	} else if hand.OffsetSpace.Kind == address.SpaceKindUnique {
		ptrOffset |= dynamicUniqueOffset(ctx)
	} else {
		ptrOffset = wrapSpaceOffset(hand.OffsetSpace, ptrOffset)
	}
	pointer := pcode.VarnodeData{
		Space:  hand.OffsetSpace,
		Offset: ptrOffset,
		Size:   hand.OffsetSize,
	}
	spaceSelector, err := lowerDynamicSpaceSelector(ctx, hand.Space)
	if err != nil {
		return pcode.VarnodeData{}, pcode.VarnodeData{}, err
	}
	return pointer, spaceSelector, nil
}

func lowerDynamicPointerAddOps(vn VarnodeTplBoundary, ctx LoweringContext, hand HandleReference, pointer pcode.VarnodeData) ([]pcode.RawOp, pcode.VarnodeData, error) {
	offsetPlusLow16, hasOffsetPlus := dynamicOffsetPlusLow16(vn)
	if !hasOffsetPlus || offsetPlusLow16 == 0 {
		return nil, pointer, nil
	}
	if hand.OffsetSpace == nil {
		return nil, pcode.VarnodeData{}, newUnimplError(ErrLoweringUnimplemented, "dynamic varnode handle is missing pointer space")
	}
	if hand.OffsetSpace.IsConstant() {
		return nil, pointer, nil
	}
	uniqueSpace := runtimeUniqueSpace(ctx)
	if uniqueSpace == nil {
		return nil, pcode.VarnodeData{}, newUnimplError(
			ErrLoweringUnimplemented,
			fmt.Sprintf("dynamic varnode v_offset_plus low16=0x%x requires unique runtime temp space", offsetPlusLow16),
		)
	}
	if ctx.ConstantSpace == nil {
		return nil, pcode.VarnodeData{}, fmt.Errorf("lower dynamic pointer-add: constant space is nil")
	}
	// C++ counterpart: SleighBuilder::generatePointerAdd() stores ptr+low16
	// into Translate::RUNTIME_BITRANGE_EA under unique space.
	runtimeTemp := pcode.VarnodeData{
		Space:  uniqueSpace,
		Offset: runtimeBitrangeEAOffset(ctx),
		Size:   pointer.Size,
	}
	addImmediate := pcode.VarnodeData{
		Space:  ctx.ConstantSpace,
		Offset: offsetPlusLow16,
		Size:   pointer.Size,
	}
	add := pcode.RawOp{
		OpCode: pcode.CPUI_INT_ADD,
		Output: &runtimeTemp,
		Inputs: []pcode.VarnodeData{pointer, addImmediate},
	}
	return []pcode.RawOp{add}, runtimeTemp, nil
}

func lowerDynamicSpaceSelector(ctx LoweringContext, targetSpace *address.Space) (pcode.VarnodeData, error) {
	if ctx.ConstantSpace == nil {
		return pcode.VarnodeData{}, fmt.Errorf("lower dynamic pointer: constant space is nil")
	}
	if targetSpace == nil {
		return pcode.VarnodeData{}, newUnimplError(ErrLoweringUnimplemented, "dynamic varnode handle is missing load/store target space")
	}
	// C++ counterpart: SleighBuilder::dump() writes (uintp)AddrSpace* as the space selector into
	// const-space input[0] for LOAD/STORE. We use the space index instead of a raw pointer so
	// that the selector is deterministic across runs and matches the Ghidra p-code semantic
	// (LOAD/STORE input[0] is logically the address space identifier, which is the index).
	return pcode.VarnodeData{
		Space:  ctx.ConstantSpace,
		Offset: uint64(targetSpace.Index),
		Size:   dynamicSpaceSelectorSize(),
	}, nil
}

func dynamicSpaceSelectorSize() uint32 {
	return uint32(bits.UintSize / 8)
}

func runtimeUniqueSpace(ctx LoweringContext) *address.Space {
	if ctx.UniqueSpace != nil {
		return ctx.UniqueSpace
	}
	var (
		candidate    *address.Space
		candidateKey int64
		hasCandidate bool
	)
	for key, space := range ctx.SpacesByIndex {
		if space == nil || space.Kind != address.SpaceKindUnique {
			continue
		}
		if !hasCandidate || key < candidateKey {
			candidate = space
			candidateKey = key
			hasCandidate = true
		}
	}
	return candidate
}

func dynamicOffsetPlusLow16(vn VarnodeTplBoundary) (uint64, bool) {
	if vn.Offset.Selector != handleFieldOffsetPlus {
		return 0, false
	}
	return vn.Offset.Plus & 0xffff, true
}

func dynamicUniqueOffset(ctx LoweringContext) uint64 {
	return (ctx.Instruction.Offset & ctx.UniqueMask) << 8
}

func runtimeBitrangeEAOffset(ctx LoweringContext) uint64 {
	// C++ counterpart: uniq_space->getTrans()->getUniqueStart(Translate::RUNTIME_BITRANGE_EA).
	return ctx.UniqueBase + 0x100
}

func applyDynamicUniqueOffset(vn *pcode.VarnodeData, ctx LoweringContext) {
	if vn == nil || vn.Space == nil {
		return
	}
	if vn.Space.Kind != address.SpaceKindUnique {
		return
	}
	vn.Offset |= dynamicUniqueOffset(ctx)
}

func calcMask(size uint32) uint64 {
	if size >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (size * 8)) - 1
}

func pointerWordSize(ctx LoweringContext) uint32 {
	if ctx.Instruction.Space != nil && ctx.Instruction.Space.AddrSize > 0 {
		return uint32(ctx.Instruction.Space.AddrSize)
	}
	if ctx.CurrentSpace != nil && ctx.CurrentSpace.AddrSize > 0 {
		return uint32(ctx.CurrentSpace.AddrSize)
	}
	return 8
}

func isDynamicVarnodeTpl(vn VarnodeTplBoundary, ctx LoweringContext) (bool, error) {
	// C++ counterpart: VarnodeTpl::isDynamic(const ParserWalker &walker).
	if vn.Offset.Kind != ConstKindHandle {
		return false, nil
	}
	runtime := ctx.runtimeContext()
	hand, err := runtime.handle(vn.Offset.HandleIndex)
	if err != nil {
		return false, err
	}
	return hand.OffsetSpace != nil, nil
}

func lowerSpaceConst(c ConstBoundary, ctx LoweringContext) (*address.Space, error) {
	return fixConstSpace(c, ctx.runtimeContext())
}

func lowerOffsetConst(c ConstBoundary, ctx LoweringContext) (uint64, error) {
	return fixConstScalar(c, ctx.runtimeContext())
}

func lowerScalarConst(c ConstBoundary, ctx LoweringContext) (uint64, error) {
	return fixConstScalar(c, ctx.runtimeContext())
}
