package sla

import (
	"fmt"

	"gosleigh/pkg/address"
)

// FixedHandle mirrors ghidra::FixedHandle in context.hh.
type FixedHandle struct {
	Space        *address.Space
	Size         uint32
	OffsetSpace  *address.Space
	OffsetOffset uint64
	OffsetSize   uint32
	TempSpace    *address.Space
	TempOffset   uint64
}

func (h FixedHandle) IsDynamic() bool {
	return h.OffsetSpace != nil
}

// RuntimeContext is the minimum runtime state needed to resolve ConstTpl and HandleTpl.
type RuntimeContext struct {
	Instruction   address.Address
	CurrentSpace  *address.Space
	ConstantSpace *address.Space
	Next          address.Address
	HasNext       bool
	Next2         address.Address
	HasNext2      bool
	Ref           address.Address
	HasRef        bool
	Dest          address.Address
	HasDest       bool
	SpacesByIndex map[int64]*address.Space
	Handles       []FixedHandle
	ParentHandle  *FixedHandle
}

// RuntimeContextFromLowering bridges the older lowering context into the runtime handle model.
func RuntimeContextFromLowering(ctx LoweringContext) RuntimeContext {
	runtime := RuntimeContext{
		Instruction:   ctx.Instruction,
		CurrentSpace:  ctx.CurrentSpace,
		ConstantSpace: ctx.ConstantSpace,
		SpacesByIndex: ctx.SpacesByIndex,
		HasNext:       ctx.HasNext,
		HasNext2:      ctx.HasNext2,
	}
	if ctx.CurrentSpace != nil {
		if ctx.HasNext {
			runtime.Next = address.Address{Space: ctx.CurrentSpace, Offset: ctx.NextOffset}
		}
		if ctx.HasNext2 {
			runtime.Next2 = address.Address{Space: ctx.CurrentSpace, Offset: ctx.Next2Offset}
		}
	}
	if len(ctx.Handles) != 0 {
		runtime.Handles = make([]FixedHandle, len(ctx.Handles))
		for i := range ctx.Handles {
			runtime.Handles[i] = FixedHandle{
				Space:        ctx.Handles[i].Space,
				Size:         ctx.Handles[i].Size,
				OffsetSpace:  ctx.Handles[i].OffsetSpace,
				OffsetOffset: ctx.Handles[i].Offset,
				OffsetSize:   ctx.Handles[i].OffsetSize,
				TempSpace:    ctx.Handles[i].TempSpace,
				TempOffset:   ctx.Handles[i].TempOffset,
			}
		}
	}
	return runtime
}

// ResolveConstructorResult mirrors sleigh.cc where templ->getResult()->fix() populates the parent handle.
func ResolveConstructorResult(tpl ConstructTplBoundary, ctx RuntimeContext) (*FixedHandle, error) {
	if tpl.Result == nil {
		return nil, nil
	}
	hand, err := ResolveHandleTpl(*tpl.Result, ctx)
	if err != nil {
		return nil, err
	}
	return &hand, nil
}

// PropagateConstructorResult mirrors sleigh.cc lines 699-704.
func PropagateConstructorResult(tpl ConstructTplBoundary, ctx *RuntimeContext) error {
	if ctx == nil || ctx.ParentHandle == nil || tpl.Result == nil {
		return nil
	}
	hand, err := ResolveHandleTpl(*tpl.Result, *ctx)
	if err != nil {
		return err
	}
	*ctx.ParentHandle = hand
	return nil
}

// ResolveHandleTpl mirrors HandleTpl::fix in semantics.cc.
func ResolveHandleTpl(tpl HandleTplBoundary, ctx RuntimeContext) (FixedHandle, error) {
	var hand FixedHandle
	if tpl.PtrSpace.Kind == ConstKindReal {
		if err := fillFixedHandleSpace(&hand, tpl.Space, ctx); err != nil {
			return FixedHandle{}, err
		}
		sizeValue, err := fixConstScalar(tpl.Size, ctx)
		if err != nil {
			return FixedHandle{}, fmt.Errorf("resolve handle size: %w", err)
		}
		if sizeValue > uint64(^uint32(0)) {
			return FixedHandle{}, fmt.Errorf("handle size %d overflows uint32", sizeValue)
		}
		hand.Size = uint32(sizeValue)
		if err := fillFixedHandleOffset(&hand, tpl.PtrOffset, ctx); err != nil {
			return FixedHandle{}, err
		}
		return hand, nil
	}

	space, err := fixConstSpace(tpl.Space, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle target space: %w", err)
	}
	sizeValue, err := fixConstScalar(tpl.Size, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle size: %w", err)
	}
	if sizeValue > uint64(^uint32(0)) {
		return FixedHandle{}, fmt.Errorf("handle size %d overflows uint32", sizeValue)
	}
	offsetValue, err := fixConstScalar(tpl.PtrOffset, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle pointer offset: %w", err)
	}
	offsetSpace, err := fixConstSpace(tpl.PtrSpace, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle pointer space: %w", err)
	}
	hand.Space = space
	hand.Size = uint32(sizeValue)
	hand.OffsetOffset = offsetValue
	hand.OffsetSpace = offsetSpace
	if hand.OffsetSpace != nil && hand.OffsetSpace.IsConstant() {
		hand.OffsetSpace = nil
		hand.OffsetOffset = addressToByte(hand.OffsetOffset, hand.Space)
		hand.OffsetOffset = wrapSpaceOffset(hand.Space, hand.OffsetOffset)
		return hand, nil
	}

	ptrSizeValue, err := fixConstScalar(tpl.PtrSize, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle pointer size: %w", err)
	}
	if ptrSizeValue > uint64(^uint32(0)) {
		return FixedHandle{}, fmt.Errorf("handle pointer size %d overflows uint32", ptrSizeValue)
	}
	tempSpace, err := fixConstSpace(tpl.TempSpace, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle temp space: %w", err)
	}
	tempOffset, err := fixConstScalar(tpl.TempOffset, ctx)
	if err != nil {
		return FixedHandle{}, fmt.Errorf("resolve handle temp offset: %w", err)
	}
	hand.OffsetSize = uint32(ptrSizeValue)
	hand.TempSpace = tempSpace
	hand.TempOffset = tempOffset
	return hand, nil
}

func fixConstScalar(c ConstBoundary, ctx RuntimeContext) (uint64, error) {
	switch c.Kind {
	case ConstKindStart:
		return ctx.Instruction.Offset, nil
	case ConstKindNext:
		if !ctx.HasNext {
			return 0, fmt.Errorf("next address is not set")
		}
		return ctx.Next.Offset, nil
	case ConstKindNext2:
		if !ctx.HasNext2 {
			return 0, fmt.Errorf("next2 address is not set")
		}
		return ctx.Next2.Offset, nil
	case ConstKindFlowRef:
		if !ctx.HasRef {
			return 0, fmt.Errorf("flowref address is not set")
		}
		return ctx.Ref.Offset, nil
	case ConstKindFlowRefSize:
		if !ctx.HasRef || ctx.Ref.Space == nil {
			return 0, fmt.Errorf("flowref address is not set")
		}
		return uint64(ctx.Ref.Space.AddrSize), nil
	case ConstKindFlowDest:
		if !ctx.HasDest {
			return 0, fmt.Errorf("flowdest address is not set")
		}
		return ctx.Dest.Offset, nil
	case ConstKindFlowDestSize:
		if !ctx.HasDest || ctx.Dest.Space == nil {
			return 0, fmt.Errorf("flowdest address is not set")
		}
		return uint64(ctx.Dest.Space.AddrSize), nil
	case ConstKindCurSpaceSize:
		if ctx.CurrentSpace == nil {
			return 0, fmt.Errorf("current space is not set")
		}
		return uint64(ctx.CurrentSpace.AddrSize), nil
	case ConstKindCurSpace:
		if ctx.CurrentSpace == nil {
			return 0, fmt.Errorf("current space is not set")
		}
		return uint64(ctx.CurrentSpace.Index), nil
	case ConstKindHandle:
		return fixHandleSelector(c, ctx)
	case ConstKindRelative, ConstKindReal:
		return c.Value, nil
	case ConstKindSpaceID:
		space, err := ctx.spaceByIndex(c.SpaceIndex)
		if err != nil {
			return 0, err
		}
		return uint64(space.Index), nil
	default:
		return 0, fmt.Errorf("const kind %q cannot resolve to a scalar", c.Kind)
	}
}

func fixConstSpace(c ConstBoundary, ctx RuntimeContext) (*address.Space, error) {
	switch c.Kind {
	case ConstKindCurSpace:
		if ctx.CurrentSpace == nil {
			return nil, fmt.Errorf("current space is not set")
		}
		return ctx.CurrentSpace, nil
	case ConstKindHandle:
		hand, err := ctx.handle(c.HandleIndex)
		if err != nil {
			return nil, err
		}
		switch c.Selector {
		case handleFieldSpace:
			if hand.OffsetSpace == nil {
				return hand.Space, nil
			}
			return hand.TempSpace, nil
		default:
			return nil, fmt.Errorf("handle selector %d is not a space", c.Selector)
		}
	case ConstKindSpaceID:
		return ctx.spaceByIndex(c.SpaceIndex)
	case ConstKindFlowRef:
		if !ctx.HasRef || ctx.Ref.Space == nil {
			return nil, fmt.Errorf("flowref address is not set")
		}
		return ctx.Ref.Space, nil
	default:
		return nil, fmt.Errorf("const kind %q is not a space", c.Kind)
	}
}

func fillFixedHandleSpace(hand *FixedHandle, c ConstBoundary, ctx RuntimeContext) error {
	switch c.Kind {
	case ConstKindCurSpace:
		if ctx.CurrentSpace == nil {
			return fmt.Errorf("current space is not set")
		}
		hand.Space = ctx.CurrentSpace
		return nil
	case ConstKindHandle:
		other, err := ctx.handle(c.HandleIndex)
		if err != nil {
			return err
		}
		switch c.Selector {
		case handleFieldSpace:
			hand.Space = other.Space
			return nil
		default:
			return fmt.Errorf("handle selector %d is not a space fill", c.Selector)
		}
	case ConstKindSpaceID:
		space, err := ctx.spaceByIndex(c.SpaceIndex)
		if err != nil {
			return err
		}
		hand.Space = space
		return nil
	default:
		return fmt.Errorf("const kind %q is not a space fill", c.Kind)
	}
}

func fillFixedHandleOffset(hand *FixedHandle, c ConstBoundary, ctx RuntimeContext) error {
	if c.Kind == ConstKindHandle {
		other, err := ctx.handle(c.HandleIndex)
		if err != nil {
			return err
		}
		hand.OffsetSpace = other.OffsetSpace
		hand.OffsetOffset = other.OffsetOffset
		hand.OffsetSize = other.OffsetSize
		hand.TempSpace = other.TempSpace
		hand.TempOffset = other.TempOffset
		return nil
	}
	if hand.Space == nil {
		return fmt.Errorf("handle space must be resolved before offset")
	}
	value, err := fixConstScalar(c, ctx)
	if err != nil {
		return err
	}
	hand.OffsetSpace = nil
	hand.OffsetOffset = wrapSpaceOffset(hand.Space, value)
	return nil
}

func fixHandleSelector(c ConstBoundary, ctx RuntimeContext) (uint64, error) {
	hand, err := ctx.handle(c.HandleIndex)
	if err != nil {
		return 0, err
	}
	switch c.Selector {
	case handleFieldSpace:
		if hand.OffsetSpace == nil {
			if hand.Space == nil {
				return 0, fmt.Errorf("handle %d has nil space", c.HandleIndex)
			}
			return uint64(hand.Space.Index), nil
		}
		if hand.TempSpace == nil {
			return 0, fmt.Errorf("handle %d has nil temp space", c.HandleIndex)
		}
		return uint64(hand.TempSpace.Index), nil
	case handleFieldOffset:
		if hand.OffsetSpace == nil {
			return hand.OffsetOffset, nil
		}
		return hand.TempOffset, nil
	case handleFieldSize:
		return uint64(hand.Size), nil
	case handleFieldOffsetPlus:
		var value uint64
		if hand.OffsetSpace == nil {
			value = hand.OffsetOffset
		} else {
			value = hand.TempOffset
		}
		if hand.Space != ctx.ConstantSpace {
			return value + (c.Plus & 0xffff), nil
		}
		return value >> (8 * (c.Plus >> 16)), nil
	default:
		return 0, fmt.Errorf("unsupported handle selector %d", c.Selector)
	}
}

func (ctx RuntimeContext) handle(index int64) (*FixedHandle, error) {
	if index < 0 || index >= int64(len(ctx.Handles)) {
		return nil, fmt.Errorf("handle index %d out of range", index)
	}
	return &ctx.Handles[index], nil
}

func (ctx RuntimeContext) spaceByIndex(index int64) (*address.Space, error) {
	space, ok := ctx.SpacesByIndex[index]
	if !ok {
		return nil, fmt.Errorf("space index %d not found", index)
	}
	return space, nil
}

func addressToByte(value uint64, space *address.Space) uint64 {
	if space == nil || space.WordSize <= 1 {
		return value
	}
	return value * uint64(space.WordSize)
}

func wrapSpaceOffset(space *address.Space, off uint64) uint64 {
	if space == nil || space.AddrSize >= 8 {
		return off
	}
	mod := uint64(1) << (8 * space.AddrSize)
	mod *= uint64(space.WordSize)
	if mod == 0 {
		return off
	}
	return off % mod
}
