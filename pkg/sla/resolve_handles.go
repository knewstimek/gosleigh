package sla

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
)

var ErrResolveHandlesUnimplemented = errors.New("resolveHandles shell is unimplemented")

func normalizeResolveHandlesUnimpl(err error) error {
	if err == nil {
		return nil
	}
	var existing *UnimplError
	if errors.As(err, &existing) {
		return err
	}
	if errors.Is(err, ErrResolveHandlesUnimplemented) {
		return newUnimplError(ErrResolveHandlesUnimplemented, err.Error())
	}
	return err
}

const (
	flowDestBuiltinSymbolName = "inst_dest"
	flowRefBuiltinSymbolName  = "inst_ref"
)

// ResolveHandlesHooks carries the hook-only pieces of Sleigh::resolveHandles().
// TripleSymbol::getFixedHandle and PatternExpression::getValue are intentionally
// left behind these callbacks so the shell does not guess semantic behavior.
type ResolveHandlesHooks struct {
	ResolveFixedHandle     func(walker *ParserWalker) (FixedHandle, bool, error)
	ResolveExpressionValue func(walker *ParserWalker) (uint64, bool, error)
}

// ResolveHandles walks an already resolved constructor tree and promotes the
// parse state to pcode. Anything beyond the traversal/result-propagation shell
// remains explicitly unimplemented.
func ResolveHandles(ctx *ParserContext, hooks ResolveHandlesHooks) error {
	if ctx == nil {
		return newUnimplError(ErrResolveHandlesUnimplemented, "parser context is nil")
	}

	walker := NewParserWalker(ctx)
	walker.BaseState()
	if !walker.IsState() {
		return newUnimplError(ErrResolveHandlesUnimplemented, "parser walker has no base state")
	}

	if err := resolveHandlesState(walker, hooks); err != nil {
		return normalizeResolveHandlesUnimpl(err)
	}

	ctx.SetParserState(ParseStatePcode)
	return nil
}

type resolveHandlesFrame struct {
	operand int
	numoper int
}

func resolveHandlesState(walker *ParserWalker, hooks ResolveHandlesHooks) error {
	if walker == nil || !walker.IsState() {
		return newUnimplError(ErrResolveHandlesUnimplemented, "parser walker is not positioned on a constructor state")
	}
	current := walker.Point
	if current == nil || current.Constructor == nil {
		return newUnimplError(ErrResolveHandlesUnimplemented, "constructor state is missing a constructor")
	}

	frames := []resolveHandlesFrame{{
		operand: 0,
		numoper: len(current.Constructor.OperandSymbolIDs),
	}}

	for walker.IsState() {
		current = walker.Point
		if current == nil || current.Constructor == nil {
			return newUnimplError(ErrResolveHandlesUnimplemented, "constructor state is missing a constructor")
		}
		if len(frames) == 0 {
			return newUnimplError(ErrResolveHandlesUnimplemented, "constructor stack is empty")
		}

		frame := &frames[len(frames)-1]
		if frame.numoper != len(current.Constructor.OperandSymbolIDs) {
			frame.numoper = len(current.Constructor.OperandSymbolIDs)
		}

		if frame.operand >= frame.numoper {
			if err := propagateConstructorResult(walker); err != nil {
				return err
			}
			walker.PopOperand()
			frames = frames[:len(frames)-1]
			if len(frames) > 0 {
				frames[len(frames)-1].operand++
			}
			continue
		}

		operandIndex := frame.operand
		if err := walker.PushOperand(operandIndex); err != nil {
			return err
		}

		child := walker.Point
		if child == nil {
			return newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("operand %d did not create a child state", operandIndex))
		}
		if child.Constructor != nil {
			frames = append(frames, resolveHandlesFrame{
				operand: 0,
				numoper: len(child.Constructor.OperandSymbolIDs),
			})
			continue
		}

		if err := resolveLeafOperand(walker, hooks); err != nil {
			return err
		}
		walker.PopOperand()
		frame.operand++
	}
	return nil
}

func resolveLeafOperand(walker *ParserWalker, hooks ResolveHandlesHooks) error {
	if walker == nil || walker.Point == nil {
		return newUnimplError(ErrResolveHandlesUnimplemented, "leaf operand has no active walker state")
	}
	if handled, err := resolveLeafOperandAuto(walker, hooks); err != nil {
		return normalizeResolveHandlesUnimpl(err)
	} else if handled {
		return nil
	}

	if hooks.ResolveFixedHandle != nil {
		hand, handled, err := hooks.ResolveFixedHandle(walker)
		if err != nil {
			return normalizeResolveHandlesUnimpl(err)
		}
		if handled {
			if target := walker.GetParentHandle(); target != nil {
				*target = hand
				return nil
			}
				return newUnimplError(ErrResolveHandlesUnimplemented, "fixed handle target is nil")
		}
	}

	if hooks.ResolveExpressionValue != nil {
		value, handled, err := hooks.ResolveExpressionValue(walker)
		if err != nil {
			return normalizeResolveHandlesUnimpl(err)
		}
		if handled {
			constSpace := walker.GetConstSpace()
			if constSpace == nil {
					return newUnimplError(ErrResolveHandlesUnimplemented, "constant space is not available for expression results")
			}
			if target := walker.GetParentHandle(); target != nil {
				*target = FixedHandle{
					Space:       constSpace,
					Size:        0,
					OffsetSpace: nil,
					OffsetOffset: value,
					OffsetSize:  0,
					TempSpace:   nil,
					TempOffset:  0,
				}
				return nil
			}
				return newUnimplError(ErrResolveHandlesUnimplemented, "expression result target is nil")
		}
	}

	return newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("operand %d has no hook resolution", walker.GetOperand()))
}

func resolveLeafOperandAuto(walker *ParserWalker, hooks ResolveHandlesHooks) (bool, error) {
	if walker == nil || walker.Point == nil || walker.ParserContext() == nil || walker.ParserContext().GetSymbolTable() == nil {
		return false, nil
	}
	parent := walker.Point.Parent
	if parent == nil || parent.Constructor == nil {
		return false, nil
	}
	operandIndex := walker.GetOperand()
	operand, ok := walker.ParserContext().GetSymbolTable().FindOperandForConstructor(parent.Constructor, operandIndex)
	if !ok {
		return false, nil
	}
	if operand.HasDefiningSymbolID {
		defsym, ok := walker.ParserContext().GetSymbolTable().FindSymbol(operand.DefiningSymbolID)
		if ok {
				hand, handled, err := resolveBoundarySymbolFixedHandle(defsym, walker, hooks)
				if err != nil {
					return true, normalizeResolveHandlesUnimpl(err)
				}
			if handled {
				copyHandleFromFixed(walker.GetParentHandle(), hand)
				return true, nil
			}
		}
	}
	if operand.DefiningExpression != nil {
		value, err := GetPatternExpressionValue(operand.DefiningExpression, walker, patternHooksFromResolveHandles(hooks))
		if err != nil {
			return true, normalizeResolveHandlesUnimpl(err)
		}
		copyConstHandle(walker.GetParentHandle(), uint64(value), walker.GetConstSpace())
		return true, nil
	}
	return false, nil
}

func resolveBoundarySymbolFixedHandle(sym *SymbolBoundary, walker *ParserWalker, hooks ResolveHandlesHooks) (FixedHandle, bool, error) {
	if sym == nil {
		return FixedHandle{}, false, nil
	}
	switch sym.HeaderElement {
	// ContextSymbol inherits ValueSymbol::getFixedHandle but stores its pattern
	// inside ContextSymbolBoundary.Pattern after the ContextSym-specific decode.
	case elemContextSymHead:
		pattern := contextSymbolPattern(sym)
		if pattern == nil || pattern.Expression == nil {
			return FixedHandle{}, false, nil
		}
		value, err := GetPatternExpressionValue(pattern.Expression, walker, patternHooksFromResolveHandles(hooks))
		if err != nil {
			return FixedHandle{}, true, normalizeResolveHandlesUnimpl(err)
		}
		constSpace := walker.GetConstSpace()
		if constSpace == nil {
			return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable for context symbol")
		}
		return FixedHandle{Space: constSpace, OffsetOffset: uint64(value), Size: 0}, true, nil
	// Ghidra NameSymbol inherits ValueSymbol::getFixedHandle (slghsymbol.hh/slghsymbol.cc).
	case elemValueSymHead, elemValueMapSymHead, elemNameSymHead:
		if sym.Body.Pattern == nil || sym.Body.Pattern.Expression == nil {
			return FixedHandle{}, false, nil
		}
			value, err := GetPatternExpressionValue(sym.Body.Pattern.Expression, walker, patternHooksFromResolveHandles(hooks))
			if err != nil {
				return FixedHandle{}, true, normalizeResolveHandlesUnimpl(err)
			}
		if sym.HeaderElement == elemValueMapSymHead {
			if value < 0 || int(value) >= len(sym.Body.Pattern.ValueTable) {
					return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("valuemap index %d is out of range", value))
			}
			value = sym.Body.Pattern.ValueTable[int(value)]
		}
		constSpace := walker.GetConstSpace()
		if constSpace == nil {
				return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable for value symbol")
		}
		return FixedHandle{Space: constSpace, OffsetOffset: uint64(value), Size: 0}, true, nil
	// Mirrors EpsilonSymbol::getFixedHandle in slghsymbol.cc.
	case elemEpsilonSymHead:
		constSpace := walker.GetConstSpace()
		if constSpace == nil {
				return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable for epsilon symbol")
		}
		return FixedHandle{Space: constSpace, OffsetOffset: 0, Size: 0}, true, nil
	case elemStartSymHead:
		cur := walker.GetCurSpace()
		if cur == nil {
				return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "current space is unavailable for start symbol")
		}
		return FixedHandle{Space: cur, OffsetOffset: walker.GetAddr().Offset, Size: uint32(cur.AddrSize)}, true, nil
	case elemEndSymHead:
		cur := walker.GetCurSpace()
		if cur == nil {
				return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "current space is unavailable for end symbol")
		}
		return FixedHandle{Space: cur, OffsetOffset: walker.GetNaddr().Offset, Size: uint32(cur.AddrSize)}, true, nil
	case elemNext2SymHead:
		cur := walker.GetCurSpace()
		if cur == nil {
				return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "current space is unavailable for next2 symbol")
		}
		return FixedHandle{Space: cur, OffsetOffset: walker.GetN2addr().Offset, Size: uint32(cur.AddrSize)}, true, nil
	// Mirrors OperandSymbol::getFixedHandle in slghsymbol.cc.
	case elemOperandSymHead:
		return resolveOperandSymbolFixedHandle(sym, walker)
	// Mirrors VarnodeSymbol::getFixedHandle in slghsymbol.cc.
	case elemVarnodeSymHead:
		return resolveVarnodeSymbolFixedHandle(sym, walker)
	// Mirrors VarnodeListSymbol::getFixedHandle in slghsymbol.cc.
	case elemVarListSymHead:
		return resolveVarnodeListSymbolFixedHandle(sym, walker, hooks)
	default:
		if isFlowDestSymbolBoundaryCandidate(sym) {
			return resolveFlowDestSymbolFixedHandle(walker)
		}
		if isFlowRefSymbolBoundaryCandidate(sym) {
			return resolveFlowRefSymbolFixedHandle(walker)
		}
		return FixedHandle{}, false, nil
	}
}

// contextSymbolPattern returns the underlying PatternSymbolBoundary for a ContextSymbol.
// ContextSymbol stores its pattern inside ContextSymbolBoundary; this helper
// provides a uniform accessor that also falls back to Body.Pattern for backward compat.
func contextSymbolPattern(sym *SymbolBoundary) *PatternSymbolBoundary {
	if sym == nil {
		return nil
	}
	if sym.Body.Context != nil {
		return sym.Body.Context.Pattern
	}
	// Fallback: pre-refactor boundaries may still store context as a plain pattern.
	return sym.Body.Pattern
}

func isFlowDestSymbolBoundaryCandidate(sym *SymbolBoundary) bool {
	return isFlowSymbolBoundaryCandidate(sym, flowDestBuiltinSymbolName)
}

func isFlowRefSymbolBoundaryCandidate(sym *SymbolBoundary) bool {
	return isFlowSymbolBoundaryCandidate(sym, flowRefBuiltinSymbolName)
}

func isFlowSymbolBoundaryCandidate(sym *SymbolBoundary, expectedName string) bool {
	if sym == nil || sym.Name != expectedName {
		return false
	}
	if expectedBodyElement(sym.HeaderElement) != 0 {
		return false
	}
	// slaformat.hh has no flow symbol tags, so only treat unknown+opaque shells as flow candidates.
	if sym.BodyElement == 0 && sym.Body.Opaque == nil {
		return false
	}
	if sym.Body.UserOp != nil || sym.Body.Subtable != nil || sym.Body.Pattern != nil || sym.Body.Context != nil || sym.Body.Operand != nil || sym.Body.Varnode != nil || sym.Body.VarnodeList != nil {
		return false
	}
	return true
}

// Mirrors FlowDestSymbol::getFixedHandle in slghsymbol.cc.
func resolveFlowDestSymbolFixedHandle(walker *ParserWalker) (FixedHandle, bool, error) {
	if walker == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "parser walker is unavailable for flowdest symbol")
	}
	constSpace := walker.GetConstSpace()
	if constSpace == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable for flowdest symbol")
	}
	destAddr := walker.GetDestAddr()
	if destAddr.Space == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "flowdest address is unavailable")
	}
	return FixedHandle{
		Space:        constSpace,
		Size:         uint32(destAddr.Space.AddrSize),
		OffsetSpace:  nil,
		OffsetOffset: destAddr.Offset,
		OffsetSize:   0,
		TempSpace:    nil,
		TempOffset:   0,
	}, true, nil
}

// Mirrors FlowRefSymbol::getFixedHandle in slghsymbol.cc.
func resolveFlowRefSymbolFixedHandle(walker *ParserWalker) (FixedHandle, bool, error) {
	if walker == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "parser walker is unavailable for flowref symbol")
	}
	constSpace := walker.GetConstSpace()
	if constSpace == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable for flowref symbol")
	}
	refAddr := walker.GetRefAddr()
	if refAddr.Space == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "flowref address is unavailable")
	}
	return FixedHandle{
		Space:        constSpace,
		Size:         uint32(refAddr.Space.AddrSize),
		OffsetSpace:  nil,
		OffsetOffset: refAddr.Offset,
		OffsetSize:   0,
		TempSpace:    nil,
		TempOffset:   0,
	}, true, nil
}

func resolveOperandSymbolFixedHandle(sym *SymbolBoundary, walker *ParserWalker) (FixedHandle, bool, error) {
	if sym == nil || sym.Body.Operand == nil {
		return FixedHandle{}, false, nil
	}
	if sym.Body.Operand.Index < 0 {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("operand symbol handle index %d is invalid", sym.Body.Operand.Index))
	}
	if walker == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "parser walker is unavailable for operand symbol")
	}
	hand, err := walker.GetFixedHandle(int(sym.Body.Operand.Index))
	if err != nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("operand symbol handle index %d is unavailable: %v", sym.Body.Operand.Index, err))
	}
	if hand == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("operand symbol handle index %d resolved to nil handle", sym.Body.Operand.Index))
	}
	return *hand, true, nil
}

func resolveVarnodeSymbolFixedHandle(sym *SymbolBoundary, walker *ParserWalker) (FixedHandle, bool, error) {
	if sym == nil || sym.Body.Varnode == nil {
		return FixedHandle{}, false, nil
	}

	body := sym.Body.Varnode
	space, ok := findWalkerSpaceByIndex(walker, body.SpaceIndex)
	if !ok {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode symbol space index %d is unavailable", body.SpaceIndex))
	}
	if body.Size < 0 || body.Size > int64(^uint32(0)) {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode symbol size %d is invalid", body.Size))
	}

	return FixedHandle{
		Space:        space,
		Size:         uint32(body.Size),
		OffsetSpace:  nil,
		OffsetOffset: body.Offset,
		OffsetSize:   0,
		TempSpace:    nil,
		TempOffset:   0,
	}, true, nil
}

func resolveVarnodeListSymbolFixedHandle(sym *SymbolBoundary, walker *ParserWalker, hooks ResolveHandlesHooks) (FixedHandle, bool, error) {
	if sym == nil || sym.Body.VarnodeList == nil {
		return FixedHandle{}, false, nil
	}

	body := sym.Body.VarnodeList
	if body.Selector == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "varnode list selector is missing")
	}

	index, err := GetPatternExpressionValue(body.Selector, walker, patternHooksFromResolveHandles(hooks))
	if err != nil {
		return FixedHandle{}, true, normalizeResolveHandlesUnimpl(err)
	}
	if index < 0 || int(index) >= len(body.Table) {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode list selector index %d is out of range", index))
	}

	entry := body.Table[int(index)]
	if !entry.HasVarnodeSymbolID {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode list entry %d is null", index))
	}
	if walker == nil || walker.ParserContext() == nil || walker.ParserContext().GetSymbolTable() == nil {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, "symbol table is unavailable for varnode list resolution")
	}
	selected, ok := walker.ParserContext().GetSymbolTable().FindSymbol(entry.VarnodeSymbolID)
	if !ok {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode list entry %d references unknown symbol id %d", index, entry.VarnodeSymbolID))
	}
	hand, handled, err := resolveVarnodeSymbolFixedHandle(selected, walker)
	if err != nil {
		return FixedHandle{}, true, normalizeResolveHandlesUnimpl(err)
	}
	if !handled {
		return FixedHandle{}, true, newUnimplError(ErrResolveHandlesUnimplemented, fmt.Sprintf("varnode list entry %d does not reference a varnode symbol", index))
	}
	return hand, true, nil
}

func findWalkerSpaceByIndex(walker *ParserWalker, index int64) (*address.Space, bool) {
	if walker == nil {
		return nil, false
	}
	// Prefer the full space registry when available; this covers register,
	// unique, overlay, and other spaces beyond the walker's implicit set.
	if walker.ParserContext() != nil && walker.ParserContext().SpacesByIndex != nil {
		if space, ok := walker.ParserContext().SpacesByIndex[index]; ok && space != nil {
			return space, true
		}
	}
	// Fallback: scan the spaces reachable from the walker's address fields.
	candidates := make([]*address.Space, 0, 7)
	add := func(space *address.Space) {
		if space == nil {
			return
		}
		for i := range candidates {
			if candidates[i] == space {
				return
			}
		}
		candidates = append(candidates, space)
	}
	add(walker.GetCurSpace())
	add(walker.GetConstSpace())
	add(walker.GetAddr().Space)
	add(walker.GetNaddr().Space)
	add(walker.GetN2addr().Space)
	add(walker.GetRefAddr().Space)
	add(walker.GetDestAddr().Space)
	for i := range candidates {
		if int64(candidates[i].Index) == index {
			return candidates[i], true
		}
	}
	return nil, false
}

func patternHooksFromResolveHandles(hooks ResolveHandlesHooks) PatternExpressionValueHooks {
	if hooks.ResolveExpressionValue == nil {
		return PatternExpressionValueHooks{}
	}
	return PatternExpressionValueHooks{
		ResolveOperandValue: func(req OperandValueRequest) (int64, bool, error) {
			value, handled, err := hooks.ResolveExpressionValue(req.Walker)
			return int64(value), handled, err
		},
	}
}

func propagateConstructorResult(walker *ParserWalker) error {
	if walker == nil || walker.Point == nil {
		return newUnimplError(ErrResolveHandlesUnimplemented, "constructor result has no active walker state")
	}

	current := walker.Point
	if current.Constructor == nil || current.Constructor.MainSection == nil || current.Constructor.MainSection.Result == nil {
		return nil
	}

	runtime, err := runtimeContextForWalker(walker)
	if err != nil {
		return normalizeResolveHandlesUnimpl(err)
	}
	if err := PropagateConstructorResult(*current.Constructor.MainSection, &runtime); err != nil {
		return newUnimplError(
			fmt.Errorf("%w: %w", ErrResolveHandlesUnimplemented, err),
			fmt.Sprintf("constructor result propagation failed: %v", err),
		)
	}
	return nil
}

func runtimeContextForWalker(walker *ParserWalker) (RuntimeContext, error) {
	if walker == nil || walker.ParserContext() == nil {
		return RuntimeContext{}, newUnimplError(ErrResolveHandlesUnimplemented, "parser context is unavailable")
	}

	ctx := walker.ParserContext()
	runtime := RuntimeContext{
		Instruction:   ctx.GetAddr(),
		CurrentSpace:  ctx.GetCurSpace(),
		ConstantSpace: ctx.GetConstSpace(),
		ParentHandle:  walker.GetParentHandle(),
	}
	if !ctx.GetNaddr().IsInvalid() {
		runtime.Next = ctx.GetNaddr()
		runtime.HasNext = true
	}
	if !ctx.GetN2addr().IsInvalid() {
		runtime.Next2 = ctx.GetN2addr()
		runtime.HasNext2 = true
	}
	if !ctx.GetRefAddr().IsInvalid() {
		runtime.Ref = ctx.GetRefAddr()
		runtime.HasRef = true
	}
	if !ctx.GetDestAddr().IsInvalid() {
		runtime.Dest = ctx.GetDestAddr()
		runtime.HasDest = true
	}
	if runtime.Instruction.IsInvalid() {
		return RuntimeContext{}, newUnimplError(ErrResolveHandlesUnimplemented, "instruction address is invalid")
	}
	if runtime.CurrentSpace == nil {
		return RuntimeContext{}, newUnimplError(ErrResolveHandlesUnimplemented, "current space is unavailable")
	}
	if runtime.ConstantSpace == nil {
		return RuntimeContext{}, newUnimplError(ErrResolveHandlesUnimplemented, "constant space is unavailable")
	}

	// Mirrors HandleTpl::fix() in semantics.cc: ConstTpl::fix() with type==handle
	// accesses walker.getFixedHandle(handle_index). Populate Handles from the
	// current constructor state's resolved child operand handles.
	if walker.Point != nil && len(walker.Point.Children) > 0 {
		runtime.Handles = make([]FixedHandle, len(walker.Point.Children))
		for i, child := range walker.Point.Children {
			if child != nil {
				runtime.Handles[i] = child.Handle
			}
		}
	}

	// Pass through SpacesByIndex so ConstKindSpaceID resolution works in
	// HandleTpl resolution (fixConstSpace -> spaceByIndex).
	if ctx.SpacesByIndex != nil {
		runtime.SpacesByIndex = ctx.SpacesByIndex
	}

	return runtime, nil
}

func copyHandleFromFixed(dst *FixedHandle, src FixedHandle) {
	if dst == nil {
		return
	}
	*dst = src
}

func copyConstHandle(dst *FixedHandle, value uint64, constSpace *address.Space) {
	if dst == nil {
		return
	}
	*dst = FixedHandle{
		Space:        constSpace,
		Size:         0,
		OffsetSpace:  nil,
		OffsetOffset: value,
		OffsetSize:   0,
		TempSpace:    nil,
		TempOffset:   0,
	}
}
