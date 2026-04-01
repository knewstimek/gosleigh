package sla

import (
	"errors"
	"fmt"

	"gosleigh/pkg/address"
)

// ErrPatternExpressionUnimplemented marks PatternExpression::getValue cases that
// are still outside the current parity shell.
var ErrPatternExpressionUnimplemented = errors.New("pattern expression getValue is unimplemented")

func normalizePatternExpressionUnimpl(err error) error {
	if err == nil {
		return nil
	}
	var uerr *UnimplError
	if errors.As(err, &uerr) {
		return err
	}
	if errors.Is(err, ErrPatternExpressionUnimplemented) {
		return newUnimplError(ErrPatternExpressionUnimplemented, err.Error())
	}
	return err
}

// PatternExpressionValueHooks carries explicit hook boundaries for original
// Ghidra behavior that the current decoded boundary model cannot yet recreate.
type PatternExpressionValueHooks struct {
	ResolveOperandValue func(req OperandValueRequest) (int64, bool, error)
}

// OperandValueRequest mirrors the OperandValue::getValue hand-off point to
// OperandSymbol metadata in slghsymbol.cc.
type OperandValueRequest struct {
	Expr         PatternExprBoundary
	Walker       *ParserWalker
	OperandIndex int64
}

// GetPatternExpressionValue evaluates the current minimum shell of
// ghidra::PatternExpression::getValue from slghpatexpress.cc.
func GetPatternExpressionValue(expr *PatternExprBoundary, walker *ParserWalker, hooks PatternExpressionValueHooks) (int64, error) {
	if expr == nil {
		return 0, fmt.Errorf("pattern expression is nil")
	}
	switch expr.ElementID {
	case elemIntB:
		return evalConstantValue(*expr)
	case elemStartExp:
		return evalStartInstructionValue(walker)
	case elemEndExp:
		return evalEndInstructionValue(walker)
	case elemNext2Exp:
		return evalNext2InstructionValue(walker)
	case elemTokenField:
		return evalTokenField(*expr, walker)
	case elemContextField:
		return evalContextField(*expr, walker)
	case elemOperandExp:
		return evalOperandValue(*expr, walker, hooks)
	case elemPlusExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left + right })
	case elemSubExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left - right })
	case elemMultExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left * right })
	case elemLShiftExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left << uint(right) })
	case elemRShiftExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left >> uint(right) })
	case elemAndExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left & right })
	case elemOrExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left | right })
	case elemXorExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left ^ right })
	case elemDivExp:
		return evalBinaryExpr(*expr, walker, hooks, func(left, right int64) int64 { return left / right })
	case elemMinusExp:
		return evalUnaryExpr(*expr, walker, hooks, func(value int64) int64 { return -value })
	case elemNotExp:
		return evalUnaryExpr(*expr, walker, hooks, func(value int64) int64 { return ^value })
	default:
		return 0, newUnimplError(ErrPatternExpressionUnimplemented, fmt.Sprintf("element %d", expr.ElementID))
	}
}

func evalConstantValue(expr PatternExprBoundary) (int64, error) {
	value, err := requiredIntAttr(exprAttrSlice(expr), attrVal)
	if err != nil {
		return 0, fmt.Errorf("read constant value: %w", err)
	}
	return value, nil
}

func evalStartInstructionValue(walker *ParserWalker) (int64, error) {
	if walker == nil {
		return 0, fmt.Errorf("walker is nil")
	}
	addr := walker.GetAddr()
	if addr.Space == nil {
		return 0, fmt.Errorf("start expression address space is nil")
	}
	return byteOffsetToAddressValue(addr.Offset, addr.Space), nil
}

func evalEndInstructionValue(walker *ParserWalker) (int64, error) {
	if walker == nil {
		return 0, fmt.Errorf("walker is nil")
	}
	addr := walker.GetNaddr()
	if addr.Space == nil {
		return 0, fmt.Errorf("end expression address space is nil")
	}
	return byteOffsetToAddressValue(addr.Offset, addr.Space), nil
}

func evalNext2InstructionValue(walker *ParserWalker) (int64, error) {
	if walker == nil {
		return 0, fmt.Errorf("walker is nil")
	}
	addr := walker.GetN2addr()
	if addr.Space == nil {
		return 0, fmt.Errorf("next2 expression address space is nil")
	}
	return byteOffsetToAddressValue(addr.Offset, addr.Space), nil
}

func evalTokenField(expr PatternExprBoundary, walker *ParserWalker) (int64, error) {
	if walker == nil || walker.constContext == nil || walker.Point == nil {
		return 0, fmt.Errorf("token field requires active walker state")
	}
	bigendian, err := requiredBoolAttr(exprAttrSlice(expr), attrBigEndian)
	if err != nil {
		return 0, fmt.Errorf("read token field endian: %w", err)
	}
	signbit, err := requiredBoolAttr(exprAttrSlice(expr), attrSignBit)
	if err != nil {
		return 0, fmt.Errorf("read token field signbit: %w", err)
	}
	bitstart, err := requiredIntAttr(exprAttrSlice(expr), attrStartBit)
	if err != nil {
		return 0, fmt.Errorf("read token field startbit: %w", err)
	}
	bitend, err := requiredIntAttr(exprAttrSlice(expr), attrEndBit)
	if err != nil {
		return 0, fmt.Errorf("read token field endbit: %w", err)
	}
	bytestart, err := requiredIntAttr(exprAttrSlice(expr), attrStartByte)
	if err != nil {
		return 0, fmt.Errorf("read token field startbyte: %w", err)
	}
	byteend, err := requiredIntAttr(exprAttrSlice(expr), attrEndByte)
	if err != nil {
		return 0, fmt.Errorf("read token field endbyte: %w", err)
	}
	shift, err := requiredIntAttr(exprAttrSlice(expr), attrShift)
	if err != nil {
		return 0, fmt.Errorf("read token field shift: %w", err)
	}
	raw, err := getPatternInstructionBytes(walker, int(bytestart), int(byteend), bigendian)
	if err != nil {
		return 0, err
	}
	raw >>= uint(shift)
	return extendPatternValue(raw, int(bitend-bitstart+1), signbit)
}

func evalContextField(expr PatternExprBoundary, walker *ParserWalker) (int64, error) {
	if walker == nil || walker.constContext == nil {
		return 0, fmt.Errorf("context field requires active walker context")
	}
	signbit, err := requiredBoolAttr(exprAttrSlice(expr), attrSignBit)
	if err != nil {
		return 0, fmt.Errorf("read context field signbit: %w", err)
	}
	startbit, err := requiredIntAttr(exprAttrSlice(expr), attrStartBit)
	if err != nil {
		return 0, fmt.Errorf("read context field startbit: %w", err)
	}
	endbit, err := requiredIntAttr(exprAttrSlice(expr), attrEndBit)
	if err != nil {
		return 0, fmt.Errorf("read context field endbit: %w", err)
	}
	startbyte, err := requiredIntAttr(exprAttrSlice(expr), attrStartByte)
	if err != nil {
		return 0, fmt.Errorf("read context field startbyte: %w", err)
	}
	endbyte, err := requiredIntAttr(exprAttrSlice(expr), attrEndByte)
	if err != nil {
		return 0, fmt.Errorf("read context field endbyte: %w", err)
	}
	shift, err := requiredIntAttr(exprAttrSlice(expr), attrShift)
	if err != nil {
		return 0, fmt.Errorf("read context field shift: %w", err)
	}
	raw, err := getPatternContextBytes(walker, int(startbyte), int(endbyte))
	if err != nil {
		return 0, err
	}
	raw >>= uint(shift)
	return extendPatternValue(raw, int(endbit-startbit+1), signbit)
}

func evalOperandValue(expr PatternExprBoundary, walker *ParserWalker, hooks PatternExpressionValueHooks) (int64, error) {
	index, err := requiredIntAttr(exprAttrSlice(expr), attrIndex)
	if err != nil {
		return 0, fmt.Errorf("read operand expression index: %w", err)
	}
	if value, handled, err := evalOperandValueAuto(int(index), walker, hooks); err != nil {
		return 0, err
	} else if handled {
		return value, nil
	}
	if hooks.ResolveOperandValue == nil {
		return 0, newUnimplError(
			ErrPatternExpressionUnimplemented,
			fmt.Sprintf("operand %d requires OperandSymbol metadata from slghsymbol.cc", index),
		)
	}
	value, handled, err := hooks.ResolveOperandValue(OperandValueRequest{
		Expr:         expr,
		Walker:       walker,
		OperandIndex: index,
	})
	if err != nil {
		return 0, normalizePatternExpressionUnimpl(err)
	}
	if !handled {
		return 0, newUnimplError(ErrPatternExpressionUnimplemented, fmt.Sprintf("operand %d hook declined resolution", index))
	}
	return value, nil
}

func evalOperandValueAuto(index int, walker *ParserWalker, hooks PatternExpressionValueHooks) (int64, bool, error) {
	if walker == nil || walker.ParserContext() == nil || walker.ParserContext().GetSymbolTable() == nil {
		return 0, false, nil
	}
	state := nearestConstructorState(walker)
	if state == nil || state.Constructor == nil {
		return 0, false, nil
	}
	operand, ok := walker.ParserContext().GetSymbolTable().FindOperandForConstructor(state.Constructor, index)
	if !ok {
		return 0, false, nil
	}
	pattern := operand.DefiningExpression
	if pattern == nil && operand.HasDefiningSymbolID {
		defsym, ok := walker.ParserContext().GetSymbolTable().FindSymbol(operand.DefiningSymbolID)
		if ok {
			// ContextSymbol stores its expression inside Body.Context.Pattern.
			if defsym.Body.Context != nil && defsym.Body.Context.Pattern != nil {
				pattern = defsym.Body.Context.Pattern.Expression
			} else if defsym.Body.Pattern != nil {
				pattern = defsym.Body.Pattern.Expression
			}
		}
	}
	if pattern == nil {
		return 0, true, nil
	}
	var temp ConstructState
	newWalker := NewParserWalker(walker.ParserContext())
	if err := newWalker.SetOutOfBandState(state, index, &temp, walker); err != nil {
		return 0, true, newUnimplError(
			ErrPatternExpressionUnimplemented,
			fmt.Sprintf("operand %d out-of-band state setup failed: %v", index, err),
		)
	}
	value, err := GetPatternExpressionValue(pattern, newWalker, hooks)
	if err != nil {
		return 0, true, normalizePatternExpressionUnimpl(err)
	}
	return value, true, nil
}

func nearestConstructorState(walker *ParserWalker) *ConstructState {
	if walker == nil {
		return nil
	}
	for state := walker.Point; state != nil; state = state.Parent {
		if state.Constructor != nil {
			return state
		}
	}
	return nil
}

func evalBinaryExpr(expr PatternExprBoundary, walker *ParserWalker, hooks PatternExpressionValueHooks, op func(left, right int64) int64) (int64, error) {
	if len(expr.Children) != 2 {
		return 0, fmt.Errorf("binary pattern expression %d expected 2 children, got %d", expr.ElementID, len(expr.Children))
	}
	left, err := GetPatternExpressionValue(&expr.Children[0], walker, hooks)
	if err != nil {
		return 0, normalizePatternExpressionUnimpl(err)
	}
	right, err := GetPatternExpressionValue(&expr.Children[1], walker, hooks)
	if err != nil {
		return 0, normalizePatternExpressionUnimpl(err)
	}
	return op(left, right), nil
}

func evalUnaryExpr(expr PatternExprBoundary, walker *ParserWalker, hooks PatternExpressionValueHooks, op func(value int64) int64) (int64, error) {
	if len(expr.Children) != 1 {
		return 0, fmt.Errorf("unary pattern expression %d expected 1 child, got %d", expr.ElementID, len(expr.Children))
	}
	value, err := GetPatternExpressionValue(&expr.Children[0], walker, hooks)
	if err != nil {
		return 0, normalizePatternExpressionUnimpl(err)
	}
	return op(value), nil
}

func exprAttrSlice(expr PatternExprBoundary) []packedAttribute {
	if len(expr.Attrs) == 0 {
		return nil
	}
	result := make([]packedAttribute, 0, len(expr.Attrs))
	for _, attr := range expr.Attrs {
		result = append(result, attr)
	}
	return result
}

func getPatternInstructionBytes(walker *ParserWalker, bytestart, byteend int, bigendian bool) (uint64, error) {
	if bytestart < 0 || byteend < bytestart {
		return 0, fmt.Errorf("invalid token field byte window [%d,%d]", bytestart, byteend)
	}
	size := byteend - bytestart + 1
	data := walker.constContext.InstructionBytes
	base := int(walker.Point.Offset) + bytestart
	if base < 0 || base+size > len(data) {
		return 0, fmt.Errorf("token field window [%d,%d] exceeds instruction bytes", bytestart, byteend)
	}
	if size > 8 {
		return 0, newUnimplError(ErrPatternExpressionUnimplemented, fmt.Sprintf("token field width %d exceeds 8-byte shell", size))
	}
	var result uint64
	if bigendian {
		for i := 0; i < size; i++ {
			result <<= 8
			result |= uint64(data[base+i])
		}
		return result, nil
	}
	for i := size - 1; i >= 0; i-- {
		result <<= 8
		result |= uint64(data[base+i])
	}
	return result, nil
}

func getPatternContextBytes(walker *ParserWalker, bytestart, byteend int) (uint64, error) {
	if bytestart < 0 || byteend < bytestart {
		return 0, fmt.Errorf("invalid context field byte window [%d,%d]", bytestart, byteend)
	}
	size := byteend - bytestart + 1
	if size > 8 {
		return 0, newUnimplError(ErrPatternExpressionUnimplemented, fmt.Sprintf("context field width %d exceeds 8-byte shell", size))
	}
	return walker.GetContextBytes(bytestart, size)
}

func extendPatternValue(raw uint64, width int, signbit bool) (int64, error) {
	if width <= 0 || width > 64 {
		return 0, fmt.Errorf("invalid pattern value width %d", width)
	}
	if width < 64 {
		raw &= (uint64(1) << uint(width)) - 1
	}
	if !signbit {
		return int64(raw), nil
	}
	if width == 64 {
		return int64(raw), nil
	}
	signMask := uint64(1) << uint(width-1)
	if raw&signMask == 0 {
		return int64(raw), nil
	}
	raw |= ^((uint64(1) << uint(width)) - 1)
	return int64(raw), nil
}

func byteOffsetToAddressValue(offset uint64, space *address.Space) int64 {
	if space == nil || space.WordSize <= 1 {
		return int64(offset)
	}
	return int64(offset / uint64(space.WordSize))
}
