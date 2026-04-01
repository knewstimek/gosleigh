package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"gosleigh/pkg/address"
)

func TestGetPatternExpressionValueArithmeticShell(t *testing.T) {
	expr := patternExpr(elemSubExp,
		patternExpr(elemPlusExp,
			patternConst(7),
			patternConst(5),
		),
		patternExpr(elemMultExp,
			patternConst(2),
			patternConst(3),
		),
	)

	value, err := GetPatternExpressionValue(&expr, nil, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("GetPatternExpressionValue() error: %v", err)
	}
	if value != 6 {
		t.Fatalf("unexpected arithmetic value: got %d", value)
	}
}

func TestGetPatternExpressionValueUnaryShell(t *testing.T) {
	expr := patternExpr(elemMinusExp,
		patternExpr(elemNotExp, patternConst(1)),
	)

	value, err := GetPatternExpressionValue(&expr, nil, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("GetPatternExpressionValue() error: %v", err)
	}
	if value != 2 {
		t.Fatalf("unexpected unary value: got %d", value)
	}
}

func TestGetPatternExpressionValueWalkerAccessShell(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 4, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x20}, nil)
	ctx.SetNaddr(address.Address{Space: ram, Offset: 0x28})
	ctx.SetN2addr(address.Address{Space: ram, Offset: 0x30})
	ctx.SetInstructionBytes([]byte{0x12, 0x34, 0x56, 0x78})
	ctx.SetContextWords([]uint64{0xF100000000000000})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	startExpr := patternExpr(elemStartExp)
	startValue, err := GetPatternExpressionValue(&startExpr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("start expression error: %v", err)
	}
	if startValue != 0x8 {
		t.Fatalf("unexpected start value: got 0x%x", startValue)
	}

	endExpr := patternExpr(elemEndExp)
	endValue, err := GetPatternExpressionValue(&endExpr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("end expression error: %v", err)
	}
	if endValue != 0xa {
		t.Fatalf("unexpected end value: got 0x%x", endValue)
	}

	next2Expr := patternExpr(elemNext2Exp)
	next2Value, err := GetPatternExpressionValue(&next2Expr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("next2 expression error: %v", err)
	}
	if next2Value != 0xc {
		t.Fatalf("unexpected next2 value: got 0x%x", next2Value)
	}

	tokenExpr := patternExpr(elemTokenField,
		patternBoolAttr(attrBigEndian, false),
		patternBoolAttr(attrSignBit, false),
		patternIntAttr(attrStartBit, 0),
		patternIntAttr(attrEndBit, 15),
		patternIntAttr(attrStartByte, 0),
		patternIntAttr(attrEndByte, 1),
		patternIntAttr(attrShift, 0),
	)
	tokenValue, err := GetPatternExpressionValue(&tokenExpr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("token field error: %v", err)
	}
	if tokenValue != 0x3412 {
		t.Fatalf("unexpected token field value: got 0x%x", tokenValue)
	}

	contextExpr := patternExpr(elemContextField,
		patternBoolAttr(attrSignBit, true),
		patternIntAttr(attrStartBit, 0),
		patternIntAttr(attrEndBit, 3),
		patternIntAttr(attrStartByte, 0),
		patternIntAttr(attrEndByte, 0),
		patternIntAttr(attrShift, 4),
	)
	contextValue, err := GetPatternExpressionValue(&contextExpr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("context field error: %v", err)
	}
	if contextValue != -1 {
		t.Fatalf("unexpected context field value: got %d", contextValue)
	}
}

func TestGetPatternExpressionValueOperandHookShell(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30})
	ctx.BaseState.Offset = 1

	walker := NewParserWalker(ctx)
	walker.BaseState()

	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 2))
	value, err := GetPatternExpressionValue(&expr, walker, PatternExpressionValueHooks{
		ResolveOperandValue: func(req OperandValueRequest) (int64, bool, error) {
			if req.OperandIndex != 2 {
				t.Fatalf("unexpected operand index: got %d", req.OperandIndex)
			}
			if req.Walker != walker {
				t.Fatal("operand hook received unexpected walker")
			}
			byteValue, err := req.Walker.GetInstructionBytes(0, 1)
			if err != nil {
				return 0, false, err
			}
			return int64(byteValue) + 1, true, nil
		},
	})
	if err != nil {
		t.Fatalf("operand expression error: %v", err)
	}
	if value != 0x21 {
		t.Fatalf("unexpected operand expression value: got 0x%x", value)
	}
}

func TestGetPatternExpressionValueNormalizesHookSentinelErrorToTypedUnimpl(t *testing.T) {
	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 0))
	_, err := GetPatternExpressionValue(&expr, nil, PatternExpressionValueHooks{
		ResolveOperandValue: func(req OperandValueRequest) (int64, bool, error) {
			return 0, false, fmt.Errorf("%w: operand hook parity gap", ErrPatternExpressionUnimplemented)
		},
	})
	if err == nil {
		t.Fatal("GetPatternExpressionValue() returned nil for sentinel hook error")
	}
	if !errors.Is(err, ErrPatternExpressionUnimplemented) {
		t.Fatalf("GetPatternExpressionValue() error does not wrap ErrPatternExpressionUnimplemented: %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("GetPatternExpressionValue() error type = %T, want *UnimplError", err)
	}
	if !strings.Contains(uerr.Explain, "operand hook parity gap") {
		t.Fatalf("pattern expression unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestGetPatternExpressionValueResolvesOperandAutomaticallyFromBoundary(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30})
	ctx.SetNaddr(address.Address{Space: ram, Offset: 0x1003})
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 7,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:              0,
			LocalExpression:    &PatternExprBoundary{ElementID: elemOperandExp, Attrs: map[uint32]packedAttribute{attrIndex: patternIntAttr(attrIndex, 0)}},
			DefiningExpression: &PatternExprBoundary{ElementID: elemPlusExp, Attrs: map[uint32]packedAttribute{}, Children: []PatternExprBoundary{patternConst(1), patternConst(2)}},
		}},
	}}})
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{7}})
	ctx.BaseState.Children = []*ConstructState{{Parent: ctx.BaseState, OperandIndex: 0, Offset: 1, Length: 1}}

	walker := NewParserWalker(ctx)
	walker.BaseState()
	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 0))
	value, err := GetPatternExpressionValue(&expr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("GetPatternExpressionValue() error: %v", err)
	}
	if value != 3 {
		t.Fatalf("unexpected automatic operand value: got %d", value)
	}
}

func TestGetPatternExpressionValueResolvesConstructorRelativeOperandWithoutChild(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30})
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 7,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:          0,
			RelativeOffset: 1,
			OffsetBase:     -1,
			MinimumLength:  1,
			DefiningExpression: &PatternExprBoundary{
				ElementID: elemTokenField,
				Attrs: map[uint32]packedAttribute{
					attrBigEndian: patternBoolAttr(attrBigEndian, false),
					attrSignBit:   patternBoolAttr(attrSignBit, false),
					attrStartBit:  patternIntAttr(attrStartBit, 0),
					attrEndBit:    patternIntAttr(attrEndBit, 7),
					attrStartByte: patternIntAttr(attrStartByte, 0),
					attrEndByte:   patternIntAttr(attrEndByte, 0),
					attrShift:     patternIntAttr(attrShift, 0),
				},
			},
		}},
	}}})
	ctx.BaseState.Offset = 0
	ctx.BaseState.Length = 3
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{7}})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 0))
	value, err := GetPatternExpressionValue(&expr, walker, PatternExpressionValueHooks{})
	if err != nil {
		t.Fatalf("GetPatternExpressionValue() error: %v", err)
	}
	if value != 0x20 {
		t.Fatalf("unexpected constructor-relative automatic operand value: got 0x%x", value)
	}
}

func TestGetPatternExpressionValueReportsOutOfBandGapForNonRelativeOperandWithoutChild(t *testing.T) {
	ram := &address.Space{Name: "ram", Kind: address.SpaceKindProcessor, Index: 1, AddrSize: 8, WordSize: 1, Physical: true}
	ctx := NewParserContext(address.Address{Space: ram, Offset: 0x1000}, nil)
	ctx.SetInstructionBytes([]byte{0x10, 0x20, 0x30})
	ctx.SetSymbolTable(&SymbolTableBoundary{Symbols: []SymbolBoundary{{
		ID: 7,
		Body: SymbolBodyBoundary{Operand: &OperandSymbolBoundary{
			Index:          0,
			RelativeOffset: 0,
			OffsetBase:     0,
			MinimumLength:  1,
			DefiningExpression: &PatternExprBoundary{
				ElementID: elemTokenField,
				Attrs: map[uint32]packedAttribute{
					attrBigEndian: patternBoolAttr(attrBigEndian, false),
					attrSignBit:   patternBoolAttr(attrSignBit, false),
					attrStartBit:  patternIntAttr(attrStartBit, 0),
					attrEndBit:    patternIntAttr(attrEndBit, 7),
					attrStartByte: patternIntAttr(attrStartByte, 0),
					attrEndByte:   patternIntAttr(attrEndByte, 0),
					attrShift:     patternIntAttr(attrShift, 0),
				},
			},
		}},
	}}})
	ctx.BaseState.Offset = 0
	ctx.BaseState.Length = 3
	ctx.BaseState.SetConstructor(ConstructorBoundary{OperandSymbolIDs: []uint64{7}})

	walker := NewParserWalker(ctx)
	walker.BaseState()

	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 0))
	_, err := GetPatternExpressionValue(&expr, walker, PatternExpressionValueHooks{})
	if !errors.Is(err, ErrPatternExpressionUnimplemented) {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if !strings.Contains(uerr.Explain, "out-of-band state setup failed") {
		t.Fatalf("unexpected out-of-band explain: %q", uerr.Explain)
	}
}

func TestGetPatternExpressionValueMarksOperandWithoutHookUnimplemented(t *testing.T) {
	expr := patternExpr(elemOperandExp, patternIntAttr(attrIndex, 0))
	_, err := GetPatternExpressionValue(&expr, nil, PatternExpressionValueHooks{})
	if !errors.Is(err, ErrPatternExpressionUnimplemented) {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "operand 0 requires OperandSymbol metadata from slghsymbol.cc" {
		t.Fatalf("operand unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func TestGetPatternExpressionValueMarksUnknownNodeUnimplemented(t *testing.T) {
	expr := patternExpr(0xffff)
	_, err := GetPatternExpressionValue(&expr, nil, PatternExpressionValueHooks{})
	if !errors.Is(err, ErrPatternExpressionUnimplemented) {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
	var uerr *UnimplError
	if !errors.As(err, &uerr) {
		t.Fatalf("error type = %T, want *UnimplError", err)
	}
	if uerr.Explain != "element 65535" {
		t.Fatalf("unknown-element unimplemented explain mismatch: got %q", uerr.Explain)
	}
}

func patternExpr(id uint32, parts ...interface{}) PatternExprBoundary {
	expr := PatternExprBoundary{
		ElementID: id,
		Attrs:     make(map[uint32]packedAttribute),
	}
	for _, part := range parts {
		switch value := part.(type) {
		case packedAttribute:
			expr.Attrs[value.ID] = value
		case PatternExprBoundary:
			expr.Children = append(expr.Children, value)
		default:
			panic("unsupported pattern expression test part")
		}
	}
	return expr
}

func patternConst(value int64) PatternExprBoundary {
	return patternExpr(elemIntB, patternIntAttr(attrVal, value))
}

func patternIntAttr(id uint32, value int64) packedAttribute {
	return packedAttribute{ID: id, Type: attributeValueInt, Int: value}
}

func patternBoolAttr(id uint32, value bool) packedAttribute {
	return packedAttribute{ID: id, Type: attributeValueBool, Bool: value}
}
