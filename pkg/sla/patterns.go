package sla

import "fmt"

// PatternExprBoundary is the shallow decoded form of one PatternExpression node.
type PatternExprBoundary struct {
	ElementID uint32
	Attrs     map[uint32]packedAttribute
	Children  []PatternExprBoundary
}

// PatternBlockBoundary preserves one mask/value pattern block.
type PatternBlockBoundary struct {
	Offset      int64
	NonZeroSize int64
	MaskWords   []PatternMaskWordBoundary
}

// PatternMaskWordBoundary preserves one packed mask/value pair.
type PatternMaskWordBoundary struct {
	Mask uint64
	Val  uint64
}

// Pattern blocks in the persisted .sla stream are encoded as 32-bit uintm words.
// Matchers must read and advance in the same 4-byte units even on 64-bit hosts.
const patternMaskWordBytes = 4

const maxPatternMaskWord32 = uint64(^uint32(0))

func patternBlockWordBytes(block PatternBlockBoundary) int {
	for _, word := range block.MaskWords {
		if word.Mask > maxPatternMaskWord32 || word.Val > maxPatternMaskWord32 {
			return 8
		}
	}
	return patternMaskWordBytes
}

// DisjointPatternBoundary is the shallow decoded form of one disjoint pattern subtree.
type DisjointPatternBoundary struct {
	ElementID uint32
	Block     *PatternBlockBoundary
	Children  []DisjointPatternBoundary
}

func decodePatternExpression(elem packedElement) (*PatternExprBoundary, error) {
	if !isPatternExpressionElement(elem.ID) {
		return nil, fmt.Errorf("unsupported pattern expression element %d", elem.ID)
	}
	result := &PatternExprBoundary{ElementID: elem.ID, Attrs: copyAttrMap(elem.Attrs)}
	for _, child := range elem.Children {
		sub, err := decodePatternExpression(child)
		if err != nil {
			return nil, err
		}
		result.Children = append(result.Children, *sub)
	}
	return result, nil
}

func decodeDisjointPattern(elem packedElement) (*DisjointPatternBoundary, error) {
	result := &DisjointPatternBoundary{ElementID: elem.ID}
	switch elem.ID {
	case elemInstructPat, elemContextPat:
		if len(elem.Children) != 1 {
			return nil, fmt.Errorf("pattern %d expected one pat_block child", elem.ID)
		}
		block, err := decodePatternBlock(elem.Children[0])
		if err != nil {
			return nil, err
		}
		result.Block = block
	case elemCombinePat:
		for _, child := range elem.Children {
			sub, err := decodeDisjointPattern(child)
			if err != nil {
				return nil, err
			}
			result.Children = append(result.Children, *sub)
		}
	default:
		return nil, fmt.Errorf("unsupported disjoint pattern element %d", elem.ID)
	}
	return result, nil
}

func decodePatternTree(elem packedElement) (*DisjointPatternBoundary, error) {
	if elem.ID == elemOrPat {
		result := &DisjointPatternBoundary{ElementID: elem.ID}
		for _, child := range elem.Children {
			sub, err := decodeDisjointPattern(child)
			if err != nil {
				return nil, err
			}
			result.Children = append(result.Children, *sub)
		}
		return result, nil
	}
	return decodeDisjointPattern(elem)
}

func decodePatternBlock(elem packedElement) (*PatternBlockBoundary, error) {
	if elem.ID != elemPatBlock {
		return nil, fmt.Errorf("unexpected pattern block element %d", elem.ID)
	}
	offset, err := requiredIntAttr(elem.Attrs, attrOff)
	if err != nil {
		return nil, fmt.Errorf("read pattern block offset: %w", err)
	}
	nonzero, err := requiredIntAttr(elem.Attrs, attrNonZero)
	if err != nil {
		return nil, fmt.Errorf("read pattern block nonzero size: %w", err)
	}
	result := &PatternBlockBoundary{Offset: offset, NonZeroSize: nonzero}
	for _, child := range elem.Children {
		if child.ID != elemMaskWord {
			continue
		}
		mask, err := requiredUintAttr(child.Attrs, attrMask)
		if err != nil {
			return nil, fmt.Errorf("read pattern mask: %w", err)
		}
		val, err := requiredUintAttr(child.Attrs, attrVal)
		if err != nil {
			return nil, fmt.Errorf("read pattern value: %w", err)
		}
		result.MaskWords = append(result.MaskWords, PatternMaskWordBoundary{Mask: mask, Val: val})
	}
	return result, nil
}

func isPatternExpressionElement(id uint32) bool {
	switch id {
	case elemTokenField, elemContextField, elemIntB, elemOperandExp, elemStartExp, elemEndExp, elemNext2Exp,
		elemPlusExp, elemSubExp, elemMultExp, elemLShiftExp, elemRShiftExp,
		elemAndExp, elemOrExp, elemXorExp, elemDivExp, elemMinusExp, elemNotExp:
		return true
	default:
		return false
	}
}

func copyAttrMap(attrs []packedAttribute) map[uint32]packedAttribute {
	result := make(map[uint32]packedAttribute, len(attrs))
	for _, attr := range attrs {
		result[attr.ID] = attr
	}
	return result
}
