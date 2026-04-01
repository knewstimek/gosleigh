package sla

import "fmt"

const decisionPatternWordBytes = 8

// ResolveSubtableDecision mirrors SubtableSymbol::resolve() by dispatching into the
// persisted decision tree for the current walker state.
func ResolveSubtableDecision(subtable *SubtableBoundary, walker *ParserWalker) (*ConstructorBoundary, error) {
	if subtable == nil {
		return nil, fmt.Errorf("subtable is nil")
	}
	if walker == nil {
		return nil, fmt.Errorf("walker is nil")
	}
	if subtable.Decision == nil {
		return nil, fmt.Errorf("subtable has no decision tree")
	}
	return ResolveDecisionNode(subtable, subtable.Decision, walker)
}

// ResolveDecisionNode mirrors DecisionNode::resolve() for the currently selected parser state.
func ResolveDecisionNode(subtable *SubtableBoundary, node *DecisionNodeBoundary, walker *ParserWalker) (*ConstructorBoundary, error) {
	if subtable == nil {
		return nil, fmt.Errorf("subtable is nil")
	}
	if node == nil {
		return nil, fmt.Errorf("decision node is nil")
	}
	if walker == nil {
		return nil, fmt.Errorf("walker is nil")
	}
	if node.Size == 0 {
		for _, pair := range node.Pairs {
			matched, err := matchDecisionPattern(pair.Pattern, walker)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}
			return constructorByID(subtable, pair.ConstructorID)
		}
		return nil, fmt.Errorf("%s: unable to resolve constructor", walker.GetAddr())
	}

	var (
		value uint64
		err   error
	)
	if node.Context {
		value, err = walker.GetContextBits(int(node.StartBit), int(node.Size))
	} else {
		value, err = walker.GetInstructionBits(int(node.StartBit), int(node.Size))
	}
	if err != nil {
		return nil, err
	}
	if value >= uint64(len(node.Children)) {
		return nil, fmt.Errorf("decision child index %d out of range", value)
	}
	return ResolveDecisionNode(subtable, &node.Children[value], walker)
}

func matchDecisionPattern(pattern *DisjointPatternBoundary, walker *ParserWalker) (bool, error) {
	if pattern == nil {
		return true, nil
	}
	switch pattern.ElementID {
	case elemOrPat:
		for _, child := range pattern.Children {
			matched, err := matchDecisionPattern(&child, walker)
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	case elemInstructPat:
		if pattern.Block == nil {
			return false, fmt.Errorf("instruction pattern missing pattern block")
		}
		return matchDecisionPatternBlock(*pattern.Block, false, walker)
	case elemContextPat:
		if pattern.Block == nil {
			return false, fmt.Errorf("context pattern missing pattern block")
		}
		return matchDecisionPatternBlock(*pattern.Block, true, walker)
	case elemCombinePat:
		for _, child := range pattern.Children {
			matched, err := matchDecisionPattern(&child, walker)
			if err != nil {
				return false, err
			}
			if !matched {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported pattern element %d", pattern.ElementID)
	}
}

func matchDecisionPatternBlock(block PatternBlockBoundary, context bool, walker *ParserWalker) (bool, error) {
	if block.NonZeroSize <= 0 {
		return block.NonZeroSize == 0, nil
	}
	offset := int(block.Offset)
	for _, word := range block.MaskWords {
		var (
			data uint64
			err  error
		)
		if context {
			data, err = walker.GetContextBytes(offset, decisionPatternWordBytes)
		} else {
			data, err = walker.GetInstructionBytes(offset, decisionPatternWordBytes)
		}
		if err != nil {
			return false, err
		}
		if (word.Mask & data) != word.Val {
			return false, nil
		}
		offset += decisionPatternWordBytes
	}
	return true, nil
}
