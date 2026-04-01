package sla

import "fmt"

// ConstKind is the shallow decoded kind of a persisted ConstTpl.
type ConstKind string

const (
	ConstKindReal         ConstKind = "real"
	ConstKindHandle       ConstKind = "handle"
	ConstKindStart        ConstKind = "start"
	ConstKindNext         ConstKind = "next"
	ConstKindNext2        ConstKind = "next2"
	ConstKindCurSpace     ConstKind = "curspace"
	ConstKindCurSpaceSize ConstKind = "curspace_size"
	ConstKindSpaceID      ConstKind = "spaceid"
	ConstKindRelative     ConstKind = "relative"
	ConstKindFlowRef      ConstKind = "flowref"
	ConstKindFlowRefSize  ConstKind = "flowref_size"
	ConstKindFlowDest     ConstKind = "flowdest"
	ConstKindFlowDestSize ConstKind = "flowdest_size"
)

// ConstBoundary is the preserved form of one ConstTpl subtree.
type ConstBoundary struct {
	Kind        ConstKind
	ElementID   uint32
	Value       uint64
	HandleIndex int64
	Selector    int64
	Plus        uint64
	SpaceIndex  int64
}

// VarnodeTplBoundary is the preserved form of one VarnodeTpl subtree.
type VarnodeTplBoundary struct {
	Space  ConstBoundary
	Offset ConstBoundary
	Size   ConstBoundary
}

// HandleTplBoundary is the preserved form of one HandleTpl subtree.
type HandleTplBoundary struct {
	Space      ConstBoundary
	Size       ConstBoundary
	PtrSpace   ConstBoundary
	PtrOffset  ConstBoundary
	PtrSize    ConstBoundary
	TempSpace  ConstBoundary
	TempOffset ConstBoundary
}

// OpTplBoundary is the preserved form of one OpTpl subtree.
type OpTplBoundary struct {
	OpcodeID int64
	Opcode   string
	Output   *VarnodeTplBoundary
	Inputs   []VarnodeTplBoundary
}

// ConstructTplBoundary is the preserved form of one ConstructTpl subtree.
type ConstructTplBoundary struct {
	SectionID *int64
	DelaySlot uint64
	NumLabels uint64
	Result    *HandleTplBoundary
	Ops       []OpTplBoundary
}

func decodeConstructTpl(elem packedElement) (*ConstructTplBoundary, error) {
	if elem.ID != elemConstructTpl {
		return nil, fmt.Errorf("unexpected construct tpl element %d", elem.ID)
	}
	result := &ConstructTplBoundary{}
	if sectionID, ok := optionalIntAttr(elem.Attrs, attrSection); ok {
		result.SectionID = &sectionID
	}
	result.DelaySlot = uint64(optionalIntAttrDefault(elem.Attrs, attrDelay, 0))
	result.NumLabels = uint64(optionalIntAttrDefault(elem.Attrs, attrLabels, 0))
	if len(elem.Children) == 0 {
		return nil, fmt.Errorf("construct tpl missing result child")
	}
	first := elem.Children[0]
	if first.ID == elemNull {
		result.Result = nil
	} else if first.ID == elemHandleTpl {
		handle, err := decodeHandleTpl(first)
		if err != nil {
			return nil, err
		}
		result.Result = handle
	} else {
		return nil, fmt.Errorf("unexpected construct tpl result element %d", first.ID)
	}
	for _, child := range elem.Children[1:] {
		if child.ID != elemOpTpl {
			continue
		}
		op, err := decodeOpTpl(child)
		if err != nil {
			return nil, err
		}
		result.Ops = append(result.Ops, op)
	}
	return result, nil
}

func decodeHandleTpl(elem packedElement) (*HandleTplBoundary, error) {
	if elem.ID != elemHandleTpl {
		return nil, fmt.Errorf("unexpected handle tpl element %d", elem.ID)
	}
	if len(elem.Children) != 7 {
		return nil, fmt.Errorf("handle tpl expected 7 const children, got %d", len(elem.Children))
	}
	decoded := make([]ConstBoundary, 7)
	for i, child := range elem.Children {
		constant, err := decodeConst(child)
		if err != nil {
			return nil, err
		}
		decoded[i] = constant
	}
	return &HandleTplBoundary{
		Space:      decoded[0],
		Size:       decoded[1],
		PtrSpace:   decoded[2],
		PtrOffset:  decoded[3],
		PtrSize:    decoded[4],
		TempSpace:  decoded[5],
		TempOffset: decoded[6],
	}, nil
}

func decodeOpTpl(elem packedElement) (OpTplBoundary, error) {
	if elem.ID != elemOpTpl {
		return OpTplBoundary{}, fmt.Errorf("unexpected op tpl element %d", elem.ID)
	}
	opcode, err := requiredIntAttr(elem.Attrs, attrCode)
	if err != nil {
		return OpTplBoundary{}, fmt.Errorf("read op tpl opcode: %w", err)
	}
	result := OpTplBoundary{OpcodeID: opcode, Opcode: decodeOpcodeName(opcode)}
	if len(elem.Children) == 0 {
		return OpTplBoundary{}, fmt.Errorf("op tpl missing output child")
	}
	first := elem.Children[0]
	if first.ID == elemNull {
		result.Output = nil
	} else if first.ID == elemVarnodeTpl {
		output, err := decodeVarnodeTpl(first)
		if err != nil {
			return OpTplBoundary{}, err
		}
		result.Output = output
	} else {
		return OpTplBoundary{}, fmt.Errorf("unexpected op tpl output element %d", first.ID)
	}
	for _, child := range elem.Children[1:] {
		if child.ID != elemVarnodeTpl {
			continue
		}
		input, err := decodeVarnodeTpl(child)
		if err != nil {
			return OpTplBoundary{}, err
		}
		result.Inputs = append(result.Inputs, *input)
	}
	return result, nil
}

func decodeVarnodeTpl(elem packedElement) (*VarnodeTplBoundary, error) {
	if elem.ID != elemVarnodeTpl {
		return nil, fmt.Errorf("unexpected varnode tpl element %d", elem.ID)
	}
	if len(elem.Children) != 3 {
		return nil, fmt.Errorf("varnode tpl expected 3 const children, got %d", len(elem.Children))
	}
	space, err := decodeConst(elem.Children[0])
	if err != nil {
		return nil, err
	}
	offset, err := decodeConst(elem.Children[1])
	if err != nil {
		return nil, err
	}
	size, err := decodeConst(elem.Children[2])
	if err != nil {
		return nil, err
	}
	return &VarnodeTplBoundary{Space: space, Offset: offset, Size: size}, nil
}

func decodeConst(elem packedElement) (ConstBoundary, error) {
	result := ConstBoundary{ElementID: elem.ID}
	switch elem.ID {
	case elemConstReal:
		value, err := requiredUintAttr(elem.Attrs, attrVal)
		if err != nil {
			return ConstBoundary{}, fmt.Errorf("read const real value: %w", err)
		}
		result.Kind = ConstKindReal
		result.Value = value
	case elemConstHandle:
		handleIndex, err := requiredIntAttr(elem.Attrs, attrVal)
		if err != nil {
			return ConstBoundary{}, fmt.Errorf("read const handle index: %w", err)
		}
		selector, err := requiredIntAttr(elem.Attrs, attrS)
		if err != nil {
			return ConstBoundary{}, fmt.Errorf("read const handle selector: %w", err)
		}
		result.Kind = ConstKindHandle
		result.HandleIndex = handleIndex
		result.Selector = selector
		result.Plus = optionalUintAttr(elem.Attrs, attrPlus)
	case elemConstStart:
		result.Kind = ConstKindStart
	case elemConstNext:
		result.Kind = ConstKindNext
	case elemConstNext2:
		result.Kind = ConstKindNext2
	case elemConstCurSpace:
		result.Kind = ConstKindCurSpace
	case elemConstCurSpaceSize:
		result.Kind = ConstKindCurSpaceSize
	case elemConstSpaceID:
		spaceIndex, err := requiredIntAttr(elem.Attrs, attrSpace)
		if err != nil {
			return ConstBoundary{}, fmt.Errorf("read const space index: %w", err)
		}
		result.Kind = ConstKindSpaceID
		result.SpaceIndex = spaceIndex
	case elemConstRelative:
		value, err := requiredUintAttr(elem.Attrs, attrVal)
		if err != nil {
			return ConstBoundary{}, fmt.Errorf("read const relative value: %w", err)
		}
		result.Kind = ConstKindRelative
		result.Value = value
	case elemConstFlowRef:
		result.Kind = ConstKindFlowRef
	case elemConstFlowRefSize:
		result.Kind = ConstKindFlowRefSize
	case elemConstFlowDest:
		result.Kind = ConstKindFlowDest
	case elemConstFlowDestSize:
		result.Kind = ConstKindFlowDestSize
	default:
		return ConstBoundary{}, fmt.Errorf("unsupported const element %d", elem.ID)
	}
	return result, nil
}
