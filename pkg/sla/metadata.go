package sla

import (
	"fmt"
	"math"

	"gosleigh/pkg/address"
	"gosleigh/pkg/pcode"
)

const (
	elemConstReal         = 1
	elemVarnodeTpl        = 2
	elemConstSpaceID      = 3
	elemConstHandle       = 4
	elemOpTpl             = 5
	elemMaskWord          = 6
	elemPatBlock          = 7
	elemPrint             = 8
	elemPair              = 9
	elemContextPat        = 10
	elemNull              = 11
	elemOperandExp        = 12
	elemOperandSym        = 13
	elemOperandSymHead    = 14
	elemOper              = 15
	elemDecision          = 16
	elemOpPrint           = 17
	elemInstructPat       = 18
	elemCombinePat        = 19
	elemConstructor       = 20
	elemConstructTpl      = 21
	elemScope             = 22
	elemVarnodeSym        = 23
	elemVarnodeSymHead    = 24
	elemUserOp            = 25
	elemUserOpHead        = 26
	elemTokenField        = 27
	elemVar               = 28
	elemContextField      = 29
	elemHandleTpl         = 30
	elemConstRelative     = 31
	elemContextOp         = 32
	elemSleigh            = 33
	elemSpaces            = 34
	elemSourceFiles       = 35
	elemSourceFile        = 36
	elemSpace             = 37
	elemSymbolTable       = 38
	elemValueSym          = 39
	elemValueSymHead      = 40
	elemContextSym        = 41
	elemContextSymHead    = 42
	elemEndSym            = 43
	elemEndSymHead        = 44
	elemSpaceOther        = 45
	elemSpaceUnique       = 46
	elemAndExp            = 47
	elemDivExp            = 48
	elemLShiftExp         = 49
	elemMinusExp          = 50
	elemMultExp           = 51
	elemNotExp            = 52
	elemOrExp             = 53
	elemPlusExp           = 54
	elemRShiftExp         = 55
	elemSubExp            = 56
	elemXorExp            = 57
	elemIntB              = 58
	elemEndExp            = 59
	elemNext2Exp          = 60
	elemStartExp          = 61
	elemEpsilonSym        = 62
	elemEpsilonSymHead    = 63
	elemNameSym           = 64
	elemNameSymHead       = 65
	elemNameTab           = 66
	elemNext2Sym          = 67
	elemNext2SymHead      = 68
	elemStartSym          = 69
	elemStartSymHead      = 70
	elemSubtableSym       = 71
	elemSubtableSymHead   = 72
	elemValueMapSym       = 73
	elemValueMapSymHead   = 74
	elemValueTab          = 75
	elemVarListSym        = 76
	elemVarListSymHead    = 77
	elemOrPat             = 78
	elemCommit            = 79
	elemConstStart        = 80
	elemConstNext         = 81
	elemConstNext2        = 82
	elemConstCurSpace     = 83
	elemConstCurSpaceSize = 84
	// slaformat.hh defines flow address constants but no flow symbol head/body elements.
	// FlowDestSymbol/FlowRefSymbol are runtime-only symbols in slghsymbol.cc.
	elemConstFlowRef      = 85
	elemConstFlowRefSize  = 86
	elemConstFlowDest     = 87
	elemConstFlowDestSize = 88
)

const (
	attrVal          = 2
	attrID           = 3
	attrSpace        = 4
	attrS            = 5
	attrOff          = 6
	attrCode         = 7
	attrMask         = 8
	attrIndex        = 9
	attrNonZero      = 10
	attrPiece        = 11
	attrName         = 12
	attrScope        = 13
	attrStartBit     = 14
	attrSize         = 15
	attrTable        = 16
	attrCT           = 17
	attrMinLen       = 18
	attrBase         = 19
	attrNumber       = 20
	attrContext      = 21
	attrParent       = 22
	attrSubSym       = 23
	attrLine         = 24
	attrSource       = 25
	attrLength       = 26
	attrFirst        = 27
	attrPlus         = 28
	attrShift        = 29
	attrEndBit       = 30
	attrSignBit      = 31
	attrEndByte      = 32
	attrStartByte    = 33
	attrVersion      = 34
	attrBigEndian    = 35
	attrAlign        = 36
	attrUniqBase     = 37
	attrMaxDelay     = 38
	attrUniqMask     = 39
	attrNumSections  = 40
	attrDefaultSpace = 41
	attrDelay        = 42
	attrWordSize     = 43
	attrPhysical     = 44
	attrScopeSize    = 45
	attrSymbolSize   = 46
	attrVarnode      = 47
	attrLow          = 48
	attrHigh         = 49
	attrFlow         = 50
	attrContain      = 51
	attrI            = 52
	attrNumCT        = 53
	attrSection      = 54
	attrLabels       = 55
)

// Metadata is the first decoded view of the <sleigh> root and its encoded spaces.
type Metadata struct {
	Version      int64
	BigEndian    bool
	Align        int64
	UniqueBase   uint64
	MaxDelay     uint64
	UniqueMask   uint64
	NumSections  uint64
	DefaultSpace string
	Spaces       []address.Space
}

func DecodeMetadataPayload(payload []byte) (*Metadata, error) {
	root, err := decodeRootElement(payload)
	if err != nil {
		return nil, err
	}
	return decodeMetadata(root)
}

func decodeRootElement(payload []byte) (*packedElement, error) {
	if isXMLPayload(payload) {
		return parseXMLRootElement(payload)
	}
	root, err := parsePackedElement(payload)
	if err != nil {
		return nil, err
	}
	if root.ID != elemSleigh {
		return nil, fmt.Errorf("unexpected root element: got %d want %d", root.ID, elemSleigh)
	}
	return root, nil
}

func decodeMetadata(root *packedElement) (*Metadata, error) {
	metadata := &Metadata{}
	version, err := requiredIntAttr(root.Attrs, attrVersion)
	if err != nil {
		return nil, fmt.Errorf("read sleigh version: %w", err)
	}
	metadata.Version = version
	if metadata.Version != FormatVersion && metadata.Version != XMLFormatVersion {
		return nil, fmt.Errorf("unsupported sleigh format version: got %d want %d or %d", metadata.Version, XMLFormatVersion, FormatVersion)
	}
	metadata.BigEndian, err = requiredBoolAttr(root.Attrs, attrBigEndian)
	if err != nil {
		return nil, fmt.Errorf("read sleigh bigendian: %w", err)
	}
	metadata.Align, err = requiredIntAttr(root.Attrs, attrAlign)
	if err != nil {
		return nil, fmt.Errorf("read sleigh align: %w", err)
	}
	metadata.UniqueBase, err = requiredUintAttr(root.Attrs, attrUniqBase)
	if err != nil {
		return nil, fmt.Errorf("read sleigh uniqbase: %w", err)
	}
	metadata.MaxDelay = optionalUintAttr(root.Attrs, attrMaxDelay)
	metadata.UniqueMask = optionalUintAttr(root.Attrs, attrUniqMask)
	metadata.NumSections = optionalUintAttr(root.Attrs, attrNumSections)

	spacesElem, err := findChild(*root, elemSpaces)
	if err != nil {
		return nil, err
	}
	metadata.DefaultSpace, err = requiredStringAttr(spacesElem.Attrs, attrDefaultSpace)
	if err != nil {
		return nil, fmt.Errorf("read default space: %w", err)
	}
	for _, child := range spacesElem.Children {
		if child.ID != elemSpace && child.ID != elemSpaceUnique && child.ID != elemSpaceOther {
			continue
		}
		space, err := decodeSpace(child)
		if err != nil {
			return nil, err
		}
		metadata.Spaces = append(metadata.Spaces, space)
	}
	if len(metadata.Spaces) == 0 {
		return nil, fmt.Errorf("sleigh metadata did not contain any encoded spaces")
	}
	return metadata, nil
}

func decodeSpace(elem packedElement) (address.Space, error) {
	space := address.Space{}
	switch elem.ID {
	case elemSpace:
		space.Kind = address.SpaceKindProcessor
	case elemSpaceUnique:
		space.Kind = address.SpaceKindUnique
	case elemSpaceOther:
		space.Kind = address.SpaceKindOther
	default:
		return address.Space{}, fmt.Errorf("unsupported space element id %d", elem.ID)
	}

	name, err := requiredStringAttr(elem.Attrs, attrName)
	if err != nil {
		return address.Space{}, fmt.Errorf("read space name: %w", err)
	}
	index, err := requiredIntAttr(elem.Attrs, attrIndex)
	if err != nil {
		return address.Space{}, fmt.Errorf("read space index: %w", err)
	}
	addrSize, err := requiredIntAttr(elem.Attrs, attrSize)
	if err != nil {
		return address.Space{}, fmt.Errorf("read space size: %w", err)
	}
	delay, err := requiredIntAttr(elem.Attrs, attrDelay)
	if err != nil {
		return address.Space{}, fmt.Errorf("read space delay: %w", err)
	}
	space.Name = name
	space.Index = uint16(index)
	space.AddrSize = uint8(addrSize)
	space.Delay = int32(delay)
	space.BigEndian = optionalBoolAttr(elem.Attrs, attrBigEndian)
	space.WordSize = uint8(optionalIntAttrDefault(elem.Attrs, attrWordSize, 1))
	space.Physical = optionalBoolAttr(elem.Attrs, attrPhysical)
	if err := space.Validate(); err != nil {
		return address.Space{}, err
	}
	return space, nil
}

func findChild(elem packedElement, childID uint32) (*packedElement, error) {
	for i := range elem.Children {
		if elem.Children[i].ID == childID {
			return &elem.Children[i], nil
		}
	}
	return nil, fmt.Errorf("required child element %d missing", childID)
}

func findAttr(attrs []packedAttribute, id uint32) (packedAttribute, bool) {
	for _, attr := range attrs {
		if attr.ID == id {
			return attr, true
		}
	}
	return packedAttribute{}, false
}

func requiredBoolAttr(attrs []packedAttribute, id uint32) (bool, error) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return false, fmt.Errorf("required bool attribute %d missing", id)
	}
	if attr.Type != attributeValueBool {
		return false, fmt.Errorf("attribute %d is not a bool", id)
	}
	return attr.Bool, nil
}

func optionalBoolAttr(attrs []packedAttribute, id uint32) bool {
	attr, ok := findAttr(attrs, id)
	if !ok || attr.Type != attributeValueBool {
		return false
	}
	return attr.Bool
}

func requiredIntAttr(attrs []packedAttribute, id uint32) (int64, error) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return 0, fmt.Errorf("required integer attribute %d missing", id)
	}
	switch attr.Type {
	case attributeValueInt:
		return attr.Int, nil
	case attributeValueUint:
		if attr.Uint > math.MaxInt64 {
			return 0, fmt.Errorf("attribute %d overflows signed integer", id)
		}
		return int64(attr.Uint), nil
	default:
		return 0, fmt.Errorf("attribute %d is not a signed integer", id)
	}
}

func optionalIntAttr(attrs []packedAttribute, id uint32) (int64, bool) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return 0, false
	}
	switch attr.Type {
	case attributeValueInt:
		return attr.Int, true
	case attributeValueUint:
		if attr.Uint > math.MaxInt64 {
			return 0, false
		}
		return int64(attr.Uint), true
	default:
		return 0, false
	}
}

func optionalIntAttrDefault(attrs []packedAttribute, id uint32, fallback int64) int64 {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return fallback
	}
	switch attr.Type {
	case attributeValueInt:
		return attr.Int
	case attributeValueUint:
		if attr.Uint > math.MaxInt64 {
			return fallback
		}
		return int64(attr.Uint)
	default:
		return fallback
	}
}

// requiredSpaceAttr reads a space index attribute that may be encoded as
// signed int (XML/text format) or unsigned int (packed binary address space type 5).
// C++ PackedDecode::readSpace returns an integer index for TYPECODE_ADDRESSSPACE.
func requiredSpaceAttr(attrs []packedAttribute, id uint32) (int64, error) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return 0, fmt.Errorf("required space attribute %d missing", id)
	}
	switch attr.Type {
	case attributeValueInt:
		return attr.Int, nil
	case attributeValueUint:
		return int64(attr.Uint), nil
	default:
		return 0, fmt.Errorf("attribute %d is not a space index (type=%d)", id, attr.Type)
	}
}

func requiredUintAttr(attrs []packedAttribute, id uint32) (uint64, error) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return 0, fmt.Errorf("required unsigned integer attribute %d missing", id)
	}
	switch attr.Type {
	case attributeValueUint:
		return attr.Uint, nil
	case attributeValueInt:
		if attr.Int < 0 {
			return 0, fmt.Errorf("attribute %d is negative", id)
		}
		return uint64(attr.Int), nil
	default:
		return 0, fmt.Errorf("attribute %d is not an unsigned integer", id)
	}
}

func optionalUintAttr(attrs []packedAttribute, id uint32) uint64 {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return 0
	}
	switch attr.Type {
	case attributeValueUint:
		return attr.Uint
	case attributeValueInt:
		if attr.Int < 0 {
			return 0
		}
		return uint64(attr.Int)
	default:
		return 0
	}
}

func requiredStringAttr(attrs []packedAttribute, id uint32) (string, error) {
	attr, ok := findAttr(attrs, id)
	if !ok {
		return "", fmt.Errorf("required string attribute %d missing", id)
	}
	if attr.Type != attributeValueString {
		return "", fmt.Errorf("attribute %d is not a string", id)
	}
	return attr.Text, nil
}

func decodeOpcodeName(opcode int64) string {
	if opcode > 0 && opcode <= int64(pcode.CPUI_MAX) {
		return pcode.OpCode(opcode).String()
	}
	return fmt.Sprintf("opcode_%d", opcode)
}
