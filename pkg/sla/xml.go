package sla

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"gosleigh/pkg/pcode"
)

var xmlUTF8BOM = []byte{0xef, 0xbb, 0xbf}

type xmlElementNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr       `xml:",any,attr"`
	Children []xmlElementNode `xml:",any"`
}

type xmlDecodeContext struct {
	spaceIndexes map[string]int64
}

var xmlElementNameToID = map[string]uint32{
	"and_exp":           elemAndExp,
	"combine_pat":       elemCombinePat,
	"commit":            elemCommit,
	"context_pat":       elemContextPat,
	"context_op":        elemContextOp,
	"context_sym":       elemContextSym,
	"context_sym_head":  elemContextSymHead,
	"contextfield":      elemContextField,
	"constructor":       elemConstructor,
	"construct_tpl":     elemConstructTpl,
	"decision":          elemDecision,
	"div_exp":           elemDivExp,
	"end_exp":           elemEndExp,
	"end_sym":           elemEndSym,
	"end_sym_head":      elemEndSymHead,
	"epsilon_sym":       elemEpsilonSym,
	"epsilon_sym_head":  elemEpsilonSymHead,
	"handle_tpl":        elemHandleTpl,
	"instruct_pat":      elemInstructPat,
	"intb":              elemIntB,
	"lshift_exp":        elemLShiftExp,
	"mask_word":         elemMaskWord,
	"minus_exp":         elemMinusExp,
	"mult_exp":          elemMultExp,
	"name_sym":          elemNameSym,
	"name_sym_head":     elemNameSymHead,
	"name_tab":          elemNameTab,
	"next2_exp":         elemNext2Exp,
	"next2_sym":         elemNext2Sym,
	"next2_sym_head":    elemNext2SymHead,
	"not_exp":           elemNotExp,
	"null":              elemNull,
	"op_tpl":            elemOpTpl,
	"operand_exp":       elemOperandExp,
	"operand_sym":       elemOperandSym,
	"operand_sym_head":  elemOperandSymHead,
	"oper":              elemOper,
	"opprint":           elemOpPrint,
	"or_exp":            elemOrExp,
	"or_pat":            elemOrPat,
	"pair":              elemPair,
	"pat_block":         elemPatBlock,
	"plus_exp":          elemPlusExp,
	"print":             elemPrint,
	"rshift_exp":        elemRShiftExp,
	"scope":             elemScope,
	"sleigh":            elemSleigh,
	"sourcefile":        elemSourceFile,
	"sourcefiles":       elemSourceFiles,
	"space":             elemSpace,
	"spaces":            elemSpaces,
	"space_other":       elemSpaceOther,
	"space_unique":      elemSpaceUnique,
	"start_exp":         elemStartExp,
	"start_sym":         elemStartSym,
	"start_sym_head":    elemStartSymHead,
	"sub_exp":           elemSubExp,
	"subtable_sym":      elemSubtableSym,
	"subtable_sym_head": elemSubtableSymHead,
	"symbol_table":      elemSymbolTable,
	"tokenfield":        elemTokenField,
	"userop":            elemUserOp,
	"userop_head":       elemUserOpHead,
	"valuemap_sym":      elemValueMapSym,
	"valuemap_sym_head": elemValueMapSymHead,
	"value_sym":         elemValueSym,
	"value_sym_head":    elemValueSymHead,
	"value_tab":         elemValueTab,
	"var":               elemVar,
	"varlist_sym":       elemVarListSym,
	"varlist_sym_head":  elemVarListSymHead,
	"varnode_sym":       elemVarnodeSym,
	"varnode_sym_head":  elemVarnodeSymHead,
	"varnode_tpl":       elemVarnodeTpl,
	"xor_exp":           elemXorExp,
}

var xmlConstTypeToElementID = map[string]uint32{
	string(ConstKindCurSpace):     elemConstCurSpace,
	string(ConstKindCurSpaceSize): elemConstCurSpaceSize,
	string(ConstKindFlowDest):     elemConstFlowDest,
	string(ConstKindFlowDestSize): elemConstFlowDestSize,
	string(ConstKindFlowRef):      elemConstFlowRef,
	string(ConstKindFlowRefSize):  elemConstFlowRefSize,
	string(ConstKindHandle):       elemConstHandle,
	string(ConstKindNext):         elemConstNext,
	string(ConstKindNext2):        elemConstNext2,
	string(ConstKindReal):         elemConstReal,
	string(ConstKindRelative):     elemConstRelative,
	string(ConstKindSpaceID):      elemConstSpaceID,
	string(ConstKindStart):        elemConstStart,
}

var xmlAttrNameToID = map[string]uint32{
	"align":        attrAlign,
	"base":         attrBase,
	"bigendian":    attrBigEndian,
	"bitend":       attrEndBit,
	"bitstart":     attrStartBit,
	"byteend":      attrEndByte,
	"bytestart":    attrStartByte,
	"code":         attrCode,
	"context":      attrContext,
	"ct":           attrCT,
	"defaultspace": attrDefaultSpace,
	"delay":        attrDelay,
	"first":        attrFirst,
	"flow":         attrFlow,
	"high":         attrHigh,
	"id":           attrID,
	"index":        attrIndex,
	"labels":       attrLabels,
	"length":       attrLength,
	"line":         attrLine,
	"low":          attrLow,
	"mask":         attrMask,
	"maxdelay":     attrMaxDelay,
	"minlen":       attrMinLen,
	"name":         attrName,
	"nonzero":      attrNonZero,
	"number":       attrNumber,
	"numct":        attrNumCT,
	"numsections":  attrNumSections,
	"off":          attrOff,
	"offset":       attrOff,
	"parent":       attrParent,
	"physical":     attrPhysical,
	"piece":        attrPiece,
	"plus":         attrPlus,
	"s":            attrS,
	"scope":        attrScope,
	"scopesize":    attrScopeSize,
	"section":      attrSection,
	"shift":        attrShift,
	"signbit":      attrSignBit,
	"size":         attrSize,
	"source":       attrSource,
	"space":        attrSpace,
	"start":        attrStartBit,
	"subsym":       attrSubSym,
	"symbolsize":   attrSymbolSize,
	"table":        attrTable,
	"uniqbase":     attrUniqBase,
	"uniqmask":     attrUniqMask,
	"val":          attrVal,
	"varnode":      attrVarnode,
	"version":      attrVersion,
	"wordsize":     attrWordSize,
}

var xmlOpcodeNameToID = func() map[string]int64 {
	result := map[string]int64{
		"BUILD":      int64(pcode.CPUI_MULTIEQUAL),
		"DELAY_SLOT": int64(pcode.CPUI_INDIRECT),
	}
	for opcode := pcode.OpCode(1); opcode <= pcode.CPUI_MAX; opcode++ {
		result[opcode.String()] = int64(opcode)
	}
	return result
}()

func isXMLPayload(data []byte) bool {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, xmlUTF8BOM))
	return bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<sleigh"))
}

func parseXMLRootElement(data []byte) (*packedElement, error) {
	var rootNode xmlElementNode
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&rootNode); err != nil {
		return nil, fmt.Errorf("decode sla xml: %w", err)
	}
	ctx, err := newXMLDecodeContext(rootNode)
	if err != nil {
		return nil, err
	}
	root, err := decodeXMLElement(rootNode, ctx)
	if err != nil {
		return nil, err
	}
	if root.ID != elemSleigh {
		return nil, fmt.Errorf("unexpected xml root element: got %d want %d", root.ID, elemSleigh)
	}
	return &root, nil
}

func newXMLDecodeContext(root xmlElementNode) (xmlDecodeContext, error) {
	ctx := xmlDecodeContext{
		spaceIndexes: map[string]int64{
			"const": int64(^uint16(0)),
		},
	}
	for _, child := range root.Children {
		if child.XMLName.Local != "spaces" {
			continue
		}
		for _, spaceNode := range child.Children {
			switch spaceNode.XMLName.Local {
			case "space", "space_other", "space_unique":
			default:
				continue
			}
			name, ok := xmlAttrValue(spaceNode.Attrs, "name")
			if !ok {
				return xmlDecodeContext{}, fmt.Errorf("xml space is missing name")
			}
			indexText, ok := xmlAttrValue(spaceNode.Attrs, "index")
			if !ok {
				return xmlDecodeContext{}, fmt.Errorf("xml space %q is missing index", name)
			}
			index, err := parseXMLInt(indexText)
			if err != nil {
				return xmlDecodeContext{}, fmt.Errorf("parse xml space %q index: %w", name, err)
			}
			ctx.spaceIndexes[name] = index
		}
	}
	return ctx, nil
}

func decodeXMLElement(node xmlElementNode, ctx xmlDecodeContext) (packedElement, error) {
	id, err := xmlElementID(node)
	if err != nil {
		return packedElement{}, err
	}
	attrs, err := decodeXMLAttributes(node, ctx)
	if err != nil {
		return packedElement{}, err
	}
	elem := packedElement{
		ID:       id,
		Attrs:    attrs,
		Children: make([]packedElement, 0, len(node.Children)),
	}
	for _, childNode := range node.Children {
		child, err := decodeXMLElement(childNode, ctx)
		if err != nil {
			return packedElement{}, err
		}
		elem.Children = append(elem.Children, child)
	}
	return elem, nil
}

func xmlElementID(node xmlElementNode) (uint32, error) {
	if node.XMLName.Local == "const_tpl" {
		kind, ok := xmlAttrValue(node.Attrs, "type")
		if !ok {
			return 0, fmt.Errorf("xml const_tpl is missing type")
		}
		id, ok := xmlConstTypeToElementID[kind]
		if !ok {
			return 0, fmt.Errorf("unsupported xml const_tpl type %q", kind)
		}
		return id, nil
	}
	id, ok := xmlElementNameToID[node.XMLName.Local]
	if !ok {
		return 0, fmt.Errorf("unsupported xml element %q", node.XMLName.Local)
	}
	return id, nil
}

func decodeXMLAttributes(node xmlElementNode, ctx xmlDecodeContext) ([]packedAttribute, error) {
	attrs := make([]packedAttribute, 0, len(node.Attrs)+1)
	hasSourceAttr := false
	hasLineAttr := false
	for _, rawAttr := range node.Attrs {
		switch {
		case node.XMLName.Local == "const_tpl" && rawAttr.Name.Local == "type":
			continue
		case node.XMLName.Local == "const_tpl" && rawAttr.Name.Local == "name":
			kind, _ := xmlAttrValue(node.Attrs, "type")
			if kind != string(ConstKindSpaceID) {
				continue
			}
			spaceIndex, err := xmlSpaceIndex(ctx, rawAttr.Value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, packedAttribute{ID: attrSpace, Type: attributeValueInt, Int: spaceIndex})
			continue
		case node.XMLName.Local == "const_tpl" && rawAttr.Name.Local == "s":
			selector, err := xmlHandleSelector(node, rawAttr.Value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, packedAttribute{ID: attrS, Type: attributeValueInt, Int: selector})
			continue
		case rawAttr.Name.Local == "space" && !looksLikeXMLNumber(rawAttr.Value):
			spaceIndex, err := xmlSpaceIndex(ctx, rawAttr.Value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, packedAttribute{ID: attrSpace, Type: attributeValueInt, Int: spaceIndex})
			continue
		case node.XMLName.Local == "op_tpl" && rawAttr.Name.Local == "code":
			opcode, err := xmlOpcodeID(rawAttr.Value)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, packedAttribute{ID: attrCode, Type: attributeValueInt, Int: opcode})
			continue
		case node.XMLName.Local == "constructor" && rawAttr.Name.Local == "line":
			sourceIndex, lineNumber, err := parseXMLSourceLine(rawAttr.Value)
			if err != nil {
				return nil, err
			}
			if !hasSourceAttr {
				attrs = append(attrs, packedAttribute{ID: attrSource, Type: attributeValueInt, Int: sourceIndex})
				hasSourceAttr = true
			}
			attrs = append(attrs, packedAttribute{ID: attrLine, Type: attributeValueInt, Int: lineNumber})
			hasLineAttr = true
			continue
		}

		attrID, ok := xmlAttrNameToID[rawAttr.Name.Local]
		if !ok {
			return nil, fmt.Errorf("unsupported xml attribute %q on <%s>", rawAttr.Name.Local, node.XMLName.Local)
		}
		if attrID == attrSource {
			hasSourceAttr = true
		}
		if attrID == attrLine {
			hasLineAttr = true
		}
		attr, err := xmlPackedAttribute(attrID, rawAttr.Value)
		if err != nil {
			return nil, fmt.Errorf("parse xml attribute %q on <%s>: %w", rawAttr.Name.Local, node.XMLName.Local, err)
		}
		attrs = append(attrs, attr)
	}
	if node.XMLName.Local == "constructor" && hasLineAttr && !hasSourceAttr {
		attrs = append(attrs, packedAttribute{ID: attrSource, Type: attributeValueInt, Int: 0})
	}
	return attrs, nil
}

func xmlPackedAttribute(id uint32, raw string) (packedAttribute, error) {
	if value, ok := parseXMLBool(raw); ok {
		return packedAttribute{ID: id, Type: attributeValueBool, Bool: value}, nil
	}
	if strings.HasPrefix(raw, "-") {
		value, err := parseXMLInt(raw)
		if err != nil {
			return packedAttribute{}, err
		}
		return packedAttribute{ID: id, Type: attributeValueInt, Int: value}, nil
	}
	if looksLikeXMLNumber(raw) {
		if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
			value, err := parseXMLUint(raw)
			if err != nil {
				return packedAttribute{}, err
			}
			return packedAttribute{ID: id, Type: attributeValueUint, Uint: value}, nil
		}
		value, err := parseXMLInt(raw)
		if err != nil {
			return packedAttribute{}, err
		}
		return packedAttribute{ID: id, Type: attributeValueInt, Int: value}, nil
	}
	return packedAttribute{ID: id, Type: attributeValueString, Text: raw}, nil
}

func xmlAttrValue(attrs []xml.Attr, name string) (string, bool) {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value, true
		}
	}
	return "", false
}

func xmlSpaceIndex(ctx xmlDecodeContext, name string) (int64, error) {
	index, ok := ctx.spaceIndexes[name]
	if !ok {
		return 0, fmt.Errorf("unknown xml space %q", name)
	}
	return index, nil
}

func xmlHandleSelector(node xmlElementNode, selector string) (int64, error) {
	switch selector {
	case "space":
		return handleFieldSpace, nil
	case "size":
		return handleFieldSize, nil
	case "offset":
		if _, ok := xmlAttrValue(node.Attrs, "plus"); ok {
			return handleFieldOffsetPlus, nil
		}
		return handleFieldOffset, nil
	default:
		return 0, fmt.Errorf("unsupported xml handle selector %q", selector)
	}
}

func xmlOpcodeID(name string) (int64, error) {
	id, ok := xmlOpcodeNameToID[name]
	if !ok {
		return 0, fmt.Errorf("unsupported xml opcode %q", name)
	}
	return id, nil
}

func parseXMLSourceLine(raw string) (int64, int64, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) == 2 {
		sourceIndex, err := parseXMLInt(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("parse xml constructor source index: %w", err)
		}
		lineNumber, err := parseXMLInt(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("parse xml constructor line number: %w", err)
		}
		return sourceIndex, lineNumber, nil
	}
	lineNumber, err := parseXMLInt(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("parse xml constructor line number: %w", err)
	}
	return 0, lineNumber, nil
}

func parseXMLBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func parseXMLInt(raw string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("parse int %q: %w", raw, err)
	}
	return value, nil
}

func parseXMLUint(raw string) (uint64, error) {
	value, err := strconv.ParseUint(strings.TrimSpace(raw), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("parse uint %q: %w", raw, err)
	}
	return value, nil
}

func looksLikeXMLNumber(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if raw[0] == '-' {
		raw = raw[1:]
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		if len(raw) == 2 {
			return false
		}
		for _, r := range raw[2:] {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return false
			}
		}
		return true
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
