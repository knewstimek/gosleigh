package sla

import (
	"fmt"
)

const (
	headerMask       = 0xc0
	elementStart     = 0x40
	elementEnd       = 0x80
	attributeStart   = 0xc0
	headerExtendMask = 0x20
	elementIDMask    = 0x1f
	rawDataMask      = 0x7f
	rawDataMarker    = 0x80
	typeCodeShift    = 4
	lengthCodeMask   = 0x0f
)

const (
	attrTypeBool uint8 = 1 + iota
	attrTypeSignedPositive
	attrTypeSignedNegative
	attrTypeUnsigned
	attrTypeAddressSpace
	attrTypeSpecialSpace
	attrTypeString
)

type attributeValueType uint8

const (
	attributeValueBool attributeValueType = iota + 1
	attributeValueInt
	attributeValueUint
	attributeValueString
)

type packedAttribute struct {
	ID   uint32
	Type attributeValueType
	Bool bool
	Int  int64
	Uint uint64
	Text string
}

type packedElement struct {
	ID       uint32
	Attrs    []packedAttribute
	Children []packedElement
}

type packedParser struct {
	data []byte
	pos  int
}

func parsePackedElement(data []byte) (*packedElement, error) {
	parser := packedParser{data: data}
	elem, err := parser.parseElement()
	if err != nil {
		return nil, err
	}
	if parser.pos != len(data) {
		return nil, fmt.Errorf("unexpected trailing packed data")
	}
	return elem, nil
}

func (p *packedParser) parseElement() (*packedElement, error) {
	header, err := p.readByte()
	if err != nil {
		return nil, err
	}
	if header&headerMask != elementStart {
		return nil, fmt.Errorf("expected packed element start")
	}
	id, err := p.readID(header)
	if err != nil {
		return nil, err
	}
	elem := &packedElement{ID: id}
	for {
		header, err = p.peekByte()
		if err != nil {
			return nil, err
		}
		if header&headerMask != attributeStart {
			break
		}
		attr, err := p.parseAttribute()
		if err != nil {
			return nil, err
		}
		elem.Attrs = append(elem.Attrs, attr)
	}
	for {
		header, err = p.peekByte()
		if err != nil {
			return nil, err
		}
		switch header & headerMask {
		case elementStart:
			child, err := p.parseElement()
			if err != nil {
				return nil, err
			}
			elem.Children = append(elem.Children, *child)
		case elementEnd:
			_, err := p.readByte()
			if err != nil {
				return nil, err
			}
			closeID, err := p.readID(header)
			if err != nil {
				return nil, err
			}
			if closeID != id {
				return nil, fmt.Errorf("packed element close mismatch: got %d want %d", closeID, id)
			}
			return elem, nil
		default:
			return nil, fmt.Errorf("unexpected packed record header 0x%x", header)
		}
	}
}

func (p *packedParser) parseAttribute() (packedAttribute, error) {
	header, err := p.readByte()
	if err != nil {
		return packedAttribute{}, err
	}
	if header&headerMask != attributeStart {
		return packedAttribute{}, fmt.Errorf("expected packed attribute start")
	}
	id, err := p.readID(header)
	if err != nil {
		return packedAttribute{}, err
	}
	typeByte, err := p.readByte()
	if err != nil {
		return packedAttribute{}, err
	}
	typeCode := typeByte >> typeCodeShift
	lengthCode := int(typeByte & lengthCodeMask)
	attr := packedAttribute{ID: id}
	switch typeCode {
	case attrTypeBool:
		attr.Type = attributeValueBool
		attr.Bool = lengthCode != 0
	case attrTypeSignedPositive:
		value, err := p.readInteger(lengthCode)
		if err != nil {
			return packedAttribute{}, err
		}
		attr.Type = attributeValueInt
		attr.Int = int64(value)
	case attrTypeSignedNegative:
		value, err := p.readInteger(lengthCode)
		if err != nil {
			return packedAttribute{}, err
		}
		attr.Type = attributeValueInt
		attr.Int = -int64(value)
	case attrTypeUnsigned:
		value, err := p.readInteger(lengthCode)
		if err != nil {
			return packedAttribute{}, err
		}
		attr.Type = attributeValueUint
		attr.Uint = value
	case attrTypeString:
		lengthValue, err := p.readInteger(lengthCode)
		if err != nil {
			return packedAttribute{}, err
		}
		text, err := p.readStringData(int(lengthValue))
		if err != nil {
			return packedAttribute{}, err
		}
		attr.Type = attributeValueString
		attr.Text = text
	default:
		return packedAttribute{}, fmt.Errorf("unsupported packed attribute type %d", typeCode)
	}
	return attr, nil
}

func (p *packedParser) readID(header byte) (uint32, error) {
	id := uint32(header & elementIDMask)
	if header&headerExtendMask == 0 {
		return id, nil
	}
	ext, err := p.readByte()
	if err != nil {
		return 0, err
	}
	if ext&rawDataMarker == 0 {
		return 0, fmt.Errorf("packed id extension missing marker bit")
	}
	id <<= 7
	id |= uint32(ext & rawDataMask)
	return id, nil
}

func (p *packedParser) readInteger(length int) (uint64, error) {
	if length == 0 {
		return 0, nil
	}
	var value uint64
	for i := 0; i < length; i++ {
		b, err := p.readByte()
		if err != nil {
			return 0, err
		}
		if b&rawDataMarker == 0 {
			return 0, fmt.Errorf("packed integer chunk missing marker bit")
		}
		value <<= 7
		value |= uint64(b & rawDataMask)
	}
	return value, nil
}

func (p *packedParser) readStringData(length int) (string, error) {
	if length < 0 {
		return "", fmt.Errorf("negative packed string length")
	}
	if p.pos+length > len(p.data) {
		return "", fmt.Errorf("unexpected end of packed string")
	}
	text := string(p.data[p.pos : p.pos+length])
	p.pos += length
	return text, nil
}

func (p *packedParser) readByte() (byte, error) {
	if p.pos >= len(p.data) {
		return 0, fmt.Errorf("unexpected end of packed stream")
	}
	b := p.data[p.pos]
	p.pos++
	return b, nil
}

func (p *packedParser) peekByte() (byte, error) {
	if p.pos >= len(p.data) {
		return 0, fmt.Errorf("unexpected end of packed stream")
	}
	return p.data[p.pos], nil
}
