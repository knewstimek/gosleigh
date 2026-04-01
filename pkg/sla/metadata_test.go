package sla

import (
	"bytes"
	"testing"

	"gosleigh/pkg/address"
)

func TestDecodeMetadataPayload(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrAlign, 4)
	payload.writeUnsigned(attrUniqBase, 0x1000)
	payload.writeUnsigned(attrMaxDelay, 8)
	payload.writeUnsigned(attrUniqMask, 0xff)
	payload.writeUnsigned(attrNumSections, 2)
	payload.openElement(elemSourceFiles)
	payload.openElement(elemSourceFile)
	payload.writeString(attrName, "sample.sinc")
	payload.writeSigned(attrIndex, 0)
	payload.closeElement(elemSourceFile)
	payload.closeElement(elemSourceFiles)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.openElement(elemSpaceUnique)
	payload.writeString(attrName, "unique")
	payload.writeSigned(attrIndex, 2)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, false)
	payload.closeElement(elemSpaceUnique)
	payload.openElement(elemSpaceOther)
	payload.writeString(attrName, "OTHER")
	payload.writeSigned(attrIndex, 3)
	payload.writeBool(attrBigEndian, true)
	payload.writeSigned(attrDelay, 1)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 2)
	payload.writeBool(attrPhysical, false)
	payload.closeElement(elemSpaceOther)
	payload.closeElement(elemSpaces)
	payload.closeElement(elemSleigh)

	metadata, err := DecodeMetadataPayload(payload.bytes())
	if err != nil {
		t.Fatalf("DecodeMetadataPayload() returned unexpected error: %v", err)
	}
	if metadata.Version != FormatVersion {
		t.Fatalf("unexpected version: got %d want %d", metadata.Version, FormatVersion)
	}
	if !metadata.BigEndian {
		t.Fatal("expected big-endian metadata")
	}
	if metadata.Align != 4 {
		t.Fatalf("unexpected alignment: got %d", metadata.Align)
	}
	if metadata.UniqueBase != 0x1000 {
		t.Fatalf("unexpected unique base: got 0x%x", metadata.UniqueBase)
	}
	if metadata.MaxDelay != 8 {
		t.Fatalf("unexpected max delay: got %d", metadata.MaxDelay)
	}
	if metadata.UniqueMask != 0xff {
		t.Fatalf("unexpected unique mask: got 0x%x", metadata.UniqueMask)
	}
	if metadata.NumSections != 2 {
		t.Fatalf("unexpected section count: got %d", metadata.NumSections)
	}
	if metadata.DefaultSpace != "ram" {
		t.Fatalf("unexpected default space: got %q", metadata.DefaultSpace)
	}
	if len(metadata.Spaces) != 3 {
		t.Fatalf("unexpected space count: got %d", len(metadata.Spaces))
	}
	if metadata.Spaces[0].Kind != address.SpaceKindProcessor {
		t.Fatalf("unexpected first space kind: got %s", metadata.Spaces[0].Kind)
	}
	if metadata.Spaces[1].Kind != address.SpaceKindUnique {
		t.Fatalf("unexpected second space kind: got %s", metadata.Spaces[1].Kind)
	}
	if metadata.Spaces[2].Kind != address.SpaceKindOther {
		t.Fatalf("unexpected third space kind: got %s", metadata.Spaces[2].Kind)
	}
	if metadata.Spaces[2].Delay != 1 {
		t.Fatalf("unexpected other space delay: got %d", metadata.Spaces[2].Delay)
	}
	if metadata.Spaces[2].WordSize != 2 {
		t.Fatalf("unexpected other space word size: got %d", metadata.Spaces[2].WordSize)
	}
}

func TestDecodeMetadataPayloadRejectsWrongVersion(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, 99)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSpaces)
	payload.writeString(attrDefaultSpace, "ram")
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.closeElement(elemSleigh)

	_, err := DecodeMetadataPayload(payload.bytes())
	if err == nil {
		t.Fatal("DecodeMetadataPayload() returned nil for wrong version")
	}
}

func TestDecodeMetadataPayloadRejectsMissingDefaultSpace(t *testing.T) {
	payload := newPackedTestEncoder()
	payload.openElement(elemSleigh)
	payload.writeSigned(attrVersion, FormatVersion)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrAlign, 1)
	payload.writeUnsigned(attrUniqBase, 0)
	payload.openElement(elemSpaces)
	payload.openElement(elemSpace)
	payload.writeString(attrName, "ram")
	payload.writeSigned(attrIndex, 1)
	payload.writeBool(attrBigEndian, false)
	payload.writeSigned(attrDelay, 0)
	payload.writeSigned(attrSize, 8)
	payload.writeSigned(attrWordSize, 1)
	payload.writeBool(attrPhysical, true)
	payload.closeElement(elemSpace)
	payload.closeElement(elemSpaces)
	payload.closeElement(elemSleigh)

	_, err := DecodeMetadataPayload(payload.bytes())
	if err == nil {
		t.Fatal("DecodeMetadataPayload() returned nil for missing default space")
	}
}

type packedTestEncoder struct {
	buf bytes.Buffer
}

func newPackedTestEncoder() *packedTestEncoder {
	return &packedTestEncoder{}
}

func (e *packedTestEncoder) bytes() []byte {
	return e.buf.Bytes()
}

func (e *packedTestEncoder) openElement(id uint32) {
	e.writeHeader(elementStart, id)
}

func (e *packedTestEncoder) closeElement(id uint32) {
	e.writeHeader(elementEnd, id)
}

func (e *packedTestEncoder) writeBool(id uint32, value bool) {
	e.writeHeader(attributeStart, id)
	typeByte := byte(attrTypeBool << typeCodeShift)
	if value {
		typeByte |= 1
	}
	e.buf.WriteByte(typeByte)
}

func (e *packedTestEncoder) writeSigned(id uint32, value int64) {
	e.writeHeader(attributeStart, id)
	if value < 0 {
		e.writeInteger(byte(attrTypeSignedNegative<<typeCodeShift), uint64(-value))
		return
	}
	e.writeInteger(byte(attrTypeSignedPositive<<typeCodeShift), uint64(value))
}

func (e *packedTestEncoder) writeUnsigned(id uint32, value uint64) {
	e.writeHeader(attributeStart, id)
	e.writeInteger(byte(attrTypeUnsigned<<typeCodeShift), value)
}

func (e *packedTestEncoder) writeString(id uint32, value string) {
	e.writeHeader(attributeStart, id)
	e.writeInteger(byte(attrTypeString<<typeCodeShift), uint64(len(value)))
	e.buf.WriteString(value)
}

func (e *packedTestEncoder) writeHeader(kind byte, id uint32) {
	header := kind
	if id > 0x1f {
		header |= headerExtendMask
		header |= byte(id >> 7)
		e.buf.WriteByte(header)
		e.buf.WriteByte(byte(id&rawDataMask) | rawDataMarker)
		return
	}
	e.buf.WriteByte(header | byte(id))
}

func (e *packedTestEncoder) writeInteger(typeByte byte, value uint64) {
	pieces := make([]byte, 0, 10)
	if value != 0 {
		for value > 0 {
			pieces = append(pieces, byte(value&rawDataMask)|rawDataMarker)
			value >>= 7
		}
	}
	e.buf.WriteByte(typeByte | byte(len(pieces)))
	for i := len(pieces) - 1; i >= 0; i-- {
		e.buf.WriteByte(pieces[i])
	}
}
