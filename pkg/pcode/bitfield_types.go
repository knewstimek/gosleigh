// Copyright 2026 The Gosleigh Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import "sort"

// TypeBitField is a structure member not aligned or sized on byte
// boundaries: an integer of Type held in the bits of Bits.
// C++ parity: class TypeBitField (type.hh).
type TypeBitField struct {
	Name  string
	Type  Datatype
	Bits  BitRange
	Ident int32
}

// bitFieldTriple is a bitfield, the structure immediately holding it and
// that structure's byte offset in the root structure.
// C++ parity: class BitFieldTriple (type.hh).
type bitFieldTriple struct {
	immedContainer *Struct
	bitfield       *TypeBitField
	offset         int32
}

// bitFieldTripleLess orders bitfields from least to most significant.
// C++ parity: BitFieldTriple::compare.
func bitFieldTripleLess(op1, op2 bitFieldTriple) bool {
	isBigEndian := op1.bitfield.Bits.IsBigEndian
	byteOff1 := op1.offset + op1.bitfield.Bits.ByteOffset
	byteOff2 := op2.offset + op2.bitfield.Bits.ByteOffset
	if byteOff1 != byteOff2 {
		if isBigEndian {
			return byteOff1 > byteOff2 // a bigger byte offset is less significant
		}
		return byteOff1 < byteOff2
	}
	return op1.bitfield.Bits.LeastSigBit < op2.bitfield.Bits.LeastSigBit
}

// splitBitfields separates bitfield members (TypeField.IsBitfield, given
// as a storage unit at Offset of Type's size and the field's bits in it)
// from byte-aligned fields. Each bitfield's container is minimized to the
// bytes it touches; one that is a whole byte range becomes an ordinary
// field. Bitfields overlapping an earlier one are dropped.
// C++ parity: TypeStruct::decodeBitField, with the host's storage unit in
// place of the <bitfield> element's offset/first attributes.
// TODO known mismatch: bitfields are taken as little-endian (the data
// space's endianness is not known where structures are built).
func splitBitfields(fields []TypeField) ([]TypeField, []TypeBitField) {
	var plain []TypeField
	var bitfields []TypeBitField
	for i, f := range fields {
		if !f.IsBitfield {
			plain = append(plain, f)
			continue
		}
		if f.Type == nil || f.BitSize <= 0 {
			continue
		}
		meta := f.Type.Metatype()
		if meta != TYPE_INT && meta != TYPE_UINT && meta != TYPE_BOOL && meta != TYPE_ENUM_INT && meta != TYPE_ENUM_UINT {
			continue // non integer data-type for a bitfield
		}
		bits := BitRange{ByteOffset: f.Offset, ByteSize: f.Type.Size(), LeastSigBit: f.BitOffset, NumBits: f.BitSize}
		if bits.LeastSigBit+bits.NumBits > 8*bits.ByteSize {
			continue
		}
		bits.minimizeContainer()
		if bits.isByteRange() {
			dt := f.Type
			if dt.Size() != bits.ByteSize {
				if meta == TYPE_ENUM_INT || meta == TYPE_ENUM_UINT {
					meta = TYPE_UINT
				}
				dt = sharedTypeFactory.GetBase(bits.ByteSize, meta, "")
			}
			plain = append(plain, TypeField{Ident: f.Ident, Offset: bits.ByteOffset, Name: f.Name, Type: dt})
			continue
		}
		bitfields = append(bitfields, TypeBitField{Name: f.Name, Type: f.Type, Bits: bits, Ident: int32(i)})
	}
	sort.SliceStable(plain, func(i, j int) bool { return plain[i].Offset < plain[j].Offset })
	sort.SliceStable(bitfields, func(i, j int) bool { return bitfields[i].Bits.compare(bitfields[j].Bits) < 0 })
	kept := bitfields[:0]
	for _, bf := range bitfields {
		if n := len(kept); n > 0 && kept[n-1].Bits.overlapTest(bf.Bits) != -1 {
			continue // ignoring an overlapping bit field
		}
		kept = append(kept, bf)
	}
	if len(kept) == 0 {
		kept = nil
	}
	return plain, kept
}

// NumBitFields is the number of bitfield members.
// C++ parity: TypeStruct::numBitFields.
func (s *Struct) NumBitFields() int { return len(s.bitfields) }

// BitField is the i-th bitfield member. C++ parity: TypeStruct::getBitField.
func (s *Struct) BitField(i int) *TypeBitField { return &s.bitfields[i] }

// findMatchingBitField is the bitfield exactly matching range, or nil.
// C++ parity: TypeStruct::findMatchingBitField.
func (s *Struct) findMatchingBitField(rng BitRange) *TypeBitField {
	lo, hi := 0, len(s.bitfields)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		cur := &s.bitfields[mid]
		switch rng.overlapTest(cur.Bits) {
		case 0:
			return cur
		case -1:
			hi = mid - 1
		case 1:
			lo = mid + 1
		default:
			return nil // partial overlap
		}
	}
	return nil
}

// firstBitFieldAfter is the index of the first bitfield whose container
// ends after byte offset off. C++ parity: upper_bound with
// TypeBitField::compareMaxByte.
func (s *Struct) firstBitFieldAfter(off int32) int {
	return sort.Search(len(s.bitfields), func(i int) bool {
		b := s.bitfields[i].Bits
		return off < b.ByteOffset+b.ByteSize
	})
}

// firstFieldAfter is the index of the first field ending after byte offset
// off. C++ parity: upper_bound with TypeField::compareMaxByte.
func (s *Struct) firstFieldAfter(off int32) int {
	return sort.Search(len(s.fields), func(i int) bool {
		return off < s.fields[i].End()
	})
}

// collectBitFields appends the bitfields overlapping the byte range
// [offset, offset+sz), descending into nested structures; baseOffset is
// this structure's offset in the root. The result may be out of order.
// C++ parity: TypeStruct::collectBitFields.
func (s *Struct) collectBitFields(baseOffset int32, res *[]bitFieldTriple, offset, sz int32) {
	if i := s.firstBitFieldAfter(offset); i < len(s.bitfields) {
		rng := byteBitRange(offset, sz, s.bitfields[i].Bits.IsBigEndian)
		for ; i < len(s.bitfields); i++ {
			cur := &s.bitfields[i]
			code := cur.Bits.overlapTest(rng)
			if code == 1 {
				break
			}
			if code == -1 {
				continue
			}
			*res = append(*res, bitFieldTriple{immedContainer: s, bitfield: cur, offset: baseOffset})
		}
	}
	for i := s.firstFieldAfter(offset); i < len(s.fields); i++ {
		f := s.fields[i]
		if f.Offset >= offset+sz {
			break
		}
		sub, ok := f.Type.(*Struct)
		if !ok || !sub.HasBitfields() {
			continue
		}
		sub.collectBitFields(baseOffset+f.Offset, res, offset-f.Offset, sz)
	}
}

// hasBitFieldsInRange reports a bitfield overlapping the byte range
// [offset, offset+sz), here or in a nested structure.
// C++ parity: TypeStruct::hasBitFieldsInRange.
func (s *Struct) hasBitFieldsInRange(offset, sz int32) bool {
	if i := s.firstBitFieldAfter(offset); i < len(s.bitfields) {
		rng := byteBitRange(offset, sz, s.bitfields[i].Bits.IsBigEndian)
		for ; i < len(s.bitfields); i++ {
			code := s.bitfields[i].Bits.overlapTest(rng)
			if code == 1 {
				break
			}
			if code != -1 {
				return true
			}
		}
	}
	for i := s.firstFieldAfter(offset); i < len(s.fields); i++ {
		f := s.fields[i]
		if f.Offset >= offset+sz {
			break
		}
		if sub, ok := f.Type.(*Struct); ok && sub.HasBitfields() && sub.hasBitFieldsInRange(offset-f.Offset, sz) {
			return true
		}
	}
	return false
}
