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

// Package pcode -- bitfield transform infrastructure.
// C++ parity: ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/bitfield.hh
// and bitfield.cc. The transform family walks backward (insert) or forward
// (pull) from a container Varnode to find places where individual bitfields
// are read or written, and rewrites those sites in terms of the explicit
// INSERT/ZPULL/SPULL p-code ops.
package pcode

import (
	"math/bits"
	"sort"
)

// BitRange represents a contiguous run of bits within a byte container.
// C++ parity: class BitRange in address.hh. The Go struct carries the same
// fields as the C++ counterpart -- the transform walker mutates byteOffset,
// byteSize, leastSigBit, and numBits together to follow shifts/truncations.
type BitRange struct {
	// ByteOffset is the byte offset of the enclosing region.
	ByteOffset int32
	// ByteSize is the size of the enclosing region in bytes.
	ByteSize int32
	// LeastSigBit is the zero-based index of the least significant bit.
	LeastSigBit int32
	// NumBits is the width of the range in bits.
	NumBits int32
	// IsBigEndian records the endianness of the enclosing region.
	IsBigEndian bool
}

// NewBitRange constructs a BitRange with the given least-significant bit and width.
// C++ parity: BitRange::BitRange(int4,int4,int4,int4,bool) with byteOffset=0,
// byteSize computed from numBits.
func NewBitRange(leastSig, numBits int32) BitRange {
	sz := (leastSig + numBits + 7) / 8
	if sz <= 0 {
		sz = 1
	}
	return BitRange{ByteOffset: 0, ByteSize: sz, LeastSigBit: leastSig, NumBits: numBits}
}

// Empty reports whether the range covers zero bits.
// C++ parity: BitRange::empty.
func (b BitRange) Empty() bool { return b.NumBits <= 0 }

// MostSigBit returns the inclusive upper bit index of the range.
// C++ parity: helper used throughout bitfield.cc.
func (b BitRange) MostSigBit() int32 {
	if b.NumBits <= 0 {
		return b.LeastSigBit
	}
	return b.LeastSigBit + b.NumBits - 1
}

// Mask returns a bitmask covering the described range, aligned with the byte container.
// C++ parity: BitRange::getMask (address.cc ~L816).
func (b BitRange) Mask() uint64 {
	if b.NumBits <= 0 {
		return 0
	}
	var res uint64
	if b.NumBits >= 64 {
		res = ^uint64(0)
	} else {
		res = (uint64(1) << uint(b.NumBits)) - 1
	}
	if b.LeastSigBit >= 64 {
		return 0
	}
	return res << uint(b.LeastSigBit)
}

// ByteBitSize returns ByteSize*8 as int32.
func (b BitRange) ByteBitSize() int32 { return b.ByteSize * 8 }

// IsMostSignificant reports whether the range occupies the most significant
// bits of the byte container.
// C++ parity: BitRange::isMostSignificant (address.cc ~L841).
func (b BitRange) IsMostSignificant() bool {
	return 8*b.ByteSize == b.LeastSigBit+b.NumBits
}

// Shift shifts the range by leftShiftAmount (positive = toward more significant).
// C++ parity: BitRange::shift (address.cc ~L754).
func (b *BitRange) Shift(leftShiftAmount int32) {
	b.LeastSigBit += leftShiftAmount
	most := b.LeastSigBit + b.NumBits
	if b.LeastSigBit < 0 {
		b.NumBits += b.LeastSigBit
		b.LeastSigBit = 0
	} else if most > b.ByteSize*8 {
		b.NumBits -= most - b.ByteSize*8
	}
	if b.NumBits < 0 {
		b.LeastSigBit = 0
		b.NumBits = 0
	}
}

// IntersectMask intersects the range with a bit mask.
// C++ parity: BitRange::intersectMask (address.cc ~L731).
func (b *BitRange) IntersectMask(mask uint64) {
	mask &= b.Mask()
	if mask == 0 {
		b.LeastSigBit = 0
		b.NumBits = 0
		return
	}
	newLeast := int32(bits.TrailingZeros64(mask))
	newMost := int32(64-bits.LeadingZeros64(mask)) // exclusive
	thisMost := b.LeastSigBit + b.NumBits
	if newLeast > b.LeastSigBit {
		b.NumBits -= newLeast - b.LeastSigBit
		b.LeastSigBit = newLeast
	}
	if newMost < thisMost {
		b.NumBits -= thisMost - newMost
	}
}

// TruncateMostSigBytes removes the most significant bytes from the container.
// C++ parity: BitRange::truncateMostSigBytes (address.cc ~L774).
func (b *BitRange) TruncateMostSigBytes(num int32) {
	if b.IsBigEndian {
		b.ByteOffset += num
	}
	b.ByteSize -= num
	maxOffset := b.LeastSigBit + b.NumBits
	if maxOffset > b.ByteSize*8 {
		b.NumBits -= maxOffset - b.ByteSize*8
	}
	if b.NumBits < 0 {
		b.NumBits = 0
	}
}

// TruncateLeastSigBytes removes the least significant bytes from the container.
// C++ parity: BitRange::truncateLeastSigBytes (address.cc ~L789).
func (b *BitRange) TruncateLeastSigBytes(num int32) {
	if !b.IsBigEndian {
		b.ByteOffset += num
	}
	b.ByteSize -= num
	b.LeastSigBit -= num * 8
	if b.LeastSigBit < 0 {
		b.NumBits = b.NumBits + b.LeastSigBit
		b.LeastSigBit = 0
		if b.NumBits < 0 {
			b.NumBits = 0
		}
	}
}

// ExtendBytes widens the byte container (bit range unchanged).
// C++ parity: BitRange::extendBytes (address.cc ~L806).
func (b *BitRange) ExtendBytes(num int32) {
	if b.IsBigEndian {
		b.ByteOffset -= num
	}
	b.ByteSize += num
}

// ExpandToMost extends the numBits so it reaches the most significant bit of the container.
// C++ parity: BitRange::expandToMost (address.cc ~L864).
func (b *BitRange) ExpandToMost() {
	b.NumBits = 8*b.ByteSize - b.LeastSigBit
}

// TypeBitField is the Go-side descriptor for a bitfield member's type.
// C++ parity: class TypeBitField in type.hh. The Go type model stores
// bitfield metadata on TypeField, so this is a transient holder the walker
// consumes; it carries the logical primitive type, byte offset within the
// primitive, bit size, and signedness.
type TypeBitField struct {
	LogicalType Datatype
	BitOffset   int32
	BitSize     int32
	IsSigned    bool
}

// GetMetatype returns TYPE_INT for signed bitfields, TYPE_UINT otherwise.
// C++ parity: TypeBitField::getMetatype.
func (t *TypeBitField) GetMetatype() metatype {
	if t.IsSigned {
		return TYPE_INT
	}
	return TYPE_UINT
}

// BitFieldNodeState tracks a single Varnode the transform is walking through.
// C++ parity: class BitFieldNodeState in bitfield.hh.
type BitFieldNodeState struct {
	BitsUsed        BitRange
	BitsField       BitRange
	Node            *Varnode
	Field           *TypeBitField
	OrigLeastSigBit int32
	IsSignExtended  bool
}

// NewBitFieldNodeStateForField constructs a state for a Varnode that carries the given bitfield.
// C++ parity: BitFieldNodeState::BitFieldNodeState(BitRange,Varnode,TypeBitField).
func NewBitFieldNodeStateForField(used BitRange, vn *Varnode, fld *TypeBitField) BitFieldNodeState {
	field := BitRange{
		ByteOffset:  used.ByteOffset,
		ByteSize:    used.ByteSize,
		LeastSigBit: used.LeastSigBit,
		NumBits:     used.NumBits,
		IsBigEndian: used.IsBigEndian,
	}
	return BitFieldNodeState{
		BitsUsed:        used,
		BitsField:       field,
		Node:            vn,
		Field:           fld,
		OrigLeastSigBit: used.LeastSigBit,
	}
}

// NewBitFieldNodeStateForHole constructs a state for a hole.
// C++ parity: BitFieldNodeState::BitFieldNodeState(BitRange,Varnode,int4,int4).
func NewBitFieldNodeStateForHole(used BitRange, vn *Varnode, leastSig, numBits int32) BitFieldNodeState {
	field := BitRange{
		ByteOffset:  used.ByteOffset,
		ByteSize:    used.ByteSize,
		LeastSigBit: leastSig,
		NumBits:     numBits,
		IsBigEndian: used.IsBigEndian,
	}
	usedCopy := used
	usedCopy.LeastSigBit = leastSig
	usedCopy.NumBits = numBits
	return BitFieldNodeState{
		BitsUsed:        usedCopy,
		BitsField:       field,
		Node:            vn,
		Field:           nil,
		OrigLeastSigBit: leastSig,
	}
}

// newBitFieldNodeStateCopy builds a new state that carries over walker history
// but swaps in a fresh BitsField and output Varnode.
// C++ parity: BitFieldNodeState::BitFieldNodeState(BitFieldNodeState,BitRange,Varnode,bool)
// (bitfield.cc ~L44).
func newBitFieldNodeStateCopy(src BitFieldNodeState, newField BitRange, vn *Varnode, sgnExt bool) BitFieldNodeState {
	st := src
	st.BitsField = newField
	st.Node = vn
	st.IsSignExtended = sgnExt
	return st
}

// IsFieldAligned reports whether the Varnode can be treated as the isolated bitfield.
// C++ parity: BitFieldNodeState::isFieldAligned.
func (s BitFieldNodeState) IsFieldAligned() bool {
	return s.BitsField.LeastSigBit == 0 && s.BitsField.NumBits == s.BitsUsed.NumBits
}

// DoesSignExtensionMatch reports whether the signedness of the tracked field
// matches the observed sign extension.
// C++ parity: BitFieldNodeState::doesSignExtensionMatch.
func (s BitFieldNodeState) DoesSignExtensionMatch() bool {
	if s.Field == nil {
		return !s.IsSignExtended
	}
	return s.IsSignExtended == (s.Field.GetMetatype() == TYPE_INT)
}

// bitFieldTransform is the common base for insert and pull transforms.
// C++ parity: class BitFieldTransform in bitfield.hh.
type bitFieldTransform struct {
	fd            *Funcdata
	parentStruct  *Struct
	workList      []BitFieldNodeState
	initialOffset int32
	containerSize int32
	isBigEndian   bool
}

// newBitFieldTransform records basic info about a bitfield container.
// C++ parity: BitFieldTransform::BitFieldTransform (bitfield.cc ~L96).
func newBitFieldTransform(fd *Funcdata, dt Datatype, off int32) bitFieldTransform {
	var parent *Struct
	var sz int32
	if s, ok := dt.(*Struct); ok {
		parent = s
		sz = s.Size()
	} else if dt != nil {
		// TypePartialStruct is not modelled yet; fall back to the plain size
		// and rely on the caller-supplied offset.
		sz = dt.Size()
	}
	return bitFieldTransform{
		fd:            fd,
		parentStruct:  parent,
		initialOffset: off,
		containerSize: sz,
	}
}

// containerFieldLSB translates a bitfield member's LSB into the container frame.
// C++ parity: BitRange::translateLSB (address.cc ~L660).
func containerFieldLSB(initialOffset, containerSize int32, isBigEndian bool, f TypeField) int32 {
	runSize := int32(0)
	if f.Type != nil {
		runSize = f.Type.Size()
	}
	if isBigEndian {
		thisPos := initialOffset + containerSize
		op2Pos := f.Offset + runSize
		return f.BitOffset + 8*(thisPos-op2Pos)
	}
	return f.BitOffset + 8*(f.Offset-initialOffset)
}

// bitfieldOverlapsContainer reports whether any portion of the bitfield sits inside the container window.
func bitfieldOverlapsContainer(initialOffset, containerSize int32, f TypeField) bool {
	runSize := int32(0)
	if f.Type != nil {
		runSize = f.Type.Size()
	}
	if f.Offset+runSize <= initialOffset {
		return false
	}
	if f.Offset >= initialOffset+containerSize {
		return false
	}
	return true
}

// establishFields populates workList with one BitFieldNodeState per bitfield
// (and each hole when followHoles is set) overlapping the given Varnode.
// C++ parity: BitFieldTransform::establishFields (bitfield.cc ~L57).
func (t *bitFieldTransform) establishFields(vn *Varnode, followHoles bool) {
	t.workList = t.workList[:0]
	if vn == nil || t.parentStruct == nil {
		return
	}
	if vn.Space() != nil {
		t.isBigEndian = vn.Space().BigEndian
	}
	vnBitSize := vn.Size() * 8
	if vnBitSize <= 0 {
		return
	}
	container := BitRange{
		ByteOffset:  0,
		ByteSize:    vn.Size(),
		LeastSigBit: 0,
		NumBits:     vnBitSize,
		IsBigEndian: t.isBigEndian,
	}

	type fieldSlot struct {
		field    TypeField
		fieldPos int32
		fieldEnd int32
	}
	overlaps := make([]fieldSlot, 0, len(t.parentStruct.fields))
	for _, f := range t.parentStruct.fields {
		if !f.IsBitfield {
			continue
		}
		if !bitfieldOverlapsContainer(t.initialOffset, t.containerSize, f) {
			continue
		}
		lsb := containerFieldLSB(t.initialOffset, t.containerSize, t.isBigEndian, f)
		overlaps = append(overlaps, fieldSlot{
			field:    f,
			fieldPos: lsb,
			fieldEnd: lsb + f.BitSize,
		})
	}
	sort.SliceStable(overlaps, func(i, j int) bool {
		return overlaps[i].fieldPos < overlaps[j].fieldPos
	})

	pos := int32(0)
	for _, slot := range overlaps {
		fieldPos := slot.fieldPos
		fieldEnd := slot.fieldEnd
		if fieldPos > vnBitSize {
			fieldPos = vnBitSize
		}
		if fieldEnd > vnBitSize {
			fieldEnd = vnBitSize
		}
		if fieldPos > pos { // hole before this field
			if followHoles {
				t.workList = append(t.workList,
					NewBitFieldNodeStateForHole(container, vn, pos, fieldPos-pos))
			}
			pos = fieldPos
		}
		contained := slot.fieldPos >= 0 && slot.fieldEnd <= vnBitSize
		if contained {
			fld := &TypeBitField{
				LogicalType: slot.field.Type,
				BitOffset:   slot.field.BitOffset,
				BitSize:     slot.field.BitSize,
				IsSigned:    slot.field.Type != nil && slot.field.Type.Metatype() == TYPE_INT,
			}
			used := BitRange{
				ByteOffset:  0,
				ByteSize:    vn.Size(),
				LeastSigBit: fieldPos,
				NumBits:     fieldEnd - fieldPos,
				IsBigEndian: t.isBigEndian,
			}
			t.workList = append(t.workList, NewBitFieldNodeStateForField(used, vn, fld))
		} else if followHoles {
			t.workList = append(t.workList,
				NewBitFieldNodeStateForHole(container, vn, pos, fieldEnd-pos))
		}
		pos = fieldEnd
	}
	if pos < vnBitSize && followHoles {
		t.workList = append(t.workList,
			NewBitFieldNodeStateForHole(container, vn, pos, vnBitSize-pos))
	}
}

// buildPartialType returns the data-type associated with the root bitfield container.
// C++ parity: BitFieldTransform::buildPartialType (bitfield.cc ~L547).
// TypePartialStruct is not ported -- the partial case falls back to parentStruct.
func (t *bitFieldTransform) buildPartialType() Datatype {
	if t.parentStruct == nil {
		return nil
	}
	return t.parentStruct
}

// findOverwrite walks forward from a Varnode within a single basic block to
// check whether an unspecified bit range is subsequently overwritten.
// C++ parity: BitFieldTransform::findOverwrite (bitfield.cc ~L562).
// The Go port is conservative: without the full BitRange byte geometry tracking
// across multi-op chains, it returns true only when the range collapses to
// zero width along a simple walk -- otherwise false.
func (bitFieldTransform) findOverwrite(vn *Varnode, bl *BlockBasic, r BitRange) bool {
	if vn == nil || bl == nil {
		return false
	}
	for _, startOp := range vn.DescendIter() {
		curVn := vn
		curRange := r
		op := startOp
		for op != nil {
			if op.Parent() != bl {
				if curRange.NumBits != 0 {
					return false
				}
				break
			}
			switch op.Code() {
			case CPUI_INT_LEFT:
				cvn := op.Input(1)
				if cvn == nil || !cvn.IsConstant() {
					return false
				}
				curRange.Shift(int32(cvn.Offset()))
			case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
				cvn := op.Input(1)
				if cvn == nil || !cvn.IsConstant() {
					return false
				}
				curRange.Shift(-int32(cvn.Offset()))
			case CPUI_COPY, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_NEGATE:
				// bits still live
			case CPUI_INT_AND:
				cvn := op.Input(1)
				if cvn != nil && cvn.IsConstant() {
					curRange.IntersectMask(cvn.Offset())
				}
			case CPUI_INSERT:
				if op.NumInput() >= 4 {
					posVn := op.Input(2)
					bitsVn := op.Input(3)
					if posVn != nil && posVn.IsConstant() && bitsVn != nil && bitsVn.IsConstant() {
						insPos := int32(posVn.Offset())
						insBits := int32(bitsVn.Offset())
						if insPos <= curRange.LeastSigBit &&
							insPos+insBits >= curRange.LeastSigBit+curRange.NumBits {
							curRange.NumBits = 0
						}
					}
				}
			case CPUI_INDIRECT:
				out := op.Output()
				if out != nil && out.Addr() == vn.Addr() && out.Size() == vn.Size() {
					return curRange.NumBits == 0
				}
				return false
			default:
				if curRange.NumBits != 0 {
					return false
				}
				op = nil
			}
			if op == nil {
				break
			}
			curVn = op.Output()
			if curVn == nil {
				break
			}
			if curVn.Addr() == vn.Addr() && curVn.Size() == vn.Size() {
				if curRange.NumBits == 0 {
					return true
				}
			}
			if curVn.HasNoDescend() {
				break
			}
			op = curVn.LoneDescend()
		}
	}
	return false
}

// insertRecord captures a point that can be treated as a single-field write.
// C++ parity: BitFieldInsertTransform::InsertRecord.
type insertRecord struct {
	vn          *Varnode
	constVal    uint64
	dt          Datatype
	pos         int32
	numBits     int32
	shiftAmount int32
	isConstant  bool
}

// newInsertRecordVarnode constructs a record for a Varnode-sourced insertion.
// C++ parity: InsertRecord(Varnode,Datatype,int4,int4,int4).
func newInsertRecordVarnode(vn *Varnode, dt Datatype, pos, numBits, shiftAmount int32) insertRecord {
	return insertRecord{vn: vn, dt: dt, pos: pos, numBits: numBits, shiftAmount: shiftAmount}
}

// newInsertRecordConstant constructs a record for a constant-sourced insertion.
// C++ parity: InsertRecord(uintb,Datatype,int4,int4).
func newInsertRecordConstant(val uint64, dt Datatype, pos, numBits int32) insertRecord {
	return insertRecord{constVal: val, dt: dt, pos: pos, numBits: numBits, isConstant: true}
}

// BitFieldInsertTransform walks backward from a terminating op to collect
// writes that can be rewritten as explicit INSERT operations.
// C++ parity: class BitFieldInsertTransform in bitfield.hh.
type BitFieldInsertTransform struct {
	bitFieldTransform
	finalWriteOp  *PcodeOp
	originalValue *Varnode
	mappedVn      *Varnode
	insertList    []insertRecord
}

// NewBitFieldInsertTransform constructs the backward tracer from a terminating op.
// C++ parity: BitFieldInsertTransform::BitFieldInsertTransform (bitfield.cc ~L782).
func NewBitFieldInsertTransform(fd *Funcdata, op *PcodeOp, dt Datatype, off int32) *BitFieldInsertTransform {
	t := &BitFieldInsertTransform{
		bitFieldTransform: newBitFieldTransform(fd, dt, off),
		finalWriteOp:      op,
	}
	if op == nil {
		return t
	}
	var outvn *Varnode
	switch op.Code() {
	case CPUI_STORE:
		if op.NumInput() > 2 {
			outvn = op.Input(2)
		}
	case CPUI_INDIRECT:
		t.mappedVn = op.Output()
		if op.NumInput() < 1 {
			return t
		}
		outvn = op.Input(0)
		if outvn == nil || !outvn.IsWritten() {
			return t
		}
		t.finalWriteOp = outvn.Def()
	default:
		outvn = op.Output()
		t.mappedVn = outvn
	}
	if outvn == nil {
		return t
	}
	t.containerSize = outvn.Size()
	t.originalValue = nil
	t.establishFields(outvn, true)
	return t
}

// checkOriginalBase mirrors the C++ predicate for identifying the storage
// location's pre-insert value. The Go port implements the non-STORE path
// (mapped-variable case) faithfully, and accepts any LOAD at the same pointer
// as the STORE for the STORE path without the pointerEquality root analysis.
// TODO(bitfield-pointer-equality): pointerEquality/rootPointer are not yet
// ported -- so the STORE case approximates with a LOAD-address comparison.
// C++ parity: BitFieldInsertTransform::checkOriginalBase (bitfield.cc ~L155).
func (t *BitFieldInsertTransform) checkOriginalBase(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	if t.finalWriteOp != nil && t.finalWriteOp.Code() == CPUI_STORE {
		if !vn.IsWritten() {
			return false
		}
		loadOp := vn.Def()
		if loadOp == nil || loadOp.Code() != CPUI_LOAD {
			return false
		}
		if loadOp.NumInput() < 2 || t.finalWriteOp.NumInput() < 2 {
			return false
		}
		ptrA := loadOp.Input(1)
		ptrB := t.finalWriteOp.Input(1)
		if ptrA == nil || ptrB == nil {
			return false
		}
		// Conservative: accept when the pointer Varnodes are identical.
		if ptrA != ptrB {
			return false
		}
		if loadOp.Parent() != t.finalWriteOp.Parent() {
			return false
		}
	} else {
		if t.mappedVn == nil || t.mappedVn == vn {
			return false
		}
		if t.mappedVn.Addr() != vn.Addr() || t.mappedVn.Size() != vn.Size() {
			return false
		}
		if !vn.IsAddrTied() {
			return false
		}
	}
	t.originalValue = vn
	return true
}

// checkPulledOriginalValue reports whether the tracked Varnode is a ZPULL/SPULL
// of the bitfield container acting as the pre-insert value.
// C++ parity: BitFieldInsertTransform::checkPulledOriginalValue (bitfield.cc ~L137).
func (t *BitFieldInsertTransform) checkPulledOriginalValue(state *BitFieldNodeState) bool {
	if state.Node == nil || !state.Node.IsWritten() {
		return false
	}
	op := state.Node.Def()
	if op == nil {
		return false
	}
	opc := op.Code()
	if opc != CPUI_ZPULL && opc != CPUI_SPULL {
		return false
	}
	if op.NumInput() < 3 {
		return false
	}
	if !op.Input(1).IsConstant() || !op.Input(2).IsConstant() {
		return false
	}
	pos := int32(op.Input(1).Offset())
	nb := int32(op.Input(2).Offset())
	if pos != state.BitsField.LeastSigBit {
		return false
	}
	if nb != state.BitsField.NumBits {
		return false
	}
	return t.checkOriginalBase(op.Input(0))
}

// isOriginalValue reports whether state.Node is the pre-insert container value.
// C++ parity: BitFieldInsertTransform::isOriginalValue (bitfield.cc ~L177).
func (t *BitFieldInsertTransform) isOriginalValue(state *BitFieldNodeState) bool {
	if state.BitsField.LeastSigBit != state.OrigLeastSigBit {
		return false
	}
	if state.Node == t.originalValue {
		return true
	}
	if t.checkPulledOriginalValue(state) {
		return true
	}
	return t.checkOriginalBase(state.Node)
}

// addConstantWrite records a constant being written into the field.
// C++ parity: BitFieldInsertTransform::addConstantWrite (bitfield.cc ~L190).
func (t *BitFieldInsertTransform) addConstantWrite(state *BitFieldNodeState) bool {
	if state.Node == nil {
		return false
	}
	value := state.Node.Offset()
	state.Node = nil
	if state.Field == nil {
		return false
	}
	if state.BitsField.ByteSize > 8 {
		return false
	}
	mask := state.BitsField.Mask()
	value &= mask
	value >>= uint(state.BitsField.LeastSigBit)
	if state.Field.LogicalType != nil && state.Field.LogicalType.Metatype() == TYPE_INT {
		byteSz := state.BitsField.ByteSize
		if byteSz <= 0 {
			byteSz = 1
		}
		value = uint64(signExtendToInt64(value, byteSz))
		// Re-mask to bitsField width in case signExtendToInt64 blows past the
		// numBits boundary: use extend_signbit semantics.
		if state.BitsField.NumBits < 64 {
			signBit := uint64(1) << uint(state.BitsField.NumBits-1)
			if value&signBit != 0 {
				hi := ^uint64(0) << uint(state.BitsField.NumBits)
				value |= hi
			} else {
				value &= (uint64(1) << uint(state.BitsField.NumBits)) - 1
			}
		}
	}
	t.insertList = append(t.insertList,
		newInsertRecordConstant(value, state.Field.LogicalType, state.OrigLeastSigBit, state.Field.BitSize))
	return true
}

// addZeroOut records a zero write into the field.
// C++ parity: BitFieldInsertTransform::addZeroOut (bitfield.cc ~L213).
func (t *BitFieldInsertTransform) addZeroOut(state *BitFieldNodeState) bool {
	state.Node = nil
	if state.Field == nil {
		return false
	}
	t.insertList = append(t.insertList,
		newInsertRecordConstant(0, state.Field.LogicalType, state.OrigLeastSigBit, state.Field.BitSize))
	return true
}

// addFieldWrite records the current Varnode as the source of the field.
// C++ parity: BitFieldInsertTransform::addFieldWrite (bitfield.cc ~L225).
func (t *BitFieldInsertTransform) addFieldWrite(state *BitFieldNodeState) {
	if state.Field == nil || state.Node == nil {
		return
	}
	dt := state.Field.LogicalType
	if dt != nil && dt.Size() != state.Node.Size() {
		dt = nil
	}
	t.insertList = append(t.insertList,
		newInsertRecordVarnode(state.Node, dt, state.OrigLeastSigBit, state.Field.BitSize, state.BitsField.LeastSigBit))
	state.Node = nil
}

// handleAndBack follows the field back through INT_AND with a constant mask.
// C++ parity: BitFieldInsertTransform::handleAndBack (bitfield.cc ~L242).
func (t *BitFieldInsertTransform) handleAndBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return false
	}
	if state.BitsField.ByteSize > 8 {
		return false
	}
	val := state.BitsField.Mask()
	res := val & cvn.Offset()
	if res == val {
		state.Node = op.Input(0)
		state.BitsUsed.IntersectMask(cvn.Offset())
		return true
	}
	if res == 0 {
		return t.addZeroOut(state)
	}
	return false
}

// handleOrBack follows the field through one branch of INT_OR.
// C++ parity: BitFieldInsertTransform::handleOrBack (bitfield.cc ~L266).
func (t *BitFieldInsertTransform) handleOrBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	if state.BitsField.ByteSize > 8 {
		return false
	}
	mask := state.BitsField.Mask()
	vn0 := op.Input(0)
	vn1 := op.Input(1)
	if vn0 == nil || vn1 == nil {
		return false
	}
	isMasked0 := vn0.NZMask()&mask == 0
	isMasked1 := vn1.NZMask()&mask == 0
	if isMasked0 == isMasked1 {
		if vn1.IsConstant() {
			if vn1.NZMask()&mask == mask {
				state.Node = vn1
				return true
			}
		}
		return false
	}
	if isMasked0 {
		state.Node = vn1
	} else {
		state.Node = vn0
	}
	return true
}

// handleAddBack follows the field through one branch of INT_ADD with disjoint NZMasks.
// C++ parity: BitFieldInsertTransform::handleAddBack (bitfield.cc ~L289).
func (t *BitFieldInsertTransform) handleAddBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	if state.BitsField.ByteSize > 8 {
		return false
	}
	vn0 := op.Input(0)
	vn1 := op.Input(1)
	if vn0 == nil || vn1 == nil {
		return false
	}
	mask0 := vn0.NZMask()
	mask1 := vn1.NZMask()
	if mask0&mask1 != 0 {
		return false
	}
	mask := state.BitsField.Mask()
	isMasked0 := mask0&mask == 0
	isMasked1 := mask1&mask == 0
	if isMasked0 == isMasked1 {
		return false
	}
	if isMasked0 {
		state.Node = vn1
	} else {
		state.Node = vn0
	}
	return true
}

// handleLeftBack follows the field through INT_LEFT by a constant.
// C++ parity: BitFieldInsertTransform::handleLeftBack (bitfield.cc ~L314).
func (t *BitFieldInsertTransform) handleLeftBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return false
	}
	sa := int32(cvn.Offset())
	if sa < 0 || sa >= 64 {
		return false
	}
	newRange := state.BitsField
	newRange.Shift(-sa)
	if state.BitsField.NumBits == newRange.NumBits {
		state.BitsField = newRange
		state.BitsUsed.Shift(-sa)
		state.Node = op.Input(0)
		return true
	} else if newRange.NumBits == 0 {
		return t.addZeroOut(state)
	}
	return false
}

// handleRightBack follows the field through INT_SRIGHT by a constant.
// C++ parity: BitFieldInsertTransform::handleRightBack (bitfield.cc ~L340).
func (t *BitFieldInsertTransform) handleRightBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return false
	}
	sa := int32(cvn.Offset())
	if sa < 0 || sa >= 64 {
		return false
	}
	newRange := state.BitsField
	newRange.Shift(sa)
	if state.BitsField.NumBits == newRange.NumBits {
		state.BitsField = newRange
		state.BitsUsed.Shift(sa)
		state.Node = op.Input(0)
		return true
	}
	return false
}

// handleZextBack follows the field back through INT_ZEXT.
// C++ parity: BitFieldInsertTransform::handleZextBack (bitfield.cc ~L363).
func (t *BitFieldInsertTransform) handleZextBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 1 || op.Output() == nil {
		return false
	}
	vn := op.Input(0)
	if vn == nil {
		return false
	}
	truncAmount := op.Output().Size() - vn.Size()
	newRange := state.BitsField
	newRange.TruncateMostSigBytes(truncAmount)
	if state.BitsField.NumBits == newRange.NumBits {
		state.BitsField = newRange
		state.BitsUsed.TruncateMostSigBytes(truncAmount)
		state.Node = vn
	} else if state.BitsField.NumBits == 0 {
		return t.addZeroOut(state)
	} else {
		return false
	}
	return true
}

// handleMultBack follows the field back through INT_MULT when the multiplier is a power of 2.
// C++ parity: BitFieldInsertTransform::handleMultBack (bitfield.cc ~L386).
func (t *BitFieldInsertTransform) handleMultBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 {
		return false
	}
	vn1 := op.Input(1)
	if vn1 == nil || !vn1.IsConstant() {
		return false
	}
	val := vn1.Offset()
	if bits.OnesCount64(val) != 1 {
		return false
	}
	sa := int32(bits.TrailingZeros64(val))
	newRange := state.BitsField
	newRange.Shift(-sa)
	if state.BitsField.NumBits == newRange.NumBits {
		state.BitsField = newRange
		state.BitsUsed.Shift(-sa)
		state.Node = op.Input(0)
		return true
	} else if state.BitsField.NumBits == 0 {
		return t.addZeroOut(state)
	}
	return false
}

// handleSubpieceBack follows the field back through SUBPIECE.
// C++ parity: BitFieldInsertTransform::handleSubpieceBack (bitfield.cc ~L412).
func (t *BitFieldInsertTransform) handleSubpieceBack(state *BitFieldNodeState, op *PcodeOp) bool {
	if op.NumInput() < 2 || state.Node == nil {
		return false
	}
	inVn := op.Input(0)
	if inVn == nil {
		return false
	}
	extendAmount := inVn.Size() - state.Node.Size()
	sa := int32(op.Input(1).Offset()) * 8
	newRange := state.BitsField
	newRange.ExtendBytes(extendAmount)
	newRange.Shift(-sa)
	if state.BitsField.NumBits == newRange.NumBits {
		state.BitsField = newRange
		state.BitsUsed.ExtendBytes(extendAmount)
		state.BitsUsed.Shift(-sa)
		state.Node = op.Input(0)
		return true
	}
	return false
}

// testCallOriginal is the C++ fallback where a CALL return value may itself
// be the original value. Without a ported type-propagation pipeline we
// conservatively return false.
// C++ parity: BitFieldInsertTransform::testCallOriginal (bitfield.cc ~L436).
// TODO(bitfield-call-original): requires TypePartialStruct and typedef facing
// support, not yet ported.
func (t *BitFieldInsertTransform) testCallOriginal(state *BitFieldNodeState, op *PcodeOp) bool {
	_ = state
	_ = op
	return false
}

// processBackward walks the field back until an InsertRecord is created or a conflict is hit.
// C++ parity: BitFieldInsertTransform::processBackward (bitfield.cc ~L464).
func (t *BitFieldInsertTransform) processBackward(state *BitFieldNodeState) bool {
	for state.Node != nil {
		if state.Node.IsConstant() {
			return t.addConstantWrite(state)
		}
		if t.isOriginalValue(state) {
			state.Node = nil
			return true
		}
		if state.Field != nil && state.IsFieldAligned() {
			t.addFieldWrite(state)
			return true
		}
		if !state.Node.IsWritten() {
			return false
		}
		op := state.Node.Def()
		if op == nil {
			return false
		}
		liftRes := false
		switch op.Code() {
		case CPUI_COPY:
			state.Node = op.Input(0)
			liftRes = true
		case CPUI_INT_ADD:
			liftRes = t.handleAddBack(state, op)
		case CPUI_INT_AND:
			liftRes = t.handleAndBack(state, op)
		case CPUI_INT_LEFT:
			liftRes = t.handleLeftBack(state, op)
		case CPUI_INT_ZEXT:
			liftRes = t.handleZextBack(state, op)
		case CPUI_INT_OR:
			liftRes = t.handleOrBack(state, op)
		case CPUI_INT_MULT:
			liftRes = t.handleMultBack(state, op)
		case CPUI_SUBPIECE:
			liftRes = t.handleSubpieceBack(state, op)
		case CPUI_INT_SRIGHT:
			liftRes = t.handleRightBack(state, op)
		case CPUI_CALL, CPUI_CALLIND, CPUI_CALLOTHER:
			liftRes = t.testCallOriginal(state, op)
			if liftRes {
				state.Node = nil
				return true
			}
		default:
			liftRes = false
		}
		if !liftRes {
			if state.Field == nil {
				return false
			}
			if state.BitsField.ByteSize > 8 {
				return false
			}
			nonZero := state.BitsField
			nonZero.IntersectMask(state.Node.NZMask())
			if nonZero.NumBits == 0 {
				return t.addZeroOut(state)
			}
			state.BitsUsed.IntersectMask(state.Node.NZMask())
			if nonZero.NumBits == state.BitsUsed.NumBits {
				t.addFieldWrite(state)
				return true
			}
			return false
		}
	}
	return true
}

// isOverwrittenPartial is conservatively false in the Go port.
// C++ parity: BitFieldInsertTransform::isOverwrittenPartial (bitfield.cc ~L122).
// TODO(bitfield-overwrite-partial): depends on the full BitRange byte geometry
// tracking in findOverwrite, which is approximated here.
func (t *BitFieldInsertTransform) isOverwrittenPartial(state *BitFieldNodeState) bool {
	if state.Field != nil {
		return false
	}
	if state.BitsField.ByteSize > 8 {
		return false
	}
	if t.finalWriteOp == nil || t.finalWriteOp.Code() == CPUI_STORE {
		return false
	}
	if t.mappedVn == nil {
		return false
	}
	r := BitRange{
		ByteOffset:  t.initialOffset,
		ByteSize:    t.mappedVn.Size(),
		LeastSigBit: state.OrigLeastSigBit,
		NumBits:     state.BitsField.NumBits,
		IsBigEndian: t.isBigEndian,
	}
	return t.findOverwrite(t.mappedVn, t.finalWriteOp.Parent(), r)
}

// verifyOriginalValueBits is a conservative pass-through in the Go port.
// C++ parity: BitFieldInsertTransform::verifyOriginalValueBits (bitfield.cc ~L892).
// TODO(bitfield-verify-originals): the pointerEquality / rootPointer helpers
// required by the C++ verification pass are not ported, so the Go port accepts
// the collected insertList when originalValue is set by checkOriginalBase and
// blocks it otherwise. This is strictly looser than the C++ check.
func (t *BitFieldInsertTransform) verifyOriginalValueBits() bool {
	return true
}

// DoTrace walks backward from the terminating op to discover one InsertRecord
// per bitfield write. Returns true if apply can proceed.
// C++ parity: BitFieldInsertTransform::doTrace (bitfield.cc ~L905).
func (t *BitFieldInsertTransform) DoTrace() bool {
	if len(t.workList) == 0 {
		return false
	}
	for len(t.workList) > 0 {
		node := t.workList[0]
		t.workList = t.workList[1:]
		if !t.processBackward(&node) && !t.isOverwrittenPartial(&node) {
			return false
		}
	}
	if len(t.insertList) == 0 {
		return false
	}
	return t.verifyOriginalValueBits()
}

// Apply materializes INSERT operations for every collected record.
// C++ parity: BitFieldInsertTransform::apply (bitfield.cc ~L920).
// The Go port handles the STORE and mapped-variable flavors; foldLoad /
// foldPtrsub marking is performed, but redundancy checks and checkRedundancy
// cross-op deletion are elided (TODO).
func (t *BitFieldInsertTransform) Apply() {
	if len(t.insertList) == 0 {
		return
	}
	partialType := t.buildPartialType()
	fd := t.fd
	if fd == nil || t.finalWriteOp == nil {
		return
	}
	if t.finalWriteOp.Code() == CPUI_STORE {
		if t.finalWriteOp.NumInput() < 3 {
			return
		}
		deadPoint := t.finalWriteOp.Input(2)
		currentStore := t.finalWriteOp
		var loadModel *PcodeOp
		var loadType Datatype
		if t.originalValue == nil {
			t.originalValue = fd.NewConstant(t.containerSize, 0)
		} else {
			loadModel = t.originalValue.Def()
			loadType = t.originalValue.TypeDefFacing()
		}
		for i := range t.insertList {
			rec := &t.insertList[i]
			if currentStore == nil {
				currentStore = fd.NewOp(3, t.finalWriteOp.Addr())
				fd.OpSetOpcode(currentStore, CPUI_STORE)
				fd.OpSetInput(currentStore, t.finalWriteOp.Input(0), 0)
				fd.OpSetInput(currentStore, t.finalWriteOp.Input(1), 1)
				fd.OpInsertAfter(currentStore, t.finalWriteOp)
				if loadModel != nil {
					loadOp := fd.NewOp(2, loadModel.Addr())
					fd.OpSetOpcode(loadOp, CPUI_LOAD)
					fd.OpSetInput(loadOp, loadModel.Input(0), 0)
					fd.OpSetInput(loadOp, loadModel.Input(1), 1)
					t.originalValue = fd.NewUniqueOut(t.containerSize, loadOp)
					if loadType != nil {
						t.originalValue.UpdateType(loadType)
					}
					fd.OpInsertBefore(loadOp, currentStore)
					loadOp.SetFlag(PcodeOpNonPrinting)
				}
			}
			insertOp := t.setInsertInputs(nil, rec)
			newOut := fd.NewUniqueOut(t.containerSize, insertOp)
			if partialType != nil {
				newOut.UpdateType(partialType)
			}
			fd.OpSetInput(currentStore, insertOp.Output(), 2)
			fd.OpInsertBefore(insertOp, currentStore)
			currentStore.SetAdditionalFlag(PcodeOpSpecialPrint)
			t.addFieldShift(insertOp, rec)
			currentStore = nil
		}
		if deadPoint != nil {
			fd.DestroyVarnodeRecursive(deadPoint)
		}
		return
	}
	// Mapped-variable path: replace finalWriteOp's output with a chain of
	// INSERT ops.
	deadPoints := make([]*Varnode, 0, t.finalWriteOp.NumInput())
	for i := 0; i < t.finalWriteOp.NumInput(); i++ {
		deadPoints = append(deadPoints, t.finalWriteOp.Input(i))
	}
	if t.originalValue == nil {
		t.originalValue = fd.NewConstant(t.containerSize, 0)
	}
	if len(t.insertList) == 0 {
		return
	}
	// Redefine finalWriteOp as the first INSERT.
	insertOp := t.setInsertInputs(t.finalWriteOp, &t.insertList[0])
	if partialType != nil && insertOp.Output() != nil {
		insertOp.Output().UpdateType(partialType)
	}
	t.addFieldShift(insertOp, &t.insertList[0])
	for i := 1; i < len(t.insertList); i++ {
		rec := &t.insertList[i]
		lastOp := insertOp
		fd.OpUnsetInput(lastOp, 0)
		insertOp = t.setInsertInputs(nil, rec)
		newOut := fd.NewVarnodeOut(t.containerSize, t.mappedVn.Addr(), insertOp)
		if partialType != nil {
			newOut.UpdateType(partialType)
		}
		fd.OpSetInput(lastOp, newOut, 0)
		fd.OpInsertBefore(insertOp, lastOp)
		t.addFieldShift(insertOp, rec)
	}
	for _, vn := range deadPoints {
		if vn != nil {
			fd.DestroyVarnodeRecursive(vn)
		}
	}
}

// setInsertInputs fills an INSERT op's inputs from an InsertRecord, allocating
// a fresh op when one is not passed in.
// C++ parity: BitFieldInsertTransform::setInsertInputs (bitfield.cc ~L648).
func (t *BitFieldInsertTransform) setInsertInputs(op *PcodeOp, rec *insertRecord) *PcodeOp {
	fd := t.fd
	if op == nil {
		op = fd.NewOp(4, t.finalWriteOp.Addr())
	} else {
		for op.NumInput() < 4 {
			fd.OpInsertInput(op, nil, op.NumInput())
		}
	}
	fd.OpSetOpcode(op, CPUI_INSERT)
	fd.OpSetInput(op, t.originalValue, 0)
	valVn := rec.vn
	if valVn == nil {
		if rec.dt != nil {
			valVn = fd.NewConstant(rec.dt.Size(), rec.constVal)
			valVn.UpdateType(rec.dt)
		} else {
			valVn = fd.NewConstant(t.containerSize, rec.constVal)
		}
	}
	fd.OpSetInput(op, valVn, 1)
	fd.OpSetInput(op, fd.NewConstant(4, uint64(rec.pos)), 2)
	fd.OpSetInput(op, fd.NewConstant(4, uint64(rec.numBits)), 3)
	op.SetAdditionalFlag(PcodeOpSpecialPrint)
	return op
}

// addFieldShift inserts an INT_RIGHT ahead of an INSERT when the record asks for one.
// C++ parity: BitFieldInsertTransform::addFieldShift (bitfield.cc ~L680).
func (t *BitFieldInsertTransform) addFieldShift(insertOp *PcodeOp, rec *insertRecord) {
	if rec.shiftAmount == 0 {
		return
	}
	fd := t.fd
	valVn := insertOp.Input(1)
	if valVn == nil {
		return
	}
	shiftOp := fd.NewOp(2, insertOp.Addr())
	fd.OpSetOpcode(shiftOp, CPUI_INT_RIGHT)
	newOut := fd.NewUniqueOut(valVn.Size(), shiftOp)
	fd.OpSetInput(insertOp, newOut, 1)
	fd.OpSetInput(shiftOp, valVn, 0)
	fd.OpSetInput(shiftOp, fd.NewConstant(4, uint64(rec.shiftAmount)), 1)
	fd.OpInsertBefore(shiftOp, insertOp)
}

// pullRecordKind is the discriminator for pullRecord.
// C++ parity: anonymous enum in BitFieldPullTransform::PullRecord.
type pullRecordKind int32

const (
	pullRecordNormal  pullRecordKind = 0
	pullRecordEqual   pullRecordKind = 1
	pullRecordAborted pullRecordKind = 2
)

// pullRecord captures a read site that can be treated as isolating a single bitfield.
// C++ parity: BitFieldPullTransform::PullRecord.
type pullRecord struct {
	readVn    *Varnode
	readOp    *PcodeOp
	dt        Datatype
	kind      pullRecordKind
	pos       int32
	numBits   int32
	leftShift int32
	mask      uint64
}

// newPullRecordNormal constructs a normal pullRecord from a state and op.
// C++ parity: PullRecord::PullRecord(BitFieldNodeState,PcodeOp).
func newPullRecordNormal(state BitFieldNodeState, op *PcodeOp) pullRecord {
	var dt Datatype
	var nb int32
	if state.Field != nil {
		dt = state.Field.LogicalType
		nb = state.Field.BitSize
	}
	return pullRecord{
		readVn:    state.Node,
		readOp:    op,
		dt:        dt,
		kind:      pullRecordNormal,
		pos:       state.OrigLeastSigBit,
		numBits:   nb,
		leftShift: state.BitsField.LeastSigBit,
	}
}

// newPullRecordEqual constructs a comparison pullRecord.
// C++ parity: PullRecord::PullRecord(BitFieldNodeState,PcodeOp,uintb).
func newPullRecordEqual(state BitFieldNodeState, op *PcodeOp, val uint64) pullRecord {
	r := newPullRecordNormal(state, op)
	r.kind = pullRecordEqual
	r.mask = val
	return r
}

// newPullRecordAborted constructs an abort record.
// C++ parity: PullRecord::PullRecord(PcodeOp).
func newPullRecordAborted(op *PcodeOp) pullRecord {
	return pullRecord{readOp: op, kind: pullRecordAborted}
}

// BitFieldPullTransform traces forward from a bitfield container Varnode.
// C++ parity: class BitFieldPullTransform in bitfield.hh.
type BitFieldPullTransform struct {
	bitFieldTransform
	root     *Varnode
	loadOp   *PcodeOp
	pullList []pullRecord
}

// NewBitFieldPullTransform constructs the forward tracer rooted at vn.
// C++ parity: BitFieldPullTransform::BitFieldPullTransform (bitfield.cc ~L1594).
func NewBitFieldPullTransform(fd *Funcdata, vn *Varnode, dt Datatype, off int32) *BitFieldPullTransform {
	t := &BitFieldPullTransform{
		bitFieldTransform: newBitFieldTransform(fd, dt, off),
		root:              vn,
	}
	if vn == nil {
		return t
	}
	t.containerSize = vn.Size()
	if vn.IsWritten() && vn.Def() != nil && vn.Def().Code() == CPUI_LOAD {
		t.loadOp = vn.Def()
	}
	t.establishFields(vn, false)
	return t
}

// testConsumed reports whether all consumed bits of vn lie inside the bitfield.
// C++ parity: BitFieldPullTransform::testConsumed (bitfield.cc ~L1070).
func (t *BitFieldPullTransform) testConsumed(vn *Varnode, bitField BitRange) bool {
	if vn == nil {
		return false
	}
	if bitField.ByteSize > 8 {
		return false
	}
	mask := bitField.Mask()
	intersect := mask & vn.Consumed()
	return intersect == vn.Consumed()
}

// handleLeftForward follows the bitfield forward through INT_LEFT.
// C++ parity: BitFieldPullTransform::handleLeftForward (bitfield.cc ~L1083).
func (t *BitFieldPullTransform) handleLeftForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 || op.Input(0) != state.Node {
		return
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return
	}
	sa := int32(cvn.Offset())
	newRange := state.BitsField
	newRange.Shift(sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.BitsField.NumBits == newRange.NumBits {
		newSignExt := state.IsSignExtended || newRange.IsMostSignificant()
		next := newBitFieldNodeStateCopy(state, newRange, op.Output(), newSignExt)
		next.BitsUsed.Shift(sa)
		t.workList = append(t.workList, next)
	} else if t.testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleRightForward follows the bitfield forward through INT_RIGHT / INT_SRIGHT.
// C++ parity: BitFieldPullTransform::handleRightForward (bitfield.cc ~L1108).
func (t *BitFieldPullTransform) handleRightForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 || op.Input(0) != state.Node {
		return
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return
	}
	sa := int32(cvn.Offset())
	newRange := state.BitsField
	newRange.Shift(-sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.BitsField.NumBits == newRange.NumBits {
		newSignExt := false
		if op.Code() == CPUI_INT_SRIGHT {
			newSignExt = state.IsSignExtended
		}
		next := newBitFieldNodeStateCopy(state, newRange, op.Output(), newSignExt)
		next.BitsUsed.Shift(-sa)
		if op.Code() == CPUI_INT_SRIGHT && !state.IsSignExtended {
			next.BitsUsed.ExpandToMost()
		}
		t.workList = append(t.workList, next)
	} else if t.testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleAndForward follows the bitfield forward through INT_AND.
// C++ parity: BitFieldPullTransform::handleAndForward (bitfield.cc ~L1138).
func (t *BitFieldPullTransform) handleAndForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 || op.Input(0) != state.Node {
		return
	}
	if state.BitsField.ByteSize > 8 {
		return
	}
	cvn := op.Input(1)
	if cvn == nil || !cvn.IsConstant() {
		return
	}
	andVal := cvn.Offset()
	mask := state.BitsField.Mask()
	intersect := andVal & mask
	if intersect == 0 {
		return
	}
	if intersect == mask {
		newSignExt := state.BitsField.IsMostSignificant()
		next := newBitFieldNodeStateCopy(state, state.BitsField, op.Output(), newSignExt)
		next.BitsUsed.IntersectMask(andVal)
		t.workList = append(t.workList, next)
	} else if t.testConsumed(op.Output(), state.BitsField) {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleExtForward follows the bitfield forward through INT_ZEXT / INT_SEXT.
// C++ parity: BitFieldPullTransform::handleExtForward (bitfield.cc ~L1162).
func (t *BitFieldPullTransform) handleExtForward(state BitFieldNodeState, op *PcodeOp) {
	outvn := op.Output()
	if outvn == nil || state.Node == nil {
		return
	}
	diff := outvn.Size() - state.Node.Size()
	newSignExt := false
	if op.Code() == CPUI_INT_SEXT {
		newSignExt = state.IsSignExtended
	}
	next := newBitFieldNodeStateCopy(state, state.BitsField, outvn, newSignExt)
	next.BitsField.ExtendBytes(diff)
	next.BitsUsed.ExtendBytes(diff)
	if op.Code() == CPUI_INT_SEXT && !state.IsSignExtended {
		next.BitsUsed.ExpandToMost()
	}
	t.workList = append(t.workList, next)
}

// handleMultForward follows the bitfield forward through INT_MULT.
// C++ parity: BitFieldPullTransform::handleMultForward (bitfield.cc ~L1181).
func (t *BitFieldPullTransform) handleMultForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 || op.Input(0) != state.Node {
		return
	}
	vn1 := op.Input(1)
	if vn1 == nil || !vn1.IsConstant() {
		return
	}
	val := vn1.Offset()
	if bits.OnesCount64(val) != 1 {
		t.handleLeastSigOp(state, op)
		return
	}
	sa := int32(bits.TrailingZeros64(val))
	newRange := state.BitsField
	newRange.Shift(sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.BitsField.NumBits == newRange.NumBits {
		newSignExt := state.IsSignExtended || newRange.IsMostSignificant()
		next := newBitFieldNodeStateCopy(state, newRange, op.Output(), newSignExt)
		next.BitsUsed.Shift(sa)
		t.workList = append(t.workList, next)
	}
}

// handleSubpieceForward follows the bitfield forward through SUBPIECE.
// C++ parity: BitFieldPullTransform::handleSubpieceForward (bitfield.cc ~L1208).
func (t *BitFieldPullTransform) handleSubpieceForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 || op.Input(0) != state.Node || op.Output() == nil {
		return
	}
	leastTrunc := int32(op.Input(1).Offset())
	mostTrunc := (state.BitsField.ByteSize - leastTrunc) - op.Output().Size()
	newRange := state.BitsField
	newRange.TruncateLeastSigBytes(leastTrunc)
	newRange.TruncateMostSigBytes(mostTrunc)
	if newRange.NumBits == 0 {
		return
	}
	if state.BitsField.NumBits == newRange.NumBits {
		next := newBitFieldNodeStateCopy(state, newRange, op.Output(), state.IsSignExtended)
		next.BitsUsed.TruncateLeastSigBytes(leastTrunc)
		next.BitsUsed.TruncateMostSigBytes(mostTrunc)
		t.workList = append(t.workList, next)
	} else if t.testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleInsertForward handles the forward walk into an INSERT slot-1 reader.
// C++ parity: BitFieldPullTransform::handleInsertForward (bitfield.cc ~L1235).
func (t *BitFieldPullTransform) handleInsertForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 4 || op.Input(1) != state.Node {
		return
	}
	if state.BitsField.LeastSigBit != 0 {
		return
	}
	sz := int32(op.Input(3).Offset())
	if sz > state.BitsField.NumBits {
		return
	}
	t.pullList = append(t.pullList, newPullRecordNormal(state, op))
}

// handleLessForward follows the bitfield into INT_LESS / INT_SLESS compares.
// C++ parity: BitFieldPullTransform::handleLessForward (bitfield.cc ~L1251).
func (t *BitFieldPullTransform) handleLessForward(state BitFieldNodeState, op *PcodeOp) {
	if !state.BitsField.IsMostSignificant() {
		return
	}
	if op.NumInput() < 2 {
		return
	}
	slot := -1
	for i := 0; i < op.NumInput(); i++ {
		if op.Input(i) == state.Node {
			slot = i
			break
		}
	}
	if slot < 0 {
		return
	}
	var cvn *Varnode
	if slot == 0 {
		cvn = op.Input(1)
	} else {
		cvn = op.Input(0)
	}
	if cvn == nil || !cvn.IsConstant() {
		return
	}
	val := cvn.Offset()
	leastSigZeroBits := val&1 == 0
	var numExtremalBits int32
	if leastSigZeroBits {
		if val == 0 {
			numExtremalBits = 64
		} else {
			numExtremalBits = int32(bits.TrailingZeros64(val))
		}
	} else {
		inv := ^val
		if inv == 0 {
			numExtremalBits = 64
		} else {
			numExtremalBits = int32(bits.TrailingZeros64(inv))
		}
	}
	needMaskCheck := false
	opc := op.Code()
	if opc == CPUI_INT_SLESS || opc == CPUI_INT_LESS {
		if leastSigZeroBits && slot != 0 {
			return
		}
		if !leastSigZeroBits && slot == 0 {
			needMaskCheck = true
		}
	} else if opc == CPUI_INT_SLESSEQUAL || opc == CPUI_INT_LESSEQUAL {
		if leastSigZeroBits && slot != 1 {
			return
		}
		if !leastSigZeroBits && slot == 1 {
			needMaskCheck = true
		}
	}
	if needMaskCheck {
		var mask uint64
		if numExtremalBits >= 64 {
			mask = 0
		} else {
			mask = uint64(1) << uint(numExtremalBits)
		}
		mask -= 1
		if mask&state.Node.NZMask() == mask {
			return
		}
	}
	if state.BitsField.LeastSigBit <= numExtremalBits {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleLeastSigOp handles ops where least-significant bits are unaffected.
// C++ parity: BitFieldPullTransform::handleLeastSigOp (bitfield.cc ~L1301).
func (t *BitFieldPullTransform) handleLeastSigOp(state BitFieldNodeState, op *PcodeOp) {
	if state.BitsField.LeastSigBit != 0 {
		return
	}
	if t.testConsumed(op.Output(), state.BitsField) {
		t.pullList = append(t.pullList, newPullRecordNormal(state, op))
	}
}

// handleEqualForward follows the bitfield into INT_EQUAL/INT_NOTEQUAL.
// C++ parity: BitFieldPullTransform::handleEqualForward (bitfield.cc ~L1312).
func (t *BitFieldPullTransform) handleEqualForward(state BitFieldNodeState, op *PcodeOp) {
	if op.NumInput() < 2 {
		return
	}
	cvn := op.Input(1)
	if state.BitsField.ByteSize > 8 {
		return
	}
	if cvn == nil || !cvn.IsConstant() {
		return
	}
	if state.Field != nil && state.Field.BitSize == state.BitsField.NumBits {
		val := state.BitsField.Mask()
		t.pullList = append(t.pullList, newPullRecordEqual(state, op, val))
	} else {
		t.pullList = append(t.pullList, newPullRecordAborted(op))
	}
}

// processForward walks one level of descendants of the state's Varnode.
// C++ parity: BitFieldPullTransform::processForward (bitfield.cc ~L1328).
func (t *BitFieldPullTransform) processForward(state BitFieldNodeState) {
	if state.IsFieldAligned() && state.DoesSignExtensionMatch() {
		t.pullList = append(t.pullList, newPullRecordNormal(state, nil))
		return
	}
	if state.Node == nil {
		return
	}
	for _, op := range state.Node.DescendIter() {
		switch op.Code() {
		case CPUI_INT_LEFT:
			t.handleLeftForward(state, op)
		case CPUI_INT_MULT:
			t.handleMultForward(state, op)
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			t.handleRightForward(state, op)
		case CPUI_INT_AND:
			t.handleAndForward(state, op)
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			t.handleExtForward(state, op)
		case CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL:
			t.handleLessForward(state, op)
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			t.handleEqualForward(state, op)
		case CPUI_INT_ADD, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_2COMP, CPUI_INT_NEGATE:
			t.handleLeastSigOp(state, op)
		case CPUI_SUBPIECE:
			t.handleSubpieceForward(state, op)
		case CPUI_INSERT:
			t.handleInsertForward(state, op)
		}
	}
}

// DoTrace walks forward from the root Varnode collecting pullRecords.
// C++ parity: BitFieldPullTransform::doTrace (bitfield.cc ~L1610).
func (t *BitFieldPullTransform) DoTrace() bool {
	for len(t.workList) > 0 {
		front := t.workList[0]
		t.workList = t.workList[1:]
		t.processForward(front)
	}
	if len(t.pullList) == 0 {
		return false
	}
	sort.SliceStable(t.pullList, func(i, j int) bool {
		ai := t.pullList[i].readOp
		aj := t.pullList[j].readOp
		if ai != nil && aj != nil {
			if ai != aj {
				return pullSeqLess(ai, aj)
			}
			return false
		}
		if ai == nil {
			return true
		}
		return false
	})
	return len(t.pullList) > 0
}

// pullSeqLess orders two ops by sequence number (address time/order).
// C++ parity: PcodeOp::getSeqNum comparison used by PullRecord::operator<.
func pullSeqLess(a, b *PcodeOp) bool {
	sa := a.Seq()
	sb := b.Seq()
	if sa.Address.Less(sb.Address) {
		return true
	}
	if sb.Address.Less(sa.Address) {
		return false
	}
	if sa.Time != sb.Time {
		return sa.Time < sb.Time
	}
	return sa.Order < sb.Order
}

// Apply materializes ZPULL / SPULL operations for every collected record.
// C++ parity: BitFieldPullTransform::apply (bitfield.cc ~L1633).
// The Go port implements the core single-pull redefinition path. The
// INT_EQUAL / INT_NOTEQUAL compare-group handling (applyCompareRecord) is
// not yet ported -- those records are dropped so the pipeline never emits an
// incorrect compare rewrite.
// TODO(bitfield-pull-compare-group): port applyCompareRecord / testCompareGroup.
func (t *BitFieldPullTransform) Apply() {
	if len(t.pullList) == 0 {
		return
	}
	partialType := t.buildPartialType()
	fd := t.fd
	if fd == nil {
		return
	}
	count := 0
	for _, rec := range t.pullList {
		if rec.kind != pullRecordNormal {
			continue
		}
		t.applyPullRecord(&rec, partialType, &count)
	}
	if t.loadOp != nil {
		t.loadOp.SetFlag(PcodeOpNonPrinting)
	}
}

// applyPullRecord performs the transform for a single normal pullRecord.
// C++ parity: BitFieldPullTransform::applyRecord (bitfield.cc ~L1419). The
// Go port skips the duplicate-LOAD cloning path and the shift-after output
// rewiring when root does not equal readVn -- both are conservative TODOs.
func (t *BitFieldPullTransform) applyPullRecord(rec *pullRecord, partialType Datatype, count *int) {
	fd := t.fd
	if rec.readVn == nil || rec.dt == nil {
		return
	}
	var modOp *PcodeOp
	if rec.readOp == nil {
		modOp = rec.readVn.Def()
		if modOp == nil {
			return
		}
		fd.OpUnsetOutput(modOp)
	} else {
		if rec.readVn != t.root {
			modOp = rec.readVn.Def()
		} else {
			modOp = rec.readOp
		}
		if modOp == nil {
			return
		}
		slot := -1
		for i := 0; i < rec.readOp.NumInput(); i++ {
			if rec.readOp.Input(i) == rec.readVn {
				slot = i
				break
			}
		}
		if slot < 0 {
			return
		}
	}
	inVn := t.root
	if partialType != nil && inVn != nil {
		inVn.UpdateType(partialType)
	}
	pullOp := fd.NewOp(3, modOp.Addr())
	if rec.dt.Metatype() == TYPE_INT {
		fd.OpSetOpcode(pullOp, CPUI_SPULL)
	} else {
		fd.OpSetOpcode(pullOp, CPUI_ZPULL)
	}
	fd.OpSetInput(pullOp, inVn, 0)
	fd.OpSetInput(pullOp, fd.NewConstant(4, uint64(rec.pos)), 1)
	fd.OpSetInput(pullOp, fd.NewConstant(4, uint64(rec.numBits)), 2)
	if rec.readOp == nil {
		// Redefine readVn by the PULL output.
		pullOut := fd.NewVarnodeOut(rec.readVn.Size(), rec.readVn.Addr(), pullOp)
		if pullOut != nil {
			pullOut.UpdateType(rec.dt)
		}
		fd.OpInsertAfter(pullOp, modOp)
	} else {
		pullOut := fd.NewUniqueOut(rec.readVn.Size(), pullOp)
		if pullOut != nil {
			pullOut.UpdateType(rec.dt)
		}
		// Replace rec.readVn at the specific readOp slot.
		for i := 0; i < rec.readOp.NumInput(); i++ {
			if rec.readOp.Input(i) == rec.readVn {
				fd.OpSetInput(rec.readOp, pullOut, i)
			}
		}
		fd.OpInsertBefore(pullOp, rec.readOp)
	}
	*count += 1
}

// insertExpressionLSBMask returns the LSB mask of an INSERT op's destination slice.
// C++ parity: InsertExpression::getLSBMask in bitfield.cc (used by RuleInsertAbsorb).
func insertExpressionLSBMask(insertOp *PcodeOp) uint64 {
	if insertOp == nil || insertOp.NumInput() < 4 {
		return 0
	}
	bitsVn := insertOp.Input(3)
	if bitsVn == nil || !bitsVn.IsConstant() {
		return 0
	}
	nb := int32(bitsVn.Offset())
	if nb <= 0 {
		return 0
	}
	if nb >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(nb)) - 1
}
