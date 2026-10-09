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

// rootPointer back-tracks a pointer through PTRSUB, INT_ADD of a constant
// and COPY, returning the pointer reached and the accumulated offset.
// C++ parity: rootPointer (expression.cc).
func rootPointer(vn *Varnode) (*Varnode, uint64) {
	var offset uint64
	for vn.IsWritten() {
		op := vn.Def()
		switch op.Code() {
		case CPUI_PTRSUB:
			offset += op.Input(1).Offset()
			vn = op.Input(0)
		case CPUI_INT_ADD:
			cvn := op.Input(1)
			if !cvn.IsConstant() {
				return vn, offset
			}
			offset += cvn.Offset()
			vn = op.Input(0)
		case CPUI_COPY:
			vn = op.Input(0)
		default:
			return vn, offset
		}
	}
	return vn, offset
}

// pointerEquality reports two pointers that always hold the same value.
// C++ parity: pointerEquality (expression.cc).
func pointerEquality(vn1, vn2 *Varnode) bool {
	if vn1 == vn2 {
		return true
	}
	r1, off1 := rootPointer(vn1)
	r2, off2 := rootPointer(vn2)
	return off1 == off2 && r1 == r2
}

// bitFieldExpression is the structure and bitfield an INSERT, ZPULL or
// SPULL expression refers to. C++ parity: class BitFieldExpression.
type bitFieldExpression struct {
	theStruct         *Struct       // structure immediately containing the bitfield
	bitfield          *TypeBitField // the bitfield, nil when not recovered
	byteRangeOffset   int32         // offset of the byte range in the encompassing structure
	offsetToBitStruct int32         // offset of theStruct in the encompassing structure
}

func (e *bitFieldExpression) isValid() bool { return e.bitfield != nil }

// getStructures finds the structure holding the byte range dt describes,
// then the (possibly nested) structure holding the bitfield whose least
// significant bit is leastBitOff in that range.
// C++ parity: BitFieldExpression::getStructures.
func (e *bitFieldExpression) getStructures(dt Datatype, initByteOff, leastBitOff int32, isBigEndian bool) {
	e.theStruct = nil
	e.byteRangeOffset = initByteOff
	if initByteOff < 0 {
		e.byteRangeOffset = 0
	}
	var encompass *Struct
	switch t := dt.(type) {
	case *PartialStruct:
		st, ok := t.Container().(*Struct)
		if !ok {
			return
		}
		e.byteRangeOffset += int32(t.Offset())
		encompass = st
	case *Struct:
		encompass = t
	default:
		return
	}
	offset := int64(e.byteRangeOffset)
	leastBitOff /= 8
	if isBigEndian {
		offset += int64(dt.Size() - leastBitOff - 1)
	} else {
		offset += int64(leastBitOff)
	}
	e.theStruct = encompass
	e.offsetToBitStruct = 0
	for {
		sub, newoff := datatypeSubType(e.theStruct, offset)
		st, ok := sub.(*Struct)
		if !ok {
			break
		}
		e.theStruct = st
		e.offsetToBitStruct += int32(offset - newoff)
		offset = newoff
	}
}

// recoverStructurePointer is the Varnode holding the pointer to the
// structure containing the bitfield, skipping a PTRSUB to its byte range.
// C++ parity: BitFieldExpression::recoverStructurePointer.
func (e *bitFieldExpression) recoverStructurePointer(vn *Varnode, offset int32) *Varnode {
	if offset == 0 && e.theStruct.Size() == vn.Size() {
		return vn
	}
	if vn.IsWritten() {
		if ptrSub := vn.Def(); ptrSub.Code() == CPUI_PTRSUB && int32(ptrSub.Input(1).Offset()) == offset {
			return ptrSub.Input(0)
		}
	}
	if offset != 0 {
		return nil
	}
	return vn
}

// getPullField is the bitfield a ZPULL or SPULL extracts, or nil.
// C++ parity: BitFieldExpression::getPullField.
func getPullField(pull *PcodeOp) *TypeBitField {
	var expr bitFieldExpression
	inVn := pull.Input(0)
	leastBitOff := int32(pull.Input(1).Offset())
	bitSize := int32(pull.Input(2).Offset())
	isBig := inVn.Space().BigEndian
	expr.getStructures(inVn.TypeReadFacing(pull), 0, leastBitOff, isBig)
	if expr.theStruct == nil {
		return nil
	}
	rng := BitRange{ByteOffset: expr.byteRangeOffset - expr.offsetToBitStruct, ByteSize: inVn.Size(),
		LeastSigBit: leastBitOff, NumBits: bitSize, IsBigEndian: isBig}
	return expr.theStruct.findMatchingBitField(rng)
}

// insertExpression is a write to a bitfield held in a Varnode mapped to a
// (partial) structure symbol. C++ parity: class InsertExpression.
type insertExpression struct {
	bitFieldExpression
	insertOp *PcodeOp
	symbol   *Symbol
}

// newInsertExpression recovers the bitfield an INSERT writes.
// C++ parity: InsertExpression::InsertExpression.
func newInsertExpression(insert *PcodeOp) *insertExpression {
	e := &insertExpression{insertOp: insert}
	value := insert.Output()
	if value == nil || value.High() == nil {
		return e
	}
	e.symbol = value.High().GetSymbol()
	if e.symbol == nil {
		return e
	}
	spc := value.Space()
	leastBitOff := int32(insert.Input(2).Offset())
	bitSize := int32(insert.Input(3).Offset())
	e.getStructures(e.symbol.Type(), value.High().GetSymbolOffset(), leastBitOff, spc.BigEndian)
	if e.theStruct == nil {
		return e
	}
	rng := BitRange{ByteOffset: e.byteRangeOffset - e.offsetToBitStruct, ByteSize: value.Size(),
		LeastSigBit: leastBitOff, NumBits: bitSize, IsBigEndian: spc.BigEndian}
	e.bitfield = e.theStruct.findMatchingBitField(rng)
	return e
}

// insertRangeMask has a 1 at every bit an INSERT writes.
// C++ parity: InsertExpression::getRangeMask.
func insertRangeMask(insert *PcodeOp) uint64 {
	leastBitOff := insert.Input(2).Offset()
	return insertLSBMask(insert) << leastBitOff
}

// insertLSBMask is the mask of the least significant bits an INSERT takes
// from its value. C++ parity: InsertExpression::getLSBMask.
func insertLSBMask(insert *PcodeOp) uint64 {
	bitSize := insert.Input(3).Offset()
	res := ^uint64(0)
	if bitSize < 64 {
		res = ^(res << bitSize)
	}
	return res
}

// insertStoreExpression is a write to a bitfield through a STORE of an
// INSERT, possibly of a LOAD of the unaffected bits.
// C++ parity: class InsertStoreExpression.
type insertStoreExpression struct {
	bitFieldExpression
	insertOp  *PcodeOp
	loadOp    *PcodeOp
	structPtr *Varnode
}

// newInsertStoreExpression recovers the bitfield a STORE writes.
// C++ parity: InsertStoreExpression::InsertStoreExpression.
func newInsertStoreExpression(store *PcodeOp) *insertStoreExpression {
	e := &insertStoreExpression{}
	value := store.Input(2)
	if !value.IsWritten() {
		return e
	}
	e.insertOp = value.Def()
	if e.insertOp.Code() != CPUI_INSERT {
		return e
	}
	dest := e.insertOp.Input(0) // a constant or a LOAD
	if dest.IsWritten() {
		e.loadOp = dest.Def()
		if e.loadOp.Code() != CPUI_LOAD {
			return e
		}
	} else if !dest.IsConstant() {
		return e
	}
	spc := store.Input(0).GetSpaceFromConst()
	if spc == nil {
		return e
	}
	leastBitOff := int32(e.insertOp.Input(2).Offset())
	bitSize := int32(e.insertOp.Input(3).Offset())
	e.getStructures(value.TypeDefFacing(), 0, leastBitOff, spc.BigEndian)
	if e.theStruct == nil {
		return e
	}
	e.structPtr = e.recoverStructurePointer(store.Input(1), e.byteRangeOffset)
	if e.structPtr == nil {
		return e
	}
	rng := BitRange{ByteOffset: e.byteRangeOffset - e.offsetToBitStruct, ByteSize: value.Size(),
		LeastSigBit: leastBitOff, NumBits: bitSize, IsBigEndian: spc.BigEndian}
	e.bitfield = e.theStruct.findMatchingBitField(rng)
	return e
}

// pullExpression is a read of a bitfield by a ZPULL or SPULL, from a LOAD
// or a (partial) structure symbol. C++ parity: class PullExpression.
type pullExpression struct {
	bitFieldExpression
	pullOp    *PcodeOp
	loadOp    *PcodeOp
	structPtr *Varnode
	symbol    *Symbol
}

// newPullExpression recovers the bitfield a ZPULL or SPULL reads.
// C++ parity: PullExpression::PullExpression.
func newPullExpression(pull *PcodeOp) *pullExpression {
	e := &pullExpression{pullOp: pull}
	inVn := pull.Input(0)
	var bigEndian bool
	var dt Datatype
	var offset int32
	if inVn.IsWritten() && inVn.Def().Code() == CPUI_LOAD {
		e.loadOp = inVn.Def()
		spc := e.loadOp.Input(0).GetSpaceFromConst()
		if spc == nil {
			return e
		}
		bigEndian = spc.BigEndian
		dt = inVn.TypeReadFacing(pull)
	} else {
		if inVn.High() == nil {
			return e
		}
		e.symbol = inVn.High().GetSymbol()
		if e.symbol == nil {
			return e
		}
		bigEndian = inVn.Space().BigEndian
		dt = e.symbol.Type()
		offset = inVn.High().GetSymbolOffset()
	}
	leastBitOff := int32(pull.Input(1).Offset())
	bitSize := int32(pull.Input(2).Offset())
	e.getStructures(dt, offset, leastBitOff, bigEndian)
	if e.theStruct == nil {
		return e
	}
	if e.loadOp != nil {
		e.structPtr = e.recoverStructurePointer(e.loadOp.Input(1), e.byteRangeOffset)
		if e.structPtr == nil {
			return e
		}
	}
	rng := BitRange{ByteOffset: e.byteRangeOffset - e.offsetToBitStruct, ByteSize: inVn.Size(),
		LeastSigBit: leastBitOff, NumBits: bitSize, IsBigEndian: bigEndian}
	e.bitfield = e.theStruct.findMatchingBitField(rng)
	return e
}
