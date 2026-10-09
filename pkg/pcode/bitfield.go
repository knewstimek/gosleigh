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

// Bitfield transforms: follow the bits of a structure's bitfields backward
// from a write (INSERT) or forward from a read (ZPULL/SPULL) and rewrite
// the masks and shifts in terms of those ops.
// C++ parity: bitfield.hh / bitfield.cc.
package pcode

import (
	"math/bits"
	"sort"
)

// bitFieldNodeState is a bitfield (or a hole between bitfields) being
// followed through a Varnode. C++ parity: class BitFieldNodeState.
type bitFieldNodeState struct {
	bitsUsed        BitRange      // bits of the node in use
	bitsField       BitRange      // bits of the bitfield being followed
	node            *Varnode      // Varnode holding the bitfield
	field           *TypeBitField // nil for a hole
	origLeastSigBit int32         // original position of the least significant bit
	isSignExtended  bool          // the bitfield has been sign-extended into node
}

// newFieldState follows a bitfield. C++ parity: BitFieldNodeState(used,vn,fld).
func newFieldState(used BitRange, vn *Varnode, fld *TypeBitField) bitFieldNodeState {
	s := bitFieldNodeState{bitsUsed: used, bitsField: newBitRangeIn(fld.Bits, used.ByteOffset, used.ByteSize), node: vn, field: fld}
	s.origLeastSigBit = s.bitsField.LeastSigBit
	s.isSignExtended = fld.Type.Metatype() == TYPE_INT && s.bitsField.IsMostSignificant()
	return s
}

// newHoleState follows a hole. C++ parity: BitFieldNodeState(used,vn,leastSig,numBits).
func newHoleState(used BitRange, vn *Varnode, leastSig, numBits int32) bitFieldNodeState {
	s := bitFieldNodeState{bitsUsed: used, node: vn,
		bitsField: BitRange{ByteOffset: used.ByteOffset, ByteSize: used.ByteSize, LeastSigBit: leastSig, NumBits: numBits, IsBigEndian: used.IsBigEndian}}
	s.origLeastSigBit = s.bitsField.LeastSigBit
	return s
}

// movedState copies a state with a new field range and node.
// C++ parity: BitFieldNodeState(copy,newField,vn,sgnExt).
func movedState(cp bitFieldNodeState, newField BitRange, vn *Varnode, sgnExt bool) bitFieldNodeState {
	s := cp
	s.bitsField = newField
	s.node = vn
	s.isSignExtended = sgnExt
	return s
}

func (s *bitFieldNodeState) isFieldAligned() bool {
	return s.bitsField.LeastSigBit == 0 && s.bitsField.NumBits == s.bitsUsed.NumBits
}

func (s *bitFieldNodeState) doesSignExtensionMatch() bool {
	return s.isSignExtended == (s.field.Type.Metatype() == TYPE_INT)
}

// bitFieldTransform is the state common to the insert and pull transforms.
// C++ parity: class BitFieldTransform.
type bitFieldTransform struct {
	fd            *Funcdata
	parentStruct  *Struct
	workList      []bitFieldNodeState
	initialOffset int32
	containerSize int32
	isBigEndian   bool
}

// newBitFieldTransform sets up the structure owning the bitfields; dt may be
// a piece of it. initialOffset stays -1 when dt is neither.
// C++ parity: BitFieldTransform::BitFieldTransform.
func newBitFieldTransform(fd *Funcdata, dt Datatype, off int32) bitFieldTransform {
	t := bitFieldTransform{fd: fd, containerSize: -1, initialOffset: -1}
	switch d := dt.(type) {
	case *Struct:
		t.parentStruct, t.initialOffset = d, off
	case *PartialStruct:
		if st, ok := d.Container().(*Struct); ok {
			t.parentStruct, t.initialOffset = st, off+int32(d.Offset())
		}
	}
	// The default data space is the code space on every supported target.
	if sp := fd.BaseAddr().Space; sp != nil {
		t.isBigEndian = sp.BigEndian
	}
	return t
}

// establishFields queues a state for every bitfield vn overlaps, and for
// the holes between them when followHoles is set.
// C++ parity: BitFieldTransform::establishFields.
func (t *bitFieldTransform) establishFields(vn *Varnode, followHoles bool) {
	vnBitSize := vn.Size() * 8
	bitrange := BitRange{ByteOffset: t.initialOffset, ByteSize: vn.Size(), NumBits: vnBitSize, IsBigEndian: t.isBigEndian}
	var overlap []bitFieldTriple
	t.parentStruct.collectBitFields(0, &overlap, t.initialOffset, vn.Size())
	sort.SliceStable(overlap, func(i, j int) bool { return bitFieldTripleLess(overlap[i], overlap[j]) })
	pos := int32(0)
	for _, triple := range overlap { // least significant to most
		fieldPos := bitrange.translateLSB(triple.bitfield.Bits)
		fieldEnd := fieldPos + triple.bitfield.Bits.NumBits
		fieldPos = min(fieldPos, vnBitSize)
		fieldEnd = min(fieldEnd, vnBitSize)
		if fieldPos > pos { // a hole
			if followHoles {
				t.workList = append(t.workList, newHoleState(bitrange, vn, pos, fieldPos-pos))
			}
			pos = fieldPos
		}
		if code := bitrange.overlapTest(triple.bitfield.Bits); code == 0 || code == 3 {
			t.workList = append(t.workList, newFieldState(bitrange, vn, triple.bitfield)) // properly contained in vn
		} else if followHoles {
			t.workList = append(t.workList, newHoleState(bitrange, vn, pos, fieldEnd-pos))
		}
		pos = fieldEnd
	}
	if pos < vnBitSize && followHoles {
		t.workList = append(t.workList, newHoleState(bitrange, vn, pos, vnBitSize-pos)) // final hole
	}
}

// buildPartialType is the data-type of the root container.
// C++ parity: BitFieldTransform::buildPartialType.
func (t *bitFieldTransform) buildPartialType() Datatype {
	if t.containerSize == t.parentStruct.Size() {
		return t.parentStruct
	}
	return sharedTypeFactory.GetPartialStruct(t.parentStruct, int64(t.initialOffset), t.containerSize)
}

// findOverwrite reports that the given bits of vn are overwritten in block
// bl before any use, other bits of vn being preserved at that point.
// C++ parity: BitFieldTransform::findOverwrite.
func findOverwrite(vn *Varnode, bl *BlockBasic, rng BitRange) bool {
	minRange := rng
	minRange.minimizeContainer()
	addr := vn.Addr()
	addr.Offset += uint64(minRange.ByteOffset - rng.ByteOffset)
	containedIn := func(v *Varnode) bool {
		return v.Space() == addr.Space && addr.Offset >= v.Offset() && addr.Offset+uint64(minRange.ByteSize) <= v.Offset()+uint64(v.Size())
	}
	for _, op := range vn.DescendIter() {
		curVn := vn
		curRange := rng
		for op != nil {
			if op.Parent() != bl {
				if curRange.NumBits != 0 {
					return false // bits are used outside the block
				}
				break
			}
			switch op.Code() {
			case CPUI_PIECE:
				if op.Input(0) == curVn {
					sz := op.Input(1).Size()
					curRange.ExtendBytes(sz)
					curRange.Shift(sz * 8)
				} else {
					curRange.ExtendBytes(op.Input(0).Size())
				}
			case CPUI_INT_LEFT:
				cvn := op.Input(1)
				if !cvn.IsConstant() {
					return false
				}
				curRange.Shift(int32(cvn.Offset()))
			case CPUI_INT_RIGHT:
				cvn := op.Input(1)
				if !cvn.IsConstant() {
					return false
				}
				curRange.Shift(-int32(cvn.Offset()))
			case CPUI_COPY, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_NEGATE:
				// the remaining range continues to be used
			case CPUI_INT_AND:
				if cvn := op.Input(1); cvn.IsConstant() {
					curRange.IntersectMask(cvn.Offset())
				}
			case CPUI_INSERT:
				curRange.IntersectMask(^insertRangeMask(op))
			case CPUI_INDIRECT:
				if containedIn(op.Output()) {
					return curRange.NumBits == 0
				}
				return false
			default:
				if curRange.NumBits != 0 {
					return false // bits are actively used, not overwritten
				}
				op = nil // no overlap yet, but don't follow this path further
			}
			if op == nil {
				break
			}
			curVn = op.Output()
			if curVn == nil {
				break
			}
			if containedIn(curVn) && curRange.NumBits == 0 {
				return true
			}
			if curVn.HasNoDescend() {
				break
			}
			op = curVn.LoneDescend()
		}
	}
	return false
}

// insertRecord is one INSERT to build: a Varnode or constant written into
// numBits bits at pos, shifted right by shiftAmount first.
// C++ parity: BitFieldInsertTransform::InsertRecord.
type insertRecord struct {
	vn          *Varnode
	constVal    uint64
	dt          Datatype
	pos         int32
	numBits     int32
	shiftAmount int32
}

// bitFieldInsertTransform turns the masks and shifts writing bitfields of a
// container into INSERT ops. C++ parity: class BitFieldInsertTransform.
type bitFieldInsertTransform struct {
	bitFieldTransform
	finalWriteOp  *PcodeOp // STORE to the bitfields or op writing them
	originalValue *Varnode // value before the insertion
	mappedVn      *Varnode // container written to
	insertList    []insertRecord
}

// newBitFieldInsertTransform starts from the op terminating the putative
// bitfield expression. C++ parity: BitFieldInsertTransform::BitFieldInsertTransform.
func newBitFieldInsertTransform(fd *Funcdata, op *PcodeOp, dt Datatype, off int32) *bitFieldInsertTransform {
	t := &bitFieldInsertTransform{bitFieldTransform: newBitFieldTransform(fd, dt, off)}
	if t.initialOffset == -1 {
		return t
	}
	t.finalWriteOp = op
	var outvn *Varnode
	switch op.Code() {
	case CPUI_STORE:
		outvn = op.Input(2)
	case CPUI_INDIRECT:
		t.mappedVn = op.Output() // keep the storage location of the INDIRECT output
		outvn = op.Input(0)
		if !outvn.IsWritten() {
			return t
		}
		t.finalWriteOp = outvn.Def() // but the op feeding the INDIRECT is the final write
	default:
		outvn = op.Output()
		t.mappedVn = outvn
	}
	t.containerSize = outvn.Size()
	t.establishFields(outvn, true)
	return t
}

// isOverwrittenPartial reports a partial field whose storage is
// overwritten later in the same block.
// C++ parity: BitFieldInsertTransform::isOverwrittenPartial.
func (t *bitFieldInsertTransform) isOverwrittenPartial(state *bitFieldNodeState) bool {
	if state.field != nil || state.bitsField.ByteSize > 8 {
		return false
	}
	if t.finalWriteOp.Code() != CPUI_STORE {
		cur := BitRange{ByteOffset: t.initialOffset, ByteSize: t.mappedVn.Size(), LeastSigBit: state.origLeastSigBit,
			NumBits: state.bitsField.NumBits, IsBigEndian: t.isBigEndian}
		return findOverwrite(t.mappedVn, t.finalWriteOp.Parent(), cur)
	}
	return false
}

// checkPulledOriginalValue reports a node pulled (ZPULL/SPULL) from the
// original value at the field's own position.
// C++ parity: BitFieldInsertTransform::checkPulledOriginalValue.
func (t *bitFieldInsertTransform) checkPulledOriginalValue(state *bitFieldNodeState) bool {
	if !state.node.IsWritten() {
		return false
	}
	op := state.node.Def()
	if op.Code() != CPUI_ZPULL && op.Code() != CPUI_SPULL {
		return false
	}
	if int32(op.Input(1).Offset()) != state.bitsField.LeastSigBit || int32(op.Input(2).Offset()) != state.bitsField.NumBits {
		return false
	}
	return t.checkOriginalBase(op.Input(0))
}

// checkOriginalBase reports the initial value of the storage being
// inserted into: the original LOAD, or the mapped location read directly.
// C++ parity: BitFieldInsertTransform::checkOriginalBase.
func (t *bitFieldInsertTransform) checkOriginalBase(vn *Varnode) bool {
	if t.finalWriteOp.Code() == CPUI_STORE {
		if !vn.IsWritten() {
			return false
		}
		loadOp := vn.Def()
		if loadOp.Code() != CPUI_LOAD || !pointerEquality(loadOp.Input(1), t.finalWriteOp.Input(1)) {
			return false
		}
		if loadOp.Parent() != t.finalWriteOp.Parent() {
			return false
		}
	} else {
		if t.mappedVn == vn || t.mappedVn.Addr() != vn.Addr() || t.mappedVn.Size() != vn.Size() || !vn.IsAddrTied() {
			return false
		}
	}
	t.originalValue = vn
	return true
}

// isOriginalValue reports a (partial) copy of the original value.
// C++ parity: BitFieldInsertTransform::isOriginalValue.
func (t *bitFieldInsertTransform) isOriginalValue(state *bitFieldNodeState) bool {
	if state.bitsField.LeastSigBit != state.origLeastSigBit {
		return false
	}
	if state.node == t.originalValue {
		return true
	}
	if t.checkPulledOriginalValue(state) {
		return true
	}
	return t.checkOriginalBase(state.node)
}

// addConstantWrite records a constant written into the field.
// C++ parity: BitFieldInsertTransform::addConstantWrite.
func (t *bitFieldInsertTransform) addConstantWrite(state *bitFieldNodeState) bool {
	value := state.node.Offset()
	state.node = nil
	if state.field == nil || state.bitsField.ByteSize > 8 {
		return false
	}
	value &= state.bitsField.Mask()
	value >>= uint(state.bitsField.LeastSigBit)
	if state.field.Type.Metatype() == TYPE_INT {
		value = extendSignBit(value, state.bitsField.NumBits, state.bitsField.ByteSize)
	}
	t.insertList = append(t.insertList, insertRecord{constVal: value, dt: state.field.Type, pos: state.origLeastSigBit, numBits: state.field.Bits.NumBits})
	return true
}

// addZeroOut records zero written into the field; the state stops.
// C++ parity: BitFieldInsertTransform::addZeroOut.
func (t *bitFieldInsertTransform) addZeroOut(state *bitFieldNodeState) bool {
	state.node = nil
	if state.field == nil {
		return false
	}
	t.insertList = append(t.insertList, insertRecord{dt: state.field.Type, pos: state.origLeastSigBit, numBits: state.field.Bits.NumBits})
	return true
}

// addFieldWrite records the node written into the field.
// C++ parity: BitFieldInsertTransform::addFieldWrite.
func (t *bitFieldInsertTransform) addFieldWrite(state *bitFieldNodeState) {
	dt := state.field.Type
	if dt.Size() != state.node.Size() {
		dt = nil
	}
	t.insertList = append(t.insertList, insertRecord{vn: state.node, dt: dt, pos: state.origLeastSigBit,
		numBits: state.field.Bits.NumBits, shiftAmount: state.bitsField.LeastSigBit})
	state.node = nil
}

// handleAndBack follows the field through an INT_AND that keeps it whole,
// or records a zero when the mask clears it.
// C++ parity: BitFieldInsertTransform::handleAndBack.
func (t *bitFieldInsertTransform) handleAndBack(state *bitFieldNodeState, op *PcodeOp) bool {
	cvn := op.Input(1)
	if !cvn.IsConstant() || state.bitsField.ByteSize > 8 {
		return false
	}
	val := state.bitsField.Mask()
	res := val & cvn.Offset()
	if res == val {
		state.node = op.Input(0)
		state.bitsUsed.IntersectMask(cvn.Offset()) // a bit range was masked
		return true
	}
	if res == 0 {
		return t.addZeroOut(state)
	}
	return false // partial zeroing
}

// handleOrBack follows the field through the one INT_OR input not masking
// it off. C++ parity: BitFieldInsertTransform::handleOrBack.
func (t *bitFieldInsertTransform) handleOrBack(state *bitFieldNodeState, op *PcodeOp) bool {
	if state.bitsField.ByteSize > 8 {
		return false
	}
	mask := state.bitsField.Mask()
	vn0, vn1 := op.Input(0), op.Input(1)
	isMasked0 := vn0.NZMask()&mask == 0
	isMasked1 := vn1.NZMask()&mask == 0
	if isMasked0 == isMasked1 {
		if vn1.IsConstant() && vn1.NZMask()&mask == mask { // or-ing a constant setting every bit of the field
			state.node = vn1
			return true
		}
		return false
	}
	if isMasked0 {
		state.node = vn1
	} else {
		state.node = vn0
	}
	return true
}

// handleAddBack follows the field through the one INT_ADD input holding
// it when the inputs' bits don't mix.
// C++ parity: BitFieldInsertTransform::handleAddBack.
func (t *bitFieldInsertTransform) handleAddBack(state *bitFieldNodeState, op *PcodeOp) bool {
	if state.bitsField.ByteSize > 8 {
		return false
	}
	vn0, vn1 := op.Input(0), op.Input(1)
	mask0, mask1 := vn0.NZMask(), vn1.NZMask()
	if mask0&mask1 != 0 {
		return false // the inputs are mixed
	}
	mask := state.bitsField.Mask()
	isMasked0 := mask0&mask == 0
	isMasked1 := mask1&mask == 0
	if isMasked0 == isMasked1 {
		return false
	}
	if isMasked0 {
		state.node = vn1
	} else {
		state.node = vn0
	}
	return true
}

// handleLeftBack follows the field back through INT_LEFT by a constant,
// or records a zero when only shifted-in zeroes fill it.
// C++ parity: BitFieldInsertTransform::handleLeftBack.
func (t *bitFieldInsertTransform) handleLeftBack(state *bitFieldNodeState, op *PcodeOp) bool {
	cvn := op.Input(1)
	if !cvn.IsConstant() || cvn.Offset() >= 64 {
		return false
	}
	sa := int32(cvn.Offset())
	newRange := state.bitsField
	newRange.Shift(-sa)
	if state.bitsField.NumBits == newRange.NumBits { // all the bits are still present
		state.bitsField = newRange
		state.bitsUsed.Shift(-sa)
		state.node = op.Input(0)
		return true
	}
	if newRange.NumBits == 0 { // zero bits shifted into the field
		return t.addZeroOut(state)
	}
	return false
}

// handleRightBack follows the field back through INT_SRIGHT by a constant.
// C++ parity: BitFieldInsertTransform::handleRightBack.
func (t *bitFieldInsertTransform) handleRightBack(state *bitFieldNodeState, op *PcodeOp) bool {
	cvn := op.Input(1)
	if !cvn.IsConstant() || cvn.Offset() >= 64 {
		return false
	}
	sa := int32(cvn.Offset())
	newRange := state.bitsField
	newRange.Shift(sa)
	if state.bitsField.NumBits == newRange.NumBits {
		state.bitsField = newRange
		state.bitsUsed.Shift(sa)
		state.node = op.Input(0)
		return true
	}
	return false
}

// handleZextBack follows the field into the smaller input of an INT_ZEXT.
// C++ parity: BitFieldInsertTransform::handleZextBack.
func (t *bitFieldInsertTransform) handleZextBack(state *bitFieldNodeState, op *PcodeOp) bool {
	vn := op.Input(0)
	truncAmount := op.Output().Size() - vn.Size()
	newRange := state.bitsField
	newRange.TruncateMostSigBytes(truncAmount)
	switch {
	case state.bitsField.NumBits == newRange.NumBits:
		state.bitsField = newRange
		state.bitsUsed.TruncateMostSigBytes(truncAmount)
		state.node = vn
	case state.bitsField.NumBits == 0:
		return t.addZeroOut(state) // extended zeroes fill out the bitfield
	default:
		return false
	}
	return true
}

// handleMultBack treats INT_MULT by a power of 2 like INT_LEFT.
// C++ parity: BitFieldInsertTransform::handleMultBack.
func (t *bitFieldInsertTransform) handleMultBack(state *bitFieldNodeState, op *PcodeOp) bool {
	vn1 := op.Input(1)
	if !vn1.IsConstant() {
		return false
	}
	val := vn1.Offset()
	if bits.OnesCount64(val) != 1 {
		return false
	}
	sa := int32(leastSigBitSet(val))
	newRange := state.bitsField
	newRange.Shift(-sa)
	switch {
	case state.bitsField.NumBits == newRange.NumBits:
		state.bitsField = newRange
		state.bitsUsed.Shift(-sa)
		state.node = op.Input(0)
		return true
	case state.bitsField.NumBits == 0:
		return t.addZeroOut(state)
	}
	return false
}

// handleSubpieceBack follows the field into the input of a SUBPIECE.
// C++ parity: BitFieldInsertTransform::handleSubpieceBack.
func (t *bitFieldInsertTransform) handleSubpieceBack(state *bitFieldNodeState, op *PcodeOp) bool {
	inVn := op.Input(0)
	extendAmount := inVn.Size() - state.node.Size()
	sa := int32(op.Input(1).Offset()) * 8
	newRange := state.bitsField
	newRange.ExtendBytes(extendAmount)
	newRange.Shift(-sa)
	if state.bitsField.NumBits == newRange.NumBits {
		state.bitsField = newRange
		state.bitsUsed.ExtendBytes(extendAmount)
		state.bitsUsed.Shift(-sa)
		state.node = op.Input(0)
		return true
	}
	return false
}

// testCallOriginal treats a call returning the bitfield structure itself
// as the original value. C++ parity: BitFieldInsertTransform::testCallOriginal.
func (t *bitFieldInsertTransform) testCallOriginal(state *bitFieldNodeState, op *PcodeOp) bool {
	if !op.IsCall() || t.finalWriteOp.Code() == CPUI_STORE {
		return false
	}
	if state.bitsField.LeastSigBit != state.origLeastSigBit || t.mappedVn.IsAddrTied() || t.originalValue != nil {
		return false
	}
	if op.Output() == nil {
		return false
	}
	dt := op.Output().TypeDefFacing()
	var off int32
	switch d := dt.(type) {
	case *Struct:
	case *PartialStruct:
		off = int32(d.Offset())
		dt = d.Container()
	default:
		return false
	}
	if dt != Datatype(t.parentStruct) || off != t.initialOffset {
		return false
	}
	t.originalValue = op.Output()
	return true
}

// processBackward follows a field back, recording an INSERT if possible.
// C++ parity: BitFieldInsertTransform::processBackward.
func (t *bitFieldInsertTransform) processBackward(state *bitFieldNodeState) bool {
	for state.node != nil {
		if state.node.IsConstant() {
			return t.addConstantWrite(state)
		}
		if t.isOriginalValue(state) {
			state.node = nil
			return true
		}
		if state.field != nil && state.isFieldAligned() {
			t.addFieldWrite(state)
			return true
		}
		if !state.node.IsWritten() {
			return false
		}
		op := state.node.Def()
		var liftRes bool
		switch op.Code() {
		case CPUI_COPY:
			state.node = op.Input(0)
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
			if t.testCallOriginal(state, op) {
				state.node = nil // treated as if it matched the original value
				return true
			}
		}
		if !liftRes {
			if state.field == nil || state.bitsField.ByteSize > 8 {
				return false
			}
			nonZeroBits := state.bitsField
			nonZeroBits.IntersectMask(state.node.NZMask()) // what is known about zero bits
			if nonZeroBits.NumBits == 0 {
				return t.addZeroOut(state) // every bit in the field is zero
			}
			state.bitsUsed.IntersectMask(state.node.NZMask())
			if nonZeroBits.NumBits == state.bitsUsed.NumBits { // only the field's bits are non-zero
				t.addFieldWrite(state)
				return true
			}
			return false
		}
	}
	return true
}

// setInsertInputs makes op (or a new op) the INSERT a record describes;
// the output is left alone. C++ parity: BitFieldInsertTransform::setInsertInputs.
func (t *bitFieldInsertTransform) setInsertInputs(op *PcodeOp, rec *insertRecord) *PcodeOp {
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
	op.SetAdditionalFlag(PcodeOpSpecialPrint) // not printed as an operator with an output
	return op
}

// addFieldShift right-shifts the INSERT's value when the record asks.
// C++ parity: BitFieldInsertTransform::addFieldShift.
func (t *bitFieldInsertTransform) addFieldShift(insertOp *PcodeOp, rec *insertRecord) {
	if rec.shiftAmount == 0 {
		return
	}
	fd := t.fd
	valVn := insertOp.Input(1)
	shiftOp := fd.NewOp(2, insertOp.Addr())
	fd.OpSetOpcode(shiftOp, CPUI_INT_RIGHT)
	newOut := fd.NewUniqueOut(valVn.Size(), shiftOp)
	fd.OpSetInput(insertOp, newOut, 1)
	fd.OpSetInput(shiftOp, valVn, 0)
	fd.OpSetInput(shiftOp, fd.NewConstant(4, uint64(rec.shiftAmount)), 1)
	fd.OpInsertBefore(shiftOp, insertOp)
}

// foldLoad marks a LOAD read only by INSERT/ZPULL/SPULL (or the final
// write) as not printed. C++ parity: BitFieldInsertTransform::foldLoad.
func (t *bitFieldInsertTransform) foldLoad(loadOp *PcodeOp) bool {
	for _, op := range loadOp.Output().DescendIter() {
		if op == t.finalWriteOp {
			continue
		}
		if opc := op.Code(); opc != CPUI_INSERT && opc != CPUI_ZPULL && opc != CPUI_SPULL {
			return false
		}
	}
	loadOp.SetFlag(PcodeOpNonPrinting)
	return true
}

// foldPtrsub marks a PTRSUB feeding only absorbed LOADs and STOREs as not
// printed. C++ parity: BitFieldInsertTransform::foldPtrsub.
func foldPtrsubForInsert(loadOp *PcodeOp) {
	vn := loadOp.Input(1)
	if !vn.IsWritten() {
		return
	}
	ptrsub := vn.Def()
	if ptrsub.Code() != CPUI_PTRSUB {
		return
	}
	for _, op := range vn.DescendIter() {
		if op.Code() == CPUI_STORE && op.addlFlags&PcodeOpSpecialPrint != 0 {
			continue
		}
		if op.Code() == CPUI_LOAD && op.NotPrinted() {
			continue
		}
		return
	}
	ptrsub.SetFlag(PcodeOpNonPrinting)
}

// checkRedundancy deletes the second of two identical INSERTs of the same
// value into the same place. C++ parity: BitFieldInsertTransform::checkRedundancy.
func (t *bitFieldInsertTransform) checkRedundancy(rec *insertRecord) {
	if rec.vn == nil {
		return
	}
	var immedOp *PcodeOp
	for _, op := range rec.vn.DescendIter() {
		if op.Code() != CPUI_INSERT {
			if op.Code() != CPUI_INT_RIGHT {
				continue
			}
			op = op.Output().LoneDescend()
			if op == nil || op.Code() != CPUI_INSERT {
				continue
			}
		}
		if immedOp == nil {
			immedOp = op
			continue
		}
		if op.Input(2).Offset() != immedOp.Input(2).Offset() || op.Input(3).Offset() != immedOp.Input(3).Offset() {
			continue
		}
		if t.finalWriteOp.Code() == CPUI_STORE {
			store1 := op.Output().LoneDescend()
			if store1 == nil || store1.Code() != CPUI_STORE {
				continue
			}
			store2 := immedOp.Output().LoneDescend()
			if store2 == nil || store2.Code() != CPUI_STORE {
				continue
			}
			if store1.Parent() != store2.Parent() || !pointerEquality(store1.Input(1), store2.Input(1)) {
				continue
			}
			if store1.Seq().Order < store2.Seq().Order {
				t.fd.OpDestroyRecursive(store2)
			} else {
				t.fd.OpDestroyRecursive(store1)
			}
		}
		return
	}
}

// verifyLoadStoreOriginalValue checks that no STORE between the original
// value's LOAD and the final STORE writes the bits in mask.
// C++ parity: BitFieldInsertTransform::verifyLoadStoreOriginalValue.
func (t *bitFieldInsertTransform) verifyLoadStoreOriginalValue(mask uint64) bool {
	loadOp := t.originalValue.Def()
	ops := t.finalWriteOp.Parent().Ops()
	basePtr, off := rootPointer(t.finalWriteOp.Input(1))
	for i := indexOfOp(ops, t.finalWriteOp) - 1; i >= 0; i-- {
		op := ops[i]
		if op == loadOp {
			return true
		}
		if op.IsCall() {
			return false
		}
		if op.Code() != CPUI_STORE {
			continue
		}
		if op.Input(0).Offset() != loadOp.Input(0).Offset() {
			continue // LOAD and STORE not to the same address space
		}
		other, otherOff := rootPointer(op.Input(1))
		if basePtr != other {
			return false // unrelated pointer (potential alias)
		}
		if otherOff != off {
			continue
		}
		vn := op.Input(2)
		if !vn.IsWritten() {
			return false // unknown value
		}
		insertOp := vn.Def()
		if insertOp.Code() != CPUI_INSERT || insertRangeMask(insertOp)&mask != 0 {
			return false
		}
	}
	return true
}

// verifyMappedOriginalValue checks that no write to the mapped storage
// between the original value and the final write touches the bits in mask.
// C++ parity: BitFieldInsertTransform::verifyMappedOriginalValue.
func (t *bitFieldInsertTransform) verifyMappedOriginalValue(mask uint64) bool {
	ops := t.finalWriteOp.Parent().Ops()
	for i := indexOfOp(ops, t.finalWriteOp) - 1; i >= 0; i-- {
		op := ops[i]
		vn := op.Output()
		if vn == t.originalValue {
			return true
		}
		if vn == nil {
			continue
		}
		if op.IsCall() {
			return false // mapped location in unknown state
		}
		if vn.Addr() != t.originalValue.Addr() || vn.Size() != t.originalValue.Size() {
			continue
		}
		insertOp := vn.Def()
		if insertOp.Code() != CPUI_INSERT || insertRangeMask(insertOp)&mask != 0 {
			return false
		}
	}
	return true
}

// indexOfOp is op's position in its block's op list (len when absent, so
// a backward walk starts from the end). C++ parity: PcodeOp::getBasicIter.
func indexOfOp(ops []*PcodeOp, op *PcodeOp) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return len(ops)
}

// constructOriginalValueMask has a 1 at every bit not INSERTed: those
// come from the original value.
// C++ parity: BitFieldInsertTransform::constructOriginalValueMask.
func (t *bitFieldInsertTransform) constructOriginalValueMask() uint64 {
	var mask uint64
	for _, rec := range t.insertList {
		var val uint64
		if rec.numBits < 64 {
			val = uint64(1) << uint(rec.numBits)
		}
		val--
		mask |= val << uint(rec.pos)
	}
	return ^mask & bitfieldSizeMask(t.originalValue.Size())
}

// verifyOriginalValueBits checks that the bits not INSERTed really come
// from the original value. C++ parity: BitFieldInsertTransform::verifyOriginalValueBits.
func (t *bitFieldInsertTransform) verifyOriginalValueBits() bool {
	if t.originalValue == nil {
		return true
	}
	mask := t.constructOriginalValueMask()
	if mask == 0 {
		return true
	}
	if t.finalWriteOp.Code() == CPUI_STORE {
		return t.verifyLoadStoreOriginalValue(mask)
	}
	return t.verifyMappedOriginalValue(mask)
}

// doTrace follows every field back, matching insert expressions.
// C++ parity: BitFieldInsertTransform::doTrace.
func (t *bitFieldInsertTransform) doTrace() bool {
	if len(t.workList) == 0 {
		return false
	}
	for i := range t.workList {
		node := &t.workList[i]
		if !t.processBackward(node) && !t.isOverwrittenPartial(node) {
			return false
		}
	}
	t.workList = nil
	if len(t.insertList) == 0 {
		return false
	}
	return t.verifyOriginalValueBits()
}

// apply rewrites the recovered expressions as INSERT ops.
// C++ parity: BitFieldInsertTransform::apply.
func (t *bitFieldInsertTransform) apply() {
	fd := t.fd
	partialType := t.buildPartialType()
	if t.finalWriteOp.Code() == CPUI_STORE {
		deadPoint := t.finalWriteOp.Input(2) // root of an expression that may be dead
		currentStore := t.finalWriteOp       // the original STORE takes the first INSERT
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
				currentStore = fd.NewOp(3, t.finalWriteOp.Addr()) // a new STORE for each additional INSERT
				fd.OpSetOpcode(currentStore, CPUI_STORE)
				fd.OpSetInput(currentStore, t.finalWriteOp.Input(0), 0)
				fd.OpSetInput(currentStore, t.finalWriteOp.Input(1), 1)
				fd.OpInsertAfter(currentStore, t.finalWriteOp)
				if loadModel != nil {
					loadOp := fd.NewOp(2, loadModel.Addr()) // and a new LOAD
					fd.OpSetOpcode(loadOp, CPUI_LOAD)
					fd.OpSetInput(loadOp, loadModel.Input(0), 0)
					fd.OpSetInput(loadOp, loadModel.Input(1), 1)
					t.originalValue = fd.NewUniqueOut(t.containerSize, loadOp)
					t.originalValue.UpdateType(loadType)
					fd.OpInsertBefore(loadOp, currentStore)
					loadOp.SetFlag(PcodeOpNonPrinting) // don't print the LOAD, prevent CAST ops
				}
			}
			insertOp := t.setInsertInputs(nil, rec)
			newOut := fd.NewUniqueOut(t.containerSize, insertOp)
			newOut.UpdateType(partialType)
			fd.OpSetInput(currentStore, insertOp.Output(), 2)
			fd.OpInsertBefore(insertOp, currentStore)
			currentStore.SetAdditionalFlag(PcodeOpSpecialPrint) // special bitfield printing on the STORE
			t.addFieldShift(insertOp, rec)
			currentStore = nil
		}
		fd.DestroyVarnodeRecursive(deadPoint)
		if loadModel != nil && loadModel.Code() == CPUI_LOAD {
			if t.foldLoad(loadModel) {
				foldPtrsubForInsert(loadModel)
			}
		}
	} else { // mapped variable
		deadPoints := make([]*Varnode, 0, t.finalWriteOp.NumInput())
		for i := 0; i < t.finalWriteOp.NumInput(); i++ {
			deadPoints = append(deadPoints, t.finalWriteOp.Input(i)) // roots of expressions that may be dead
		}
		if t.originalValue == nil {
			t.originalValue = fd.NewConstant(t.containerSize, 0)
		}
		// Redefine finalWriteOp as the first INSERT, keeping its output.
		insertOp := t.setInsertInputs(t.finalWriteOp, &t.insertList[0])
		insertOp.Output().UpdateType(partialType)
		t.addFieldShift(insertOp, &t.insertList[0])
		for i := 1; i < len(t.insertList); i++ {
			lastOp := insertOp
			fd.OpUnsetInput(lastOp, 0) // the original value moves to the new INSERT
			insertOp = t.setInsertInputs(nil, &t.insertList[i])
			newOut := fd.NewVarnodeOut(t.containerSize, t.mappedVn.Addr(), insertOp)
			newOut.UpdateType(partialType)
			fd.OpSetInput(lastOp, newOut, 0)
			fd.OpInsertBefore(insertOp, lastOp)
			t.addFieldShift(insertOp, &t.insertList[i])
		}
		for _, vn := range deadPoints {
			fd.DestroyVarnodeRecursive(vn)
		}
	}
	for i := range t.insertList {
		t.checkRedundancy(&t.insertList[i])
	}
}

// Pull record kinds. C++ parity: BitFieldPullTransform::PullRecord enum.
const (
	pullNormal  = 0 // a single field pull
	pullEqual   = 1 // a pull for INT_EQUAL or INT_NOTEQUAL
	pullAborted = 2 // abort the pull for the entire op
)

// pullRecord is a point where a bitfield is extracted.
// C++ parity: BitFieldPullTransform::PullRecord.
type pullRecord struct {
	readVn    *Varnode // Varnode holding the pulled value
	readOp    *PcodeOp // op reading it, or nil when readVn itself is redefined
	dt        Datatype // data-type of the pulled value
	kind      int
	pos       int32  // bit position of the field
	numBits   int32  // bits in the field
	leftShift int32  // amount the final field is left shifted
	mask      uint64 // the bitfield within the Varnode (equal records)
}

func newPullRecord(state *bitFieldNodeState, op *PcodeOp) pullRecord {
	return pullRecord{readVn: state.node, readOp: op, dt: state.field.Type, kind: pullNormal,
		pos: state.origLeastSigBit, numBits: state.field.Bits.NumBits, leftShift: state.bitsField.LeastSigBit}
}

func newEqualPullRecord(state *bitFieldNodeState, op *PcodeOp, val uint64) pullRecord {
	r := newPullRecord(state, op)
	r.kind, r.mask = pullEqual, val
	return r
}

// pullRecordLess orders records by the op whose input is pulled.
// C++ parity: PullRecord::operator<.
func pullRecordLess(a, b *pullRecord) bool {
	switch {
	case a.readOp != nil && b.readOp != nil:
		if a.readOp != b.readOp {
			return seqLess(a.readOp, b.readOp)
		}
		return false
	case a.readOp == nil:
		return true
	}
	return false
}

// bitFieldPullTransform turns the masks and shifts reading bitfields of a
// container into ZPULL/SPULL ops. C++ parity: class BitFieldPullTransform.
type bitFieldPullTransform struct {
	bitFieldTransform
	root     *Varnode
	loadOp   *PcodeOp // LOAD producing root, if any
	pullList []pullRecord
}

// newBitFieldPullTransform starts from a Varnode with a bitfield data-type.
// C++ parity: BitFieldPullTransform::BitFieldPullTransform.
func newBitFieldPullTransform(fd *Funcdata, r *Varnode, dt Datatype, off int32) *bitFieldPullTransform {
	t := &bitFieldPullTransform{bitFieldTransform: newBitFieldTransform(fd, dt, off)}
	if t.initialOffset == -1 {
		return t
	}
	t.root = r
	t.containerSize = r.Size()
	if r.IsWritten() && r.Def().Code() == CPUI_LOAD {
		t.loadOp = r.Def()
	}
	t.establishFields(r, false) // holes are not followed
	return t
}

// testConsumed reports that every consumed bit of vn is in the bitfield.
// C++ parity: BitFieldPullTransform::testConsumed.
func testConsumed(vn *Varnode, bitField BitRange) bool {
	if bitField.ByteSize > 8 {
		return false
	}
	return bitField.Mask()&vn.Consumed() == vn.Consumed()
}

func (t *bitFieldPullTransform) follow(state *bitFieldNodeState, newRange BitRange, vn *Varnode, sgnExt bool) *bitFieldNodeState {
	t.workList = append(t.workList, movedState(*state, newRange, vn, sgnExt))
	return &t.workList[len(t.workList)-1]
}

// handleLeftForward: C++ parity BitFieldPullTransform::handleLeftForward.
func (t *bitFieldPullTransform) handleLeftForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(0) != state.node {
		return
	}
	cvn := op.Input(1)
	if !cvn.IsConstant() {
		return
	}
	sa := int32(cvn.Offset())
	newRange := state.bitsField
	newRange.Shift(sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.bitsField.NumBits == newRange.NumBits {
		next := t.follow(state, newRange, op.Output(), state.isSignExtended || newRange.IsMostSignificant())
		next.bitsUsed.Shift(sa)
	} else if testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleRightForward: C++ parity BitFieldPullTransform::handleRightForward.
func (t *bitFieldPullTransform) handleRightForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(0) != state.node {
		return
	}
	cvn := op.Input(1)
	if !cvn.IsConstant() {
		return
	}
	sa := int32(cvn.Offset())
	newRange := state.bitsField
	newRange.Shift(-sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.bitsField.NumBits == newRange.NumBits {
		newSignExt := false
		if op.Code() == CPUI_INT_SRIGHT {
			newSignExt = state.isSignExtended
		}
		next := t.follow(state, newRange, op.Output(), newSignExt)
		next.bitsUsed.Shift(-sa)
		if op.Code() == CPUI_INT_SRIGHT && !state.isSignExtended {
			next.bitsUsed.ExpandToMost() // sign-extending bits not in the field
		}
	} else if testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleAndForward: C++ parity BitFieldPullTransform::handleAndForward.
func (t *bitFieldPullTransform) handleAndForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(0) != state.node || state.bitsField.ByteSize > 8 {
		return
	}
	cvn := op.Input(1)
	if !cvn.IsConstant() {
		return
	}
	andVal := cvn.Offset()
	mask := state.bitsField.Mask()
	intersect := andVal & mask
	if intersect == 0 {
		return // the field is masked away
	}
	if intersect == mask { // nothing masked away: follow the whole field
		next := t.follow(state, state.bitsField, op.Output(), state.bitsField.IsMostSignificant())
		next.bitsUsed.IntersectMask(andVal)
	} else if testConsumed(op.Output(), state.bitsField) {
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleExtForward: C++ parity BitFieldPullTransform::handleExtForward.
func (t *bitFieldPullTransform) handleExtForward(state *bitFieldNodeState, op *PcodeOp) {
	outvn := op.Output()
	diff := outvn.Size() - state.node.Size()
	newSignExt := false
	if op.Code() == CPUI_INT_SEXT {
		newSignExt = state.isSignExtended
	}
	next := t.follow(state, state.bitsField, outvn, newSignExt)
	next.bitsField.ExtendBytes(diff)
	next.bitsUsed.ExtendBytes(diff)
	if op.Code() == CPUI_INT_SEXT && !state.isSignExtended {
		next.bitsUsed.ExpandToMost() // sign-extending bits not in the field
	}
}

// handleMultForward: C++ parity BitFieldPullTransform::handleMultForward.
func (t *bitFieldPullTransform) handleMultForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(0) != state.node {
		return
	}
	vn1 := op.Input(1)
	if !vn1.IsConstant() {
		return
	}
	val := vn1.Offset()
	if bits.OnesCount64(val) != 1 {
		t.handleLeastSigOp(state, op)
		return
	}
	sa := int32(leastSigBitSet(val))
	newRange := state.bitsField
	newRange.Shift(sa)
	if newRange.NumBits == 0 {
		return
	}
	if state.bitsField.NumBits == newRange.NumBits {
		next := t.follow(state, newRange, op.Output(), state.isSignExtended || newRange.IsMostSignificant())
		next.bitsUsed.Shift(sa)
	}
}

// handleSubpieceForward: C++ parity BitFieldPullTransform::handleSubpieceForward.
func (t *bitFieldPullTransform) handleSubpieceForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(0) != state.node {
		return
	}
	leastTrunc := int32(op.Input(1).Offset())
	mostTrunc := (state.bitsField.ByteSize - leastTrunc) - op.Output().Size()
	newRange := state.bitsField
	newRange.TruncateLeastSigBytes(leastTrunc)
	newRange.TruncateMostSigBytes(mostTrunc)
	if newRange.NumBits == 0 {
		return
	}
	if state.bitsField.NumBits == newRange.NumBits {
		// Any sign extension is preserved: only truncated, the whole field is present.
		next := t.follow(state, newRange, op.Output(), state.isSignExtended)
		next.bitsUsed.TruncateLeastSigBytes(leastTrunc)
		next.bitsUsed.TruncateMostSigBytes(mostTrunc)
	} else if testConsumed(op.Output(), newRange) {
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleInsertForward treats the value INSERTed as a pull of the field when
// it takes only the field's bits.
// C++ parity: BitFieldPullTransform::handleInsertForward.
func (t *bitFieldPullTransform) handleInsertForward(state *bitFieldNodeState, op *PcodeOp) {
	if op.Input(1) != state.node || state.bitsField.LeastSigBit != 0 {
		return
	}
	if sz := int32(op.Input(3).Offset()); sz > state.bitsField.NumBits {
		return
	}
	t.pullList = append(t.pullList, newPullRecord(state, op))
}

// handleLessForward records a comparison acting only on the field's bits
// (the field being the most significant bits compared).
// C++ parity: BitFieldPullTransform::handleLessForward.
func (t *bitFieldPullTransform) handleLessForward(state *bitFieldNodeState, op *PcodeOp) {
	if !state.bitsField.IsMostSignificant() {
		return
	}
	slot := op.GetSlot(state.node)
	cvn := op.Input(1 - slot)
	if !cvn.IsConstant() {
		return
	}
	val := cvn.Offset()
	leastSigZeroBits := val&1 == 0
	var numExtremalBits int
	if leastSigZeroBits {
		numExtremalBits = leastSigBitSet(val) // least significant 0 bits
	} else {
		numExtremalBits = leastSigBitSet(^val) // least significant 1 bits
	}
	if numExtremalBits < 0 {
		numExtremalBits = 64
	}
	needMaskCheck := false
	switch op.Code() {
	case CPUI_INT_SLESS, CPUI_INT_LESS:
		if leastSigZeroBits && slot != 0 {
			return
		}
		if !leastSigZeroBits && slot == 0 {
			needMaskCheck = true
		}
	case CPUI_INT_SLESSEQUAL, CPUI_INT_LESSEQUAL:
		if leastSigZeroBits && slot != 1 {
			return
		}
		if !leastSigZeroBits && slot == 1 {
			needMaskCheck = true
		}
	}
	if needMaskCheck {
		var mask uint64
		if numExtremalBits < 64 {
			mask = uint64(1) << uint(numExtremalBits)
		}
		mask--
		if mask&state.node.NZMask() == mask {
			return // there must be at least one 0 bit
		}
	}
	if int(state.bitsField.LeastSigBit) <= numExtremalBits {
		// The comparison is only affected by field bits: a pull, then a shift.
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleLeastSigOp records ops whose low result bits don't depend on the
// inputs' higher bits. C++ parity: BitFieldPullTransform::handleLeastSigOp.
func (t *bitFieldPullTransform) handleLeastSigOp(state *bitFieldNodeState, op *PcodeOp) {
	if state.bitsField.LeastSigBit != 0 {
		return
	}
	if testConsumed(op.Output(), state.bitsField) {
		t.pullList = append(t.pullList, newPullRecord(state, op))
	}
}

// handleEqualForward: C++ parity BitFieldPullTransform::handleEqualForward.
func (t *bitFieldPullTransform) handleEqualForward(state *bitFieldNodeState, op *PcodeOp) {
	cvn := op.Input(1)
	if state.bitsField.ByteSize > 8 || !cvn.IsConstant() {
		return
	}
	if state.field != nil && state.field.Bits.NumBits == state.bitsField.NumBits {
		t.pullList = append(t.pullList, newEqualPullRecord(state, op, state.bitsField.Mask()))
	} else {
		t.pullList = append(t.pullList, pullRecord{readOp: op, kind: pullAborted}) // abort pulls into this op
	}
}

// processForward follows a field one level through its descendants.
// C++ parity: BitFieldPullTransform::processForward.
func (t *bitFieldPullTransform) processForward(state *bitFieldNodeState) {
	if state.isFieldAligned() && state.doesSignExtensionMatch() {
		t.pullList = append(t.pullList, newPullRecord(state, nil))
		return
	}
	for _, op := range state.node.DescendIter() {
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

// testCompareGroup drops the records of one INT_EQUAL/INT_NOTEQUAL starting
// at i when any is aborted or unrelated bits are compared, returning the
// index after the group. C++ parity: BitFieldPullTransform::testCompareGroup.
func (t *bitFieldPullTransform) testCompareGroup(i int) int {
	vn := t.pullList[i].readVn
	op := t.pullList[i].readOp
	val := op.Input(1).Offset()
	isAborted := false
	var collectMask uint64
	j := i
	for ; j < len(t.pullList) && t.pullList[j].readOp == op; j++ {
		if t.pullList[j].kind == pullAborted {
			isAborted = true
		}
		collectMask |= t.pullList[j].mask
	}
	if isAborted || ^collectMask&val != 0 || (vn != nil && ^collectMask&vn.NZMask() != 0) {
		t.pullList = append(t.pullList[:i], t.pullList[j:]...)
		return i
	}
	return j
}

// pullTransformState is kept across the records of one apply.
// C++ parity: BitFieldPullTransform::TransformState.
type pullTransformState struct {
	partialType Datatype
	count       int
}

// applyRecord creates the ZPULL or SPULL for a record, duplicating the LOAD
// for every record after the first and left-shifting when needed.
// C++ parity: BitFieldPullTransform::applyRecord.
func (t *bitFieldPullTransform) applyRecord(rec *pullRecord, state *pullTransformState) {
	fd := t.fd
	var modOp *PcodeOp
	if rec.readOp == nil { // readVn holds a complete pull
		modOp = rec.readVn.Def()
		fd.OpUnsetOutput(modOp) // modify the definition of readVn
	} else { // modify the single read of readVn by readOp
		if rec.readVn != t.root {
			modOp = rec.readVn.Def()
		} else {
			modOp = rec.readOp
		}
		slot := rec.readOp.GetSlot(rec.readVn)
		rec.readVn = fd.NewUnique(rec.readVn.Size()) // holds the complete pull
		fd.OpSetInput(rec.readOp, rec.readVn, slot)
	}
	inVn := t.root
	if t.loadOp != nil && state.count > 0 {
		newLoad := fd.NewOp(2, t.loadOp.Addr()) // a copy of the original LOAD
		fd.OpSetOpcode(newLoad, CPUI_LOAD)
		fd.OpSetInput(newLoad, t.loadOp.Input(0), 0)
		fd.OpSetInput(newLoad, t.loadOp.Input(1), 1)
		inVn = fd.NewUniqueOut(t.containerSize, newLoad)
		fd.OpInsertAfter(newLoad, t.loadOp)
		newLoad.SetFlag(PcodeOpNonPrinting)
	}
	inVn.UpdateType(state.partialType)
	pullOp := fd.NewOp(3, modOp.Addr())
	if rec.dt.Metatype() == TYPE_INT {
		fd.OpSetOpcode(pullOp, CPUI_SPULL)
	} else {
		fd.OpSetOpcode(pullOp, CPUI_ZPULL)
	}
	fd.OpSetInput(pullOp, inVn, 0)
	fd.OpSetInput(pullOp, fd.NewConstant(4, uint64(rec.pos)), 1)
	fd.OpSetInput(pullOp, fd.NewConstant(4, uint64(rec.numBits)), 2)
	if modOp != rec.readOp {
		fd.OpInsertAfter(pullOp, modOp)
	} else {
		fd.OpInsertBefore(pullOp, modOp)
	}
	if rec.leftShift != 0 {
		shiftVn := fd.NewUniqueOut(t.containerSize, pullOp)
		shiftOp := fd.NewOp(2, modOp.Addr())
		fd.OpSetOpcode(shiftOp, CPUI_INT_LEFT)
		fd.OpSetInput(shiftOp, shiftVn, 0)
		fd.OpSetInput(shiftOp, fd.NewConstant(4, uint64(rec.leftShift)), 1)
		fd.OpInsertAfter(shiftOp, pullOp)
		fd.OpSetOutput(shiftOp, rec.readVn)
	} else {
		fd.OpSetOutput(pullOp, rec.readVn)
	}
	pullOut := pullOp.Output()
	if pullOut.Type() == nil || pullOut.Type().Metatype() == TYPE_UNKNOWN {
		pullOut.UpdateType(resizeInteger(rec.dt, pullOut.Size()))
	} else if rec.dt.Metatype() == TYPE_BOOL && pullOut.Size() == 1 && rec.numBits == 1 {
		pullOut.UpdateType(rec.dt)
	}
	if modOp != rec.readOp {
		if outvn := modOp.Output(); outvn == nil || outvn.HasNoDescend() {
			fd.OpDestroyRecursive(modOp)
		}
	}
	state.count++
}

// applyCompareRecord splits a comparison of several fields into one
// comparison per field (joined by BOOL_AND/BOOL_OR) and adjusts each
// constant to its field; the records become normal pulls.
// C++ parity: BitFieldPullTransform::applyCompareRecord.
func (t *bitFieldPullTransform) applyCompareRecord(rec *pullRecord) {
	fd := t.fd
	origVal := rec.readOp.Input(1).Offset()
	num := 0
	for num < len(t.pullList) && t.pullList[num].readOp == rec.readOp {
		num++
	}
	if num > 1 {
		opc := rec.readOp.Code()
		combineCode := CPUI_BOOL_OR
		if opc == CPUI_INT_EQUAL {
			combineCode = CPUI_BOOL_AND
		}
		vn := rec.readOp.Input(0)
		curCombine := rec.readOp
		fd.OpSetOpcode(curCombine, combineCode)
		for i := 0; i < num; i++ {
			op := fd.NewOp(2, curCombine.Addr())
			fd.OpSetOpcode(op, opc)
			boolVn := fd.NewUniqueOut(1, op)
			fd.OpSetInput(op, vn, 0)
			fd.OpInsertBefore(op, curCombine)
			switch {
			case i == 0:
				fd.OpSetInput(curCombine, boolVn, 0)
			case i < num-1:
				combineOp := fd.NewOp(2, curCombine.Addr())
				fd.OpSetOpcode(combineOp, combineCode)
				bool2Vn := fd.NewUniqueOut(1, combineOp)
				fd.OpSetInput(curCombine, bool2Vn, 1)
				fd.OpSetInput(combineOp, boolVn, 0)
				fd.OpInsertBefore(combineOp, curCombine)
				curCombine = combineOp
			default:
				fd.OpSetInput(curCombine, boolVn, 1)
			}
			t.pullList[i].readOp = op
		}
	}
	for i := 0; i < num; i++ {
		sub := &t.pullList[i]
		val := (origVal & sub.mask) >> uint(sub.leftShift)
		if sub.dt.Metatype() == TYPE_INT {
			val = extendSignBit(val, sub.numBits, sub.readVn.Size())
		}
		vn := fd.NewConstant(sub.readVn.Size(), val)
		vn.UpdateType(resizeInteger(sub.dt, sub.readVn.Size()))
		fd.OpSetInput(sub.readOp, vn, 1) // adjust the compare value
		sub.kind = pullNormal
		sub.leftShift = 0 // accounted for
	}
}

// foldLoad marks a LOAD read only by ZPULL/SPULL/INSERT as not printed.
// C++ parity: BitFieldPullTransform::foldLoad.
func (t *bitFieldPullTransform) foldLoad(loadOp *PcodeOp) bool {
	for _, op := range loadOp.Output().DescendIter() {
		if opc := op.Code(); opc != CPUI_ZPULL && opc != CPUI_SPULL && opc != CPUI_INSERT {
			return false
		}
	}
	loadOp.SetFlag(PcodeOpNonPrinting)
	return true
}

// foldPtrsub marks a PTRSUB feeding only absorbed LOADs as not printed.
// C++ parity: BitFieldPullTransform::foldPtrsub.
func (t *bitFieldPullTransform) foldPtrsub(loadOp *PcodeOp) {
	vn := loadOp.Input(1)
	if !vn.IsWritten() {
		return
	}
	ptrsub := vn.Def()
	if ptrsub.Code() != CPUI_PTRSUB {
		return
	}
	for _, op := range vn.DescendIter() {
		if op.Code() != CPUI_LOAD || !op.NotPrinted() {
			return
		}
	}
	ptrsub.SetFlag(PcodeOpNonPrinting)
}

// doTrace creates a pull record at each point a field is extracted.
// C++ parity: BitFieldPullTransform::doTrace.
func (t *bitFieldPullTransform) doTrace() bool {
	for i := 0; i < len(t.workList); i++ { // the list grows while walked
		state := t.workList[i]
		t.processForward(&state)
	}
	t.workList = nil
	if len(t.pullList) == 0 {
		return false
	}
	sort.SliceStable(t.pullList, func(i, j int) bool { return pullRecordLess(&t.pullList[i], &t.pullList[j]) })
	for i := 0; i < len(t.pullList); {
		if t.pullList[i].kind != pullNormal {
			i = t.testCompareGroup(i)
		} else {
			i++
		}
	}
	return len(t.pullList) > 0
}

// apply redefines each readVn as a ZPULL/SPULL (deleting its old op), or
// gives a specific readOp a Varnode holding the pulled value.
// C++ parity: BitFieldPullTransform::apply.
func (t *bitFieldPullTransform) apply() {
	state := pullTransformState{partialType: t.buildPartialType()}
	for len(t.pullList) > 0 {
		rec := &t.pullList[0]
		if rec.kind == pullEqual {
			t.applyCompareRecord(rec)
		} else {
			t.applyRecord(rec, &state)
			t.pullList = t.pullList[1:]
		}
	}
	if t.loadOp != nil && t.foldLoad(t.loadOp) {
		t.foldPtrsub(t.loadOp)
	}
}

// resizeInteger is an integer data-type like ct at a new size.
// C++ parity: TypeFactory::resizeInteger.
func resizeInteger(ct Datatype, newSize int32) Datatype {
	if newSize == ct.Size() {
		return ct
	}
	meta := ct.Metatype()
	if meta != TYPE_INT && meta != TYPE_UINT {
		meta = TYPE_UINT
	}
	if !isCharPrint(ct) && newSize == 1 && meta == TYPE_INT {
		return sharedTypeFactory.GetBase(1, TYPE_INT, "sbyte") // getBaseNoChar
	}
	return sharedTypeFactory.GetBase(newSize, meta, "")
}
