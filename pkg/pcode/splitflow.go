// Copyright 2026 The Gosleigh Authors.
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

import (
)

// SplitFlow::SplitFlow -- subflow.cc.
type SplitFlow struct {
	*TransformManager
	laneDescription LaneDescription
	worklist        [][]*TransformVar
}

// SplitFlow::SplitFlow -- subflow.cc.
func NewSplitFlow(f *Funcdata, root *Varnode, lowSize int32) *SplitFlow {
	sf := &SplitFlow{
		TransformManager: NewTransformManager(f),
		laneDescription:  *NewLaneDescriptionTwoLanes(root.Size(), lowSize, root.Size()-lowSize),
	}
	sf.setReplacement(root)
	return sf
}

// SplitFlow::setReplacement -- subflow.cc.
func (sf *SplitFlow) setReplacement(vn *Varnode) []*TransformVar {
	if vn == nil {
		return nil
	}
	if vn.IsMark() {
		return sf.GetSplit(vn, &sf.laneDescription)
	}
	if vn.IsTypeLock() {
		if dt := vn.TypeReadFacing(nil); dt != nil && dt.Metatype() != TYPE_PARTIALSTRUCT {
			return nil
		}
	}
	if vn.IsInput() {
		return nil
	}
	if vn.IsFree() && !vn.IsConstant() {
		return nil
	}
	res := sf.NewSplit(vn, &sf.laneDescription)
	if res == nil {
		return nil
	}
	vn.SetMark()
	if !vn.IsConstant() {
		sf.worklist = append(sf.worklist, res)
	}
	return res
}

// SplitFlow::addOp -- subflow.cc.
func (sf *SplitFlow) addOp(op *PcodeOp, rvn []*TransformVar, slot int) bool {
	if op == nil || len(rvn) < 2 {
		return false
	}
	var outvn []*TransformVar
	if slot == -1 {
		outvn = rvn
	} else {
		outvn = sf.setReplacement(op.Output())
		if outvn == nil {
			return false
		}
	}
	if outvn[0].GetDef() != nil {
		return true
	}
	loOp := sf.NewOpReplace(op.NumInput(), op.Code(), op)
	hiOp := sf.NewOpReplace(op.NumInput(), op.Code(), op)
	numParam := op.NumInput()
	if op.Code() == CPUI_INDIRECT {
		sf.OpSetInput(loOp, sf.NewIop(op.Input(1)), 1)
		sf.OpSetInput(hiOp, sf.NewIop(op.Input(1)), 1)
		loOp.inheritIndirect(op)
		hiOp.inheritIndirect(op)
		numParam = 1
	}
	for i := 0; i < numParam; i++ {
		var invn []*TransformVar
		if i == slot {
			invn = rvn
		} else {
			invn = sf.setReplacement(op.Input(i))
			if invn == nil {
				return false
			}
		}
		sf.OpSetInput(loOp, invn[0], i)
		sf.OpSetInput(hiOp, invn[1], i)
	}
	sf.OpSetOutput(loOp, outvn[0])
	sf.OpSetOutput(hiOp, outvn[1])
	return true
}

// SplitFlow::traceForward -- subflow.cc.
func (sf *SplitFlow) traceForward(rvn []*TransformVar) bool {
	if len(rvn) < 2 {
		return false
	}
	origvn := rvn[0].GetOriginal()
	for _, op := range origvn.DescendIter() {
		outvn := op.Output()
		if outvn != nil && outvn.IsMark() && !op.IsCall() {
			continue
		}
		switch op.Code() {
		case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INDIRECT, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR:
			if !sf.addOp(op, rvn, op.GetSlot(origvn)) {
				return false
			}
		case CPUI_SUBPIECE:
			if outvn != nil && (outvn.IsPrecisLo() || outvn.IsPrecisHi()) {
				return false
			}
			val := int32(op.Input(1).Offset())
			if val == 0 && outvn != nil && outvn.Size() == sf.laneDescription.GetSize(0) {
				rop := sf.NewPreexistingOp(1, CPUI_COPY, op)
				sf.OpSetInput(rop, rvn[0], 0)
			} else if outvn != nil && val == sf.laneDescription.GetSize(0) && outvn.Size() == sf.laneDescription.GetSize(1) {
				rop := sf.NewPreexistingOp(1, CPUI_COPY, op)
				sf.OpSetInput(rop, rvn[1], 0)
			} else {
				return false
			}
		case CPUI_INT_LEFT:
			if !op.Input(1).IsConstant() {
				return false
			}
			if int32(op.Input(1).Offset()) != sf.laneDescription.GetSize(0)*8 {
				return false
			}
			invn := op.Input(0)
			if !invn.IsWritten() {
				return false
			}
			zextOp := invn.Def()
			if zextOp == nil || zextOp.Code() != CPUI_INT_ZEXT {
				return false
			}
			invn = zextOp.Input(0)
			if invn.Size() != sf.laneDescription.GetSize(1) || invn.IsFree() {
				return false
			}
			loOp := sf.NewPreexistingOp(1, CPUI_COPY, op)
			hiOp := sf.NewPreexistingOp(1, CPUI_COPY, op)
			sf.OpSetInput(loOp, sf.NewConstant(sf.laneDescription.GetSize(0), 0, 0), 0)
			sf.OpSetOutput(loOp, rvn[0])
			sf.OpSetInput(hiOp, sf.GetPreexistingVarnode(invn), 0)
			sf.OpSetOutput(hiOp, rvn[1])
		case CPUI_INT_SRIGHT, CPUI_INT_RIGHT:
			if !op.Input(1).IsConstant() {
				return false
			}
			val := int32(op.Input(1).Offset())
			if val < sf.laneDescription.GetSize(0)*8 {
				return false
			}
			extOpCode := CPUI_INT_ZEXT
			if op.Code() == CPUI_INT_SRIGHT {
				extOpCode = CPUI_INT_SEXT
			}
			if val == sf.laneDescription.GetSize(0)*8 {
				rop := sf.NewPreexistingOp(1, extOpCode, op)
				sf.OpSetInput(rop, rvn[1], 0)
			} else {
				remainShift := val - sf.laneDescription.GetSize(0)*8
				rop := sf.NewPreexistingOp(2, op.Code(), op)
				extrop := sf.NewOp(1, extOpCode, rop)
				sf.OpSetInput(extrop, rvn[1], 0)
				sf.OpSetOutput(extrop, sf.NewUnique(sf.laneDescription.GetWholeSize()))
				sf.OpSetInput(rop, extrop.GetOut(), 0)
				sf.OpSetInput(rop, sf.NewConstant(op.Input(1).Size(), 0, uint64(remainShift)), 1)
			}
		default:
			return false
		}
	}
	return true
}

// SplitFlow::traceBackward -- subflow.cc.
func (sf *SplitFlow) traceBackward(rvn []*TransformVar) bool {
	if len(rvn) == 0 || rvn[0] == nil || rvn[0].GetOriginal() == nil {
		return false
	}
	op := rvn[0].GetOriginal().Def()
	if op == nil {
		return true
	}
	switch op.Code() {
	case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INDIRECT:
		if !sf.addOp(op, rvn, -1) {
			return false
		}
	case CPUI_PIECE:
		if op.Input(0).Size() != sf.laneDescription.GetSize(1) {
			return false
		}
		if op.Input(1).Size() != sf.laneDescription.GetSize(0) {
			return false
		}
		loOp := sf.NewOpReplace(1, CPUI_COPY, op)
		hiOp := sf.NewOpReplace(1, CPUI_COPY, op)
		sf.OpSetInput(loOp, sf.GetPreexistingVarnode(op.Input(1)), 0)
		sf.OpSetOutput(loOp, rvn[0])
		sf.OpSetInput(hiOp, sf.GetPreexistingVarnode(op.Input(0)), 0)
		sf.OpSetOutput(hiOp, rvn[1])
	case CPUI_INT_ZEXT:
		if op.Input(0).Size() != sf.laneDescription.GetSize(0) || op.Output().Size() != sf.laneDescription.GetWholeSize() {
			return false
		}
		loOp := sf.NewOpReplace(1, CPUI_COPY, op)
		hiOp := sf.NewOpReplace(1, CPUI_COPY, op)
		sf.OpSetInput(loOp, sf.GetPreexistingVarnode(op.Input(0)), 0)
		sf.OpSetOutput(loOp, rvn[0])
		sf.OpSetInput(hiOp, sf.NewConstant(sf.laneDescription.GetSize(1), 0, 0), 0)
		sf.OpSetOutput(hiOp, rvn[1])
	case CPUI_INT_LEFT:
		cvn := op.Input(1)
		if !cvn.IsConstant() || int32(cvn.Offset()) != sf.laneDescription.GetSize(0)*8 {
			return false
		}
		invn := op.Input(0)
		if !invn.IsWritten() {
			return false
		}
		zextOp := invn.Def()
		if zextOp == nil || zextOp.Code() != CPUI_INT_ZEXT {
			return false
		}
		invn = zextOp.Input(0)
		if invn.Size() != sf.laneDescription.GetSize(1) || invn.IsFree() {
			return false
		}
		loOp := sf.NewOpReplace(1, CPUI_COPY, op)
		hiOp := sf.NewOpReplace(1, CPUI_COPY, op)
		sf.OpSetInput(loOp, sf.NewConstant(sf.laneDescription.GetSize(0), 0, 0), 0)
		sf.OpSetOutput(loOp, rvn[0])
		sf.OpSetInput(hiOp, sf.GetPreexistingVarnode(invn), 0)
		sf.OpSetOutput(hiOp, rvn[1])
	default:
		return false
	}
	return true
}

// SplitFlow::processNextWork -- subflow.cc.
func (sf *SplitFlow) processNextWork() bool {
	if len(sf.worklist) == 0 {
		return false
	}
	rvn := sf.worklist[len(sf.worklist)-1]
	sf.worklist = sf.worklist[:len(sf.worklist)-1]
	if !sf.traceBackward(rvn) {
		return false
	}
	return sf.traceForward(rvn)
}

// SplitFlow::doTrace -- subflow.cc.
func (sf *SplitFlow) DoTrace() bool {
	if len(sf.worklist) == 0 {
		return false
	}
	retval := true
	for len(sf.worklist) > 0 {
		if !sf.processNextWork() {
			retval = false
			break
		}
	}
	sf.ClearVarnodeMarks()
	return retval
}

// splitDatatypePiece is one pair of matching data-types in a split.
// C++ parity: SplitDatatype::Component.
type splitDatatypePiece struct {
	inType  Datatype
	outType Datatype
	offset  int32
}

// splitPointerType is a pointer data-type a LOAD/STORE address may carry:
// a plain or a relative pointer.
type splitPointerType interface {
	Datatype
	Pointee() Datatype
	WordSize() uint32
}

// splitRootPointer describes the pointer feeding a LOAD or STORE and the
// root pointer to the containing structure or array it is an offset from.
// C++ parity: SplitDatatype::RootPointer.
type splitRootPointer struct {
	loadStore    *PcodeOp
	ptrType      splitPointerType
	firstPointer *Varnode
	pointer      *Varnode
	baseOffset   int32
}

// backUpPointer moves pointer back through a COPY, INT_ADD, PTRSUB or PTRADD
// from a pointer to a structure, an array, or the implied array element.
// C++ parity: SplitDatatype::RootPointer::backUpPointer.
func (rp *splitRootPointer) backUpPointer(impliedBase Datatype) bool {
	if !rp.pointer.IsWritten() {
		return false
	}
	addOp := rp.pointer.Def()
	opc := addOp.Code()
	var off int32
	switch opc {
	case CPUI_PTRSUB, CPUI_INT_ADD, CPUI_PTRADD:
		cvn := addOp.Input(1)
		if !cvn.IsConstant() {
			return false
		}
		off = int32(cvn.Offset())
	case CPUI_COPY:
		off = 0
	default:
		return false
	}
	tmpPointer := addOp.Input(0)
	ct, ok := tmpPointer.TypeReadFacing(addOp).(splitPointerType)
	if !ok || ct.Metatype() != TYPE_PTR {
		return false
	}
	parent := ct.Pointee()
	meta := parent.Metatype()
	if meta != TYPE_STRUCT && meta != TYPE_ARRAY {
		if (opc != CPUI_PTRADD && opc != CPUI_COPY) || parent != impliedBase {
			return false
		}
	}
	rp.ptrType = ct
	if opc == CPUI_PTRADD {
		off *= int32(addOp.Input(2).Offset())
	}
	off = int32(int64(off)*splitWordSize(ct))
	rp.baseOffset += off
	rp.pointer = tmpPointer
	return true
}

// find locates the pointer to valueType feeding op (directly or one hop
// back), then backs up through nested structure/array offsets.
// C++ parity: SplitDatatype::RootPointer::find.
func (rp *splitRootPointer) find(op *PcodeOp, valueType Datatype) bool {
	var impliedBase Datatype
	if p, ok := valueType.(*PartialStruct); ok { // Strip off partial to get containing struct or array
		valueType = p.container
	}
	if arr, ok := valueType.(*Array); ok { // An implied array (pointer to element) also matches
		valueType = arr.Element()
		impliedBase = valueType
	}
	rp.loadStore = op
	rp.baseOffset = 0
	rp.pointer = op.Input(1)
	rp.firstPointer = rp.pointer
	ct, ok := rp.pointer.TypeReadFacing(op).(splitPointerType)
	if !ok || ct.Metatype() != TYPE_PTR {
		return false
	}
	rp.ptrType = ct
	if ct.Pointee() != valueType {
		if impliedBase != nil {
			return false
		}
		if !rp.backUpPointer(impliedBase) {
			return false
		}
		if rp.ptrType.Pointee() != valueType {
			return false
		}
	}
	for i := 0; i < 3; i++ {
		if rp.pointer.IsAddrTied() || rp.pointer.LoneDescend() == nil {
			break
		}
		if !rp.backUpPointer(impliedBase) {
			break
		}
	}
	return true
}

// duplicateToTemp COPYs the root pointer into a temporary so later STOREs
// cannot modify it. C++ parity: SplitDatatype::RootPointer::duplicateToTemp.
func (rp *splitRootPointer) duplicateToTemp(data *Funcdata, followOp *PcodeOp) {
	copyOp := data.NewOp(1, followOp.Addr())
	data.OpSetOpcode(copyOp, CPUI_COPY)
	newRoot := data.NewUniqueOut(rp.pointer.Size(), copyOp)
	data.OpSetInput(copyOp, rp.pointer, 0)
	data.OpInsertBefore(copyOp, followOp)
	newRoot.UpdateType(rp.ptrType)
	rp.pointer = newRoot
}

// freePointerChain removes the pointer calculations left unused.
// C++ parity: SplitDatatype::RootPointer::freePointerChain.
func (rp *splitRootPointer) freePointerChain(data *Funcdata) {
	for rp.firstPointer != rp.pointer && !rp.firstPointer.IsAddrTied() && rp.firstPointer.HasNoDescend() {
		tmpOp := rp.firstPointer.Def()
		rp.firstPointer = tmpOp.Input(0)
		data.OpDestroy(tmpOp)
	}
}

// SplitDatatype splits COPY, LOAD and STORE ops moving several logical
// components of a structure or array at once.
// C++ parity: class SplitDatatype (subflow.cc).
type SplitDatatype struct {
	data            *Funcdata
	types           *TypeFactory
	pieces          []splitDatatypePiece
	splitStructures bool
	splitArrays     bool
	isLoadStore     bool
}

// NewSplitDatatype uses the default split_datatype_config (structures and
// arrays). C++ parity: SplitDatatype::SplitDatatype.
func NewSplitDatatype(funcdata *Funcdata) *SplitDatatype {
	return &SplitDatatype{
		data:            funcdata,
		types:           sharedTypeFactory,
		splitStructures: true,
		splitArrays:     true,
	}
}

// datatypeHoleSize is the size of the undefined gap at off, 0 if off is
// covered by a component. C++ parity: Datatype::getHoleSize overrides.
func datatypeHoleSize(dt Datatype, off int64) int64 {
	switch t := dt.(type) {
	case *Struct:
		fields := t.Fields()
		i := structLowerBoundField(fields, off)
		if i >= 0 {
			cur := fields[i]
			newOff := off - int64(cur.Offset)
			if newOff < int64(cur.Type.Size()) {
				return datatypeHoleSize(cur.Type, newOff)
			}
		}
		i++
		if i < len(fields) {
			return int64(fields[i].Offset) - off
		}
		return int64(t.Size()) - off
	case *Array:
		el := t.Element()
		if el == nil || el.AlignSize() <= 0 {
			return 0
		}
		return datatypeHoleSize(el, off%int64(el.AlignSize()))
	case *PartialStruct:
		sizeLeft := int64(t.Size()) - off
		res := datatypeHoleSize(t.container, off+t.offset)
		if res > sizeLeft {
			res = sizeLeft
		}
		return res
	}
	return 0
}

// getComponent returns the (possibly nested) component starting exactly at
// offset, or an undefined type the size of a hole there (isHole).
// C++ parity: SplitDatatype::getComponent.
func (sd *SplitDatatype) getComponent(ct Datatype, offset int32) (Datatype, bool) {
	curType := ct
	curOff := int64(offset)
	for {
		curType, curOff = datatypeSubType(curType, curOff)
		if curType == nil {
			hole := datatypeHoleSize(ct, int64(offset))
			if hole > 0 {
				if hole > 8 {
					hole = 8
				}
				return sd.types.GetBase(int32(hole), TYPE_UNKNOWN, ""), true
			}
			return nil, false
		}
		if curOff == 0 && curType.Metatype() != TYPE_ARRAY {
			return curType, false
		}
	}
}

// categorizeDatatype: -1 not splittable, 0 structure to split, 1 array to
// split, 2 primitive that can be split any way (an undefined1 array acts as
// a large primitive). C++ parity: SplitDatatype::categorizeDatatype.
func (sd *SplitDatatype) categorizeDatatype(ct Datatype) int {
	unknownBytes := func(arr *Array) int {
		el := arr.Element()
		if el.Metatype() != TYPE_UNKNOWN || el.Size() != 1 {
			return 1
		}
		return 2
	}
	switch t := ct.(type) {
	case *Array:
		if sd.splitArrays {
			return unknownBytes(t)
		}
		return -1
	case *PartialStruct:
		switch parent := t.container.(type) {
		case *Array:
			if sd.splitArrays {
				return unknownBytes(parent)
			}
		case *Struct:
			if sd.splitStructures {
				return 0
			}
		}
		return -1
	case *Struct:
		if sd.splitStructures && len(t.fields) > 1 {
			return 0
		}
		return -1
	}
	switch ct.Metatype() {
	case TYPE_INT, TYPE_UINT, TYPE_UNKNOWN:
		return 2
	}
	return -1
}

// testDatatypeCompatibility tests whether the data-types split into
// components of matching size and offset, recording them in pieces.
// C++ parity: SplitDatatype::testDatatypeCompatibility.
func (sd *SplitDatatype) testDatatypeCompatibility(inBase, outBase Datatype, inConstant bool) bool {
	inCategory := sd.categorizeDatatype(inBase)
	if inCategory < 0 {
		return false
	}
	outCategory := sd.categorizeDatatype(outBase)
	if outCategory < 0 {
		return false
	}
	if outCategory == 2 && inCategory == 2 {
		return false
	}
	if !inConstant && inBase == outBase && inBase.Metatype() == TYPE_STRUCT {
		return false // Don't split a whole structure unless it is getting initialized from a constant
	}
	if sd.isLoadStore && outCategory == 2 && inCategory == 1 {
		return false // Don't split array pointer writing into primitive
	}
	if sd.isLoadStore && inCategory == 2 && !inConstant && outCategory == 1 {
		return false // Don't split primitive into an array pointer
	}
	if sd.isLoadStore && inCategory == 1 && outCategory == 1 && !inConstant {
		return false // Don't split copies between arrays
	}
	curOff := int32(0)
	sizeLeft := inBase.Size()
	holeCheck := func(isHole bool) bool {
		if isHole {
			if len(sd.pieces) == 1 {
				return false // Initial offset into structure is at a hole
			}
			if sizeLeft == 0 && len(sd.pieces) == 2 {
				return false // Two pieces, one is a hole. Likely padding.
			}
		}
		return true
	}
	switch {
	case inCategory == 2: // Input is primitive
		for sizeLeft > 0 {
			curOut, outHole := sd.getComponent(outBase, curOff)
			if curOut == nil {
				return false
			}
			curIn := curOut // Throw away primitive data-type if it is a constant
			if !inConstant {
				curIn = sd.types.GetBase(curOut.Size(), TYPE_UNKNOWN, "")
			}
			sd.pieces = append(sd.pieces, splitDatatypePiece{curIn, curOut, curOff})
			sizeLeft -= curOut.Size()
			curOff += curOut.Size()
			if !holeCheck(outHole) {
				return false
			}
		}
	case outCategory == 2: // Output is primitive
		for sizeLeft > 0 {
			curIn, inHole := sd.getComponent(inBase, curOff)
			if curIn == nil {
				return false
			}
			curOut := sd.types.GetBase(curIn.Size(), TYPE_UNKNOWN, "")
			sd.pieces = append(sd.pieces, splitDatatypePiece{curIn, curOut, curOff})
			sizeLeft -= curIn.Size()
			curOff += curIn.Size()
			if !holeCheck(inHole) {
				return false
			}
		}
	default: // Both in and out data-types have components
		for sizeLeft > 0 {
			curIn, inHole := sd.getComponent(inBase, curOff)
			if curIn == nil {
				return false
			}
			curOut, outHole := sd.getComponent(outBase, curOff)
			if curOut == nil {
				return false
			}
			for curIn.Size() != curOut.Size() {
				if curIn.Size() > curOut.Size() {
					if inHole {
						curIn = sd.types.GetBase(curOut.Size(), TYPE_UNKNOWN, "")
					} else {
						curIn, inHole = sd.getComponent(curIn, 0)
					}
					if curIn == nil {
						return false
					}
				} else {
					if outHole {
						curOut = sd.types.GetBase(curIn.Size(), TYPE_UNKNOWN, "")
					} else {
						curOut, outHole = sd.getComponent(curOut, 0)
					}
					if curOut == nil {
						return false
					}
				}
			}
			sd.pieces = append(sd.pieces, splitDatatypePiece{curIn, curOut, curOff})
			sizeLeft -= curIn.Size()
			curOff += curIn.Size()
		}
	}
	return len(sd.pieces) > 1
}

// testCopyConstraints: don't split function inputs or hidden COPYs.
// C++ parity: SplitDatatype::testCopyConstraints.
func (sd *SplitDatatype) testCopyConstraints(copyOp *PcodeOp) bool {
	inVn := copyOp.Input(0)
	if inVn.IsInput() {
		return false
	}
	if inVn.IsAddrTied() {
		outVn := copyOp.Output()
		if outVn.IsAddrTied() && outVn.Addr() == inVn.Addr() {
			return false
		}
	} else if inVn.IsWritten() && inVn.Def().Code() == CPUI_LOAD {
		if inVn.LoneDescend() == copyOp {
			return false // Handled by splitCopy()
		}
	}
	return true
}

// generateConstants splits an extended precision constant, ZEXT(c) or
// CONCAT(c1,c2), into per-piece constants.
// C++ parity: SplitDatatype::generateConstants.
func (sd *SplitDatatype) generateConstants(vn *Varnode) ([]*Varnode, bool) {
	if vn.LoneDescend() == nil || !vn.IsWritten() {
		return nil, false
	}
	op := vn.Def()
	opc := op.Code()
	switch opc {
	case CPUI_INT_ZEXT:
		if !op.Input(0).IsConstant() {
			return nil, false
		}
	case CPUI_PIECE:
		if !op.Input(0).IsConstant() || !op.Input(1).IsConstant() {
			return nil, false
		}
	default:
		return nil, false
	}
	var lo, hi uint64
	var losize int32
	fullsize := vn.Size()
	isBigEndian := vn.Space() != nil && vn.Space().BigEndian
	if opc == CPUI_INT_ZEXT {
		lo = op.Input(0).Offset()
		losize = op.Input(0).Size()
	} else {
		hi = op.Input(0).Offset()
		lo = op.Input(1).Offset()
		losize = op.Input(1).Size()
	}
	var out []*Varnode
	for _, piece := range sd.pieces {
		dt := piece.inType
		if dt.Size() > 8 {
			return nil, false
		}
		sa := piece.offset
		if isBigEndian {
			sa = fullsize - (piece.offset + dt.Size())
		}
		var val uint64
		if sa >= losize {
			val = hi >> uint(sa-losize)
		} else {
			val = lo >> uint(sa*8)
			if sa+dt.Size() > losize {
				val |= hi << uint((losize-sa)*8)
			}
		}
		val &= maskForSize(dt.Size())
		outVn := sd.data.NewConstant(dt.Size(), val)
		outVn.UpdateType(dt)
		out = append(out, outVn)
	}
	sd.data.OpDestroy(op)
	return out, true
}

// buildInConstants splits a constant input by the piece offsets.
// C++ parity: SplitDatatype::buildInConstants.
func (sd *SplitDatatype) buildInConstants(rootVn *Varnode, bigEndian bool) []*Varnode {
	baseVal := rootVn.Offset()
	out := make([]*Varnode, 0, len(sd.pieces))
	for _, piece := range sd.pieces {
		dt := piece.inType
		off := piece.offset
		if bigEndian {
			off = rootVn.Size() - off - dt.Size()
		}
		val := (baseVal >> uint(8*off)) & maskForSize(dt.Size())
		outVn := sd.data.NewConstant(dt.Size(), val)
		outVn.UpdateType(dt)
		out = append(out, outVn)
	}
	return out
}

// buildInSubpieces extracts each input piece with a SUBPIECE before
// followOp. C++ parity: SplitDatatype::buildInSubpieces.
func (sd *SplitDatatype) buildInSubpieces(rootVn *Varnode, followOp *PcodeOp) []*Varnode {
	if out, ok := sd.generateConstants(rootVn); ok {
		return out
	}
	baseAddr := rootVn.Addr()
	out := make([]*Varnode, 0, len(sd.pieces))
	for _, piece := range sd.pieces {
		dt := piece.inType
		off := piece.offset
		addr := baseAddr.Add(uint64(off))
		addr.Renormalize(dt.Size())
		if addr.Space != nil && addr.Space.BigEndian {
			off = rootVn.Size() - off - dt.Size()
		}
		subpiece := sd.data.NewOp(2, followOp.Addr())
		sd.data.OpSetOpcode(subpiece, CPUI_SUBPIECE)
		sd.data.OpSetInput(subpiece, rootVn, 0)
		sd.data.OpSetInput(subpiece, sd.data.NewConstant(4, uint64(off)), 1)
		outVn := sd.data.NewVarnodeOut(dt.Size(), addr, subpiece)
		outVn.UpdateType(dt)
		out = append(out, outVn)
		sd.data.OpInsertBefore(subpiece, followOp)
	}
	return out
}

// buildOutVarnodes creates the output pieces in the root's storage.
// C++ parity: SplitDatatype::buildOutVarnodes.
func (sd *SplitDatatype) buildOutVarnodes(rootVn *Varnode) []*Varnode {
	baseAddr := rootVn.Addr()
	out := make([]*Varnode, 0, len(sd.pieces))
	for _, piece := range sd.pieces {
		dt := piece.outType
		addr := baseAddr.Add(uint64(piece.offset))
		addr.Renormalize(dt.Size())
		vn := sd.data.NewVarnode(dt.Size(), addr)
		SetVarnodeType(vn, dt)
		out = append(out, vn)
	}
	return out
}

// buildOutConcats rebuilds the root from the output pieces with a PIECE
// tree inserted after previousOp, most significant first.
// C++ parity: SplitDatatype::buildOutConcats.
func (sd *SplitDatatype) buildOutConcats(rootVn *Varnode, previousOp *PcodeOp, outVarnodes []*Varnode) {
	if rootVn.HasNoDescend() {
		return // Don't need to produce concatenation if its unused
	}
	baseAddr := rootVn.Addr()
	preOp := previousOp
	addressTied := rootVn.IsAddrTied()
	if !addressTied {
		for _, vn := range outVarnodes {
			vn.SetFlags(VarnodeProtoPartial)
		}
	}
	var concatOp *PcodeOp
	newConcat := func(hi, lo *Varnode) {
		concatOp = sd.data.NewOp(2, previousOp.Addr())
		sd.data.OpSetOpcode(concatOp, CPUI_PIECE)
		sd.data.OpSetInput(concatOp, hi, 0) // Most significant
		sd.data.OpSetInput(concatOp, lo, 1) // Least significant
		sd.data.OpInsertAfter(concatOp, preOp)
	}
	if baseAddr.Space != nil && baseAddr.Space.BigEndian {
		vn := outVarnodes[0]
		for i := 1; ; i++ {
			newConcat(vn, outVarnodes[i])
			if i+1 >= len(outVarnodes) {
				break
			}
			preOp = concatOp
			sz := vn.Size() + outVarnodes[i].Size()
			addr := baseAddr
			addr.Renormalize(sz)
			vn = sd.data.NewVarnodeOut(sz, addr, concatOp)
			if !addressTied {
				vn.SetFlags(VarnodeProtoPartial)
			}
		}
	} else {
		vn := outVarnodes[len(outVarnodes)-1]
		for i := len(outVarnodes) - 2; ; i-- {
			newConcat(vn, outVarnodes[i])
			if i <= 0 {
				break
			}
			preOp = concatOp
			sz := vn.Size() + outVarnodes[i].Size()
			addr := outVarnodes[i].Addr()
			addr.Renormalize(sz)
			vn = sd.data.NewVarnodeOut(sz, addr, concatOp)
			if !addressTied {
				vn.SetFlags(VarnodeProtoPartial)
			}
		}
	}
	concatOp.addlFlags |= PcodeOpConcatRoot
	sd.data.OpSetOutput(concatOp, rootVn)
	if !addressTied {
		sd.data.protoPartial = append(sd.data.protoPartial, concatOp) // Merge::registerProtoPartialRoot
	}
}

// buildPointers builds a PTRSUB/PTRADD chain from the root pointer to each
// piece, inserted before followOp.
// C++ parity: SplitDatatype::buildPointers.
func (sd *SplitDatatype) buildPointers(rootVn *Varnode, ptrType splitPointerType, baseOffset int32, followOp *PcodeOp, isInput bool) []*Varnode {
	baseType := ptrType.Pointee()
	out := make([]*Varnode, 0, len(sd.pieces))
	for _, piece := range sd.pieces {
		matchType := piece.outType
		if isInput {
			matchType = piece.inType
		}
		curOff := int64(baseOffset + piece.offset)
		tmpType := baseType
		inPtr := rootVn
		for {
			var newOff int64
			var newType Datatype
			if curOff < 0 || curOff >= int64(tmpType.Size()) { // An offset outside the data-type indicates an array
				newType = tmpType
				newOff = curOff % int64(tmpType.Size())
				if newOff < 0 {
					newOff += int64(tmpType.Size())
				}
			} else {
				newType, newOff = datatypeSubType(tmpType, curOff)
				if newType == nil { // A hole in a structure: use the precomputed data-type
					newType = matchType
					newOff = 0
				}
			}
			var newOp *PcodeOp
			if tmpType == newType || tmpType.Metatype() == TYPE_ARRAY {
				sz := int64(newType.Size()) // Element size in bytes
				finalOffset := (curOff - newOff) / sz
				sz = sz / splitWordSize(ptrType)
				newOp = sd.data.NewOp(3, followOp.Addr())
				sd.data.OpSetOpcode(newOp, CPUI_PTRADD)
				sd.data.OpSetInput(newOp, inPtr, 0)
				indexVn := sd.data.NewConstant(inPtr.Size(), uint64(finalOffset)&maskForSize(inPtr.Size()))
				sd.data.OpSetInput(newOp, indexVn, 1)
				sd.data.OpSetInput(newOp, sd.data.NewConstant(inPtr.Size(), uint64(sz)), 2)
				indexVn.UpdateType(sd.types.GetBase(indexVn.Size(), TYPE_INT, ""))
			} else {
				finalOffset := (curOff - newOff) / splitWordSize(ptrType)
				newOp = sd.data.NewOp(2, followOp.Addr())
				sd.data.OpSetOpcode(newOp, CPUI_PTRSUB)
				sd.data.OpSetInput(newOp, inPtr, 0)
				sd.data.OpSetInput(newOp, sd.data.NewConstant(inPtr.Size(), uint64(finalOffset)&maskForSize(inPtr.Size())), 1)
			}
			inPtr = sd.data.NewUniqueOut(inPtr.Size(), newOp)
			inPtr.UpdateType(sd.types.GetPointerStripArray(ptrType.Size(), newType, ptrType.WordSize()))
			sd.data.OpInsertBefore(newOp, followOp)
			tmpType = newType
			curOff = newOff
			if tmpType.Size() <= matchType.Size() {
				break
			}
		}
		out = append(out, inPtr)
	}
	return out
}

// splitWordSize is the pointer's word size (bytes per address unit).
func splitWordSize(p splitPointerType) int64 {
	if ws := p.WordSize(); ws > 1 {
		return int64(ws)
	}
	return 1
}

// isArithmeticOpcode reports TypeOp::isArithmeticOp (the arithmetic_op flag).
func isArithmeticOpcode(opc OpCode) bool {
	switch opc {
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW, CPUI_INT_2COMP,
		CPUI_INT_MULT, CPUI_INT_DIV, CPUI_INT_SDIV, CPUI_INT_REM, CPUI_INT_SREM, CPUI_PTRADD, CPUI_PTRSUB:
		return true
	}
	return false
}

// isArithmeticInput: some descendant of vn is arithmetic.
// C++ parity: SplitDatatype::isArithmeticInput.
func splitIsArithmeticInput(vn *Varnode) bool {
	for _, op := range vn.DescendIter() {
		if isArithmeticOpcode(op.Code()) {
			return true
		}
	}
	return false
}

// isArithmeticOutput: vn is defined by an arithmetic op.
// C++ parity: SplitDatatype::isArithmeticOutput.
func splitIsArithmeticOutput(vn *Varnode) bool {
	return vn.IsWritten() && isArithmeticOpcode(vn.Def().Code())
}

// newSpaceLike builds a LOAD/STORE space-id constant equal to orig.
// C++ parity: Funcdata::newVarnodeSpace(getSpaceFromConst()).
func (sd *SplitDatatype) newSpaceLike(orig *Varnode) *Varnode {
	vn := sd.data.NewConstant(orig.Size(), orig.Offset())
	BindSpaceConstant(vn, orig.GetSpaceFromConst())
	return vn
}

// splitCopy splits a COPY by the input and output data-types.
// C++ parity: SplitDatatype::splitCopy.
func (sd *SplitDatatype) splitCopy(copyOp *PcodeOp, inType, outType Datatype) bool {
	if !sd.testCopyConstraints(copyOp) {
		return false
	}
	inVn := copyOp.Input(0)
	if !sd.testDatatypeCompatibility(inType, outType, inVn.IsConstant()) {
		return false
	}
	if splitIsArithmeticOutput(inVn) { // Sanity check on input
		return false
	}
	outVn := copyOp.Output()
	if splitIsArithmeticInput(outVn) { // Sanity check on output
		return false
	}
	var inVarnodes []*Varnode
	if inVn.IsConstant() {
		inVarnodes = sd.buildInConstants(inVn, outVn.Space() != nil && outVn.Space().BigEndian)
	} else {
		inVarnodes = sd.buildInSubpieces(inVn, copyOp)
	}
	outVarnodes := sd.buildOutVarnodes(outVn)
	sd.buildOutConcats(outVn, copyOp, outVarnodes)
	for i := range inVarnodes {
		newCopyOp := sd.data.NewOp(1, copyOp.Addr())
		sd.data.OpSetOpcode(newCopyOp, CPUI_COPY)
		sd.data.OpSetInput(newCopyOp, inVarnodes[i], 0)
		sd.data.OpSetOutput(newCopyOp, outVarnodes[i])
		sd.data.OpInsertBefore(newCopyOp, copyOp)
	}
	sd.data.OpDestroy(copyOp)
	return true
}

// splitLoad splits a LOAD (and a lone COPY of its output) by inType.
// C++ parity: SplitDatatype::splitLoad.
func (sd *SplitDatatype) splitLoad(loadOp *PcodeOp, inType Datatype) bool {
	sd.isLoadStore = true
	outVn := loadOp.Output()
	var copyOp *PcodeOp
	if !outVn.IsAddrTied() {
		copyOp = outVn.LoneDescend()
	}
	if copyOp != nil {
		switch copyOp.Code() {
		case CPUI_STORE:
			return false // Handled by RuleSplitStore
		case CPUI_ZPULL, CPUI_SPULL:
			return false
		case CPUI_COPY:
		default:
			copyOp = nil
		}
	}
	if copyOp != nil {
		outVn = copyOp.Output()
	}
	outType := outVn.TypeDefFacing()
	if !sd.testDatatypeCompatibility(inType, outType, false) {
		return false
	}
	if splitIsArithmeticInput(outVn) { // Sanity check on output
		return false
	}
	var root splitRootPointer
	if !root.find(loadOp, inType) {
		return false
	}
	insertPoint := loadOp
	if copyOp != nil {
		insertPoint = copyOp
	}
	ptrVarnodes := sd.buildPointers(root.pointer, root.ptrType, root.baseOffset, loadOp, true)
	outVarnodes := sd.buildOutVarnodes(outVn)
	sd.buildOutConcats(outVn, insertPoint, outVarnodes)
	for i := range ptrVarnodes {
		newLoadOp := sd.data.NewOp(2, insertPoint.Addr())
		sd.data.OpSetOpcode(newLoadOp, CPUI_LOAD)
		sd.data.OpSetInput(newLoadOp, sd.newSpaceLike(loadOp.Input(0)), 0)
		sd.data.OpSetInput(newLoadOp, ptrVarnodes[i], 1)
		sd.data.OpSetOutput(newLoadOp, outVarnodes[i])
		sd.data.OpInsertBefore(newLoadOp, insertPoint)
	}
	if copyOp != nil {
		sd.data.OpDestroy(copyOp)
	}
	sd.data.OpDestroy(loadOp)
	root.freePointerChain(sd.data)
	return true
}

// splitStore splits a STORE (and a lone LOAD feeding it) by outType.
// C++ parity: SplitDatatype::splitStore.
func (sd *SplitDatatype) splitStore(storeOp *PcodeOp, outType Datatype) bool {
	sd.isLoadStore = true
	inVn := storeOp.Input(2)
	var loadOp *PcodeOp
	var inType Datatype
	if inVn.IsWritten() && inVn.Def().Code() == CPUI_LOAD && inVn.LoneDescend() == storeOp {
		loadOp = inVn.Def()
		inType = splitValueDatatype(loadOp, inVn.Size(), sd.types)
		if inType == nil {
			loadOp = nil
		}
	}
	if inType == nil {
		inType = inVn.TypeReadFacing(storeOp)
	}
	if !sd.testDatatypeCompatibility(inType, outType, inVn.IsConstant()) {
		if loadOp == nil {
			return false
		}
		// Not compatible while considering the LOAD: check again without it
		loadOp = nil
		inType = inVn.TypeReadFacing(storeOp)
		sd.pieces = nil
		if !sd.testDatatypeCompatibility(inType, outType, inVn.IsConstant()) {
			return false
		}
	}
	if splitIsArithmeticOutput(inVn) { // Sanity check
		return false
	}
	var storeRoot splitRootPointer
	if !storeRoot.find(storeOp, outType) {
		return false
	}
	var loadRoot splitRootPointer
	if loadOp != nil && !loadRoot.find(loadOp, inType) {
		return false
	}
	storeSpace := storeOp.Input(0)
	var inVarnodes []*Varnode
	switch {
	case inVn.IsConstant():
		spc := storeSpace.GetSpaceFromConst()
		inVarnodes = sd.buildInConstants(inVn, spc != nil && spc.BigEndian)
	case loadOp != nil:
		loadPtrs := sd.buildPointers(loadRoot.pointer, loadRoot.ptrType, loadRoot.baseOffset, loadOp, true)
		for i, ptr := range loadPtrs {
			newLoadOp := sd.data.NewOp(2, loadOp.Addr())
			sd.data.OpSetOpcode(newLoadOp, CPUI_LOAD)
			sd.data.OpSetInput(newLoadOp, sd.newSpaceLike(loadOp.Input(0)), 0)
			sd.data.OpSetInput(newLoadOp, ptr, 1)
			dt := sd.pieces[i].inType
			vn := sd.data.NewUniqueOut(dt.Size(), newLoadOp)
			vn.UpdateType(dt)
			inVarnodes = append(inVarnodes, vn)
			sd.data.OpInsertBefore(newLoadOp, loadOp)
		}
	default:
		inVarnodes = sd.buildInSubpieces(inVn, storeOp)
	}
	if storeRoot.pointer.IsAddrTied() {
		storeRoot.duplicateToTemp(sd.data, storeOp)
	}
	storePtrs := sd.buildPointers(storeRoot.pointer, storeRoot.ptrType, storeRoot.baseOffset, storeOp, false)
	// Keep the original STORE (INDIRECT references stay valid) as the first piece
	sd.data.OpSetInput(storeOp, storePtrs[0], 1)
	sd.data.OpSetInput(storeOp, inVarnodes[0], 2)
	lastStore := storeOp
	for i := 1; i < len(storePtrs); i++ {
		newStoreOp := sd.data.NewOp(3, storeOp.Addr())
		sd.data.OpSetOpcode(newStoreOp, CPUI_STORE)
		sd.data.OpSetInput(newStoreOp, sd.newSpaceLike(storeSpace), 0)
		sd.data.OpSetInput(newStoreOp, storePtrs[i], 1)
		sd.data.OpSetInput(newStoreOp, inVarnodes[i], 2)
		sd.data.OpInsertAfter(newStoreOp, lastStore)
		lastStore = newStoreOp
	}
	if loadOp != nil {
		sd.data.OpDestroy(loadOp)
		loadRoot.freePointerChain(sd.data)
	}
	storeRoot.freePointerChain(sd.data)
	return true
}

// splitValueDatatype describes the value a LOAD/STORE moves at the given
// size, as an array of a primitive pointee or an exact piece of a
// structure/array pointee; nil if not splittable.
// C++ parity: SplitDatatype::getValueDatatype.
func splitValueDatatype(loadStore *PcodeOp, size int32, tlst *TypeFactory) Datatype {
	var resType Datatype
	var baseOffset int64
	switch p := loadStore.Input(1).TypeReadFacing(loadStore).(type) {
	case *PointerRel:
		resType = p.Parent()
		baseOffset = int64(p.ByteOffset())
	case *Pointer:
		resType = p.Pointee()
	default:
		return nil
	}
	if resType == nil {
		return nil
	}
	metain := resType.Metatype()
	if resType.AlignSize() < size {
		switch metain {
		case TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR:
			if align := resType.AlignSize(); align > 0 && size%align == 0 {
				return tlst.GetArray(size/align, resType)
			}
		}
	} else if metain == TYPE_STRUCT || metain == TYPE_ARRAY {
		return tlst.exactPiece(resType, baseOffset, size)
	}
	return nil
}
