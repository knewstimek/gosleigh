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
	"sort"
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

// SplitDatatype::SplitDatatype -- subflow.cc.
type splitDatatypePiece struct {
	inType  Datatype
	outType Datatype
	offset  int32
}

// SplitDatatype::SplitDatatype -- subflow.cc.
type SplitDatatype struct {
	data            *Funcdata
	types           *TypeFactory
	pieces          []splitDatatypePiece
	splitStructures bool
	splitArrays     bool
	isLoadStore     bool
}

// SplitDatatype::SplitDatatype -- subflow.cc.
func NewSplitDatatype(funcdata *Funcdata) *SplitDatatype {
	return &SplitDatatype{
		data:            funcdata,
		types:           sharedTypeFactory,
		splitStructures: true,
		splitArrays:     true,
	}
}

// SplitDatatype::getValueDatatype -- subflow.cc.
func (sd *SplitDatatype) getValueDatatype(loadStore *PcodeOp, size int32, tlst *TypeFactory) Datatype {
	if loadStore == nil || loadStore.NumInput() < 2 || loadStore.Input(1) == nil || tlst == nil {
		return nil
	}
	ptrType, ok := loadStore.Input(1).TypeReadFacing(loadStore).(*Pointer)
	if !ok || ptrType == nil {
		return nil
	}
	if ptrType.Pointee() == nil {
		return tlst.GetBase(size, TYPE_UNKNOWN, "unknown")
	}
	return ptrType.Pointee()
}

// SplitDatatype::testCopyConstraints -- subflow.cc.
func (sd *SplitDatatype) testCopyConstraints(copyOp *PcodeOp) bool {
	if copyOp == nil || copyOp.NumInput() == 0 || copyOp.Input(0) == nil {
		return false
	}
	inVn := copyOp.Input(0)
	if inVn.IsInput() {
		return false
	}
	if inVn.IsAddrTied() {
		outVn := copyOp.Output()
		if outVn != nil && outVn.IsAddrTied() && outVn.Addr() == inVn.Addr() {
			return false
		}
	} else if inVn.IsWritten() && inVn.Def() != nil && inVn.Def().Code() == CPUI_LOAD {
		if inVn.LoneDescend() == copyOp {
			return false
		}
	}
	return true
}

// SplitDatatype::testDatatypeCompatibility -- subflow.cc.
func (sd *SplitDatatype) testDatatypeCompatibility(inBase, outBase Datatype, inConstant bool) bool {
	if inBase == nil || outBase == nil {
		return false
	}
	if inBase.Size() != outBase.Size() {
		return false
	}
	if inConstant {
		return true
	}
	if inBase.Metatype() == outBase.Metatype() {
		return true
	}
	switch inBase.Metatype() {
	case TYPE_STRUCT, TYPE_ARRAY:
		return outBase.Metatype() == TYPE_STRUCT || outBase.Metatype() == TYPE_ARRAY
	}
	switch outBase.Metatype() {
	case TYPE_STRUCT, TYPE_ARRAY:
		return true
	}
	return false
}

// SplitDatatype::categorizeDatatype -- subflow.cc.
func (sd *SplitDatatype) categorizeDatatype(ct Datatype) int {
	if ct == nil {
		return -1
	}
	switch ct.Metatype() {
	case TYPE_ARRAY:
		if !sd.splitArrays {
			return -1
		}
		return 1
	case TYPE_STRUCT:
		if !sd.splitStructures {
			return -1
		}
		return 0
	default:
		return -1
	}
}

// SplitDatatype::getPieces -- subflow.cc.
func (sd *SplitDatatype) getPieces(dt Datatype) []splitDatatypePiece {
	if dt == nil || dt.Size() <= 0 {
		return nil
	}
	pieces := make([]splitDatatypePiece, 0, 4)
	var flatten func(base Datatype, offset int32, outType Datatype)
	flatten = func(base Datatype, offset int32, outType Datatype) {
		if base == nil || base.Size() <= 0 {
			return
		}
		switch typed := base.(type) {
		case *Struct:
			fields := typed.Fields()
			sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })
			cur := int32(0)
			for _, field := range fields {
				if field.Type == nil {
					continue
				}
				if field.Offset > cur {
					gap := field.Offset - cur
					pieces = append(pieces, splitDatatypePiece{
						inType:  sd.types.GetBase(gap, TYPE_UNKNOWN, "unknown"),
						outType: sd.types.GetBase(gap, TYPE_UNKNOWN, "unknown"),
						offset:  offset + cur,
					})
				}
				flatten(field.Type, offset+field.Offset, field.Type)
				cur = field.End()
			}
			if cur < typed.Size() {
				gap := typed.Size() - cur
				pieces = append(pieces, splitDatatypePiece{
					inType:  sd.types.GetBase(gap, TYPE_UNKNOWN, "unknown"),
					outType: sd.types.GetBase(gap, TYPE_UNKNOWN, "unknown"),
					offset:  offset + cur,
				})
			}
		case *Array:
			elem := typed.Element()
			if elem == nil {
				pieces = append(pieces, splitDatatypePiece{inType: dt, outType: outType, offset: offset})
				return
			}
			stride := elem.Size()
			if stride <= 0 {
				stride = elem.AlignSize()
			}
			if stride <= 0 {
				stride = 1
			}
			for i := int32(0); i < typed.Count(); i++ {
				flatten(elem, offset+i*stride, elem)
			}
		case *Union:
			pieces = append(pieces, splitDatatypePiece{inType: dt, outType: outType, offset: offset})
		default:
			pieces = append(pieces, splitDatatypePiece{inType: dt, outType: outType, offset: offset})
		}
	}
	flatten(dt, 0, dt)
	return pieces
}

// SplitDatatype::buildInConstants -- subflow.cc.
func (sd *SplitDatatype) buildInConstants(rootVn *Varnode, pieces []splitDatatypePiece, bigEndian bool) []*Varnode {
	out := make([]*Varnode, 0, len(pieces))
	baseVal := rootVn.Offset()
	for _, piece := range pieces {
		off := piece.offset
		if bigEndian {
			off = rootVn.Size() - off - piece.inType.Size()
		}
		val := (baseVal >> uint(8*off)) & maskForSize(piece.inType.Size())
		vn := sd.data.NewConstant(piece.inType.Size(), val)
		SetVarnodeType(vn, piece.inType)
		out = append(out, vn)
	}
	return out
}

// SplitDatatype::buildInSubpieces -- subflow.cc.
func (sd *SplitDatatype) buildInSubpieces(rootVn *Varnode, followOp *PcodeOp, pieces []splitDatatypePiece) []*Varnode {
	out := make([]*Varnode, 0, len(pieces))
	for _, piece := range pieces {
		off := piece.offset
		if rootVn.Space() != nil && rootVn.Space().BigEndian {
			off = rootVn.Size() - off - piece.inType.Size()
		}
		subpiece := sd.data.NewOpBefore(followOp, CPUI_SUBPIECE, rootVn)
		sd.data.OpSetOpcode(subpiece, CPUI_SUBPIECE)
		sd.data.OpSetInput(subpiece, rootVn, 0)
		sd.data.OpSetInput(subpiece, sd.data.NewConstant(4, uint64(off)), 1)
		vn := sd.data.NewUniqueOut(piece.inType.Size(), subpiece)
		SetVarnodeType(vn, piece.inType)
		out = append(out, vn)
	}
	return out
}

// SplitDatatype::buildOutVarnodes -- subflow.cc.
func (sd *SplitDatatype) buildOutVarnodes(rootVn *Varnode, pieces []splitDatatypePiece) []*Varnode {
	out := make([]*Varnode, 0, len(pieces))
	for _, piece := range pieces {
		off := piece.offset
		if rootVn.Space() != nil && rootVn.Space().BigEndian {
			off = rootVn.Size() - off - piece.outType.Size()
		}
		addr := rootVn.Addr().Add(uint64(off))
		addr.Renormalize(piece.outType.Size())
		vn := sd.data.NewVarnode(piece.outType.Size(), addr)
		SetVarnodeType(vn, piece.outType)
		out = append(out, vn)
	}
	return out
}

// SplitDatatype::buildOutConcats -- subflow.cc.
func (sd *SplitDatatype) buildOutConcats(rootVn *Varnode, previousOp *PcodeOp, outVarnodes []*Varnode, pieces []splitDatatypePiece) {
	if len(outVarnodes) == 0 {
		return
	}
	if len(outVarnodes) == 1 {
		return
	}
	cur := outVarnodes[len(outVarnodes)-1]
	curSize := cur.Size()
	for i := len(outVarnodes) - 2; i >= 0; i-- {
		concat := sd.data.NewOpBefore(previousOp, CPUI_PIECE, cur, outVarnodes[i])
		curSize += outVarnodes[i].Size()
		if i == 0 {
			sd.data.OpSetOutput(concat, rootVn)
			SetVarnodeType(rootVn, outVarnodes[i].TypeReadFacing(concat))
			return
		}
		tmp := sd.data.NewUniqueOut(curSize, concat)
		if len(pieces) > 0 && pieces[i].outType != nil {
			SetVarnodeType(tmp, pieces[i].outType)
		}
		cur = tmp
	}
}

// SplitDatatype::buildPointers -- subflow.cc.
func (sd *SplitDatatype) buildPointers(rootVn *Varnode, ptrType *Pointer, baseOffset int32, followOp *PcodeOp, ptrVarnodes []*Varnode, pieces []splitDatatypePiece, isInput bool) []*Varnode {
	out := make([]*Varnode, 0, len(pieces))
	for _, piece := range pieces {
		pieceOff := baseOffset + piece.offset
		curPtr := rootVn
		if pieceOff != 0 {
			subType := pointerSubtypeType(ptrType, piece.inType)
			ptrOp := sd.data.NewTypedOpBefore(followOp, CPUI_PTRSUB, rootVn.Size(), subType, rootVn, sd.data.NewConstant(rootVn.Size(), uint64(pieceOff)))
			curPtr = ptrOp.Output()
		}
		if isInput {
			out = append(out, curPtr)
		} else {
			vn := sd.data.NewUniqueOut(rootVn.Size(), sd.data.NewOpBefore(followOp, CPUI_COPY, curPtr))
			out = append(out, vn)
		}
		_ = ptrVarnodes
	}
	return out
}

// SplitDatatype::splitCopy -- subflow.cc.
func (sd *SplitDatatype) splitCopy(copyOp *PcodeOp, inType, outType Datatype) bool {
	if !sd.testCopyConstraints(copyOp) {
		return false
	}
	if !sd.testDatatypeCompatibility(inType, outType, copyOp.Input(0).IsConstant()) {
		return false
	}
	pieces := sd.getPieces(inType)
	if len(pieces) <= 1 {
		return false
	}
	if len(pieces) != len(sd.getPieces(outType)) {
		return false
	}
	inVn := copyOp.Input(0)
	outVn := copyOp.Output()
	if outVn == nil {
		return false
	}
	inPieces := make([]*Varnode, 0, len(pieces))
	if inVn.IsConstant() {
		inPieces = sd.buildInConstants(inVn, pieces, outVn.Space() != nil && outVn.Space().BigEndian)
	} else {
		inPieces = sd.buildInSubpieces(inVn, copyOp, pieces)
	}
	outPieces := sd.buildOutVarnodes(outVn, pieces)
	for i := range pieces {
		newCopy := sd.data.NewOpBefore(copyOp, CPUI_COPY, inPieces[i])
		sd.data.OpSetOpcode(newCopy, CPUI_COPY)
		sd.data.OpSetInput(newCopy, inPieces[i], 0)
		sd.data.OpSetOutput(newCopy, outPieces[i])
	}
	sd.buildOutConcats(outVn, copyOp, outPieces, pieces)
	sd.data.OpDestroy(copyOp)
	return true
}

// SplitDatatype::splitLoad -- subflow.cc.
func (sd *SplitDatatype) splitLoad(loadOp *PcodeOp, inType Datatype) bool {
	sd.isLoadStore = true
	outVn := loadOp.Output()
	if outVn == nil {
		return false
	}
	pieces := sd.getPieces(inType)
	if len(pieces) <= 1 {
		return false
	}
	ptr, _ := loadOp.Input(1).TypeReadFacing(loadOp).(*Pointer)
	if ptr == nil {
		return false
	}
	spaceConst := loadOp.Input(0)
	for i, piece := range pieces {
		piecePtr := loadOp.Input(1)
		if piece.offset != 0 {
			subType := pointerSubtypeType(ptr, piece.inType)
			ptrOp := sd.data.NewTypedOpBefore(loadOp, CPUI_PTRSUB, piecePtr.Size(), subType, piecePtr, sd.data.NewConstant(piecePtr.Size(), uint64(piece.offset)))
			piecePtr = ptrOp.Output()
		}
		newLoadOp := sd.data.NewOpBefore(loadOp, CPUI_LOAD, spaceConst, piecePtr)
		sd.data.OpSetOpcode(newLoadOp, CPUI_LOAD)
		sd.data.OpSetInput(newLoadOp, spaceConst, 0)
		sd.data.OpSetInput(newLoadOp, piecePtr, 1)
		outOff := piece.offset
		if outVn.Space() != nil && outVn.Space().BigEndian {
			outOff = outVn.Size() - outOff - piece.outType.Size()
		}
		outAddr := outVn.Addr().Add(uint64(outOff))
		outAddr.Renormalize(piece.outType.Size())
		outPiece := sd.data.NewVarnodeOut(piece.outType.Size(), outAddr, newLoadOp)
		SetVarnodeType(outPiece, piece.outType)
		if i == len(pieces)-1 {
			SetVarnodeType(outVn, outVn.TypeReadFacing(loadOp))
		}
	}
	if loadOp.Output() != nil {
		sd.data.OpDestroy(loadOp)
	}
	return true
}

// SplitDatatype::splitStore -- subflow.cc.
func (sd *SplitDatatype) splitStore(storeOp *PcodeOp, outType Datatype) bool {
	sd.isLoadStore = true
	if storeOp.NumInput() < 3 {
		return false
	}
	inVn := storeOp.Input(2)
	pieces := sd.getPieces(outType)
	if len(pieces) <= 1 {
		return false
	}
	ptr, _ := storeOp.Input(1).TypeReadFacing(storeOp).(*Pointer)
	if ptr == nil {
		return false
	}
	spaceConst := storeOp.Input(0)
	for _, piece := range pieces {
		piecePtr := storeOp.Input(1)
		if piece.offset != 0 {
			subType := pointerSubtypeType(ptr, piece.outType)
			ptrOp := sd.data.NewTypedOpBefore(storeOp, CPUI_PTRSUB, piecePtr.Size(), subType, piecePtr, sd.data.NewConstant(piecePtr.Size(), uint64(piece.offset)))
			piecePtr = ptrOp.Output()
		}
		pieceVn := inVn
		if !inVn.IsConstant() {
			if piece.offset != 0 || piece.outType.Size() != inVn.Size() {
				sub := sd.data.NewOpBefore(storeOp, CPUI_SUBPIECE, inVn)
				sd.data.OpSetOpcode(sub, CPUI_SUBPIECE)
				sd.data.OpSetInput(sub, inVn, 0)
				sd.data.OpSetInput(sub, sd.data.NewConstant(4, uint64(piece.offset)), 1)
				pieceVn = sd.data.NewUniqueOut(piece.outType.Size(), sub)
				SetVarnodeType(pieceVn, piece.outType)
			}
		} else {
			off := piece.offset
			if inVn.Space() != nil && inVn.Space().BigEndian {
				off = inVn.Size() - off - piece.outType.Size()
			}
			val := (inVn.Offset() >> uint(8*off)) & maskForSize(piece.outType.Size())
			pieceVn = sd.data.NewConstant(piece.outType.Size(), val)
		}
		newStore := sd.data.NewOpBefore(storeOp, CPUI_STORE, spaceConst, piecePtr, pieceVn)
		sd.data.OpSetOpcode(newStore, CPUI_STORE)
		sd.data.OpSetInput(newStore, spaceConst, 0)
		sd.data.OpSetInput(newStore, piecePtr, 1)
		sd.data.OpSetInput(newStore, pieceVn, 2)
	}
	sd.data.OpDestroy(storeOp)
	return true
}
