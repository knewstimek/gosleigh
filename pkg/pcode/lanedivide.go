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

// laneWork is a split Varnode still to be traced.
type laneWork struct {
	lanes     []*TransformVar
	numLanes  int32
	skipLanes int32
}

// LaneDivide splits a large Varnode (a vector register or any storage of a
// laned size) and the data-flow around it into independent lanes.
// C++ parity: subflow.hh/subflow.cc class LaneDivide.
type LaneDivide struct {
	*TransformManager
	description            *LaneDescription
	workList               []laneWork
	allowSubpieceTerminator bool
}

// NewLaneDivide seeds the trace with root split per desc.
// C++ parity: LaneDivide::LaneDivide.
func NewLaneDivide(f *Funcdata, root *Varnode, desc *LaneDescription, allowDowncast bool) *LaneDivide {
	ld := &LaneDivide{TransformManager: NewTransformManager(f), description: desc, allowSubpieceTerminator: allowDowncast}
	ld.setReplacement(root, desc.GetNumLanes(), 0)
	return ld
}

// setReplacement finds or builds the lane placeholders for vn and queues it
// for tracing. Returns nil when vn must not be split.
// C++ parity: LaneDivide::setReplacement.
func (ld *LaneDivide) setReplacement(vn *Varnode, numLanes, skipLanes int32) []*TransformVar {
	if vn.IsMark() {
		return ld.GetSplitRange(vn, ld.description, numLanes, skipLanes)
	}
	if vn.IsConstant() {
		return ld.NewSplitRange(vn, ld.description, numLanes, skipLanes)
	}
	if vn.IsTypeLock() {
		meta := vn.Type().Metatype()
		if meta > TYPE_ARRAY || meta == TYPE_STRUCT || meta == TYPE_UNION {
			return nil // a primitive or composite locked type is not split
		}
	}
	vn.SetMark()
	res := ld.NewSplitRange(vn, ld.description, numLanes, skipLanes)
	if !vn.IsFree() {
		ld.workList = append(ld.workList, laneWork{res, numLanes, skipLanes})
	}
	return res
}

func (ld *LaneDivide) buildUnaryOp(opc OpCode, op *PcodeOp, inVars, outVars []*TransformVar, numLanes int32) {
	for i := int32(0); i < numLanes; i++ {
		rop := ld.NewOpReplace(1, opc, op)
		ld.OpSetOutput(rop, outVars[i])
		ld.OpSetInput(rop, inVars[i], 0)
	}
}

func (ld *LaneDivide) buildBinaryOp(opc OpCode, op *PcodeOp, in0Vars, in1Vars, outVars []*TransformVar, numLanes int32) {
	for i := int32(0); i < numLanes; i++ {
		rop := ld.NewOpReplace(2, opc, op)
		ld.OpSetOutput(rop, outVars[i])
		ld.OpSetInput(rop, in0Vars[i], 0)
		ld.OpSetInput(rop, in1Vars[i], 1)
	}
}

// laneCopies emits one COPY per lane from in into out.
func (ld *LaneDivide) laneCopies(op *PcodeOp, in, out []*TransformVar, n int32) {
	for i := int32(0); i < n; i++ {
		rop := ld.NewOpReplace(1, CPUI_COPY, op)
		ld.OpSetInput(rop, in[i], 0)
		ld.OpSetOutput(rop, out[i])
	}
}

// zeroLane emits a COPY of zero into out.
func (ld *LaneDivide) zeroLane(op *PcodeOp, out *TransformVar, size int32) {
	rop := ld.NewOpReplace(1, CPUI_COPY, op)
	ld.OpSetOutput(rop, out)
	ld.OpSetInput(rop, ld.NewConstant(size, 0, 0), 0)
}

// C++ parity: LaneDivide::buildPiece.
func (ld *LaneDivide) buildPiece(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	highVn, lowVn := op.Input(0), op.Input(1)
	ok, highLanes, highSkip := ld.description.Restriction(numLanes, skipLanes, lowVn.Size(), highVn.Size())
	if !ok {
		return false
	}
	ok, lowLanes, lowSkip := ld.description.Restriction(numLanes, skipLanes, 0, lowVn.Size())
	if !ok {
		return false
	}
	if highLanes == 1 {
		rop := ld.NewOpReplace(1, CPUI_COPY, op)
		ld.OpSetInput(rop, ld.GetPreexistingVarnode(highVn), 0)
		ld.OpSetOutput(rop, outVars[numLanes-1])
	} else {
		highRvn := ld.setReplacement(highVn, highLanes, highSkip)
		if highRvn == nil {
			return false
		}
		ld.laneCopies(op, highRvn, outVars[numLanes-highLanes:], highLanes)
	}
	if lowLanes == 1 {
		rop := ld.NewOpReplace(1, CPUI_COPY, op)
		ld.OpSetInput(rop, ld.GetPreexistingVarnode(lowVn), 0)
		ld.OpSetOutput(rop, outVars[0])
	} else {
		lowRvn := ld.setReplacement(lowVn, lowLanes, lowSkip)
		if lowRvn == nil {
			return false
		}
		ld.laneCopies(op, lowRvn, outVars, lowLanes)
	}
	return true
}

// C++ parity: LaneDivide::buildMultiequal.
func (ld *LaneDivide) buildMultiequal(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	numInput := op.NumInput()
	inVarSets := make([][]*TransformVar, numInput)
	for i := 0; i < numInput; i++ {
		inVarSets[i] = ld.setReplacement(op.Input(i), numLanes, skipLanes)
		if inVarSets[i] == nil {
			return false
		}
	}
	for i := int32(0); i < numLanes; i++ {
		rop := ld.NewOpReplace(numInput, CPUI_MULTIEQUAL, op)
		ld.OpSetOutput(rop, outVars[i])
		for j := 0; j < numInput; j++ {
			ld.OpSetInput(rop, inVarSets[j][i], j)
		}
	}
	return true
}

// C++ parity: LaneDivide::buildIndirect.
func (ld *LaneDivide) buildIndirect(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	inVn := ld.setReplacement(op.Input(0), numLanes, skipLanes)
	if inVn == nil {
		return false
	}
	for i := int32(0); i < numLanes; i++ {
		rop := ld.NewOpReplace(2, CPUI_INDIRECT, op)
		ld.OpSetOutput(rop, outVars[i])
		ld.OpSetInput(rop, inVn[i], 0)
		ld.OpSetInput(rop, ld.NewIop(op.Input(1)), 1)
		rop.inheritIndirect(op)
	}
	return true
}

// lanePointer builds the pointer for the lane at bytePos off basePtr.
func (ld *LaneDivide) lanePointer(basePtr *TransformVar, ptrSize int32, bytePos int64, follow *TransformOp) *TransformVar {
	if bytePos == 0 {
		return basePtr
	}
	ptrVn := ld.NewUnique(ptrSize)
	addOp := ld.NewOp(2, CPUI_INT_ADD, follow)
	ld.OpSetOutput(addOp, ptrVn)
	ld.OpSetInput(addOp, basePtr, 0)
	ld.OpSetInput(addOp, ld.NewConstant(ptrSize, 0, uint64(bytePos)), 1)
	return ptrVn
}

// C++ parity: LaneDivide::buildStore.
func (ld *LaneDivide) buildStore(op *PcodeOp, numLanes, skipLanes int32) bool {
	inVars := ld.setReplacement(op.Input(2), numLanes, skipLanes)
	if inVars == nil {
		return false
	}
	spcVn := op.Input(0)
	spc := spcVn.GetSpaceFromConst()
	origPtr := op.Input(1)
	if origPtr.IsFree() && !origPtr.IsConstant() {
		return false
	}
	basePtr := ld.GetPreexistingVarnode(origPtr)
	ptrSize := origPtr.Size()
	bytePos := int64(0)
	for count := int32(0); count < numLanes; count++ {
		i := count
		if spc != nil && spc.BigEndian {
			i = numLanes - 1 - count
		}
		ropStore := ld.NewOpReplace(3, CPUI_STORE, op)
		ptrVn := ld.lanePointer(basePtr, ptrSize, bytePos, ropStore)
		ld.OpSetInput(ropStore, ld.NewSpaceConstant(spcVn), 0)
		ld.OpSetInput(ropStore, ptrVn, 1)
		ld.OpSetInput(ropStore, inVars[i], 2)
		bytePos += int64(ld.description.GetSize(skipLanes + i))
	}
	return true
}

// C++ parity: LaneDivide::buildLoad.
func (ld *LaneDivide) buildLoad(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	spcVn := op.Input(0)
	spc := spcVn.GetSpaceFromConst()
	origPtr := op.Input(1)
	if origPtr.IsFree() && !origPtr.IsConstant() {
		return false
	}
	basePtr := ld.GetPreexistingVarnode(origPtr)
	ptrSize := origPtr.Size()
	bytePos := int64(0)
	for count := int32(0); count < numLanes; count++ {
		ropLoad := ld.NewOpReplace(2, CPUI_LOAD, op)
		i := count
		if spc != nil && spc.BigEndian {
			i = numLanes - 1 - count
		}
		ptrVn := ld.lanePointer(basePtr, ptrSize, bytePos, ropLoad)
		ld.OpSetInput(ropLoad, ld.NewSpaceConstant(spcVn), 0)
		ld.OpSetInput(ropLoad, ptrVn, 1)
		ld.OpSetOutput(ropLoad, outVars[i])
		bytePos += int64(ld.description.GetSize(skipLanes + i))
	}
	return true
}

// C++ parity: LaneDivide::buildRightShift.
func (ld *LaneDivide) buildRightShift(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	if !op.Input(1).IsConstant() {
		return false
	}
	shiftSize := int32(op.Input(1).Offset())
	if shiftSize&7 != 0 {
		return false
	}
	startLane := ld.description.GetBoundary(shiftSize/8 + ld.description.GetPosition(skipLanes))
	if startLane < 0 {
		return false
	}
	for src, dest := startLane, skipLanes; src-skipLanes < numLanes; src, dest = src+1, dest+1 {
		if ld.description.GetSize(src) != ld.description.GetSize(dest) {
			return false
		}
	}
	inVars := ld.setReplacement(op.Input(0), numLanes, skipLanes)
	if inVars == nil {
		return false
	}
	moved := numLanes - (startLane - skipLanes)
	ld.buildUnaryOp(CPUI_COPY, op, inVars[startLane-skipLanes:], outVars, moved)
	for z := moved; z < numLanes; z++ {
		ld.zeroLane(op, outVars[z], ld.description.GetSize(z))
	}
	return true
}

// C++ parity: LaneDivide::buildLeftShift.
func (ld *LaneDivide) buildLeftShift(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	if !op.Input(1).IsConstant() {
		return false
	}
	shiftSize := int32(op.Input(1).Offset())
	if shiftSize&7 != 0 {
		return false
	}
	startLane := ld.description.GetBoundary(shiftSize/8 + ld.description.GetPosition(skipLanes))
	if startLane < 0 {
		return false
	}
	for dest, src := startLane, skipLanes; dest-skipLanes < numLanes; dest, src = dest+1, src+1 {
		if ld.description.GetSize(src) != ld.description.GetSize(dest) {
			return false
		}
	}
	inVars := ld.setReplacement(op.Input(0), numLanes, skipLanes)
	if inVars == nil {
		return false
	}
	for z := int32(0); z < startLane-skipLanes; z++ {
		ld.zeroLane(op, outVars[z], ld.description.GetSize(z))
	}
	ld.buildUnaryOp(CPUI_COPY, op, inVars, outVars[startLane-skipLanes:], numLanes-(startLane-skipLanes))
	return true
}

// C++ parity: LaneDivide::buildZext.
func (ld *LaneDivide) buildZext(op *PcodeOp, outVars []*TransformVar, numLanes, skipLanes int32) bool {
	invn := op.Input(0)
	ok, inLanes, inSkip := ld.description.Restriction(numLanes, skipLanes, 0, invn.Size())
	if !ok {
		return false
	}
	if inLanes == 1 {
		rop := ld.NewOpReplace(1, CPUI_COPY, op)
		ld.OpSetInput(rop, ld.GetPreexistingVarnode(invn), 0)
		ld.OpSetOutput(rop, outVars[0])
	} else {
		inRvn := ld.setReplacement(invn, inLanes, inSkip)
		if inRvn == nil {
			return false
		}
		ld.laneCopies(op, inRvn, outVars, inLanes)
	}
	for i := int32(0); i < numLanes-inLanes; i++ {
		ld.zeroLane(op, outVars[inLanes+i], ld.description.GetSize(skipLanes+inLanes+i))
	}
	return true
}

// traceForward pushes the lanes into every reader of rvn's Varnode.
// C++ parity: LaneDivide::traceForward.
func (ld *LaneDivide) traceForward(rvn []*TransformVar, numLanes, skipLanes int32) bool {
	origvn := rvn[0].GetOriginal()
	for _, op := range origvn.DescendIter() {
		outvn := op.Output()
		if outvn != nil && outvn.IsMark() {
			continue
		}
		switch op.Code() {
		case CPUI_SUBPIECE:
			bytePos := int32(op.Input(1).Offset())
			ok, outLanes, outSkip := ld.description.Restriction(numLanes, skipLanes, bytePos, outvn.Size())
			if !ok {
				if !ld.allowSubpieceTerminator {
					return false
				}
				laneIndex := ld.description.GetBoundary(bytePos)
				if laneIndex < 0 || laneIndex >= ld.description.GetNumLanes() {
					return false // piece does not start on a lane boundary
				}
				if ld.description.GetSize(laneIndex) <= outvn.Size() {
					return false
				}
				rop := ld.NewPreexistingOp(2, CPUI_SUBPIECE, op)
				ld.OpSetInput(rop, rvn[laneIndex-skipLanes], 0)
				ld.OpSetInput(rop, ld.NewConstant(4, 0, 0), 1)
				break
			}
			if outLanes == 1 {
				rop := ld.NewPreexistingOp(1, CPUI_COPY, op)
				ld.OpSetInput(rop, rvn[outSkip-skipLanes], 0)
			} else if ld.setReplacement(outvn, outLanes, outSkip) == nil {
				return false
			}
		case CPUI_PIECE:
			bytePos := int32(0)
			if op.Input(0) == origvn {
				bytePos = op.Input(1).Size()
			}
			ok, outLanes, outSkip := ld.description.Extension(numLanes, skipLanes, bytePos, outvn.Size())
			if !ok || ld.setReplacement(outvn, outLanes, outSkip) == nil {
				return false
			}
		case CPUI_COPY, CPUI_INT_NEGATE, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR, CPUI_MULTIEQUAL, CPUI_INDIRECT:
			if ld.setReplacement(outvn, numLanes, skipLanes) == nil {
				return false
			}
		case CPUI_INT_RIGHT:
			if !op.Input(1).IsConstant() || ld.setReplacement(outvn, numLanes, skipLanes) == nil {
				return false
			}
		case CPUI_STORE:
			if op.Input(2) != origvn || !ld.buildStore(op, numLanes, skipLanes) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// traceBackward pulls the lanes back through rvn's defining op.
// C++ parity: LaneDivide::traceBackward.
func (ld *LaneDivide) traceBackward(rvn []*TransformVar, numLanes, skipLanes int32) bool {
	op := rvn[0].GetOriginal().Def()
	if op == nil {
		return true // an input
	}
	switch op.Code() {
	case CPUI_INT_NEGATE, CPUI_COPY:
		inVars := ld.setReplacement(op.Input(0), numLanes, skipLanes)
		if inVars == nil {
			return false
		}
		ld.buildUnaryOp(op.Code(), op, inVars, rvn, numLanes)
	case CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_XOR:
		in0 := ld.setReplacement(op.Input(0), numLanes, skipLanes)
		if in0 == nil {
			return false
		}
		in1 := ld.setReplacement(op.Input(1), numLanes, skipLanes)
		if in1 == nil {
			return false
		}
		ld.buildBinaryOp(op.Code(), op, in0, in1, rvn, numLanes)
	case CPUI_MULTIEQUAL:
		return ld.buildMultiequal(op, rvn, numLanes, skipLanes)
	case CPUI_INDIRECT:
		return ld.buildIndirect(op, rvn, numLanes, skipLanes)
	case CPUI_SUBPIECE:
		inVn := op.Input(0)
		bytePos := int32(op.Input(1).Offset())
		ok, inLanes, inSkip := ld.description.Extension(numLanes, skipLanes, bytePos, inVn.Size())
		if !ok {
			return false
		}
		inVars := ld.setReplacement(inVn, inLanes, inSkip)
		if inVars == nil {
			return false
		}
		ld.buildUnaryOp(CPUI_COPY, op, inVars[skipLanes-inSkip:], rvn, numLanes)
	case CPUI_PIECE:
		return ld.buildPiece(op, rvn, numLanes, skipLanes)
	case CPUI_LOAD:
		return ld.buildLoad(op, rvn, numLanes, skipLanes)
	case CPUI_INT_RIGHT:
		return ld.buildRightShift(op, rvn, numLanes, skipLanes)
	case CPUI_INT_LEFT:
		return ld.buildLeftShift(op, rvn, numLanes, skipLanes)
	case CPUI_INT_ZEXT:
		return ld.buildZext(op, rvn, numLanes, skipLanes)
	default:
		return false
	}
	return true
}

// DoTrace pushes the lanes from the root as far as they go naturally.
// C++ parity: LaneDivide::doTrace.
func (ld *LaneDivide) DoTrace() bool {
	if len(ld.workList) == 0 {
		return false
	}
	retval := true
	for len(ld.workList) > 0 {
		w := ld.workList[len(ld.workList)-1]
		ld.workList = ld.workList[:len(ld.workList)-1]
		if !ld.traceBackward(w.lanes, w.numLanes, w.skipLanes) || !ld.traceForward(w.lanes, w.numLanes, w.skipLanes) {
			retval = false
			break
		}
	}
	ld.ClearVarnodeMarks()
	return retval
}
