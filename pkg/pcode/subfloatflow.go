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

// SubfloatFlow::State -- subflow.cc.
type subfloatFlowState struct {
	op           *PcodeOp
	slot         int32
	maxPrecision int32
}

// SubfloatFlow::State::incorporateInputSize -- subflow.cc.
func (s *subfloatFlowState) incorporateInputSize(sz int32) {
	if s == nil {
		return
	}
	if s.maxPrecision < sz {
		s.maxPrecision = sz
	}
}

// SubfloatFlow::SubfloatFlow -- subflow.cc.
type SubfloatFlow struct {
	*TransformManager
	precision       int32
	terminatorCount int32
	format          any // TODO known mismatch: FloatFormat lookup not yet implemented.
	worklist        []*TransformVar
	maxPrecisionMap map[*PcodeOp]int32
}

// SubfloatFlow::maxPrecision -- subflow.cc.
func (sf *SubfloatFlow) maxPrecision(vn *Varnode) int32 {
	if sf == nil || vn == nil {
		return 0
	}
	if !vn.IsWritten() {
		return vn.Size()
	}
	op := vn.Def()
	if op == nil {
		return vn.Size()
	}
	switch op.Code() {
	case CPUI_MULTIEQUAL,
		CPUI_FLOAT_NEG,
		CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT,
		CPUI_FLOAT_CEIL,
		CPUI_FLOAT_FLOOR,
		CPUI_FLOAT_ROUND,
		CPUI_COPY:
	case CPUI_FLOAT_ADD,
		CPUI_FLOAT_SUB,
		CPUI_FLOAT_MULT,
		CPUI_FLOAT_DIV:
		return 0
	case CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_INT2FLOAT:
		in0 := op.Input(0)
		if in0 == nil {
			return vn.Size()
		}
		if in0.Size() > vn.Size() {
			return vn.Size()
		}
		return in0.Size()
	default:
		return vn.Size()
	}

	if cached, ok := sf.maxPrecisionMap[op]; ok {
		return cached
	}
	maxPrecision := int32(0)
	stateStack := []*subfloatFlowState{{op: op, slot: 0, maxPrecision: 0}}
	seen := map[*PcodeOp]bool{op: true}
	for len(stateStack) > 0 {
		state := stateStack[len(stateStack)-1]
		if state.slot >= int32(state.op.NumInput()) {
			maxPrecision = state.maxPrecision
			delete(seen, state.op)
			sf.maxPrecisionMap[state.op] = maxPrecision
			stateStack = stateStack[:len(stateStack)-1]
			if len(stateStack) > 0 {
				stateStack[len(stateStack)-1].incorporateInputSize(maxPrecision)
			}
			continue
		}
		nextVn := state.op.Input(int(state.slot))
		state.slot++
		if nextVn == nil {
			continue
		}
		if !nextVn.IsWritten() {
			state.incorporateInputSize(nextVn.Size())
			continue
		}
		nextOp := nextVn.Def()
		if nextOp == nil {
			state.incorporateInputSize(nextVn.Size())
			continue
		}
		if seen[nextOp] {
			continue
		}
		switch nextOp.Code() {
		case CPUI_MULTIEQUAL,
			CPUI_FLOAT_NEG,
			CPUI_FLOAT_ABS,
			CPUI_FLOAT_SQRT,
			CPUI_FLOAT_CEIL,
			CPUI_FLOAT_FLOOR,
			CPUI_FLOAT_ROUND,
			CPUI_COPY:
			if cached, ok := sf.maxPrecisionMap[nextOp]; ok {
				state.incorporateInputSize(cached)
				continue
			}
			seen[nextOp] = true
			stateStack = append(stateStack, &subfloatFlowState{op: nextOp, slot: 0, maxPrecision: 0})
		case CPUI_FLOAT_ADD,
			CPUI_FLOAT_SUB,
			CPUI_FLOAT_MULT,
			CPUI_FLOAT_DIV:
			// Deliberately stop at binary float ops.
		case CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_INT2FLOAT:
			in0 := nextOp.Input(0)
			if in0 == nil {
				state.incorporateInputSize(nextVn.Size())
				continue
			}
			if in0.Size() > nextVn.Size() {
				state.incorporateInputSize(nextVn.Size())
			} else {
				state.incorporateInputSize(in0.Size())
			}
		default:
			state.incorporateInputSize(nextVn.Size())
		}
	}
	return maxPrecision
}

// SubfloatFlow::exceedsPrecision -- subflow.cc.
func (sf *SubfloatFlow) exceedsPrecision(op *PcodeOp) bool {
	if sf == nil || op == nil || op.NumInput() < 2 {
		return false
	}
	val1 := sf.maxPrecision(op.Input(0))
	val2 := sf.maxPrecision(op.Input(1))
	if val1 > val2 {
		return val2 > sf.precision
	}
	return val1 > sf.precision
}

// SubfloatFlow::setReplacement -- subflow.cc.
func (sf *SubfloatFlow) setReplacement(vn *Varnode) *TransformVar {
	if sf == nil || vn == nil {
		return nil
	}
	if vn.IsMark() {
		if vars, ok := sf.pieceMap[vn.CreateIndex()]; ok && len(vars) > 0 {
			return vars[0]
		}
		return nil
	}
	if vn.IsConstant() {
		if vn.Size() != sf.precision {
			return nil
		}
		return sf.NewConstant(sf.precision, 0, vn.Offset())
	}
	if vn.IsFree() {
		return nil
	}
	if vn.IsAddrForce() && vn.Size() != sf.precision {
		return nil
	}
	if vn.IsTypeLock() {
		if dt := vn.TypeReadFacing(nil); dt != nil && dt.Metatype() != TYPE_PARTIALSTRUCT && dt.Size() != sf.precision {
			return nil
		}
	}
	if vn.IsInput() && vn.Size() != sf.precision {
		return nil
	}

	vn.SetMark()
	if vn.Size() == sf.precision {
		tv := sf.NewPreexistingVarnode(vn)
		return tv
	}
	tv := &TransformVar{}
	tp := TVarPieceTemp
	if sf.PreserveAddress(vn, sf.precision*8, 0) {
		tp = TVarPiece
	}
	tv.initialize(tp, vn, sf.precision*8, sf.precision, 0)
	tv.flags = TVarSplitTerminator
	sf.pieceMap[vn.CreateIndex()] = []*TransformVar{tv}
	sf.worklist = append(sf.worklist, tv)
	return tv
}

// SubfloatFlow::traceForward -- subflow.cc.
func (sf *SubfloatFlow) traceForward(rvn *TransformVar) bool {
	if sf == nil || rvn == nil || rvn.GetOriginal() == nil {
		return false
	}
	vn := rvn.GetOriginal()
	dcount := 0
	hcount := 0
	callcount := 0
	for _, op := range vn.DescendIter() {
		if op == nil {
			continue
		}
		outvn := op.Output()
		if outvn != nil && outvn.IsMark() {
			continue
		}
		dcount++
		slot := op.GetSlot(vn)
		switch op.Code() {
		case CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV:
			if sf.exceedsPrecision(op) {
				return false
			}
			fallthrough
		case CPUI_MULTIEQUAL, CPUI_COPY, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT:
			rop := sf.NewOpReplace(op.NumInput(), op.Code(), op)
			outrvn := sf.setReplacement(outvn)
			if outrvn == nil {
				return false
			}
			sf.OpSetInput(rop, rvn, slot)
			sf.OpSetOutput(rop, outrvn)
			hcount++
		case CPUI_FLOAT_FLOAT2FLOAT:
			if outvn == nil || outvn.Size() < sf.precision {
				return false
			}
			opc := CPUI_FLOAT_FLOAT2FLOAT
			if outvn.Size() == sf.precision {
				opc = CPUI_COPY
			}
			rop := sf.NewPreexistingOp(1, opc, op)
			sf.OpSetInput(rop, rvn, 0)
			sf.terminatorCount++
			hcount++
		case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
			if sf.exceedsPrecision(op) {
				return false
			}
			other := op.Input(1 - slot)
			rvn2 := sf.setReplacement(other)
			if rvn2 == nil {
				return false
			}
			if !sf.PreexistingGuard(slot, rvn2) {
				return false
			}
			rop := sf.NewPreexistingOp(2, op.Code(), op)
			sf.OpSetInput(rop, rvn, slot)
			sf.OpSetInput(rop, rvn2, 1-slot)
			sf.terminatorCount++
			hcount++
		case CPUI_FLOAT_TRUNC, CPUI_FLOAT_NAN:
			rop := sf.NewPreexistingOp(1, op.Code(), op)
			sf.OpSetInput(rop, rvn, 0)
			sf.terminatorCount++
			hcount++
		default:
			return false
		}
		_ = callcount
	}
	if dcount != hcount && vn.IsInput() {
		return false
	}
	return true
}

// SubfloatFlow::traceBackward -- subflow.cc.
func (sf *SubfloatFlow) traceBackward(rvn *TransformVar) bool {
	if sf == nil || rvn == nil || rvn.GetOriginal() == nil {
		return false
	}
	op := rvn.GetOriginal().Def()
	if op == nil {
		return true
	}
	switch op.Code() {
	case CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV:
		if sf.exceedsPrecision(op) {
			return false
		}
		fallthrough
	case CPUI_MULTIEQUAL, CPUI_COPY, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT:
		rop := rvn.GetDef()
		if rop == nil {
			rop = sf.NewOpReplace(op.NumInput(), op.Code(), op)
			sf.OpSetOutput(rop, rvn)
		}
		for i := 0; i < op.NumInput(); i++ {
			if rop.GetIn(i) != nil {
				continue
			}
			newVar := sf.setReplacement(op.Input(i))
			if newVar == nil {
				return false
			}
			sf.OpSetInput(rop, newVar, i)
		}
		return true
	case CPUI_FLOAT_INT2FLOAT:
		vn := op.Input(0)
		if vn != nil && !vn.IsConstant() && vn.IsFree() {
			return false
		}
		rop := sf.NewOpReplace(1, CPUI_FLOAT_INT2FLOAT, op)
		sf.OpSetOutput(rop, rvn)
		sf.OpSetInput(rop, sf.GetPreexistingVarnode(vn), 0)
		return true
	case CPUI_FLOAT_FLOAT2FLOAT:
		vn := op.Input(0)
		var newVar *TransformVar
		var opc OpCode
		if vn != nil && vn.IsConstant() {
			opc = CPUI_COPY
			if vn.Size() == sf.precision {
				newVar = sf.NewConstant(sf.precision, 0, vn.Offset())
			} else {
				return false
			}
		} else {
			if vn != nil && vn.IsFree() {
				return false
			}
			if vn != nil && vn.Size() == sf.precision {
				opc = CPUI_COPY
			} else {
				opc = CPUI_FLOAT_FLOAT2FLOAT
			}
			newVar = sf.GetPreexistingVarnode(vn)
		}
		rop := sf.NewOpReplace(1, opc, op)
		sf.OpSetOutput(rop, rvn)
		sf.OpSetInput(rop, newVar, 0)
		return true
	default:
		return false
	}
}

// SubfloatFlow::processNextWork -- subflow.cc.
func (sf *SubfloatFlow) processNextWork() bool {
	if sf == nil || len(sf.worklist) == 0 {
		return false
	}
	rvn := sf.worklist[len(sf.worklist)-1]
	sf.worklist = sf.worklist[:len(sf.worklist)-1]
	if !sf.traceBackward(rvn) {
		return false
	}
	return sf.traceForward(rvn)
}

// SubfloatFlow::SubfloatFlow -- subflow.cc.
func NewSubfloatFlow(f *Funcdata, root *Varnode, prec int32) *SubfloatFlow {
	sf := &SubfloatFlow{
		TransformManager: NewTransformManager(f),
		precision:        prec,
		format:           struct{}{},
		maxPrecisionMap:  make(map[*PcodeOp]int32),
	}
	if f == nil || root == nil || prec <= 0 {
		sf.format = nil
		return sf
	}
	sf.setReplacement(root)
	return sf
}

// SubfloatFlow::preserveAddress -- subflow.cc.
func (sf *SubfloatFlow) PreserveAddress(vn *Varnode, bitSize, lsbOffset int32) bool {
	_ = sf
	_ = bitSize
	_ = lsbOffset
	return vn != nil && vn.IsInput()
}

// SubfloatFlow::doTrace -- subflow.cc.
func (sf *SubfloatFlow) DoTrace() bool {
	if sf == nil || sf.format == nil {
		return false
	}
	sf.terminatorCount = 0
	retval := true
	for len(sf.worklist) > 0 {
		if !sf.processNextWork() {
			retval = false
			break
		}
	}
	sf.ClearVarnodeMarks()
	if !retval {
		return false
	}
	if sf.terminatorCount == 0 {
		return false
	}
	return true
}
