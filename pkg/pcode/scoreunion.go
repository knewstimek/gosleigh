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

// ScoreUnionFields picks which field of a union (or of the union a pointer
// points to) a given read or write uses, by fitting every field to the
// surrounding data-flow and scoring the fit.
// C++ parity: unionresolve.cc class ScoreUnionFields.

const (
	scoreUnionThreshold = 256  // Trials over which to cancel additional passes
	scoreUnionMaxPasses = 6    // Maximum number of levels to score through
	scoreUnionMaxTrials = 1024 // Maximum number of trials to evaluate
)

// scoreTrial is a trial data-type fitted to a place in the data-flow.
// C++ parity: ScoreUnionFields::Trial.
type scoreTrial struct {
	vn         *Varnode // The Varnode being tested for fit
	op         *PcodeOp // The op reading the Varnode (nil for an upward trial)
	inslot     int      // The slot reading the Varnode (or -1)
	fitUp      bool     // Push the fit up, against the data-flow
	array      bool     // The field can be accessed as an array
	fitType    Datatype // The putative data-type of the Varnode
	scoreIndex int      // The original field being scored
}

func newTrialDown(op *PcodeOp, slot int, ct Datatype, index int, isArray bool) scoreTrial {
	return scoreTrial{vn: op.Input(slot), op: op, inslot: slot, fitType: ct, scoreIndex: index, array: isArray}
}

func newTrialUp(vn *Varnode, ct Datatype, index int, isArray bool) scoreTrial {
	return scoreTrial{vn: vn, inslot: -1, fitUp: true, fitType: ct, scoreIndex: index, array: isArray}
}

type visitMark struct {
	vn    *Varnode
	index int
}

type scoreUnionFields struct {
	fd           *Funcdata
	tf           *TypeFactory
	scores       []int      // Score for each field, indexed by fieldNum + 1 (whole union is 0)
	fields       []Datatype // Field corresponding to each score
	visited      map[visitMark]bool
	trialCurrent []scoreTrial
	trialNext    []scoreTrial
	result       ResolvedUnion
	trialCount   int
}

// unionFieldCount is the number of fields of a union (or array/struct).
func unionNumDepend(dt Datatype) int {
	switch t := dt.(type) {
	case *Union:
		return len(t.fields)
	case *Struct:
		return len(t.fields)
	case *Array:
		return 1
	}
	return 0
}

// scoreUnionField returns the resolution of parent (a union or a pointer to
// one) for the read or write of op at slot.
// C++ parity: ScoreUnionFields(TypeFactory&,Datatype*,PcodeOp*,int4).
func scoreUnionField(tf *TypeFactory, parentType Datatype, op *PcodeOp, slot int) ResolvedUnion {
	s := &scoreUnionFields{fd: opFuncdata(op), tf: tf, result: newResolvedSelf(parentType), visited: map[visitMark]bool{}}
	if s.testSimpleCases(op, slot, parentType) {
		return s.result
	}
	var wordSize uint32
	if p, ok := parentType.(*Pointer); ok {
		wordSize = p.WordSize()
	}
	numFields := unionNumDepend(s.result.baseType)
	s.scores = make([]int, numFields+1)
	s.fields = make([]Datatype, numFields+1)
	var vn *Varnode
	if slot < 0 {
		vn = op.Output()
		if vn.Size() != parentType.Size() {
			s.scores[0] -= 10 // Data-type does not even match size of Varnode
		} else {
			s.trialCurrent = append(s.trialCurrent, newTrialUp(vn, parentType, 0, false))
		}
	} else {
		vn = op.Input(slot)
		if vn.Size() != parentType.Size() {
			s.scores[0] -= 10
		} else {
			s.trialCurrent = append(s.trialCurrent, newTrialDown(op, slot, parentType, 0, false))
		}
	}
	s.fields[0] = parentType
	s.visited[visitMark{vn, 0}] = true
	for i := 0; i < numFields; i++ {
		fieldType := datatypeDepend(s.result.baseType, i)
		isArray := false
		if wordSize != 0 {
			if fieldType.Metatype() == TYPE_ARRAY {
				isArray = true
			}
			fieldType = tf.GetPointerStripArray(parentType.Size(), fieldType, wordSize)
		}
		if vn.Size() != fieldType.Size() {
			s.scores[i+1] -= 10 // Does not even match the Varnode's size: no trial
		} else if slot < 0 {
			s.trialCurrent = append(s.trialCurrent, newTrialUp(vn, fieldType, i+1, isArray))
		} else {
			s.trialCurrent = append(s.trialCurrent, newTrialDown(op, slot, fieldType, i+1, isArray))
		}
		s.fields[i+1] = fieldType
		s.visited[visitMark{vn, i + 1}] = true
	}
	s.run()
	s.computeBestIndex()
	return s.result
}

// scoreUnionSubpiece scores the fields of a union truncated by a SUBPIECE.
// C++ parity: ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*).
func scoreUnionSubpiece(tf *TypeFactory, unionType *Union, offset int64, op *PcodeOp) ResolvedUnion {
	s := &scoreUnionFields{fd: opFuncdata(op), tf: tf, result: newResolvedSelf(unionType), visited: map[visitMark]bool{}}
	vn := op.Output()
	numFields := len(unionType.fields)
	s.scores = make([]int, numFields+1)
	s.fields = make([]Datatype, numFields+1)
	s.fields[0] = unionType
	s.scores[0] = -10
	for i, f := range unionType.fields {
		s.fields[i+1] = f.Type
		if f.Type.Size() != vn.Size() || int64(f.Offset) != offset {
			s.scores[i+1] = -10
			continue
		}
		s.newTrialsDown(vn, f.Type, i+1, false)
	}
	s.trialCurrent, s.trialNext = s.trialNext, nil
	if len(s.trialCurrent) > 1 {
		s.run()
	}
	s.computeBestIndex()
	return s.result
}

// scoreUnionTruncation scores the fields of a union under an implied
// truncation at offset, for the read or write of op at slot.
// C++ parity: ScoreUnionFields(TypeFactory&,TypeUnion*,int4,PcodeOp*,int4).
func scoreUnionTruncation(tf *TypeFactory, unionType *Union, offset int64, op *PcodeOp, slot int) ResolvedUnion {
	s := &scoreUnionFields{fd: opFuncdata(op), tf: tf, result: newResolvedSelf(unionType), visited: map[visitMark]bool{}}
	vn := op.Output()
	if slot >= 0 {
		vn = op.Input(slot)
	}
	numFields := len(unionType.fields)
	s.scores = make([]int, numFields+1)
	s.fields = make([]Datatype, numFields+1)
	s.fields[0] = unionType
	s.scores[0] = -10 // Assume the untruncated entire union is not a good fit
	for i, f := range unionType.fields {
		s.fields[i+1] = f.Type
		// Score the implied truncation
		if ct := s.scoreTruncation(f.Type, vn, offset-int64(f.Offset), i+1); ct != nil {
			if slot < 0 {
				s.trialCurrent = append(s.trialCurrent, newTrialUp(vn, ct, i+1, false)) // Flow backward
			} else {
				s.trialCurrent = append(s.trialCurrent, newTrialDown(op, slot, ct, i+1, false)) // Flow downward
			}
			s.visited[visitMark{vn, i + 1}] = true
		}
	}
	if len(s.trialCurrent) > 1 {
		s.run()
	}
	s.computeBestIndex()
	return s.result
}

// testArrayArithmetic: op adds a multiple of a size at least as large as
// the union to the input -- array arithmetic over union elements.
func (s *scoreUnionFields) testArrayArithmetic(op *PcodeOp, inslot int) bool {
	baseSize := uint64(s.result.baseType.Size())
	switch op.Code() {
	case CPUI_INT_ADD:
		vn := op.Input(1 - inslot)
		if vn.IsConstant() {
			if vn.Offset() >= baseSize {
				return true // Array with union elements
			}
		} else if vn.IsWritten() {
			if multOp := vn.Def(); multOp.Code() == CPUI_INT_MULT {
				if vn2 := multOp.Input(1); vn2.IsConstant() && vn2.Offset() >= baseSize {
					return true
				}
			}
		}
	case CPUI_PTRADD:
		if op.Input(2).Offset() >= baseSize {
			return true
		}
	}
	return false
}

// testSimpleCases identifies uses that should not resolve to a field.
func (s *scoreUnionFields) testSimpleCases(op *PcodeOp, inslot int, parent Datatype) bool {
	if op.IsMarker() {
		return true // Propagate raw union across MULTIEQUAL and INDIRECT
	}
	if parent.Metatype() == TYPE_PTR {
		if inslot < 0 {
			return true // Don't resolve pointers "up"
		}
		if s.testArrayArithmetic(op, inslot) {
			return true
		}
	}
	if op.Code() != CPUI_COPY {
		return false // A more complicated case
	}
	if inslot < 0 {
		return false // Generally don't propagate a union backward thru COPY
	}
	if op.Output().IsTypeLock() {
		return false // Do the full scoring
	}
	return true // Assume we don't have to extract a field if copying
}

// scoreLockedType scores a trial data-type against a locked one.
func scoreLockedType(ct, lockType Datatype) int {
	score := 0
	if lockType == ct {
		score += 5 // Perfect match
	}
	for ct.Metatype() == TYPE_PTR {
		if lockType.Metatype() != TYPE_PTR {
			break
		}
		score += 5
		ct = ct.(*Pointer).Pointee()
		lockType = lockType.(*Pointer).Pointee()
	}
	ctMeta, vnMeta := ct.Metatype(), lockType.Metatype()
	if ctMeta == vnMeta {
		if ctMeta == TYPE_STRUCT || ctMeta == TYPE_UNION || ctMeta == TYPE_ARRAY || ctMeta == TYPE_CODE {
			score += 10
		} else {
			score += 3
		}
	} else {
		if (ctMeta == TYPE_INT && vnMeta == TYPE_UINT) || (ctMeta == TYPE_UINT && vnMeta == TYPE_INT) {
			score -= 1
		} else {
			score -= 5
		}
		if ct.Size() != lockType.Size() {
			score -= 2
		}
	}
	return score
}

func isCompositeMeta(meta metatype) bool {
	return meta == TYPE_ARRAY || meta == TYPE_STRUCT || meta == TYPE_UNION || meta == TYPE_CODE
}

// scoreParameter scores a trial passed as parameter paramSlot of a call.
func (s *scoreUnionFields) scoreParameter(ct Datatype, callOp *PcodeOp, paramSlot int) int {
	if fd := opFuncdata(callOp); fd != nil {
		if fc := fd.callSpecsForOp(callOp); fc != nil && fc.IsInputLocked() {
			if p, ok := fc.LockedParam(paramSlot); ok && p.Type != nil {
				return scoreLockedType(ct, p.Type)
			}
		}
	}
	if isCompositeMeta(ct.Metatype()) {
		return -1 // Vaguely unlikely thing to pass as a param
	}
	return 0
}

// scoreReturnType scores a trial returned by a call.
func (s *scoreUnionFields) scoreReturnType(ct Datatype, callOp *PcodeOp) int {
	if fd := opFuncdata(callOp); fd != nil {
		if fc := fd.callSpecsForOp(callOp); fc != nil && fc.IsOutputLocked() && fc.lockedOut != nil && fc.lockedOut.Type != nil {
			return scoreLockedType(ct, fc.lockedOut.Type)
		}
	}
	if isCompositeMeta(ct.Metatype()) {
		return -1 // Vaguely unlikely thing to return from a function
	}
	return 0
}

// derefPointer: ct is a pointer whose target (or a leading component of it)
// fits the value loaded or stored.
func derefPointer(ct Datatype, vn *Varnode) (Datatype, int) {
	p, ok := ct.(*Pointer)
	if !ok {
		return nil, -10
	}
	ptrto := p.Pointee()
	for ptrto != nil && ptrto.Size() > vn.Size() {
		ptrto, _ = datatypeSubType(ptrto, 0)
	}
	if ptrto != nil && ptrto.Size() == vn.Size() {
		return ptrto, 10
	}
	return nil, 0
}

// newTrialsDown creates trials for every read of vn.
func (s *scoreUnionFields) newTrialsDown(vn *Varnode, ct Datatype, scoreIndex int, isArray bool) {
	mark := visitMark{vn, scoreIndex}
	if s.visited[mark] {
		return // Already visited this Varnode
	}
	s.visited[mark] = true
	if vn.IsTypeLock() {
		s.scores[scoreIndex] += scoreLockedType(ct, vn.Type())
		return // Don't propagate through locked Varnode
	}
	for _, op := range vn.DescendIter() {
		s.trialNext = append(s.trialNext, newTrialDown(op, op.GetSlot(vn), ct, scoreIndex, isArray))
	}
}

// newTrials creates trials based on the given input slot: up through its
// definition and down through its other reads.
func (s *scoreUnionFields) newTrials(op *PcodeOp, slot int, ct Datatype, scoreIndex int, isArray bool) {
	vn := op.Input(slot)
	mark := visitMark{vn, scoreIndex}
	if s.visited[mark] {
		return
	}
	s.visited[mark] = true
	if vn.IsTypeLock() {
		s.scores[scoreIndex] += scoreLockedType(ct, vn.Type())
		return
	}
	s.trialNext = append(s.trialNext, newTrialUp(vn, ct, scoreIndex, isArray)) // Try to fit up
	for _, readOp := range vn.DescendIter() {
		inslot := readOp.GetSlot(vn)
		if readOp == op && inslot == slot {
			continue // Don't go down the op we came from
		}
		s.trialNext = append(s.trialNext, newTrialDown(readOp, inslot, ct, scoreIndex, isArray))
	}
}

// scoreTrialDown fits a trial to its op as the incoming Varnode.
func (s *scoreUnionFields) scoreTrialDown(t scoreTrial, lastLevel bool) {
	if t.fitUp {
		return // Trial doesn't push in this direction
	}
	var resType Datatype // Assume by default we don't propagate
	meta := t.fitType.Metatype()
	score := 0
	comp := isCompositeMeta(meta)
	switch t.op.Code() {
	case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INDIRECT:
		resType = t.fitType // No score, but we can propagate
	case CPUI_LOAD:
		resType, score = derefPointer(t.fitType, t.op.Output())
	case CPUI_STORE:
		if t.inslot == 1 {
			var ptrto Datatype
			ptrto, score = derefPointer(t.fitType, t.op.Input(2))
			if ptrto != nil && !lastLevel {
				s.newTrials(t.op, 2, ptrto, t.scoreIndex, t.array) // Propagate to the value STOREd
			}
		} else if t.inslot == 2 {
			if meta == TYPE_CODE {
				score = -5
			} else {
				score = 1
			}
		}
	case CPUI_CBRANCH:
		if meta == TYPE_BOOL {
			score = 10
		} else {
			score = -10
		}
	case CPUI_BRANCHIND:
		if meta == TYPE_PTR || comp || meta == TYPE_FLOAT {
			score = -5
		} else {
			score = 1
		}
	case CPUI_CALL, CPUI_CALLOTHER:
		if t.inslot > 0 {
			score = s.scoreParameter(t.fitType, t.op, t.inslot-1)
		}
	case CPUI_CALLIND:
		if t.inslot == 0 {
			if p, ok := t.fitType.(*Pointer); ok {
				if p.Pointee().Metatype() == TYPE_CODE {
					score = 10
				} else {
					score = -10
				}
			}
		} else {
			score = s.scoreParameter(t.fitType, t.op, t.inslot-1)
		}
	case CPUI_RETURN:
		if comp {
			score = -1
		}
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
		if comp || meta == TYPE_FLOAT {
			score = -1
		} else {
			score = 1
		}
	case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_SCARRY, CPUI_INT_SBORROW:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_UNKNOWN || meta == TYPE_UINT || meta == TYPE_BOOL:
			score = -1
		default:
			score = 5
		}
	case CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_CARRY:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_UNKNOWN || meta == TYPE_UINT:
			score = 5
		case meta == TYPE_INT:
			score = -5
		}
	case CPUI_INT_ZEXT:
		switch {
		case meta == TYPE_UINT:
			score = 2
		case meta == TYPE_INT || meta == TYPE_BOOL:
			score = 1
		case meta == TYPE_UNKNOWN:
			score = 0
		default: // struct,union,ptr,array,code,float
			score = -5
		}
	case CPUI_INT_SEXT:
		switch {
		case meta == TYPE_INT:
			score = 2
		case meta == TYPE_UINT || meta == TYPE_BOOL:
			score = 1
		case meta == TYPE_UNKNOWN:
			score = 0
		default:
			score = -5
		}
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_PTRSUB:
		if p, ok := t.fitType.(*Pointer); ok {
			if t.inslot >= 0 {
				vn := t.op.Input(1 - t.inslot)
				if vn.IsConstant() {
					off := int64(vn.Offset())
					var par *Pointer
					var parOff int64
					if rt := pointerDownChain(s.tf, p, &off, &par, &parOff, t.array); rt != nil {
						resType = rt
						score = 5
					}
				} else if t.array {
					score = 1
					elSize := int32(1)
					if vn.IsWritten() {
						if multOp := vn.Def(); multOp.Code() == CPUI_INT_MULT {
							if multVn := multOp.Input(1); multVn.IsConstant() {
								elSize = int32(multVn.Offset())
							}
						}
					}
					if p.Pointee().AlignSize() == elSize {
						score = 5
						resType = t.fitType
					}
				} else {
					score = 5 // Indexing into something that is not an array
				}
			}
		} else if comp || meta == TYPE_FLOAT {
			score = -5
		} else {
			score = 1
		}
	case CPUI_INT_2COMP:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_UNKNOWN || meta == TYPE_BOOL:
			score = -1
		case meta == TYPE_INT:
			score = 5
		}
	case CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR, CPUI_POPCOUNT, CPUI_LZCOUNT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -1
		case meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = 2
		}
	case CPUI_INT_LEFT, CPUI_INT_RIGHT:
		if t.inslot == 0 {
			switch {
			case comp || meta == TYPE_FLOAT:
				score = -5
			case meta == TYPE_PTR || meta == TYPE_BOOL:
				score = -1
			case meta == TYPE_UINT || meta == TYPE_UNKNOWN:
				score = 2
			}
		} else if comp || meta == TYPE_FLOAT || meta == TYPE_PTR {
			score = -5
		} else {
			score = 1
		}
	case CPUI_INT_SRIGHT:
		if t.inslot == 0 {
			switch {
			case comp || meta == TYPE_FLOAT:
				score = -5
			case meta == TYPE_PTR || meta == TYPE_BOOL || meta == TYPE_UINT || meta == TYPE_UNKNOWN:
				score = -1
			default:
				score = 2
			}
		} else if comp || meta == TYPE_FLOAT || meta == TYPE_PTR {
			score = -5
		} else {
			score = 1
		}
	case CPUI_INT_MULT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		default:
			score = 5
		}
	case CPUI_INT_DIV, CPUI_INT_REM:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		case meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = 5
		}
	case CPUI_INT_SDIV, CPUI_INT_SREM:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		case meta == TYPE_INT:
			score = 5
		}
	case CPUI_BOOL_NEGATE, CPUI_BOOL_AND, CPUI_BOOL_XOR, CPUI_BOOL_OR:
		switch {
		case meta == TYPE_BOOL:
			score = 10
		case meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = -1
		default:
			score = -10
		}
	case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR,
		CPUI_FLOAT_ROUND:
		if meta == TYPE_FLOAT {
			score = 10
		} else {
			score = -10
		}
	case CPUI_FLOAT_INT2FLOAT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR:
			score = -5
		case meta == TYPE_INT:
			score = 5
		}
	case CPUI_PIECE:
		if comp || meta == TYPE_FLOAT {
			score = -5
		}
	case CPUI_SUBPIECE:
		offset := subpieceByteOffsetForComposite(t.op)
		resType = s.scoreTruncation(t.fitType, t.op.Output(), offset, t.scoreIndex)
	case CPUI_PTRADD:
		if p, ok := t.fitType.(*Pointer); ok {
			if t.inslot == 0 {
				if uint64(p.Pointee().AlignSize()) == t.op.Input(2).Offset() {
					score = 10
					resType = t.fitType
				}
			} else {
				score = -10
			}
		} else if comp || meta == TYPE_FLOAT {
			score = -5
		} else {
			score = 1
		}
	case CPUI_SEGMENTOP:
		if t.inslot == 2 {
			switch {
			case meta == TYPE_PTR:
				score = 5
			case comp || meta == TYPE_FLOAT:
				score = -5
			default:
				score = -1
			}
		} else if comp || meta == TYPE_FLOAT || meta == TYPE_PTR {
			score = -2
		}
	default:
		score = -10 // Doesn't fit
	}
	s.scores[t.scoreIndex] += score
	if resType != nil && !lastLevel && t.op.Output() != nil {
		s.newTrialsDown(t.op.Output(), resType, t.scoreIndex, t.array)
	}
}

// scoreTrialUp fits a trial to the op defining its Varnode.
func (s *scoreUnionFields) scoreTrialUp(t scoreTrial, lastLevel bool) {
	if !t.fitUp {
		return // Trial doesn't push in this direction
	}
	score := 0
	if !t.vn.IsWritten() {
		if t.vn.IsConstant() {
			s.scoreConstantFit(t)
		}
		return // Nothing to propagate up through
	}
	var resType Datatype // Assume by default we don't propagate
	newslot := 0
	meta := t.fitType.Metatype()
	comp := isCompositeMeta(meta)
	def := t.vn.Def()
	switch def.Code() {
	case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INDIRECT:
		resType = t.fitType // No score, but we can propagate
	case CPUI_LOAD:
		resType = s.tf.GetPointer(def.Input(1).Size(), t.fitType, 1)
		newslot = 1 // No score, but we can propagate
	case CPUI_CALL, CPUI_CALLOTHER, CPUI_CALLIND:
		score = s.scoreReturnType(t.fitType, def)
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_SCARRY,
		CPUI_INT_SBORROW, CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_CARRY, CPUI_BOOL_NEGATE,
		CPUI_BOOL_AND, CPUI_BOOL_XOR, CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL,
		CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN:
		switch {
		case meta == TYPE_BOOL:
			score = 10
		case t.fitType.Size() == 1:
			score = 1
		default:
			score = -10
		}
	case CPUI_INT_ADD, CPUI_INT_SUB, CPUI_PTRSUB:
		switch {
		case meta == TYPE_PTR:
			score = 5 // Don't try to back up further
		case comp || meta == TYPE_FLOAT:
			score = -5
		default:
			score = 1
		}
	case CPUI_INT_2COMP:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_UNKNOWN || meta == TYPE_BOOL:
			score = -1
		case meta == TYPE_INT:
			score = 5
		}
	case CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR, CPUI_POPCOUNT, CPUI_LZCOUNT,
		CPUI_INT_LEFT, CPUI_INT_RIGHT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -1
		case meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = 2
		}
	case CPUI_INT_SRIGHT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -5
		case meta == TYPE_PTR || meta == TYPE_BOOL || meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = -1
		default:
			score = 2
		}
	case CPUI_INT_MULT:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		default:
			score = 5
		}
	case CPUI_INT_DIV, CPUI_INT_REM:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		case meta == TYPE_UINT || meta == TYPE_UNKNOWN:
			score = 5
		}
	case CPUI_INT_SDIV, CPUI_INT_SREM:
		switch {
		case comp || meta == TYPE_FLOAT:
			score = -10
		case meta == TYPE_PTR || meta == TYPE_BOOL:
			score = -2
		case meta == TYPE_INT:
			score = 5
		}
	case CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
		CPUI_FLOAT_INT2FLOAT:
		if meta == TYPE_FLOAT {
			score = 10
		} else {
			score = -10
		}
	case CPUI_FLOAT_TRUNC:
		if meta == TYPE_INT || meta == TYPE_UINT {
			score = 2
		} else {
			score = -2
		}
	case CPUI_PIECE:
		switch {
		case meta == TYPE_FLOAT || meta == TYPE_BOOL:
			score = -5
		case meta == TYPE_CODE || meta == TYPE_PTR:
			score = -2
		}
	case CPUI_SUBPIECE:
		if meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_BOOL {
			if def.Input(1).Offset() == 0 {
				score = 3 // Likely truncation
			} else {
				score = 1
			}
		} else {
			score = -5
		}
	case CPUI_PTRADD:
		if p, ok := t.fitType.(*Pointer); ok {
			if uint64(p.Pointee().AlignSize()) == def.Input(2).Offset() {
				score = 10
			} else {
				score = 2
			}
		} else if comp || meta == TYPE_FLOAT {
			score = -5
		} else {
			score = 1
		}
	default:
		score = -10 // Datatype doesn't fit
	}
	s.scores[t.scoreIndex] += score
	if resType != nil && !lastLevel {
		s.newTrials(def, newslot, resType, t.scoreIndex, t.array)
	}
}

// scoreTruncation scores fitting ct, truncated by offset, into vn and
// returns the data-type to recurse with (nil to stop).
func (s *scoreUnionFields) scoreTruncation(ct Datatype, vn *Varnode, offset int64, scoreIndex int) Datatype {
	score := 0
	if u, ok := ct.(*Union); ok {
		ct = nil    // Don't recurse a data-type from truncation of a union
		score = -10 // Negative score if the union has no field matching the size
		for _, f := range u.fields {
			if int64(f.Offset) == offset && f.Type.Size() == vn.Size() {
				score = 10
				if s.result.baseType == Datatype(u) {
					score += 5
				}
				break
			}
		}
	} else {
		score = 10 // If we can find a size match for the truncation
		curOff := offset
		for ct != nil && (curOff != 0 || ct.Size() != vn.Size()) {
			if m := ct.Metatype(); m == TYPE_INT || m == TYPE_UINT {
				if int64(ct.Size()) >= int64(vn.Size())+curOff {
					score = 1 // Size doesn't match, but still possibly reasonable
					break
				}
			}
			ct, curOff = datatypeSubType(ct, curOff)
		}
		if ct == nil {
			score = -10
		}
	}
	s.scores[scoreIndex] += score
	return ct
}

// scoreConstantFit scores a trial against a constant, which has no
// data-type of its own: does it look like an integer, a pointer, a float.
func (s *scoreUnionFields) scoreConstantFit(t scoreTrial) {
	size := t.vn.Size()
	val := t.vn.Offset()
	meta := t.fitType.Metatype()
	score := 0
	switch {
	case meta == TYPE_BOOL:
		if size == 1 && val < 2 {
			score = 2
		} else {
			score = -2
		}
	case meta == TYPE_FLOAT:
		score = -1
		if exp, ok := floatExponentCode(val, size); ok && exp < 7 && exp > -4 { // Common exponent range
			score = 2
		}
	case meta == TYPE_INT || meta == TYPE_UINT || meta == TYPE_PTR:
		if val == 0 {
			score = 2 // Zero is equally valid as pointer or integer
		} else {
			looksLikePointer := false
			lower, upper := defaultDataPointerBounds(s.fd, t.vn)
			if val >= lower && val <= upper && bitTransitions(val, size) >= 3 {
				looksLikePointer = true
			}
			if meta == TYPE_PTR {
				if looksLikePointer {
					score = 2
				} else {
					score = -2
				}
			} else if looksLikePointer {
				score = 1
			} else {
				score = 2
			}
		}
	default:
		score = -2
	}
	s.scores[t.scoreIndex] += score
}

// floatExponentCode is the raw (biased) exponent field of an encoded float.
// C++ parity: FloatFormat::extractExponentCode for the IEEE formats.
func floatExponentCode(x uint64, size int32) (int, bool) {
	switch size {
	case 4:
		return int((x >> 23) & 0xff), true
	case 8:
		return int((x >> 52) & 0x7ff), true
	}
	return 0, false
}

// defaultDataPointerBounds is the range of values that may be pointers into
// the default data space. C++ parity: AddrSpace::calcScaleMask
// (pointerLowerBound / pointerUpperBound).
func defaultDataPointerBounds(fd *Funcdata, vn *Varnode) (uint64, uint64) {
	addrSize := int32(8)
	if fd != nil && fd.BaseAddr().Space != nil {
		addrSize = int32(fd.BaseAddr().Space.AddrSize)
	}
	highest := sizeMask(addrSize)
	buffer := uint64(0x1000)
	if addrSize < 3 {
		buffer = 0x100
	}
	return buffer, highest - buffer
}

func (s *scoreUnionFields) runOneLevel(lastPass bool) {
	for _, t := range s.trialCurrent {
		s.trialCount++
		if s.trialCount > scoreUnionMaxTrials {
			return // Absolute number of trials reached
		}
		s.scoreTrialDown(t, lastPass)
		s.scoreTrialUp(t, lastPass)
	}
}

func (s *scoreUnionFields) computeBestIndex() {
	bestScore := s.scores[0]
	bestIndex := 0
	for i := 1; i < len(s.scores); i++ {
		if s.scores[i] > bestScore {
			bestScore = s.scores[i]
			bestIndex = i
		}
	}
	s.result.fieldNum = bestIndex - 1 // Renormalize score index to field index
	s.result.resolve = s.fields[bestIndex]
}

func (s *scoreUnionFields) run() {
	s.trialCount = 0
	for pass := 0; pass < scoreUnionMaxPasses; pass++ {
		if len(s.trialCurrent) == 0 {
			break
		}
		if s.trialCount > scoreUnionThreshold {
			break // Threshold reached, don't score any more trials
		}
		if pass+1 == scoreUnionMaxPasses {
			s.runOneLevel(true)
		} else {
			s.runOneLevel(false)
			s.trialCurrent, s.trialNext = s.trialNext, nil
		}
	}
}
