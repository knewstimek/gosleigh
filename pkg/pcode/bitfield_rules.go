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

import "math/bits"

// constantMatch reports a constant Varnode with the given value.
// C++ parity: Varnode::constantMatch.
func constantMatch(vn *Varnode, val uint64) bool {
	return vn.IsConstant() && vn.Offset() == val
}

// RuleBitFieldStore turns the insertion of bitfields ending in a STORE into
// INSERT ops. C++ parity: class RuleBitFieldStore.
type RuleBitFieldStore struct{ batchRule }

func NewRuleBitFieldStore(group string) *RuleBitFieldStore {
	r := &RuleBitFieldStore{}
	r.batchRule = newBatchRule(group, "bitfield_store", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleBitFieldStore(g) })
	return r
}

// C++ parity: RuleBitFieldStore::applyOp.
func (r *RuleBitFieldStore) apply(op *PcodeOp, data *Funcdata) int {
	ptr := op.Input(1).TypeReadFacing(op)
	dt, off := GetPtrInto(ptr)
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	if vn := op.Input(2); vn.IsWritten() && vn.Def().Code() == CPUI_INSERT {
		return 0
	}
	t := newBitFieldInsertTransform(data, op, dt, off)
	if t.initialOffset == -1 || !t.doTrace() {
		return 0
	}
	t.apply()
	return 1
}

// RuleBitFieldOut turns the insertion of bitfields ending in a write to a
// mapped Varnode into INSERT ops. C++ parity: class RuleBitFieldOut.
type RuleBitFieldOut struct{ batchRule }

func NewRuleBitFieldOut(group string) *RuleBitFieldOut {
	r := &RuleBitFieldOut{}
	ops := []OpCode{
		CPUI_COPY, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_ADD, CPUI_INT_CARRY,
		CPUI_INT_SCARRY, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR, CPUI_INT_LEFT, CPUI_INT_RIGHT,
		CPUI_INT_SRIGHT, CPUI_INT_MULT, CPUI_BOOL_NEGATE, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_INDIRECT, CPUI_SUBPIECE,
	}
	r.batchRule = newBatchRule(group, "bitfield_out", ops, r.apply, func(g string) Rule { return NewRuleBitFieldOut(g) })
	return r
}

// C++ parity: RuleBitFieldOut::applyOp.
func (r *RuleBitFieldOut) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	dt := outvn.TypeDefFacing()
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	t := newBitFieldInsertTransform(data, op, dt, 0)
	if t.initialOffset == -1 || t.containerSize == -1 || !t.doTrace() {
		return 0
	}
	t.apply()
	return 1
}

// RuleBitFieldLoad turns the extraction of bitfields from a LOAD into ZPULL
// and SPULL ops. C++ parity: class RuleBitFieldLoad.
type RuleBitFieldLoad struct{ batchRule }

func NewRuleBitFieldLoad(group string) *RuleBitFieldLoad {
	r := &RuleBitFieldLoad{}
	r.batchRule = newBatchRule(group, "bitfield_load", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleBitFieldLoad(g) })
	return r
}

// C++ parity: RuleBitFieldLoad::applyOp.
func (r *RuleBitFieldLoad) apply(op *PcodeOp, data *Funcdata) int {
	ptr := op.Input(1).TypeReadFacing(op)
	dt, off := GetPtrInto(ptr)
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	if op.NotPrinted() || op.Output() == nil {
		return 0 // the LOAD was visited before
	}
	t := newBitFieldPullTransform(data, op.Output(), dt, off)
	if t.initialOffset == -1 || !t.doTrace() {
		return 0
	}
	t.apply()
	return 1
}

// RuleBitFieldIn turns the extraction of bitfields from a mapped Varnode
// into ZPULL and SPULL ops. C++ parity: class RuleBitFieldIn.
type RuleBitFieldIn struct{ batchRule }

func NewRuleBitFieldIn(group string) *RuleBitFieldIn {
	r := &RuleBitFieldIn{}
	ops := []OpCode{
		CPUI_COPY,
		CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL,
		CPUI_INT_ZEXT, CPUI_INT_SEXT,
		CPUI_INT_ADD, CPUI_INT_NEGATE,
		CPUI_INT_AND, CPUI_INT_LEFT, CPUI_INT_RIGHT, CPUI_INT_SRIGHT, CPUI_INT_MULT,
		CPUI_SUBPIECE,
	}
	r.batchRule = newBatchRule(group, "bitfield_in", ops, r.apply, func(g string) Rule { return NewRuleBitFieldIn(g) })
	return r
}

// C++ parity: RuleBitFieldIn::applyOp.
func (r *RuleBitFieldIn) apply(op *PcodeOp, data *Funcdata) int {
	invn := op.Input(0)
	dt := invn.TypeReadFacing(op)
	if dt == nil || !dt.HasBitfields() {
		return 0
	}
	t := newBitFieldPullTransform(data, invn, dt, 0)
	if t.initialOffset == -1 || !t.doTrace() {
		return 0
	}
	t.apply()
	return 1
}

// RulePullAbsorb simplifies expressions using ZPULL and SPULL.
// C++ parity: class RulePullAbsorb.
type RulePullAbsorb struct{ batchRule }

func NewRulePullAbsorb(group string) *RulePullAbsorb {
	r := &RulePullAbsorb{}
	r.batchRule = newBatchRule(group, "pull_absorb", []OpCode{CPUI_ZPULL, CPUI_SPULL}, r.apply, func(g string) Rule { return NewRulePullAbsorb(g) })
	return r
}

// C++ parity: RulePullAbsorb::applyOp.
func (r *RulePullAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	outvn := op.Output()
	if outvn == nil {
		return 0
	}
	for _, readOp := range outvn.DescendIter() {
		res := 0
		switch readOp.Code() {
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			res = absorbRight(data, readOp, op)
		case CPUI_INT_LEFT:
			res = absorbLeft(data, readOp, op)
		case CPUI_INT_AND:
			res = absorbPullAnd(data, readOp, op)
		case CPUI_INT_SLESS, CPUI_INT_LESS:
			res = absorbCompare(data, readOp, nil, op)
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			res = absorbExt(data, readOp, op)
		case CPUI_SUBPIECE:
			res = absorbSubpiece(data, readOp, op)
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			res = absorbCompZero(data, readOp, op)
		}
		if res != 0 {
			return res
		}
	}
	return 0
}

// absorbRight handles `field >> #c`. C++ parity: RulePullAbsorb::absorbRight.
func absorbRight(data *Funcdata, rightOp, pullOp *PcodeOp) int {
	for _, readOp := range rightOp.Output().DescendIter() {
		if readOp.Code() == CPUI_INT_AND {
			if res := absorbRightAndCompZero(data, rightOp, readOp, pullOp); res != 0 {
				return res
			}
		}
	}
	return 0
}

// absorbRightAndCompZero: ((sfield >> #n) & #1) == #0  =>  #0 <= sfield, and
// the != variant  =>  sfield < #0.
// C++ parity: RulePullAbsorb::absorbRightAndCompZero.
func absorbRightAndCompZero(data *Funcdata, rightOp, andOp, pullOp *PcodeOp) int {
	if pullOp.Code() != CPUI_SPULL {
		return 0
	}
	cvn := rightOp.Input(1)
	if !cvn.IsConstant() {
		return 0
	}
	sa := int64(cvn.Offset())
	numbits := int64(pullOp.Input(2).Offset())
	if numbits-1 != sa { // the shift puts the sign bit in the least significant position
		return 0
	}
	if !constantMatch(andOp.Input(1), 1) {
		return 0
	}
	outvn := andOp.Output()
	for _, readOp := range outvn.DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		if !constantMatch(readOp.Input(1), 0) {
			continue
		}
		vn := pullOp.Output()
		if opc == CPUI_INT_EQUAL {
			data.OpSetOpcode(readOp, CPUI_INT_LESSEQUAL)
			zvn := readOp.Input(1)
			data.OpSetInput(readOp, vn, 1)
			data.OpSetInput(readOp, zvn, 0)
		} else {
			data.OpSetOpcode(readOp, CPUI_INT_SLESS)
			data.OpSetInput(readOp, vn, 0)
		}
		data.DestroyVarnodeRecursive(outvn)
		return 1
	}
	return 0
}

// absorbLeft handles `field << #c`. C++ parity: RulePullAbsorb::absorbLeft.
func absorbLeft(data *Funcdata, leftOp, pullOp *PcodeOp) int {
	for _, readOp := range leftOp.Output().DescendIter() {
		res := 0
		switch readOp.Code() {
		case CPUI_INT_SLESS:
			res = absorbCompare(data, readOp, leftOp, pullOp)
		case CPUI_INT_RIGHT:
			res = absorbLeftRight(data, readOp, leftOp, pullOp)
		case CPUI_INT_AND:
			res = absorbLeftAnd(data, readOp, leftOp, pullOp)
		}
		if res != 0 {
			return res
		}
	}
	return 0
}

// absorbLeftRight: (field << #c) >> #d  =>  field >> (#d-#c).
// C++ parity: RulePullAbsorb::absorbLeftRight.
func absorbLeftRight(data *Funcdata, rightOp, leftOp, pullOp *PcodeOp) int {
	leftcvn := leftOp.Input(1)
	rightcvn := rightOp.Input(1)
	if !leftcvn.IsConstant() || !rightcvn.IsConstant() {
		return 0
	}
	bitsize := int64(pullOp.Input(2).Offset())
	containerSize := int64(pullOp.Input(0).Size()) * 8
	leftshift := int64(leftcvn.Offset())
	rightshift := int64(rightcvn.Offset())
	if leftshift+bitsize > containerSize { // the left shift destroys field data
		return 0
	}
	sa := rightshift - leftshift
	switch {
	case sa == 0:
		data.TotalReplace(rightOp.Output(), pullOp.Output())
		data.DestroyVarnodeRecursive(rightOp.Output())
	case sa > 0:
		data.OpSetInput(rightOp, data.NewConstant(rightcvn.Size(), uint64(sa)), 1)
		data.OpSetInput(rightOp, pullOp.Output(), 0)
		data.DestroyVarnodeRecursive(leftOp.Output())
	default:
		data.OpSetOpcode(rightOp, CPUI_INT_LEFT)
		data.OpSetInput(rightOp, data.NewConstant(rightcvn.Size(), uint64(-sa)), 1)
		data.OpSetInput(rightOp, pullOp.Output(), 0)
		data.DestroyVarnodeRecursive(leftOp.Output())
	}
	return 1
}

// absorbLeftAnd: ((field << #c) & #b) == #d  =>  (field & #b>>c) == #d>>c.
// C++ parity: RulePullAbsorb::absorbLeftAnd.
func absorbLeftAnd(data *Funcdata, andOp, leftOp, pullOp *PcodeOp) int {
	shiftAmount := leftOp.Input(1)
	if !shiftAmount.IsConstant() || shiftAmount.Offset() >= 64 {
		return 0
	}
	sa := uint(shiftAmount.Offset())
	maskVn := andOp.Input(1)
	if !maskVn.IsConstant() {
		return 0
	}
	mask := maskVn.Offset()
	for _, readOp := range andOp.Output().DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		compVal := readOp.Input(1)
		if !compVal.IsConstant() {
			continue
		}
		val := compVal.Offset() >> sa
		if val<<sa != compVal.Offset() {
			continue
		}
		mask >>= sa
		newAnd := data.NewConstant(maskVn.Size(), mask)
		newAnd.UpdateType(maskVn.Type())
		data.OpSetInput(andOp, newAnd, 1)
		if val != compVal.Offset() {
			newVal := data.NewConstant(compVal.Size(), val)
			newVal.UpdateType(compVal.Type())
			data.OpSetInput(readOp, newVal, 1)
		}
		data.OpSetInput(andOp, leftOp.Input(0), 0)
		data.DestroyVarnodeRecursive(leftOp.Output())
		return 1
	}
	return 0
}

// absorbPullAnd: field & #signbit == #0  =>  field < 0.
// C++ parity: RulePullAbsorb::absorbAnd.
func absorbPullAnd(data *Funcdata, andOp, pullOp *PcodeOp) int {
	maskVn := andOp.Input(1)
	if !maskVn.IsConstant() || pullOp.Code() != CPUI_SPULL {
		return 0
	}
	vn := pullOp.Output()
	bitsize := pullOp.Input(2).Offset()
	if bitsize == 0 || bitsize > 64 || uint64(1)<<(bitsize-1) != maskVn.Offset() { // mask for the sign bit
		return 0
	}
	for _, readOp := range andOp.Output().DescendIter() {
		opc := readOp.Code()
		if opc != CPUI_INT_EQUAL && opc != CPUI_INT_NOTEQUAL {
			continue
		}
		if !constantMatch(readOp.Input(1), 0) {
			continue
		}
		newZero := data.NewConstant(vn.Size(), 0)
		newZero.UpdateType(resizeInteger(vn.Type(), vn.Size()))
		if opc == CPUI_INT_EQUAL {
			data.OpSetOpcode(readOp, CPUI_INT_SLESSEQUAL)
			data.OpSetInput(readOp, newZero, 0)
			data.OpSetInput(readOp, vn, 1)
		} else {
			data.OpSetOpcode(readOp, CPUI_INT_SLESS)
			data.OpSetInput(readOp, vn, 0)
			data.OpSetInput(readOp, newZero, 1)
		}
		data.DestroyVarnodeRecursive(andOp.Output())
		return 1
	}
	return 0
}

// absorbCompare handles comparisons of a pulled field shifted into the sign
// bit:
//   - (boolfield << #c) s< #0  =>  boolfield
//   - #-1 s< (boolfield << #c)  =>  !boolfield
//   - (field << #c) < (#d<<#c)  =>  field < #d, and the mirrored form
//
// C++ parity: RulePullAbsorb::absorbCompare.
func absorbCompare(data *Funcdata, compOp, leftOp, pullOp *PcodeOp) int {
	sa := int64(0)
	if leftOp != nil {
		cvn := leftOp.Input(1)
		if !cvn.IsConstant() {
			return 0
		}
		sa = int64(cvn.Offset())
	}
	numbits := int64(pullOp.Input(2).Offset())
	sz := int64(pullOp.Input(0).Size()) * 8
	if numbits+sa != sz { // the field's high bit must land in the sign bit
		return 0
	}
	inVn := pullOp.Output()
	if leftOp != nil {
		inVn = leftOp.Output()
	}
	lessVn0, lessVn1 := compOp.Input(0), compOp.Input(1)
	if compOp.Code() == CPUI_INT_SLESS {
		if numbits == 1 && lessVn0 == inVn && lessVn1.IsConstant() && lessVn1.Offset() == 0 {
			oldVn := compOp.Output()
			data.TotalReplace(oldVn, pullOp.Output())
			data.DestroyVarnodeRecursive(oldVn)
			return 1
		}
		if numbits == 1 && lessVn1 == inVn && lessVn0.IsConstant() && lessVn0.Offset() == bitfieldSizeMask(inVn.Size()) {
			data.OpRemoveInput(compOp, 0)
			data.OpSetOpcode(compOp, CPUI_BOOL_NEGATE)
			data.OpSetInput(compOp, pullOp.Output(), 0)
			data.DestroyVarnodeRecursive(inVn)
			return 1
		}
	}
	if sa <= 0 || sa >= 64 {
		return 0
	}
	mask := uint64(1)<<uint(sa) - 1
	if inVn == lessVn0 && lessVn1.IsConstant() {
		origVal := lessVn1.Offset()
		if lowBits := mask & origVal; lowBits == 0 || lowBits == 1 {
			var newVal uint64
			if lowBits == 1 {
				newVal = (origVal - 1) >> uint(sa)                    // to a LESSEQUAL constant
				newVal = (newVal + 1) & bitfieldSizeMask(inVn.Size()) // back to LESS after the shift
			} else {
				newVal = origVal >> uint(sa)
			}
			data.OpSetInput(compOp, pullOp.Output(), 0)
			data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 1)
			data.DestroyVarnodeRecursive(inVn)
			return 1
		}
	}
	if inVn == lessVn1 && lessVn0.IsConstant() {
		origVal := lessVn0.Offset()
		if lowBits := mask & origVal; lowBits == 0 || lowBits == mask {
			var newVal uint64
			if lowBits == mask {
				newVal = (origVal + 1) >> uint(sa)
				newVal = (newVal - 1) & bitfieldSizeMask(inVn.Size())
			} else {
				newVal = origVal >> uint(sa)
			}
			data.OpSetInput(compOp, pullOp.Output(), 1)
			data.OpSetInput(compOp, data.NewConstant(inVn.Size(), newVal), 0)
			data.DestroyVarnodeRecursive(inVn)
			return 1
		}
	}
	return 0
}

// absorbExt: SEXT(SPULL(x,#p,#n))  =>  SPULL(x,#p,#n), and ZEXT of ZPULL.
// C++ parity: RulePullAbsorb::absorbExt.
func absorbExt(data *Funcdata, extOp, pullOp *PcodeOp) int {
	if (pullOp.Code() == CPUI_SPULL) != (extOp.Code() == CPUI_INT_SEXT) {
		return 0
	}
	vn := extOp.Input(0)
	if vn.LoneDescend() != extOp {
		return 0
	}
	data.OpSetOpcode(extOp, pullOp.Code())
	data.OpSetInput(extOp, pullOp.Input(0), 0)
	data.OpInsertInput(extOp, pullOp.Input(1), 1)
	data.OpInsertInput(extOp, pullOp.Input(2), 2)
	data.DestroyVarnodeRecursive(vn)
	return 1
}

// absorbSubpiece: SUB(PULL(x,#p,#n),0)  =>  PULL(x,#p,#n).
// C++ parity: RulePullAbsorb::absorbSubpiece.
func absorbSubpiece(data *Funcdata, subOp, pullOp *PcodeOp) int {
	if subOp.Input(1).Offset() != 0 {
		return 0
	}
	if bitsize := int32(pullOp.Input(2).Offset()); bitsize > 8*subOp.Output().Size() {
		return 0
	}
	vn := subOp.Input(0)
	if vn.LoneDescend() != subOp {
		return 0
	}
	data.OpSetOpcode(subOp, pullOp.Code())
	data.OpSetInput(subOp, pullOp.Input(0), 0)
	data.OpSetInput(subOp, pullOp.Input(1), 1)
	data.OpInsertInput(subOp, pullOp.Input(2), 2)
	data.DestroyVarnodeRecursive(vn)
	return 1
}

// absorbCompZero: ZPULL(x,#p,#1) != #0  =>  ZPULL(x,#p,#1), and the ==
// variant  =>  !ZPULL(x,#p,#1), for a boolean field.
// C++ parity: RulePullAbsorb::absorbCompZero.
func absorbCompZero(data *Funcdata, compOp, pullOp *PcodeOp) int {
	if !constantMatch(compOp.Input(1), 0) || pullOp.Input(2).Offset() != 1 {
		return 0
	}
	vn := compOp.Input(0)
	if vn.LoneDescend() != compOp || vn.IsAddrTied() || pullOp.Code() == CPUI_SPULL {
		return 0
	}
	field := getPullField(pullOp)
	if field == nil || field.Type.Metatype() != TYPE_BOOL {
		return 0
	}
	if compOp.Code() == CPUI_INT_EQUAL {
		if vn.Size() > 1 {
			smalladdr := vn.Addr()
			if vn.Space().BigEndian {
				smalladdr.Offset += uint64(vn.Size() - 1)
			}
			data.OpUnsetOutput(pullOp)
			newVn := data.NewVarnodeOut(1, smalladdr, pullOp)
			newVn.UpdateType(sharedTypeFactory.GetBase(1, TYPE_BOOL, ""))
			data.OpSetInput(compOp, newVn, 0)
			data.DeleteVarnode(vn)
		}
		data.OpSetOpcode(compOp, CPUI_BOOL_NEGATE)
		data.OpRemoveInput(compOp, 1)
	} else {
		data.OpSetOpcode(compOp, pullOp.Code())
		data.OpSetInput(compOp, pullOp.Input(0), 0)
		data.OpSetInput(compOp, pullOp.Input(1), 1)
		data.OpInsertInput(compOp, pullOp.Input(2), 2)
		data.DestroyVarnodeRecursive(vn)
	}
	return 1
}

// RuleInsertAbsorb simplifies expressions using INSERT.
// C++ parity: class RuleInsertAbsorb.
type RuleInsertAbsorb struct{ batchRule }

func NewRuleInsertAbsorb(group string) *RuleInsertAbsorb {
	r := &RuleInsertAbsorb{}
	r.batchRule = newBatchRule(group, "insert_absorb", []OpCode{CPUI_INSERT}, r.apply, func(g string) Rule { return NewRuleInsertAbsorb(g) })
	return r
}

// C++ parity: RuleInsertAbsorb::applyOp.
func (r *RuleInsertAbsorb) apply(op *PcodeOp, data *Funcdata) int {
	inVn := op.Input(1)
	if !inVn.IsWritten() {
		return 0
	}
	inOp := inVn.Def()
	switch inOp.Code() {
	case CPUI_SUBPIECE:
		if inOp.Input(1).Offset() != 0 {
			return 0
		}
		data.OpSetInput(op, inOp.Input(0), 1)
		data.DestroyVarnodeRecursive(inVn)
		return 1
	case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		if !inOp.Input(1).IsConstant() {
			return 0
		}
		vn := inOp.Input(0)
		if !vn.IsWritten() {
			return 0
		}
		nextOp := vn.Def()
		switch nextOp.Code() {
		case CPUI_INT_ADD:
			return absorbShiftAdd(data, inOp, nextOp, op)
		case CPUI_INT_LEFT, CPUI_SUBPIECE:
			return absorbRightLeft(data, nextOp, inOp, op)
		}
	case CPUI_INT_AND:
		return absorbInsertAnd(data, inOp, op)
	case CPUI_INT_ADD, CPUI_INT_OR, CPUI_INT_XOR, CPUI_INT_MULT:
		return absorbNestedAnd(data, inOp, op)
	}
	return 0
}

// leftShiftVarnode strips a left shift by sa (INT_LEFT or INT_MULT by a
// power of 2), or returns nil. C++ parity: RuleInsertAbsorb::leftShiftVarnode.
func leftShiftVarnode(vn *Varnode, sa int) *Varnode {
	if !vn.IsWritten() {
		return nil
	}
	multOp := vn.Def()
	multVal := multOp.Input(1)
	if !multVal.IsConstant() {
		return nil
	}
	var matchVal uint64
	switch multOp.Code() {
	case CPUI_INT_MULT:
		matchVal = uint64(1) << uint(sa)
	case CPUI_INT_LEFT:
		matchVal = uint64(sa)
	default:
		return nil
	}
	if multVal.Offset() != matchVal {
		return nil
	}
	return multOp.Input(0)
}

// absorbInsertAnd: INSERT(x & #mask,#p,#n)  =>  INSERT(x,#p,#n).
// C++ parity: RuleInsertAbsorb::absorbAnd.
func absorbInsertAnd(data *Funcdata, andOp, insertOp *PcodeOp) int {
	cvn := andOp.Input(1)
	if !cvn.IsConstant() {
		return 0
	}
	mask := insertLSBMask(insertOp)
	if mask&cvn.Offset() != mask { // the mask must keep the bits INSERTed
		return 0
	}
	data.OpSetInput(insertOp, andOp.Input(0), 1)
	data.DestroyVarnodeRecursive(andOp.Output())
	return 1
}

// absorbRightLeft: INSERT((x << #c) >> #c,#p,#n)  =>  INSERT(x,#p,#n), also
// through a SUBPIECE of the shift. C++ parity: RuleInsertAbsorb::absorbRightLeft.
func absorbRightLeft(data *Funcdata, nextOp, rightOp, insertOp *PcodeOp) int {
	var leftOp *PcodeOp
	switch nextOp.Code() {
	case CPUI_INT_LEFT:
		leftOp = nextOp
	case CPUI_SUBPIECE:
		if nextOp.Input(1).Offset() != 0 {
			return 0
		}
		subin := nextOp.Input(0)
		if !subin.IsWritten() {
			return 0
		}
		leftOp = subin.Def()
		if leftOp.Code() != CPUI_INT_LEFT {
			return 0
		}
	default:
		return 0
	}
	lvn, rvn := leftOp.Input(1), rightOp.Input(1)
	if !lvn.IsConstant() || !rvn.IsConstant() || lvn.Offset() != rvn.Offset() {
		return 0
	}
	lsa := int64(lvn.Offset())
	bitsize := int64(insertOp.Input(3).Offset())
	if bitsize > int64(insertOp.Input(1).Size())*8-lsa { // shifts cancel unless the field exceeds the bits kept
		return 0
	}
	data.OpSetInput(insertOp, leftOp.Input(0), 1)
	data.DestroyVarnodeRecursive(rightOp.Output())
	return 1
}

// absorbShiftAdd: field = (a * #c + b * #c) >> #n  =>  field = a + b.
// C++ parity: RuleInsertAbsorb::absorbShiftAdd.
func absorbShiftAdd(data *Funcdata, rightOp, addOp, insertOp *PcodeOp) int {
	sa := int(rightOp.Input(1).Offset())
	if sa <= 0 || sa >= 64 {
		return 0
	}
	vn0 := leftShiftVarnode(addOp.Input(0), sa)
	if vn0 == nil {
		return 0
	}
	var vn1 *Varnode
	addVn1 := addOp.Input(1)
	if addVn1.IsConstant() {
		addVal := addVn1.Offset() >> uint(sa)
		if addVal<<uint(sa) != addVn1.Offset() {
			return 0
		}
		vn1 = data.NewConstant(vn0.Size(), addVal)
		vn1.UpdateType(addVn1.Type())
	} else if vn1 = leftShiftVarnode(addVn1, sa); vn1 == nil {
		return 0
	}
	if bitsize := int(insertOp.Input(3).Offset()); bitsize > int(vn0.Size())*8-sa { // no carry bits reach the field
		return 0
	}
	data.OpSetOpcode(rightOp, CPUI_INT_ADD)
	data.OpSetInput(rightOp, vn0, 0)
	data.OpSetInput(rightOp, vn1, 1)
	data.DestroyVarnodeRecursive(addOp.Output())
	return 1
}

// absorbNestedAnd: INSERT((x & #0xff) + y)  =>  INSERT(x + y), for ops whose
// low result bits ignore the inputs' high bits.
// C++ parity: RuleInsertAbsorb::absorbNestedAnd.
func absorbNestedAnd(data *Funcdata, baseOp, insertOp *PcodeOp) int {
	if baseOp.Output().LoneDescend() != insertOp {
		return 0
	}
	for slot := 0; slot < 2; slot++ {
		vn := baseOp.Input(slot)
		if !vn.IsWritten() {
			continue
		}
		andOp := vn.Def()
		if andOp.Code() != CPUI_INT_AND {
			continue
		}
		cvn := andOp.Input(1)
		if !cvn.IsConstant() {
			continue
		}
		mask := coveringMask(cvn.Offset())
		if mask != cvn.Offset() || mask&1 == 0 {
			continue
		}
		if bits.OnesCount64(mask) < int(insertOp.Input(3).Offset()) { // the INSERT masks fewer bits
			continue
		}
		data.OpSetInput(baseOp, andOp.Input(0), slot)
		data.DestroyVarnodeRecursive(andOp.Output())
		return 1
	}
	return 0
}
