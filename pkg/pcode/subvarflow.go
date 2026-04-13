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
	"math/bits"

	"gosleigh/pkg/address"
)

// SubvariableFlow::ReplaceVarnode -- subflow.cc.
type subvariableFlowReplaceVarnode struct {
	vn          *Varnode
	replacement *Varnode
	mask        uint64
	val         uint64
	def         *subvariableFlowReplaceOp
}

// SubvariableFlow::ReplaceOp -- subflow.cc.
type subvariableFlowReplaceOp struct {
	op          *PcodeOp
	replacement *PcodeOp
	opc         OpCode
	numparams   int
	output      *subvariableFlowReplaceVarnode
	input       []*subvariableFlowReplaceVarnode
}

// SubvariableFlow::PatchRecord -- subflow.cc.
type subvariableFlowPatchRecord struct {
	kind    subvariableFlowPatchType
	patchOp *PcodeOp
	in1     *subvariableFlowReplaceVarnode
	in2     *subvariableFlowReplaceVarnode
	slot    int
}

// SubvariableFlow::PatchRecord::patchtype -- subflow.cc.
type subvariableFlowPatchType int

const (
	subvariableFlowCopyPatch subvariableFlowPatchType = iota
	subvariableFlowComparePatch
	subvariableFlowParameterPatch
	subvariableFlowExtensionPatch
	subvariableFlowPushPatch
	subvariableFlowInt2FloatPatch
)

// SubvariableFlow::SubvariableFlow -- subflow.cc.
type SubvariableFlow struct {
	flowsize         int32
	bitsize          int32
	returnsTraversed bool
	aggressive       bool
	sextrestrictions bool
	fd               *Funcdata
	varmap           map[*Varnode]*subvariableFlowReplaceVarnode
	newvarlist       []*subvariableFlowReplaceVarnode
	oplist           []*subvariableFlowReplaceOp
	patchlist        []subvariableFlowPatchRecord
	worklist         []*subvariableFlowReplaceVarnode
	pullcount        int32
}

// SubvariableFlow::doesOrSet -- subflow.cc.
func subvariableFlowDoesOrSet(orop *PcodeOp, mask uint64) int {
	if orop == nil || orop.NumInput() < 2 {
		return -1
	}
	index := 0
	if orop.Input(1).IsConstant() {
		index = 1
	}
	if !orop.Input(index).IsConstant() {
		return -1
	}
	orval := orop.Input(index).Offset()
	if (mask &^ orval) == 0 {
		return index
	}
	return -1
}

// SubvariableFlow::doesAndClear -- subflow.cc.
func subvariableFlowDoesAndClear(andop *PcodeOp, mask uint64) int {
	if andop == nil || andop.NumInput() < 2 {
		return -1
	}
	index := 0
	if andop.Input(1).IsConstant() {
		index = 1
	}
	if !andop.Input(index).IsConstant() {
		return -1
	}
	andval := andop.Input(index).Offset()
	if (mask & andval) == 0 {
		return index
	}
	return -1
}

// SubvariableFlow::setReplacement -- subflow.cc.
func (sf *SubvariableFlow) setReplacement(vn *Varnode, mask uint64) (*subvariableFlowReplaceVarnode, bool) {
	if vn == nil {
		return nil, false
	}
	if rep, ok := sf.varmap[vn]; ok {
		if rep.mask != mask {
			return nil, false
		}
		return rep, false
	}

	rep := &subvariableFlowReplaceVarnode{vn: vn, mask: mask}
	sf.varmap[vn] = rep
	vn.SetMark()

	inworklist := true
	if vn.IsConstant() {
		inworklist = false
		if sf.sextrestrictions && sf.flowsize < 8 {
			cval := vn.Offset()
			smallval := cval & mask
			signBit := uint64(1) << (uint(sf.flowsize)*8 - 1)
			sextval := smallval
			if smallval&signBit != 0 {
				sextval |= ^maskForSize(sf.flowsize)
			}
			if sextval != cval {
				return nil, false
			}
		}
		return sf.addConstant(nil, mask, 0, vn), false
	}

	if vn.IsFree() {
		return nil, false
	}
	if vn.IsAddrForce() && vn.Size() != sf.flowsize {
		return nil, false
	}

	if sf.sextrestrictions {
		if vn.Size() != sf.flowsize {
			if !sf.aggressive && vn.IsInput() {
				return nil, false
			}
			if vn.IsPersist() {
				return nil, false
			}
		}
		if vn.IsTypeLock() {
			if dt := vn.TypeReadFacing(nil); dt != nil && dt.Metatype() != TYPE_PARTIALSTRUCT && dt.Size() != sf.flowsize {
				return nil, false
			}
		}
	} else {
		if sf.bitsize >= 8 {
			if !sf.aggressive && (vn.Consumed()&^mask) != 0 {
				return nil, false
			}
			if vn.IsTypeLock() {
				if dt := vn.TypeReadFacing(nil); dt != nil && dt.Metatype() != TYPE_PARTIALSTRUCT && dt.Size() != sf.flowsize {
					return nil, false
				}
			}
		}
		if vn.IsInput() {
			if sf.bitsize < 8 {
				return nil, false
			}
			if (mask & 1) == 0 {
				return nil, false
			}
		}
	}

	if vn.Size() == sf.flowsize {
		if mask == maskForSize(sf.flowsize) {
			inworklist = false
			rep.replacement = vn
		} else if mask == 1 && vn.IsWritten() && vn.Def() != nil && vn.Def().IsBoolOutput() {
			inworklist = false
			rep.replacement = vn
		}
	}

	return rep, inworklist
}

// SubvariableFlow::createOp -- subflow.cc.
func (sf *SubvariableFlow) createOp(opc OpCode, numparam int, outrvn *subvariableFlowReplaceVarnode) *subvariableFlowReplaceOp {
	if outrvn.def != nil {
		return outrvn.def
	}
	rop := &subvariableFlowReplaceOp{op: outrvn.vn.Def(), opc: opc, numparams: numparam, output: outrvn}
	outrvn.def = rop
	sf.oplist = append(sf.oplist, rop)
	return rop
}

// SubvariableFlow::createOpDown -- subflow.cc.
func (sf *SubvariableFlow) createOpDown(opc OpCode, numparam int, op *PcodeOp, inrvn *subvariableFlowReplaceVarnode, slot int) *subvariableFlowReplaceOp {
	rop := &subvariableFlowReplaceOp{op: op, opc: opc, numparams: numparam}
	rop.input = make([]*subvariableFlowReplaceVarnode, 0, max(slot+1, numparam))
	for len(rop.input) <= slot {
		rop.input = append(rop.input, nil)
	}
	rop.input[slot] = inrvn
	sf.oplist = append(sf.oplist, rop)
	return rop
}

// SubvariableFlow::tryCallPull -- subflow.cc.
func (sf *SubvariableFlow) tryCallPull(op *PcodeOp, rvn *subvariableFlowReplaceVarnode, slot int) bool {
	// TODO known mismatch: call-spec classification is not yet ported to Gosleigh,
	// so the conservative behavior is to refuse call-site trimming rather than guess.
	_ = op
	_ = rvn
	_ = slot
	return false
}

// SubvariableFlow::tryReturnPull -- subflow.cc.
func (sf *SubvariableFlow) tryReturnPull(op *PcodeOp, rvn *subvariableFlowReplaceVarnode, slot int) bool {
	// TODO known mismatch: return-value classification is not yet ported to Gosleigh.
	_ = op
	_ = rvn
	_ = slot
	return false
}

// SubvariableFlow::tryCallReturnPush -- subflow.cc.
func (sf *SubvariableFlow) tryCallReturnPush(op *PcodeOp, rvn *subvariableFlowReplaceVarnode) bool {
	// TODO known mismatch: call return-spec handling is not yet ported to Gosleigh.
	_ = op
	_ = rvn
	return false
}

// SubvariableFlow::trySwitchPull -- subflow.cc.
func (sf *SubvariableFlow) trySwitchPull(op *PcodeOp, rvn *subvariableFlowReplaceVarnode) bool {
	// TODO known mismatch: jump-table analysis is not yet ported to Gosleigh.
	_ = op
	_ = rvn
	return false
}

// SubvariableFlow::tryInt2FloatPull -- subflow.cc.
func (sf *SubvariableFlow) tryInt2FloatPull(op *PcodeOp, rvn *subvariableFlowReplaceVarnode) bool {
	if rvn == nil || rvn.vn == nil || (rvn.mask&1) == 0 {
		return false
	}
	if (rvn.vn.NZMask() &^ rvn.mask) != 0 {
		return false
	}
	if rvn.vn.Size() == sf.flowsize {
		return false
	}
	pullModification := true
	if rvn.vn.IsWritten() && rvn.vn.Def() != nil && rvn.vn.Def().Code() == CPUI_INT_ZEXT {
		if rvn.vn.Size() == int32(preferredZextSizeFloatInt2Float(int(sf.flowsize))) && rvn.vn.LoneDescend() == op {
			pullModification = false
		}
	}
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowInt2FloatPatch, patchOp: op, in1: rvn})
	if pullModification {
		sf.pullcount++
	}
	return true
}

// SubvariableFlow::traceForward -- subflow.cc.
func (sf *SubvariableFlow) traceForward(rvn *subvariableFlowReplaceVarnode) bool {
	if rvn == nil || rvn.vn == nil {
		return false
	}
	var dcount, hcount, callcount int
	for _, op := range rvn.vn.DescendIter() {
		outvn := op.Output()
		if outvn != nil && outvn.IsMark() && !op.IsCall() {
			continue
		}
		dcount++
		slot := op.GetSlot(rvn.vn)
		switch op.Code() {
		case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INT_NEGATE, CPUI_INT_XOR:
			rop := sf.createOpDown(op.Code(), op.NumInput(), op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_OR:
			if subvariableFlowDoesOrSet(op, rvn.mask) != -1 {
				break
			}
			rop := sf.createOpDown(CPUI_INT_OR, 2, op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_AND:
			if op.NumInput() > 1 && op.Input(1).IsConstant() && op.Input(1).Offset() == rvn.mask {
				if outvn != nil && outvn.Size() == sf.flowsize && (rvn.mask&1) != 0 {
					sf.addTerminalPatch(op, rvn)
					hcount++
					break
				}
				if !sf.aggressive && outvn != nil && (outvn.Consumed()&rvn.mask) != outvn.Consumed() {
					sf.addExtensionPatch(rvn, op, -1)
					hcount++
					break
				}
			}
			if subvariableFlowDoesAndClear(op, rvn.mask) != -1 {
				break
			}
			rop := sf.createOpDown(CPUI_INT_AND, 2, op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_ZEXT, CPUI_INT_SEXT:
			rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_MULT:
			if (rvn.mask & 1) == 0 {
				return false
			}
			sa := bits.TrailingZeros64(op.Input(1-slot).NZMask()) &^ 7
			if sf.bitsize+int32(sa) > 8*rvn.vn.Size() {
				return false
			}
			rop := sf.createOpDown(CPUI_INT_MULT, 2, op, rvn, slot)
			if !sf.createLink(rop, rvn.mask<<uint(sa), -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_DIV, CPUI_INT_REM:
			if (rvn.mask&1) == 0 || (sf.bitsize&7) != 0 {
				return false
			}
			if (op.Input(0).NZMask()&^maskForSize(sf.flowsize)) != 0 || (op.Input(1).NZMask()&^maskForSize(sf.flowsize)) != 0 {
				return false
			}
			rop := sf.createOpDown(op.Code(), 2, op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_ADD:
			if (rvn.mask & 1) == 0 {
				return false
			}
			rop := sf.createOpDown(CPUI_INT_ADD, 2, op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_LEFT:
			if slot == 1 {
				if (rvn.mask&1) == 0 || sf.bitsize < 8 {
					return false
				}
				sf.addTerminalPatchSameOp(op, rvn, slot)
				hcount++
				break
			}
			if !op.Input(1).IsConstant() {
				return false
			}
			sa := int32(op.Input(1).Offset())
			if sa >= 64 {
				return false
			}
			newmask := (rvn.mask << uint(sa)) & maskForSize(outvn.Size())
			if newmask == 0 {
				break
			}
			if rvn.mask != (newmask >> uint(sa)) {
				return false
			}
			if (rvn.mask&1) != 0 && sa+sf.bitsize == 8*outvn.Size() && (outvn.Consumed()&^newmask) != 0 {
				sf.addExtensionPatch(rvn, op, int(sa))
				hcount++
				break
			}
			rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
			if !sf.createLink(rop, newmask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
			if slot == 1 {
				if (rvn.mask&1) == 0 || sf.bitsize < 8 {
					return false
				}
				sf.addTerminalPatchSameOp(op, rvn, slot)
				hcount++
				break
			}
			if !op.Input(1).IsConstant() {
				return false
			}
			sa := int32(op.Input(1).Offset())
			var newmask uint64
			if sa >= 64 {
				newmask = 0
			} else {
				newmask = rvn.mask >> uint(sa)
			}
			if newmask == 0 {
				if op.Code() == CPUI_INT_RIGHT {
					break
				}
				return false
			}
			if rvn.mask != (newmask << uint(sa)) {
				return false
			}
			if outvn != nil && outvn.Size() == sf.flowsize && (newmask&1) == 1 && op.Input(0).NZMask() == rvn.mask {
				sf.addTerminalPatch(op, rvn)
				hcount++
				break
			}
			if (newmask&1) == 1 && sa+sf.bitsize == 8*outvn.Size() && (outvn.Consumed()&^newmask) != 0 {
				sf.addExtensionPatch(rvn, op, 0)
				hcount++
				break
			}
			rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
			if !sf.createLink(rop, newmask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_SUBPIECE:
			sa := int32(op.Input(1).Offset()) * 8
			if sa >= 64 {
				break
			}
			newmask := (rvn.mask >> uint(sa)) & maskForSize(outvn.Size())
			if newmask == 0 {
				break
			}
			if rvn.mask != (newmask << uint(sa)) {
				if sf.flowsize > (int32(op.Input(1).Offset())+outvn.Size()) && (rvn.mask&1) != 0 {
					sf.addTerminalPatchSameOp(op, rvn, 0)
					hcount++
					break
				}
				return false
			}
			if (newmask&1) != 0 && outvn.Size() == sf.flowsize {
				sf.addTerminalPatch(op, rvn)
				hcount++
				break
			}
			rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
			if !sf.createLink(rop, newmask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_PIECE:
			if rvn.vn == op.Input(0) {
				rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
				if !sf.createLink(rop, rvn.mask<<uint(8*op.Input(1).Size()), -1, outvn) {
					return false
				}
			} else {
				rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
				if !sf.createLink(rop, rvn.mask, -1, outvn) {
					return false
				}
			}
			hcount++
		case CPUI_INT_LESS, CPUI_INT_LESSEQUAL:
			outvn = op.Input(1 - slot)
			if !sf.aggressive && ((rvn.vn.NZMask() | rvn.mask) != rvn.mask) {
				return false
			}
			if outvn.IsConstant() {
				if (rvn.mask | outvn.Offset()) != rvn.mask {
					return false
				}
			} else if !sf.aggressive && ((rvn.mask | outvn.NZMask()) != rvn.mask) {
				return false
			}
			if !sf.createCompareBridge(op, rvn, slot, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_NOTEQUAL, CPUI_INT_EQUAL:
			outvn = op.Input(1 - slot)
			if sf.bitsize != 1 {
				if !sf.aggressive && ((rvn.vn.NZMask() | rvn.mask) != rvn.mask) {
					return false
				}
				if outvn.IsConstant() {
					if (rvn.mask | outvn.Offset()) != rvn.mask {
						return false
					}
				} else if !sf.aggressive && ((rvn.mask | outvn.NZMask()) != rvn.mask) {
					return false
				}
				if !sf.createCompareBridge(op, rvn, slot, outvn) {
					return false
				}
			} else {
				if !outvn.IsConstant() {
					return false
				}
				newmask := rvn.vn.NZMask()
				if newmask != rvn.mask {
					return false
				}
				booldir := false
				switch op.Input(1 - slot).Offset() {
				case 0:
					booldir = true
				case newmask:
					booldir = false
				default:
					return false
				}
				if op.Code() == CPUI_INT_EQUAL {
					booldir = !booldir
				}
				if booldir {
					sf.addTerminalPatch(op, rvn)
				} else {
					rop := sf.createOpDown(CPUI_BOOL_NEGATE, 1, op, rvn, 0)
					sf.createNewOut(rop, 1)
					sf.addTerminalPatch(op, rop.output)
				}
			}
			hcount++
		case CPUI_CALL, CPUI_CALLIND:
			callcount++
			if !sf.tryCallPull(op, rvn, slot) {
				return false
			}
			hcount++
		case CPUI_RETURN:
			if !sf.tryReturnPull(op, rvn, slot) {
				return false
			}
			hcount++
		case CPUI_BRANCHIND:
			if !sf.trySwitchPull(op, rvn) {
				return false
			}
			hcount++
		case CPUI_BOOL_NEGATE, CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_BOOL_XOR:
			if sf.bitsize != 1 || rvn.mask != 1 {
				return false
			}
			sf.addBooleanPatch(op, rvn, slot)
		case CPUI_FLOAT_INT2FLOAT:
			if !sf.tryInt2FloatPull(op, rvn) {
				return false
			}
			hcount++
		case CPUI_CBRANCH:
			if sf.bitsize != 1 || slot != 1 || rvn.mask != 1 {
				return false
			}
			sf.addBooleanPatch(op, rvn, 1)
			hcount++
		default:
			return false
		}
		_ = callcount
	}
	if dcount != hcount && rvn.vn.IsInput() {
		return false
	}
	return true
}

// SubvariableFlow::traceBackward -- subflow.cc.
func (sf *SubvariableFlow) traceBackward(rvn *subvariableFlowReplaceVarnode) bool {
	if rvn == nil || rvn.vn == nil {
		return false
	}
	op := rvn.vn.Def()
	if op == nil {
		return true
	}
	switch op.Code() {
	case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INT_NEGATE, CPUI_INT_XOR:
		rop := sf.createOp(op.Code(), op.NumInput(), rvn)
		for i := 0; i < op.NumInput(); i++ {
			if !sf.createLink(rop, rvn.mask, i, op.Input(i)) {
				return false
			}
		}
		return true
	case CPUI_INT_AND:
		if sa := subvariableFlowDoesAndClear(op, rvn.mask); sa != -1 {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			sf.addConstant(rop, rvn.mask, 0, op.Input(sa))
		} else {
			rop := sf.createOp(CPUI_INT_AND, 2, rvn)
			if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
				return false
			}
			if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
				return false
			}
		}
		return true
	case CPUI_INT_OR:
		if sa := subvariableFlowDoesOrSet(op, rvn.mask); sa != -1 {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			sf.addConstant(rop, rvn.mask, 0, op.Input(sa))
		} else {
			rop := sf.createOp(CPUI_INT_OR, 2, rvn)
			if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
				return false
			}
			if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
				return false
			}
		}
		return true
	case CPUI_INT_ZEXT, CPUI_INT_SEXT:
		if (rvn.mask & maskForSize(op.Input(0).Size())) != rvn.mask {
			if (rvn.mask&1) != 0 && sf.flowsize > op.Input(0).Size() {
				sf.addPush(op, rvn)
				return true
			}
			return false
		}
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		return true
	case CPUI_INT_ADD:
		if (rvn.mask & 1) == 0 {
			return false
		}
		if rvn.mask == 1 {
			rop := sf.createOp(CPUI_INT_XOR, 2, rvn)
			if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
				return false
			}
			if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
				return false
			}
			return true
		}
		rop := sf.createOp(CPUI_INT_ADD, 2, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
			return false
		}
		return true
	case CPUI_INT_LEFT:
		if !op.Input(1).IsConstant() {
			return false
		}
		sa := int32(op.Input(1).Offset())
		var newmask uint64
		if sa >= 64 {
			newmask = 0
		} else {
			newmask = rvn.mask >> uint(sa)
		}
		if newmask == 0 {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			sf.addNewConstant(rop, 0, 0)
			return true
		}
		if (newmask << uint(sa)) == rvn.mask {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			if !sf.createLink(rop, newmask, 0, op.Input(0)) {
				return false
			}
			return true
		}
		if (rvn.mask & 1) == 0 {
			return false
		}
		rop := sf.createOp(CPUI_INT_LEFT, 2, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		sf.addConstant(rop, maskForSize(op.Input(1).Size()), 1, op.Input(1))
		return true
	case CPUI_INT_RIGHT:
		if !op.Input(1).IsConstant() {
			return false
		}
		sa := int32(op.Input(1).Offset())
		if sa >= 64 {
			return false
		}
		newmask := (rvn.mask << uint(sa)) & maskForSize(op.Input(0).Size())
		if newmask == 0 {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			sf.addNewConstant(rop, 0, 0)
			return true
		}
		if (newmask >> uint(sa)) != rvn.mask {
			return false
		}
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		if !sf.createLink(rop, newmask, 0, op.Input(0)) {
			return false
		}
		return true
	case CPUI_INT_SRIGHT:
		if !op.Input(1).IsConstant() {
			return false
		}
		sa := int32(op.Input(1).Offset())
		if sa >= 64 {
			return false
		}
		newmask := (rvn.mask << uint(sa)) & maskForSize(op.Input(0).Size())
		if (newmask >> uint(sa)) != rvn.mask {
			return false
		}
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		if !sf.createLink(rop, newmask, 0, op.Input(0)) {
			return false
		}
		return true
	case CPUI_INT_MULT:
		sa := bits.TrailingZeros64(rvn.mask)
		if sa != 0 {
			sa2 := bits.TrailingZeros64(op.Input(1).NZMask())
			if sa2 < sa {
				return false
			}
			newmask := rvn.mask >> uint(sa)
			rop := sf.createOp(CPUI_INT_MULT, 2, rvn)
			if !sf.createLink(rop, newmask, 0, op.Input(0)) {
				return false
			}
			if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
				return false
			}
		} else {
			if rvn.mask == 1 {
				rop := sf.createOp(CPUI_INT_AND, 2, rvn)
				if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
					return false
				}
				if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
					return false
				}
			} else {
				rop := sf.createOp(CPUI_INT_MULT, 2, rvn)
				if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
					return false
				}
				if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
					return false
				}
			}
		}
		return true
	case CPUI_INT_DIV, CPUI_INT_REM:
		if (rvn.mask&1) == 0 || (sf.bitsize&7) != 0 {
			return false
		}
		if (op.Input(0).NZMask()&^maskForSize(sf.flowsize)) != 0 || (op.Input(1).NZMask()&^maskForSize(sf.flowsize)) != 0 {
			return false
		}
		rop := sf.createOp(op.Code(), 2, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		if !sf.createLink(rop, rvn.mask, 1, op.Input(1)) {
			return false
		}
		return true
	case CPUI_SUBPIECE:
		sa := int32(op.Input(1).Offset()) * 8
		newmask := rvn.mask << uint(sa)
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		if !sf.createLink(rop, newmask, 0, op.Input(0)) {
			return false
		}
		return true
	case CPUI_PIECE:
		if rvn.mask&maskForSize(op.Input(1).Size()) == rvn.mask {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			if !sf.createLink(rop, rvn.mask, 0, op.Input(1)) {
				return false
			}
			return true
		}
		sa := op.Input(1).Size() * 8
		newmask := rvn.mask >> uint(sa)
		if newmask<<uint(sa) == rvn.mask {
			rop := sf.createOp(CPUI_COPY, 1, rvn)
			if !sf.createLink(rop, newmask, 0, op.Input(0)) {
				return false
			}
			return true
		}
		return false
	case CPUI_CALL, CPUI_CALLIND:
		if sf.tryCallReturnPush(op, rvn) {
			return true
		}
		return false
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW, CPUI_BOOL_NEGATE, CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR, CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN:
		if (rvn.mask & 1) == 1 {
			return false
		}
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		sf.addNewConstant(rop, 0, 0)
		return true
	default:
		return false
	}
}

// SubvariableFlow::traceForwardSext -- subflow.cc.
func (sf *SubvariableFlow) traceForwardSext(rvn *subvariableFlowReplaceVarnode) bool {
	if rvn == nil || rvn.vn == nil {
		return false
	}
	var dcount, hcount, callcount int
	for _, op := range rvn.vn.DescendIter() {
		outvn := op.Output()
		if outvn != nil && outvn.IsMark() && !op.IsCall() {
			continue
		}
		dcount++
		slot := op.GetSlot(rvn.vn)
		switch op.Code() {
		case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_OR, CPUI_INT_AND:
			rop := sf.createOpDown(op.Code(), op.NumInput(), op, rvn, slot)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_SEXT:
			rop := sf.createOpDown(CPUI_COPY, 1, op, rvn, 0)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			hcount++
		case CPUI_INT_SRIGHT:
			if !op.Input(1).IsConstant() {
				return false
			}
			rop := sf.createOpDown(CPUI_INT_SRIGHT, 2, op, rvn, 0)
			if !sf.createLink(rop, rvn.mask, -1, outvn) {
				return false
			}
			sf.addConstant(rop, maskForSize(op.Input(1).Size()), 1, op.Input(1))
			hcount++
		case CPUI_SUBPIECE:
			if op.Input(1).Offset() != 0 || outvn.Size() > sf.flowsize {
				return false
			}
			if outvn.Size() == sf.flowsize {
				sf.addTerminalPatch(op, rvn)
			} else {
				sf.addTerminalPatchSameOp(op, rvn, 0)
			}
			hcount++
		case CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			outvn = op.Input(1 - slot)
			if !sf.createCompareBridge(op, rvn, slot, outvn) {
				return false
			}
			hcount++
		case CPUI_CALL, CPUI_CALLIND:
			callcount++
			if !sf.tryCallPull(op, rvn, slot) {
				return false
			}
			hcount++
		case CPUI_RETURN:
			if !sf.tryReturnPull(op, rvn, slot) {
				return false
			}
			hcount++
		case CPUI_BRANCHIND:
			if !sf.trySwitchPull(op, rvn) {
				return false
			}
			hcount++
		default:
			return false
		}
		_ = callcount
	}
	if dcount != hcount && rvn.vn.IsInput() {
		return false
	}
	return true
}

// SubvariableFlow::traceBackwardSext -- subflow.cc.
func (sf *SubvariableFlow) traceBackwardSext(rvn *subvariableFlowReplaceVarnode) bool {
	if rvn == nil || rvn.vn == nil {
		return false
	}
	op := rvn.vn.Def()
	if op == nil {
		return true
	}
	switch op.Code() {
	case CPUI_COPY, CPUI_MULTIEQUAL, CPUI_INT_NEGATE, CPUI_INT_XOR, CPUI_INT_AND, CPUI_INT_OR:
		rop := sf.createOp(op.Code(), op.NumInput(), rvn)
		for i := 0; i < op.NumInput(); i++ {
			if !sf.createLink(rop, rvn.mask, i, op.Input(i)) {
				return false
			}
		}
		return true
	case CPUI_INT_ZEXT:
		if op.Input(0).Size() < sf.flowsize {
			sf.addPush(op, rvn)
			return true
		}
		return false
	case CPUI_INT_SEXT:
		if sf.flowsize != op.Input(0).Size() {
			return false
		}
		rop := sf.createOp(CPUI_COPY, 1, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		return true
	case CPUI_INT_SRIGHT:
		if !op.Input(1).IsConstant() {
			return false
		}
		rop := sf.createOp(CPUI_INT_SRIGHT, 2, rvn)
		if !sf.createLink(rop, rvn.mask, 0, op.Input(0)) {
			return false
		}
		sf.addConstant(rop, maskForSize(op.Input(1).Size()), 1, op.Input(1))
		return true
	case CPUI_CALL, CPUI_CALLIND:
		if sf.tryCallReturnPush(op, rvn) {
			return true
		}
		return false
	default:
		return false
	}
}

// SubvariableFlow::createLink -- subflow.cc.
func (sf *SubvariableFlow) createLink(rop *subvariableFlowReplaceOp, mask uint64, slot int, vn *Varnode) bool {
	rep, inworklist := sf.setReplacement(vn, mask)
	if rep == nil {
		return false
	}
	if rop != nil {
		if slot == -1 {
			rop.output = rep
			rep.def = rop
		} else {
			for len(rop.input) <= slot {
				rop.input = append(rop.input, nil)
			}
			rop.input[slot] = rep
		}
	}
	if inworklist {
		sf.worklist = append(sf.worklist, rep)
	}
	return true
}

// SubvariableFlow::createCompareBridge -- subflow.cc.
func (sf *SubvariableFlow) createCompareBridge(op *PcodeOp, inrvn *subvariableFlowReplaceVarnode, slot int, othervn *Varnode) bool {
	rep, inworklist := sf.setReplacement(othervn, inrvn.mask)
	if rep == nil {
		return false
	}
	if slot == 0 {
		sf.addComparePatch(inrvn, rep, op)
	} else {
		sf.addComparePatch(rep, inrvn, op)
	}
	if inworklist {
		sf.worklist = append(sf.worklist, rep)
	}
	return true
}

// SubvariableFlow::addConstant -- subflow.cc.
func (sf *SubvariableFlow) addConstant(rop *subvariableFlowReplaceOp, mask uint64, slot int, constvn *Varnode) *subvariableFlowReplaceVarnode {
	res := &subvariableFlowReplaceVarnode{vn: constvn, mask: mask}
	sa := bits.TrailingZeros64(mask)
	res.val = (mask & constvn.Offset()) >> uint(sa)
	if rop != nil {
		for len(rop.input) <= slot {
			rop.input = append(rop.input, nil)
		}
		rop.input[slot] = res
	}
	sf.newvarlist = append(sf.newvarlist, res)
	return res
}

// SubvariableFlow::addNewConstant -- subflow.cc.
func (sf *SubvariableFlow) addNewConstant(rop *subvariableFlowReplaceOp, slot int, val uint64) *subvariableFlowReplaceVarnode {
	res := &subvariableFlowReplaceVarnode{val: val}
	if rop != nil {
		for len(rop.input) <= slot {
			rop.input = append(rop.input, nil)
		}
		rop.input[slot] = res
	}
	sf.newvarlist = append(sf.newvarlist, res)
	return res
}

// SubvariableFlow::createNewOut -- subflow.cc.
func (sf *SubvariableFlow) createNewOut(rop *subvariableFlowReplaceOp, mask uint64) {
	res := &subvariableFlowReplaceVarnode{mask: mask}
	rop.output = res
	res.def = rop
	sf.newvarlist = append(sf.newvarlist, res)
}

// SubvariableFlow::addPush -- subflow.cc.
func (sf *SubvariableFlow) addPush(pushOp *PcodeOp, rvn *subvariableFlowReplaceVarnode) {
	sf.patchlist = append([]subvariableFlowPatchRecord{{kind: subvariableFlowPushPatch, patchOp: pushOp, in1: rvn}}, sf.patchlist...)
}

// SubvariableFlow::addTerminalPatch -- subflow.cc.
func (sf *SubvariableFlow) addTerminalPatch(pullop *PcodeOp, rvn *subvariableFlowReplaceVarnode) {
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowCopyPatch, patchOp: pullop, in1: rvn})
	sf.pullcount++
}

// SubvariableFlow::addTerminalPatchSameOp -- subflow.cc.
func (sf *SubvariableFlow) addTerminalPatchSameOp(pullop *PcodeOp, rvn *subvariableFlowReplaceVarnode, slot int) {
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowParameterPatch, patchOp: pullop, in1: rvn, slot: slot})
	sf.pullcount++
}

// SubvariableFlow::addBooleanPatch -- subflow.cc.
func (sf *SubvariableFlow) addBooleanPatch(pullop *PcodeOp, rvn *subvariableFlowReplaceVarnode, slot int) {
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowParameterPatch, patchOp: pullop, in1: rvn, slot: slot})
}

// SubvariableFlow::addExtensionPatch -- subflow.cc.
func (sf *SubvariableFlow) addExtensionPatch(rvn *subvariableFlowReplaceVarnode, pushop *PcodeOp, sa int) {
	if sa == -1 {
		sa = bits.TrailingZeros64(rvn.mask)
	}
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowExtensionPatch, patchOp: pushop, in1: rvn, slot: sa})
}

// SubvariableFlow::addComparePatch -- subflow.cc.
func (sf *SubvariableFlow) addComparePatch(in1, in2 *subvariableFlowReplaceVarnode, op *PcodeOp) {
	sf.patchlist = append(sf.patchlist, subvariableFlowPatchRecord{kind: subvariableFlowComparePatch, patchOp: op, in1: in1, in2: in2})
	sf.pullcount++
}

// SubvariableFlow::replaceInput -- subflow.cc.
func (sf *SubvariableFlow) replaceInput(rvn *subvariableFlowReplaceVarnode) {
	newvn := sf.fd.GetVarnodeBank().CreateUnique(rvn.vn.Size())
	newvn = sf.fd.SetInputVarnode(newvn)
	sf.fd.TotalReplace(rvn.vn, newvn)
	sf.fd.DeleteVarnode(rvn.vn)
	rvn.vn = newvn
}

// SubvariableFlow::useSameAddress -- subflow.cc.
func (sf *SubvariableFlow) useSameAddress(rvn *subvariableFlowReplaceVarnode) bool {
	if rvn.vn.IsInput() {
		return true
	}
	if rvn.vn.IsAddrTied() || (rvn.mask&1) == 0 {
		return false
	}
	if sf.bitsize >= 8 || sf.aggressive {
		return true
	}
	bitmask := uint64(1<<uint(sf.bitsize)) - 1
	mask := rvn.vn.Consumed() | bitmask
	return mask == rvn.mask
}

// SubvariableFlow::getReplacementAddress -- subflow.cc.
func (sf *SubvariableFlow) getReplacementAddress(rvn *subvariableFlowReplaceVarnode) address.Address {
	addr := rvn.vn.Addr()
	sa := bits.TrailingZeros64(rvn.mask) / 8
	if addr.Space != nil && addr.Space.BigEndian {
		addr = addr.Add(uint64(rvn.vn.Size() - sf.flowsize - int32(sa)))
	} else {
		addr = addr.Add(uint64(sa))
	}
	addr.Renormalize(sf.flowsize)
	return addr
}

// SubvariableFlow::getReplaceVarnode -- subflow.cc.
func (sf *SubvariableFlow) getReplaceVarnode(rvn *subvariableFlowReplaceVarnode) *Varnode {
	if rvn == nil {
		return nil
	}
	if rvn.replacement != nil {
		return rvn.replacement
	}
	if rvn.vn == nil {
		if rvn.def == nil {
			return sf.fd.NewConstant(sf.flowsize, rvn.val)
		}
		rvn.replacement = sf.fd.GetVarnodeBank().CreateUnique(sf.flowsize)
		return rvn.replacement
	}
	if rvn.vn.IsConstant() {
		return sf.fd.NewConstant(sf.flowsize, rvn.val)
	}
	isinput := rvn.vn.IsInput()
	if sf.useSameAddress(rvn) {
		addr := sf.getReplacementAddress(rvn)
		if isinput {
			sf.replaceInput(rvn)
		}
		rvn.replacement = sf.fd.NewVarnode(sf.flowsize, addr)
	} else {
		rvn.replacement = sf.fd.GetVarnodeBank().CreateUnique(sf.flowsize)
	}
	if isinput {
		rvn.replacement = sf.fd.SetInputVarnode(rvn.replacement)
	}
	return rvn.replacement
}

// SubvariableFlow::processNextWork -- subflow.cc.
func (sf *SubvariableFlow) processNextWork() bool {
	rvn := sf.worklist[len(sf.worklist)-1]
	sf.worklist = sf.worklist[:len(sf.worklist)-1]
	if sf.sextrestrictions {
		if !sf.traceBackwardSext(rvn) {
			return false
		}
		return sf.traceForwardSext(rvn)
	}
	if !sf.traceBackward(rvn) {
		return false
	}
	return sf.traceForward(rvn)
}

// SubvariableFlow::SubvariableFlow -- subflow.cc.
func NewSubvariableFlow(f *Funcdata, root *Varnode, mask uint64, aggr, sext, big bool) *SubvariableFlow {
	sf := &SubvariableFlow{fd: f, aggressive: aggr, sextrestrictions: sext, varmap: make(map[*Varnode]*subvariableFlowReplaceVarnode)}
	if mask == 0 {
		sf.fd = nil
		return sf
	}
	sfbits := bits.Len64(mask)
	if sfbits == 0 {
		sf.fd = nil
		return sf
	}
	sf.bitsize = int32(sfbits - bits.TrailingZeros64(mask))
	switch {
	case sf.bitsize <= 8:
		sf.flowsize = 1
	case sf.bitsize <= 16:
		sf.flowsize = 2
	case sf.bitsize <= 24:
		sf.flowsize = 3
	case sf.bitsize <= 32:
		sf.flowsize = 4
	case sf.bitsize <= 64:
		if !big {
			sf.fd = nil
			return sf
		}
		sf.flowsize = 8
	default:
		sf.fd = nil
		return sf
	}
	sf.createLink(nil, mask, 0, root)
	return sf
}

// SubvariableFlow::doTrace -- subflow.cc.
func (sf *SubvariableFlow) DoTrace() bool {
	sf.pullcount = 0
	retval := false
	if sf.fd != nil {
		retval = true
		for len(sf.worklist) > 0 {
			if !sf.processNextWork() {
				retval = false
				break
			}
		}
	}
	for _, rep := range sf.varmap {
		if rep != nil && rep.vn != nil {
			rep.vn.ClearMark()
		}
	}
	if !retval || sf.pullcount == 0 {
		return false
	}
	return true
}

// SubvariableFlow::doReplacement -- subflow.cc.
func (sf *SubvariableFlow) DoReplacement() {
	piter := 0
	for piter < len(sf.patchlist) && sf.patchlist[piter].kind == subvariableFlowPushPatch {
		pushOp := sf.patchlist[piter].patchOp
		newVn := sf.getReplaceVarnode(sf.patchlist[piter].in1)
		oldVn := pushOp.Output()
		sf.fd.OpSetOutput(pushOp, newVn)
		newZext := sf.fd.NewOp(1, pushOp.Addr())
		sf.fd.OpSetOpcode(newZext, CPUI_INT_ZEXT)
		sf.fd.OpSetInput(newZext, newVn, 0)
		sf.fd.OpSetOutput(newZext, oldVn)
		sf.fd.OpInsertAfter(newZext, pushOp)
		piter++
	}

	for _, rop := range sf.oplist {
		newop := sf.fd.NewOp(rop.numparams, rop.op.Addr())
		rop.replacement = newop
		sf.fd.OpSetOpcode(newop, rop.opc)
		sf.fd.OpSetOutput(newop, sf.getReplaceVarnode(rop.output))
		sf.fd.OpInsertAfter(newop, rop.op)
	}

	for _, rop := range sf.oplist {
		newop := rop.replacement
		for i, rvn := range rop.input {
			if rvn != nil {
				sf.fd.OpSetInput(newop, sf.getReplaceVarnode(rvn), i)
			}
		}
	}

	for ; piter < len(sf.patchlist); piter++ {
		p := sf.patchlist[piter]
		pullop := p.patchOp
		switch p.kind {
		case subvariableFlowCopyPatch:
			for pullop.NumInput() > 1 {
				sf.fd.OpRemoveInput(pullop, pullop.NumInput()-1)
			}
			sf.fd.OpSetInput(pullop, sf.getReplaceVarnode(p.in1), 0)
			sf.fd.OpSetOpcode(pullop, CPUI_COPY)
		case subvariableFlowComparePatch:
			sf.fd.OpSetInput(pullop, sf.getReplaceVarnode(p.in1), 0)
			sf.fd.OpSetInput(pullop, sf.getReplaceVarnode(p.in2), 1)
		case subvariableFlowParameterPatch:
			sf.fd.OpSetInput(pullop, sf.getReplaceVarnode(p.in1), p.slot)
		case subvariableFlowExtensionPatch:
			sa := p.slot
			inVn := sf.getReplaceVarnode(p.in1)
			outSize := pullop.Output().Size()
			if sa == 0 {
				opc := CPUI_INT_ZEXT
				if inVn.Size() == outSize {
					opc = CPUI_COPY
				}
				sf.fd.OpSetOpcode(pullop, opc)
				sf.fd.OpSetAllInput(pullop, []*Varnode{inVn})
			} else {
				inputs := []*Varnode{}
				if inVn.Size() != outSize {
					zextop := sf.fd.NewOp(1, pullop.Addr())
					sf.fd.OpSetOpcode(zextop, CPUI_INT_ZEXT)
					zextout := sf.fd.NewUniqueOut(outSize, zextop)
					sf.fd.OpSetInput(zextop, inVn, 0)
					sf.fd.OpInsertBefore(zextop, pullop)
					inputs = append(inputs, zextout)
				} else {
					inputs = append(inputs, inVn)
				}
				inputs = append(inputs, sf.fd.NewConstant(4, uint64(sa)))
				sf.fd.OpSetAllInput(pullop, inputs)
				sf.fd.OpSetOpcode(pullop, CPUI_INT_LEFT)
			}
		case subvariableFlowPushPatch:
		case subvariableFlowInt2FloatPatch:
			zextOp := sf.fd.NewOp(1, pullop.Addr())
			sf.fd.OpSetOpcode(zextOp, CPUI_INT_ZEXT)
			invn := sf.getReplaceVarnode(p.in1)
			sf.fd.OpSetInput(zextOp, invn, 0)
			sizeout := int32(preferredZextSizeFloatInt2Float(int(invn.Size())))
			outvn := sf.fd.NewUniqueOut(sizeout, zextOp)
			sf.fd.OpInsertBefore(zextOp, pullop)
			sf.fd.OpSetInput(pullop, outvn, 0)
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
