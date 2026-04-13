/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pcode

import "gosleigh/pkg/address"

// SplitVarnode is the Go port of ghidra::SplitVarnode in double.cc.
// This scaffold keeps the hi/lo pair together and implements the pieces
// needed by the double-precision rules in Gosleigh.
type SplitVarnode struct {
	lo        *Varnode
	hi        *Varnode
	whole     *Varnode
	defpoint  *PcodeOp
	defblock  *BlockBasic
	val       uint64
	wholesize int32
}

func (sv *SplitVarnode) initPartial(sz int32, v uint64) {
	sv.lo = nil
	sv.hi = nil
	sv.whole = nil
	sv.defpoint = nil
	sv.defblock = nil
	sv.val = v
	sv.wholesize = sz
}

func (sv *SplitVarnode) initPartialPieces(sz int32, l *Varnode, h *Varnode) {
	sv.whole = nil
	sv.defpoint = nil
	sv.defblock = nil
	sv.wholesize = sz
	if l != nil && l.IsConstant() && (h == nil || h.IsConstant()) {
		sv.lo = nil
		sv.hi = nil
		if h == nil {
			sv.val = l.Offset()
			return
		}
		sv.val = h.Offset()
		sv.val <<= uint(l.Size() * 8)
		sv.val |= l.Offset()
		return
	}
	sv.lo = l
	sv.hi = h
}

func (sv *SplitVarnode) initAll(w *Varnode, l *Varnode, h *Varnode) {
	if w != nil {
		sv.wholesize = w.Size()
	} else if l != nil && h != nil {
		sv.wholesize = l.Size() + h.Size()
	}
	sv.whole = w
	sv.lo = l
	sv.hi = h
	sv.defpoint = nil
	sv.defblock = nil
}

func (sv *SplitVarnode) isConstant() bool { return sv.lo == nil }

func (sv *SplitVarnode) hasBothPieces() bool { return sv.lo != nil && sv.hi != nil }

func (sv *SplitVarnode) getSize() int32 { return sv.wholesize }

func (sv *SplitVarnode) getLo() *Varnode { return sv.lo }

func (sv *SplitVarnode) getHi() *Varnode { return sv.hi }

func (sv *SplitVarnode) getWhole() *Varnode { return sv.whole }

func (sv *SplitVarnode) getDefPoint() *PcodeOp { return sv.defpoint }

func (sv *SplitVarnode) getDefBlock() *BlockBasic { return sv.defblock }

func (sv *SplitVarnode) getValue() uint64 { return sv.val }

func (sv *SplitVarnode) inHandHi(h *Varnode) bool {
	if h == nil || !h.IsPrecisHi() || !h.IsWritten() {
		return false
	}
	def := h.Def()
	if def == nil || def.Code() != CPUI_SUBPIECE || def.NumInput() < 2 || def.Input(1) == nil {
		return false
	}
	whole := def.Input(0)
	if def.Input(1).Offset() != uint64(whole.Size()-h.Size()) {
		return false
	}
	for _, op := range whole.DescendIter() {
		if op == nil || op.Code() != CPUI_SUBPIECE || op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		lo := op.Output()
		if lo == nil || !lo.IsPrecisLo() || lo.Size()+h.Size() != whole.Size() {
			continue
		}
		if op.Input(1).Offset() != 0 {
			continue
		}
		sv.initAll(whole, lo, h)
		return true
	}
	return false
}

func (sv *SplitVarnode) inHandLo(l *Varnode) bool {
	if l == nil || !l.IsPrecisLo() || !l.IsWritten() {
		return false
	}
	def := l.Def()
	if def == nil || def.Code() != CPUI_SUBPIECE || def.NumInput() < 2 || def.Input(1) == nil {
		return false
	}
	whole := def.Input(0)
	if def.Input(1).Offset() != 0 {
		return false
	}
	for _, op := range whole.DescendIter() {
		if op == nil || op.Code() != CPUI_SUBPIECE || op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		hi := op.Output()
		if hi == nil || !hi.IsPrecisHi() || hi.Size()+l.Size() != whole.Size() {
			continue
		}
		if op.Input(1).Offset() != uint64(l.Size()) {
			continue
		}
		sv.initAll(whole, l, hi)
		return true
	}
	return false
}

func (sv *SplitVarnode) inHandLoNoHi(l *Varnode) bool {
	if l == nil || !l.IsPrecisLo() || !l.IsWritten() {
		return false
	}
	def := l.Def()
	if def == nil || def.Code() != CPUI_SUBPIECE || def.NumInput() < 2 || def.Input(1) == nil || def.Input(1).Offset() != 0 {
		return false
	}
	sv.whole = def.Input(0)
	sv.lo = l
	sv.hi = nil
	sv.wholesize = sv.whole.Size()
	return true
}

func (sv *SplitVarnode) inHandHiOut(h *Varnode) bool {
	if h == nil || !h.IsPrecisHi() {
		return false
	}
	for _, op := range h.DescendIter() {
		if op == nil || op.Code() != CPUI_PIECE || op.NumInput() < 2 || op.Input(0) != h {
			continue
		}
		lo := op.Input(1)
		if lo == nil || !lo.IsPrecisLo() {
			continue
		}
		sv.initAll(op.Output(), lo, h)
		return true
	}
	return false
}

func (sv *SplitVarnode) inHandLoOut(l *Varnode) bool {
	if l == nil || !l.IsPrecisLo() {
		return false
	}
	for _, op := range l.DescendIter() {
		if op == nil || op.Code() != CPUI_PIECE || op.NumInput() < 2 || op.Input(1) != l {
			continue
		}
		hi := op.Input(0)
		if hi == nil || !hi.IsPrecisHi() {
			continue
		}
		sv.initAll(op.Output(), l, hi)
		return true
	}
	return false
}

func (sv *SplitVarnode) findWholeSplitToPieces() bool {
	if sv.whole != nil || sv.hi == nil || sv.lo == nil {
		return sv.whole != nil
	}
	if !sv.hi.IsWritten() || !sv.lo.IsWritten() {
		return false
	}
	hiDef := sv.hi.Def()
	loDef := sv.lo.Def()
	if hiDef == nil || loDef == nil || hiDef.Code() != CPUI_SUBPIECE || loDef.Code() != CPUI_SUBPIECE {
		return false
	}
	if hiDef.NumInput() < 2 || loDef.NumInput() < 2 || hiDef.Input(1) == nil || loDef.Input(1) == nil {
		return false
	}
	if hiDef.Input(1).Offset() != uint64(sv.wholesize-sv.hi.Size()) {
		return false
	}
	if loDef.Input(1).Offset() != 0 || hiDef.Input(0) != loDef.Input(0) {
		return false
	}
	sv.whole = hiDef.Input(0)
	return true
}

func (sv *SplitVarnode) findDefinitionPoint() bool {
	if sv.isConstant() {
		return true
	}
	if sv.lo == nil {
		return false
	}
	if sv.hi == nil {
		if sv.lo.IsInput() {
			sv.defpoint = nil
			sv.defblock = nil
			return true
		}
		if !sv.lo.IsWritten() {
			return false
		}
		sv.defpoint = sv.lo.Def()
		if sv.defpoint != nil {
			sv.defblock = sv.defpoint.Parent()
		}
		return sv.defpoint != nil
	}
	if !sv.lo.IsWritten() || !sv.hi.IsWritten() {
		return false
	}
	hiOp := sv.hi.Def()
	loOp := sv.lo.Def()
	if hiOp == nil || loOp == nil {
		return false
	}
	if hiOp.Parent() != loOp.Parent() {
		sv.defpoint = hiOp
		sv.defblock = hiOp.Parent()
		return true
	}
	if hiOp.Seq().Order < loOp.Seq().Order {
		sv.defpoint = loOp
	} else {
		sv.defpoint = hiOp
	}
	sv.defblock = hiOp.Parent()
	return true
}

func (sv *SplitVarnode) findWholeBuiltFromPieces() bool {
	if sv.hi == nil || sv.lo == nil {
		return false
	}
	for _, op := range sv.lo.DescendIter() {
		if op == nil || op.Code() != CPUI_PIECE || op.NumInput() < 2 || op.Input(0) != sv.hi || op.Input(1) != sv.lo {
			continue
		}
		sv.whole = op.Output()
		sv.defpoint = op
		sv.defblock = op.Parent()
		return true
	}
	return false
}

func (sv *SplitVarnode) isWholeFeasible(existop *PcodeOp) bool {
	if sv.isConstant() {
		return true
	}
	if sv.whole == nil && !sv.findWholeSplitToPieces() && !sv.findWholeBuiltFromPieces() && !sv.findDefinitionPoint() {
		return false
	}
	if sv.defblock == nil || existop == nil || existop.Parent() == nil {
		return true
	}
	if sv.defblock == existop.Parent() {
		if sv.defpoint == nil {
			return true
		}
		return sv.defpoint.Seq().Order <= existop.Seq().Order
	}
	return true
}

func (sv *SplitVarnode) isWholePhiFeasible(bl *BlockBasic) bool {
	if sv.isConstant() || bl == nil {
		return false
	}
	if sv.whole == nil && !sv.findWholeSplitToPieces() && !sv.findWholeBuiltFromPieces() && !sv.findDefinitionPoint() {
		return false
	}
	return true
}

func (sv *SplitVarnode) findCreateWhole(data *Funcdata) {
	if sv.isConstant() {
		sv.whole = data.NewConstant(sv.wholesize, sv.val)
		return
	}
	if sv.whole != nil {
		return
	}
	if sv.lo != nil {
		sv.lo.SetPrecisLo()
	}
	if sv.hi != nil {
		sv.hi.SetPrecisHi()
	}
	addr := address.Address{}
	if sv.defpoint != nil {
		addr = sv.defpoint.Addr()
	}
	op := data.NewOp(2, addr)
	if sv.hi == nil {
		op.SetNumInputs(1)
		data.OpSetOpcode(op, CPUI_INT_ZEXT)
		data.OpSetInput(op, sv.lo, 0)
	} else {
		data.OpSetOpcode(op, CPUI_PIECE)
		data.OpSetInput(op, sv.hi, 0)
		data.OpSetInput(op, sv.lo, 1)
	}
	sv.whole = data.NewUniqueOut(sv.wholesize, op)
	if sv.defpoint != nil {
		data.OpInsertAfter(op, sv.defpoint)
	} else {
		if bg := data.GetBasicBlocks(); bg != nil && bg.GetSize() > 0 {
			if bb, ok := bg.GetBlock(0).Concrete().(*BlockBasic); ok {
				data.OpInsertBegin(op, bb)
			}
		}
	}
	sv.defpoint = op
	sv.defblock = op.Parent()
}

func (sv *SplitVarnode) findCreateOutputWhole(data *Funcdata) {
	if sv.whole != nil {
		return
	}
	if sv.lo != nil {
		sv.lo.SetPrecisLo()
	}
	if sv.hi != nil {
		sv.hi.SetPrecisHi()
	}
	op := data.NewOp(0, address.Address{})
	sv.whole = data.NewUniqueOut(sv.wholesize, op)
}

func (sv *SplitVarnode) createJoinedWhole(data *Funcdata) {
	if sv.whole != nil {
		return
	}
	if sv.lo != nil {
		sv.lo.SetPrecisLo()
	}
	if sv.hi != nil {
		sv.hi.SetPrecisHi()
	}
	op := data.NewOp(0, address.Address{})
	sv.whole = data.NewUniqueOut(sv.wholesize, op)
}

func (sv *SplitVarnode) buildLoFromWhole(data *Funcdata) {
	if sv.lo == nil || sv.whole == nil || !sv.lo.IsWritten() {
		return
	}
	op := sv.lo.Def()
	if op == nil {
		return
	}
	data.OpSetOpcode(op, CPUI_SUBPIECE)
	data.OpSetAllInput(op, []*Varnode{sv.whole, data.NewConstant(4, 0)})
}

func (sv *SplitVarnode) buildHiFromWhole(data *Funcdata) {
	if sv.hi == nil || sv.whole == nil || !sv.hi.IsWritten() {
		return
	}
	op := sv.hi.Def()
	if op == nil {
		return
	}
	data.OpSetOpcode(op, CPUI_SUBPIECE)
	data.OpSetAllInput(op, []*Varnode{sv.whole, data.NewConstant(4, uint64(sv.lo.Size()))})
}

func (sv *SplitVarnode) findEarliestSplitPoint() *PcodeOp {
	if sv.lo == nil || sv.hi == nil || !sv.lo.IsWritten() || !sv.hi.IsWritten() {
		return nil
	}
	hiOp := sv.hi.Def()
	loOp := sv.lo.Def()
	if hiOp == nil || loOp == nil || hiOp.Parent() != loOp.Parent() {
		return nil
	}
	if loOp.Seq().Order < hiOp.Seq().Order {
		return loOp
	}
	return hiOp
}

func (sv *SplitVarnode) findOutExist() *PcodeOp {
	if sv.findWholeBuiltFromPieces() {
		return sv.defpoint
	}
	return sv.findEarliestSplitPoint()
}

func (sv *SplitVarnode) exceedsConstPrecision() bool {
	return sv.isConstant() && sv.wholesize > 8
}

func (sv *SplitVarnode) adjacentOffsets(vn1 *Varnode, vn2 *Varnode, size1 uint64) bool {
	if vn1 == nil || vn2 == nil {
		return false
	}
	if vn1.IsConstant() {
		return vn2.IsConstant() && vn1.Offset()+size1 == vn2.Offset()
	}
	if !vn2.IsWritten() || vn2.Def() == nil || vn2.Def().Code() != CPUI_INT_ADD || vn2.Def().NumInput() < 2 {
		return false
	}
	if vn2.Def().Input(1) == nil || !vn2.Def().Input(1).IsConstant() {
		return false
	}
	if vn2.Def().Input(0) == vn1 {
		return size1 == vn2.Def().Input(1).Offset()
	}
	if !vn1.IsWritten() || vn1.Def() == nil || vn1.Def().Code() != CPUI_INT_ADD || vn1.Def().NumInput() < 2 {
		return false
	}
	if vn1.Def().Input(1) == nil || !vn1.Def().Input(1).IsConstant() {
		return false
	}
	return vn1.Def().Input(0) == vn2.Def().Input(0) && vn1.Def().Input(1).Offset()+size1 == vn2.Def().Input(1).Offset()
}

func (sv *SplitVarnode) testContiguousPointers(most *PcodeOp, least *PcodeOp) (*PcodeOp, *PcodeOp, *address.Space, bool) {
	if most == nil || least == nil || most.NumInput() < 2 || least.NumInput() < 2 {
		return nil, nil, nil, false
	}
	if most.Input(0) == nil || least.Input(0) == nil {
		return nil, nil, nil, false
	}
	spc := least.Input(0).GetSpaceFromConst()
	if most.Input(0).GetSpaceFromConst() != spc {
		return nil, nil, nil, false
	}
	if most.Input(1) == nil || least.Input(1) == nil || most.Input(1).IsFree() || least.Input(1).IsFree() {
		return nil, nil, nil, false
	}
	first := least
	second := most
	if spc != nil && spc.BigEndian {
		first = most
		second = least
	}
	if !sv.adjacentOffsets(first.Input(1), second.Input(1), uint64(outputSize(first))) {
		return nil, nil, nil, false
	}
	return first, second, spc, true
}

func (sv *SplitVarnode) isAddrTiedContiguous(lo *Varnode, hi *Varnode, res *address.Address) bool {
	if lo == nil || hi == nil || !lo.IsAddrTied() || !hi.IsAddrTied() || lo.Space() != hi.Space() {
		return false
	}
	if lo.Space() == nil {
		return false
	}
	if lo.Space().BigEndian {
		if hi.Offset()+uint64(hi.Size()) != lo.Offset() {
			return false
		}
		*res = hi.Addr()
		return true
	}
	if lo.Offset()+uint64(lo.Size()) != hi.Offset() {
		return false
	}
	*res = lo.Addr()
	return true
}

func (sv *SplitVarnode) wholeList(w *Varnode, splitvec *[]SplitVarnode) {
	if w == nil || splitvec == nil {
		return
	}
	base := SplitVarnode{whole: w, wholesize: w.Size()}
	for _, op := range w.DescendIter() {
		if op == nil || op.Code() != CPUI_SUBPIECE || op.NumInput() < 2 || op.Input(1) == nil {
			continue
		}
		out := op.Output()
		if out == nil {
			continue
		}
		pair := base
		if op.Input(1).Offset() == 0 && out.IsPrecisLo() {
			pair.lo = out
		}
		if op.Input(1).Offset() == uint64(w.Size()-out.Size()) && out.IsPrecisHi() {
			pair.hi = out
		}
		if pair.lo != nil || pair.hi != nil {
			*splitvec = append(*splitvec, pair)
		}
	}
}

func (sv *SplitVarnode) findCopies(in SplitVarnode, splitvec *[]SplitVarnode) {
	if splitvec == nil || in.lo == nil || in.hi == nil || in.whole == nil {
		return
	}
	for _, lop := range in.lo.DescendIter() {
		if lop == nil || lop.Code() != CPUI_COPY || lop.Output() == nil {
			continue
		}
		for _, hip := range in.hi.DescendIter() {
			if hip == nil || hip.Code() != CPUI_COPY || hip.Output() == nil || hip.Parent() != lop.Parent() {
				continue
			}
			pair := SplitVarnode{whole: in.whole, lo: lop.Output(), hi: hip.Output(), wholesize: in.wholesize}
			*splitvec = append(*splitvec, pair)
		}
	}
}

func (sv *SplitVarnode) applyRuleIn(in SplitVarnode, data *Funcdata) int {
	_ = data
	_ = in
	return 0
}

func (sv *SplitVarnode) prepareBinaryOp(out SplitVarnode, in1 SplitVarnode, in2 SplitVarnode) *PcodeOp {
	existop := out.findOutExist()
	if existop == nil || !in1.isWholeFeasible(existop) || !in2.isWholeFeasible(existop) {
		return nil
	}
	return existop
}

func (sv *SplitVarnode) createBinaryOp(data *Funcdata, out SplitVarnode, in1 SplitVarnode, in2 SplitVarnode, existop *PcodeOp, opc OpCode) {
	_ = data
	_ = out
	_ = in1
	_ = in2
	_ = existop
	_ = opc
}

func (sv *SplitVarnode) prepareShiftOp(out SplitVarnode, in SplitVarnode) *PcodeOp {
	existop := out.findOutExist()
	if existop == nil || !in.isWholeFeasible(existop) {
		return nil
	}
	return existop
}

func (sv *SplitVarnode) createShiftOp(data *Funcdata, out SplitVarnode, in SplitVarnode, sa *Varnode, existop *PcodeOp, opc OpCode) {
	_ = data
	_ = out
	_ = in
	_ = sa
	_ = existop
	_ = opc
}

func (sv *SplitVarnode) prepareBoolOp(in1 SplitVarnode, in2 SplitVarnode, testop *PcodeOp) bool {
	return in1.isWholeFeasible(testop) && in2.isWholeFeasible(testop)
}

func (sv *SplitVarnode) replaceBoolOp(data *Funcdata, boolop *PcodeOp, in1 SplitVarnode, in2 SplitVarnode, opc OpCode) {
	_ = data
	_ = boolop
	_ = in1
	_ = in2
	_ = opc
}

func (sv *SplitVarnode) createBoolOp(data *Funcdata, cbranch *PcodeOp, in1 SplitVarnode, in2 SplitVarnode, opc OpCode) {
	_ = data
	_ = cbranch
	_ = in1
	_ = in2
	_ = opc
}

func (sv *SplitVarnode) preparePhiOp(out SplitVarnode, inlist []SplitVarnode) *PcodeOp {
	_ = inlist
	return out.findEarliestSplitPoint()
}

func (sv *SplitVarnode) createPhiOp(data *Funcdata, out SplitVarnode, inlist []SplitVarnode, existop *PcodeOp) {
	_ = data
	_ = out
	_ = inlist
	_ = existop
}

func (sv *SplitVarnode) prepareIndirectOp(in SplitVarnode, affector *PcodeOp) bool {
	_ = affector
	return in.isConstant() || in.isWholeFeasible(affector)
}

func (sv *SplitVarnode) replaceIndirectOp(data *Funcdata, out SplitVarnode, in SplitVarnode, affector *PcodeOp) {
	_ = data
	_ = out
	_ = in
	_ = affector
}

func (sv *SplitVarnode) replaceCopyForce(data *Funcdata, addr address.Address, in SplitVarnode, copylo *PcodeOp, copyhi *PcodeOp) {
	_ = data
	_ = addr
	_ = in
	_ = copylo
	_ = copyhi
}
