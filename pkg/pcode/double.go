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

import (
	"gosleigh/pkg/address"
)

// C++ parity: double.hh / double.cc -- SplitVarnode and friends.
//
// A SplitVarnode is a logical double-precision value whose storage is split
// between two Varnodes: a least-significant half (lo) and a most-significant
// half (hi). Either half may be null when the value is a constant (both
// null, with the constant in val) or when the hi half is an implied zero.
//
// This file ports the core SplitVarnode machinery needed by RuleDoubleIn,
// RuleDoubleOut, RuleDoubleLoad, and RuleDoubleStore. Parts of the C++
// implementation that depend on Form classes (AddForm, SubForm, LogicalForm,
// ShiftForm, MultForm, PhiForm, IndirectForm, ...) and symbol-entry tracking
// are deliberately left out -- see applyRuleIn below -- but the rules we port
// in this slice either do not use those forms or degrade gracefully.
//
// Known TODOs (specific C++ method names):
//   - constructJoinAddress  (used by createJoinedWhole)
//   - SymbolEntry checks    (isAddrTiedContiguous, RuleDoubleOut::attemptMarking)
//   - combineInputVarnodes  (RuleDoubleOut contiguous-input collapse)
//   - newVarnodeIop + op-from-const affector chain (buildLoFromWhole / buildHiFromWhole INDIRECT case)
//   - Form classes         (SplitVarnode::applyRuleIn) -- 11/13 ported; LessThreeWay and IndirectForm remain stubs
//   - RuleDoubleStore::reassignIndirects op-from-const chain
//   - RuleDoubleIn::reset  -- Funcdata.setDoublePrecisRecovery not yet plumbed

// SplitVarnode mirrors the C++ SplitVarnode class.
//
// C++ parity: class SplitVarnode (double.hh)
type SplitVarnode struct {
	lo        *Varnode
	hi        *Varnode
	whole     *Varnode
	defpoint  *PcodeOp
	defblock  *BlockBasic
	val       uint64
	wholesize int32
}

// C++ parity: SplitVarnode::SplitVarnode(int4,uintb) -- constant ctor.
func NewSplitVarnodeConst(sz int32, v uint64) SplitVarnode {
	return SplitVarnode{val: v, wholesize: sz}
}

// C++ parity: SplitVarnode::SplitVarnode(Varnode*,Varnode*) -- piece ctor.
func NewSplitVarnodePieces(l, h *Varnode) SplitVarnode {
	s := SplitVarnode{}
	s.InitPartialPieces(l.Size()+h.Size(), l, h)
	return s
}

// C++ parity: SplitVarnode::initAll
func (s *SplitVarnode) InitAll(w, l, h *Varnode) {
	s.wholesize = w.Size()
	s.lo = l
	s.hi = h
	s.whole = w
	s.defpoint = nil
	s.defblock = nil
}

// C++ parity: SplitVarnode::initPartial(int4,uintb)
func (s *SplitVarnode) InitPartialConst(sz int32, v uint64) {
	s.val = v
	s.wholesize = sz
	s.lo = nil
	s.hi = nil
	s.whole = nil
	s.defpoint = nil
	s.defblock = nil
}

// C++ parity: SplitVarnode::initPartial(int4,Varnode*,Varnode*)
// If both pieces are constant, fold into a constant SplitVarnode.
// A nil hi means an implied zero-extension of lo.
func (s *SplitVarnode) InitPartialPieces(sz int32, l, h *Varnode) {
	if h == nil {
		s.hi = nil
		if l.IsConstant() {
			s.val = l.Offset()
			s.lo = nil
		} else {
			s.lo = l
		}
	} else if l.IsConstant() && h.IsConstant() {
		val := h.Offset()
		val <<= uint(l.Size() * 8)
		val |= l.Offset()
		s.val = val
		s.lo = nil
		s.hi = nil
	} else {
		s.lo = l
		s.hi = h
	}
	s.wholesize = sz
	s.whole = nil
	s.defpoint = nil
	s.defblock = nil
}

// C++ parity: SplitVarnode::isConstant
func (s *SplitVarnode) IsConstant() bool { return s.lo == nil && s.hi == nil }

// C++ parity: SplitVarnode::hasBothPieces
func (s *SplitVarnode) HasBothPieces() bool { return s.lo != nil && s.hi != nil }

// Simple accessors mirroring the C++ inline getters.
func (s *SplitVarnode) GetSize() int32     { return s.wholesize }
func (s *SplitVarnode) GetLo() *Varnode    { return s.lo }
func (s *SplitVarnode) GetHi() *Varnode    { return s.hi }
func (s *SplitVarnode) GetWhole() *Varnode { return s.whole }
func (s *SplitVarnode) GetDefPoint() *PcodeOp { return s.defpoint }
func (s *SplitVarnode) GetDefBlock() *BlockBasic { return s.defblock }
func (s *SplitVarnode) GetValue() uint64   { return s.val }

// C++ parity: SplitVarnode::inHandHi
// Given the most significant piece, verify it is a SUBPIECE and look for the
// matching least significant SUBPIECE off the same whole.
func (s *SplitVarnode) InHandHi(h *Varnode) bool {
	if !h.IsPrecisHi() {
		return false
	}
	if !h.IsWritten() {
		return false
	}
	op := h.Def()
	if op.Code() != CPUI_SUBPIECE {
		return false
	}
	w := op.Input(0)
	off, ok := constantValue(op.Input(1))
	if !ok {
		return false
	}
	if off != uint64(w.Size()-h.Size()) {
		return false
	}
	for _, tmpop := range w.DescendIter() {
		if tmpop.Code() != CPUI_SUBPIECE {
			continue
		}
		tmplo := tmpop.Output()
		if tmplo == nil || !tmplo.IsPrecisLo() {
			continue
		}
		if tmplo.Size()+h.Size() != w.Size() {
			continue
		}
		loff, ok := constantValue(tmpop.Input(1))
		if !ok || loff != 0 {
			continue
		}
		s.InitAll(w, tmplo, h)
		return true
	}
	return false
}

// C++ parity: SplitVarnode::inHandLo
func (s *SplitVarnode) InHandLo(l *Varnode) bool {
	if !l.IsPrecisLo() {
		return false
	}
	if !l.IsWritten() {
		return false
	}
	op := l.Def()
	if op.Code() != CPUI_SUBPIECE {
		return false
	}
	w := op.Input(0)
	loff, ok := constantValue(op.Input(1))
	if !ok || loff != 0 {
		return false
	}
	for _, tmpop := range w.DescendIter() {
		if tmpop.Code() != CPUI_SUBPIECE {
			continue
		}
		tmphi := tmpop.Output()
		if tmphi == nil || !tmphi.IsPrecisHi() {
			continue
		}
		if tmphi.Size()+l.Size() != w.Size() {
			continue
		}
		hoff, ok := constantValue(tmpop.Input(1))
		if !ok || hoff != uint64(l.Size()) {
			continue
		}
		s.InitAll(w, l, tmphi)
		return true
	}
	return false
}

// C++ parity: SplitVarnode::inHandLoNoHi
func (s *SplitVarnode) InHandLoNoHi(l *Varnode) bool {
	if !l.IsPrecisLo() {
		return false
	}
	if !l.IsWritten() {
		return false
	}
	op := l.Def()
	if op.Code() != CPUI_SUBPIECE {
		return false
	}
	loff, ok := constantValue(op.Input(1))
	if !ok || loff != 0 {
		return false
	}
	w := op.Input(0)
	for _, tmpop := range w.DescendIter() {
		if tmpop.Code() != CPUI_SUBPIECE {
			continue
		}
		tmphi := tmpop.Output()
		if tmphi == nil || !tmphi.IsPrecisHi() {
			continue
		}
		if tmphi.Size()+l.Size() != w.Size() {
			continue
		}
		hoff, ok := constantValue(tmpop.Input(1))
		if !ok || hoff != uint64(l.Size()) {
			continue
		}
		s.InitAll(w, l, tmphi)
		return true
	}
	s.InitAll(w, l, nil)
	return true
}

// C++ parity: SplitVarnode::inHandHiOut
func (s *SplitVarnode) InHandHiOut(h *Varnode) bool {
	var loTmp, outvn *Varnode
	for _, pieceop := range h.DescendIter() {
		if pieceop.Code() != CPUI_PIECE {
			continue
		}
		if pieceop.Input(0) != h {
			continue
		}
		l := pieceop.Input(1)
		if !l.IsPrecisLo() {
			continue
		}
		if loTmp != nil {
			return false
		}
		loTmp = l
		outvn = pieceop.Output()
	}
	if loTmp != nil {
		s.InitAll(outvn, loTmp, h)
		return true
	}
	return false
}

// C++ parity: SplitVarnode::inHandLoOut
func (s *SplitVarnode) InHandLoOut(l *Varnode) bool {
	var hiTmp, outvn *Varnode
	for _, pieceop := range l.DescendIter() {
		if pieceop.Code() != CPUI_PIECE {
			continue
		}
		if pieceop.Input(1) != l {
			continue
		}
		h := pieceop.Input(0)
		if !h.IsPrecisHi() {
			continue
		}
		if hiTmp != nil {
			return false
		}
		hiTmp = h
		outvn = pieceop.Output()
	}
	if hiTmp != nil {
		s.InitAll(outvn, l, hiTmp)
		return true
	}
	return false
}

// C++ parity: SplitVarnode::findWholeSplitToPieces
// Look for a common whole Varnode that both hi and lo are SUBPIECEs of.
// Also handles a single level of CPUI_COPY between the SUBPIECE and the piece.
func (s *SplitVarnode) findWholeSplitToPieces() bool {
	if s.whole == nil {
		if s.hi == nil || s.lo == nil {
			return false
		}
		if !s.hi.IsWritten() {
			return false
		}
		subhi := s.hi.Def()
		if subhi.Code() == CPUI_COPY {
			otherhi := subhi.Input(0)
			if !otherhi.IsWritten() {
				return false
			}
			subhi = otherhi.Def()
		}
		if subhi.Code() != CPUI_SUBPIECE {
			return false
		}
		off, ok := constantValue(subhi.Input(1))
		if !ok || off != uint64(s.wholesize-s.hi.Size()) {
			return false
		}
		putative := subhi.Input(0)
		if putative.Size() != s.wholesize {
			return false
		}
		if !s.lo.IsWritten() {
			return false
		}
		sublo := s.lo.Def()
		if sublo.Code() == CPUI_COPY {
			otherlo := sublo.Input(0)
			if !otherlo.IsWritten() {
				return false
			}
			sublo = otherlo.Def()
		}
		if sublo.Code() != CPUI_SUBPIECE {
			return false
		}
		if putative != sublo.Input(0) {
			return false
		}
		loff, ok := constantValue(sublo.Input(1))
		if !ok || loff != 0 {
			return false
		}
		s.whole = putative
	}
	if s.whole.IsWritten() {
		s.defpoint = s.whole.Def()
		s.defblock = s.defpoint.Parent()
	} else if s.whole.IsInput() {
		s.defpoint = nil
		s.defblock = nil
	}
	return true
}

// C++ parity: SplitVarnode::findDefinitionPoint
func (s *SplitVarnode) findDefinitionPoint() bool {
	if s.hi != nil && s.hi.IsConstant() {
		return false
	}
	if s.lo.IsConstant() {
		return false
	}
	if s.hi == nil {
		// Implied zero extension.
		if s.lo.IsInput() {
			s.defblock = nil
			s.defpoint = nil
		} else if s.lo.IsWritten() {
			s.defpoint = s.lo.Def()
			s.defblock = s.defpoint.Parent()
		} else {
			return false
		}
		return true
	}
	if s.hi.IsWritten() {
		if !s.lo.IsWritten() {
			return false
		}
		lastop := s.hi.Def()
		s.defblock = lastop.Parent()
		lastop2 := s.lo.Def()
		otherblock := lastop2.Parent()
		if s.defblock != otherblock {
			// Dominance walk: make sure defblock is dominated by otherblock
			// (or vice-versa). Gosleigh uses FlowBlock.ImmedDom.
			s.defpoint = lastop
			if blockDominatedBy(s.defblock, otherblock) {
				return true
			}
			s.defblock = otherblock
			otherblock2 := lastop.Parent()
			s.defpoint = lastop2
			if blockDominatedBy(s.defblock, otherblock2) {
				return true
			}
			s.defblock = nil
			return false
		}
		if lastop2.Seq().Order > lastop.Seq().Order {
			lastop = lastop2
		}
		s.defpoint = lastop
		return true
	}
	if s.hi.IsInput() {
		if !s.lo.IsInput() {
			return false
		}
		s.defblock = nil
		s.defpoint = nil
		return true
	}
	return false
}

// blockDominatedBy walks the immediate dominator chain of start until it
// reaches target (returning true) or the chain ends. Equivalent to the
// C++ dominance walks embedded in findDefinitionPoint / isWholeFeasible.
func blockDominatedBy(start, target *BlockBasic) bool {
	if start == nil || target == nil {
		return false
	}
	cur := start.ImmedDom()
	for cur != nil {
		if bb, ok := cur.Concrete().(*BlockBasic); ok && bb == target {
			return true
		}
		cur = cur.ImmedDom()
	}
	return false
}

// C++ parity: SplitVarnode::findEarliestSplitPoint
func (s *SplitVarnode) findEarliestSplitPoint() *PcodeOp {
	if !s.hi.IsWritten() || !s.lo.IsWritten() {
		return nil
	}
	hiop := s.hi.Def()
	loop := s.lo.Def()
	if loop.Parent() != hiop.Parent() {
		return nil
	}
	if loop.Seq().Order < hiop.Seq().Order {
		return loop
	}
	return hiop
}

// C++ parity: SplitVarnode::findWholeBuiltFromPieces
// Look for a CPUI_PIECE consuming hi and lo directly.
func (s *SplitVarnode) findWholeBuiltFromPieces() bool {
	if s.hi == nil || s.lo == nil {
		return false
	}
	var res *PcodeOp
	var bb *BlockBasic
	if s.lo.IsWritten() {
		bb = s.lo.Def().Parent()
	} else if !s.lo.IsInput() {
		return false
	}
	for _, op := range s.lo.DescendIter() {
		if op.Code() != CPUI_PIECE {
			continue
		}
		if op.Input(0) != s.hi {
			continue
		}
		if bb != nil {
			if op.Parent() != bb {
				continue
			}
		} else {
			// lo is an input -- op must live in the entry block.
			if !isEntryBlock(op.Parent()) {
				continue
			}
		}
		if res == nil || op.Seq().Order < res.Seq().Order {
			res = op
		}
	}
	if res == nil {
		s.whole = nil
		return false
	}
	s.defpoint = res
	s.defblock = res.Parent()
	s.whole = res.Output()
	return s.whole != nil
}

// isEntryBlock returns true if bb is the start block of the function body.
func isEntryBlock(bb *BlockBasic) bool {
	if bb == nil {
		return false
	}
	// A block with no in-edges is the entry point.
	return bb.SizeIn() == 0
}

// C++ parity: SplitVarnode::isWholeFeasible
func (s *SplitVarnode) IsWholeFeasible(existop *PcodeOp) bool {
	if s.IsConstant() {
		return true
	}
	if s.lo != nil && s.hi != nil {
		if s.lo.IsConstant() != s.hi.IsConstant() {
			return false
		}
	}
	if !s.findWholeSplitToPieces() {
		if !s.findWholeBuiltFromPieces() {
			if !s.findDefinitionPoint() {
				return false
			}
		}
	}
	if s.defblock == nil {
		return true
	}
	curbl := existop.Parent()
	if curbl == s.defblock {
		return s.defpoint.Seq().Order <= existop.Seq().Order
	}
	return blockDominatedBy(curbl, s.defblock)
}

// C++ parity: SplitVarnode::findCreateWhole
// Builds the whole Varnode as a CPUI_PIECE (or CPUI_INT_ZEXT when hi is nil).
func (s *SplitVarnode) FindCreateWhole(data *Funcdata) {
	if s.IsConstant() {
		s.whole = data.NewConstant(s.wholesize, s.val)
		return
	}
	if s.lo != nil {
		s.lo.SetPrecisLo()
	}
	if s.hi != nil {
		s.hi.SetPrecisHi()
	}
	if s.whole != nil {
		return
	}
	var addr address.Address
	var topblock *BlockBasic
	if s.defblock != nil {
		addr = s.defpoint.Addr()
	} else {
		topblock = startBlockOf(data)
		if topblock != nil {
			// BlockBasic.Start() is not plumbed yet; fall back to the first
			// op's address or the function base address.
			if first := topblock.FirstOp(); first != nil {
				addr = first.Addr()
			} else {
				addr = data.BaseAddr()
			}
		}
	}
	var concatop *PcodeOp
	if s.hi != nil {
		concatop = data.NewOp(2, addr)
		s.whole = data.NewUniqueOut(s.wholesize, concatop)
		data.OpSetOpcode(concatop, CPUI_PIECE)
		data.OpSetInput(concatop, s.hi, 0)
		data.OpSetInput(concatop, s.lo, 1)
	} else {
		concatop = data.NewOp(1, addr)
		s.whole = data.NewUniqueOut(s.wholesize, concatop)
		data.OpSetOpcode(concatop, CPUI_INT_ZEXT)
		data.OpSetInput(concatop, s.lo, 0)
	}
	if s.defblock != nil {
		data.OpInsertAfter(concatop, s.defpoint)
	} else if topblock != nil {
		data.OpInsertBegin(concatop, topblock)
	}
	s.defpoint = concatop
	s.defblock = concatop.Parent()
}

// startBlockOf returns the function-entry BlockBasic, or nil if not yet set.
// C++ parity: Funcdata::getBasicBlocks().getStartBlock() in double.cc:520.
// Gosleigh's BlockGraph does not expose an explicit start-block accessor yet,
// so we locate the entry by scanning for the first BlockBasic with no
// in-edges.
func startBlockOf(data *Funcdata) *BlockBasic {
	bg := data.GetBasicBlocks()
	if bg == nil {
		return nil
	}
	for i := 0; i < bg.GetSize(); i++ {
		fb := bg.GetBlock(i)
		if fb == nil {
			continue
		}
		if fb.SizeIn() != 0 {
			continue
		}
		if bb, ok := fb.Concrete().(*BlockBasic); ok {
			return bb
		}
	}
	return nil
}

// C++ parity: SplitVarnode::findOutExist
func (s *SplitVarnode) FindOutExist() *PcodeOp {
	if s.findWholeBuiltFromPieces() {
		return s.defpoint
	}
	return s.findEarliestSplitPoint()
}

// C++ parity: SplitVarnode::exceedsConstPrecision
func (s *SplitVarnode) ExceedsConstPrecision() bool {
	return s.IsConstant() && s.wholesize > 8
}

// C++ parity: SplitVarnode::adjacentOffsets
// Return true if vn1 + size1 == vn2 at the (possibly dynamic) value level.
func SplitVarnodeAdjacentOffsets(vn1, vn2 *Varnode, size1 uint64) bool {
	if vn1.IsConstant() {
		if !vn2.IsConstant() {
			return false
		}
		return (vn1.Offset() + size1) == vn2.Offset()
	}
	if !vn2.IsWritten() {
		return false
	}
	op2 := vn2.Def()
	if op2.Code() != CPUI_INT_ADD {
		return false
	}
	if !op2.Input(1).IsConstant() {
		return false
	}
	c2 := op2.Input(1).Offset()
	if op2.Input(0) == vn1 {
		return size1 == c2
	}
	if !vn1.IsWritten() {
		return false
	}
	op1 := vn1.Def()
	if op1.Code() != CPUI_INT_ADD {
		return false
	}
	if !op1.Input(1).IsConstant() {
		return false
	}
	c1 := op1.Input(1).Offset()
	if op1.Input(0) != op2.Input(0) {
		return false
	}
	return (c1 + size1) == c2
}

// C++ parity: SplitVarnode::testContiguousPointers
// Sort two LOAD/STORE ops into address order and verify their pointers address
// contiguous memory. Returns (first, second, space, true) on success.
func SplitVarnodeTestContiguousPointers(most, least *PcodeOp) (first, second *PcodeOp, spc *address.Space, ok bool) {
	spc = least.Input(0).GetSpaceFromConst()
	if spc == nil {
		return nil, nil, nil, false
	}
	if most.Input(0).GetSpaceFromConst() != spc {
		return nil, nil, nil, false
	}
	if spc.BigEndian {
		first = most
		second = least
	} else {
		first = least
		second = most
	}
	firstptr := first.Input(1)
	if firstptr.IsFree() {
		return nil, nil, nil, false
	}
	var sizeres int32
	if first.Code() == CPUI_LOAD {
		sizeres = first.Output().Size()
	} else {
		sizeres = first.Input(2).Size()
	}
	if !SplitVarnodeAdjacentOffsets(first.Input(1), second.Input(1), uint64(sizeres)) {
		return nil, nil, nil, false
	}
	return first, second, spc, true
}

// C++ parity: SplitVarnode::isAddrTiedContiguous
// Check that lo and hi are both addr-tied and their storage is contiguous.
// Symbol-entry tracking is not yet plumbed into Gosleigh, so this slice skips
// that branch -- if both varnodes are addr-tied in the same space at adjacent
// offsets, we treat them as contiguous.
// TODO(parity): symbol-entry guard from double.cc:796-803.
func SplitVarnodeIsAddrTiedContiguous(lo, hi *Varnode) (address.Address, bool) {
	if !lo.IsAddrTied() || !hi.IsAddrTied() {
		return address.Address{}, false
	}
	spc := lo.Space()
	if spc != hi.Space() {
		return address.Address{}, false
	}
	looffset := lo.Offset()
	hioffset := hi.Offset()
	if spc.BigEndian {
		if hioffset >= looffset {
			return address.Address{}, false
		}
		if hioffset+uint64(hi.Size()) != looffset {
			return address.Address{}, false
		}
		return hi.Addr(), true
	}
	if looffset >= hioffset {
		return address.Address{}, false
	}
	if looffset+uint64(lo.Size()) != hioffset {
		return address.Address{}, false
	}
	return lo.Addr(), true
}

// C++ parity: SplitVarnode::wholeList
// Enumerate all logical pair candidates that together reconstruct the given whole Varnode.
func SplitVarnodeWholeList(w *Varnode, splitvec *[]SplitVarnode) {
	var basic SplitVarnode
	basic.whole = w
	basic.wholesize = w.Size()
	res := 0
	for _, subop := range w.DescendIter() {
		if subop.Code() != CPUI_SUBPIECE {
			continue
		}
		vn := subop.Output()
		if vn == nil {
			continue
		}
		off, ok := constantValue(subop.Input(1))
		if !ok {
			continue
		}
		if vn.IsPrecisHi() {
			if off != uint64(basic.wholesize-vn.Size()) {
				continue
			}
			basic.hi = vn
			res |= 2
		} else if vn.IsPrecisLo() {
			if off != 0 {
				continue
			}
			basic.lo = vn
			res |= 1
		}
	}
	if res == 0 {
		return
	}
	if res == 3 && basic.lo.Size()+basic.hi.Size() != basic.wholesize {
		return
	}
	*splitvec = append(*splitvec, basic)
	splitVarnodeFindCopies(&basic, splitvec)
}

// C++ parity: SplitVarnode::findCopies
// Scan for pairs of COPYs that move both pieces into contiguous storage in the
// same basic block; create additional SplitVarnodes out of those COPY outputs.
func splitVarnodeFindCopies(in *SplitVarnode, splitvec *[]SplitVarnode) {
	if !in.HasBothPieces() {
		return
	}
	for _, loop := range in.GetLo().DescendIter() {
		if loop.Code() != CPUI_COPY {
			continue
		}
		locpy := loop.Output()
		if locpy == nil {
			continue
		}
		addr := locpy.Addr()
		if addr.Space != nil && addr.Space.BigEndian {
			// Go Address has no Sub; synthesize by constructing a new one.
			addr = address.Address{Space: addr.Space, Offset: addr.Offset - uint64(in.GetHi().Size())}
		} else {
			addr = addr.Add(uint64(locpy.Size()))
		}
		for _, hiop := range in.GetHi().DescendIter() {
			if hiop.Code() != CPUI_COPY {
				continue
			}
			hicpy := hiop.Output()
			if hicpy == nil {
				continue
			}
			if hicpy.Addr() != addr {
				continue
			}
			if hiop.Parent() != loop.Parent() {
				continue
			}
			var ns SplitVarnode
			ns.InitAll(in.GetWhole(), locpy, hicpy)
			*splitvec = append(*splitvec, ns)
		}
	}
}

// C++ parity: SplitVarnode::isWholePhiFeasible
// Similar to IsWholeFeasible, but the whole must be defined before the end of
// the given basic block.
func (s *SplitVarnode) IsWholePhiFeasible(bl *FlowBlock) bool {
	if s.IsConstant() {
		return false
	}
	if !s.findWholeSplitToPieces() {
		if !s.findWholeBuiltFromPieces() {
			if !s.findDefinitionPoint() {
				return false
			}
		}
	}
	if s.defblock == nil {
		return true
	}
	if bl != nil {
		if bb, ok := bl.Concrete().(*BlockBasic); ok && bb == s.defblock {
			return true
		}
	}
	cur := bl
	for cur != nil {
		cur = cur.ImmedDom()
		if cur == nil {
			return false
		}
		if bb, ok := cur.Concrete().(*BlockBasic); ok && bb == s.defblock {
			return true
		}
	}
	return false
}

// C++ parity: SplitVarnode::findCreateOutputWhole
// Create a whole Varnode as a unique register. The caller must later wire it
// as the output of some PcodeOp.
func (s *SplitVarnode) FindCreateOutputWhole(data *Funcdata) {
	s.lo.SetPrecisLo()
	s.hi.SetPrecisHi()
	if s.whole != nil {
		return
	}
	s.whole = data.vbank.CreateUnique(s.wholesize)
}

// C++ parity: SplitVarnode::createJoinedWhole
// Build the whole using the contiguous storage of the pieces when possible.
// The join-address fallback (constructJoinAddress) is not yet plumbed in
// Gosleigh, so we fall back to a unique Varnode and record a TODO.
func (s *SplitVarnode) CreateJoinedWhole(data *Funcdata) {
	s.lo.SetPrecisLo()
	s.hi.SetPrecisHi()
	if s.whole != nil {
		return
	}
	if addr, ok := SplitVarnodeIsAddrTiedContiguous(s.lo, s.hi); ok {
		s.whole = data.NewVarnode(s.wholesize, addr)
		s.whole.SetAddlFlags(VarnodeWriteMask)
		return
	}
	// TODO(parity): constructJoinAddress (double.cc:573). Use a unique as a
	// safe fallback so the rewrite still proceeds; semantics for non-contiguous
	// joined wholes may differ until the join-space plumbing is ported.
	s.whole = data.vbank.CreateUnique(s.wholesize)
	s.whole.SetAddlFlags(VarnodeWriteMask)
}

// buildPieceFromWhole converts the defining op of one piece (lo or hi) into a
// SUBPIECE of the freshly created whole.
// C++ parity: SplitVarnode::buildLoFromWhole / buildHiFromWhole (double.cc:583/621)
func (s *SplitVarnode) buildPieceFromWhole(data *Funcdata, piece *Varnode, offset int32) {
	pieceOp := piece.Def()
	if pieceOp == nil {
		return
	}
	whole := s.whole
	offConst := data.NewConstant(4, uint64(offset))
	inlist := []*Varnode{whole, offConst}
	switch pieceOp.Code() {
	case CPUI_MULTIEQUAL:
		// Reinsert at top of block so the MULTIEQUAL prefix stays contiguous.
		bb := pieceOp.Parent()
		data.OpUninsert(pieceOp)
		data.OpSetOpcode(pieceOp, CPUI_SUBPIECE)
		data.OpSetAllInput(pieceOp, inlist)
		data.OpInsertBegin(pieceOp, bb)
	case CPUI_INDIRECT:
		// TODO(parity): PcodeOp::getOpFromConst chain for affector; the C++
		// path reinserts after the affector. Without that plumbing we just
		// rewrite in place -- legal but may leave the op mis-ordered.
		data.OpSetOpcode(pieceOp, CPUI_SUBPIECE)
		data.OpSetAllInput(pieceOp, inlist)
	default:
		data.OpSetOpcode(pieceOp, CPUI_SUBPIECE)
		data.OpSetAllInput(pieceOp, inlist)
	}
}

// C++ parity: SplitVarnode::buildLoFromWhole
func (s *SplitVarnode) BuildLoFromWhole(data *Funcdata) {
	s.buildPieceFromWhole(data, s.lo, 0)
}

// C++ parity: SplitVarnode::buildHiFromWhole
func (s *SplitVarnode) BuildHiFromWhole(data *Funcdata) {
	s.buildPieceFromWhole(data, s.hi, s.lo.Size())
}

// C++ parity: SplitVarnode::getTrueFalse (double.cc:916)
func SplitVarnodeGetTrueFalse(boolop *PcodeOp, flip bool) (trueout, falseout *BlockBasic) {
	parent := boolop.Parent()
	trueBlock, _ := parent.TrueOut().Concrete().(*BlockBasic)
	falseBlock, _ := parent.FalseOut().Concrete().(*BlockBasic)
	isFlipped := boolop.HasFlag(PcodeOpBooleanFlip)
	if isFlipped != flip {
		return falseBlock, trueBlock
	}
	return trueBlock, falseBlock
}

// C++ parity: SplitVarnode::otherwiseEmpty (double.cc:938)
// Return true if the basic block containing branchop only executes the
// branch plus (optionally) the op producing its boolean input.
func SplitVarnodeOtherwiseEmpty(branchop *PcodeOp) bool {
	bl := branchop.Parent()
	if bl.SizeIn() != 1 {
		return false
	}
	var otherop *PcodeOp
	vn := branchop.Input(1)
	if vn != nil && vn.IsWritten() {
		otherop = vn.Def()
	}
	for _, op := range bl.Ops() {
		if op == otherop || op == branchop {
			continue
		}
		return false
	}
	return true
}

// C++ parity: SplitVarnode::verifyMultNegOne (double.cc:965)
func SplitVarnodeVerifyMultNegOne(op *PcodeOp) bool {
	if op == nil || op.Code() != CPUI_INT_MULT {
		return false
	}
	in1 := op.Input(1)
	if !in1.IsConstant() {
		return false
	}
	return in1.Offset() == doubleMaskOfSize(in1.Size())
}

// doubleMaskOfSize returns the byte-wide all-ones mask for the given size,
// matching ghidra's calc_mask helper for double-precision rewrites.
func doubleMaskOfSize(size int32) uint64 {
	if size <= 0 {
		return 0
	}
	if size >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << (uint(size) * 8)) - 1
}

// C++ parity: SplitVarnode::prepareBinaryOp (double.cc:984)
func SplitVarnodePrepareBinaryOp(out, in1, in2 *SplitVarnode) *PcodeOp {
	existop := out.FindOutExist()
	if existop == nil {
		return nil
	}
	if !in1.IsWholeFeasible(existop) {
		return nil
	}
	if !in2.IsWholeFeasible(existop) {
		return nil
	}
	return existop
}

// C++ parity: SplitVarnode::createBinaryOp (double.cc:1005)
func SplitVarnodeCreateBinaryOp(data *Funcdata, out, in1, in2 *SplitVarnode, existop *PcodeOp, opc OpCode) {
	out.FindCreateOutputWhole(data)
	in1.FindCreateWhole(data)
	in2.FindCreateWhole(data)
	if existop.Code() != CPUI_PIECE {
		newop := data.NewOp(2, existop.Addr())
		data.OpSetOpcode(newop, opc)
		data.OpSetOutput(newop, out.whole)
		data.OpSetInput(newop, in1.whole, 0)
		data.OpSetInput(newop, in2.whole, 1)
		data.OpInsertBefore(newop, existop)
		out.BuildLoFromWhole(data)
		out.BuildHiFromWhole(data)
	} else {
		data.OpSetOpcode(existop, opc)
		data.OpSetInput(existop, in1.whole, 0)
		data.OpSetInput(existop, in2.whole, 1)
	}
}

// C++ parity: SplitVarnode::prepareShiftOp (double.cc:1037)
func SplitVarnodePrepareShiftOp(out, in *SplitVarnode) *PcodeOp {
	existop := out.FindOutExist()
	if existop == nil {
		return nil
	}
	if !in.IsWholeFeasible(existop) {
		return nil
	}
	return existop
}

// C++ parity: SplitVarnode::createShiftOp (double.cc:1058)
func SplitVarnodeCreateShiftOp(data *Funcdata, out, in *SplitVarnode, sa *Varnode, existop *PcodeOp, opc OpCode) {
	out.FindCreateOutputWhole(data)
	in.FindCreateWhole(data)
	if sa.IsConstant() {
		sa = data.NewConstant(sa.Size(), sa.Offset())
	}
	if existop.Code() != CPUI_PIECE {
		newop := data.NewOp(2, existop.Addr())
		data.OpSetOpcode(newop, opc)
		data.OpSetOutput(newop, out.whole)
		data.OpSetInput(newop, in.whole, 0)
		data.OpSetInput(newop, sa, 1)
		data.OpInsertBefore(newop, existop)
		out.BuildLoFromWhole(data)
		out.BuildHiFromWhole(data)
	} else {
		data.OpSetOpcode(existop, opc)
		data.OpSetInput(existop, in.whole, 0)
		data.OpSetInput(existop, sa, 1)
	}
}

// C++ parity: SplitVarnode::prepareBoolOp (double.cc:1241)
func SplitVarnodePrepareBoolOp(in1, in2 *SplitVarnode, testop *PcodeOp) bool {
	if !in1.IsWholeFeasible(testop) {
		return false
	}
	if !in2.IsWholeFeasible(testop) {
		return false
	}
	return true
}

// C++ parity: SplitVarnode::replaceBoolOp (double.cc:1259)
func SplitVarnodeReplaceBoolOp(data *Funcdata, boolop *PcodeOp, in1, in2 *SplitVarnode, opc OpCode) {
	in1.FindCreateWhole(data)
	in2.FindCreateWhole(data)
	data.OpSetOpcode(boolop, opc)
	data.OpSetInput(boolop, in1.whole, 0)
	data.OpSetInput(boolop, in2.whole, 1)
}

// C++ parity: SplitVarnode::createBoolOp (double.cc:1279)
func SplitVarnodeCreateBoolOp(data *Funcdata, cbranch *PcodeOp, in1, in2 *SplitVarnode, opc OpCode) {
	addrop := cbranch
	boolvn := cbranch.Input(1)
	if boolvn != nil && boolvn.IsWritten() {
		addrop = boolvn.Def()
	}
	in1.FindCreateWhole(data)
	in2.FindCreateWhole(data)
	newop := data.NewOp(2, addrop.Addr())
	data.OpSetOpcode(newop, opc)
	newbool := data.NewUniqueOut(1, newop)
	data.OpSetInput(newop, in1.whole, 0)
	data.OpSetInput(newop, in2.whole, 1)
	data.OpInsertBefore(newop, cbranch)
	data.OpSetInput(cbranch, newbool, 1)
}

// C++ parity: SplitVarnode::preparePhiOp (double.cc:1306)
func SplitVarnodePreparePhiOp(out *SplitVarnode, inlist []SplitVarnode) *PcodeOp {
	existop := out.findEarliestSplitPoint()
	if existop == nil {
		return nil
	}
	if existop.Code() != CPUI_MULTIEQUAL {
		// Matches the LowlevelError throw in C++: treat as failure.
		return nil
	}
	bl := existop.Parent()
	for i := range inlist {
		if bl == nil || i >= bl.SizeIn() {
			return nil
		}
		if !inlist[i].IsWholePhiFeasible(bl.InEdge(i).Point) {
			return nil
		}
	}
	return existop
}

// C++ parity: SplitVarnode::createPhiOp (double.cc:1331)
func SplitVarnodeCreatePhiOp(data *Funcdata, out *SplitVarnode, inlist []SplitVarnode, existop *PcodeOp) {
	out.FindCreateOutputWhole(data)
	for i := range inlist {
		inlist[i].FindCreateWhole(data)
	}
	numin := len(inlist)
	newop := data.NewOp(numin, existop.Addr())
	data.OpSetOpcode(newop, CPUI_MULTIEQUAL)
	data.OpSetOutput(newop, out.whole)
	for i := range inlist {
		data.OpSetInput(newop, inlist[i].whole, i)
	}
	data.OpInsertBefore(newop, existop)
	out.BuildLoFromWhole(data)
	out.BuildHiFromWhole(data)
}

// C++ parity: SplitVarnode::prepareIndirectOp (double.cc:1358)
func SplitVarnodePrepareIndirectOp(in *SplitVarnode, affector *PcodeOp) bool {
	return in.IsWholeFeasible(affector)
}

// C++ parity: SplitVarnode::replaceCopyForce (double.cc:1402)
// Replaces a pair of COPY-to-addr-forced varnodes with a single wider COPY.
// The ReturnCopy special form is not yet plumbed (needs PcodeOp.isReturnCopy/
// markReturnCopy); we implement the common case and leave the return-copy
// branch as a TODO.
func SplitVarnodeReplaceCopyForce(data *Funcdata, addr address.Address, in *SplitVarnode, copylo, copyhi *PcodeOp) {
	inVn := in.whole
	wholeCopy := data.NewOp(1, copyhi.Addr())
	data.OpSetOpcode(wholeCopy, CPUI_COPY)
	outVn := data.NewVarnodeOut(in.wholesize, addr, wholeCopy)
	outVn.SetFlags(VarnodeAddrForce)
	data.OpSetInput(wholeCopy, inVn, 0)
	data.OpInsertBefore(wholeCopy, copyhi)
	data.OpDestroy(copyhi)
	data.OpDestroy(copylo)
}

// C++ parity: SplitVarnode::applyRuleIn (double.cc:1090)
// Walk each piece of the split input and dispatch to the Form classes for
// every descendant op, returning 1 on the first successful transform.
func SplitVarnodeApplyRuleIn(in *SplitVarnode, data *Funcdata) int {
	for i := 0; i < 2; i++ {
		var vn *Varnode
		if i == 0 {
			vn = in.hi
		} else {
			vn = in.lo
		}
		if vn == nil {
			continue
		}
		workishi := i == 0
		// Take a snapshot of the descendant list: transforms may mutate it.
		descs := append([]*PcodeOp(nil), vn.DescendIter()...)
		for _, workop := range descs {
			if workop.IsDead() {
				continue
			}
			// Dispatch matches C++ SplitVarnode::applyRuleIn (double.cc:1090).
			switch workop.Code() {
			case CPUI_INT_ADD:
				var addform AddForm
				if addform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
				var subform SubForm
				if subform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_AND:
				var equal3form Equal3Form
				if equal3form.ApplyRule(in, workop, workishi, data) {
					return 1
				}
				var logicalform LogicalForm
				if logicalform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_OR, CPUI_INT_XOR:
				var logicalform LogicalForm
				if logicalform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
				var lessthreeway LessThreeWay
				if lessthreeway.ApplyRule(in, workop, workishi, data) {
					return 1
				}
				var equal1form Equal1Form
				if equal1form.ApplyRule(in, workop, workishi, data) {
					return 1
				}
				var equal2form Equal2Form
				if equal2form.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_LESS, CPUI_INT_LESSEQUAL:
				var lessthreeway LessThreeWay
				if lessthreeway.ApplyRule(in, workop, workishi, data) {
					return 1
				}
				var lessconstform LessConstForm
				if lessconstform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL:
				var lessconstform LessConstForm
				if lessconstform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_LEFT:
				var shiftform ShiftForm
				if shiftform.ApplyRuleLeft(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
				var shiftform ShiftForm
				if shiftform.ApplyRuleRight(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INT_MULT:
				var multform MultForm
				if multform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_MULTIEQUAL:
				var phiform PhiForm
				if phiform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_INDIRECT:
				var indform IndirectForm
				if indform.ApplyRule(in, workop, workishi, data) {
					return 1
				}
			case CPUI_COPY:
				if workop.Output() != nil && workop.Output().IsAddrForce() {
					var copyform CopyForceForm
					if copyform.ApplyRule(in, workop, workishi, data) {
						return 1
					}
				}
			default:
				// All other op codes are no-ops for this rule family.
			}
		}
	}
	return 0
}
