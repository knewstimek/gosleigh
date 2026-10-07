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

import "gosleigh/pkg/address"

// variableGroup collects HighVariables whose storage mutually overlaps (pieces
// of one address-tied variable, e.g. a 4-byte global and a 1-byte read of its
// third byte). C++ parity: VariableGroup.
// Known mismatch: the per-piece intersection lists and extended covers
// (VariablePiece::updateIntersections/updateCover) are not modelled, so merge
// tests do not yet see a piece's overlap with its siblings.
type variableGroup struct {
	pieces []*variablePiece
	size   int64
}

// variablePiece places one HighVariable at a byte offset within its group.
// C++ parity: VariablePiece.
type variablePiece struct {
	group  *variableGroup
	high   *HighVariable
	offset int64
	size   int64
}

// newVariablePiece attaches a piece for h at offset, joining grp's group or a
// new one. C++ parity: VariablePiece::VariablePiece.
func newVariablePiece(h *HighVariable, offset int64, grp *HighVariable) *variablePiece {
	p := &variablePiece{high: h, offset: offset, size: int64(h.size())}
	if grp != nil && grp.piece != nil {
		p.group = grp.piece.group
	} else {
		p.group = &variableGroup{}
	}
	p.group.add(p)
	return p
}

func (g *variableGroup) add(p *variablePiece) {
	g.pieces = append(g.pieces, p)
	if end := p.offset + p.size; end > g.size {
		g.size = end
	}
}

func (g *variableGroup) remove(p *variablePiece) {
	for i, q := range g.pieces {
		if q == p {
			g.pieces = append(g.pieces[:i], g.pieces[i+1:]...)
			return
		}
	}
}

// adjustOffsets shifts every piece. C++ parity: VariableGroup::adjustOffsets.
func (g *variableGroup) adjustOffsets(amt int64) {
	for _, p := range g.pieces {
		p.offset += amt
	}
	g.size += amt
}

// find returns the piece of g at the same offset and size as p.
// C++ parity: pieceSet.find with PieceCompareByOffset.
func (g *variableGroup) find(p *variablePiece) *variablePiece {
	for _, q := range g.pieces {
		if q.offset == p.offset && q.size == p.size {
			return q
		}
	}
	return nil
}

// intersections lists the other pieces of the group overlapping p's bytes.
// C++ parity: VariablePiece::updateIntersections.
func (p *variablePiece) intersections() []*variablePiece {
	var out []*variablePiece
	end := p.offset + p.size
	for _, q := range p.group.pieces {
		if q == p || end <= q.offset || p.offset >= q.offset+q.size {
			continue
		}
		out = append(out, q)
	}
	return out
}

// PartialCopyShadow reports whether the smaller of vn and op2 is a copy of
// the bytes of the larger at relOff (op2's offset relative to vn).
// C++ parity: Varnode::partialCopyShadow.
func (vn *Varnode) PartialCopyShadow(op2 *Varnode, relOff int64) bool {
	small, whole := vn, op2
	switch {
	case vn.Size() < op2.Size():
	case vn.Size() > op2.Size():
		small, whole = op2, vn
		relOff = -relOff
	default:
		return false
	}
	if relOff < 0 || relOff+int64(small.Size()) > int64(whole.Size()) {
		return false // not proper containment
	}
	leastByte := relOff
	if vn.Space() != nil && vn.Space().BigEndian {
		leastByte = int64(whole.Size()-small.Size()) - relOff
	}
	return small.findSubpieceShadow(leastByte, whole, 0) || whole.findPieceShadow(leastByte, small)
}

func skipCopies(vn *Varnode) *Varnode {
	for vn.IsWritten() && vn.Def().Code() == CPUI_COPY {
		vn = vn.Def().Input(0)
	}
	return vn
}

// findSubpieceShadow: is vn a SUBPIECE copy of whole at leastByte?
// C++ parity: Varnode::findSubpieceShadow.
func (vn *Varnode) findSubpieceShadow(leastByte int64, whole *Varnode, recurse int) bool {
	cur := skipCopies(vn)
	if !cur.IsWritten() {
		if cur.IsConstant() {
			w := skipCopies(whole)
			if !w.IsConstant() {
				return false
			}
			off := (w.Offset() >> uint(leastByte*8)) & maskForSize(cur.Size())
			return off == cur.Offset()
		}
		return false
	}
	switch cur.Def().Code() {
	case CPUI_SUBPIECE:
		tmp := cur.Def().Input(0)
		if int64(cur.Def().Input(1).Offset()) != leastByte || tmp.Size() != whole.Size() {
			return false
		}
		if tmp == whole {
			return true
		}
		for tmp.IsWritten() && tmp.Def().Code() == CPUI_COPY {
			tmp = tmp.Def().Input(0)
			if tmp == whole {
				return true
			}
		}
	case CPUI_MULTIEQUAL:
		recurse++
		if recurse > 1 {
			return false // truncate the recursion
		}
		w := skipCopies(whole)
		if !w.IsWritten() || w.Def().Code() != CPUI_MULTIEQUAL {
			return false
		}
		bigOp, smallOp := w.Def(), cur.Def()
		if bigOp.Parent() != smallOp.Parent() {
			return false
		}
		for i := 0; i < smallOp.NumInput(); i++ {
			if !smallOp.Input(i).findSubpieceShadow(leastByte, bigOp.Input(i), recurse) {
				return false
			}
		}
		return true
	}
	return false
}

// findPieceShadow: does vn concatenate piece at leastByte?
// C++ parity: Varnode::findPieceShadow.
func (vn *Varnode) findPieceShadow(leastByte int64, piece *Varnode) bool {
	cur := skipCopies(vn)
	if !cur.IsWritten() || cur.Def().Code() != CPUI_PIECE {
		return false
	}
	tmp := cur.Def().Input(1) // least significant part
	if leastByte >= int64(tmp.Size()) {
		leastByte -= int64(tmp.Size())
		tmp = cur.Def().Input(0)
	} else if int64(piece.Size())+leastByte > int64(tmp.Size()) {
		return false
	}
	if leastByte == 0 && tmp.Size() == piece.Size() {
		if tmp == piece {
			return true
		}
		for tmp.IsWritten() && tmp.Def().Code() == CPUI_COPY {
			tmp = tmp.Def().Input(0)
			if tmp == piece {
				return true
			}
		}
		return false
	}
	return tmp.findPieceShadow(leastByte, piece)
}

// groupRootOf returns the piece holding the whole group when hv is a proper
// part of it, else nil.
func groupRootOf(hv *HighVariable) *variablePiece {
	if hv == nil || hv.piece == nil {
		return nil
	}
	for _, p := range hv.piece.group.pieces {
		if p.offset == 0 && p.size == hv.piece.group.size && p.high != hv {
			return p
		}
	}
	return nil
}

// namedGroupRoot is groupRootOf for naming and printing: a piece takes the
// whole variable's Symbol only when it is a prototype piece or its storage
// lies in a Symbol. An input piece outside every Symbol (the upper bytes of
// a char parameter read as a dword) gets a Symbol of its own and prints as
// an irregular input (in_stack_00000009).
// C++ parity: Funcdata::linkSymbol (linkProtoPartial for a proto-partial
// piece, otherwise queryProperties at the piece's own address).
func namedGroupRoot(hv *HighVariable, sl *ScopeLocal) *variablePiece {
	root := groupRootOf(hv)
	if root == nil || sl == nil {
		return root
	}
	for _, vn := range hv.Instances() {
		if vn.IsProtoPartial() {
			return root
		}
	}
	for _, vn := range hv.Instances() {
		if !vn.IsInput() || vn.Space() != sl.SpaceID() {
			continue
		}
		if sl.QueryContainer(vn.Addr(), 1, address.Address{}) == nil {
			return nil
		}
	}
	// The whole variable lends its Symbol only when that Symbol holds all
	// of it; a bigger write over smaller Symbols is a mismatch (_local_8)
	// and each piece keeps the Symbol at its own address (local_8). An input
	// piece (a parameter) shares the Symbol the mismatch prints through.
	for _, vn := range hv.Instances() {
		if vn.IsInput() {
			return root
		}
	}
	for _, rvn := range root.high.Instances() {
		if rvn.Space() != sl.SpaceID() {
			continue
		}
		if sl.QueryContainer(rvn.Addr(), rvn.Size(), address.Address{}) == nil {
			return nil
		}
		break
	}
	return root
}

// size returns the storage size of the variable.
func (hv *HighVariable) size() int32 {
	for _, vn := range hv.instances {
		if vn != nil {
			return vn.Size()
		}
	}
	return 0
}

// groupWith puts hv at byte offset off relative to hi2 in one group.
// C++ parity: HighVariable::groupWith (intersection bookkeeping omitted).
func (hv *HighVariable) groupWith(off int64, hi2 *HighVariable) {
	switch {
	case hv.piece == nil && hi2.piece == nil:
		hi2.piece = newVariablePiece(hi2, 0, nil)
		hv.piece = newVariablePiece(hv, off, hi2)
	case hv.piece == nil:
		hv.piece = newVariablePiece(hv, off+hi2.piece.offset, hi2)
	case hi2.piece == nil:
		hi2Off := hv.piece.offset - off
		if hi2Off < 0 {
			hv.piece.group.adjustOffsets(-hi2Off)
			hi2Off = 0
		}
		hi2.piece = newVariablePiece(hi2, hi2Off, hv)
	default:
		if diff := hi2.piece.offset + off - hv.piece.offset; diff != 0 {
			hv.piece.group.adjustOffsets(diff)
		}
		if hi2.piece.group != hv.piece.group {
			for _, p := range append([]*variablePiece(nil), hv.piece.group.pieces...) {
				hv.piece.group.remove(p)
				p.group = hi2.piece.group
				hi2.piece.group.add(p)
			}
		}
	}
}

// mergePieces carries the group membership across a merge of src into dst
// and returns the extra pairs that must merge because they hold the same
// piece of the combined group. C++ parity: HighVariable::merge (piece cases)
// and VariablePiece::mergeGroups.
func mergePieces(dst, src *HighVariable) [][2]*HighVariable {
	switch {
	case src.piece == nil:
		return nil
	case dst.piece == nil:
		dst.piece = src.piece // transferPiece
		dst.piece.high = dst
		src.piece = nil
		return nil
	}
	a, b := dst.piece, src.piece
	src.piece = nil
	b.group.remove(b)
	if a.group == b.group {
		return nil
	}
	if diff := a.offset - b.offset; diff > 0 {
		b.group.adjustOffsets(diff)
	} else if diff < 0 {
		a.group.adjustOffsets(-diff)
	}
	var pairs [][2]*HighVariable
	for _, p := range append([]*variablePiece(nil), b.group.pieces...) {
		b.group.remove(p)
		if match := a.group.find(p); match != nil {
			pairs = append(pairs, [2]*HighVariable{match.high, p.high})
			p.high.piece = nil
			continue
		}
		p.group = a.group
		a.group.add(p)
	}
	return pairs
}
