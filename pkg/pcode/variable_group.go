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
