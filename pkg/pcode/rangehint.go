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

// RangeHint / MapState type-gathering subset.
//
// C++ parity: varmap.cc RangeHint (isConstAbsorbable:30, preferred:126) and
// MapState (isReadActive:1088, gatherVarnodes:1124, addFixedType:926). This ports
// the part that turns each stack Varnode's *committed* data-type into the
// reconciled Symbol data-type used by ScopeLocal::restructure.
//
// Simplification vs C++: the full disjoint-cover restructure (compareRanges sort +
// merge/attemptJoin/absorb across offsets, gatherOpen + AliasChecker, array
// concretize) is not ported. The stack slots recovered here are disjoint and
// same-sized, so a hint that starts at the same offset always contains/reconciles
// with the others and the surviving data-type is exactly RangeHint::preferred's
// "more specific" pick (Datatype::typeOrder). Reducing per offset is therefore
// equivalent for this slice. Slot enumeration, naming and addrtied stay in
// ScopeLocal.RestructureVarnode. gatherOpen/AliasChecker remain TODO.

// RangeHint boolean flags. C++ parity: RangeHint::copy_constant / typelock.
const (
	rhCopyConstant uint32 = 0x1
	rhTypeLock     uint32 = 0x8
)

// rhRangeType mirrors RangeHint::RangeType (fixed/open/endpoint). Only fixed hints
// are produced here (addFixedType); open hints come from gatherOpen (not ported).
type rhRangeType int

const (
	rhFixed rhRangeType = iota
	rhOpen
	rhEndpoint
)

// rangeHint carries the data-type-selection fields of a C++ RangeHint.
type rangeHint struct {
	typ       Datatype
	size      int32
	flags     uint32
	rangeType rhRangeType
}

func (r *rangeHint) isTypeLock() bool { return r.flags&rhTypeLock != 0 }

// isConstAbsorbable reports whether b (a constant COPY hint) can be absorbed into
// this range as a constant. C++ parity: RangeHint::isConstAbsorbable (varmap.cc:30).
func (r *rangeHint) isConstAbsorbable(b *rangeHint) bool {
	if b.flags&rhCopyConstant == 0 {
		return false
	}
	if b.isTypeLock() {
		return false
	}
	if b.size < r.size {
		return false
	}
	meta := r.typ.Metatype()
	if meta != TYPE_INT && meta != TYPE_UINT && meta != TYPE_BOOL && meta != TYPE_FLOAT {
		return false
	}
	bMeta := b.typ.Metatype()
	if bMeta != TYPE_UNKNOWN && bMeta != TYPE_INT && bMeta != TYPE_UINT {
		return false
	}
	return true
}

// preferred reports whether this range's data-type is preferred over b's.
// C++ parity: RangeHint::preferred (varmap.cc:126), reduced to the same-start
// fixed-range case that per-offset reduction produces (reconcile is always true
// for same-offset same-size hints).
func (r *rangeHint) preferred(b *rangeHint, reconcile bool) bool {
	// C++ returns true early when starts differ; per-offset reduction only ever
	// compares hints at the same start, so that branch is not reachable here.
	if b.isTypeLock() {
		if !r.isTypeLock() {
			return false
		}
	} else if r.isTypeLock() {
		return true
	}
	if r.rangeType == rhOpen && b.rangeType != rhOpen {
		if !reconcile {
			return false
		}
		if r.isConstAbsorbable(b) {
			return true
		}
	} else if b.rangeType == rhOpen && r.rangeType != rhOpen {
		if !reconcile {
			return true
		}
		if b.isConstAbsorbable(r) {
			return false
		}
	} else if r.rangeType == rhFixed && b.rangeType == rhFixed {
		if r.size != b.size && !reconcile {
			return r.size > b.size
		}
	}
	return TypeOrder(r.typ, b.typ) < 0 // Prefer the more specific
}

// mapStateStackTypes gathers the committed data-type of every live stack Varnode
// and reduces the hints at each offset to the preferred (most specific) type.
// It returns a map from stack offset to reconciled data-type.
// C++ parity: MapState::gatherVarnodes (varmap.cc:1124) + the merge/preferred loop
// of ScopeLocal::restructure, per offset.
func mapStateStackTypes(fd *Funcdata, sl *ScopeLocal) map[uint64]*rangeHint {
	out := make(map[uint64]*rangeHint)
	add := func(offset uint64, ct Datatype, flags uint32) {
		// addFixedType: a nil/zero-size type falls back to the default unknown.
		// TYPE_PARTIALSTRUCT/PARTIALUNION handling is omitted (not produced for
		// scalar stack slots). C++ parity: MapState::addFixedType (varmap.cc:926).
		if ct == nil || ct.Size() == 0 {
			return
		}
		h := &rangeHint{typ: ct, size: ct.Size(), flags: flags, rangeType: rhFixed}
		cur := out[offset]
		if cur == nil {
			out[offset] = h
			return
		}
		// merge (same offset -> contain && reconcile): keep the preferred type.
		// C++ parity: RangeHint::merge -> preferred (varmap.cc:259/126).
		if !cur.preferred(h, true) {
			out[offset] = h
		}
	}

	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.Space() == nil || !isStackSpace(vn, sl.model) {
			continue
		}
		if vn.IsFree() {
			continue
		}
		off := vn.Offset()
		if !vn.IsWritten() {
			if mapStateReadActive(vn) {
				add(off, vn.Type(), 0)
			}
			continue
		}
		def := vn.Def()
		if def == nil {
			add(off, vn.Type(), 0)
			continue
		}
		switch def.Code() {
		case CPUI_INDIRECT:
			in0 := def.Input(0)
			if in0 == nil || vn.Addr() != in0.Addr() || mapStateReadActive(vn) {
				add(off, vn.Type(), 0)
			}
		case CPUI_MULTIEQUAL:
			sameAddr := true
			for i := 0; i < def.NumInput(); i++ {
				if in := def.Input(i); in == nil || in.Addr() != vn.Addr() {
					sameAddr = false
					break
				}
			}
			if !sameAddr || mapStateReadActive(vn) {
				add(off, vn.Type(), 0)
			}
		case CPUI_SUBPIECE:
			// Not an active write if it just truncates the same storage location.
			// C++ parity: gatherVarnodes SUBPIECE case (varmap.cc:1181).
			if mapStateSubpieceActive(def, vn) || mapStateReadActive(vn) {
				add(off, vn.Type(), 0)
			}
		case CPUI_COPY:
			flags := uint32(0)
			if in0 := def.Input(0); in0 != nil && in0.IsConstant() {
				flags = rhCopyConstant
			}
			add(off, vn.Type(), flags)
		default:
			// PIECE is treated as two COPYs in C++ (varmap.cc:1165); for scalar
			// stack slots it does not arise, so it falls through to the general
			// active-write case here (TODO: port the PIECE split if needed).
			add(off, vn.Type(), 0)
		}
	}
	return out
}

// mapStateSubpieceActive reports whether a SUBPIECE write targets a different
// storage location than its source (i.e. it is an active write, not a same-slot
// truncation). C++ parity: the addr comparison in gatherVarnodes SUBPIECE
// (varmap.cc:1181-1195).
func mapStateSubpieceActive(def *PcodeOp, vn *Varnode) bool {
	src := def.Input(0)
	amt := def.Input(1)
	if src == nil || amt == nil {
		return true
	}
	var trunc int64
	if src.Space() != nil && src.Space().BigEndian {
		trunc = int64(src.Size()) - int64(vn.Size()) - int64(amt.Offset())
	} else {
		trunc = int64(amt.Offset())
	}
	return src.Offset()+uint64(trunc) != vn.Offset()
}

// mapStateReadActive filters INDIRECT/MULTIEQUAL/PIECE reads that just copy between
// the same storage location. Returns true if some other op actively reads vn.
// C++ parity: MapState::isReadActive (varmap.cc:1088).
func mapStateReadActive(vn *Varnode) bool {
	for _, op := range vn.DescendIter() {
		if op == nil {
			continue
		}
		if op.IsMarker() {
			if op.Output() == nil || vn.Addr() != op.Output().Addr() {
				return true
			}
			continue
		}
		switch op.Code() {
		case CPUI_PIECE:
			out := op.Output()
			if out == nil {
				return true
			}
			addr := out.Addr()
			slot := 1
			if addr.Space != nil && addr.Space.BigEndian {
				slot = 0
			}
			if op.Input(slot) != vn {
				if in := op.Input(slot); in != nil {
					addr.Offset += uint64(in.Size())
				}
			}
			if vn.Addr() != addr {
				return true
			}
		case CPUI_SUBPIECE:
			// Data-type info comes from the output Varnode; ignore the input.
		default:
			return true
		}
	}
	return false
}
