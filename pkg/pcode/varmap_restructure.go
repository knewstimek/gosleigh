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
	"sort"

	"gosleigh/pkg/address"
)

// RangeHint / MapState / ScopeLocal::restructure.
//
// C++ parity: varmap.cc. Every stack Varnode, every pointer into the frame
// (gatherOpen) and the end of the mapped range become RangeHints; sorted and
// swept once, intersecting hints merge, open hints stretch to the next one,
// and each surviving hint becomes one stack Symbol.
//
// Known mismatches: the scope range still includes the parameter area (C++
// MapState removes it and fakeInputSymbols covers stack inputs, which is not
// ported); LoadGuard hints (addGuard), locked-symbol hints (gatherSymbols) and
// partial struct/union types are not modelled.

// RangeHint flags. C++ parity: RangeHint::copy_constant / typelock.
const (
	rhCopyConstant uint32 = 0x1
	rhTypeLock     uint32 = 0x8
)

// rhRangeType is RangeHint::RangeType.
type rhRangeType int

const (
	rhFixed    rhRangeType = iota // a data-type of known size
	rhOpen                        // an array of unknown extent
	rhEndpoint                    // the artificial bound after the last range
)

// mapHint is one RangeHint. C++ parity: varmap.hh RangeHint.
type mapHint struct {
	start     uint64      // byte offset in the space
	size      int32       // bytes covered
	sstart    int64       // signed start, for ordering
	typ       Datatype    // putative data-type (element type for open hints)
	flags     uint32      // rhCopyConstant | rhTypeLock
	rangeType rhRangeType // fixed, open or endpoint
	highind   int         // biggest guaranteed array index, -1 if none
}

func (a *mapHint) isTypeLock() bool { return a.flags&rhTypeLock != 0 }

// isConstAbsorbable: this (open) primitive range can absorb b, a constant
// being COPYed. C++ parity: RangeHint::isConstAbsorbable.
func (a *mapHint) isConstAbsorbable(b *mapHint) bool {
	if b.flags&rhCopyConstant == 0 || b.isTypeLock() || b.size < a.size {
		return false
	}
	switch a.typ.Metatype() {
	case TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT:
	default:
		return false
	}
	switch b.typ.Metatype() {
	case TYPE_UNKNOWN, TYPE_INT, TYPE_UINT:
	default:
		return false
	}
	end := a.sstart
	if a.highind > 0 {
		end += int64(a.highind) * int64(a.typ.AlignSize())
	} else {
		end += int64(a.size)
	}
	return b.sstart <= end
}

// reconcile: the data-types of the two intersecting ranges line up.
// C++ parity: RangeHint::reconcile.
func (a *mapHint) reconcile(b *mapHint) bool {
	if a.typ.AlignSize() < b.typ.AlignSize() {
		a, b = b, a // b is the smallest
	}
	align := int64(a.typ.AlignSize())
	mod := (b.sstart - a.sstart) % align
	if mod < 0 {
		mod += align
	}
	sub := a.typ
	for sub != nil && sub.AlignSize() > b.typ.AlignSize() {
		sub, mod = datatypeSubType(sub, mod)
	}
	if sub != nil && sub.AlignSize() == b.typ.AlignSize() {
		return true
	}
	// Component sizes do not match: protect some data-types more.
	if b.rangeType == rhOpen && b.isConstAbsorbable(a) {
		return true
	}
	if b.isTypeLock() {
		return false
	}
	switch a.typ.Metatype() {
	case TYPE_STRUCT, TYPE_UNION:
	case TYPE_ARRAY:
		if arr, ok := a.typ.(*Array); !ok || arr.Element().Metatype() != TYPE_UNKNOWN {
			return false
		}
	default:
		return false
	}
	switch b.typ.Metatype() {
	case TYPE_UNKNOWN, TYPE_INT, TYPE_UINT:
		return true // b looks like a partial/combined data-type
	}
	return false
}

// contain: one of the intersecting ranges contains the other (a starts no
// later). C++ parity: RangeHint::contain.
func (a *mapHint) contain(b *mapHint) bool {
	return a.sstart == b.sstart || b.sstart+int64(b.size) <= a.sstart+int64(a.size)
}

// preferred: a's data-type wins over b's. C++ parity: RangeHint::preferred.
func (a *mapHint) preferred(b *mapHint, reconcile bool) bool {
	if a.start != b.start {
		return true // something must occupy a.start to b.start
	}
	if b.isTypeLock() {
		if !a.isTypeLock() {
			return false
		}
	} else if a.isTypeLock() {
		return true
	}
	switch {
	case a.rangeType == rhOpen && b.rangeType != rhOpen:
		if !reconcile {
			return false // throw out the open range
		}
		if a.isConstAbsorbable(b) {
			return true
		}
	case b.rangeType == rhOpen && a.rangeType != rhOpen:
		if !reconcile {
			return true
		}
		if b.isConstAbsorbable(a) {
			return false
		}
	case a.rangeType == rhFixed && b.rangeType == rhFixed:
		if a.size != b.size && !reconcile {
			return a.size > b.size
		}
	}
	return TypeOrder(a.typ, b.typ) < 0 // the more specific
}

// attemptJoin absorbs the following range b into this open array range
// when they line up. C++ parity: RangeHint::attemptJoin.
func (a *mapHint) attemptJoin(b *mapHint) bool {
	if a.rangeType != rhOpen || b.rangeType == rhEndpoint {
		return false
	}
	if a.isConstAbsorbable(b) {
		a.absorb(b)
		return true
	}
	if a.highind < 0 {
		return false
	}
	settype := a.typ
	if settype.AlignSize() != b.typ.AlignSize() {
		return false
	}
	if settype != b.typ {
		at, bt := a.typ, b.typ
		for at.Metatype() == TYPE_PTR && bt.Metatype() == TYPE_PTR {
			at, bt = at.(*Pointer).Pointee(), bt.(*Pointer).Pointee()
		}
		am, bm := at.Metatype(), bt.Metatype()
		switch {
		case am == TYPE_UNKNOWN:
			settype = b.typ
		case bm == TYPE_UNKNOWN:
		case am == TYPE_INT && bm == TYPE_UINT:
		case am == TYPE_UINT && bm == TYPE_INT:
		case at != bt:
			return false // both known: they must be the same
		}
	}
	if a.isTypeLock() || b.isTypeLock() {
		return false
	}
	diffsz := b.sstart - a.sstart
	align := int64(settype.AlignSize())
	if diffsz%align != 0 || diffsz/align > int64(a.highind) {
		return false
	}
	a.typ = settype
	a.absorb(b)
	return true
}

// absorb takes over b's range properties (but not its data-type).
// C++ parity: RangeHint::absorb.
func (a *mapHint) absorb(b *mapHint) {
	if b.rangeType == rhOpen {
		if a.typ.AlignSize() == b.typ.AlignSize() { // compatible element type
			a.rangeType = rhOpen
			if b.highind >= 0 { // b has array indexing
				diffsz := (b.sstart - a.sstart) / int64(a.typ.AlignSize())
				if trialhi := b.highind + int(diffsz); a.highind < trialhi {
					a.highind = trialhi
				}
			}
		} else if a.start == b.start {
			if meta := a.typ.Metatype(); meta != TYPE_STRUCT && meta != TYPE_UNION {
				a.rangeType = rhOpen
			}
		}
	} else if b.flags&rhCopyConstant != 0 && a.rangeType == rhOpen {
		if diffsz := b.sstart - a.sstart + int64(b.size); diffsz > int64(a.size) {
			if trialhi := int(diffsz / int64(a.typ.AlignSize())); a.highind < trialhi {
				a.highind = trialhi
			}
		}
	}
	if a.flags&rhCopyConstant != 0 && b.flags&rhCopyConstant == 0 {
		a.flags ^= rhCopyConstant
	}
}

// merge makes a the union of the two intersecting ranges. Returns true on
// an unreconcilable overlap. C++ parity: RangeHint::merge.
func (a *mapHint) merge(b *mapHint, types *TypeFactory) bool {
	var didReconcile bool
	resType := 2 // 0 = a, 1 = b, 2 = confused
	if a.contain(b) {
		didReconcile = a.reconcile(b)
		if didReconcile || a.start == b.start {
			resType = 1
			if a.preferred(b, didReconcile) {
				resType = 0
			}
		}
	} else if a.isTypeLock() {
		resType = 0
	}
	if !didReconcile && a.isTypeLock() {
		if b.isTypeLock() {
			panic("Overlapping forced variable types : " + a.typ.Name() + "   " + b.typ.Name())
		}
		if a.start != b.start {
			return false // discard b entirely
		}
	}
	switch resType {
	case 0:
		a.absorb(b)
	case 1:
		old := *a
		a.typ, a.flags, a.rangeType, a.highind, a.size = b.typ, b.flags, b.rangeType, b.highind, b.size
		a.absorb(&old)
	default:
		// Concede confusion: an unknown type covering both.
		a.flags = 0
		a.rangeType = rhFixed
		if diff := int32(b.sstart - a.sstart); diff+b.size > a.size {
			a.size = diff + b.size
		}
		if a.size != 1 && a.size != 2 && a.size != 4 && a.size != 8 {
			a.size = 1
			a.rangeType = rhOpen
		}
		a.typ = types.GetBase(a.size, TYPE_UNKNOWN, "")
		a.highind = -1
	}
	return false
}

// compareHints orders by signed start, size, range type, flags, highind.
// C++ parity: RangeHint::compare.
func compareHints(a, b *mapHint) int {
	switch {
	case a.sstart != b.sstart:
		return cmpInt64(a.sstart, b.sstart)
	case a.size != b.size:
		return cmpInt64(int64(a.size), int64(b.size))
	case a.rangeType != b.rangeType:
		return cmpInt64(int64(a.rangeType), int64(b.rangeType))
	case a.flags != b.flags:
		return cmpInt64(int64(a.flags), int64(b.flags))
	}
	return cmpInt64(int64(a.highind), int64(b.highind))
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// mapState collects the RangeHints for one restructure.
// C++ parity: varmap.hh MapState.
type mapState struct {
	sl          *ScopeLocal
	space       *address.Space
	defaultType Datatype
	types       *TypeFactory
	hints       []*mapHint
}

// addRange records a hint inside the scope's range.
// C++ parity: MapState::addRange.
func (ms *mapState) addRange(st uint64, ct Datatype, fl uint32, rt rhRangeType, hi int) {
	if ct == nil || ct.Size() == 0 {
		ct = ms.defaultType
	}
	sz := ct.Size()
	if !ms.sl.inScopeRange(st, sz) || ms.sl.inParamRange(st, sz) {
		return
	}
	ms.hints = append(ms.hints, &mapHint{start: st, size: sz, sstart: signExtendSpaceOffset(st, ms.space),
		typ: ct, flags: fl, rangeType: rt, highind: hi})
}

// isReadActive: vn is read by something other than a copy between the same
// storage (markers, PIECE into place, SUBPIECE).
// C++ parity: MapState::isReadActive.
func mapStateIsReadActive(vn *Varnode) bool {
	for _, op := range vn.DescendIter() {
		switch {
		case op.IsMarker():
			if vn.Addr() != op.Output().Addr() {
				return true
			}
		case op.Code() == CPUI_PIECE:
			addr := op.Output().Addr()
			slot := 1
			if addr.Space.BigEndian {
				slot = 0
			}
			if op.Input(slot) != vn {
				addr.Offset += uint64(op.Input(slot).Size())
			}
			if vn.Addr() != addr {
				return true
			}
		case op.Code() == CPUI_SUBPIECE:
			// data-type information comes from the output
		default:
			return true
		}
	}
	return false
}

// hintType is vn's data-type, undefined of its size when none is committed
// yet (a C++ Varnode always carries one).
func hintType(vn *Varnode) Datatype {
	if dt := vn.Type(); dt != nil {
		return dt
	}
	return sharedTypeFactory.GetBase(vn.Size(), TYPE_UNKNOWN, "")
}

// gatherVarnodes adds a fixed hint for every stack Varnode that actively
// holds a value. C++ parity: MapState::gatherVarnodes.
func (ms *mapState) gatherVarnodes(fd *Funcdata) {
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn.IsFree() || vn.Space() != ms.space {
			continue
		}
		if !vn.IsWritten() {
			if mapStateIsReadActive(vn) {
				ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
			}
			continue
		}
		op := vn.Def()
		switch op.Code() {
		case CPUI_INDIRECT:
			if vn.Addr() != op.Input(0).Addr() || mapStateIsReadActive(vn) {
				ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
			}
		case CPUI_MULTIEQUAL:
			same := true
			for i := 0; i < op.NumInput(); i++ {
				if vn.Addr() != op.Input(i).Addr() {
					same = false
					break
				}
			}
			if !same || mapStateIsReadActive(vn) {
				ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
			}
		case CPUI_PIECE: // two COPYs
			addr := vn.Addr()
			slot := 1
			if addr.Space.BigEndian {
				slot = 0
			}
			inFirst := op.Input(slot)
			if inFirst.Addr() != addr {
				ms.addRange(addr.Offset, hintType(inFirst), 0, rhFixed, -1)
			}
			addr.Offset += uint64(inFirst.Size())
			if inSecond := op.Input(1 - slot); inSecond.Addr() != addr {
				ms.addRange(addr.Offset, hintType(inSecond), 0, rhFixed, -1)
			}
			if mapStateIsReadActive(vn) {
				ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
			}
		case CPUI_SUBPIECE:
			// Not an active write when just copying within the same storage.
			addr := op.Input(0).Addr()
			trunc := int32(op.Input(1).Offset())
			if addr.Space.BigEndian {
				trunc = op.Input(0).Size() - vn.Size() - trunc
			}
			addr.Offset += uint64(trunc)
			if addr != vn.Addr() || mapStateIsReadActive(vn) {
				ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
			}
		case CPUI_COPY:
			var fl uint32
			if op.Input(0).IsConstant() {
				fl = rhCopyConstant
			}
			ms.addRange(vn.Offset(), hintType(vn), fl, rhFixed, -1)
		default:
			ms.addRange(vn.Offset(), hintType(vn), 0, rhFixed, -1)
		}
	}
}

// initialize appends the bounding endpoint, sorts and reconciles. Returns
// false when there is nothing to map. C++ parity: MapState::initialize.
func (ms *mapState) initialize() bool {
	ranges := ms.sl.scopeRanges()
	if len(ranges) == 0 || len(ms.hints) == 0 {
		return false
	}
	// The last range in signed order bounds any final open hint.
	last := ranges[0]
	for _, r := range ranges[1:] {
		if signExtendSpaceOffset(r[0], ms.space) > signExtendSpaceOffset(last[0], ms.space) {
			last = r
		}
	}
	high := wrapSpaceOffset(ms.space, last[1]+1)
	ms.hints = append(ms.hints, &mapHint{start: high, size: 1, sstart: signExtendSpaceOffset(high, ms.space),
		typ: ms.defaultType, rangeType: rhEndpoint, highind: -2})
	sort.SliceStable(ms.hints, func(i, j int) bool { return compareHints(ms.hints[i], ms.hints[j]) < 0 })
	ms.reconcileDatatypes()
	return true
}

// reconcileDatatypes gives every hint with the same start, size and flags
// the most specific of their data-types and drops duplicates.
// C++ parity: MapState::reconcileDatatypes.
func (ms *mapState) reconcileDatatypes() {
	list := ms.hints
	newList := []*mapHint{list[0]}
	startPos := 0
	startHint := list[0]
	startType := startHint.typ
	flush := func() {
		for ; startPos < len(newList); startPos++ {
			newList[startPos].typ = startType
		}
	}
	for _, cur := range list[1:] {
		if cur.start == startHint.start && cur.size == startHint.size && cur.flags == startHint.flags {
			if TypeOrder(cur.typ, startType) < 0 {
				startType = cur.typ
			}
			if compareHints(cur, newList[len(newList)-1]) != 0 {
				newList = append(newList, cur)
			}
			continue
		}
		flush()
		startHint = cur
		startType = cur.typ
		newList = append(newList, cur)
	}
	flush()
	ms.hints = newList
}

// scopeRanges is the scope's mapped stack ranges, sorted, with the
// MarkNotMapped holes cut out. C++ parity: ScopeLocal's range tree.
func (sl *ScopeLocal) scopeRanges() [][2]uint64 {
	var out [][2]uint64
	for _, r := range sl.model.StackRanges() {
		pieces := [][2]uint64{r}
		for _, hole := range sl.ext().notMapped {
			var next [][2]uint64
			for _, p := range pieces {
				if hole[1] < p[0] || hole[0] > p[1] {
					next = append(next, p)
					continue
				}
				if hole[0] > p[0] {
					next = append(next, [2]uint64{p[0], hole[0] - 1})
				}
				if hole[1] < p[1] {
					next = append(next, [2]uint64{hole[1] + 1, p[1]})
				}
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// inParamRange: [st, st+sz) touches the parameter range, which MapState
// removes from its range (stack inputs get their symbols elsewhere).
// C++ parity: MapState::MapState (range.removeRange over the param range).
func (sl *ScopeLocal) inParamRange(st uint64, sz int32) bool {
	last := st + uint64(sz) - 1
	for _, r := range sl.model.ParamRanges() {
		if st <= r[1] && last >= r[0] {
			return true
		}
	}
	return false
}

// inScopeRange: [st, st+sz) lies inside one mapped range.
// C++ parity: RangeList::inRange.
func (sl *ScopeLocal) inScopeRange(st uint64, sz int32) bool {
	for _, r := range sl.scopeRanges() {
		if st >= r[0] && st+uint64(sz)-1 <= r[1] && st+uint64(sz)-1 >= st {
			return true
		}
	}
	return false
}

// longestFit is how many mapped bytes run from off, chaining adjacent
// ranges, stopping once maxsize is reached. C++ parity: RangeList::longestFit.
func (sl *ScopeLocal) longestFit(off uint64, maxsize uint64) uint64 {
	ranges := sl.scopeRanges()
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i][0] > off })
	if i == 0 {
		return 0
	}
	i--
	if ranges[i][1] < off {
		return 0
	}
	var sizeres uint64
	for ; i < len(ranges) && ranges[i][0] <= off; i++ {
		sizeres += ranges[i][1] + 1 - off
		off = ranges[i][1] + 1
		if sizeres >= maxsize {
			break
		}
	}
	return sizeres
}

// adjustFit shrinks the hint so it fits the mapped region and overlaps no
// Symbol already made. C++ parity: ScopeLocal::adjustFit.
func (sl *ScopeLocal) adjustFit(a *mapHint) bool {
	if a.size == 0 || a.isTypeLock() {
		return false
	}
	maxsize := sl.longestFit(a.start, uint64(a.size))
	if maxsize == 0 {
		return false
	}
	if maxsize < uint64(a.size) {
		if maxsize < uint64(a.typ.Size()) {
			return false
		}
		a.size = int32(maxsize)
	}
	entry := sl.overlapEntry(a.start, a.size)
	if entry == nil {
		return true
	}
	if entry.Addr().Offset <= a.start {
		return false
	}
	maxsize = entry.Addr().Offset - a.start
	if maxsize < uint64(a.typ.Size()) {
		return false
	}
	a.size = int32(maxsize)
	return true
}

// overlapEntry is the lowest stack entry overlapping [start, start+size).
// C++ parity: ScopeInternal::findOverlap.
func (sl *ScopeLocal) overlapEntry(start uint64, size int32) *SymbolEntry {
	var best *SymbolEntry
	last := start + uint64(size) - 1
	for _, e := range sl.ext().entries {
		if e.IsDynamic() || e.Size() <= 0 || e.Addr().Space != sl.SpaceID() {
			continue
		}
		f := e.Addr().Offset
		if f > last || f+uint64(e.Size())-1 < start {
			continue
		}
		if best == nil || f < best.Addr().Offset {
			best = e
		}
	}
	return best
}

// createEntry makes the Symbol for a final hint, an array when it holds
// more than one element. C++ parity: ScopeLocal::createEntry.
func (sl *ScopeLocal) createEntry(a *mapHint) {
	addr := address.Address{Space: sl.SpaceID(), Offset: a.start}
	ct := a.typ
	if align := ct.AlignSize(); align > 0 {
		if num := a.size / align; num > 1 {
			ct = sharedTypeFactory.GetArray(num, ct)
		}
	}
	// A host symbol fixing this slot's type keeps it (and its lock).
	locked := false
	if t, ok := sl.ext().hostLocalTypes[a.start]; ok && t.Size() == a.size {
		ct, locked = t, true
	}
	sym := NewSymbol(sl.buildVariableName(addr, address.Address{}, ct), ct)
	// Stack slots are address-tied: no usepoint limits them, and the flag has
	// to reach the Varnodes before the speculative merges.
	// C++ parity: ScopeInternal::buildFrom (addrtied without a usepoint).
	sym.SetFlags(VarnodeAddrTied)
	if locked {
		sym.SetFlags(VarnodeTypeLock | VarnodeNameLock)
	}
	entry := NewSymbolEntry(sym, 0, addr, a.size, 0)
	sym.attachEntry(entry)
	sl.ext().entries = append(sl.ext().entries, entry)
}

// restructureMap sweeps the sorted hints into a disjoint cover of Symbols.
// Returns true on unreconcilable overlaps. C++ parity: ScopeLocal::restructure.
func (sl *ScopeLocal) restructureMap(ms *mapState) bool {
	overlapProblems := false
	if !ms.initialize() {
		return false // no references to the stack at all
	}
	cur := *ms.hints[0]
	for _, next := range ms.hints[1:] {
		if next.sstart < cur.sstart+int64(cur.size) { // the ranges intersect
			if cur.merge(next, ms.types) {
				overlapProblems = true
			}
			continue
		}
		if !cur.attemptJoin(next) {
			if cur.rangeType == rhOpen {
				cur.size = int32(next.sstart - cur.sstart)
			}
			if sl.adjustFit(&cur) {
				sl.createEntry(&cur)
			}
			cur = *next
		}
	}
	// The last hint is the artificial endpoint: no Symbol for it.
	return overlapProblems
}

// fakeInputSymbols gives each run of overlapping stack inputs in the
// parameter range an unnamed undefined Symbol, so references into the
// parameter area resolve (&param_1).
// C++ parity: ScopeLocal::fakeInputSymbols. Symbols of a locked prototype
// (function_parameter) are not modelled, so lockedinputs is always 0.
func (sl *ScopeLocal) fakeInputSymbols(fd *Funcdata) {
	space := sl.SpaceID()
	var inputs []*Varnode
	for _, vn := range fd.GetVarnodeBank().AllVarnodes() {
		if vn.IsInput() && vn.Space() == space {
			inputs = append(inputs, vn)
		}
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Offset() != inputs[j].Offset() {
			return inputs[i].Offset() < inputs[j].Offset()
		}
		return inputs[i].Size() < inputs[j].Size()
	})
	for i := 0; i < len(inputs); {
		vn := inputs[i]
		i++
		if !sl.inParamRange(vn.Offset(), 1) {
			continue // only offsets that can be parameters
		}
		locked := vn.IsTypeLock()
		start := vn.Offset()
		endpoint := start + uint64(vn.Size()) - 1
		for ; i < len(inputs) && inputs[i].Offset() <= endpoint; i++ {
			if e := inputs[i].Offset() + uint64(inputs[i].Size()) - 1; e > endpoint {
				endpoint = e
			}
			locked = locked || inputs[i].IsTypeLock()
		}
		if locked {
			continue
		}
		size := int32(endpoint-start) + 1
		addr := address.Address{Space: space, Offset: start}
		sym := NewSymbol("", sharedTypeFactory.GetBase(size, TYPE_UNKNOWN, ""))
		sym.SetFlags(VarnodeAddrTied)
		sym.SetCategory(SymbolFakeInput, -1)
		entry := NewSymbolEntry(sym, 0, addr, size, 0)
		sym.attachEntry(entry)
		sl.ext().entries = append(sl.ext().entries, entry)
	}
}
