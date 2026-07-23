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
	"fmt"

	"gosleigh/pkg/address"
)

// AliasChecker + MapState::gatherOpen subset.
//
// C++ parity: varmap.cc AliasChecker::gatherAdditiveBase (L741),
// AliasChecker::gatherOffset (L817), AliasChecker::gatherInternal (L660),
// MapState::gatherOpen (L1211), MapState::addRange (L896),
// ScopeLocal::restructure open-range branch (L1313-1318),
// ScopeLocal::adjustFit (L587), ScopeLocal::createEntry (L617),
// ScopeLocal::buildVariableName (L548).
//
// This is the half of ScopeLocal::restructureVarnode that recovers a stack
// object which is never addressed as a whole Varnode: an array reached only
// through a computed pointer (PTRSUB(sp,off) + PTRADD(.,index,step)). The
// fixed-Varnode half already lives in rangehint.go / scopelocal_ext.go.
//
// Deliberate scope limits (each is a known mismatch, not an approximation of
// something we could have ported here):
//   - MapState::addGuard (the LoadGuard arm of gatherOpen) is unreachable:
//     heritage.go declares loadGuards/storeGuards but nothing fills them and
//     Funcdata exposes no getLoadGuards(). The AliasChecker arm alone recovers
//     the pointer references this port needs.
//   - AliasChecker::deriveBoundaries / hasLocalAlias / markUnaliased are not
//     ported. They only feed Varnode::nolocalalias marking, which is a separate
//     (still unported) branch of restructureVarnode; gatherOpen itself never
//     consults the boundaries.
//   - The full RangeHint merge loop (merge/attemptJoin/absorb across offsets)
//     is not ported, so an open hint whose start coincides with an existing
//     fixed stack slot is dropped instead of merged. Only open hints that fall
//     in a gap of the fixed layout create Symbols.

// aliasAddBase is a pointer Varnode into the analyzed space plus the (optional)
// non-constant index value that was added into it.
// C++ parity: varmap.hh AliasChecker::AddBase.
type aliasAddBase struct {
	base  *Varnode
	index *Varnode
}

// gatherAdditiveBase collects the result Varnode of every additive expression
// rooted at startvn, together with the last non-constant index Varnode seen on
// the way. A "sum" is any chain of INT_ADD / INT_SUB / PTRADD / PTRSUB /
// SEGMENTOP / COPY.
//
// The index Varnode is carried the way C++ carries it: `indexvn` is a single
// local that is re-assigned while walking one Varnode's descendants, so a later
// descendant inherits whatever an earlier one stored, and the AddBase pushed
// for the Varnode itself uses the last value. That is load-bearing (it is what
// makes a LOAD off a PTRADD report "has an index"), so it is reproduced
// literally rather than tidied into per-descendant state.
//
// C++ parity: varmap.cc AliasChecker::gatherAdditiveBase (L741).
func gatherAdditiveBase(startvn *Varnode) []aliasAddBase {
	if startvn == nil {
		return nil
	}
	var addbase []aliasAddBase
	vnqueue := []aliasAddBase{{base: startvn}}
	startvn.SetMark()
	push := func(subvn *Varnode, indexvn *Varnode) {
		if subvn == nil || subvn.IsMark() {
			return
		}
		subvn.SetMark()
		vnqueue = append(vnqueue, aliasAddBase{base: subvn, index: indexvn})
	}
	for i := 0; i < len(vnqueue); i++ {
		vn := vnqueue[i].base
		indexvn := vnqueue[i].index
		nonadduse := false
		for _, op := range vn.DescendIter() {
			if op == nil {
				continue
			}
			switch op.Code() {
			case CPUI_COPY:
				// A COPY is both a non-additive use and part of the sum.
				nonadduse = true
				push(op.Output(), indexvn)
			case CPUI_INT_SUB:
				if vn == op.Input(1) { // Subtracting the pointer
					nonadduse = true
					break
				}
				if othervn := op.Input(1); othervn != nil && !othervn.IsConstant() {
					indexvn = othervn
				}
				push(op.Output(), indexvn)
			case CPUI_INT_ADD, CPUI_PTRADD:
				othervn := op.Input(1)
				if othervn == vn {
					othervn = op.Input(0)
				}
				if othervn != nil && !othervn.IsConstant() {
					indexvn = othervn
				}
				fallthrough
			case CPUI_PTRSUB, CPUI_SEGMENTOP:
				push(op.Output(), indexvn)
			default:
				nonadduse = true // Used in a non-additive expression
			}
		}
		if nonadduse {
			addbase = append(addbase, aliasAddBase{base: vn, index: indexvn})
		}
	}
	for _, entry := range vnqueue {
		entry.base.ClearMark()
	}
	return addbase
}

// aliasGatherOffset sums the constant terms of the additive expression rooted
// at vn, walking backwards through additive ops only.
// C++ parity: varmap.cc AliasChecker::gatherOffset (L817).
func aliasGatherOffset(vn *Varnode) uint64 {
	if vn == nil {
		return 0
	}
	if vn.IsConstant() {
		return vn.Offset()
	}
	def := vn.Def()
	if def == nil {
		return 0
	}
	var retval uint64
	switch def.Code() {
	case CPUI_COPY:
		retval = aliasGatherOffset(def.Input(0))
	case CPUI_PTRSUB, CPUI_INT_ADD:
		retval = aliasGatherOffset(def.Input(0)) + aliasGatherOffset(def.Input(1))
	case CPUI_INT_SUB:
		retval = aliasGatherOffset(def.Input(0)) - aliasGatherOffset(def.Input(1))
	case CPUI_PTRADD:
		othervn := def.Input(2)
		idx := def.Input(1)
		retval = aliasGatherOffset(def.Input(0))
		if idx != nil && idx.IsConstant() && othervn != nil {
			retval += idx.Offset() * othervn.Offset()
		} else if othervn != nil && othervn.Offset() == 1 {
			// A PTRADD with step 1 has to be treated exactly like ADD+MULT,
			// because a plain MULT truncates the ADD tree.
			retval += aliasGatherOffset(idx)
		}
	case CPUI_SEGMENTOP:
		retval = aliasGatherOffset(def.Input(2))
	default:
		retval = 0
	}
	return retval & bitfieldSizeMask(vn.Size())
}

// findSpacebaseInput returns the input Varnode holding the base register of the
// given spacebase-kind space (the stack pointer for the stack space).
// C++ parity: funcdata.cc Funcdata::findSpacebaseInput (L291).
func (fd *Funcdata) findSpacebaseInput(id *address.Space) *Varnode {
	if fd == nil || id == nil || id.NumSpacebase() == 0 {
		return nil
	}
	point := id.GetSpacebase(0)
	if point.Space == nil || point.Size == 0 {
		return nil
	}
	return fd.FindVarnodeInput(point.Size, address.Address{Space: point.Space, Offset: point.Offset})
}

// openRangeHint is the subset of a C++ RangeHint that gatherOpen produces:
// always RangeHint::open, always flags==0, with the element data-type and the
// minimum guaranteed array index.
// C++ parity: varmap.cc MapState::gatherOpen -> addRange(...,RangeHint::open,minItems).
//
// minItems mirrors RangeHint::highind. It is recorded but not yet consumed:
// the only readers in C++ are attemptJoin/absorb, which belong to the merge
// loop this port omits.
type openRangeHint struct {
	start    uint64   // Byte offset within the space
	sstart   int64    // Signed form of start
	elem     Datatype // Data-type of a single element
	minItems int      // Biggest guaranteed index (highind)
}

// gatherOpen turns every pointer reference into the scope's space into an open
// RangeHint. The element data-type is read from the pointer Varnode: a real
// TYPE_PTR contributes its (array-stripped) pointee, anything else contributes
// nothing and the default unknown type is used.
// C++ parity: varmap.cc MapState::gatherOpen (L1211) + MapState::addRange (L896).
func (sl *ScopeLocal) gatherOpen(fd *Funcdata) []openRangeHint {
	if sl == nil || fd == nil {
		return nil
	}
	space := sl.SpaceID()
	if space == nil {
		return nil
	}
	spacebase := fd.findSpacebaseInput(space)
	if spacebase == nil {
		return nil // No possible alias
	}
	wordSize := uint64(space.WordSize)
	if wordSize == 0 {
		wordSize = 1
	}
	types := sharedTypeFactory
	defaultType := types.GetBase(1, TYPE_UNKNOWN, "undefined1")

	var hints []openRangeHint
	for _, ab := range gatherAdditiveBase(spacebase) {
		offset := aliasGatherOffset(ab.base) * wordSize // addressToByte
		var ct Datatype
		if ptr, ok := ab.base.Type().(*Pointer); ok {
			ct = ptr.Pointee()
			for {
				arr, isArray := ct.(*Array)
				if !isArray {
					break
				}
				ct = arr.Element()
			}
		}
		// addRange: a missing or zero-sized data-type falls back to the
		// MapState default (getBase(1,TYPE_UNKNOWN)).
		if ct == nil || ct.Size() == 0 {
			ct = defaultType
		}
		minItems := -1
		if ab.index != nil {
			minItems = 3 // With an index, assume it takes on at least [0,3]
		}
		hints = append(hints, openRangeHint{
			start:    offset,
			sstart:   signExtendSpaceOffset(offset, space),
			elem:     ct,
			minItems: minItems,
		})
	}
	return hints
}

// signExtendSpaceOffset converts a raw space offset into its signed form.
// C++ parity: the sign_extend(byteToAddress(...)) pair in MapState::addRange
// (varmap.cc L904-906); word-size scaling cancels out for byte-addressed
// stacks, which is the only configuration Gosleigh currently loads.
func signExtendSpaceOffset(off uint64, space *address.Space) int64 {
	bits := uint(8)
	if space != nil && space.AddrSize > 0 {
		bits = uint(space.AddrSize) * 8
	}
	if bits >= 64 {
		return int64(off)
	}
	shift := 64 - bits
	return int64(off<<shift) >> shift
}

// localWindowFit returns the number of contiguous mapped bytes the scope offers
// starting at the given signed offset, i.e. the value ScopeLocal::adjustFit
// reads out of getRangeTree()->longestFit().
//
// Gosleigh has no per-scope RangeList: ProtoModel.IsLocalOffset draws the same
// boundary the cspec <localrange> does for the negative half of the frame,
// which ends at -1 (the x86-64 Windows cspec spells this
// "0xfffffffffff0bdc1..0xffffffffffffffff"). The window therefore stops at 0,
// exactly like the C++ range tree, whose next range (the +8..+39 home area) is
// not contiguous with it. That 0 boundary is what shrinks the recovered array
// to the bytes below the frame base.
//
// Known mismatch: the separate home-area range is not modelled, so an open hint
// at a non-negative offset yields 0 (adjustFit fails, no Symbol is created).
// C++ parity: address.cc RangeList::longestFit (L512) over ScopeLocal's range tree.
func localWindowFit(sstart int64) uint64 {
	if sstart >= 0 {
		return 0
	}
	return uint64(-sstart)
}

// createOpenEntries adds a Symbol for each open RangeHint that falls in a gap of
// the fixed stack-slot layout. fixedStarts holds the signed start offset of
// every SymbolEntry RestructureVarnode already created, in ascending order.
//
// This is the `cur.rangeType == open` arm of ScopeLocal::restructure
// (varmap.cc L1313-1318) followed by adjustFit + createEntry: an open range is
// stretched to the start of the next hint, clipped to the mapped window, and
// then concretized into an array when it holds more than one element.
// C++ parity: varmap.cc ScopeLocal::restructure / adjustFit / createEntry.
func (sl *ScopeLocal) createOpenEntries(fd *Funcdata, fixedStarts []int64) {
	if sl == nil || fd == nil {
		return
	}
	hints := sl.gatherOpen(fd)
	if len(hints) == 0 {
		return
	}
	ext := sl.ext()
	space := sl.SpaceID()
	types := sharedTypeFactory

	// Collect the start offsets of everything that bounds an open range: the
	// fixed slots plus the other open hints.
	bounds := make([]int64, 0, len(fixedStarts)+len(hints))
	bounds = append(bounds, fixedStarts...)
	seen := make(map[int64]bool, len(hints))
	for _, h := range hints {
		if seen[h.sstart] {
			continue
		}
		seen[h.sstart] = true
		bounds = append(bounds, h.sstart)
	}

	// reconcileDatatypes: among the hints that start at the same offset keep the
	// most specific data-type (Datatype::typeOrder), then drop the duplicates.
	// C++ parity: varmap.cc MapState::reconcileDatatypes (L960).
	reconciled := make([]openRangeHint, 0, len(hints))
	byStart := make(map[int64]int, len(hints))
	for _, h := range hints {
		if pos, ok := byStart[h.sstart]; ok {
			if TypeOrder(h.elem, reconciled[pos].elem) < 0 {
				reconciled[pos].elem = h.elem
			}
			continue
		}
		byStart[h.sstart] = len(reconciled)
		reconciled = append(reconciled, h)
	}
	hints = reconciled

	created := make(map[int64]bool)
	for _, h := range hints {
		if created[h.sstart] {
			continue // One Symbol per start offset
		}
		// An open hint that starts where a fixed slot starts would go through
		// RangeHint::merge in C++; that path is not ported, so leave the fixed
		// slot alone.
		fixedHere := false
		for _, s := range fixedStarts {
			if s == h.sstart {
				fixedHere = true
				break
			}
		}
		if fixedHere {
			continue
		}
		// restructure: an open range runs up to the next hint.
		size := int64(-1)
		for _, s := range bounds {
			if s <= h.sstart {
				continue
			}
			if size < 0 || s-h.sstart < size {
				size = s - h.sstart
			}
		}
		// adjustFit: clip to the mapped window, then to any existing Symbol.
		maxsize := int64(localWindowFit(h.sstart))
		if maxsize == 0 {
			continue
		}
		if size < 0 || maxsize < size {
			if maxsize < int64(h.elem.Size()) {
				continue // Can't shrink that far and keep the data-type
			}
			size = maxsize
		}
		if !sl.openFitAgainstEntries(space, h, &size) {
			continue
		}
		// createEntry: more than one element concretizes into an array.
		ct := h.elem
		align := int64(ct.AlignSize())
		if align <= 0 {
			align = 1
		}
		if num := size / align; num > 1 {
			ct = types.GetArray(int32(num), ct)
		}
		name := sl.buildVariableName(address.Address{Space: space, Offset: h.start}, address.Address{}, ct)
		sym := NewSymbol(name, ct)
		// Stack Symbols carry addrtied for the same reason the fixed slots do
		// (see RestructureVarnode); the recovered array has no Varnode of its
		// own, but keeping the flag consistent means queryContainer answers for
		// it exactly like for a scalar slot.
		sym.SetFlags(VarnodeAddrTied)
		entry := NewSymbolEntry(sym, 0, address.Address{Space: space, Offset: h.start}, int32(size), 0)
		sym.attachEntry(entry)
		ext.entries = append(ext.entries, entry)
		created[h.sstart] = true
	}
}

// openFitAgainstEntries applies the findOverlap half of ScopeLocal::adjustFit:
// an existing Symbol at or below the hint start blocks the fit entirely, and one
// above it shrinks the hint. Returns false when the hint cannot be placed.
// C++ parity: varmap.cc ScopeLocal::adjustFit (L599-611).
func (sl *ScopeLocal) openFitAgainstEntries(space *address.Space, h openRangeHint, size *int64) bool {
	var lowest *SymbolEntry
	target := h.sstart
	end := target + *size - 1
	for _, e := range sl.ext().entries {
		if e == nil || e.IsDynamic() || e.Size() <= 0 {
			continue
		}
		ea := e.Addr()
		if ea.Space != space {
			continue
		}
		first := signExtendSpaceOffset(ea.Offset, space)
		last := first + int64(e.Size()) - 1
		if last < target || first > end {
			continue
		}
		if lowest == nil || first < signExtendSpaceOffset(lowest.Addr().Offset, space) {
			lowest = e
		}
	}
	if lowest == nil {
		return true
	}
	first := signExtendSpaceOffset(lowest.Addr().Offset, space)
	if first <= target {
		// "<" generally shouldn't be possible; "==" is handled by the caller.
		return false
	}
	maxsize := first - target
	if maxsize < int64(h.elem.Size()) {
		return false
	}
	*size = maxsize
	return true
}

// coreStackName builds the C++ decompiler-core default name for a stack slot:
// <printNameBase><Space>[X|Y]_<hex offset>, e.g. "aiStack_48" for an int[18] at
// frame offset -0x48 and "uStackX_c" for an undefined4 at +0xc.
//
// Gosleigh's normal stack naming (ScopeLocal.stackLocalName) emulates the Ghidra
// *Java* naming layer, because every scalar frame slot in the goldens arrives
// already named by the Program DB. A decompiler-recovered aggregate is the one
// case where no Java name exists -- the Java stack-frame analysis never created
// a variable for that range -- so the core name is what reaches the listing.
// Both spellings appear side by side in the goldens (x64_auto
// array_init_then_sum: local_58 / local_54 / aiStack_48).
//
// C++ parity: varmap.cc ScopeLocal::buildVariableName (L548-581). The 'Y'
// (unusual region) marker depends on minParamOffset/maxParamOffset, which
// Gosleigh's ScopeLocal does not track (markNotMapped is unported), so it is
// never emitted; the 'X' (caller-allocated) marker is reproduced.
func coreStackName(space *address.Space, offset uint64, growsNegative bool, ct Datatype) string {
	start := signExtendSpaceOffset(offset, space)
	if growsNegative {
		start = -start
	}
	prefix := datatypeNameBase(ct)
	spacename := "stack"
	if space != nil && space.Name != "" {
		spacename = space.Name
	}
	spacename = string(spacename[0]-32) + spacename[1:] // toupper on the first byte
	marker := ""
	if start <= 0 {
		marker = "X" // Local stack space allocated by the caller
		start = -start
	}
	return fmt.Sprintf("%s%s%s_%x", prefix, spacename, marker, uint64(start))
}

// datatypeNameBase is the name-prefix a data-type contributes to a default
// variable name: the first letter of its name, with pointers and arrays
// prepending 'p' / 'a' and recursing.
// C++ parity: type.hh Datatype::printNameBase (L285), TypePointer::printNameBase
// (L473), TypeArray::printNameBase (L508).
func datatypeNameBase(dt Datatype) string {
	switch typed := dt.(type) {
	case nil:
		return ""
	case *Pointer:
		return "p" + datatypeNameBase(typed.Pointee())
	case *PointerRel:
		return "p" + datatypeNameBase(typed.Pointee())
	case *Array:
		return "a" + datatypeNameBase(typed.Element())
	}
	name := dt.Name()
	if name == "" {
		return ""
	}
	return name[:1]
}
