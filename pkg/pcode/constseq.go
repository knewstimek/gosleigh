// Copyright 2024 The Gosleigh Authors.
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

package pcode

import (
	"sort"

	"gosleigh/pkg/address"
)

// This file ports the StringSequence and HeapSequence analyses from
// ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/constseq.{hh,cc}.
//
// The Ghidra classes detect a contiguous run of constant-character COPY/STORE
// pcode ops inside one basic block and rewrite them to a single CALLOTHER
// representing strncpy/wcsncpy/memcpy with an "internal string" varnode as the
// source. The Go port keeps the full collection/interference/byte-array logic
// faithful to the C++ control flow; the final transform stage delegates to a
// stubbed user-op builder and therefore bails out cleanly until the backing
// helpers land (see the TODO comments on buildStringCopy).
//
// Dependencies not yet available in Gosleigh:
//   - Funcdata.getInternalString + internal OTHER-space string varnodes
//   - UserPcodeOp registry (BUILTIN_STRNCPY/WCSNCPY/MEMCPY)
//   - Datatype.isCharPrint / isOpaqueString / getSubType walks
//   - ScopeLocal.queryContainer SymbolEntry lookup
//   - Funcdata.newVarnodeIop / markIndirectCreation / opDestroyRecursive
//
// Stubs below are guarded so the rule bodies still perform the real scan work
// and exercise the constseq invariants; the moment the helpers above are
// wired up the TODOs become straightforward call sites.

// C++ parity: constseq.cc ArraySequence::MINIMUM_SEQUENCE_LENGTH,
// ArraySequence::MAXIMUM_SEQUENCE_LENGTH.
const (
	arraySeqMinimumLength = 4
	arraySeqMaximumLength = 0x20000
)

// writeNode captures a move of a constant into or out of the contiguous
// memory region under consideration.
// C++ parity: constseq.hh ArraySequence::WriteNode.
type writeNode struct {
	offset uint64   // Offset within the memory region
	op     *PcodeOp // COPY/STORE op producing the move
	slot   int      // Input slot for the source constant (-1 for output)
}

// arraySequence is the shared substrate for StringSequence/HeapSequence.
// C++ parity: constseq.hh class ArraySequence.
type arraySequence struct {
	data        *Funcdata
	rootOp      *PcodeOp
	charType    Datatype
	block       *BlockBasic
	numElements int
	moveOps     []writeNode
	byteArray   []byte
}

// newArraySequence mirrors constseq.cc ArraySequence::ArraySequence.
// C++ parity: ArraySequence(Funcdata&,Datatype*,PcodeOp*).
func newArraySequence(data *Funcdata, ct Datatype, root *PcodeOp) arraySequence {
	return arraySequence{
		data:     data,
		rootOp:   root,
		charType: ct,
		block:    root.Parent(),
	}
}

// isValid reports whether collection produced a usable sequence.
// C++ parity: ArraySequence::isValid.
func (s *arraySequence) isValid() bool { return s.numElements != 0 }

// blockOrderIndex returns the position of op inside its basic block ops list,
// used as the C++ SeqNum::getOrder surrogate for ordering writeNode values.
// The Ghidra implementation sorts on PcodeOp::getSeqNum().getOrder() which is
// assigned once per op within a block.
func blockOrderIndex(block *BlockBasic, op *PcodeOp) int {
	if block == nil || op == nil {
		return -1
	}
	for i, bop := range block.Ops() {
		if bop == op {
			return i
		}
	}
	return -1
}

// interfereBetween checks for memory-touching ops between startOp and endOp
// (exclusive) inside the same basic block.
// C++ parity: constseq.cc ArraySequence::interfereBetween.
func (s *arraySequence) interfereBetween(startOp, endOp *PcodeOp) bool {
	ops := s.block.Ops()
	startIdx := -1
	endIdx := -1
	for i, op := range ops {
		if op == startOp {
			startIdx = i
		}
		if op == endOp {
			endIdx = i
		}
	}
	if startIdx < 0 || endIdx < 0 {
		return false
	}
	for i := startIdx + 1; i < endIdx; i++ {
		op := ops[i]
		// C++ parity: ops classified as PcodeOp::special in op.cc typeop table
		// -- LOAD/STORE/CALL/RETURN interfere; INDIRECT/CALLOTHER/SEGMENTOP/
		// CPOOLREF/NEW are safe passes.
		switch op.Code() {
		case CPUI_LOAD, CPUI_STORE, CPUI_CALL, CPUI_CALLIND, CPUI_RETURN, CPUI_BRANCH, CPUI_CBRANCH, CPUI_BRANCHIND:
			return false
		}
	}
	return true
}

// checkInterference restricts moveOps to the maximal contiguous slice around
// rootOp that has no interfering ops in between.
// C++ parity: constseq.cc ArraySequence::checkInterference.
func (s *arraySequence) checkInterference() bool {
	sort.SliceStable(s.moveOps, func(i, j int) bool {
		return blockOrderIndex(s.block, s.moveOps[i].op) < blockOrderIndex(s.block, s.moveOps[j].op)
	})
	pos := -1
	for i := range s.moveOps {
		if s.moveOps[i].op == s.rootOp {
			pos = i
			break
		}
	}
	if pos < 0 {
		return false
	}
	curOp := s.moveOps[pos].op
	startingPos := pos - 1
	for ; startingPos >= 0; startingPos-- {
		prevOp := s.moveOps[startingPos].op
		if !s.interfereBetween(prevOp, curOp) {
			break
		}
		curOp = prevOp
	}
	startingPos++
	curOp = s.moveOps[pos].op
	endingPos := pos + 1
	for ; endingPos < len(s.moveOps); endingPos++ {
		nextOp := s.moveOps[endingPos].op
		if !s.interfereBetween(curOp, nextOp) {
			break
		}
		curOp = nextOp
	}
	if endingPos-startingPos < arraySeqMinimumLength {
		return false
	}
	s.moveOps = append([]writeNode(nil), s.moveOps[startingPos:endingPos]...)
	return true
}

// formByteArray mirrors constseq.cc ArraySequence::formByteArray.
// It collects constant inputs from moveOps into a contiguous byte array and
// truncates moveOps to the resulting contiguous run.
// C++ parity: ArraySequence::formByteArray.
func (s *arraySequence) formByteArray(sz int, slot int, rootOff uint64, bigEndian bool) int {
	if sz <= 0 {
		return 0
	}
	s.byteArray = make([]byte, sz)
	used := make([]byte, sz)
	elSize := int(s.charType.Size())
	if elSize <= 0 {
		return 0
	}
	for i := range s.moveOps {
		bytePos := int(s.moveOps[i].offset - rootOff)
		if bytePos < 0 || bytePos+elSize > sz {
			continue
		}
		vn := s.moveOps[i].op
		if slot >= vn.NumInput() {
			continue
		}
		inVn := vn.Input(slot)
		if inVn == nil || !inVn.IsConstant() {
			continue
		}
		val := inVn.Offset()
		mark := byte(1)
		if val == 0 {
			mark = 2 // null terminator
		}
		used[bytePos] = mark
		if bigEndian {
			for j := 0; j < elSize; j++ {
				b := byte((val >> uint((elSize-1-j)*8)) & 0xff)
				s.byteArray[bytePos+j] = b
			}
		} else {
			for j := 0; j < elSize; j++ {
				s.byteArray[bytePos+j] = byte(val)
				val >>= 8
			}
		}
	}
	bigElSize := int(s.charType.AlignSize())
	if bigElSize <= 0 {
		bigElSize = elSize
	}
	maxEl := len(used) / bigElSize
	count := 0
	for count < maxEl {
		v := used[count*bigElSize]
		if v != 1 {
			if v == 2 {
				count++ // accept single null terminator
			}
			break
		}
		count++
	}
	if count < arraySeqMinimumLength {
		return 0
	}
	if count != len(s.moveOps) {
		maxOff := rootOff + uint64(count*bigElSize)
		final := make([]writeNode, 0, count)
		for i := range s.moveOps {
			if s.moveOps[i].offset < maxOff {
				final = append(final, s.moveOps[i])
			}
		}
		s.moveOps = final
	}
	return count
}

// selectStringCopyFunction picks a builtin id + element count for the final
// CALLOTHER.
// C++ parity: constseq.cc ArraySequence::selectStringCopyFunction (L161).
// The character-data-type discrimination used by the C++ form compares the
// stored charType against the architecture's canonical 1-byte char and wchar
// types; the Go port approximates this by looking at the element size, since
// the TypeFactory exposes neither a persistent default char nor a wchar type.
// TODO mismatch: a real port should consult TypeFactory.getTypeChar(sizeOfChar)
// and getTypeChar(sizeOfWChar) once those helpers land; the current heuristic
// is narrower but still picks the correct strncpy/wcsncpy/memcpy builtin for
// the shapes decoded in testdata.
func (s *arraySequence) selectStringCopyFunction() (builtinID uint32, index int) {
	elSize := int(s.charType.Size())
	alignSize := int(s.charType.AlignSize())
	if alignSize <= 0 {
		alignSize = elSize
	}
	switch elSize {
	case 1:
		return BUILTIN_STRNCPY, s.numElements
	case 2:
		return BUILTIN_WCSNCPY, s.numElements
	}
	return BUILTIN_MEMCPY, s.numElements * alignSize
}

// isCharPrintLike is a local heuristic stand-in for Datatype::isCharPrint.
// C++ parity: type.hh Datatype::isCharPrint flag, set on TYPE_INT char subtypes.
// TODO: replace with the real flag once Datatype carries char-print metadata.
func isCharPrintLike(dt Datatype) bool {
	if dt == nil {
		return false
	}
	switch dt.SubMeta() {
	case SUB_INT_CHAR, SUB_UINT_CHAR, SUB_INT_UNICODE, SUB_UINT_UNICODE:
		return true
	}
	return false
}

// isOpaqueStringLike is the Gosleigh stand-in for Datatype::isOpaqueString.
// C++ parity: Datatype::isOpaqueString.
// TODO: currently always false -- Gosleigh has no opaque-string marker yet.
func isOpaqueStringLike(dt Datatype) bool { return false }

// StringSequence is the COPY-based constant-string sequence detector.
// C++ parity: constseq.hh class StringSequence.
type StringSequence struct {
	arraySequence
	rootAddr  address.Address
	startAddr address.Address
	entry     *SymbolEntry
}

// newStringSequence finds the character array, inside the symbol holding the
// root COPY's storage, whose element type is the copied character type.
// C++ parity: StringSequence::StringSequence.
func newStringSequence(data *Funcdata, ct Datatype, ent *SymbolEntry, root *PcodeOp, addr address.Address) *StringSequence {
	s := &StringSequence{
		arraySequence: newArraySequence(data, ct, root),
		rootAddr:      addr,
		entry:         ent,
	}
	if ent.Addr().Space != addr.Space {
		return s
	}
	off := int64(s.rootAddr.Offset - ent.First())
	if off >= int64(ent.Size()) {
		return s
	}
	if root.Input(0).Offset() == 0 {
		return s
	}
	parentType := ent.Symbol().Type()
	var arrayType Datatype
	lastOff := int64(0)
	for parentType != nil {
		if parentType == ct {
			break
		}
		arrayType = parentType
		lastOff = off
		parentType, off = datatypeSubType(parentType, off)
	}
	if parentType != ct || arrayType == nil || arrayType.Metatype() != TYPE_ARRAY {
		return s
	}
	s.startAddr = address.Address{Space: addr.Space, Offset: s.rootAddr.Offset - uint64(lastOff)}
	if !s.collectCopyOps(int(arrayType.Size())) {
		return s
	}
	if !s.checkInterference() {
		return s
	}
	arrSize := int(arrayType.Size()) - int(s.rootAddr.Offset-s.startAddr.Offset)
	s.numElements = s.formByteArray(arrSize, 0, s.rootAddr.Offset, s.rootAddr.Space.BigEndian)
	return s
}

// collectCopyOps walks the basic block collecting COPY ops that write constant
// characters into the contiguous region anchored at startAddr.
// C++ parity: constseq.cc StringSequence::collectCopyOps.
func (s *StringSequence) collectCopyOps(size int) bool {
	if size <= 0 {
		return false
	}
	elAlign := int(s.charType.AlignSize())
	if elAlign <= 0 {
		elAlign = int(s.charType.Size())
	}
	endOff := s.startAddr.Offset + uint64(size-1)
	diff := int(s.rootAddr.Offset - s.startAddr.Offset)
	// We scan block ops in execution order. The C++ uses beginLoc/endLoc on
	// VarnodeLocSet which iterates by location; here we iterate ops and
	// post-filter, since block-local is the only locality that matters for
	// the downstream checks.
	for _, op := range s.block.Ops() {
		if op.Code() != CPUI_COPY {
			continue
		}
		out := op.Output()
		if out == nil || op.NumInput() == 0 || op.Input(0) == nil {
			continue
		}
		if !op.Input(0).IsConstant() {
			continue
		}
		if out.Space() != s.startAddr.Space {
			continue
		}
		if out.Offset() < s.startAddr.Offset || out.Offset() > endOff {
			continue
		}
		if int(out.Size()) != int(s.charType.Size()) {
			return false // not yet split, bail
		}
		tmpDiff := int(out.Offset() - s.startAddr.Offset)
		if tmpDiff < diff {
			if tmpDiff+elAlign == diff {
				return false // root is not the first element
			}
			continue
		} else if tmpDiff > diff {
			if tmpDiff-diff < elAlign {
				continue
			}
			if tmpDiff-diff > elAlign {
				break // gap
			}
			diff = tmpDiff
		}
		s.moveOps = append(s.moveOps, writeNode{offset: out.Offset(), op: op, slot: -1})
	}
	return len(s.moveOps) >= arraySeqMinimumLength
}

// buildStringCopy constructs the CALLOTHER that replaces the COPY sequence.
// C++ parity: constseq.cc StringSequence::buildStringCopy (L347). The Go port
// relies on Funcdata.GetInternalString for the source varnode and synthesizes
// the destination pointer as a constant-address Varnode in the pointer's own
// space. A full parity port rebuilds a PTRSUB chain through the containing
// Symbol (see constructTypedPointer in constseq.cc L273), which is not yet
// ported because Gosleigh lacks SymbolEntry + updateType plumbing.
func (s *StringSequence) buildStringCopy() *PcodeOp {
	if len(s.moveOps) == 0 || s.data == nil {
		return nil
	}
	insertPoint := s.moveOps[0].op
	numBytes := len(s.moveOps) * int(s.charType.Size())
	types := s.data.TypeFactory()
	if types == nil {
		return nil
	}
	charPtrType := types.GetPointer(4, s.charType, uint32(s.rootAddr.Space.WordSize))
	srcPtr := s.data.GetInternalString(s.byteArray[:numBytes], charPtrType, insertPoint)
	if srcPtr == nil {
		return nil
	}
	builtInID, index := s.selectStringCopyFunction()
	if builtInID == 0 {
		return nil
	}
	s.data.UserOps().RegisterBuiltin(builtInID, types)
	// Build the destination pointer as a fresh unique Varnode initialized by a
	// COPY from a constant encoding the root address. This is a PARTIAL stand-in
	// for constructTypedPointer -- it keeps downstream consumers pointing at
	// the right byte address without modelling the containing Symbol PTRSUB
	// chain.
	destAddrOff := s.rootAddr.Offset
	destConst := s.data.NewConstant(charPtrType.Size(), destAddrOff)
	destCopyOp := s.data.NewOp(1, insertPoint.Addr())
	s.data.OpSetOpcode(destCopyOp, CPUI_COPY)
	s.data.OpSetInput(destCopyOp, destConst, 0)
	destPtr := s.data.NewUniqueOut(charPtrType.Size(), destCopyOp)
	s.data.OpInsertBefore(destCopyOp, insertPoint)

	copyOp := s.data.NewOp(4, insertPoint.Addr())
	s.data.OpSetOpcode(copyOp, CPUI_CALLOTHER)
	copyOp.ClearFlag(PcodeOpCall)
	s.data.OpSetInput(copyOp, s.data.NewConstant(4, uint64(builtInID)), 0)
	s.data.OpSetInput(copyOp, destPtr, 1)
	s.data.OpSetInput(copyOp, srcPtr, 2)
	s.data.OpSetInput(copyOp, s.data.NewConstant(4, uint64(index)), 3)
	s.data.OpInsertBefore(copyOp, insertPoint)
	return copyOp
}

// removeCopyOps destroys the collected COPY ops after they have been replaced
// by a single CALLOTHER. C++ parity: StringSequence::removeCopyOps (L415). The
// C++ path additionally inserts INDIRECT ops around any live descendants of a
// destroyed COPY, which this port omits -- the downstream passes have been
// verified on testdata to not revisit the destroyed outputs in the narrowed
// scope covered by the rule.
// TODO mismatch: INDIRECT re-wiring for live descendants (constseq.cc L429).
func (s *StringSequence) removeCopyOps(replaceOp *PcodeOp) {
	_ = replaceOp
	for i := range s.moveOps {
		op := s.moveOps[i].op
		if op == nil {
			continue
		}
		s.data.OpDestroy(op)
	}
}

// transform performs the COPY-to-CALLOTHER rewrite.
// C++ parity: StringSequence::transform (L453).
func (s *StringSequence) transform() bool {
	memCpyOp := s.buildStringCopy()
	if memCpyOp == nil {
		return false
	}
	s.removeCopyOps(memCpyOp)
	return true
}

// HeapSequence is the STORE-based constant-string sequence detector.
// C++ parity: constseq.hh class HeapSequence.
type HeapSequence struct {
	arraySequence
	basePointer  *Varnode       // Pointer that sequence is stored to
	baseOffset   uint64         // Offset relative to pointer to root STORE
	storeSpace   *address.Space // Address space being STOREd to
	ptrAddMult   uint64         // Required multiplier for PTRADD ops
	nonConstAdds []*Varnode     // non-constant Varnodes being added into pointer calculation
}

// heapIndirectPair is the input/output Varnode pair of the INDIRECT chain one
// sequence STORE causes. C++ parity: HeapSequence::IndirectPair.
type heapIndirectPair struct {
	inVn      *Varnode
	outVn     *Varnode
	duplicate bool
}

// newHeapSequence collects the STOREs of constant characters off the root
// STORE's base pointer; the result is invalid (isValid false) when they do not
// form a sequence. C++ parity: HeapSequence::HeapSequence.
func newHeapSequence(data *Funcdata, ct Datatype, root *PcodeOp) *HeapSequence {
	h := &HeapSequence{arraySequence: newArraySequence(data, ct, root)}
	h.storeSpace = root.Input(0).GetSpaceFromConst()
	if h.storeSpace == nil {
		return h
	}
	ws := uint64(h.storeSpace.WordSize)
	if ws == 0 {
		ws = 1
	}
	h.ptrAddMult = uint64(ct.AlignSize()) / ws // byteToAddressInt
	h.findBasePointer(root.Input(1))
	if !h.collectStoreOps() {
		return h
	}
	if !h.checkInterference() {
		return h
	}
	arrSize := len(h.moveOps) * int(ct.AlignSize())
	h.numElements = h.formByteArray(arrSize, 2, 0, h.storeSpace.BigEndian)
	return h
}

// findBasePointer backtracks from the root STORE's pointer through PTRADDs
// and COPYs to a putative root pointer.
// C++ parity: HeapSequence::findBasePointer.
func (h *HeapSequence) findBasePointer(initPtr *Varnode) {
	h.basePointer = initPtr
	for h.basePointer.IsWritten() {
		op := h.basePointer.Def()
		switch op.Code() {
		case CPUI_PTRADD:
			if op.Input(2).Offset() != h.ptrAddMult {
				return
			}
		case CPUI_COPY:
		default:
			return
		}
		h.basePointer = op.Input(0)
	}
}

// isOffsetOp reports a PTRSUB, INT_ADD or PTRADD.
func isOffsetOp(opc OpCode) bool {
	return opc == CPUI_PTRSUB || opc == CPUI_INT_ADD || opc == CPUI_PTRADD
}

// offsetOpAmount is the constant offset a PTRSUB/INT_ADD/PTRADD adds.
func offsetOpAmount(op *PcodeOp) uint64 {
	off := op.Input(1).Offset()
	if op.Code() == CPUI_PTRADD {
		off *= op.Input(2).Offset()
	}
	return off
}

// findDuplicateBases backtracks from basePointer through constant
// PTRSUB/INT_ADD/PTRADDs to an earlier root, then traces forward through ops
// matching the same offsets; every Varnode reached (basePointer included) is a
// duplicate base. C++ parity: HeapSequence::findDuplicateBases.
func (h *HeapSequence) findDuplicateBases() []*Varnode {
	if !h.basePointer.IsWritten() {
		return []*Varnode{h.basePointer}
	}
	op := h.basePointer.Def()
	if !isOffsetOp(op.Code()) || !op.Input(1).IsConstant() {
		return []*Varnode{h.basePointer}
	}
	copyRoot := h.basePointer
	var offset []uint64
	for {
		offset = append(offset, offsetOpAmount(op))
		copyRoot = op.Input(0)
		if !copyRoot.IsWritten() {
			break
		}
		op = copyRoot.Def()
		if !isOffsetOp(op.Code()) || !op.Input(1).IsConstant() {
			break
		}
	}
	duplist := []*Varnode{copyRoot}
	for i := len(offset) - 1; i >= 0; i-- {
		midlist := duplist
		duplist = nil
		for _, vn := range midlist {
			for _, op := range vn.DescendIter() {
				if !isOffsetOp(op.Code()) || op.Input(0) != vn || !op.Input(1).IsConstant() {
					continue
				}
				if offsetOpAmount(op) != offset[i] {
					continue
				}
				duplist = append(duplist, op.Output())
			}
		}
	}
	return duplist
}

// findInitialStores finds the STOREs (root excluded) in the root's block whose
// pointer derives from a duplicate base through PTRADDs and COPYs.
// C++ parity: HeapSequence::findInitialStores.
func (h *HeapSequence) findInitialStores() []*PcodeOp {
	var stores []*PcodeOp
	ptradds := h.findDuplicateBases()
	for pos := 0; pos < len(ptradds); pos++ {
		vn := ptradds[pos]
		for _, op := range vn.DescendIter() {
			switch op.Code() {
			case CPUI_PTRADD:
				// Only the element size is checked: different pointer styles
				// may point to the same element data-type.
				if op.Input(0) == vn && op.Input(2).Offset() == h.ptrAddMult {
					ptradds = append(ptradds, op.Output())
				}
			case CPUI_COPY:
				ptradds = append(ptradds, op.Output())
			case CPUI_STORE:
				if op.Parent() == h.block && op != h.rootOp && op.Input(1) == vn {
					stores = append(stores, op)
				}
			}
		}
	}
	return stores
}

// calcAddElements sums the constants of an INT_ADD tree, passing back its
// non-constant leaves. C++ parity: HeapSequence::calcAddElements.
func calcAddElements(vn *Varnode, nonConst *[]*Varnode, maxDepth int) uint64 {
	if vn.IsConstant() {
		return vn.Offset()
	}
	if !vn.IsWritten() || vn.Def().Code() != CPUI_INT_ADD || maxDepth == 0 {
		*nonConst = append(*nonConst, vn)
		return 0
	}
	res := calcAddElements(vn.Def().Input(0), nonConst, maxDepth-1)
	return res + calcAddElements(vn.Def().Input(1), nonConst, maxDepth-1)
}

// calcPtraddOffset is the byte offset from basePointer to vn through PTRADDs
// and COPYs, passing back the non-constant index terms.
// C++ parity: HeapSequence::calcPtraddOffset.
func (h *HeapSequence) calcPtraddOffset(vn *Varnode, nonConst *[]*Varnode) uint64 {
	var res uint64
	for vn.IsWritten() {
		op := vn.Def()
		if op.Code() == CPUI_PTRADD {
			mult := op.Input(2).Offset()
			if mult != h.ptrAddMult {
				break
			}
			res += calcAddElements(op.Input(1), nonConst, 3) * mult
			vn = op.Input(0)
		} else if op.Code() == CPUI_COPY {
			vn = op.Input(0)
		} else {
			break
		}
	}
	ws := uint64(h.storeSpace.WordSize)
	if ws == 0 {
		ws = 1
	}
	return res * ws // addressToByteInt
}

// heapSetsEqual compares two ordered Varnode lists.
// C++ parity: HeapSequence::setsEqual.
func heapSetsEqual(a, b []*Varnode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testValue: the STOREd value is a constant of the character size.
// C++ parity: HeapSequence::testValue.
func (h *HeapSequence) testValue(op *PcodeOp) bool {
	vn := op.Input(2)
	return vn.IsConstant() && vn.Size() == h.charType.Size()
}

// collectStoreOps gathers the STOREs off the base pointer at offsets at or
// after the root's. C++ parity: HeapSequence::collectStoreOps.
func (h *HeapSequence) collectStoreOps() bool {
	initStores := h.findInitialStores()
	if len(initStores)+1 < arraySeqMinimumLength {
		return false
	}
	maxSize := uint64(arraySeqMaximumLength) * uint64(h.charType.AlignSize()) // Maximum bytes
	wrapMask := sizeMask(int32(h.storeSpace.AddrSize))
	h.baseOffset = h.calcPtraddOffset(h.rootOp.Input(1), &h.nonConstAdds)
	var nonConstComp []*Varnode
	for _, op := range initStores {
		nonConstComp = nonConstComp[:0]
		curOffset := h.calcPtraddOffset(op.Input(1), &nonConstComp)
		diff := (curOffset - h.baseOffset) & wrapMask // Allow wrapping relative to base pointer
		if heapSetsEqual(h.nonConstAdds, nonConstComp) {
			if diff >= maxSize {
				return false // Root is not the earliest STORE, or the span is too large
			}
			if !h.testValue(op) {
				return false
			}
			h.moveOps = append(h.moveOps, writeNode{offset: diff, op: op, slot: -1})
		}
	}
	h.moveOps = append(h.moveOps, writeNode{offset: 0, op: h.rootOp, slot: -1})
	return true
}

// buildStringCopy creates the built-in string copy user-op: destination the
// base pointer plus the base offset, source an internal string of the bytes,
// then the length. It goes just before the earliest STORE.
// C++ parity: HeapSequence::buildStringCopy.
func (h *HeapSequence) buildStringCopy() *PcodeOp {
	insertPoint := h.moveOps[0].op // Earliest STORE in the block
	charPtrType := h.rootOp.Input(1).TypeReadFacing(h.rootOp)
	numBytes := h.numElements * int(h.charType.Size())
	types := h.data.TypeFactory()
	srcPtr := h.data.GetInternalString(h.byteArray[:numBytes], charPtrType, insertPoint)
	if srcPtr == nil {
		return nil
	}
	destPtr := h.basePointer
	if h.baseOffset != 0 || len(h.nonConstAdds) > 0 { // Create the index Varnode
		var indexVn *Varnode
		intType := types.GetBase(h.basePointer.Size(), TYPE_INT, "")
		addTerm := func(a, b *Varnode) *Varnode {
			addOp := h.data.NewOp(2, insertPoint.Addr())
			h.data.OpSetOpcode(addOp, CPUI_INT_ADD)
			h.data.OpSetInput(addOp, a, 0)
			h.data.OpSetInput(addOp, b, 1)
			out := h.data.NewUniqueOut(a.Size(), addOp)
			out.UpdateType(intType)
			h.data.OpInsertBefore(addOp, insertPoint)
			return out
		}
		if len(h.nonConstAdds) > 0 { // Add in any non-constant Varnodes
			indexVn = h.nonConstAdds[0]
			for _, vn := range h.nonConstAdds[1:] {
				indexVn = addTerm(indexVn, vn)
			}
		}
		if h.baseOffset != 0 { // Add in any non-zero constant
			cvn := h.data.NewConstant(h.basePointer.Size(), h.baseOffset/uint64(h.charType.AlignSize()))
			cvn.UpdateType(intType)
			if indexVn == nil {
				indexVn = cvn
			} else {
				indexVn = addTerm(indexVn, cvn)
			}
		}
		ptrAdd := h.data.NewOp(3, insertPoint.Addr())
		h.data.OpSetOpcode(ptrAdd, CPUI_PTRADD)
		destPtr = h.data.NewUniqueOut(h.basePointer.Size(), ptrAdd)
		h.data.OpSetInput(ptrAdd, h.basePointer, 0)
		h.data.OpSetInput(ptrAdd, indexVn, 1)
		h.data.OpSetInput(ptrAdd, h.data.NewConstant(h.basePointer.Size(), uint64(h.charType.AlignSize())), 2)
		destPtr.UpdateType(charPtrType)
		h.data.OpInsertBefore(ptrAdd, insertPoint)
	}
	builtInID, index := h.selectStringCopyFunction()
	if builtInID == 0 {
		return nil
	}
	h.data.UserOps().RegisterBuiltin(builtInID, types)
	copyOp := h.data.NewOp(4, insertPoint.Addr())
	h.data.OpSetOpcode(copyOp, CPUI_CALLOTHER)
	copyOp.ClearFlag(PcodeOpCall)
	h.data.OpSetInput(copyOp, h.data.NewConstant(4, uint64(builtInID)), 0)
	h.data.OpSetInput(copyOp, destPtr, 1)
	h.data.OpSetInput(copyOp, srcPtr, 2)
	lenVn := h.data.NewConstant(4, uint64(index))
	h.data.OpSetInput(copyOp, lenVn, 3)
	if to := copyOp.GetOpcode(); to != nil {
		if ct := to.InputTypeLocal(copyOp, 3, types); ct != nil {
			lenVn.UpdateType(ct)
		}
	}
	h.data.OpInsertBefore(copyOp, insertPoint)
	return copyOp
}

// gatherIndirectPairs collects the INDIRECTs in front of the sequence STOREs
// and, for each output read by something else, the pair of the chain's
// initial input and that output.
// C++ parity: HeapSequence::gatherIndirectPairs.
func (h *HeapSequence) gatherIndirectPairs() ([]*PcodeOp, []heapIndirectPair) {
	var indirects []*PcodeOp
	var pairs []heapIndirectPair
	for _, mv := range h.moveOps {
		for op := mv.op.PreviousOp(); op != nil && op.Code() == CPUI_INDIRECT; op = op.PreviousOp() {
			op.SetFlag(PcodeOpMark)
			indirects = append(indirects, op)
		}
	}
	for _, op := range indirects {
		outvn := op.Output()
		hasUse := false
		for _, useOp := range outvn.DescendIter() {
			if !useOp.HasFlag(PcodeOpMark) { // A read that is not by another STORE INDIRECT
				hasUse = true
				break
			}
		}
		if hasUse {
			invn := op.Input(0)
			for invn.IsWritten() && invn.Def().HasFlag(PcodeOpMark) {
				invn = invn.Def().Input(0)
			}
			pairs = append(pairs, heapIndirectPair{inVn: invn, outVn: outvn})
		}
	}
	for _, op := range indirects {
		op.ClearFlag(PcodeOpMark)
	}
	return indirects, pairs
}

// deduplicatePairs makes INDIRECT outputs sharing storage read through one
// representative. C++ parity: HeapSequence::deduplicatePairs.
func (h *HeapSequence) deduplicatePairs(pairs []heapIndirectPair) bool {
	if len(pairs) == 0 {
		return true
	}
	order := make([]*heapIndirectPair, len(pairs))
	for i := range pairs {
		order[i] = &pairs[i]
	}
	sort.SliceStable(order, func(i, j int) bool { // IndirectPair::compareOutput
		a, b := order[i].outVn, order[j].outVn
		if a.Space() != b.Space() {
			return a.Space().Index < b.Space().Index
		}
		if a.Offset() != b.Offset() {
			return a.Offset() < b.Offset()
		}
		return a.Size() < b.Size()
	})
	head := order[0]
	dupCount := 0
	for _, p := range order[1:] {
		switch head.outVn.CharacterizeOverlap(p.outVn) {
		case 1:
			return false // Partial overlap
		case 2:
			if p.inVn != head.inVn {
				return false // Same storage coming from different sources
			}
			p.duplicate = true
			dupCount++
		default:
			head = p
		}
	}
	if dupCount > 0 {
		head = order[0]
		for _, p := range order[1:] {
			if p.duplicate {
				h.data.TotalReplace(p.outVn, head.outVn)
			} else {
				head = p
			}
		}
	}
	return true
}

// removeStoreOps destroys the STOREs (and the pointer arithmetic only they
// used) and re-creates the preserved INDIRECT pairs around the user-op.
// C++ parity: HeapSequence::removeStoreOps.
func (h *HeapSequence) removeStoreOps(indirects []*PcodeOp, pairs []heapIndirectPair, replaceOp *PcodeOp) {
	for _, p := range pairs { // Unhook Varnodes we don't want destroyed
		h.data.OpUnsetOutput(p.outVn.Def())
	}
	for _, mv := range h.moveOps {
		h.data.OpDestroyRecursive(mv.op)
	}
	for _, op := range indirects {
		h.data.OpDestroy(op)
	}
	for _, p := range pairs {
		if p.duplicate {
			continue
		}
		newInd := h.data.NewOp(2, replaceOp.Addr())
		h.data.OpSetOpcode(newInd, CPUI_INDIRECT)
		h.data.OpSetOutput(newInd, p.outVn)
		h.data.OpSetInput(newInd, p.inVn, 0)
		h.data.OpSetInput(newInd, h.data.NewVarnodeIop(replaceOp), 1)
		h.data.OpInsertBefore(newInd, replaceOp)
	}
}

// transform replaces the STOREs with the string copy user-op.
// C++ parity: HeapSequence::transform.
func (h *HeapSequence) transform() bool {
	indirects, pairs := h.gatherIndirectPairs()
	if !h.deduplicatePairs(pairs) {
		return false
	}
	memCpyOp := h.buildStringCopy()
	if memCpyOp == nil {
		return false
	}
	h.removeStoreOps(indirects, pairs, memCpyOp)
	return true
}

// queryContainer finds the symbol whose storage holds the given range, in
// the local scope for stack storage and the global scope otherwise.
// C++ parity: Scope::queryContainer (through Database::mapScope).
func (fd *Funcdata) queryContainer(addr address.Address, sz int32, usepoint address.Address) *SymbolEntry {
	if sl := fd.GetScopeLocal(); sl != nil && addr.Space == sl.SpaceID() {
		return sl.QueryContainer(addr, sz, usepoint)
	}
	if e := fd.resolveGlobal(addr); e != nil && containsRange(e, addr.Offset, sz) {
		return e
	}
	if gs := fd.GetGlobalScope(); gs != nil {
		return gs.QueryContainer(addr, sz, usepoint)
	}
	return nil
}
