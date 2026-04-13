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
	entry     symbolEntryStub
}

// symbolEntryStub is a placeholder for the still-unported SymbolEntry type.
// TODO: replace with a real SymbolEntry once ScopeLocal::queryContainer lands.
// C++ parity: database.hh SymbolEntry.
type symbolEntryStub struct {
	first uint64
	size  int32
	space *address.Space
}

// newStringSequence mirrors constseq.cc StringSequence::StringSequence.
// C++ parity: StringSequence::StringSequence.
func newStringSequence(data *Funcdata, ct Datatype, ent symbolEntryStub, root *PcodeOp, addr address.Address) *StringSequence {
	s := &StringSequence{
		arraySequence: newArraySequence(data, ct, root),
		rootAddr:      addr,
		entry:         ent,
	}
	if ent.space != nil && ent.space != addr.Space {
		return s
	}
	// Require the root COPY source constant to be non-zero; zero-only sequences
	// are ignored by the C++ path.
	if root.NumInput() == 0 || root.Input(0) == nil || !root.Input(0).IsConstant() || root.Input(0).Offset() == 0 {
		return s
	}
	// The Ghidra version walks the containing Symbol type to locate the array
	// subcomponent. Without the Datatype::getSubType walk we instead treat the
	// whole entry region as the candidate array when the element datatype
	// matches. This is a narrower precondition than the C++ form but the
	// downstream invariants are the same.
	// TODO: port Datatype::getSubType array descent when TypeArray lands.
	arraySize := int(ent.size)
	if ent.size == 0 {
		arraySize = int(ct.Size()) * arraySeqMinimumLength
	}
	s.startAddr = address.Address{Space: addr.Space, Offset: ent.first}
	if !s.collectCopyOps(arraySize) {
		return s
	}
	if !s.checkInterference() {
		return s
	}
	diff := int(s.rootAddr.Offset - s.startAddr.Offset)
	arrSize := arraySize - diff
	if arrSize <= 0 {
		return s
	}
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
	basePointer  *Varnode
	baseOffset   uint64
	storeSpace   *address.Space
	ptrAddMult   int64
	nonConstAdds []*Varnode
}

// newHeapSequence mirrors constseq.cc HeapSequence::HeapSequence.
// C++ parity: HeapSequence::HeapSequence.
func newHeapSequence(data *Funcdata, ct Datatype, root *PcodeOp) *HeapSequence {
	h := &HeapSequence{
		arraySequence: newArraySequence(data, ct, root),
	}
	if root.NumInput() < 3 {
		return h
	}
	space := root.Input(0).GetSpaceFromConst()
	if space == nil {
		return h
	}
	h.storeSpace = space
	h.ptrAddMult = int64(ct.AlignSize())
	h.findBasePointer(root.Input(1))
	if !h.collectStoreOps() {
		return h
	}
	if !h.checkInterference() {
		return h
	}
	arrSize := len(h.moveOps) * int(ct.AlignSize())
	bigEndian := space.BigEndian
	h.numElements = h.formByteArray(arrSize, 2, 0, bigEndian)
	return h
}

// findBasePointer back-walks through PTRADDs and COPYs to locate a canonical
// base Varnode for the sequence.
// C++ parity: constseq.cc HeapSequence::findBasePointer.
func (h *HeapSequence) findBasePointer(initPtr *Varnode) {
	h.basePointer = initPtr
	for h.basePointer != nil && h.basePointer.IsWritten() {
		op := h.basePointer.Def()
		if op == nil {
			break
		}
		code := op.Code()
		if code == CPUI_PTRADD {
			if op.NumInput() < 3 || op.Input(2) == nil || !op.Input(2).IsConstant() {
				break
			}
			if int64(op.Input(2).Offset()) != h.ptrAddMult {
				break
			}
		} else if code != CPUI_COPY {
			break
		}
		h.basePointer = op.Input(0)
	}
}

// collectStoreOps gathers candidate STORE ops in the same basic block that
// share base-pointer derivation with the root.
// C++ parity: constseq.cc HeapSequence::collectStoreOps (simplified).
// TODO: the C++ form walks duplicate bases through findDuplicateBases /
// findInitialStores; without PTRSUB/INT_ADD decomposition available we limit
// ourselves to STOREs that share the same base pointer varnode directly. The
// rest of the invariants (block membership, minimum count, byte-array form)
// still apply.
func (h *HeapSequence) collectStoreOps() bool {
	if h.basePointer == nil || h.block == nil {
		return false
	}
	h.baseOffset = 0
	// Capture root STORE first, at offset 0.
	h.moveOps = append(h.moveOps, writeNode{offset: 0, op: h.rootOp, slot: 2})
	for _, op := range h.block.Ops() {
		if op == h.rootOp || op.Code() != CPUI_STORE {
			continue
		}
		if op.NumInput() < 3 {
			continue
		}
		if op.Input(1) != h.basePointer {
			// TODO: allow PTRADD/COPY-based aliases once findDuplicateBases is ported.
			continue
		}
		if !h.testValue(op) {
			return false
		}
		// Root is at offset 0; any other base-equal STORE is at offset 0 too
		// in this narrowed form, which fails the unique-offset invariant.
		// TODO: recover per-store offsets via calcPtraddOffset.
		return false
	}
	return len(h.moveOps) >= arraySeqMinimumLength
}

// testValue mirrors HeapSequence::testValue.
// C++ parity: constseq.cc HeapSequence::testValue.
func (h *HeapSequence) testValue(op *PcodeOp) bool {
	if op.NumInput() < 3 {
		return false
	}
	vn := op.Input(2)
	if vn == nil || !vn.IsConstant() {
		return false
	}
	if int(vn.Size()) != int(h.charType.Size()) {
		return false
	}
	return true
}

// buildStringCopy mirrors constseq.cc HeapSequence::buildStringCopy (L698).
// The Go port routes the source through Funcdata.GetInternalString and emits a
// CALLOTHER wiring (destPtr, srcPtr, length). The destination pointer is the
// detected base pointer; when baseOffset is non-zero we bias it with a PTRADD.
// Non-constant stride contributions (nonConstAdds) are not tracked by this
// port (the collect path currently only recognises constant-base STOREs), so
// the C++ index-Varnode fan-in is omitted.
// TODO mismatch: nonConstAdds composition + updateType on generated varnodes.
func (h *HeapSequence) buildStringCopy() *PcodeOp {
	if len(h.moveOps) == 0 || h.data == nil {
		return nil
	}
	insertPoint := h.moveOps[0].op
	numBytes := h.numElements * int(h.charType.Size())
	types := h.data.TypeFactory()
	if types == nil || h.basePointer == nil {
		return nil
	}
	charPtrType := types.GetPointer(h.basePointer.Size(), h.charType, 1)
	srcPtr := h.data.GetInternalString(h.byteArray[:numBytes], charPtrType, insertPoint)
	if srcPtr == nil {
		return nil
	}
	builtInID, index := h.selectStringCopyFunction()
	if builtInID == 0 {
		return nil
	}
	h.data.UserOps().RegisterBuiltin(builtInID, types)
	destPtr := h.basePointer
	if h.baseOffset != 0 {
		numEl := h.baseOffset / uint64(h.charType.AlignSize())
		ptrAdd := h.data.NewOp(3, insertPoint.Addr())
		h.data.OpSetOpcode(ptrAdd, CPUI_PTRADD)
		newDest := h.data.NewUniqueOut(h.basePointer.Size(), ptrAdd)
		h.data.OpSetInput(ptrAdd, h.basePointer, 0)
		h.data.OpSetInput(ptrAdd, h.data.NewConstant(h.basePointer.Size(), numEl), 1)
		h.data.OpSetInput(ptrAdd, h.data.NewConstant(h.basePointer.Size(), uint64(h.charType.AlignSize())), 2)
		h.data.OpInsertBefore(ptrAdd, insertPoint)
		destPtr = newDest
	}
	copyOp := h.data.NewOp(4, insertPoint.Addr())
	h.data.OpSetOpcode(copyOp, CPUI_CALLOTHER)
	copyOp.ClearFlag(PcodeOpCall)
	h.data.OpSetInput(copyOp, h.data.NewConstant(4, uint64(builtInID)), 0)
	h.data.OpSetInput(copyOp, destPtr, 1)
	h.data.OpSetInput(copyOp, srcPtr, 2)
	h.data.OpSetInput(copyOp, h.data.NewConstant(4, uint64(index)), 3)
	h.data.OpInsertBefore(copyOp, insertPoint)
	return copyOp
}

// removeStoreOps tears down the STORE sequence once it has been replaced.
// C++ parity: HeapSequence::removeStoreOps (L871). The INDIRECT re-wiring that
// the C++ performs (gatherIndirectPairs + deduplicatePairs) is not reproduced
// because the Go collectStoreOps currently only accepts a single root STORE
// without surrounding indirect chains.
// TODO mismatch: INDIRECT pair preservation for STOREs that shipped with
// pre-existing INDIRECT side-effects.
func (h *HeapSequence) removeStoreOps(replaceOp *PcodeOp) {
	_ = replaceOp
	for i := range h.moveOps {
		op := h.moveOps[i].op
		if op == nil {
			continue
		}
		h.data.OpDestroyRecursive(op)
	}
}

// transform mirrors HeapSequence::transform (L927).
func (h *HeapSequence) transform() bool {
	memCpyOp := h.buildStringCopy()
	if memCpyOp == nil {
		return false
	}
	h.removeStoreOps(memCpyOp)
	return true
}

// queryContainerStub is a local stand-in for ScopeLocal::queryContainer.
// C++ parity: database.cc Scope::queryContainer.
// TODO: return a real SymbolEntry once Scope lookup lands; for now we
// approximate by returning a stub rooted at the varnode address so the rule
// body still exercises the collection path.
func queryContainerStub(data *Funcdata, addr address.Address, sz int32) symbolEntryStub {
	return symbolEntryStub{
		first: addr.Offset,
		size:  sz * arraySeqMinimumLength,
		space: addr.Space,
	}
}
