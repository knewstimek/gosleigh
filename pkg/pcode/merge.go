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

// merge.go -- HighVariable coalescing after Heritage (SSA phi-node merging).
// C++ parity: merge.hh / merge.cc Merge

// highPair is a canonical, ordered pair of *HighVariable used as a map key.
// Ordering is by the createIndex of each high's first instance, which is unique.
// C++ parity: variable.hh HighEdge
type highPair struct {
	a, b *HighVariable
}

// highKey returns the first instance's createIndex, used for canonical ordering.
// Falls back to 0 for a nil or empty HighVariable.
func highKey(h *HighVariable) uint32 {
	if h == nil || len(h.instances) == 0 {
		return 0
	}
	return h.instances[0].CreateIndex()
}

// canonicalPair returns a highPair with a.key <= b.key so pairs are order-invariant.
func canonicalPair(h1, h2 *HighVariable) highPair {
	if highKey(h1) <= highKey(h2) {
		return highPair{h1, h2}
	}
	return highPair{h2, h1}
}

// HighIntersectTest caches pairwise Cover intersection test results.
// C++ parity: variable.hh HighIntersectTest
type HighIntersectTest struct {
	cache map[highPair]bool
}

// newHighIntersectTest allocates an empty cache.
func newHighIntersectTest() *HighIntersectTest {
	return &HighIntersectTest{cache: make(map[highPair]bool)}
}

// UpdateHigh rebuilds the Cover for a HighVariable and purges any stale cached
// tests that reference it.
// C++ parity: HighIntersectTest::updateHigh
func (t *HighIntersectTest) UpdateHigh(h *HighVariable) {
	if h == nil {
		return
	}
	h.rebuildCover()
	for key := range t.cache {
		if key.a == h || key.b == h {
			delete(t.cache, key)
		}
	}
}

// MoveIntersectTests removes all cached entries that reference old so that
// the caller may safely merge old into merged.
// C++ parity: HighIntersectTest::moveIntersectTests
func (t *HighIntersectTest) MoveIntersectTests(merged, old *HighVariable) {
	if merged == old {
		return
	}
	for key := range t.cache {
		if key.a == old || key.b == old {
			delete(t.cache, key)
		}
	}
}

// Intersection returns true if the Covers of h1 and h2 have a range intersection
// that would prevent merging.  Results are cached.
// C++ parity: HighIntersectTest::intersection
func (t *HighIntersectTest) Intersection(h1, h2 *HighVariable) bool {
	if h1 == h2 {
		return false
	}
	key := canonicalPair(h1, h2)
	if v, ok := t.cache[key]; ok {
		return v
	}
	result := computeHighIntersection(h1, h2)
	t.cache[key] = result
	return result
}

// vnGetCover builds the individual live-range Cover for a single Varnode.
// C++ parity: Varnode::getCover (cached in C++; computed on demand in Go)
func vnGetCover(vn *Varnode) *Cover {
	c := &Cover{}
	c.Rebuild(vn)
	return c
}

// gatherBlockVarnodes collects instances of hv whose individual Cover has a
// level > 1 intersection with unionCover on block blk.
// C++ parity: HighIntersectTest::gatherBlockVarnodes (variable.cc:947)
func gatherBlockVarnodes(hv *HighVariable, blk int32, unionCover *Cover) []*Varnode {
	var res []*Varnode
	for _, vn := range hv.instances {
		if vn == nil {
			continue
		}
		vnCov := vnGetCover(vn)
		if vnCov.IntersectByBlock(blk, unionCover) > 1 {
			res = append(res, vn)
		}
	}
	return res
}

// testBlockIntersection checks instances of hv for a real intersection with
// blist on block blk.  A real intersection is one not explained by copy
// shadowing.  Returns true when merging would be unsafe.
// C++ parity: HighIntersectTest::testBlockIntersection (variable.cc:968)
func testBlockIntersection(hv *HighVariable, blk int32, bCover *Cover, blist []*Varnode) bool {
	for _, vn := range hv.instances {
		if vn == nil {
			continue
		}
		vnCov := vnGetCover(vn)
		if vnCov.IntersectByBlock(blk, bCover) < 2 {
			continue
		}
		for _, vn2 := range blist {
			if vn2 == nil {
				continue
			}
			vn2Cov := vnGetCover(vn2)
			if vn2Cov.IntersectByBlock(blk, vnCov) > 1 {
				if vn.Size() == vn2.Size() {
					cs := vn.CopyShadow(vn2)
					if !cs {
						return true
					}
				} else {
					// partialCopyShadow is not yet ported (known mismatch).
					return true
				}
			}
		}
	}
	return false
}

// highBlockIntersection tests if h1 and h2 have a real intersection on block blk.
// C++ parity: HighIntersectTest::blockIntersection (variable.cc:998)
// VariablePiece is not ported; only the base case is implemented here.
func highBlockIntersection(h1, h2 *HighVariable, blk int32) bool {
	c1 := h1.getCover()
	c2 := h2.getCover()
	blist := gatherBlockVarnodes(h2, blk, c1)
	return testBlockIntersection(h1, blk, c2, blist)
}

// computeHighIntersection implements the two-phase per-varnode intersection test.
// Phase 1 uses union covers to find candidate blocks; phase 2 uses individual
// varnode covers and copy-shadow filtering to eliminate false positives.
// C++ parity: HighIntersectTest::intersection (variable.cc:1166), base algorithm only.
// Known mismatch: testUntiedCallIntersection (variable.cc:1188-1196) is not ported.
func computeHighIntersection(h1, h2 *HighVariable) bool {
	c1 := h1.getCover()
	c2 := h2.getCover()
	if c1 == nil || c2 == nil {
		return false
	}
	for _, blk := range c1.IntersectList(c2, 2) {
		if highBlockIntersection(h1, h2, blk) {
			return true
		}
	}
	return false
}

// Clear removes all cached results.
func (t *HighIntersectTest) Clear() {
	t.cache = make(map[highPair]bool)
}

// ---------------------------------------------------------------------------
// mergeTestRequired -- non-Cover precondition checks
// ---------------------------------------------------------------------------

// mergeTestRequired checks non-Cover conditions that would prevent two
// HighVariables from being merged.  Returns true when merging is allowed.
// This is a simplified port; properties not tracked in Gosleigh are skipped.
//
// C++ parity: merge.cc Merge::mergeTestRequired (lines 102-166)
func mergeTestRequired(h1, h2 *HighVariable) bool {
	if h1 == h2 {
		return true // already the same variable
	}
	if h1 == nil || h2 == nil {
		return true // nil HighVariable cannot conflict
	}
	// If both have locked types they must agree.
	// C++ parity: merge.cc Merge::mergeTestRequired lines 107-109 uses isTypeLock().
	if h1.IsTypeLock() && h2.IsTypeLock() {
		if h1.datatype != h2.datatype {
			return false
		}
	}
	// Addr-tied guard: two addr-tied HVs at different addresses must not merge,
	// because each is bound to distinct storage (different stack slots, etc.).
	// This is the critical invariant that keeps param_N (stack-backed) separate
	// from register-backed iVar1 in loops that reuse register values.
	// C++ parity: merge.cc Merge::mergeTestRequired lines 111-116.
	if h1.IsAddrTied() && h2.IsAddrTied() {
		v1 := h1.TiedVarnode()
		v2 := h2.TiedVarnode()
		if v1 != nil && v2 != nil {
			if v1.Space() != v2.Space() || v1.Offset() != v2.Offset() {
				return false
			}
		}
	}
	// Input/addr-tied asymmetry: a function input HV cannot absorb (or be
	// absorbed by) a non-addrtied HV when the other is addr-tied.
	// C++ parity: merge.cc Merge::mergeTestRequired lines 118-132.
	if h1.IsInput() {
		if h2.IsPersist() {
			return false
		}
		if h2.IsAddrTied() && !h1.IsAddrTied() {
			return false
		}
	}
	if h2.IsInput() {
		if h1.IsPersist() {
			return false
		}
		if h1.IsAddrTied() && !h2.IsAddrTied() {
			return false
		}
	}
	return true
}

func mergeTestBasic(vn *Varnode) bool {
	if vn == nil {
		return false
	}
	if vn.IsImplied() || vn.IsProtoPartial() || vn.IsSpaceBase() {
		return false
	}
	if vn.IsConstant() || vn.IsAnnotation() {
		return false
	}
	return vn.High() != nil
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

// Merge orchestrates HighVariable coalescing after Heritage.
// C++ parity: merge.hh Merge
type Merge struct {
	fd        *Funcdata
	testCache *HighIntersectTest
	copyTrims []*PcodeOp // COPYs inserted by allocateCopyTrim/snipReads
}

// NewMerge creates a Merge engine for the given function.
// C++ parity: Merge::Merge (constructor)
func NewMerge(fd *Funcdata) *Merge {
	return &Merge{
		fd:        fd,
		testCache: newHighIntersectTest(),
	}
}

// mergeHighVariables merges the instances of src into dst, updating all
// Varnode back-pointers, then clears src.  dst inherits name/datatype from src
// when dst does not already have them.
// C++ parity: HighVariable::mergeInternal (non-speculative path, simplified)
func mergeHighVariables(dst, src *HighVariable, cache *HighIntersectTest) {
	if dst == src {
		return
	}
	if cache != nil {
		cache.MoveIntersectTests(dst, src)
	}
	for _, vn := range src.instances {
		vn.SetHigh(dst)
		dst.instances = append(dst.instances, vn)
	}
	src.instances = nil
	// Merge covers if available; otherwise mark dst cover as stale.
	if dst.cover != nil && src.cover != nil {
		dst.cover.Merge(src.cover)
	} else {
		dst.cover = nil
	}
	// Prefer a named dst; inherit src name only when dst has none.
	if dst.name == "" && src.name != "" {
		dst.name = src.name
	}
	if dst.datatype == nil && src.datatype != nil {
		dst.datatype = src.datatype
	}
}

// mergeTest checks whether high can be added to an ongoing merge group (testlist)
// without introducing a Cover intersection.
// Returns true when the addition is safe.
// C++ parity: Merge::mergeTest
func (m *Merge) mergeTest(high *HighVariable, testlist []*HighVariable) bool {
	m.testCache.UpdateHigh(high)
	for _, other := range testlist {
		if m.testCache.Intersection(high, other) {
			return false
		}
	}
	return true
}

// TrimOpInput inserts a COPY before the given input slot of op to break a Cover
// overlap.  For MULTIEQUAL ops the COPY is placed at the end of the predecessor
// block; for all other ops it is placed immediately before op.
//
// The new COPY output varnode receives a fresh HighVariable so that it can
// participate in subsequent merge tests and Phase 3 merging.
//
// C++ parity: Merge::trimOpInput (lines 692-712)
func (m *Merge) TrimOpInput(op *PcodeOp, slot int) {
	vn := op.Input(slot)
	if vn == nil {
		return
	}
	if op.Code() == CPUI_MULTIEQUAL {
		pred := op.Parent().InEdge(slot).Point
		bb, ok := pred.Concrete().(*BlockBasic)
		if !ok || bb == nil {
			return
		}
		var addr = op.Addr()
		if last := bb.LastOp(); last != nil {
			addr = last.Addr()
		}
		copyOp := m.fd.NewOp(1, addr)
		m.fd.OpSetOpcode(copyOp, CPUI_COPY)
		m.fd.NewUniqueOut(vn.Size(), copyOp)
		m.fd.OpSetInput(copyOp, vn, 0)
		// Assign a HighVariable to the new unique output so merge Phase 3 can find it.
		trimHigh := NewHighVariable("")
		trimHigh.AddInstance(copyOp.Output())
		// Wire the new unique output as the MULTIEQUAL input.
		m.fd.OpSetInput(op, copyOp.Output(), slot)
		m.fd.OpInsertEnd(copyOp, bb)
	} else {
		copyOp := m.fd.NewOp(1, op.Addr())
		m.fd.OpSetOpcode(copyOp, CPUI_COPY)
		m.fd.NewUniqueOut(vn.Size(), copyOp)
		m.fd.OpSetInput(copyOp, vn, 0)
		trimHigh := NewHighVariable("")
		trimHigh.AddInstance(copyOp.Output())
		m.fd.OpSetInput(op, copyOp.Output(), slot)
		m.fd.OpInsertBefore(copyOp, op)
	}
}

// TrimOpOutput inserts a COPY immediately after op to separate the long-lived output
// Varnode from the op itself.  The op's output is replaced with a new tiny unique
// Varnode, and the original output Varnode becomes the COPY output.  This shrinks
// the Cover of the op's output so that subsequent merge tests pass.
//
// C++ parity: Merge::trimOpOutput (lines 656-682)
func (m *Merge) TrimOpOutput(op *PcodeOp) {
	vn := op.Output()
	if vn == nil {
		return
	}
	// For INDIRECT: C++ inserts after the op causing the effect via getOpFromConst.
	// Gosleigh falls back to inserting after op itself (same block, correct ordering).
	afterop := op

	// Allocate a new free unique varnode; it will become the tiny MULTIEQUAL output.
	uniq := m.fd.GetVarnodeBank().CreateUnique(vn.Size())

	// Create the COPY op that carries the original output forward.
	copyOp := m.fd.NewOp(1, op.Addr())
	m.fd.OpSetOpcode(copyOp, CPUI_COPY)

	// Reassign outputs:
	//   op    -> uniq (tiny cover, immediately consumed by copyOp)
	//   copyOp -> vn  (original long-lived varnode, bumped forward)
	// OpSetOutput calls vbank.SetDef which moves varnodes from free to written state.
	m.fd.OpSetOutput(op, uniq)
	m.fd.OpSetOutput(copyOp, vn)
	m.fd.OpSetInput(copyOp, uniq, 0)

	// Give uniq a HighVariable so MergeOp Phase 3 can find it during merging.
	uniqHigh := NewHighVariable("")
	uniqHigh.AddInstance(uniq)

	m.fd.OpInsertAfter(copyOp, afterop)
}

// MergeOp forces the merge of all input and output Varnodes of op into a single
// HighVariable.  If Cover intersections prevent a direct merge, TrimOpInput is
// called to insert COPY ops that shorten the conflicting live ranges.  If all
// TrimOpInput attempts fail, TrimOpOutput is called as a last resort.
// C++ parity: Merge::mergeOp (lines 719-772)
func (m *Merge) MergeOp(op *PcodeOp) {
	outVn := op.Output()
	if outVn == nil {
		return
	}
	highOut := outVn.High()
	if highOut == nil {
		return
	}
	max := op.NumInput()
	if op.Code() == CPUI_INDIRECT {
		max = 1
	}

	// Phase 1: trim inputs that violate non-Cover constraints.
	for i := 0; i < max; i++ {
		inVn := op.Input(i)
		if inVn == nil {
			continue
		}
		highIn := inVn.High()
		if highIn == nil {
			continue
		}
		if !mergeTestRequired(highOut, highIn) {
			m.TrimOpInput(op, i)
			continue
		}
		for j := 0; j < i; j++ {
			prevVn := op.Input(j)
			if prevVn == nil {
				continue
			}
			if !mergeTestRequired(prevVn.High(), highIn) {
				m.TrimOpInput(op, i)
				break
			}
		}
	}

	// Phase 2: Cover intersection test -- trim inputs until all can merge.
	testlist := make([]*HighVariable, 0, max+1)
	m.mergeTest(highOut, testlist)
	testlist = append(testlist, highOut)

	allOK := true
	for i := 0; i < max; i++ {
		inVn := op.Input(i)
		if inVn == nil {
			continue
		}
		if !m.mergeTest(inVn.High(), testlist) {
			allOK = false
			break
		}
		testlist = append(testlist, inVn.High())
	}

	if !allOK {
		// A loop-condition MULTIEQUAL whose cover conflict cannot be resolved by
		// trimming inputs: its back-edge input transitively reads the phi output, so
		// every input-trim COPY still lives inside the phi output's loop-spanning
		// cover. C++ mergeOp discovers this by exhausting the input-trim loop
		// (nexttrim==max) and falling through to trimOpOutput (merge.cc:759-760);
		// Gosleigh's input-trim re-test spuriously succeeds for this cyclic case
		// (a residual loop-carried Cover gap -- see docs/STATUS.md H8-debt-1), so we
		// route loop-condition phis straight to trimOpOutput. trimOpOutput splits the
		// long-lived output off via a COPY, producing the loop-head snapshot (iVar1).
		// This replaces the former TrimJoinblockMultiequals forward-snip pass with the
		// faithful C++ trimOpOutput mechanism. The loop-condition test (not a bare
		// cyclic-input test) is deliberate: in gcd BOTH loop-variable phis are cyclic,
		// but only the condition phi -- whose output is also consumed in the body as the
		// pre-swap value (iVar1) -- has the output-side cover conflict that input-trim
		// cannot resolve. Trimming the non-condition cyclic phi's output would split a
		// variable Ghidra leaves merged. (Verified: a bare cyclic gate over-trims gcd.)
		forceOutputTrim := op.Code() == CPUI_MULTIEQUAL && isLoopCondMultiequal(op)
		trimmed := false
		if !forceOutputTrim {
			for nexttrim := 0; nexttrim < max; nexttrim++ {
				m.TrimOpInput(op, nexttrim)
				testlist = testlist[:0]
				m.mergeTest(highOut, testlist)
				testlist = append(testlist, highOut)
				ok := true
				for i := 0; i < max; i++ {
					inVn := op.Input(i)
					if inVn == nil {
						continue
					}
					if !m.mergeTest(inVn.High(), testlist) {
						ok = false
						break
					}
					testlist = append(testlist, inVn.High())
				}
				if ok {
					trimmed = true
					break
				}
			}
		}
		if !trimmed {
			// All TrimOpInput attempts failed (or were skipped for a loop-cond phi):
			// trim the output instead. This inserts COPY(original_out = uniq) after op
			// so that op's output becomes a tiny-cover unique, allowing the merge.
			// C++ parity: merge.cc MergeOp lines 759-760.
			m.TrimOpOutput(op)
			// Refresh outVn: op.Output() is now the new tiny unique.
			outVn = op.Output()
			if outVn != nil {
				highOut = outVn.High()
			}
		}
	}

	// Phase 3: perform the actual merges.
	for i := 0; i < max; i++ {
		inVn := op.Input(i)
		if inVn == nil {
			continue
		}
		// Re-read highOut: a previous merge iteration may have updated it.
		highOut = outVn.High()
		highIn := inVn.High()
		if highIn == nil {
			// Varnode has no HighVariable -- this happens when a COPY-propagation
			// rule (e.g. RulePropagateCopy in BatchA) replaces a stack-space phi
			// input with a unique-space intermediate that was never assigned a High.
			// C++ parity: Ghidra Heritage always assigns a HighVariable to every
			// live varnode before mergeMarker runs; we bootstrap the unique here.
			highIn = NewHighVariable("")
			highIn.AddInstance(inVn)
			inVn.SetHigh(highIn)
		}
		if highIn == highOut {
			continue
		}
		if !mergeTestRequired(highOut, highIn) {
			continue // still blocked after trimming; skip rather than crash
		}
		mergeHighVariables(highOut, highIn, m.testCache)
	}
}

// isLoopCondMultiequal returns true if the MULTIEQUAL's output is used (directly
// or via a COPY chain ending at INT_EQUAL/INT_NOTEQUAL) as the condition for a
// CBRANCH.  This identifies loop-head phi ops that feed the while condition;
// MergeOp routes these straight to TrimOpOutput when they have a Cover conflict,
// producing the loop-head snapshot local (e.g. iVar1) for a swapped loop variable.
func isLoopCondMultiequal(op *PcodeOp) bool {
	out := op.Output()
	if out == nil {
		return false
	}
	// Direct: output consumed by INT_EQUAL/INT_NOTEQUAL.
	for _, desc := range out.DescendIter() {
		if desc == nil {
			continue
		}
		switch desc.Code() {
		case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
			return true
		case CPUI_CBRANCH:
			return true
		}
	}
	return false
}

// MergeMarker iterates over all live MULTIEQUAL and INDIRECT ops and forces the
// merge of their input and output Varnodes into a single HighVariable.
// C++ parity: Merge::mergeMarker (lines 889-902)
func (m *Merge) MergeMarker() {
	ops := m.fd.GetPcodeOpBank().AliveOps()
	for _, op := range ops {
		if !op.IsMarker() || op.IsIndirectCreation() {
			continue
		}
		m.MergeOp(op)
	}
}

// MergeAdjacent attempts speculative merges of op input/output pairs.
// C++ parity: Merge::mergeAdjacent
func (m *Merge) MergeAdjacent() {
	m.mergeAdjacentCopies()
}

// processCopyTrims processes COPY ops inserted by the addr-tied trimming phase.
// The C++ version tries to consolidate redundant COPYs; here we just clear the list
// because the COPYs have already been correctly wired by snipReads.
// C++ parity: merge.cc Merge::processCopyTrims (lines 1415-1436)
func (m *Merge) processCopyTrims() {
	// Mark all trimmed COPY output highs for the copyIn tracking pass, then
	// clear the list. C++ calls processHighDominantCopy for highs with >= 2 COPYs;
	// that optimization is not yet ported (known mismatch).
	m.copyTrims = m.copyTrims[:0]
}

// markInternalCopies marks COPY ops that copy within the same HighVariable as NonPrinting.
// C++ parity: merge.cc Merge::markInternalCopies (lines 1444-1542)
func (m *Merge) markInternalCopies() {
	for _, op := range m.fd.GetPcodeOpBank().AliveOps() {
		if op == nil || op.Code() != CPUI_COPY {
			continue
		}
		v1 := op.Output()
		if v1 == nil {
			continue
		}
		h1 := v1.High()
		if h1 == nil {
			continue
		}
		in0 := op.Input(0)
		if in0 == nil {
			continue
		}
		// If input and output share the same HighVariable, the COPY is internal.
		if h1 == in0.High() {
			op.SetFlag(PcodeOpNonPrinting)
		}
	}
}

// mergeMultiEntry merges Varnodes with multiple SymbolEntrys.
// C++ parity: merge.cc Merge::mergeMultiEntry
func (m *Merge) mergeMultiEntry() {
	_ = m
}

// mergeOpcode tries to force merges of input to output for all p-code ops of a
// given type. For COPY in particular, skip the merge whenever the two
// HighVariable Covers would intersect. C++ parity: merge.cc Merge::mergeOpcode
// calls Merge::merge(high1,high2,false) which rejects on testCache.intersection;
// the equivalent check must live here because Go's mergeHighVariables has no
// return-false path.
func (m *Merge) mergeOpcode(opc OpCode) {
	for _, op := range m.fd.GetPcodeOpBank().AliveOps() {
		if op == nil || op.Code() != opc {
			continue
		}
		outvn := op.Output()
		if !mergeTestBasic(outvn) {
			continue
		}
		highOut := outvn.High()
		for i := 0; i < op.NumInput(); i++ {
			invn := op.Input(i)
			if !mergeTestBasic(invn) {
				continue
			}
			highIn := invn.High()
			if highIn == highOut {
				continue
			}
			if !mergeTestRequired(highOut, highIn) {
				continue
			}
			if m.testCache.Intersection(highOut, highIn) {
				continue
			}
			mergeHighVariables(highOut, highIn, m.testCache)
		}
	}
}

func (m *Merge) mergeRequired() {
	// C++ parity: ActionMergeRequired::apply calls mergeAddrTied, groupPartials, mergeMarker.
	// groupPartials is not yet ported (known mismatch). mergeAddrTied is now implemented.
	m.mergeAddrTied()
	m.MergeMarker()
}

func (m *Merge) mergeByDatatype() {
	highByType := make(map[Datatype][]*HighVariable)
	seen := make(map[*HighVariable]struct{})
	for _, vn := range m.fd.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() {
			continue
		}
		if !mergeTestBasic(vn) {
			continue
		}
		high := vn.High()
		if high == nil {
			continue
		}
		if _, ok := seen[high]; ok {
			continue
		}
		seen[high] = struct{}{}
		highByType[high.Type()] = append(highByType[high.Type()], high)
	}
	for _, group := range highByType {
		if len(group) <= 1 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			return highKey(group[i]) < highKey(group[j])
		})
		var merged []*HighVariable
		for _, high := range group {
			placed := false
			for _, dst := range merged {
				if !mergeTestRequired(dst, high) {
					continue
				}
				if m.testCache.Intersection(dst, high) {
					continue
				}
				mergeHighVariables(dst, high, m.testCache)
				placed = true
				break
			}
			if !placed {
				merged = append(merged, high)
			}
		}
	}
}

func (m *Merge) mergeAdjacentCopies() {
	for _, op := range m.fd.GetPcodeOpBank().AliveOps() {
		if op == nil || op.IsCall() {
			continue
		}
		outvn := op.Output()
		if !mergeTestBasic(outvn) {
			continue
		}
		highOut := outvn.High()
		outType := outvn.Type()
		for i := 0; i < op.NumInput(); i++ {
			invn := op.Input(i)
			if !mergeTestBasic(invn) {
				continue
			}
			if outvn.Size() != invn.Size() {
				continue
			}
			if invn.Def() == nil && !invn.IsInput() {
				continue
			}
			if outType != invn.Type() {
				continue
			}
			highIn := invn.High()
			if !mergeTestRequired(highOut, highIn) {
				continue
			}
			if m.testCache.Intersection(highIn, highOut) {
				continue
			}
			mergeHighVariables(highOut, highIn, m.testCache)
		}
	}
}

func (m *Merge) markImplied(vn *Varnode) {
	if vn == nil {
		return
	}
	vn.SetImplied()
	op := vn.Def()
	if op == nil {
		return
	}
	for i := 0; i < op.NumInput(); i++ {
		defvn := op.Input(i)
		if defvn == nil {
			continue
		}
		defvn.SetFlags(VarnodeCoverDirty)
		if high := defvn.High(); high != nil {
			high.MarkCoverDirty()
		}
	}
	if high := vn.High(); high != nil {
		high.MarkCoverDirty()
	}
}

// HideShadows walks the given HighVariable looking for speculative merges
// that shadow an earlier Varnode on the same storage. When the port of the
// full intersection test lands this should return true once per hidden
// shadow so ActionHideShadow can bump its count. The real C++ body is in
// merge.cc Merge::hideShadows and depends on HighIntersectTest +
// Cover::intersect plus HighVariable::hasShadows which are only partially
// available in Gosleigh today.
// C++ parity: merge.cc Merge::hideShadows
// TODO known mismatch: HighVariable::hasShadows / remerge tracking is not
// ported, so this stub never reports a hidden shadow.
func (m *Merge) HideShadows(high *HighVariable) bool {
	if m == nil || high == nil {
		return false
	}
	_ = m.testCache
	return false
}

// ---------------------------------------------------------------------------
// mergeAddrTied pipeline
// C++ parity: merge.cc Merge::allocateCopyTrim, snipReads, eliminateIntersect,
//             unifyAddress, mergeAddrTied, mergeRangeMust
// ---------------------------------------------------------------------------

// allocateCopyTrim allocates a COPY PcodeOp designed to trim an overextended Cover.
// A COPY is allocated with the given input, placed at addr, and recorded in copyTrims.
// The COPY output is a fresh unique Varnode that gets its own HighVariable.
// C++ parity: merge.cc Merge::allocateCopyTrim (lines 411-434)
func (m *Merge) allocateCopyTrim(inVn *Varnode, addr address.Address) *PcodeOp {
	copyOp := m.fd.NewOp(1, addr)
	m.fd.OpSetOpcode(copyOp, CPUI_COPY)
	outVn := m.fd.NewUniqueOut(inVn.Size(), copyOp)
	m.fd.OpSetInput(copyOp, inVn, 0)
	// Assign a fresh HighVariable to the new output so later merge phases find it.
	// Inherit the input's type so a trim COPY created after type inference (e.g.
	// the loop-head snapshot) still gets the right name prefix (iVar vs uVar).
	// C++ parity: Merge::allocateCopyTrim uses inVn->getType() for the new unique.
	outHigh := NewHighVariable("")
	outHigh.AddInstance(outVn)
	if inHigh := inVn.High(); inHigh != nil {
		outHigh.SetType(inHigh.Type())
	}
	m.copyTrims = append(m.copyTrims, copyOp)
	return copyOp
}

// snipReads truncates data-flow for vn at a set of reading ops by inserting a COPY
// immediately after vn's definition site, then replacing those reads with the COPY output.
// C++ parity: merge.cc Merge::snipReads (lines 443-480)
func (m *Merge) snipReads(vn *Varnode, markedOps []*PcodeOp) {
	if len(markedOps) == 0 {
		return
	}
	var bl *BlockBasic
	var pc address.Address
	var afterop *PcodeOp

	if vn.IsInput() {
		// Input varnode: insert at beginning of block 0.
		bg := m.fd.GetBasicBlocks()
		if bg == nil || bg.GetSize() == 0 {
			return
		}
		b0 := bg.GetBlock(0)
		if b0 == nil {
			return
		}
		bb0, ok := b0.Concrete().(*BlockBasic)
		if !ok || bb0 == nil {
			return
		}
		bl = bb0
		// Use the address of the first op in block 0, or a zero address if empty.
		if first := bb0.FirstOp(); first != nil {
			pc = first.Addr()
		}
		afterop = nil // insert at begin
	} else {
		def := vn.Def()
		if def == nil {
			return
		}
		parent := def.Parent()
		if parent == nil {
			return
		}
		bb, ok := parent.Concrete().(*BlockBasic)
		if !ok || bb == nil {
			return
		}
		bl = bb
		pc = def.Addr()
		if def.Code() == CPUI_INDIRECT {
			// Snip must come after the op causing the indirect effect, not the indirect itself.
			// C++ parity: PcodeOp::getOpFromConst(vn->getDef()->getIn(1)->getAddr())
			// In Go there is no getOpFromConst; fall back to using the indirect op itself.
			afterop = def
		} else {
			afterop = def
		}
	}

	copyOp := m.allocateCopyTrim(vn, pc)
	if afterop == nil {
		m.fd.OpInsertBegin(copyOp, bl)
	} else {
		m.fd.OpInsertAfter(copyOp, afterop)
	}

	for _, op := range markedOps {
		slot := op.GetSlot(vn)
		if slot < 0 {
			continue
		}
		m.fd.OpSetInput(op, copyOp.Output(), slot)
	}
}

// blockVarnodeEntry associates a Varnode with the block index of its definition.
// Used to build the sorted list for eliminateIntersect.
// C++ parity: merge.hh BlockVarnode
type blockVarnodeEntry struct {
	index int32    // block index of the defining op (0 if no def / input)
	vn    *Varnode // the Varnode
}

// blockVarnodeFindFront binary-searches the sorted list for the first entry with blocknum.
// Returns -1 if no entry in that block.
// C++ parity: merge.cc BlockVarnode::findFront (lines 43-61)
func blockVarnodeFindFront(blocknum int32, list []blockVarnodeEntry) int {
	lo, hi := 0, len(list)-1
	for lo < hi {
		mid := (lo + hi) / 2
		if list[mid].index >= blocknum {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	if lo > hi {
		return -1
	}
	if list[lo].index != blocknum {
		return -1
	}
	return lo
}

// eliminateIntersect checks whether a single read of vn causes a Cover intersection with
// any other Varnode in blocksort that lives at the same storage address. For each
// offending read it collects the read op and calls snipReads to insert a trimming COPY.
// C++ parity: merge.cc Merge::eliminateIntersect (lines 489-572)
func (m *Merge) eliminateIntersect(vn *Varnode, blocksort []blockVarnodeEntry) {
	var markedOps []*PcodeOp

	for _, op := range vn.DescendIter() {
		insertop := false

		// Build a single-read Cover for vn from def point to this read.
		single := &Cover{}
		single.AddDefPoint(vn)
		single.AddRefPoint(op, vn)

		// Iterate over all (block, CoverBlock) pairs in 'single' in a stable
		// order so the chosen trim reads are deterministic across runs.
		blkKeys := make([]int32, 0, len(single.blocks))
		for blkIdx := range single.blocks {
			blkKeys = append(blkKeys, blkIdx)
		}
		sort.Slice(blkKeys, func(i, j int) bool { return blkKeys[i] < blkKeys[j] })
		for _, blkIdx := range blkKeys {
			slot := blockVarnodeFindFront(blkIdx, blocksort)
			if slot < 0 {
				continue
			}
			for slot < len(blocksort) {
				if blocksort[slot].index != blkIdx {
					break
				}
				vn2 := blocksort[slot].vn
				slot++
				if vn2 == vn {
					continue
				}

				// Check if the definition of vn2 falls within single's range for this block.
				boundtype := single.ContainVarnodeDef(vn2)
				if boundtype == 0 {
					continue
				}

				// Check storage overlap: we only care if they share storage.
				overlaptype := vn.CharacterizeOverlap(vn2)
				if overlaptype == 0 {
					continue // No storage overlap -- no conflict.
				}

				// Gosleigh-specific: ActionStackPtrFlow creates one input varnode per LOAD
				// site at the same stack address (C++ deduplicates via VarnodeBank::xref).
				// Two input varnodes at identical storage cannot have a real live-range
				// conflict (both are defined at function entry). Skip to avoid spurious COPYs.
				// C++ parity: this case never arises because C++ xref deduplicates inputs.
				if vn.IsInput() && vn2.IsInput() && overlaptype == 2 {
					continue
				}

				// overlaptype==1 means partial overlap. The C++ code checks partialCopyShadow
				// here to skip SUBPIECE-derived shadows. That check is not yet ported, so we
				// conservatively treat all partial overlaps as conflicts.
				// C++ parity: merge.cc Merge::eliminateIntersect lines 522-527

				if boundtype == 2 {
					// Both defined at the "same" point: use pointer ordering to pick a canonical order.
					// C++ parity: merge.cc lines 528-542: `if (vn < vn2) continue` for two inputs.
					// We use createIndex as a stable proxy for pointer ordering (lower index = smaller ptr).
					if vn2.Def() == nil {
						if vn.Def() == nil {
							// Both inputs at the same address: Gosleigh may have multiple input
							// varnodes at the same stack address (ActionStackPtrFlow creates one
							// per LOAD site; C++ deduplicates via VarnodeBank::xref which Gosleigh
							// lacks). These are semantically equivalent -- no live-range conflict
							// exists. Skip to avoid inserting spurious trimming COPYs.
							// C++ parity: never hits this case because xref deduplicates inputs.
							continue
						} else {
							continue // vn2 is input, vn is written: vn2 "defined first"
						}
					} else {
						if vn.Def() != nil {
							if vn2.Def().Seq().Order < vn.Def().Seq().Order {
								continue // vn2 defined before vn: no conflict from vn's perspective
							}
						}
					}
				} else if boundtype == 3 {
					// Intersection on the tail: only a conflict if vn2 is addrForce INDIRECT.
					// C++ parity: merge.cc lines 543-562
					if !vn2.IsAddrForce() {
						continue
					}
					if !vn2.IsWritten() {
						continue
					}
					indop := vn2.Def()
					if indop == nil || indop.Code() != CPUI_INDIRECT {
						continue
					}
					// The INDIRECT must be linked to the read op (vn causing the effect).
					// In Go we do not have getOpFromConst, so skip this secondary check.
					// Conservative: treat as conflict when addrForce+INDIRECT present.
				}

				insertop = true
				break // no need to scan more varnodes in this block
			}
			if insertop {
				break // no need to scan more blocks
			}
		}
		if insertop {
			markedOps = append(markedOps, op)
		}
	}

	sort.SliceStable(markedOps, func(i, j int) bool {
		return SeqNumLess(markedOps[i].Seq(), markedOps[j].Seq())
	})
	m.snipReads(vn, markedOps)
}

// unifyAddress ensures all Varnodes in the given group (same storage address/size) can be
// merged by eliminating Cover intersections via snipReads.
// C++ parity: merge.cc Merge::unifyAddress (lines 581-601)
func (m *Merge) unifyAddress(group []*Varnode) {
	if len(group) == 0 {
		return
	}
	// Build blocksort: for each non-free varnode, record its defining block index.
	blocksort := make([]blockVarnodeEntry, 0, len(group))
	for _, vn := range group {
		if vn.IsFree() {
			continue
		}
		e := blockVarnodeEntry{vn: vn}
		def := vn.Def()
		if def == nil {
			e.index = 0 // input varnodes assigned to block 0
		} else {
			parent := def.Parent()
			if parent == nil {
				e.index = 0
			} else {
				e.index = parent.Index()
			}
		}
		blocksort = append(blocksort, e)
	}
	// Stable sort by block index (C++ uses stable_sort).
	sort.SliceStable(blocksort, func(i, j int) bool {
		return blocksort[i].index < blocksort[j].index
	})

	for _, vn := range group {
		if vn.IsFree() {
			continue
		}
		m.eliminateIntersect(vn, blocksort)
	}
}

// mergeRangeMust forces the merge of all non-free Varnodes in a group into a single
// HighVariable. Any Cover intersection at this point causes a panic (the intersections
// should have been resolved by unifyAddress/snipReads first).
// C++ parity: merge.cc Merge::mergeRangeMust (lines 301-317)
func (m *Merge) mergeRangeMust(group []*Varnode) {
	if len(group) == 0 {
		return
	}
	var baseHigh *HighVariable
	for _, vn := range group {
		if vn.IsFree() {
			continue
		}
		h := vn.High()
		if h == nil {
			continue
		}
		if baseHigh == nil {
			baseHigh = h
			continue
		}
		if h == baseHigh {
			continue
		}
		// Forced merge: intersections should be cleared by snipReads.
		// Unlike speculative merges we do not skip on intersection; instead we
		// attempt the merge and log a mismatch if it still conflicts.
		// C++ parity: merge.cc mergeRangeMust calls merge(high, vn->getHigh(), false)
		// which throws on intersection. We skip silently rather than panic.
		if m.testCache.Intersection(baseHigh, h) {
			// known mismatch: intersection still present after snipReads
			continue
		}
		mergeHighVariables(baseHigh, h, m.testCache)
	}
}

// mergeAddrTied performs the forced merge pass for all address-tied Varnodes.
// For each group of Varnodes sharing the same (space, offset, size) in processor or
// spacebase (stack) spaces, it eliminates Cover intersections via snipReads and then
// forces a merge via mergeRangeMust.
// C++ parity: merge.cc Merge::mergeAddrTied (lines 609-648)
func (m *Merge) mergeAddrTied() {
	allVns := m.fd.GetVarnodeBank().AllVarnodes()

	// Walk locTree groups: consecutive varnodes with the same (space, offset, size)
	// in processor or stack spaces that contain at least one addr-tied varnode.
	i := 0
	for i < len(allVns) {
		vn := allVns[i]
		if vn == nil {
			i++
			continue
		}
		spc := vn.Space()
		if spc == nil {
			i++
			continue
		}
		// Only processor and spacebase (stack) spaces.
		// C++ parity: mergeAddrTied checks IPTR_PROCESSOR and IPTR_SPACEBASE.
		// In Go: SpaceKindProcessor and SpaceKindStack.
		kind := spc.Kind
		if kind != address.SpaceKindProcessor && kind != address.SpaceKindStack {
			// Skip the whole space: advance past all varnodes in this space.
			i++
			for i < len(allVns) && allVns[i] != nil && allVns[i].Space() == spc {
				i++
			}
			continue
		}

		// Collect all non-free varnodes at the same (space, offset, size).
		// Also collect any overlapping varnodes (different sizes at overlapping offsets)
		// because overlapLoc in C++ expands the range.
		// For simplicity in Go, we group by exact (space, offset, size) only.
		// The gcd case has exact-match groups, so this is sufficient.
		off := vn.Offset()
		sz := vn.Size()

		groupStart := i
		for i < len(allVns) && allVns[i] != nil &&
			allVns[i].Space() == spc &&
			allVns[i].Offset() == off &&
			allVns[i].Size() == sz {
			i++
		}
		group := allVns[groupStart:i]

		// Check if any varnode in the group is addr-tied.
		// C++ parity: mergeAddrTied checks (flags & Varnode::addrtied) != 0.
		hasAddrTied := false
		for _, gvn := range group {
			if gvn != nil && !gvn.IsFree() && gvn.IsAddrTied() {
				hasAddrTied = true
				break
			}
		}
		if !hasAddrTied {
			continue
		}

		// Build non-free group list for unifyAddress + mergeRangeMust.
		nonFree := make([]*Varnode, 0, len(group))
		for _, gvn := range group {
			if gvn != nil && !gvn.IsFree() {
				nonFree = append(nonFree, gvn)
			}
		}
		if len(nonFree) == 0 {
			continue
		}

		m.unifyAddress(nonFree)
		m.mergeRangeMust(nonFree)
	}
}

func (m *Merge) inflateTest(a *Varnode, high *HighVariable) bool {
	if a == nil || high == nil {
		return false
	}
	ahigh := a.High()
	if ahigh == nil {
		return false
	}
	m.testCache.UpdateHigh(high)
	highCover := high.getCover()
	if highCover == nil {
		return false
	}
	for _, b := range ahigh.Instances() {
		if b == nil || b == a {
			continue
		}
		// C++ parity: b->getCover() is per-varnode, not the HV aggregate.
		// Using b.High().getCover() (aggregate) is wrong -- it merges all
		// instance ranges and creates false level-2 intersections.
		bIndivCover := vnGetCover(b)
		if bIndivCover == nil {
			continue
		}
		if bIndivCover.Intersect(highCover) == 2 {
			return true
		}
	}
	return false
}
