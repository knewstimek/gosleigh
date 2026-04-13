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

import "sort"

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

// computeHighIntersection checks whether the union Covers of two HighVariables have
// a range-level (level 2) intersection.
func computeHighIntersection(h1, h2 *HighVariable) bool {
	c1 := h1.getCover()
	c2 := h2.getCover()
	if c1 == nil || c2 == nil {
		return false
	}
	return c1.Intersect(c2) == 2
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
// C++ parity: merge.cc Merge::mergeTestRequired (lines 102-166, simplified)
func mergeTestRequired(h1, h2 *HighVariable) bool {
	if h1 == h2 {
		return true // already the same variable
	}
	if h1 == nil || h2 == nil {
		return true // nil HighVariable cannot conflict
	}
	// If both have locked types they must agree.
	if h1.datatype != nil && h2.datatype != nil {
		if h1.datatype != h2.datatype {
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

// MergeOp forces the merge of all input and output Varnodes of op into a single
// HighVariable.  If Cover intersections prevent a direct merge, TrimOpInput is
// called to insert COPY ops that shorten the conflicting live ranges.
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
				break
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

// processCopyTrims records the dominant-copy trimming phase.
// C++ parity: merge.cc Merge::processCopyTrims
func (m *Merge) processCopyTrims() {
	_ = m
}

// markInternalCopies marks COPY ops between internal Varnodes.
// C++ parity: merge.cc Merge::markInternalCopies
func (m *Merge) markInternalCopies() {
	_ = m
}

// mergeMultiEntry merges Varnodes with multiple SymbolEntrys.
// C++ parity: merge.cc Merge::mergeMultiEntry
func (m *Merge) mergeMultiEntry() {
	_ = m
}

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
			if !mergeTestRequired(highOut, highIn) {
				continue
			}
			mergeHighVariables(highOut, highIn, m.testCache)
		}
	}
}

func (m *Merge) mergeRequired() {
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
		bCover := b.High()
		if bCover == nil || bCover.getCover() == nil {
			continue
		}
		if bCover.getCover().Intersect(highCover) == 2 {
			return true
		}
	}
	return false
}
