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

// processCopyTrims replaces groups of trim COPYs that feed one variable from
// the same value with a single COPY in their common dominator.
// C++ parity: Merge::processCopyTrims.
func (m *Merge) processCopyTrims() {
	count := make(map[*HighVariable]int)
	var order []*HighVariable
	for _, op := range m.copyTrims {
		if op.IsDead() || op.Output() == nil {
			continue
		}
		high := op.Output().High()
		if count[high] == 0 {
			order = append(order, high)
		}
		count[high]++
	}
	m.copyTrims = m.copyTrims[:0]
	for _, high := range order {
		if count[high] >= 2 {
			m.processHighDominantCopy(high)
		}
	}
}

// compareCopyByInVarnode groups COPYs by input Varnode, then block, then
// position in the block. C++ parity: Merge::compareCopyByInVarnode.
func compareCopyByInVarnode(op1, op2 *PcodeOp) bool {
	in1, in2 := op1.Input(0), op2.Input(0)
	if in1 != in2 {
		return in1.CreateIndex() < in2.CreateIndex()
	}
	i1, i2 := op1.Parent().Index(), op2.Parent().Index()
	if i1 != i2 {
		return i1 < i2
	}
	return opBlockUIndex(op1) < opBlockUIndex(op2)
}

// findAllIntoCopies lists the COPYs writing into high from another variable,
// optionally only those with temporary (unique) output.
// C++ parity: Merge::findAllIntoCopies.
func findAllIntoCopies(high *HighVariable, filterTemps bool) []*PcodeOp {
	var res []*PcodeOp
	for _, vn := range high.Instances() {
		if !vn.IsWritten() {
			continue
		}
		op := vn.Def()
		if op.Code() != CPUI_COPY || op.Input(0).High() == high {
			continue
		}
		if filterTemps && !op.Output().Space().IsUnique() {
			continue
		}
		res = append(res, op)
	}
	sort.SliceStable(res, func(i, j int) bool { return compareCopyByInVarnode(res[i], res[j]) })
	return res
}

// copyGroups calls fn for each run of COPYs sharing an input Varnode.
func copyGroups(copyIns []*PcodeOp, fn func(group []*PcodeOp)) {
	for pos := 0; pos < len(copyIns); {
		inVn := copyIns[pos].Input(0)
		sz := 1
		for pos+sz < len(copyIns) && copyIns[pos+sz].Input(0) == inVn {
			sz++
		}
		if sz > 1 {
			fn(copyIns[pos : pos+sz])
		}
		pos += sz
	}
}

// C++ parity: Merge::processHighDominantCopy.
func (m *Merge) processHighDominantCopy(high *HighVariable) {
	copyIns := findAllIntoCopies(high, true)
	if len(copyIns) < 2 {
		return
	}
	copyGroups(copyIns, func(g []*PcodeOp) { m.buildDominantCopy(high, g) })
}

// C++ parity: Merge::processHighRedundantCopy.
func (m *Merge) processHighRedundantCopy(high *HighVariable) {
	copyIns := findAllIntoCopies(high, false)
	if len(copyIns) < 2 {
		return
	}
	copyGroups(copyIns, func(g []*PcodeOp) { m.markRedundantCopies(high, g) })
}

// findCommonBlockSet is the dominator of every block in the set.
// C++ parity: FlowBlock::findCommonBlock(const vector<FlowBlock *> &).
func findCommonBlockSet(blockSet []*FlowBlock) *FlowBlock {
	var marked []*FlowBlock
	res := blockSet[0]
	bestIndex := res.Index()
	for bl := res; bl != nil; bl = bl.ImmedDom() {
		bl.SetFlag(BlockFlagMark)
		marked = append(marked, bl)
	}
	for _, bl := range blockSet[1:] {
		if bestIndex == 0 {
			break
		}
		for !bl.HasFlag(BlockFlagMark) {
			bl.SetFlag(BlockFlagMark)
			marked = append(marked, bl)
			bl = bl.ImmedDom()
		}
		if bl.Index() < bestIndex {
			res = bl
			bestIndex = res.Index()
		}
	}
	for _, bl := range marked {
		bl.ClearFlag(BlockFlagMark)
	}
	return res
}

// buildDominantCopy replaces the COPYs in copy (all from one Varnode) with a
// single COPY in their common dominator, except those whose new live range
// would intersect the variable.
// C++ parity: Merge::buildDominantCopy.
func (m *Merge) buildDominantCopy(high *HighVariable, copy []*PcodeOp) {
	blockSet := make([]*FlowBlock, len(copy))
	for i, op := range copy {
		blockSet[i] = &op.Parent().FlowBlock
	}
	domBl, _ := findCommonBlockSet(blockSet).Concrete().(*BlockBasic)
	if domBl == nil {
		return
	}
	domCopy := copy[0]
	rootVn := domCopy.Input(0)
	domVn := domCopy.Output()
	domCopyIsNew := domBl != domCopy.Parent()
	if domCopyIsNew {
		addr := domCopy.Addr()
		if last := domBl.LastOp(); last != nil {
			addr = last.Addr() // C++ uses BlockBasic::getStop
		}
		oldCopy := domCopy
		domCopy = m.fd.NewOp(1, addr)
		m.fd.OpSetOpcode(domCopy, CPUI_COPY)
		if ct := rootVn.Type(); ct != nil && ct.NeedsResolution() {
			fieldNum := -1
			if res := m.fd.getUnionField(ct, oldCopy, 0); res != nil {
				fieldNum = res.fieldNum
			}
			m.fd.forceFacingType(ct, fieldNum, domCopy, 0)
			m.fd.forceFacingType(ct, fieldNum, domCopy, -1)
		}
		domVn = m.fd.NewUnique(rootVn.Size())
		SetVarnodeType(domVn, rootVn.Type())
		NewHighVariable("").AddInstance(domVn) // C++ newUnique assigns a high once highs are on
		m.fd.OpSetOutput(domCopy, domVn)
		m.fd.OpSetInput(domCopy, rootVn, 0)
		m.fd.OpInsertEnd(domCopy, domBl)
	}
	// The cover the variable has without any COPY from rootVn.
	bCover := &Cover{}
	for _, vn := range high.Instances() {
		if vn.IsWritten() {
			if op := vn.Def(); op.Code() == CPUI_COPY && op.Input(0).CopyShadow(rootVn) {
				continue
			}
		}
		bCover.Merge(vnGetCover(vn))
	}
	keep := make(map[*PcodeOp]bool)
	count := len(copy)
	for _, op := range copy {
		if op == domCopy {
			continue
		}
		outVn := op.Output()
		aCover := &Cover{}
		aCover.AddDefPoint(domVn)
		for _, rd := range outVn.DescendIter() {
			aCover.AddRefPoint(rd, outVn)
		}
		if bCover.Intersect(aCover) > 1 {
			count--
			keep[op] = true
		}
	}
	if count <= 1 { // not worth replacing one COPY with another
		for _, op := range copy {
			keep[op] = true
		}
		count = 0
		if domCopyIsNew {
			m.fd.OpDestroy(domCopy)
		}
	}
	for _, op := range copy {
		if keep[op] {
			continue
		}
		if outVn := op.Output(); outVn != domVn {
			high.removeInstance(outVn)
			m.fd.TotalReplace(outVn, domVn)
			m.fd.OpDestroy(op)
		}
	}
	if count > 0 && domCopyIsNew && domVn.High() != high {
		mergeHighVariablesSpeculative(high, domVn.High(), nil)
	}
}

// checkCopyPair reports whether subOp is redundant given domOp: domOp
// dominates it and no other write to high lies between them.
// C++ parity: Merge::checkCopyPair.
func checkCopyPair(high *HighVariable, domOp, subOp *PcodeOp) bool {
	if !domOp.Parent().FlowBlock.Dominates(&subOp.Parent().FlowBlock) {
		return false
	}
	rng := &Cover{}
	rng.AddDefPoint(domOp.Output())
	rng.AddRefPoint(subOp, subOp.Input(0))
	inVn := domOp.Input(0)
	for _, vn := range high.Instances() {
		if !vn.IsWritten() {
			continue
		}
		op := vn.Def()
		if op.Code() == CPUI_COPY && op.Input(0) == inVn {
			continue
		}
		if rng.contain(op, 1) {
			return false
		}
	}
	return true
}

// C++ parity: Merge::markRedundantCopies.
func (m *Merge) markRedundantCopies(high *HighVariable, copy []*PcodeOp) {
	for i := len(copy) - 1; i > 0; i-- {
		subOp := copy[i]
		if subOp.IsDead() {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			domOp := copy[j]
			if domOp.IsDead() {
				continue
			}
			if checkCopyPair(high, domOp, subOp) {
				subOp.SetFlag(PcodeOpNonPrinting)
				break
			}
		}
	}
}

// contain reports whether op lies in the cover; with max==2 it must be
// strictly inside, not on a boundary. C++ parity: Cover::contain.
func (c *Cover) contain(op *PcodeOp, max int) bool {
	cb := c.GetCoverBlock(op.Parent().Index())
	if cb == nil || !cb.Contain(op) {
		return false
	}
	return max == 1 || cb.Boundary(op) == 0
}

// removeInstance drops vn from the variable. C++ parity: HighVariable::remove.
func (hv *HighVariable) removeInstance(vn *Varnode) {
	for i, w := range hv.instances {
		if w == vn {
			hv.instances = append(hv.instances[:i], hv.instances[i+1:]...)
			break
		}
	}
	hv.MarkCoverDirty()
}
