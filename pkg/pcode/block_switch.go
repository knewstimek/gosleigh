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

// switchCase annotates one case of a structured switch.
// C++ parity: BlockSwitch::CaseOrder.
type switchCase struct {
	block     *FlowBlock // structured case block
	basic     *FlowBlock // first basic block executed, in the control-flow graph
	label     uint64     // untyped case label
	depth     int        // position in a fall-thru chain
	chain     int        // case this one falls into, -1 for none
	outindex  int        // switch out-edge reaching the case
	gototype  uint32     // non-zero for an unstructured case
	isexit    bool       // case flows to the switch exit
	isdefault bool       // formal default case
}

// cfgBlock maps a structure-graph leaf to its control-flow basic block.
// C++ parity: BlockCopy::subBlock(0).
func cfgBlock(leaf *FlowBlock) *FlowBlock {
	if bb, ok := leaf.Concrete().(*BlockBasic); ok && bb.srcDelegate != nil {
		return &bb.srcDelegate.FlowBlock
	}
	return leaf
}

// exitLeaf is the leaf that exits b, or nil.
// C++ parity: FlowBlock::getExitLeaf and overrides.
func (b *FlowBlock) exitLeaf() *FlowBlock {
	if _, ok := b.Concrete().(*BlockBasic); ok {
		return b
	}
	children := b.StructuredChildren()
	if len(children) == 0 {
		return nil
	}
	switch b.Type() {
	case BlockListType:
		return children[len(children)-1].exitLeaf()
	case BlockIfType:
		if len(children) == 1 {
			return children[0].exitLeaf()
		}
	case BlockGotoType, BlockMultiGotoType:
		return children[0].exitLeaf()
	}
	return nil
}

// addSwitchCase appends a case reached from switchbl.
// C++ parity: BlockSwitch::addCase.
func addSwitchCase(cases []switchCase, switchbl, bl *FlowBlock, gt uint32) []switchCase {
	basic := cfgBlock(bl.getFrontLeaf())
	c := switchCase{block: bl, basic: basic, chain: -1, gototype: gt}
	if in := basic.GetInIndex(switchbl); in >= 0 {
		c.outindex = basic.InRevIndex(in)
	}
	c.isexit = gt == 0 && bl.SizeOut() == 1
	c.isdefault = switchbl.OutEdge(c.outindex).Label&EdgeFlagDefaultSwitch != 0
	return append(cases, c)
}

// grabSwitchCases builds the case annotations of a switch whose first
// component is the switch itself; it must run before the components are
// collapsed, while the cases still have their out-edges.
// C++ parity: BlockSwitch::grabCaseBasic.
func grabSwitchCases(cs []*FlowBlock) []switchCase {
	leaf := cs[0].exitLeaf()
	if leaf == nil {
		return nil
	}
	switchbl := cfgBlock(leaf)
	casemap := make([]int, switchbl.SizeOut())
	for i := range casemap {
		casemap[i] = -1
	}
	var cases []switchCase
	for _, bl := range cs[1:] {
		cases = addSwitchCase(cases, switchbl, bl, 0)
		casemap[cases[len(cases)-1].outindex] = len(cases) - 1
	}
	// Fill in fall-thru chaining; all fall-thru blocks are plain gotos.
	for i := range cases {
		if cases[i].block.Type() != BlockGotoType {
			continue
		}
		target := cases[i].block.GotoTargetBlock()
		if target == nil {
			continue
		}
		basic := cfgBlock(target.getFrontLeaf())
		if in := basic.GetInIndex(switchbl); in >= 0 {
			cases[i].chain = casemap[basic.InRevIndex(in)]
		}
	}
	if cs[0].Type() == BlockMultiGotoType {
		for _, target := range getBlockStructInfo(cs[0]).gotoTargets {
			cases = addSwitchCase(cases, switchbl, target, BlockFlagGotoGoto)
		}
	}
	return cases
}

// finalizeSwitch assigns labels from the jump-table and sorts the cases by
// label, keeping fall-thru chains together.
// C++ parity: BlockSwitch::finalizePrinting.
func finalizeSwitch(fd *Funcdata, b *FlowBlock) {
	info := getBlockStructInfo(b)
	cases := info.cases
	jt := b.switchJumpTable(fd)
	if jt == nil {
		return
	}
	for i := range cases {
		for j := cases[i].chain; j != -1; j = cases[j].chain {
			if cases[j].depth != 0 {
				break // already visited: break loops
			}
			cases[j].depth = -1 // not the root of a chain
		}
	}
	for i := range cases {
		c := &cases[i]
		if jt.NumIndicesByBlock(c.basic) == 0 {
			c.label = 0
			continue
		}
		if c.depth != 0 {
			continue // labels are set from chain roots
		}
		c.label = jt.caseLabel(c.basic, 0)
		depth := 1
		for j := c.chain; j != -1; j = cases[j].chain {
			if cases[j].depth > 0 {
				break
			}
			cases[j].depth = depth
			depth++
			cases[j].label = c.label
		}
	}
	sort.SliceStable(cases, func(i, j int) bool {
		if cases[i].label != cases[j].label {
			return cases[i].label < cases[j].label
		}
		return cases[i].depth < cases[j].depth
	})
}

// switchJumpTable is the jump-table of the BRANCHIND ending the switch.
// C++ parity: BlockSwitch::jump.
func (b *FlowBlock) switchJumpTable(fd *Funcdata) *JumpTable {
	children := b.StructuredChildren()
	if fd == nil || len(children) == 0 {
		return nil
	}
	leaf := children[0].exitLeaf()
	if leaf == nil {
		return nil
	}
	bb, ok := cfgBlock(leaf).Concrete().(*BlockBasic)
	if !ok || bb.EmptyOp() {
		return nil
	}
	return fd.FindJumpTable(bb.LastOp())
}

// caseLabel is the label of the i-th table entry reaching bl.
// C++ parity: JumpTable::getLabelByIndex(getIndexByBlock(bl,i)).
func (jt *JumpTable) caseLabel(bl *FlowBlock, i int) uint64 {
	idx, err := jt.IndexByBlock(bl, i)
	if err != nil || int(idx) >= len(jt.label) {
		return 0
	}
	return jt.label[idx]
}

// finalizeSwitches runs finalizeSwitch over every switch under b.
// C++ parity: BlockGraph::finalizePrinting recursion.
func finalizeSwitches(fd *Funcdata, b *FlowBlock) {
	for _, c := range b.StructuredChildren() {
		finalizeSwitches(fd, c)
	}
	if b.Type() == BlockSwitchType {
		finalizeSwitch(fd, b)
	}
}
