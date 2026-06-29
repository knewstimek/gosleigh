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

// ---- ActionNormalizeBranches ----

// ActionNormalizeBranches normalizes conditional branches so INT_NOTEQUAL
// conditions become INT_EQUAL (with swapped edges). This creates a canonical
// form that ConditionalJoin can match.
// C++ parity: blockaction.cc ActionNormalizeBranches::apply (lines 2117-2138)
type ActionNormalizeBranches struct {
	ActionBase
}

func NewActionNormalizeBranches(group string) *ActionNormalizeBranches {
	a := &ActionNormalizeBranches{}
	// C++ parity: ActionNormalizeBranches uses flags=0 (blockaction.hh:286).
	a.ActionBase = NewActionBase(a, 0, "normalizebranches", group)
	return a
}

func (a *ActionNormalizeBranches) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionNormalizeBranches(a.GetGroup())
}

func (a *ActionNormalizeBranches) Apply(data *Funcdata) int {
	bg := data.GetBasicBlocks()
	if bg == nil {
		return 0
	}
	changed := 0
	for i := 0; i < bg.GetSize(); i++ {
		bb := bg.GetBlock(i)
		if bb == nil || bb.SizeOut() != 2 {
			continue
		}
		concrete, ok := bb.Concrete().(*BlockBasic)
		if !ok {
			continue
		}
		cbranch := concrete.LastOp()
		if cbranch == nil || cbranch.Code() != CPUI_CBRANCH {
			continue
		}
		var fliplist []*PcodeOp
		if opFlipInPlaceTest(cbranch, &fliplist) != 0 {
			continue
		}
		opFlipInPlaceExecute(data, fliplist)
		// flipInPlaceExecuteBlock takes *FlowBlock (from prefer_complement.go).
		flipInPlaceExecuteBlock(&concrete.FlowBlock)
		changed++
	}
	data.ClearDeadOps()
	if changed > 0 {
		return 1
	}
	return 0
}

// ---- ConditionalJoin ----

// mergePair is an ordered pair of varnodes that need to be merged in the joinblock.
type mergePair struct{ side1, side2 *Varnode }

func mergePairLess(a, b mergePair) bool {
	switch {
	case a.side1 == nil:
		return b.side1 != nil
	case b.side1 == nil:
		return false
	}
	if cmp := CompareLocDef(a.side1, b.side1); cmp != 0 {
		return cmp < 0
	}
	switch {
	case a.side2 == nil:
		return b.side2 != nil
	case b.side2 == nil:
		return false
	}
	if cmp := CompareLocDef(a.side2, b.side2); cmp != 0 {
		return cmp < 0
	}
	return a.side1.CreateIndex() < b.side1.CreateIndex()
}

// ConditionalJoin merges two identical conditional branches (block1, block2)
// that share the same pair of exit blocks (exita, exitb) into a single joinblock.
// C++ parity: blockaction.cc ConditionalJoin (lines 1895-2108)
type ConditionalJoin struct {
	data         *Funcdata
	block1       *BlockBasic
	block2       *BlockBasic
	exita        *BlockBasic
	exitb        *BlockBasic
	joinblock    *BlockBasic
	cbranch1     *PcodeOp
	cbranch2     *PcodeOp
	a_in1, a_in2 int // reverse indices into exita
	b_in1, b_in2 int // reverse indices into exitb
	mergeneed    map[mergePair]*Varnode
}

func newConditionalJoin(data *Funcdata) *ConditionalJoin {
	return &ConditionalJoin{data: data, mergeneed: make(map[mergePair]*Varnode)}
}

func (cj *ConditionalJoin) clear() {
	cj.mergeneed = make(map[mergePair]*Varnode)
	cj.block1 = nil
	cj.block2 = nil
	cj.exita = nil
	cj.exitb = nil
	cj.joinblock = nil
	cj.cbranch1 = nil
	cj.cbranch2 = nil
}

// findDups checks if the two CBRANCHes have functionally equivalent conditions.
// C++ parity: blockaction.cc ConditionalJoin::findDups (lines 1912-1944)
func (cj *ConditionalJoin) findDups() bool {
	cj.cbranch1 = cj.block1.LastOp()
	if cj.cbranch1 == nil || cj.cbranch1.Code() != CPUI_CBRANCH {
		return false
	}
	cj.cbranch2 = cj.block2.LastOp()
	if cj.cbranch2 == nil || cj.cbranch2.Code() != CPUI_CBRANCH {
		return false
	}
	if cj.cbranch1.HasFlag(PcodeOpBooleanFlip) {
		return false
	}
	if cj.cbranch2.HasFlag(PcodeOpBooleanFlip) {
		return false
	}
	vn1 := cj.cbranch1.Input(1)
	vn2 := cj.cbranch2.Input(1)
	if vn1 == vn2 {
		return true
	}
	if !vn1.IsWritten() || !vn2.IsWritten() {
		return false
	}
	if vn1.IsSpacebasePlaceholder() || vn2.IsSpacebasePlaceholder() {
		return false
	}
	var buf1, buf2 [2]*Varnode
	res := functionalEqualityLevel(vn1, vn2, buf1[:], buf2[:])
	if res < 0 || res > 1 {
		return false
	}
	op1 := vn1.Def()
	if op1.Code() == CPUI_SUBPIECE || op1.Code() == CPUI_COPY {
		return false
	}
	cj.mergeneed[mergePair{vn1, vn2}] = nil
	return true
}

// checkExitBlock scans MULTIEQUALs in exit and records pairs that differ
// between block1 and block2's in-edges.
// C++ parity: blockaction.cc ConditionalJoin::checkExitBlock (lines 1954-1971)
func (cj *ConditionalJoin) checkExitBlock(exit *BlockBasic, in1, in2 int) {
	for _, op := range exit.Ops() {
		if op.Code() == CPUI_MULTIEQUAL {
			vn1 := op.Input(in1)
			vn2 := op.Input(in2)
			if vn1 != vn2 {
				cj.mergeneed[mergePair{vn1, vn2}] = nil
			}
		} else if op.Code() != CPUI_COPY {
			break
		}
	}
}

// setupMultiequals creates MULTIEQUAL ops in joinblock for each pair in mergeneed.
// C++ parity: blockaction.cc ConditionalJoin::setupMultiequals (lines 2023-2039)
func (cj *ConditionalJoin) setupMultiequals() {
	addr := cj.cbranch1.Addr()
	pairs := make([]mergePair, 0, len(cj.mergeneed))
	for k := range cj.mergeneed {
		pairs = append(pairs, k)
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return mergePairLess(pairs[i], pairs[j])
	})
	for _, k := range pairs {
		if cj.mergeneed[k] != nil {
			continue
		}
		vn1, vn2 := k.side1, k.side2
		multi := cj.data.NewOp(2, addr)
		cj.data.OpSetOpcode(multi, CPUI_MULTIEQUAL)
		outvn := cj.data.NewUniqueOut(vn1.Size(), multi)
		cj.data.OpSetInput(multi, vn1, 0)
		cj.data.OpSetInput(multi, vn2, 1)
		cj.mergeneed[k] = outvn
		cj.data.OpInsertEnd(multi, cj.joinblock)
	}
}

// moveCbranch moves cbranch1 to joinblock and destroys cbranch2.
// C++ parity: blockaction.cc ConditionalJoin::moveCbranch (lines 2043-2056)
func (cj *ConditionalJoin) moveCbranch() {
	vn1 := cj.cbranch1.Input(1)
	vn2 := cj.cbranch2.Input(1)
	cj.data.OpUninsert(cj.cbranch1)
	cj.data.OpInsertEnd(cj.cbranch1, cj.joinblock)
	var vn *Varnode
	if vn1 != vn2 {
		vn = cj.mergeneed[mergePair{vn1, vn2}]
	} else {
		vn = vn1
	}
	cj.data.OpSetInput(cj.cbranch1, vn, 1)
	cj.data.OpDestroy(cj.cbranch2)
}

// cutDownMultiequals reduces 2-input MULTIEQUALs in exit to 1-input (COPY).
// C++ parity: blockaction.cc ConditionalJoin::cutDownMultiequals (lines 1981-2018)
func (cj *ConditionalJoin) cutDownMultiequals(exit *BlockBasic, in1, in2 int) {
	lo, hi := in1, in2
	if in1 > in2 {
		lo, hi = in2, in1
	}
	ops := exit.Ops() // snapshot
	for _, op := range ops {
		if op.Code() == CPUI_MULTIEQUAL {
			vn1 := op.Input(in1)
			vn2 := op.Input(in2)
			cj.data.OpRemoveInput(op, hi)
			if vn1 != vn2 {
				subvn := cj.mergeneed[mergePair{vn1, vn2}]
				if subvn != nil {
					cj.data.OpSetInput(op, subvn, lo)
				}
			}
			if op.NumInput() == 1 {
				cj.data.OpUninsert(op)
				cj.data.OpSetOpcode(op, CPUI_COPY)
				cj.data.OpInsertBegin(op, exit)
			}
		} else if op.Code() != CPUI_COPY {
			break
		}
	}
}

// match checks if block1 and block2 can be joined, sets up mergeneed.
// C++ parity: blockaction.cc ConditionalJoin::match (lines 2065-2091)
func (cj *ConditionalJoin) match(b1, b2 *BlockBasic) bool {
	cj.block1 = b1
	cj.block2 = b2
	if b1 == b2 {
		return false
	}
	if b1.SizeOut() != 2 || b2.SizeOut() != 2 {
		return false
	}
	exitaFB := b1.FalseOut()
	exitbFB := b1.TrueOut()
	if exitaFB == exitbFB {
		return false
	}
	if b2.FalseOut() != exitaFB {
		return false
	}
	if b2.TrueOut() != exitbFB {
		return false
	}
	// exita and exitb must be BlockBasic (check concrete type).
	exitaConc, ok1 := exitaFB.Concrete().(*BlockBasic)
	exitbConc, ok2 := exitbFB.Concrete().(*BlockBasic)
	if !ok1 || !ok2 {
		return false
	}
	cj.exita = exitaConc
	cj.exitb = exitbConc
	// Get reverse indices: position of b1/b2 edge in exit's in-edges.
	cj.a_in1 = b1.FlowBlock.OutRevIndex(0) // position of b1's false-edge in exita.inEdges
	cj.b_in1 = b1.FlowBlock.OutRevIndex(1) // position of b1's true-edge in exitb.inEdges
	cj.a_in2 = b2.FlowBlock.OutRevIndex(0) // position of b2's false-edge in exita.inEdges
	cj.b_in2 = b2.FlowBlock.OutRevIndex(1) // position of b2's true-edge in exitb.inEdges
	if !cj.findDups() {
		cj.clear()
		return false
	}
	cj.checkExitBlock(cj.exita, cj.a_in1, cj.a_in2)
	cj.checkExitBlock(cj.exitb, cj.b_in1, cj.b_in2)
	return true
}

// execute performs the actual join after match() succeeded.
// C++ parity: blockaction.cc ConditionalJoin::execute (lines 2094-2101)
func (cj *ConditionalJoin) execute() {
	pairs := make([]mergePair, 0, len(cj.mergeneed))
	for k := range cj.mergeneed {
		pairs = append(pairs, k)
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return mergePairLess(pairs[i], pairs[j])
	})

	cj.joinblock = cj.data.NodeJoinCreateBlock(
		cj.block1, cj.block2, cj.exita, cj.exitb,
		cj.a_in1 > cj.a_in2, cj.b_in1 > cj.b_in2,
		cj.cbranch1.Addr(),
	)
	cj.setupMultiequals()
	cj.moveCbranch()
	cj.cutDownMultiequals(cj.exita, cj.a_in1, cj.a_in2)
	cj.cutDownMultiequals(cj.exitb, cj.b_in1, cj.b_in2)
}

// ---- ActionNodeJoin ----

// ActionNodeJoin scans all basic blocks for pairs that can be merged by
// ConditionalJoin. Pairs are found by looking at the in-edges of the "least
// in-degree" successor of each block.
// C++ parity: blockaction.cc ActionNodeJoin::apply (lines 2326-2364)
type ActionNodeJoin struct {
	ActionBase
}

func NewActionNodeJoin(group string) *ActionNodeJoin {
	a := &ActionNodeJoin{}
	// C++ parity: ActionNodeJoin uses flags=0 (blockaction.hh:352), NOT once-per-func.
	// It must re-run every mainloop pass: ActionBlockStructure's collapse can set
	// PcodeOpBooleanFlip on a loop CBRANCH (making findDups reject), and only a later
	// pass -- after RuleCondNegate clears the flip -- can the join succeed. A once-per-
	// func NodeJoin would reject in pass 1 and never retry, freezing a do-while loop.
	a.ActionBase = NewActionBase(a, 0, "nodejoin", group)
	return a
}

func (a *ActionNodeJoin) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionNodeJoin(a.GetGroup())
}

func (a *ActionNodeJoin) Apply(data *Funcdata) int {
	bg := data.GetBasicBlocks()
	if bg == nil || bg.GetSize() == 0 {
		return 0
	}

	condjoin := newConditionalJoin(data)
	changed := 0

	for i := 0; i < bg.GetSize(); i++ {
		bb := bg.GetBlock(i)
		if bb == nil || bb.SizeOut() != 2 {
			continue
		}
		bbConc, ok := bb.Concrete().(*BlockBasic)
		if !ok {
			continue
		}

		out1 := bb.FalseOut() // outEdges[0]
		out2 := bb.TrueOut()  // outEdges[1]

		var leastout *FlowBlock
		var inslot int
		if out1.SizeIn() < out2.SizeIn() {
			leastout = out1
			inslot = bb.OutRevIndex(0)
		} else {
			leastout = out2
			inslot = bb.OutRevIndex(1)
		}
		if leastout.SizeIn() <= 1 {
			continue
		}
		for j := 0; j < leastout.SizeIn(); j++ {
			if j == inslot {
				continue
			}
			bb2 := leastout.InEdge(j).Point
			bb2Conc, ok := bb2.Concrete().(*BlockBasic)
			if !ok {
				continue
			}
			matchResult := condjoin.match(bbConc, bb2Conc)
			if matchResult {
				changed++
				condjoin.execute()
				condjoin.clear()
				break
			}
		}
	}
	if changed > 0 {
		return 1
	}
	return 0
}
