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

const (
	defaultMaxImpliedRef      = 2
	defaultMaxTermDuplication = 2
)

func markVarnodeExplicit(vn *Varnode) {
	if vn == nil {
		return
	}
	vn.SetExplicit()
	if high := vn.High(); high != nil {
		high.SetExplicit()
	}
}

type explicitStackElement struct {
	vn       *Varnode
	slot     int
	slotback int
}

func newExplicitStackElement(vn *Varnode) explicitStackElement {
	elem := explicitStackElement{vn: vn}
	if vn == nil || !vn.IsWritten() || vn.Def() == nil {
		return elem
	}
	switch vn.Def().Code() {
	case CPUI_LOAD:
		elem.slot = 1
		elem.slotback = 2
	case CPUI_PTRADD:
		elem.slotback = 1
	case CPUI_SEGMENTOP:
		elem.slot = 2
		elem.slotback = 3
	default:
		elem.slotback = vn.Def().NumInput()
	}
	return elem
}

// ActionMarkExplicit identifies varnodes that must remain visible in the final
// syntax tree.
// C++ parity: coreaction.cc ActionMarkExplicit::apply (simplified)
type ActionMarkExplicit struct {
	ActionBase
}

var _ Action = (*ActionMarkExplicit)(nil)

func NewActionMarkExplicit(group string) *ActionMarkExplicit {
	act := &ActionMarkExplicit{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "markexplicit", group)
	return act
}

func (a *ActionMarkExplicit) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMarkExplicit(a.GetGroup())
}

// known mismatch: baseExplicit does not yet model mapped-symbol aliasing,
// PTRSUB spacebase special-casing, or proto-partial PIECE root analysis.
func markExplicitBase(vn *Varnode, maxref int) int {
	def := vn.Def()
	if def == nil {
		return -1
	}
	if def.IsMarker() {
		return -1
	}
	if def.IsCall() {
		if def.Code() == CPUI_NEW && def.NumInput() == 1 {
			return -2
		}
		return -1
	}
	if high := vn.High(); high != nil && high.NumInstances() > 1 {
		return -1
	}
	if vn.IsAddrTied() || vn.IsMapped() || vn.IsProtoPartial() {
		return -1
	}
	if vn.HasNoDescend() {
		return -1
	}
	if def.Code() == CPUI_INSERT {
		storeOp := def.Output().LoneDescend()
		if storeOp == nil || storeOp.Code() != CPUI_STORE {
			return -1
		}
	}
	descCount := 0
	for _, op := range vn.DescendIter() {
		if op == nil {
			continue
		}
		if op.IsMarker() {
			return -1
		}
		descCount++
		if descCount > maxref {
			return -1
		}
	}
	return descCount
}

func markExplicitMultipleInteraction(multlist []*Varnode) int {
	purge := make(map[*Varnode]struct{})
	for _, vn := range multlist {
		if vn == nil || vn.Def() == nil {
			continue
		}
		op := vn.Def()
		opc := op.Code()
		if !(op.IsBoolOutput() || opc == CPUI_INT_ZEXT || opc == CPUI_INT_SEXT || opc == CPUI_PTRADD) {
			continue
		}
		maxparam := 2
		if op.NumInput() < maxparam {
			maxparam = op.NumInput()
		}
		for i := 0; i < maxparam; i++ {
			topvn := op.Input(i)
			if topvn == nil || !topvn.IsMark() {
				continue
			}
			if topvn.IsWritten() && topvn.Def() != nil && topvn.Def().IsBoolOutput() {
				continue
			}
			if opc == CPUI_PTRADD {
				if topvn.Def() != nil && topvn.Def().Code() == CPUI_PTRADD {
					purge[topvn] = struct{}{}
				}
				continue
			}
			purge[topvn] = struct{}{}
		}
	}
	for vn := range purge {
		markVarnodeExplicit(vn)
		vn.ClearImplied()
		if high := vn.High(); high != nil {
			high.ClearImplied()
		}
		vn.ClearMark()
	}
	return len(purge)
}

func markExplicitProcessMultiplier(vn *Varnode, max int) {
	opstack := []explicitStackElement{newExplicitStackElement(vn)}
	finalCount := 0
	for len(opstack) != 0 {
		cur := &opstack[len(opstack)-1]
		vncur := cur.vn
		isTerm := vncur == nil || vncur.IsExplicit() || !vncur.IsWritten() || vncur.Def() == nil
		if isTerm || cur.slotback <= cur.slot {
			if isTerm && vncur != nil && !vncur.IsSpaceBase() {
				finalCount++
			}
			if finalCount > max {
				markVarnodeExplicit(vn)
				vn.ClearImplied()
				if high := vn.High(); high != nil {
					high.ClearImplied()
				}
				return
			}
			opstack = opstack[:len(opstack)-1]
			continue
		}
		op := vncur.Def()
		newvn := op.Input(cur.slot)
		cur.slot++
		if newvn != nil && newvn.IsMark() {
			markVarnodeExplicit(vn)
			vn.ClearImplied()
			if high := vn.High(); high != nil {
				high.ClearImplied()
			}
		}
		opstack = append(opstack, newExplicitStackElement(newvn))
	}
}

func markExplicitCheckNewToConstructor(vn *Varnode) {
	if vn == nil || vn.Def() == nil {
		return
	}
	op := vn.Def()
	bb := op.Parent()
	if bb == nil {
		return
	}
	var firstUse *PcodeOp
	for _, desc := range vn.DescendIter() {
		if desc == nil || desc.Parent() != bb {
			continue
		}
		if firstUse == nil || SeqNumLess(desc.Seq(), firstUse.Seq()) {
			firstUse = desc
		}
	}
	if firstUse == nil || !firstUse.IsCall() || firstUse.Output() != nil || firstUse.NumInput() < 2 {
		return
	}
	if firstUse.Input(1) != vn {
		return
	}
	firstUse.SetAdditionalFlag(PcodeOpSpecialPrint)
	op.SetFlag(PcodeOpNonPrinting)
}

func (a *ActionMarkExplicit) Apply(data *Funcdata) int {
	multlist := make([]*Varnode, 0)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() {
			continue
		}
		descCount := markExplicitBase(vn, defaultMaxImpliedRef)
		if descCount < 0 {
			markVarnodeExplicit(vn)
			if descCount < -1 {
				markExplicitCheckNewToConstructor(vn)
			}
			continue
		}
		if descCount > 1 {
			vn.SetMark()
			multlist = append(multlist, vn)
		}
	}
	markExplicitMultipleInteraction(multlist)
	for _, vn := range multlist {
		if vn.IsMark() {
			markExplicitProcessMultiplier(vn, defaultMaxTermDuplication)
		}
	}
	for _, vn := range multlist {
		vn.ClearMark()
	}
	return 0
}

type descTreeElement struct {
	vn   *Varnode
	desc []*PcodeOp
	idx  int
}

func newDescTreeElement(vn *Varnode) descTreeElement {
	elem := descTreeElement{vn: vn}
	if vn != nil {
		elem.desc = vn.DescendIter()
	}
	return elem
}

// ActionMarkImplied marks expression-only varnodes as implied when their
// propagated cover remains safe.
// C++ parity: coreaction.cc ActionMarkImplied::apply (simplified)
type ActionMarkImplied struct {
	ActionBase
}

var _ Action = (*ActionMarkImplied)(nil)

func NewActionMarkImplied(group string) *ActionMarkImplied {
	act := &ActionMarkImplied{}
	act.ActionBase = NewActionBase(act, ActionRuleOncePerFunc, "markimplied", group)
	return act
}

func (a *ActionMarkImplied) Clone(groups ActionGroupList) Action {
	if !a.MatchGroup(groups) {
		return nil
	}
	return NewActionMarkImplied(a.GetGroup())
}

// known mismatch: alias reasoning only distinguishes exact varnode identity and
// equal constants. The current Go port does not yet model the richer PTRADD and
// shadow alias analysis used by Ghidra.
func markImpliedPossibleAliasStep(vn1, vn2 *Varnode) bool {
	if vn1 == vn2 {
		return true
	}
	if vn1 == nil || vn2 == nil {
		return false
	}
	if vn1.IsConstant() && vn2.IsConstant() {
		return vn1.Offset() == vn2.Offset()
	}
	return true
}

func markImpliedPossibleAlias(vn1, vn2 *Varnode, depth int) bool {
	if vn1 == vn2 {
		return true
	}
	if depth <= 0 {
		return markImpliedPossibleAliasStep(vn1, vn2)
	}
	if vn1 != nil && vn1.IsWritten() && vn1.Def() != nil {
		switch vn1.Def().Code() {
		case CPUI_COPY, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_2COMP, CPUI_INT_NEGATE:
			return markImpliedPossibleAlias(vn1.Def().Input(0), vn2, depth-1)
		}
	}
	if vn2 != nil && vn2.IsWritten() && vn2.Def() != nil {
		switch vn2.Def().Code() {
		case CPUI_COPY, CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_2COMP, CPUI_INT_NEGATE:
			return markImpliedPossibleAlias(vn1, vn2.Def().Input(0), depth-1)
		}
	}
	return markImpliedPossibleAliasStep(vn1, vn2)
}

func markImpliedCheckCover(data *Funcdata, vn *Varnode) bool {
	if vn == nil || vn.Def() == nil {
		return false
	}
	op := vn.Def()
	high := vn.High()
	if high == nil {
		return false
	}
	cov := high.getCover()
	if cov == nil {
		return false
	}
	if op.Code() == CPUI_LOAD {
		for _, storeOp := range data.GetPcodeOpBank().AllOps() {
			if storeOp == nil || storeOp.IsDead() || storeOp.Code() != CPUI_STORE {
				continue
			}
			storeBlock := storeOp.Parent()
			if storeBlock == nil {
				continue
			}
			// C++ parity: coreaction.cc checkImpliedCover uses
			// vn->getCover()->contain(storeop,2). Cover::contain with max==2
			// requires INTERIOR containment (boundary()==0): a STORE sitting
			// exactly on the LOAD's def or last-use boundary does not count as
			// "crossing". Boundary-inclusive containment would wrongly force
			// e.g. the *param_2 LOAD in "*param_1 = *param_2" to stay explicit.
			cb := cov.GetCoverBlock(storeBlock.Index())
			if !cb.Contain(storeOp) || cb.Boundary(storeOp) != 0 {
				continue
			}
			if storeOp.NumInput() < 3 || op.NumInput() < 2 {
				continue
			}
			if storeOp.Input(0) == nil || op.Input(0) == nil {
				continue
			}
			if storeOp.Input(0).Offset() == op.Input(0).Offset() {
				// C++ parity: isPossibleAlias(...) -> return false. If the LOAD
				// and STORE pointers may hold the same value, the loaded value
				// can change across the STORE, so the LOAD must stay explicit.
				if markImpliedPossibleAlias(storeOp.Input(1), op.Input(1), 2) {
					return false
				}
			}
		}
	}
	for i := 0; i < op.NumInput(); i++ {
		defvn := op.Input(i)
		if defvn == nil || defvn.IsConstant() {
			continue
		}
		itResult := NewMerge(data).inflateTest(defvn, high)
		if itResult {
			return false
		}
	}
	// C++ checkImpliedCover (coreaction.cc:3408) guards with op->isCall(), which
	// covers CPUI_CALL, CPUI_CALLIND and CPUI_CALLOTHER -- not a bare CPUI_CALL
	// compare. An indirect/other call output must also honour the crossing-call
	// cover test before it can be folded implied.
	if op.IsCall() || op.Code() == CPUI_LOAD {
		for _, callOp := range data.GetPcodeOpBank().AllOps() {
			if callOp == nil || callOp.IsDead() || !callOp.IsCall() {
				continue
			}
			callBlock := callOp.Parent()
			if callBlock == nil {
				continue
			}
			// C++ parity: vn->getCover()->contain(callop,2) -- interior only.
			cb := cov.GetCoverBlock(callBlock.Index())
			if cb.Contain(callOp) && cb.Boundary(callOp) == 0 {
				return false
			}
		}
	}
	return true
}

func (a *ActionMarkImplied) Apply(data *Funcdata) int {
	merge := NewMerge(data)
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if vn == nil || vn.IsFree() || vn.IsExplicit() || vn.IsImplied() {
			continue
		}
		stack := []descTreeElement{newDescTreeElement(vn)}
		for len(stack) != 0 {
			top := &stack[len(stack)-1]
			vncur := top.vn
			if top.idx >= len(top.desc) {
				checkResult := markImpliedCheckCover(data, vncur)
				if !checkResult {
					markVarnodeExplicit(vncur)
				} else {
					merge.markImplied(vncur)
				}
				stack = stack[:len(stack)-1]
				continue
			}
			outvn := top.desc[top.idx].Output()
			top.idx++
			if outvn == nil || outvn.IsExplicit() || outvn.IsImplied() {
				continue
			}
			stack = append(stack, newDescTreeElement(outvn))
		}
	}
	return 0
}
