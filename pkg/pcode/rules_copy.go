package pcode

type RulePropagateCopy struct{ batchRule }

func NewRulePropagateCopy(group string) *RulePropagateCopy {
	r := &RulePropagateCopy{}
	r.batchRule = newBatchRule(group, "propagatecopy", nil, r.apply, func(g string) Rule { return NewRulePropagateCopy(g) })
	return r
}

func (r *RulePropagateCopy) apply(op *PcodeOp, data *Funcdata) int {
	changed := 0
	for i := 0; i < op.NumInput(); i++ {
		copyop := definedBy(op.Input(i), CPUI_COPY)
		if copyop == nil || copyop.Input(0) == nil {
			continue
		}
		if copyop.Input(0) == op.Input(i) {
			continue
		}
		// Don't propagate into marker ops (MULTIEQUAL/INDIRECT) when:
		//  (a) source is a constant, or
		//  (b) source and output are addr-tied to different locations.
		// C++ parity: RulePropagateCopy::applyOp ruleaction.cc:3966-3971
		if op.IsMarker() {
			invn := copyop.Input(0)
			if invn.IsConstant() {
				continue
			}
			out := op.Output()
			// C++ parity: ruleaction.cc:3969 -- block only when both the COPY
			// source and the marker output carry the real addrtied flag and map
			// to different addresses. Registers used as transient computation are
			// not addrtied, so propagating a stack param into a register-space phi
			// is allowed (this is what unifies the param and register SSA chains).
			if out != nil && invn.IsAddrTied() && out.IsAddrTied() {
				if invn.Space() != out.Space() || invn.Offset() != out.Offset() {
					continue
				}
			}
		}
		data.OpUnsetInput(op, i)
		data.OpSetInput(op, copyop.Input(0), i)
		changed = 1
		// C++ leaves the now-dead COPY for the dead-code pass to reap
		// (RulePropagateCopy::applyOp, ruleaction.cc:3960). Gosleigh used to reap
		// detached COPYs here because AddTreeState created its ops without splicing
		// them into a basic block, so ActionDeadCode never saw them; both the
		// detached-op bug (Funcdata.NewOpBefore) and the spurious address-expression
		// COPY (AddTreeState.buildTree) are fixed at the source, so the eager reap
		// is gone.
	}
	return changed
}

type RuleConcatCommute struct{ batchRule }

func NewRuleConcatCommute(group string) *RuleConcatCommute {
	r := &RuleConcatCommute{}
	r.batchRule = newBatchRule(group, "concatcommute", []OpCode{CPUI_PIECE, CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleConcatCommute(g) })
	return r
}

func (r *RuleConcatCommute) apply(op *PcodeOp, data *Funcdata) int {
	changed := 0
	for i := 0; i < op.NumInput(); i++ {
		if i == 1 && op.Code() == CPUI_SUBPIECE && op.Input(i).IsConstant() {
			continue
		}
		copyop := definedBy(op.Input(i), CPUI_COPY)
		if copyop == nil {
			continue
		}
		data.OpUnsetInput(op, i)
		data.OpSetInput(op, copyop.Input(0), i)
		changed = 1
	}
	return changed
}

type RuleSubCancel struct{ batchRule }

func NewRuleSubCancel(group string) *RuleSubCancel {
	r := &RuleSubCancel{}
	r.batchRule = newBatchRule(group, "subcancel", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubCancel(g) })
	return r
}

func (r *RuleSubCancel) apply(op *PcodeOp, data *Funcdata) int {
	piece := definedBy(op.Input(0), CPUI_PIECE)
	if piece == nil {
		return 0
	}
	offset, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	lo := piece.Input(1)
	hi := piece.Input(0)
	if offset == 0 && outputSize(op) == lo.Size() {
		return rewriteToCopy(data, op, lo)
	}
	if offset == uint64(lo.Size()) && outputSize(op) == hi.Size() {
		return rewriteToCopy(data, op, hi)
	}
	return 0
}

type RuleSubNormal struct{ batchRule }

func NewRuleSubNormal(group string) *RuleSubNormal {
	r := &RuleSubNormal{}
	r.batchRule = newBatchRule(group, "subnormal", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSubNormal(g) })
	return r
}

func (r *RuleSubNormal) apply(op *PcodeOp, data *Funcdata) int {
	if isZeroConst(op.Input(1)) && outputSize(op) == op.Input(0).Size() {
		return rewriteToCopy(data, op, op.Input(0))
	}
	return 0
}

type RuleMultiCollapse struct{ batchRule }

func NewRuleMultiCollapse(group string) *RuleMultiCollapse {
	r := &RuleMultiCollapse{}
	r.batchRule = newBatchRule(group, "multicollapse", []OpCode{CPUI_MULTIEQUAL}, r.apply, func(g string) Rule { return NewRuleMultiCollapse(g) })
	return r
}

// heritageKnownVn mirrors C++ Varnode::isHeritageKnown(): a varnode has a
// stable identity once it is constant, written, or a function input.
func heritageKnownVn(v *Varnode) bool {
	return v != nil && (v.IsConstant() || v.IsWritten() || v.IsInput())
}

// apply collapses a MULTIEQUAL whose branches all carry the same value.
// C++ parity: ruleaction.cc RuleMultiCollapse::applyOp (3254-3363). The
// mark-based walk skips branches that recur unchanged around a loop (a branch
// that is the MULTIEQUAL output itself, or another already-visited MULTIEQUAL),
// which is what collapses a self-referential phi MULTIEQUAL(V, self) -> COPY(V).
// Without this, dead addr-tied self-phis keep a param HighVariable's Cover alive
// across the loop and block merging the param with its loop-carried register.
//
// Deviation: C++ reuses an existing copy via cseFindInBlock on the functional-
// equality path; Gosleigh always creates a fresh copy (no CSE) -- a safe
// inefficiency, not a correctness change.
func (r *RuleMultiCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() == 0 {
		return 0
	}
	for i := 0; i < op.NumInput(); i++ {
		if !heritageKnownVn(op.Input(i)) {
			return 0 // everything must be heritaged before collapse
		}
	}

	funcEq := false // matching by functional equality
	nofunc := false // functional equality initially allowed
	var defcopyr *Varnode
	matchlist := make([]*Varnode, 0, op.NumInput())
	for i := 0; i < op.NumInput(); i++ {
		matchlist = append(matchlist, op.Input(i))
	}
	// Find base branch to match: first input not defined by a MULTIEQUAL.
	for i := 0; i < op.NumInput(); i++ {
		copyr := matchlist[i]
		if !copyr.IsWritten() || copyr.Def().Code() != CPUI_MULTIEQUAL {
			defcopyr = copyr
			break
		}
	}

	success := true
	skiplist := []*Varnode{op.Output()}
	op.Output().SetMark()
	for j := 0; j < len(matchlist); j++ {
		copyr := matchlist[j]
		if copyr.IsMark() {
			continue // recurring value in a loop -- treat as equal, skip
		}
		if defcopyr == nil {
			defcopyr = copyr
			if !copyr.IsWritten() || copyr.Def().Code() == CPUI_MULTIEQUAL {
				nofunc = true // MULTIEQUAL/unwritten cannot match by functional equality
			}
		} else if defcopyr == copyr {
			continue // a matching branch
		} else if !nofunc && functionalEquality(defcopyr, copyr) {
			// Functional-equality collapse path not yet ported; bail rather than
			// risk a malformed op. Absolute-equality (incl. self-ref skip) below
			// is what the gcd loop-phi collapse needs.
			// TODO known mismatch: port the func_eq copy/CSE path (ruleaction.cc 3324-3351).
			_ = funcEq
			for _, v := range skiplist {
				v.ClearMark()
			}
			return 0
		} else if copyr.IsWritten() && copyr.Def().Code() == CPUI_MULTIEQUAL {
			// Give the branch one last chance: add its inputs to the match list.
			newop := copyr.Def()
			skiplist = append(skiplist, copyr)
			copyr.SetMark()
			for i := 0; i < newop.NumInput(); i++ {
				matchlist = append(matchlist, newop.Input(i))
			}
		} else {
			success = false
			break
		}
	}

	if !success {
		for _, v := range skiplist {
			v.ClearMark()
		}
		return 0
	}

	for _, copyr := range skiplist {
		copyr.ClearMark()
		cur := copyr.Def()
		if cur == nil {
			continue
		}
		if funcEq {
			// Only functional equality: rebuild cur as a copy of defcopyr's op.
			newop := defcopyr.Def()
			if newop == nil {
				continue
			}
			needsReinsert := cur.Code() == CPUI_MULTIEQUAL
			parms := make([]*Varnode, 0, newop.NumInput())
			for i := 0; i < newop.NumInput(); i++ {
				parms = append(parms, newop.Input(i))
			}
			data.OpSetAllInput(cur, parms)
			data.OpSetOpcode(cur, newop.Code())
			if needsReinsert {
				bl := cur.Parent()
				data.OpUninsert(cur)
				data.OpInsertBegin(cur, bl) // insert AFTER any other MULTIEQUAL
			}
		} else {
			// Absolute equality: replace all refs to copyr with defcopyr.
			data.TotalReplace(copyr, defcopyr)
			data.OpDestroy(cur)
		}
	}
	return 1
}

type RuleHumptyOr struct{ batchRule }

func NewRuleHumptyOr(group string) *RuleHumptyOr {
	r := &RuleHumptyOr{}
	r.batchRule = newBatchRule(group, "humptyor", []OpCode{CPUI_PIECE}, r.apply, func(g string) Rule { return NewRuleHumptyOr(g) })
	return r
}

func (r *RuleHumptyOr) apply(op *PcodeOp, data *Funcdata) int {
	hi := definedBy(op.Input(0), CPUI_SUBPIECE)
	lo := definedBy(op.Input(1), CPUI_SUBPIECE)
	if hi == nil || lo == nil || !sameValue(hi.Input(0), lo.Input(0)) {
		return 0
	}
	hiOff, hiOK := constantValue(hi.Input(1))
	loOff, loOK := constantValue(lo.Input(1))
	root := hi.Input(0)
	if !hiOK || !loOK || loOff != 0 || hiOff != uint64(outputSize(op.Input(1).Def())) {
		_ = root
	}
	if !hiOK || !loOK || loOff != 0 || hiOff != uint64(op.Input(1).Size()) {
		return 0
	}
	if root.Size() != outputSize(op) {
		return 0
	}
	return rewriteToCopy(data, op, root)
}

type batchARuleFactory func(string) Rule

var batchARuleFactories = []batchARuleFactory{
	func(group string) Rule { return NewRulePiece2Zext(group) },
	func(group string) Rule { return NewRulePiece2Sext(group) },
	func(group string) Rule { return NewRuleBxor2NotEqual(group) },
	func(group string) Rule { return NewRuleOrMask(group) },
	func(group string) Rule { return NewRuleAndMask(group) },
	func(group string) Rule { return NewRuleOrCollapse(group) },
	func(group string) Rule { return NewRuleAndOrLump(group) },
	func(group string) Rule { return NewRuleNegateIdentity(group) },
	func(group string) Rule { return NewRuleShiftBitops(group) },
	func(group string) Rule { return NewRuleRightShiftAnd(group) },
	func(group string) Rule { return NewRuleTrivialArith(group) },
	func(group string) Rule { return NewRuleEquality(group) },
	func(group string) Rule { return NewRuleTrivialBool(group) },
	func(group string) Rule { return NewRuleZextEliminate(group) },
	func(group string) Rule { return NewRuleSlessToLess(group) },
	func(group string) Rule { return NewRuleZextSless(group) },
	func(group string) Rule { return NewRuleBooleanDedup(group) },
	func(group string) Rule { return NewRuleBooleanNegate(group) },
	func(group string) Rule { return NewRuleBoolZext(group) },
	func(group string) Rule { return NewRuleLogic2Bool(group) },
	func(group string) Rule { return NewRuleMultiCollapse(group) },
	func(group string) Rule { return NewRuleAddUnsigned(group) },
	func(group string) Rule { return NewRule2Comp2Sub(group) },
	func(group string) Rule { return NewRuleSubRight(group) },
	// RulePushMultiME must come BEFORE RulePropagateCopy: PushMultiME fires on
	// MULTIEQUAL(COPY(x), COPY(y)) and needs both inputs still written (COPY-defined).
	// PropagateCopy would inline the COPY sources (making inputs non-written) before
	// PushMultiME gets a chance to find/create the substitute phi. C++ parity:
	// oppool1 registers RulePushMulti (our RulePushMultiME) at line 5529,
	// RulePropagateCopy at line 5577 -- PUSHME comes first.
	func(group string) Rule { return NewRulePushMultiME(group) },
	func(group string) Rule { return NewRulePropagateCopy(group) },
	func(group string) Rule { return NewRuleAndCommute(group) },
	func(group string) Rule { return NewRuleAndPiece(group) },
	func(group string) Rule { return NewRuleAndZext(group) },
	func(group string) Rule { return NewRuleShift2Mult(group) },
	func(group string) Rule { return NewRuleConcatCommute(group) },
	func(group string) Rule { return NewRule2Comp2Mult(group) },
	func(group string) Rule { return NewRuleSub2Add(group) },
	func(group string) Rule { return NewRuleXorCollapse(group) },
	func(group string) Rule { return NewRuleAddMultCollapse(group) },
	func(group string) Rule { return NewRuleSubExtComm(group) },
	func(group string) Rule { return NewRuleSubCommute(group) },
	func(group string) Rule { return NewRuleConcatZext(group) },
	func(group string) Rule { return NewRuleZextCommute(group) },
	func(group string) Rule { return NewRuleZextShiftZext(group) },
	func(group string) Rule { return NewRuleSubZext(group) },
	func(group string) Rule { return NewRuleSubCancel(group) },
	func(group string) Rule { return NewRuleHumptyOr(group) },
	func(group string) Rule { return NewRuleBoolNegate(group) },
	func(group string) Rule { return NewRuleCondNegate(group) },
	func(group string) Rule { return NewRuleLess2Zero(group) },
	func(group string) Rule { return NewRuleLessEqual2Zero(group) },
	func(group string) Rule { return NewRuleSLess2Zero(group) },
	func(group string) Rule { return NewRuleEqual2Zero(group) },
	func(group string) Rule { return NewRuleEqual2Constant(group) },
	func(group string) Rule { return NewRuleMultNegOne(group) },
	func(group string) Rule { return NewRuleNegateNegate(group) },
	func(group string) Rule { return NewRuleSubNormal(group) },
	func(group string) Rule { return NewRuleSborrow(group) },
	func(group string) Rule { return NewRuleLessNotEqualBoolAnd(group) },
	func(group string) Rule { return NewRuleSignForm(group) },   // CDQ: SUBPIECE(INT_SEXT(x),c) -> INT_SRIGHT
	func(group string) Rule { return NewRuleOrSextForm(group) }, // IDIV dividend: INT_OR(..SRIGHT..) -> INT_SEXT
	// pointer rules -- C++ ActionPool::registerRule equivalents; inserted before identityel
	func(group string) Rule { return NewRulePtrArith(group) },
	func(group string) Rule { return NewRulePtraddUndo(group) },
	func(group string) Rule { return NewRulePtrsubUndo(group) },
	func(group string) Rule { return NewRuleStructOffset0(group) },
	func(group string) Rule { return NewRuleSegment(group) },
	func(group string) Rule { return NewRulePtrFlow(group) },
	func(group string) Rule { return NewRulePtrsubCharConstant(group) },
	func(group string) Rule { return NewRulePtraddZero(group) },
	func(group string) Rule { return NewRulePtraddConstantIndex(group) },
	func(group string) Rule { return NewRulePtrsubZero(group) },
	func(group string) Rule { return NewRulePtrsubAddConst(group) },
	func(group string) Rule { return NewRulePtrsubCollapse(group) },
	func(group string) Rule { return NewRulePtrFlowCopy(group) },
	func(group string) Rule { return NewRuleLessEqual(group) },
	func(group string) Rule { return NewRuleIdentityEl(group) },
	// rules_ghidra_port.go: new C++ parity ports
	func(group string) Rule { return NewRuleCollectTerms(group) },
	func(group string) Rule { return NewRuleTermOrder(group) },
	func(group string) Rule { return NewRuleSelectCse(group) },
	func(group string) Rule { return NewRuleEarlyRemoval(group) },
	func(group string) Rule { return NewRuleCollapseConstants(group) },
	func(group string) Rule { return NewRuleCarryElim(group) },
	func(group string) Rule { return NewRuleScarry(group) },
	func(group string) Rule { return NewRuleTrivialShift(group) },
	func(group string) Rule { return NewRuleSignShift(group) },
	func(group string) Rule { return NewRuleTestSign(group) },
	func(group string) Rule { return NewRuleOrConsume(group) },
	func(group string) Rule { return NewRuleIntLessEqual(group) },
	func(group string) Rule { return NewRuleBitUndistribute(group) },
	func(group string) Rule { return NewRuleBooleanUndistribute(group) },
	func(group string) Rule { return NewRuleShiftAnd(group) },
	func(group string) Rule { return NewRuleConcatZero(group) },
	func(group string) Rule { return NewRuleHumptyDumpty(group) },
	func(group string) Rule { return NewRuleDumptyHump(group) },
	func(group string) Rule { return NewRuleIndirectCollapse(group) },
	func(group string) Rule { return NewRuleDivTermAdd(group) },
	func(group string) Rule { return NewRuleDivTermAdd2(group) },
	func(group string) Rule { return NewRuleSignNearMult(group) },
	func(group string) Rule { return NewRuleRangeMeld(group) },
	func(group string) Rule { return NewRuleFloatRange(group) },
	func(group string) Rule { return NewRulePopcountBoolXor(group) },
	func(group string) Rule { return NewRuleExtensionPush(group) },
	func(group string) Rule { return NewRulePieceStructure(group) },
	// C++ groups under floatprecision pool; tentatively in BatchA pending dedicated pool
	func(group string) Rule { return NewRuleInt2FloatCollapse(group) },
	func(group string) Rule { return NewRuleOrPredicate(group) },
	func(group string) Rule { return NewRuleDumptyHumpLate(group) },
	func(group string) Rule { return NewRuleSubvarAnd(group) },
	func(group string) Rule { return NewRuleSubvarSubpiece(group) },
	func(group string) Rule { return NewRuleSubvarCompZero(group) },
	func(group string) Rule { return NewRuleSubvarShift(group) },
	func(group string) Rule { return NewRuleSubvarZext(group) },
	func(group string) Rule { return NewRuleSubvarSext(group) },
	func(group string) Rule { return NewRuleSplitFlow(group) },
	func(group string) Rule { return NewRuleSplitCopy(group) },
	func(group string) Rule { return NewRuleSplitLoad(group) },
	func(group string) Rule { return NewRuleSplitStore(group) },
	func(group string) Rule { return NewRuleSubfloatConvert(group) },
	// bitfield.go rules -- real control-flow ports; short-circuit on HasBitfields()==false
	func(group string) Rule { return NewRuleBitFieldStore(group) },
	func(group string) Rule { return NewRuleBitFieldLoad(group) },
	func(group string) Rule { return NewRuleBitFieldOut(group) },
	func(group string) Rule { return NewRuleBitFieldIn(group) },
	func(group string) Rule { return NewRulePullAbsorb(group) },
	func(group string) Rule { return NewRuleInsertAbsorb(group) },
	// double.go rules -- real ports of RuleDouble*
	func(group string) Rule { return NewRuleDoubleIn(group) },
	func(group string) Rule { return NewRuleDoubleOut(group) },
	func(group string) Rule { return NewRuleDoubleLoad(group) },
	func(group string) Rule { return NewRuleDoubleStore(group) },
	// constseq.go rules -- real ports of RuleStringCopy / RuleStringStore
	func(group string) Rule { return NewRuleStringCopy(group) },
	func(group string) Rule { return NewRuleStringStore(group) },
}

func BatchARules(group string) []Rule {
	rules := make([]Rule, 0, len(batchARuleFactories))
	for _, factory := range batchARuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchARules(pool *ActionPool, group string) int {
	count := 0
	for _, rule := range BatchARules(group) {
		pool.AddRule(rule)
		count++
	}
	return count
}

func NewBatchAActionPool(name string, group string) *ActionPool {
	pool := NewActionPool(0, name)
	AddBatchARules(pool, group)
	return pool
}
