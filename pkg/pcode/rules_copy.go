package pcode

type RulePropagateCopy struct{ batchRule }

func NewRulePropagateCopy(group string) *RulePropagateCopy {
	r := &RulePropagateCopy{}
	r.batchRule = newBatchRule(group, "propagatecopy", nil, r.apply, func(g string) Rule { return NewRulePropagateCopy(g) })
	return r
}

func (r *RulePropagateCopy) apply(op *PcodeOp, data *Funcdata) int {
	// C++ parity: RulePropagateCopy::applyOp (ruleaction.cc:3953) skips a
	// return-copy op. Gosleigh does not plumb the dedicated return-copy COPY form
	// (double.go), so it flags the CPUI_RETURN opcode itself with PcodeOpReturnCopy
	// (typeop.go). Propagating a COPY into the RETURN's input moves the return value
	// off the ABI return register onto the copy's source register (e.g. `return EAX`
	// where `EAX = EDX` becomes `return EDX`); a later deadcode round then empties
	// the return because the source register is not the return register, collapsing
	// the function to `void`. Keep the return-materializing COPY here, as Ghidra does.
	if op.HasFlag(PcodeOpReturnCopy) {
		return 0
	}
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
	r.batchRule = newBatchRule(group, "humptyor", []OpCode{CPUI_INT_OR}, r.apply, func(g string) Rule { return NewRuleHumptyOr(g) })
	return r
}

// apply is a faithful port of RuleHumptyOr::applyOp (ruleaction.cc:5350):
// simplify masked pieces INT_ORed together, `(V & W) | (V & X) => V & (W|X)`.
//
// The previous body under this name matched {PIECE} and folded
// concat(sub(V,hi),sub(V,0)) back into V; that is a strict subset of
// RuleHumptyDumpty (rules_ghidra_port.go, registered on the analysis pool),
// so dropping it loses no coverage.
//
// Oscillation note: when the shared operand `a` is a constant that fully covers
// the other operands, C++ never reaches here because RuleAndMask has already
// reduced `a & b => b`. Gosleigh cannot guarantee that pre-reduction has run
// (commutative normalization ordering differs), so the slot-symmetric cover
// branch in RuleAndMask (rules_bitwise.go) reduces `K & X => X` in either slot;
// that, together with the NZMask guards below (ruleaction.cc:5407-5408), is what
// keeps this rule and RuleAndDistribute from oscillating.
func (r *RuleHumptyOr) apply(op *PcodeOp, data *Funcdata) int {
	vn1 := op.Input(0)
	if !vn1.IsWritten() {
		return 0
	}
	vn2 := op.Input(1)
	if !vn2.IsWritten() {
		return 0
	}
	and1 := vn1.Def()
	if and1.Code() != CPUI_INT_AND {
		return 0
	}
	and2 := vn2.Def()
	if and2.Code() != CPUI_INT_AND {
		return 0
	}
	a := and1.Input(0)
	b := and1.Input(1)
	c := and2.Input(0)
	d := and2.Input(1)
	// Identify the operand `a` shared by both ANDs; b and c become the two
	// non-matching operands. Varnode identity (SSA), matching C++ `==`.
	switch {
	case a == c:
		c = d // non-matching are b and d
	case a == d:
		// non-matching are b and c
	case b == c:
		b = a
		a = c
		c = d
	case b == d:
		b = a
		a = d
	default:
		return 0
	}
	if b.IsConstant() && c.IsConstant() {
		totalbits := b.Offset() | c.Offset()
		if totalbits == maskForSize(a.Size()) {
			// Between the two sides we get all bits of a: convert to COPY.
			data.OpSetOpcode(op, CPUI_COPY)
			data.OpRemoveInput(op, 1)
			data.OpSetInput(op, a, 0)
		} else {
			// Some bits, but not all: convert to an AND.
			data.OpSetOpcode(op, CPUI_INT_AND)
			data.OpSetInput(op, a, 0)
			data.OpSetInput(op, data.NewConstant(a.Size(), totalbits), 1)
		}
		return 1
	}
	if !b.IsHeritageKnown() {
		return 0
	}
	if !c.IsHeritageKnown() {
		return 0
	}
	aMask := a.NZMask()
	if b.NZMask()&aMask == 0 {
		return 0 // RuleAndDistribute would reverse us
	}
	if c.NZMask()&aMask == 0 {
		return 0 // RuleAndDistribute would reverse us
	}
	// Oscillation guard (not present in C++). RuleHumptyOr and RuleAndDistribute are
	// exact inverses: this rule folds (a&b)|(a&c) into a&(b|c), and RuleAndDistribute's
	// trivial-cover branch (ruleaction.cc:1289-1290) distributes it straight back when
	// the constant `a` fully covers b or c. Their guards do not exclude each other for
	// that constant-cover case, so the pair is a LATENT livelock -- and it is latent in
	// C++ too: RuleTermOrder, RuleAndMask, RuleAndDistribute are faithful line-for-line
	// ports and ActionPool::processOp is structurally identical to action.cc:822 (same
	// re-fire-until-stable loop, same SeqNum op order). C++ simply never hands these two
	// rules the triggering shape, because its normal analysis reduces the covered
	// `a&x => x` (RuleAndMask) on a standalone INT_AND op before the INT_OR is revisited.
	// Gosleigh's 6502 path reaches the INT_OR with the covered AND still intact, so the
	// inverse pair flips the same op forever (measured: 55858 iterations). Declining the
	// exact case AndDistribute would reverse closes the gap between the two inverse rules;
	// it is byte-identical to C++ on every golden (and, if anything, more robust than
	// stock Ghidra, which would hang on the same input). NOT an ActionPool or RuleTermOrder
	// defect -- both are faithful. The only "more upstream" fix is to find why this masked
	// form (constant clearing a single bit, covering one OR branch) is produced at all on
	// the 6502 path; low priority, arch-specific.
	if a.IsConstant() {
		if b.NZMask()&aMask == b.NZMask() {
			return 0
		}
		if c.NZMask()&aMask == c.NZMask() {
			return 0
		}
	}
	newOrOp := data.NewOp(2, op.Addr())
	data.OpSetOpcode(newOrOp, CPUI_INT_OR)
	orVn := data.NewUniqueOut(a.Size(), newOrOp)
	data.OpSetInput(newOrOp, b, 0)
	data.OpSetInput(newOrOp, c, 1)
	data.OpInsertBefore(newOrOp, op)
	data.OpSetInput(op, a, 0)
	data.OpSetInput(op, orVn, 1)
	data.OpSetOpcode(op, CPUI_INT_AND)
	return 1
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
	func(group string) Rule { return NewRuleZextIdentity(group) },
	func(group string) Rule { return NewRuleZextEliminate(group) },
	func(group string) Rule { return NewRuleSlessToLess(group) },
	func(group string) Rule { return NewRuleZextSless(group) },
	func(group string) Rule { return NewRuleBooleanDedup(group) },
	func(group string) Rule { return NewRuleBooleanNegate(group) },
	func(group string) Rule { return NewRuleBoolZext(group) },
	func(group string) Rule { return NewRuleLogic2Bool(group) },
	func(group string) Rule { return NewRuleMultiCollapse(group) },
	// RuleAddUnsigned is deliberately NOT registered here. C++ registers it only in
	// the cleanup pool (coreaction.cc:5708 actcleanup), never in an analysis pool.
	// Co-registering it alongside RuleSub2Add (below) forms a rewrite cycle:
	// RuleSub2Add turns `x - c` into `x + (c * -1)`, RuleCollapseConstants folds
	// that back to `x + (-c)`, and RuleAddUnsigned turns it into `x - c` again.
	// Gosleigh used to break the cycle by excluding all-ones constants from
	// RuleAddUnsigned, which also broke the faithful `x + 0xffffffff => x - 1`
	// rewrite. Matching the C++ pool placement is the parity fix.
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
	func(group string) Rule { return NewRuleXorIdentity(group) },
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
	// RuleMultNegOne is deliberately NOT registered here. C++ places it only in
	// the cleanup pool (actcleanup, action.go:1428), never in an analysis pool.
	// It is the exact inverse of Rule2Comp2Mult (`V * -1 => -V` vs `-V => V * -1`),
	// so co-registering the pair in this analysis batch makes the convergence loop
	// oscillate forever. Matching the C++ pool placement is the parity fix.
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
