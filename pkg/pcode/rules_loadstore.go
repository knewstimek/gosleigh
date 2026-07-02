package pcode

import "gosleigh/pkg/address"

type RuleLoadVarnode struct{ batchRule }

type RuleStoreVarnode struct{ batchRule }

type RuleLoadConstAddr struct{ batchRule }

type RuleLoadSpacebase struct{ batchRule }

type RuleLoadSegment struct{ batchRule }

type RuleLoadPlaceholderClear struct{ batchRule }

type RuleStoreConstAddr struct{ batchRule }

type RuleStoreSpacebase struct{ batchRule }

type RuleStoreSegment struct{ batchRule }

type RuleStoreStackMark struct{ batchRule }

func NewRuleLoadVarnode(group string) *RuleLoadVarnode {
	r := &RuleLoadVarnode{}
	r.batchRule = newBatchRule(group, "loadvarnode", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleLoadVarnode(g) })
	return r
}

func NewRuleStoreVarnode(group string) *RuleStoreVarnode {
	r := &RuleStoreVarnode{}
	r.batchRule = newBatchRule(group, "storevarnode", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStoreVarnode(g) })
	return r
}

func NewRuleLoadConstAddr(group string) *RuleLoadConstAddr {
	r := &RuleLoadConstAddr{}
	r.batchRule = newBatchRule(group, "loadconstaddr", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleLoadConstAddr(g) })
	return r
}

func NewRuleLoadSpacebase(group string) *RuleLoadSpacebase {
	r := &RuleLoadSpacebase{}
	r.batchRule = newBatchRule(group, "loadspacebase", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleLoadSpacebase(g) })
	return r
}

func NewRuleLoadSegment(group string) *RuleLoadSegment {
	r := &RuleLoadSegment{}
	r.batchRule = newBatchRule(group, "loadsegment", []OpCode{CPUI_LOAD}, r.apply, func(g string) Rule { return NewRuleLoadSegment(g) })
	return r
}

func NewRuleLoadPlaceholderClear(group string) *RuleLoadPlaceholderClear {
	r := &RuleLoadPlaceholderClear{}
	r.batchRule = newBatchRule(group, "loadplaceholderclear", []OpCode{CPUI_COPY}, r.apply, func(g string) Rule { return NewRuleLoadPlaceholderClear(g) })
	return r
}

func NewRuleStoreConstAddr(group string) *RuleStoreConstAddr {
	r := &RuleStoreConstAddr{}
	r.batchRule = newBatchRule(group, "storeconstaddr", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStoreConstAddr(g) })
	return r
}

func NewRuleStoreSpacebase(group string) *RuleStoreSpacebase {
	r := &RuleStoreSpacebase{}
	r.batchRule = newBatchRule(group, "storespacebase", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStoreSpacebase(g) })
	return r
}

func NewRuleStoreSegment(group string) *RuleStoreSegment {
	r := &RuleStoreSegment{}
	r.batchRule = newBatchRule(group, "storesegment", []OpCode{CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStoreSegment(g) })
	return r
}

func NewRuleStoreStackMark(group string) *RuleStoreStackMark {
	r := &RuleStoreStackMark{}
	r.batchRule = newBatchRule(group, "storestackmark", []OpCode{CPUI_COPY}, r.apply, func(g string) Rule { return NewRuleStoreStackMark(g) })
	return r
}

func loadStoreSpace(op *PcodeOp) *address.Space {
	if op == nil || op.NumInput() == 0 || op.Input(0) == nil {
		return nil
	}
	return op.Input(0).GetSpaceFromConst()
}

func correctSpacebase(vn *Varnode, spc *address.Space) *address.Space {
	if vn == nil || !vn.IsSpaceBase() {
		return nil
	}
	if vn.IsConstant() {
		return spc
	}
	if !vn.IsInput() {
		return nil
	}
	return vn.AssociatedSpacebase()
}

func vnSpacebase(vn *Varnode, spc *address.Space) (*address.Space, uint64, bool) {
	if assoc := correctSpacebase(vn, spc); assoc != nil {
		return assoc, 0, true
	}
	if vn == nil || !vn.IsWritten() {
		return nil, 0, false
	}
	op := vn.Def()
	if op.Code() != CPUI_INT_ADD {
		return nil, 0, false
	}
	if assoc := correctSpacebase(op.Input(0), spc); assoc != nil && op.Input(1).IsConstant() {
		return assoc, op.Input(1).Offset(), true
	}
	if assoc := correctSpacebase(op.Input(1), spc); assoc != nil && op.Input(0).IsConstant() {
		return assoc, op.Input(0).Offset(), true
	}
	return nil, 0, false
}

func checkLoadStoreAddress(op *PcodeOp) (*address.Space, uint64, bool) {
	spc := loadStoreSpace(op)
	if spc == nil || op.NumInput() < 2 {
		return nil, 0, false
	}
	offVn := op.Input(1)
	if seg := definedBy(offVn, CPUI_SEGMENTOP); seg != nil && seg.NumInput() >= 3 {
		offVn = seg.Input(2)
	}
	if offVn.IsConstant() {
		return spc, offVn.Offset(), true
	}
	return vnSpacebase(offVn, spc)
}

func rewriteLoadToCopy(op *PcodeOp, data *Funcdata, spc *address.Space, off uint64) int {
	if op.Output() == nil {
		return 0
	}
	newvn := data.NewVarnode(op.Output().Size(), address.Address{Space: spc, Offset: off})
	// Do NOT seed a data-type on the new stack/const varnode. C++
	// RuleLoadVarnode::applyOp (ruleaction.cc:4310) creates it with
	// data.newVarnode(size,baseoff,offoff) and leaves the type undefined so that
	// ActionInferTypes assigns it later. Seeding the LOAD-output's already-
	// propagated type here caused ScopeLocal's restructure snapshot
	// (MapState::gatherVarnodes reading vn.Type()) to leak a speculative int/uint
	// into the stack Symbol instead of the pre-typeprop undefined that Ghidra
	// records (e.g. counted_loop local_c: undefined4 vs unsigned int).
	data.OpSetInput(op, newvn, 0)
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, CPUI_COPY)
	if op.Output().IsSpacebasePlaceholder() {
		op.Output().ClearSpacebasePlaceholder()
	}
	return 1
}

func rewriteStoreToCopy(op *PcodeOp, data *Funcdata, spc *address.Space, off uint64) int {
	if op.NumInput() < 3 {
		return 0
	}
	out := data.NewVarnodeOut(op.Input(2).Size(), address.Address{Space: spc, Offset: off}, op)
	// Do NOT seed a data-type on the new stack varnode. C++
	// RuleStoreVarnode::applyOp (ruleaction.cc:4352) uses data.newVarnodeOut(size,
	// addr, op) with no type; ActionInferTypes assigns it later. See the parity
	// note in rewriteLoadToCopy -- seeding the stored value's type here leaks a
	// speculative int/uint into the stack Symbol via the restructure snapshot.
	out.SetStackStore()
	data.OpRemoveInput(op, 1)
	data.OpRemoveInput(op, 0)
	data.OpSetOpcode(op, CPUI_COPY)
	return 1
}

func (r *RuleLoadVarnode) apply(op *PcodeOp, data *Funcdata) int {
	spc, off, ok := checkLoadStoreAddress(op)
	if !ok {
		return 0
	}
	return rewriteLoadToCopy(op, data, spc, off)
}

func (r *RuleStoreVarnode) apply(op *PcodeOp, data *Funcdata) int {
	spc, off, ok := checkLoadStoreAddress(op)
	if !ok {
		return 0
	}
	return rewriteStoreToCopy(op, data, spc, off)
}

func (r *RuleLoadConstAddr) apply(op *PcodeOp, data *Funcdata) int {
	spc := loadStoreSpace(op)
	if spc == nil || op.NumInput() < 2 || !op.Input(1).IsConstant() {
		return 0
	}
	return rewriteLoadToCopy(op, data, spc, op.Input(1).Offset())
}

func (r *RuleLoadSpacebase) apply(op *PcodeOp, data *Funcdata) int {
	spc := loadStoreSpace(op)
	assoc, off, ok := vnSpacebase(op.Input(1), spc)
	if !ok {
		return 0
	}
	return rewriteLoadToCopy(op, data, assoc, off)
}

func (r *RuleLoadSegment) apply(op *PcodeOp, data *Funcdata) int {
	seg := definedBy(op.Input(1), CPUI_SEGMENTOP)
	if seg == nil || seg.NumInput() < 3 {
		return 0
	}
	spc := loadStoreSpace(op)
	if spc == nil {
		return 0
	}
	if seg.Input(2).IsConstant() {
		return rewriteLoadToCopy(op, data, spc, seg.Input(2).Offset())
	}
	assoc, off, ok := vnSpacebase(seg.Input(2), spc)
	if !ok {
		return 0
	}
	return rewriteLoadToCopy(op, data, assoc, off)
}

func (r *RuleLoadPlaceholderClear) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil || !op.Output().IsSpacebasePlaceholder() {
		return 0
	}
	op.Output().ClearSpacebasePlaceholder()
	return 1
}

func (r *RuleStoreConstAddr) apply(op *PcodeOp, data *Funcdata) int {
	spc := loadStoreSpace(op)
	if spc == nil || op.NumInput() < 2 || !op.Input(1).IsConstant() {
		return 0
	}
	return rewriteStoreToCopy(op, data, spc, op.Input(1).Offset())
}

func (r *RuleStoreSpacebase) apply(op *PcodeOp, data *Funcdata) int {
	spc := loadStoreSpace(op)
	assoc, off, ok := vnSpacebase(op.Input(1), spc)
	if !ok {
		return 0
	}
	return rewriteStoreToCopy(op, data, assoc, off)
}

func (r *RuleStoreSegment) apply(op *PcodeOp, data *Funcdata) int {
	seg := definedBy(op.Input(1), CPUI_SEGMENTOP)
	if seg == nil || seg.NumInput() < 3 {
		return 0
	}
	spc := loadStoreSpace(op)
	if spc == nil {
		return 0
	}
	if seg.Input(2).IsConstant() {
		return rewriteStoreToCopy(op, data, spc, seg.Input(2).Offset())
	}
	assoc, off, ok := vnSpacebase(seg.Input(2), spc)
	if !ok {
		return 0
	}
	return rewriteStoreToCopy(op, data, assoc, off)
}

func (r *RuleStoreStackMark) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil || op.Output().IsStackStore() {
		return 0
	}
	if op.Output().Space() != nil && op.Output().Space().Kind == address.SpaceKindStack {
		op.Output().SetStackStore()
		return 1
	}
	return 0
}

func newLoadStoreRuleSet(group string) []Rule {
	return []Rule{
		NewRuleLoadVarnode(group),
		NewRuleStoreVarnode(group),
		NewRuleLoadConstAddr(group),
		NewRuleLoadSpacebase(group),
		NewRuleLoadSegment(group),
		NewRuleLoadPlaceholderClear(group),
		NewRuleStoreConstAddr(group),
		NewRuleStoreSpacebase(group),
		NewRuleStoreSegment(group),
		NewRuleStoreStackMark(group),
	}
}
