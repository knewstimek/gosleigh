package pcode

import "gosleigh/pkg/address"

type RulePtrArith struct{ batchRule }

type RulePtraddUndo struct{ batchRule }

type RulePtrsubUndo struct{ batchRule }

type RuleStructOffset0 struct{ batchRule }

type RuleSegment struct{ batchRule }

type RulePtrFlow struct{ batchRule }

type RulePtrsubCharConstant struct{ batchRule }

type RulePtraddZero struct{ batchRule }

type RulePtraddConstantIndex struct{ batchRule }

type RulePtrsubZero struct{ batchRule }

type RulePtrsubAddConst struct{ batchRule }

type RulePtrsubCollapse struct{ batchRule }

type RulePtrFlowCopy struct{ batchRule }

func NewRulePtrArith(group string) *RulePtrArith {
	r := &RulePtrArith{}
	r.batchRule = newBatchRule(group, "ptrarith", []OpCode{CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRulePtrArith(g) })
	return r
}

func NewRulePtraddUndo(group string) *RulePtraddUndo {
	r := &RulePtraddUndo{}
	r.batchRule = newBatchRule(group, "ptraddundo", []OpCode{CPUI_PTRADD}, r.apply, func(g string) Rule { return NewRulePtraddUndo(g) })
	return r
}

func NewRulePtrsubUndo(group string) *RulePtrsubUndo {
	r := &RulePtrsubUndo{}
	r.batchRule = newBatchRule(group, "ptrsubundo", []OpCode{CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePtrsubUndo(g) })
	return r
}

func NewRuleStructOffset0(group string) *RuleStructOffset0 {
	r := &RuleStructOffset0{}
	r.batchRule = newBatchRule(group, "structoffset0", []OpCode{CPUI_LOAD, CPUI_STORE}, r.apply, func(g string) Rule { return NewRuleStructOffset0(g) })
	return r
}

func NewRuleSegment(group string) *RuleSegment {
	r := &RuleSegment{}
	r.batchRule = newBatchRule(group, "segment", []OpCode{CPUI_SEGMENTOP}, r.apply, func(g string) Rule { return NewRuleSegment(g) })
	return r
}

// ptrFlowTruncationsEnabled reports whether the default data space uses a
// truncated pointer width (pspec truncate_space). C++ RulePtrFlow is a
// pointer-width-truncation rule: its getOpList early-returns with no opcodes when
// the default data space is not truncated (ruleaction.cc:9058-9068,
// hasTruncations), so on non-truncated architectures the rule is never registered
// in the op pool and never fires. All currently supported architectures
// (x86/x64/aarch64) leave the default data space non-truncated, so this is false.
// TODO: source this from the loaded architecture's default data space
// (AddrSpace::isTruncated) once truncate_space is wired through the pspec loader.
var ptrFlowTruncationsEnabled = false

func NewRulePtrFlow(group string) *RulePtrFlow {
	r := &RulePtrFlow{}
	r.batchRule = newBatchRule(group, "ptrflow", []OpCode{CPUI_LOAD, CPUI_STORE, CPUI_PTRSUB, CPUI_PTRADD}, r.apply, func(g string) Rule { return NewRulePtrFlow(g) })
	return r
}

// GetOpList registers RulePtrFlow only when the default data space is truncated,
// mirroring C++ RulePtrFlow::getOpList (ruleaction.cc:9065-9068: `if (!hasTruncations) return;`).
// On non-truncated architectures the rule is dormant -- it must NOT fire, because
// C++ never registers it. (The previous Gosleigh port fired it whenever a LOAD/STORE
// address became pointer-typed, which spuriously reported a data-flow change during
// type recovery and drove an extra mainloop pass, leaking propagated types into
// stack-local declarations.)
func (r *RulePtrFlow) GetOpList() []OpCode {
	if !ptrFlowTruncationsEnabled {
		return nil
	}
	// TODO: when a truncated architecture is supported, the fire body
	// (RulePtrFlow.apply) must be rewritten to the C++ pointer-width truncation
	// semantics (truncatePointer + propagateFlowToDef, ruleaction.cc:9179) over
	// the C++ opcode set [STORE,LOAD,COPY,MULTIEQUAL,INDIRECT,INT_ADD,...]. The
	// current apply body is a non-parity approximation retained only for the
	// direct-call unit test and is unreachable through the op pool.
	return append([]OpCode(nil), r.batchRule.opcodes...)
}

func NewRulePtrsubCharConstant(group string) *RulePtrsubCharConstant {
	r := &RulePtrsubCharConstant{}
	r.batchRule = newBatchRule(group, "ptrsubcharconstant", []OpCode{CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePtrsubCharConstant(g) })
	return r
}

func NewRulePtraddZero(group string) *RulePtraddZero {
	r := &RulePtraddZero{}
	r.batchRule = newBatchRule(group, "ptraddzero", []OpCode{CPUI_PTRADD}, r.apply, func(g string) Rule { return NewRulePtraddZero(g) })
	return r
}

func NewRulePtraddConstantIndex(group string) *RulePtraddConstantIndex {
	r := &RulePtraddConstantIndex{}
	r.batchRule = newBatchRule(group, "ptraddconstantindex", []OpCode{CPUI_PTRADD}, r.apply, func(g string) Rule { return NewRulePtraddConstantIndex(g) })
	return r
}

func NewRulePtrsubZero(group string) *RulePtrsubZero {
	r := &RulePtrsubZero{}
	r.batchRule = newBatchRule(group, "ptrsubzero", []OpCode{CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePtrsubZero(g) })
	return r
}

func NewRulePtrsubAddConst(group string) *RulePtrsubAddConst {
	r := &RulePtrsubAddConst{}
	r.batchRule = newBatchRule(group, "ptrsubaddconst", []OpCode{CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePtrsubAddConst(g) })
	return r
}

func NewRulePtrsubCollapse(group string) *RulePtrsubCollapse {
	r := &RulePtrsubCollapse{}
	r.batchRule = newBatchRule(group, "ptrsubcollapse", []OpCode{CPUI_PTRSUB}, r.apply, func(g string) Rule { return NewRulePtrsubCollapse(g) })
	return r
}

func NewRulePtrFlowCopy(group string) *RulePtrFlowCopy {
	r := &RulePtrFlowCopy{}
	r.batchRule = newBatchRule(group, "ptrflowcopy", []OpCode{CPUI_COPY}, r.apply, func(g string) Rule { return NewRulePtrFlowCopy(g) })
	return r
}

func ptrInputSlot(op *PcodeOp) int {
	for i := 0; i < op.NumInput(); i++ {
		dt := op.Input(i).TypeReadFacing(op)
		if dt != nil && dt.Metatype() == TYPE_PTR {
			return i
		}
	}
	return -1
}

func evaluatePointerExpression(op *PcodeOp, slot int) int {
	res := 1
	count := 0
	ptrBase := op.Input(slot)
	if ptrBase.IsFree() && !ptrBase.IsConstant() {
		return 0
	}
	otherType := op.Input(1 - slot).TypeReadFacing(op)
	if otherType != nil && otherType.Metatype() == TYPE_PTR {
		res = 2
	}
	out := op.Output()
	if out == nil {
		return 0
	}
	for _, desc := range out.DescendIter() {
		count++
		switch desc.Code() {
		case CPUI_INT_ADD:
			other := desc.Input(1 - desc.GetSlot(out))
			if other.IsFree() && !other.IsConstant() {
				return 0
			}
			if dt := other.TypeReadFacing(desc); dt != nil && dt.Metatype() == TYPE_PTR {
				res = 2
			}
		case CPUI_LOAD, CPUI_STORE:
			if desc.Input(1) != out {
				res = 2 // C++ falls into the catch-all else branch here
				break
			}
			// A spacebase register plus a constant feeding a LOAD/STORE address
			// is the stack-variable form handled by RuleLoadVarnode /
			// RuleStoreVarnode: neither push nor ptrarith it.
			// C++ parity: ruleaction.cc:6612-6614.
			if ptrBase.IsSpaceBase() && (ptrBase.IsInput() || ptrBase.IsConstant()) &&
				op.Input(1-slot).IsConstant() {
				return 0
			}
			res = 2
		default:
			res = 2
		}
	}
	if count == 0 {
		return 0
	}
	if count > 1 && out.IsSpaceBase() {
		return 0
	}
	return res
}

func verifyPreferredPointer(op *PcodeOp, slot int) bool {
	vn := op.Input(slot)
	if !vn.IsWritten() {
		return true
	}
	preOp := vn.Def()
	if preOp.Code() != CPUI_INT_ADD {
		return true
	}
	preSlot := ptrInputSlot(preOp)
	if preSlot < 0 {
		return true
	}
	return evaluatePointerExpression(preOp, preSlot) != 1
}

func pointerAlignSize(ptr *Pointer) int32 {
	if ptr == nil || ptr.Pointee() == nil {
		return 0
	}
	return ptr.Pointee().AlignSize()
}

// testForArraySlack reports whether an offset outside dt can still be
// absorbed by an array inside it (or dt itself being an array).
// C++ parity: TypePointer::testForArraySlack.
func testForArraySlack(dt Datatype, off int64) bool {
	if dt.Metatype() == TYPE_ARRAY {
		return true
	}
	if off < 0 {
		dist, _, _ := nearestArrayedComponentForward(dt, off, 128)
		return dist >= 0
	}
	dist, _, _ := nearestArrayedComponentBackward(dt, off, 128)
	return dist >= 0
}

// isPtrsubMatching reports whether a PTRSUB of offset off from a value of
// type dt (plus extra constant offset and a biggest multiplier from the rest
// of the additive expression) is a valid field access. A non-pointer is never
// matching. The spacebase case resolves symbols through the scope.
// C++ parity: Datatype/TypePointer/TypePointerRel::isPtrsubMatching.
func isPtrsubMatching(data *Funcdata, spc *address.Space, dt Datatype, off, extra, multiplier int64) bool {
	ptr, _ := dt.(*Pointer)
	if ptr == nil || ptr.Pointee() == nil {
		return false
	}
	ws := int64(ptr.WordSize())
	if ws <= 0 {
		ws = 1
	}
	if ptr.IsFormalPointerRel() { // TypePointerRel without a stripped form
		iOff := off*ws + int64(ptr.ByteOffset()) + extra*ws
		return iOff >= 0 && iOff <= int64(ptr.Parent().Size())
	}
	ptrto := ptr.Pointee()
	switch ptrto.Metatype() {
	case TYPE_SPACEBASE:
		return data.spacebasePtrsubMatching(spc, ptr, off, extra)
	case TYPE_ARRAY:
		if off != 0 {
			return false
		}
		if multiplier*ws >= int64(ptrto.AlignSize()) {
			return false
		}
	case TYPE_STRUCT:
		typesize := int64(ptrto.Size())
		if multiplier*ws >= int64(ptrto.AlignSize()) {
			return false
		}
		extra *= ws
		subType, newoff := datatypeSubType(ptrto, off*ws)
		if subType != nil {
			if newoff != 0 {
				return false
			}
			if extra < 0 || extra >= int64(subType.Size()) {
				if !testForArraySlack(subType, extra) {
					return false
				}
			}
		} else {
			extra += newoff
			if (extra < 0 || extra >= typesize) && typesize != 0 {
				return false
			}
		}
	default: // including TYPE_UNION: never resolved through a PTRSUB here
		return false
	}
	return true
}

// getConstOffsetBack sums the constants of an additive expression and passes
// back the biggest multiplicative coefficient in it.
// C++ parity: RulePtrsubUndo::getConstOffsetBack.
func getConstOffsetBack(vn *Varnode, maxLevel int) (int64, int64) {
	if vn.IsConstant() {
		return int64(vn.Offset()), 0
	}
	if !vn.IsWritten() {
		return 0, 0
	}
	maxLevel--
	if maxLevel < 0 {
		return 0, 0
	}
	op := vn.Def()
	var retval, multiplier int64
	switch op.Code() {
	case CPUI_INT_ADD:
		for slot := 0; slot < 2; slot++ {
			val, sub := getConstOffsetBack(op.Input(slot), maxLevel)
			retval += val
			if sub > multiplier {
				multiplier = sub
			}
		}
	case CPUI_INT_MULT:
		cvn := op.Input(1)
		if !cvn.IsConstant() {
			return 0, 0
		}
		multiplier = int64(cvn.Offset())
		if _, sub := getConstOffsetBack(op.Input(0), maxLevel); sub > 0 {
			multiplier *= sub // Only contribute to the multiplier
		}
	}
	return retval, multiplier
}

// ptrsubUndoDepthLimit is RulePtrsubUndo::DEPTH_LIMIT.
const ptrsubUndoDepthLimit = 8

// getExtraOffset walks the additive expression (INT_ADD, PTRADD, PTRSUB) fed
// by a PTRSUB and returns the extra constant it adds plus the biggest
// multiplier of any term.
// C++ parity: RulePtrsubUndo::getExtraOffset.
func getExtraOffset(op *PcodeOp) (int64, int64) {
	var extra, multiplier int64
	outvn := op.Output()
	cur := outvn.LoneDescend()
loop:
	for cur != nil {
		switch cur.Code() {
		case CPUI_INT_ADD:
			slot := cur.GetSlot(outvn)
			val, sub := getConstOffsetBack(cur.Input(1-slot), ptrsubUndoDepthLimit) // Constants from the other input
			extra += val
			if sub > multiplier {
				multiplier = sub
			}
		case CPUI_PTRSUB:
			extra += int64(cur.Input(1).Offset())
		case CPUI_PTRADD:
			if cur.Input(0) != outvn {
				break loop
			}
			ptraddmult := int64(cur.Input(2).Offset())
			invn := cur.Input(1)
			if invn.IsConstant() { // Only contribute to the extra if the index is constant
				extra += ptraddmult * int64(invn.Offset())
			}
			if _, sub := getConstOffsetBack(invn, ptrsubUndoDepthLimit); sub != 0 {
				ptraddmult *= sub // otherwise just contribute to the multiplier
			}
			if ptraddmult > multiplier {
				multiplier = ptraddmult
			}
		default:
			break loop
		}
		outvn = cur.Output()
		cur = outvn.LoneDescend()
	}
	return signExtendToInt64(uint64(extra), outvn.Size()), multiplier
}

func removeLocalAddRecurse(op *PcodeOp, slot int, maxLevel int, data *Funcdata) int64 {
	if op == nil || maxLevel <= 0 {
		return 0
	}
	vn := op.Input(slot)
	if !vn.IsWritten() || vn.LoneDescend() != op {
		return 0
	}
	def := vn.Def()
	if def.Code() != CPUI_INT_ADD {
		return 0
	}
	if def.Input(1).IsConstant() {
		val := signExtendToInt64(def.Input(1).Offset(), def.Input(1).Size())
		data.OpRemoveInput(def, 1)
		data.OpSetOpcode(def, CPUI_COPY)
		return val
	}
	return removeLocalAddRecurse(def, 0, maxLevel-1, data) + removeLocalAddRecurse(def, 1, maxLevel-1, data)
}

func removeLocalAdds(vn *Varnode, data *Funcdata) int64 {
	extra := int64(0)
	for op := vn.LoneDescend(); op != nil; op = vn.LoneDescend() {
		switch op.Code() {
		case CPUI_INT_ADD:
			slot := op.GetSlot(vn)
			if slot == 0 && op.Input(1).IsConstant() {
				extra += signExtendToInt64(op.Input(1).Offset(), op.Input(1).Size())
				data.OpRemoveInput(op, 1)
				data.OpSetOpcode(op, CPUI_COPY)
			} else {
				extra += removeLocalAddRecurse(op, 1-slot, 8, data)
			}
		case CPUI_PTRSUB:
			extra += signExtendToInt64(op.Input(1).Offset(), op.Input(1).Size())
			op.ClearStopTypePropagation()
			data.OpRemoveInput(op, 1)
			data.OpSetOpcode(op, CPUI_COPY)
		case CPUI_PTRADD:
			if op.Input(0) != vn {
				return extra
			}
			scale := signExtendToInt64(op.Input(2).Offset(), op.Input(2).Size())
			if op.Input(1).IsConstant() {
				extra += scale * signExtendToInt64(op.Input(1).Offset(), op.Input(1).Size())
				data.OpRemoveInput(op, 2)
				data.OpRemoveInput(op, 1)
				data.OpSetOpcode(op, CPUI_COPY)
			} else {
				data.OpUndoPtradd(op, false)
				extra += removeLocalAddRecurse(op, 1, 8, data)
			}
		default:
			return extra
		}
		vn = op.Output()
		if vn == nil {
			break
		}
	}
	return extra
}

func maxWordSize(wordSize uint32) uint32 {
	if wordSize == 0 {
		return 1
	}
	return wordSize
}

func markPointerFlow(op *PcodeOp) bool {
	if op == nil {
		return false
	}
	changed := false
	if !op.HasPtrFlow() {
		op.SetPtrFlow()
		changed = true
	}
	for i := 0; i < op.NumInput(); i++ {
		vn := op.Input(i)
		if vn != nil && !vn.HasPtrFlow() {
			vn.SetPtrFlow()
			changed = true
		}
	}
	if out := op.Output(); out != nil && !out.HasPtrFlow() {
		out.SetPtrFlow()
		changed = true
	}
	return changed
}

// RulePushPtr pushes a Varnode with known pointer data-type to the bottom of
// its additive expression: the pointer must be added last, onto the expression
// computing the offset into its data-type. Without it a two-level address
// computation like (spacebase + const) + (index * scale) never presents the
// pointer to RulePtrArith on the outer INT_ADD -- verifyPreferredPointer sees
// the inner add as the preferred pointer expression and declines -- so no
// PTRSUB/PTRADD is ever built for stack array accesses.
//
// C++ parity: ruleaction.cc RulePushPtr::applyOp (L6865-6915),
// ::buildVarnodeOut (L6785), ::collectDuplicateNeeds (L6800), ::duplicateNeed
// (L6829).
type RulePushPtr struct{ batchRule }

func NewRulePushPtr(group string) *RulePushPtr {
	r := &RulePushPtr{}
	r.batchRule = newBatchRule(group, "pushptr", []OpCode{CPUI_INT_ADD}, r.apply, func(g string) Rule { return NewRulePushPtr(g) })
	return r
}

// pushPtrBuildVarnodeOut keeps the duplicated result in the original storage
// when that storage can hold a second definition; address-tied and unique
// Varnodes get a fresh unique instead.
// C++ parity: RulePushPtr::buildVarnodeOut (ruleaction.cc:6785).
func pushPtrBuildVarnodeOut(vn *Varnode, op *PcodeOp, data *Funcdata) *Varnode {
	if vn.IsAddrTied() || (vn.Space() != nil && vn.Space().IsUnique()) {
		return data.NewUniqueOut(vn.Size(), op)
	}
	return data.NewVarnodeOut(vn.Size(), vn.Addr(), op)
}

// pushPtrCollectDuplicateNeeds walks the offset expression feeding the pointer
// add and lists the single-descendant extension/scale ops that must be
// duplicated once the add itself is duplicated across several descendants.
// C++ parity: RulePushPtr::collectDuplicateNeeds (ruleaction.cc:6800).
func pushPtrCollectDuplicateNeeds(reslist []*PcodeOp, vn *Varnode) []*PcodeOp {
	for {
		if vn == nil || !vn.IsWritten() {
			return reslist
		}
		if vn.IsAutoLive() {
			return reslist
		}
		if vn.LoneDescend() == nil {
			return reslist // Already has multiple descendants
		}
		op := vn.Def()
		if op == nil {
			return reslist
		}
		switch op.Code() {
		case CPUI_INT_ZEXT, CPUI_INT_SEXT, CPUI_INT_2COMP:
			reslist = append(reslist, op)
		case CPUI_INT_MULT:
			// C++ only records the op when the scale is constant, but keeps
			// walking either way (ruleaction.cc:6811-6814).
			if op.NumInput() > 1 && op.Input(1) != nil && op.Input(1).IsConstant() {
				reslist = append(reslist, op)
			}
		default:
			return reslist
		}
		vn = op.Input(0)
	}
}

// pushPtrDuplicateNeed replaces op with one copy per descendant so each
// duplicated pointer add gets its own offset computation. The original op is
// destroyed.
// C++ parity: RulePushPtr::duplicateNeed (ruleaction.cc:6829).
func pushPtrDuplicateNeed(op *PcodeOp, data *Funcdata) {
	outVn := op.Output()
	if outVn == nil {
		return
	}
	inVn := op.Input(0)
	num := op.NumInput()
	opc := op.Code()
	for {
		descend := outVn.DescendIter()
		if len(descend) == 0 {
			break
		}
		decOp := descend[0]
		slot := decOp.GetSlot(outVn)
		if slot < 0 {
			break
		}
		newOp := data.NewOp(num, op.Addr())
		newOut := pushPtrBuildVarnodeOut(outVn, newOp, data)
		newOut.UpdateType(outVn.Type())
		data.OpSetOpcode(newOp, opc)
		data.OpSetInput(newOp, inVn, 0)
		if num > 1 {
			data.OpSetInput(newOp, op.Input(1), 1)
		}
		data.OpSetInput(decOp, newOut, slot)
		data.OpInsertBefore(newOp, decOp)
	}
	data.OpDestroy(op)
}

func (r *RulePushPtr) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() {
		return 0
	}
	slot := ptrInputSlot(op)
	if slot < 0 {
		return 0
	}
	if evaluatePointerExpression(op, slot) != 1 {
		return 0
	}
	vni := op.Input(slot)
	vn := op.Output()
	if vn == nil {
		return 0
	}
	vnadd2 := op.Input(1 - slot)
	var duplicateList []*PcodeOp
	if vn.LoneDescend() == nil {
		duplicateList = pushPtrCollectDuplicateNeeds(duplicateList, vnadd2)
	}

	for {
		descend := vn.DescendIter()
		if len(descend) == 0 {
			break
		}
		decop := descend[0]
		j := decop.GetSlot(vn)
		if j < 0 {
			break
		}
		vnadd1 := decop.Input(1 - j)
		if vnadd1 == nil {
			break
		}
		// Create a new INT_ADD for the intermediate result that did not exist in
		// the original code. It is not associated with the original INT_ADD's
		// address, and it does not preserve the original output storage.
		newop := data.NewOp(2, decop.Addr()) // Use the later address
		data.OpSetOpcode(newop, CPUI_INT_ADD)
		newout := data.NewUniqueOut(vnadd1.Size(), newop) // Temporary storage

		data.OpSetInput(decop, vni, 0)
		data.OpSetInput(decop, newout, 1)

		data.OpSetInput(newop, vnadd1, 0)
		data.OpSetInput(newop, vnadd2, 1)

		data.OpInsertBefore(newop, decop)
	}
	if !vn.IsAutoLive() {
		data.OpDestroy(op)
	}
	for _, dup := range duplicateList {
		pushPtrDuplicateNeed(dup, data)
	}
	return 1
}

func (r *RulePtrArith) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() {
		return 0
	}
	slot := ptrInputSlot(op)
	if slot < 0 {
		return 0
	}
	if evaluatePointerExpression(op, slot) != 2 {
		return 0
	}
	if !verifyPreferredPointer(op, slot) {
		return 0
	}
	state := NewAddTreeState(data, op, slot)
	if state.Apply() {
		return 1
	}
	if state.initAlternateForm() && state.Apply() {
		return 1
	}
	return 0
}

func (r *RulePtraddUndo) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() || op.NumInput() < 3 {
		return 0
	}
	ptr, _ := op.Input(0).TypeReadFacing(op).(*Pointer)
	size := int32(op.Input(2).Offset())
	if ptr != nil && pointerAlignSize(ptr) == addressUnitsToBytes(uint64(size), ptr.WordSize()) {
		if !op.Input(1).IsConstant() || op.Input(1).Offset() != 0 {
			return 0
		}
	}
	data.OpUndoPtradd(op, false)
	return 1
}

func (r *RulePtrsubUndo) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() {
		return 0
	}
	basevn := op.Input(0)
	cvn := op.Input(1)
	val := int64(cvn.Offset())
	extra, multiplier := getExtraOffset(op)
	if isPtrsubMatching(data, basevn.GetSpaceFromConst(), basevn.TypeReadFacing(op), val, extra, multiplier) {
		return 0
	}
	data.OpSetOpcode(op, CPUI_INT_ADD)
	op.ClearStopTypePropagation()
	if extra = removeLocalAdds(op.Output(), data); extra != 0 {
		val += extra // Lump extra into additive offset
		data.OpSetInput(op, data.NewConstant(cvn.Size(), truncateToSize(uint64(val), cvn.Size())), 1)
	}
	return 1
}

// apply makes a LOAD/STORE through a pointer to a structure (or array) read
// its first field (element) explicitly: ptr becomes PTRSUB(ptr, 0). A formal
// relative pointer into a structure gets a PTRSUB back to the field holding
// its offset. The new PTRSUB output keeps the default type
// (Funcdata::newOpBefore); typing it here made RulePtrArith/RulePtrsubUndo
// cycle with this rule.
// C++ parity: RuleStructOffset0::applyOp.
func (r *RuleStructOffset0) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() {
		return 0
	}
	var movesize int32
	switch op.Code() {
	case CPUI_LOAD:
		movesize = op.Output().Size()
	case CPUI_STORE:
		movesize = op.Input(2).Size()
	default:
		return 0
	}
	ptrVn := op.Input(1)
	ptr, _ := ptrVn.TypeReadFacing(op).(*Pointer)
	if ptr == nil || ptr.Pointee() == nil {
		return 0
	}
	baseType := ptr.Pointee()
	if ptr.IsFormalPointerRel() && ptr.EvaluateThruParent(0) {
		baseType = ptr.Parent()
		if baseType.Metatype() != TYPE_STRUCT {
			return 0
		}
		offset := int64(ptr.ByteOffset())
		if offset >= int64(baseType.Size()) {
			return 0
		}
		if baseType.Size() < movesize {
			return 0 // Moving something bigger than the entire structure
		}
		subType, newoff := datatypeSubType(baseType, offset) // Field at the pointer's offset
		if subType == nil || subType.Size() < movesize {
			return 0 // The field is too small for the LOAD/STORE
		}
		ws := int64(ptr.WordSize())
		if ws <= 0 {
			ws = 1
		}
		newoff /= ws // byteToAddress
		// Create a pointer up to the parent
		newop := data.newUntypedOpBefore(op, CPUI_PTRSUB, ptrVn.Size(), ptrVn,
			data.NewConstant(ptrVn.Size(), uint64(-newoff)&maskForSize(ptrVn.Size())))
		newop.SetStopTypePropagation()
		if newoff != 0 {
			// Add newoff back in to get to zero total offset
			addop := data.newUntypedOpBefore(op, CPUI_INT_ADD, ptrVn.Size(), newop.Output(),
				data.NewConstant(ptrVn.Size(), uint64(newoff)))
			data.OpSetInput(op, addop.Output(), 1)
		} else {
			data.OpSetInput(op, newop.Output(), 1)
		}
		return 1
	}
	switch baseType.Metatype() {
	case TYPE_STRUCT:
		if baseType.Size() < movesize {
			return 0 // Moving something bigger than the entire structure
		}
		subType, _ := datatypeSubType(baseType, 0)
		if subType == nil || subType.Size() < movesize {
			return 0 // The field is too small for the LOAD/STORE
		}
	case TYPE_ARRAY:
		if baseType.Size() < movesize {
			return 0 // Moving something bigger than the entire array
		}
		arr, _ := baseType.(*Array)
		if arr == nil {
			return 0
		}
		if baseType.Size() == movesize && arr.Count() != 1 {
			return 0
		}
	default:
		return 0
	}
	newop := data.newUntypedOpBefore(op, CPUI_PTRSUB, ptrVn.Size(), ptrVn, data.NewConstant(ptrVn.Size(), 0))
	newop.SetStopTypePropagation()
	data.OpSetInput(op, newop.Output(), 1)
	return 1
}

func (r *RuleSegment) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 3 {
		return 0
	}
	spc := op.Input(0).GetSpaceFromConst()
	base, bok := constantValue(op.Input(1))
	off, ook := constantValue(op.Input(2))
	if spc == nil || !bok || !ook {
		return 0
	}
	constVn := data.NewConstant(op.Input(1).Size(), truncateToSize(base+off, op.Input(1).Size()))
	BindSpaceConstant(constVn, spc)
	return rewriteToCopy(data, op, constVn)
}

func (r *RulePtrFlow) apply(op *PcodeOp, data *Funcdata) int {
	switch op.Code() {
	case CPUI_LOAD, CPUI_STORE:
		if op.NumInput() > 1 && ptrInputSlotOnInput(op, 1) {
			if markPointerFlow(op) {
				return 1
			}
		}
	case CPUI_PTRSUB, CPUI_PTRADD:
		if markPointerFlow(op) {
			return 1
		}
	}
	return 0
}

func ptrInputSlotOnInput(op *PcodeOp, slot int) bool {
	if slot < 0 || slot >= op.NumInput() {
		return false
	}
	dt := op.Input(slot).TypeReadFacing(op)
	return dt != nil && dt.Metatype() == TYPE_PTR
}

func (r *RulePtrsubCharConstant) apply(op *PcodeOp, data *Funcdata) int {
	// C++ parity: RulePtrsubCharConstant::applyOp (ruleaction.cc L7374-7422).
	if op.NumInput() < 2 {
		return 0
	}
	// Input 0 must be a pointer to a spacebase.
	sbPtr, ok := op.Input(0).TypeReadFacing(op).(*Pointer)
	if !ok || sbPtr.Pointee() == nil || sbPtr.Pointee().Metatype() != TYPE_SPACEBASE {
		return 0
	}
	if !op.Input(1).IsConstant() {
		return 0
	}
	// The PTRSUB output must be a pointer to a char-printable type. This guard
	// (C++: outtype->getPtrTo()->isCharPrint(), L7386-7389) is what keeps a
	// non-string spacebase reference -- e.g. &__ImageBase, a pointer to
	// undefined1 -- from being collapsed to a bare constant here. Without it a
	// legitimate &symbol form is lost.
	outPtr, ok := op.Output().TypeDefFacing().(*Pointer)
	if !ok || outPtr.Pointee() == nil || !isCharPrintLike(outPtr.Pointee()) {
		return 0
	}
	base := op.Input(0).Offset()
	off := op.Input(1).Offset()
	// With a load image the C++ gates apply: the target is read-only and
	// holds a string (Scope::isReadOnly + StringManager::isString).
	// TODO known mismatch: without an image the gates are skipped.
	if data.ImageReader() != nil {
		if sp := op.Input(0).GetSpaceFromConst(); sp != nil {
			at := address.Address{Space: sp, Offset: truncateToSize(base+off, op.Input(0).Size())}
			if !data.isReadOnlyGlobal(at) {
				return 0
			}
			if _, _, ok := data.stringDataSized(at, int(outPtr.Pointee().Size())); !ok {
				return 0
			}
		}
	}
	val := truncateToSize(base+off, op.Input(0).Size())
	spc := op.Input(0).GetSpaceFromConst()
	// Give each descendant a chance to absorb the constant (a PTRADD of a
	// constant index); the PTRSUB goes away when all of them do.
	outvn := op.Output()
	removeCopy := false
	if !outvn.IsAddrForce() {
		removeCopy = true
		for _, subop := range outvn.DescendIter() {
			if !ptrsubCharPushFurther(data, outPtr, spc, subop, subop.GetSlot(outvn), val) {
				removeCopy = false
			}
		}
	}
	if removeCopy {
		data.OpDestroy(op)
		return 1
	}
	constant := data.NewConstant(op.Input(0).Size(), val)
	BindSpaceConstant(constant, spc)
	SetVarnodeType(constant, outPtr)
	return rewriteToCopy(data, op, constant)
}

// ptrsubCharPushFurther folds a PTRADD of a constant index on the string
// pointer into a constant pointer of its own.
// C++ parity: RulePtrsubCharConstant::pushConstFurther.
func ptrsubCharPushFurther(data *Funcdata, outtype *Pointer, spc *address.Space, op *PcodeOp, slot int, val uint64) bool {
	if op.Code() != CPUI_PTRADD || slot != 0 {
		return false
	}
	vn := op.Input(1)
	if !vn.IsConstant() {
		return false // Must be adding a constant
	}
	val += vn.Offset() * op.Input(2).Offset()
	newconst := data.NewConstant(vn.Size(), truncateToSize(val, vn.Size()))
	BindSpaceConstant(newconst, spc)
	SetVarnodeType(newconst, outtype) // The pointer data-type goes on the new constant
	data.OpRemoveInput(op, 2)
	data.OpRemoveInput(op, 1)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpSetInput(op, newconst, 0)
	return true
}

func (r *RulePtraddZero) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 3 || !isZeroConst(op.Input(1)) {
		return 0
	}
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return rewriteToCopy(data, op, op.Input(0))
}

func (r *RulePtraddConstantIndex) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 3 {
		return 0
	}
	scale, sok := constantValue(op.Input(2))
	idx, iok := constantValue(op.Input(1))
	if !sok || !iok || scale != 1 || idx == 0 {
		return 0
	}
	rewriteOp(data, op, CPUI_PTRSUB, op.Input(0), data.NewConstant(op.Input(0).Size(), idx))
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return 1
}

func (r *RulePtrsubZero) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() < 2 || !isZeroConst(op.Input(1)) {
		return 0
	}
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return rewriteToCopy(data, op, op.Input(0))
}

func (r *RulePtrsubAddConst) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil {
		return 0
	}
	desc := op.Output().LoneDescend()
	if desc == nil || desc.Code() != CPUI_INT_ADD {
		return 0
	}
	slot := desc.GetSlot(op.Output())
	other := desc.Input(1 - slot)
	val, ok := constantValue(other)
	if !ok {
		return 0
	}
	root := signExtendToInt64(op.Input(1).Offset(), op.Input(1).Size())
	root += signExtendToInt64(val, other.Size())
	data.OpSetInput(op, data.NewConstant(op.Input(1).Size(), truncateToSize(uint64(root), op.Input(1).Size())), 1)
	rewriteToCopy(data, desc, op.Output())
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return 1
}

func (r *RulePtrsubCollapse) apply(op *PcodeOp, data *Funcdata) int {
	baseDef := definedBy(op.Input(0), CPUI_PTRSUB)
	if baseDef == nil || !op.Input(1).IsConstant() || !baseDef.Input(1).IsConstant() {
		return 0
	}
	combined := truncateToSize(baseDef.Input(1).Offset()+op.Input(1).Offset(), op.Input(1).Size())
	rewriteOp(data, op, CPUI_PTRSUB, baseDef.Input(0), data.NewConstant(op.Input(1).Size(), combined))
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return 1
}

func (r *RulePtrFlowCopy) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() == 0 || op.Input(0) == nil {
		return 0
	}
	if op.Input(0).HasPtrFlow() || (op.Output() != nil && op.Output().TypeReadFacing(op) != nil && op.Output().TypeReadFacing(op).Metatype() == TYPE_PTR) {
		if markPointerFlow(op) {
			return 1
		}
	}
	return 0
}

