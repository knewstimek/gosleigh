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
			if desc.Input(1) == out {
				res = 2
			}
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

func ptrsubMatches(ptr *Pointer, val int64, extra int64, multiplier int64) bool {
	if ptr == nil || ptr.Pointee() == nil {
		return false
	}
	totalBytes := int32((val + extra) * int64(maxWordSize(ptr.WordSize())))
	base := ptr.Pointee()
	switch base.Metatype() {
	case TYPE_STRUCT:
		if totalBytes == 0 {
			return true
		}
		_, _, ok := matchSubtype(base, totalBytes, uint64(multiplier))
		return ok
	case TYPE_ARRAY:
		arr, ok := base.(*Array)
		if !ok || arr.Element() == nil || arr.Element().AlignSize() <= 0 {
			return false
		}
		return totalBytes >= 0 && totalBytes < arr.Size() && totalBytes%arr.Element().AlignSize() == 0
	default:
		return totalBytes == 0
	}
}

func getConstOffsetBack(vn *Varnode, maxLevel int) (int64, int64) {
	if vn == nil {
		return 0, 0
	}
	if vn.IsConstant() {
		return signExtendToInt64(vn.Offset(), vn.Size()), 0
	}
	if !vn.IsWritten() || maxLevel <= 0 {
		return 0, 0
	}
	op := vn.Def()
	switch op.Code() {
	case CPUI_INT_ADD:
		a, ma := getConstOffsetBack(op.Input(0), maxLevel-1)
		b, mb := getConstOffsetBack(op.Input(1), maxLevel-1)
		if mb > ma {
			ma = mb
		}
		return a + b, ma
	case CPUI_INT_MULT:
		constSlot := -1
		if op.Input(0).IsConstant() {
			constSlot = 0
		} else if op.Input(1).IsConstant() {
			constSlot = 1
		}
		if constSlot < 0 {
			return 0, 0
		}
		mult := signExtendToInt64(op.Input(constSlot).Offset(), op.Input(constSlot).Size())
		_, submult := getConstOffsetBack(op.Input(1-constSlot), maxLevel-1)
		if submult != 0 {
			mult *= submult
		}
		return 0, mult
	}
	return 0, 0
}

func getExtraOffset(op *PcodeOp) (int64, int64) {
	extra := int64(0)
	multiplier := int64(0)
	if op == nil || op.Output() == nil {
		return 0, 0
	}
	out := op.Output()
	for desc := out.LoneDescend(); desc != nil; desc = out.LoneDescend() {
		switch desc.Code() {
		case CPUI_INT_ADD:
			slot := desc.GetSlot(out)
			add, mult := getConstOffsetBack(desc.Input(1-slot), 8)
			extra += add
			if mult > multiplier {
				multiplier = mult
			}
		case CPUI_PTRSUB:
			extra += signExtendToInt64(desc.Input(1).Offset(), desc.Input(1).Size())
		case CPUI_PTRADD:
			if desc.Input(0) != out {
				return extra, multiplier
			}
			scale := signExtendToInt64(desc.Input(2).Offset(), desc.Input(2).Size())
			idx := desc.Input(1)
			if idx.IsConstant() {
				extra += scale * signExtendToInt64(idx.Offset(), idx.Size())
			} else {
				_, mult := getConstOffsetBack(idx, 8)
				if mult != 0 {
					scale *= mult
				}
				if scale > multiplier {
					multiplier = scale
				}
			}
		default:
			return extra, multiplier
		}
		out = desc.Output()
		if out == nil {
			break
		}
	}
	return extra, multiplier
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
	if !data.HasTypeRecoveryStarted() || op.NumInput() < 2 {
		return 0
	}
	ptr, _ := op.Input(0).TypeReadFacing(op).(*Pointer)
	if ptr == nil {
		return 0
	}
	val := signExtendToInt64(op.Input(1).Offset(), op.Input(1).Size())
	extra, multiplier := getExtraOffset(op)
	// A spacebase pointer resolves its subtype through the symbol table rather
	// than a structural sub-field walk, so it needs the scope-aware check.
	// C++ parity: TypePointer::isPtrsubMatching TYPE_SPACEBASE branch.
	if ptr.Pointee() != nil && ptr.Pointee().Metatype() == TYPE_SPACEBASE {
		if data.spacebasePtrsubMatching(op.Input(0).GetSpaceFromConst(), ptr, val, extra) {
			return 0
		}
	} else if ptrsubMatches(ptr, val, extra, multiplier) {
		return 0
	}
	data.OpSetOpcode(op, CPUI_INT_ADD)
	op.ClearStopTypePropagation()
	removed := int64(0)
	if out := op.Output(); out != nil {
		removed = removeLocalAdds(out, data)
	}
	total := val + removed
	data.OpSetInput(op, data.NewConstant(op.Input(1).Size(), truncateToSize(uint64(total), op.Input(1).Size())), 1)
	SetVarnodeType(op.Output(), op.Input(0).TypeReadFacing(op))
	return 1
}

func (r *RuleStructOffset0) apply(op *PcodeOp, data *Funcdata) int {
	if !data.HasTypeRecoveryStarted() || op.NumInput() < 2 {
		return 0
	}
	moveSize := int32(0)
	switch op.Code() {
	case CPUI_LOAD:
		if op.Output() == nil {
			return 0
		}
		moveSize = op.Output().Size()
	case CPUI_STORE:
		if op.NumInput() < 3 {
			return 0
		}
		moveSize = op.Input(2).Size()
	default:
		return 0
	}
	ptrVn := op.Input(1)
	ptr, _ := ptrVn.TypeReadFacing(op).(*Pointer)
	if ptr == nil {
		return 0
	}
	st, ok := ptr.Pointee().(*Struct)
	if !ok {
		return 0
	}
	fields := st.Fields()
	if len(fields) == 0 || fields[0].Offset != 0 || fields[0].Type == nil || fields[0].Type.Size() < moveSize {
		return 0
	}
	subType := pointerSubtypeType(ptr, fields[0].Type)
	newop := data.NewTypedOpBefore(op, CPUI_PTRSUB, ptrVn.Size(), subType, ptrVn, data.NewConstant(ptrVn.Size(), 0))
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
	// C++ additionally requires the symbol data to sit in a read-only region and
	// to look like a string (Scope::isReadOnly + StringManager::isString). Those
	// facilities are not modelled here yet; the char-print guard above already
	// prevents the &__ImageBase regression, and only genuine char-pointer
	// spacebase references reach this point.
	// TODO known mismatch: read-only + isString gating (ruleaction.cc L7390-7396).
	base := op.Input(0).Offset()
	off := op.Input(1).Offset()
	constant := data.NewConstant(op.Input(0).Size(), truncateToSize(base+off, op.Input(0).Size()))
	BindSpaceConstant(constant, op.Input(0).GetSpaceFromConst())
	SetVarnodeType(constant, outPtr)
	return rewriteToCopy(data, op, constant)
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

func newPointerRuleSet(group string) []Rule {
	return []Rule{
		NewRulePtrArith(group),
		NewRulePtraddUndo(group),
		NewRulePtrsubUndo(group),
		NewRuleStructOffset0(group),
		NewRuleSegment(group),
		NewRulePtrFlow(group),
		NewRulePtrsubCharConstant(group),
		NewRulePtraddZero(group),
		NewRulePtraddConstantIndex(group),
		NewRulePtrsubZero(group),
		NewRulePtrsubAddConst(group),
		NewRulePtrsubCollapse(group),
		NewRulePtrFlowCopy(group),
	}
}

func bindAbsolutePointer(vn *Varnode, spc *address.Space, ptr *Pointer) {
	BindSpaceConstant(vn, spc)
	SetVarnodeType(vn, ptr)
}
