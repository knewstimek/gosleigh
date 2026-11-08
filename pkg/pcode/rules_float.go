package pcode

import "github.com/knewstimek/gosleigh/pkg/address"

type RuleFloatCast struct{ batchRule }

func NewRuleFloatCast(group string) *RuleFloatCast {
	r := &RuleFloatCast{}
	r.batchRule = newBatchRule(group, "floatcast", []OpCode{CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC}, r.apply, func(g string) Rule {
		return NewRuleFloatCast(g)
	})
	return r
}

func (r *RuleFloatCast) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 1 {
		return 0
	}
	castOp := op.Input(0).Def()
	if castOp == nil {
		return 0
	}
	opc2 := castOp.Code()
	if opc2 != CPUI_FLOAT_FLOAT2FLOAT && opc2 != CPUI_FLOAT_INT2FLOAT {
		return 0
	}
	vn2 := castOp.Input(0)
	if vn2.IsFree() {
		return 0
	}
	insize1 := op.Input(0).Size()
	insize2 := vn2.Size()
	outsize := outputSize(op)
	switch {
	case opc2 == CPUI_FLOAT_FLOAT2FLOAT && op.Code() == CPUI_FLOAT_FLOAT2FLOAT:
		if insize1 > outsize {
			data.OpSetInput(op, vn2, 0)
			if outsize == insize2 {
				data.OpSetOpcode(op, CPUI_COPY)
			}
			return 1
		}
		if insize2 < insize1 {
			data.OpSetInput(op, vn2, 0)
			return 1
		}
	case opc2 == CPUI_FLOAT_INT2FLOAT && op.Code() == CPUI_FLOAT_FLOAT2FLOAT:
		data.OpSetInput(op, vn2, 0)
		data.OpSetOpcode(op, CPUI_FLOAT_INT2FLOAT)
		return 1
	case opc2 == CPUI_FLOAT_FLOAT2FLOAT && op.Code() == CPUI_FLOAT_TRUNC:
		data.OpSetInput(op, vn2, 0)
		return 1
	}
	return 0
}

// NaNIgnore is Ghidra's "nanignore" decompiler option: which NaN tests the
// decompiler drops, assuming float inputs are not NaN. Dropping them reads
// better but changes what a comparison means for NaN (comiss/jnbe and minss
// print with the NaN case taken the other way).
// C++ parity: OptionNanIgnore (Architecture::nan_ignore_all/compare).
type NaNIgnore uint8

const (
	// NaNIgnoreCompare drops NaN tests protecting a float comparison
	// ("compare", Ghidra's default).
	NaNIgnoreCompare NaNIgnore = iota
	// NaNIgnoreNone keeps every NaN test ("none"): exact for NaN inputs.
	NaNIgnoreNone
	// NaNIgnoreAll drops every NaN test ("all").
	NaNIgnoreAll
)

// SetNaNIgnore sets the nanignore option for this function.
func (fd *Funcdata) SetNaNIgnore(v NaNIgnore) { fd.nanIgnore = v }

type RuleIgnoreNan struct{ batchRule }

func NewRuleIgnoreNan(group string) *RuleIgnoreNan {
	r := &RuleIgnoreNan{}
	r.batchRule = newBatchRule(group, "ignorenan", []OpCode{CPUI_FLOAT_NAN}, r.apply, func(g string) Rule { return NewRuleIgnoreNan(g) })
	return r
}

// apply removes NaN tests guarding a floating-point comparison of the same
// value, following the NaN result through up to three boolean combinations
// (NaNIgnoreCompare, Ghidra's default); NaNIgnoreAll removes every NaN test
// and NaNIgnoreNone none (C++ disables the rule).
// C++ parity: RuleIgnoreNan::applyOp, OptionNanIgnore::apply.
func (r *RuleIgnoreNan) apply(op *PcodeOp, data *Funcdata) int {
	switch data.nanIgnore {
	case NaNIgnoreNone:
		return 0
	case NaNIgnoreAll:
		// Treat the NaN operation as always returning false.
		data.OpSetOpcode(op, CPUI_COPY)
		data.OpSetInput(op, data.NewConstant(1, 0), 0)
		return 1
	}
	if op.NumInput() != 1 || op.Output() == nil || op.Input(0).IsFree() {
		return 0
	}
	floatVar := op.Input(0)
	out1 := op.Output()
	count := 0
	for _, boolRead1 := range append([]*PcodeOp(nil), out1.DescendIter()...) {
		var out2 *Varnode
		matchCode := CPUI_BOOL_OR
		if boolRead1.Code() == CPUI_BOOL_NEGATE {
			matchCode = CPUI_BOOL_AND
			out2 = boolRead1.Output()
		} else {
			out2 = nanTestForComparison(floatVar, boolRead1, boolRead1.GetSlot(out1), matchCode, &count, data)
		}
		if out2 == nil {
			continue
		}
		for _, boolRead2 := range append([]*PcodeOp(nil), out2.DescendIter()...) {
			out3 := nanTestForComparison(floatVar, boolRead2, boolRead2.GetSlot(out2), matchCode, &count, data)
			if out3 == nil {
				continue
			}
			for _, boolRead3 := range append([]*PcodeOp(nil), out3.DescendIter()...) {
				nanTestForComparison(floatVar, boolRead3, boolRead3.GetSlot(out3), matchCode, &count, data)
			}
		}
	}
	if count > 0 {
		return 1
	}
	return 0
}

type RuleUnsigned2Float struct{ batchRule }

func NewRuleUnsigned2Float(group string) *RuleUnsigned2Float {
	r := &RuleUnsigned2Float{}
	r.batchRule = newBatchRule(group, "unsigned2float", []OpCode{CPUI_FLOAT_INT2FLOAT}, r.apply, func(g string) Rule { return NewRuleUnsigned2Float(g) })
	return r
}

func (r *RuleUnsigned2Float) apply(op *PcodeOp, data *Funcdata) int {
	orOp := definedBy(op.Input(0), CPUI_INT_OR)
	if orOp == nil || !orOp.Input(0).IsWritten() || !orOp.Input(1).IsWritten() || op.Output() == nil {
		return 0
	}
	shiftOp := definedBy(orOp.Input(0), CPUI_INT_RIGHT)
	andOp := orOp.Input(1).Def()
	if shiftOp == nil {
		shiftOp = definedBy(orOp.Input(1), CPUI_INT_RIGHT)
		andOp = orOp.Input(0).Def()
	}
	if shiftOp == nil || andOp == nil || !isOneConst(shiftOp.Input(1)) {
		return 0
	}
	base := shiftOp.Input(0)
	if base.IsFree() {
		return 0
	}
	if andOp.Code() == CPUI_INT_ZEXT {
		andOp = definedBy(andOp.Input(0), CPUI_INT_AND)
		if andOp == nil {
			return 0
		}
	}
	if andOp.Code() != CPUI_INT_AND || !isOneConst(andOp.Input(1)) {
		return 0
	}
	vn := andOp.Input(0)
	if vn != base {
		subOp := definedBy(vn, CPUI_SUBPIECE)
		if subOp == nil || !isZeroConst(subOp.Input(1)) || subOp.Input(0) != base {
			return 0
		}
	}
	for _, addOp := range op.Output().DescendIter() {
		if addOp.Code() != CPUI_FLOAT_ADD || addOp.Input(0) != op.Output() || addOp.Input(1) != op.Output() {
			continue
		}
		zextOp := newAuxUnaryOp(data, addOp.Addr(), CPUI_INT_ZEXT, preferredUnsignedFloatSize(base.Size()), base)
		data.OpSetOpcode(addOp, CPUI_FLOAT_INT2FLOAT)
		data.OpRemoveInput(addOp, 1)
		data.OpSetInput(addOp, zextOp.Output(), 0)
		return 1
	}
	return 0
}

// C++ parity: ruleaction.cc RuleInt2FloatCollapse
type RuleInt2FloatCollapse struct{ batchRule }

// C++ parity: ruleaction.cc RuleInt2FloatCollapse
func NewRuleInt2FloatCollapse(group string) *RuleInt2FloatCollapse {
	r := &RuleInt2FloatCollapse{}
	r.batchRule = newBatchRule(group, "int2floatcollapse", []OpCode{CPUI_FLOAT_INT2FLOAT}, r.apply, func(g string) Rule {
		return NewRuleInt2FloatCollapse(g)
	})
	return r
}

// C++ parity: ruleaction.cc RuleInt2FloatCollapse::applyOp
func (r *RuleInt2FloatCollapse) apply(op *PcodeOp, data *Funcdata) int {
	if op.Input(0) == nil || !op.Input(0).IsWritten() {
		return 0
	}
	zextop := op.Input(0).Def()
	if zextop == nil || zextop.Code() != CPUI_INT_ZEXT {
		return 0
	}
	basevn := zextop.Input(0)
	if basevn == nil || basevn.IsFree() {
		return 0
	}
	out := op.Output()
	if out == nil {
		return 0
	}
	multiop := out.LoneDescend()
	if multiop == nil || multiop.Code() != CPUI_MULTIEQUAL || multiop.NumInput() != 2 {
		return 0
	}
	slot := multiop.GetSlot(out)
	if slot < 0 {
		return 0
	}
	otherout := multiop.Input(1 - slot)
	if otherout == nil || !otherout.IsWritten() {
		return 0
	}
	op2 := otherout.Def()
	if op2 == nil || op2.Code() != CPUI_FLOAT_INT2FLOAT || op2.Input(0) != basevn {
		return 0
	}
	parent := multiop.Parent()
	if parent == nil {
		return 0
	}
	cond, dir2unsigned := parent.FlowBlock.FindCondition(&parent.FlowBlock, slot, &parent.FlowBlock, 1-slot)
	if cond == nil {
		return 0
	}
	condBasic, ok := cond.Concrete().(*BlockBasic)
	if !ok || condBasic == nil {
		return 0
	}
	cbranch := condBasic.LastOp()
	if cbranch == nil || cbranch.Code() != CPUI_CBRANCH || cbranch.Input(1) == nil || !cbranch.Input(1).IsWritten() || cbranch.HasFlag(PcodeOpBooleanFlip) {
		return 0
	}
	compare := cbranch.Input(1).Def()
	if compare == nil || compare.Code() != CPUI_INT_SLESS || compare.NumInput() != 2 {
		return 0
	}
	switch {
	case compare.Input(1) != nil && isZeroConst(compare.Input(1)):
		if compare.Input(0) != basevn || dir2unsigned != 1 {
			return 0
		}
	case compare.Input(0) != nil && compare.Input(0).IsConstant() && compare.Input(0).Offset() == maskForSize(basevn.Size()):
		if compare.Input(1) != basevn || dir2unsigned == 1 {
			return 0
		}
	default:
		return 0
	}
	outbl := multiop.Parent()
	data.OpUninsert(multiop)
	data.OpSetOpcode(multiop, CPUI_FLOAT_INT2FLOAT)
	data.OpRemoveInput(multiop, 0)
	multiop.SetNumInputs(1)
	newzext := data.NewOp(1, multiop.Addr())
	data.OpSetOpcode(newzext, CPUI_INT_ZEXT)
	newout := data.NewUniqueOut(int32(preferredZextSizeFloatInt2Float(int(basevn.Size()))), newzext)
	data.OpSetInput(newzext, basevn, 0)
	data.OpSetInput(multiop, newout, 0)
	data.OpInsertBegin(multiop, outbl)
	data.OpInsertBefore(newzext, multiop)
	return 1
}

type RuleFloatSign struct{ batchRule }

func NewRuleFloatSign(group string) *RuleFloatSign {
	r := &RuleFloatSign{}
	r.batchRule = newBatchRule(group, "floatsign", []OpCode{
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND,
		CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_TRUNC,
	}, r.apply, func(g string) Rule { return NewRuleFloatSign(g) })
	return r
}

func (r *RuleFloatSign) apply(op *PcodeOp, data *Funcdata) int {
	res := 0
	if op.Code() != CPUI_FLOAT_INT2FLOAT {
		if rewriteFloatSignInput(op, 0, data) {
			res = 1
		}
		if op.NumInput() == 2 && rewriteFloatSignInput(op, 1, data) {
			res = 1
		}
	}
	if op.IsBoolOutput() || op.Code() == CPUI_FLOAT_TRUNC || op.Output() == nil {
		return res
	}
	for _, readOp := range op.Output().DescendIter() {
		if rewriteFloatSignOp(readOp, data) {
			res = 1
		}
	}
	return res
}

type RuleFloatSignCleanup struct{ batchRule }

func NewRuleFloatSignCleanup(group string) *RuleFloatSignCleanup {
	r := &RuleFloatSignCleanup{}
	r.batchRule = newBatchRule(group, "floatsigncleanup", []OpCode{CPUI_INT_AND, CPUI_INT_XOR}, r.apply, func(g string) Rule {
		return NewRuleFloatSignCleanup(g)
	})
	return r
}

func (r *RuleFloatSignCleanup) apply(op *PcodeOp, data *Funcdata) int {
	if op.Output() == nil {
		return 0
	}
	dt := op.Output().TypeReadFacing(op)
	if dt == nil || dt.Metatype() != TYPE_FLOAT {
		return 0
	}
	if !rewriteFloatSignOp(op, data) {
		return 0
	}
	return 1
}

// nanTestForComparison removes the NaN input of op (reading it at slot) when
// op combines it with a floating-point comparison of floatVar, through
// matchCode, INT_EQUAL/INT_NOTEQUAL, or a CBRANCH guarding a CBRANCH on the
// comparison. It returns op's output when op combines it with another NaN.
// C++ parity: RuleIgnoreNan::testForComparison.
func nanTestForComparison(floatVar *Varnode, op *PcodeOp, slot int, matchCode OpCode, count *int, data *Funcdata) *Varnode {
	if slot < 0 {
		return nil
	}
	switch opc := op.Code(); {
	case opc == matchCode:
		vn := op.Input(1 - slot)
		if nanCheckBackForCompare(floatVar, vn) {
			if !nanExactOrderTest(floatVar, op, vn, matchCode, data) {
				data.OpSetOpcode(op, CPUI_COPY)
				data.OpRemoveInput(op, 1)
				data.OpSetInput(op, vn, 0)
			}
			*count++
		} else if nanIsAnotherNan(vn) {
			return op.Output()
		}
	case opc == CPUI_INT_EQUAL || opc == CPUI_INT_NOTEQUAL:
		vn := op.Input(1 - slot)
		if nanCheckBackForCompare(floatVar, vn) {
			val := uint64(1)
			if matchCode == CPUI_BOOL_OR {
				val = 0
			}
			data.OpSetInput(op, data.NewConstant(1, val), slot)
			*count++
		}
	case opc == CPUI_CBRANCH:
		parent := op.Parent()
		outDir := 1
		if matchCode == CPUI_BOOL_OR {
			outDir = 0
		}
		if op.HasFlag(PcodeOpBooleanFlip) {
			outDir = 1 - outDir
		}
		if parent == nil || parent.SizeOut() != 2 {
			return nil
		}
		outBranch := parent.OutEdge(outDir).Point
		bb, ok := outBranch.Concrete().(*BlockBasic)
		if !ok {
			return nil
		}
		lastOp := bb.LastOp()
		if lastOp != nil && lastOp.Code() == CPUI_CBRANCH && outBranch.SizeOut() == 2 {
			otherBranch := parent.OutEdge(1 - outDir).Point
			if outBranch.OutEdge(0).Point == otherBranch || outBranch.OutEdge(1).Point == otherBranch {
				if nanCheckBackForCompare(floatVar, lastOp.Input(1)) {
					val := uint64(1)
					if matchCode == CPUI_BOOL_OR {
						val = 0
					}
					data.OpSetInput(op, data.NewConstant(1, val), 1)
					*count++
				}
			}
		}
	}
	return nil
}

// nanExactOrderTest replaces op, a NaN test combined with vn (NaN || vn, or
// !NaN && vn), by vn rewritten to take the value the NaN test gave for a NaN
// operand, when Extensions.NaNExactCompares is on (beyond Ghidra). Ghidra
// assumes no NaN and keeps vn as it is; when vn has the other value for NaN
// the NaN case moves to the other branch (comiss; ja becomes
// !NaN && !(a < b) && a != b, and dropping !NaN leaves an expression true for
// NaN). Order comparisons are rewritten through their NaN-false and NaN-true
// forms (a < b and !(b <= a) agree except on NaN); equality has no such pair,
// so a vn that needs one changed keeps Ghidra's rewrite. A test of a value
// that cannot be NaN is dropped as Ghidra does: nothing changes.
func nanExactOrderTest(floatVar *Varnode, op *PcodeOp, vn *Varnode, matchCode OpCode, data *Funcdata) bool {
	if !data.ext.NaNExactCompares || neverNaN(floatVar) {
		return false
	}
	want := matchCode == CPUI_BOOL_OR // NaN || vn is true for NaN, !NaN && vn false
	if v, ok := nanValue(vn, 0); !ok || v == want {
		return false
	}
	if !nanFixable(vn, want, 0) {
		return false
	}
	// A lone order comparison that must become true for NaN is negated by
	// op itself, which Ghidra turns into a COPY, so the block keeps Ghidra's
	// op count (conditional-execution and structuring look at it).
	if want && isFloatOrder(vn.Def().Code()) {
		swapped := nanSwappedOrder(vn.Def(), vn.LoneDescend() != nil, data)
		data.OpSetOpcode(op, CPUI_BOOL_NEGATE)
		data.OpRemoveInput(op, 1)
		data.OpSetInput(op, swapped, 0)
		return true
	}
	fixed := nanRewrite(vn, want, true, op, data, 0)
	data.OpSetOpcode(op, CPUI_COPY)
	data.OpRemoveInput(op, 1)
	data.OpSetInput(op, fixed, 0)
	return true
}

// neverNaN reports a float value that is not NaN: an integer converted to
// float, or a constant whose bits are not a NaN.
func neverNaN(vn *Varnode) bool {
	if vn.IsConstant() {
		v := vn.Offset()
		switch vn.Size() {
		case 4:
			return v&0x7f800000 != 0x7f800000 || v&0x7fffff == 0
		case 8:
			return v&0x7ff0000000000000 != 0x7ff0000000000000 || v&0xfffffffffffff == 0
		}
		return false
	}
	return vn.IsWritten() && vn.Def().Code() == CPUI_FLOAT_INT2FLOAT
}

// nanMaxDepth bounds the boolean tree nanValue and nanRewrite walk.
const nanMaxDepth = 4

// nanValue reports the value of the boolean vn when a float operand of its
// comparisons is NaN; ok is false when vn is not built only from float
// comparisons, NOT, AND and OR.
func nanValue(vn *Varnode, depth int) (val, ok bool) {
	if depth > nanMaxDepth || !vn.IsWritten() {
		return false, false
	}
	def := vn.Def()
	switch def.Code() {
	case CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_EQUAL:
		return false, true
	case CPUI_FLOAT_NOTEQUAL:
		return true, true
	case CPUI_BOOL_NEGATE:
		v, ok := nanValue(def.Input(0), depth+1)
		return !v, ok
	case CPUI_BOOL_AND, CPUI_BOOL_OR:
		a, okA := nanValue(def.Input(0), depth+1)
		b, okB := nanValue(def.Input(1), depth+1)
		if def.Code() == CPUI_BOOL_AND {
			return a && b, okA && okB
		}
		return a || b, okA && okB
	}
	return false, false
}

// nanFixable reports whether nanRewrite can give vn the value want for NaN.
// nanRewrite changes ops in place, so it runs only after this check passes.
func nanFixable(vn *Varnode, want bool, depth int) bool {
	v, ok := nanValue(vn, depth)
	if !ok || v == want {
		return ok
	}
	def := vn.Def()
	switch def.Code() {
	case CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
		return true
	case CPUI_BOOL_NEGATE:
		in := def.Input(0)
		return (in.IsWritten() && isFloatOrder(in.Def().Code())) || nanFixable(in, !want, depth+1)
	case CPUI_BOOL_AND, CPUI_BOOL_OR:
		a := nanFixable(def.Input(0), want, depth+1)
		b := nanFixable(def.Input(1), want, depth+1)
		if (def.Code() == CPUI_BOOL_AND) != want { // one operand is enough
			return a || b
		}
		return a && b
	}
	return false
}

// nanRewrite returns a value equal to vn for non-NaN operands and equal to
// want for NaN ones; the caller checked nanFixable. A NaN-false order
// comparison a < b becomes !(b <= a), a NaN-true !(a < b) becomes b <= a, and
// an AND or OR rewrites the fewest operands needed. An op read only by the
// tree (and every op between it and the dropped test) is changed in place and a new op goes next to the comparison it
// replaces, so no value lives longer or moves to another block (a copy at
// the dropped test would keep the operands alive across it).
func nanRewrite(vn *Varnode, want, owned bool, at *PcodeOp, data *Funcdata, depth int) *Varnode {
	owned = owned && vn.LoneDescend() != nil
	if v, _ := nanValue(vn, depth); v == want {
		return vn
	}
	def := vn.Def()
	switch def.Code() {
	case CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL: // NaN-false, want true
		swapped := nanSwappedOrder(def, owned, data)
		neg := newAuxUnaryOp(data, swapped.Def().Addr(), CPUI_BOOL_NEGATE, 1, swapped)
		data.OpInsertAfter(neg, swapped.Def())
		return neg.Output()
	case CPUI_BOOL_NEGATE: // NaN-true, want false
		in := def.Input(0)
		if in.IsWritten() && isFloatOrder(in.Def().Code()) {
			return nanSwappedOrder(in.Def(), owned && in.LoneDescend() != nil, data)
		}
		r := nanRewrite(in, !want, owned, at, data, depth+1)
		if owned {
			data.OpSetInput(def, r, 0)
			return vn
		}
		neg := newAuxUnaryOp(data, at.Addr(), CPUI_BOOL_NEGATE, 1, r)
		data.OpInsertBefore(neg, at)
		return neg.Output()
	case CPUI_BOOL_AND, CPUI_BOOL_OR:
		a, b := def.Input(0), def.Input(1)
		ra, rb := a, b
		if (def.Code() == CPUI_BOOL_AND) != want {
			if nanFixable(a, want, depth+1) {
				ra = nanRewrite(a, want, owned, at, data, depth+1)
			} else {
				rb = nanRewrite(b, want, owned, at, data, depth+1)
			}
		} else {
			ra = nanRewrite(a, want, owned, at, data, depth+1)
			rb = nanRewrite(b, want, owned, at, data, depth+1)
		}
		if owned {
			data.OpSetInput(def, ra, 0)
			data.OpSetInput(def, rb, 1)
			return vn
		}
		comb := newAuxBinaryOp(data, at.Addr(), def.Code(), 1, ra, rb)
		data.OpInsertBefore(comb, at)
		return comb.Output()
	}
	return nil
}

// nanSwappedOrder returns b <= a for def = a < b and b < a for a <= b: the
// negation of def except on NaN, where both are false. def itself is changed
// when owned (read only on the rewritten path), otherwise the new op follows it.
func nanSwappedOrder(def *PcodeOp, owned bool, data *Funcdata) *Varnode {
	opc := CPUI_FLOAT_LESSEQUAL
	if def.Code() == CPUI_FLOAT_LESSEQUAL {
		opc = CPUI_FLOAT_LESS
	}
	if owned {
		data.OpSetOpcode(def, opc)
		data.OpSwapInput(def, 0, 1)
		return def.Output()
	}
	op := newAuxBinaryOp(data, def.Addr(), opc, 1, def.Input(1), def.Input(0))
	data.OpInsertAfter(op, def)
	return op.Output()
}

// nanCheckBackForCompare reports a boolean root produced by (or combining
// through BOOL_AND/BOOL_OR) a floating-point comparison of floatVar.
// C++ parity: RuleIgnoreNan::checkBackForCompare.
func nanCheckBackForCompare(floatVar, root *Varnode) bool {
	if !root.IsWritten() {
		return false
	}
	def1 := root.Def()
	if !def1.IsBoolOutput() {
		return false
	}
	if def1.Code() == CPUI_BOOL_NEGATE {
		vn := def1.Input(0)
		if !vn.IsWritten() {
			return false
		}
		def1 = vn.Def()
	}
	if isFloatingPointOpcode(def1.Code()) {
		if def1.NumInput() != 2 {
			return false
		}
		return functionalEquality(floatVar, def1.Input(0)) || functionalEquality(floatVar, def1.Input(1))
	}
	if opc := def1.Code(); opc != CPUI_BOOL_AND && opc != CPUI_BOOL_OR {
		return false
	}
	for i := 0; i < 2; i++ {
		vn := def1.Input(i)
		if !vn.IsWritten() {
			continue
		}
		def2 := vn.Def()
		if !def2.IsBoolOutput() || !isFloatingPointOpcode(def2.Code()) || def2.NumInput() != 2 {
			continue
		}
		if functionalEquality(floatVar, def2.Input(0)) || functionalEquality(floatVar, def2.Input(1)) {
			return true
		}
	}
	return false
}

// nanIsAnotherNan reports vn as the direct or negated output of a NaN.
// C++ parity: RuleIgnoreNan::isAnotherNan.
func nanIsAnotherNan(vn *Varnode) bool {
	if !vn.IsWritten() {
		return false
	}
	op := vn.Def()
	if op.Code() == CPUI_BOOL_NEGATE {
		vn = op.Input(0)
		if !vn.IsWritten() {
			return false
		}
		op = vn.Def()
	}
	return op.Code() == CPUI_FLOAT_NAN
}

// isFloatingPointOpcode is TypeOp::isFloatingPointOp (floatingpoint_op).
func isFloatingPointOpcode(opc OpCode) bool {
	switch opc {
	case CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL, CPUI_FLOAT_NAN,
		CPUI_FLOAT_ADD, CPUI_FLOAT_DIV, CPUI_FLOAT_MULT, CPUI_FLOAT_SUB, CPUI_FLOAT_NEG, CPUI_FLOAT_ABS,
		CPUI_FLOAT_SQRT, CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT, CPUI_FLOAT_TRUNC, CPUI_FLOAT_CEIL,
		CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
		return true
	}
	return false
}

func rewriteFloatSignInput(op *PcodeOp, slot int, data *Funcdata) bool {
	if slot >= op.NumInput() {
		return false
	}
	signOp := op.Input(slot).Def()
	return rewriteFloatSignOp(signOp, data)
}

func rewriteFloatSignOp(op *PcodeOp, data *Funcdata) bool {
	resCode, constSlot := floatSignManipulation(op)
	if resCode == CPUI_MAX {
		return false
	}
	data.OpRemoveInput(op, constSlot)
	data.OpSetOpcode(op, resCode)
	return true
}

func floatSignManipulation(op *PcodeOp) (OpCode, int) {
	if op == nil || op.NumInput() != 2 {
		return CPUI_MAX, -1
	}
	for slot := 0; slot < 2; slot++ {
		val, ok := constantValue(op.Input(slot))
		if !ok {
			continue
		}
		size := op.Input(1 - slot).Size()
		switch op.Code() {
		case CPUI_INT_AND:
			if val == lowMask(uint64(size*8-1)) {
				return CPUI_FLOAT_ABS, slot
			}
		case CPUI_INT_XOR:
			if val == signBitForSize(size) {
				return CPUI_FLOAT_NEG, slot
			}
		}
	}
	return CPUI_MAX, -1
}

func preferredUnsignedFloatSize(size int32) int32 {
	if size < 4 {
		return 4
	}
	if size > 8 {
		return 8
	}
	return size
}

func newAuxUnaryOp(data *Funcdata, addr address.Address, opcode OpCode, outSize int32, in *Varnode) *PcodeOp {
	op := data.NewOp(1, addr)
	data.OpSetOpcode(op, opcode)
	data.NewUniqueOut(outSize, op)
	data.OpSetInput(op, in, 0)
	data.OpMarkAlive(op)
	return op
}

type batchCFloatRuleFactory func(string) Rule

var batchCFloatRuleFactories = []batchCFloatRuleFactory{
	func(group string) Rule { return NewRuleFloatCast(group) },
	func(group string) Rule { return NewRuleIgnoreNan(group) },
	func(group string) Rule { return NewRuleUnsigned2Float(group) },
	func(group string) Rule { return NewRuleFloatSign(group) },
	func(group string) Rule { return NewRuleFloatSignCleanup(group) },
}

func BatchCFloatRules(group string) []Rule {
	rules := make([]Rule, 0, len(batchCFloatRuleFactories))
	for _, factory := range batchCFloatRuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchCFloatRules(pool *ActionPool, group string) int {
	if pool == nil {
		return 0
	}
	rules := BatchCFloatRules(group)
	for _, rule := range rules {
		pool.AddRule(rule)
	}
	return len(rules)
}
