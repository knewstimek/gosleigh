package pcode

import (
	"math/big"
	"math/bits"

	"gosleigh/pkg/address"
)

type RulePositiveDiv struct{ batchRule }

func NewRulePositiveDiv(group string) *RulePositiveDiv {
	r := &RulePositiveDiv{}
	r.batchRule = newBatchRule(group, "positivediv", []OpCode{CPUI_INT_SDIV, CPUI_INT_SREM}, r.apply, func(g string) Rule {
		return NewRulePositiveDiv(g)
	})
	return r
}

func (r *RulePositiveDiv) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	signBit := signBitForSize(outputOrInputSize(op))
	if signBit == 0 {
		return 0
	}
	if op.Input(0).NZMask()&signBit != 0 {
		return 0
	}
	if op.Input(1).NZMask()&signBit != 0 {
		return 0
	}
	if op.Code() == CPUI_INT_SDIV {
		data.OpSetOpcode(op, CPUI_INT_DIV)
	} else {
		data.OpSetOpcode(op, CPUI_INT_REM)
	}
	return 1
}

type RuleDivOpt struct{ batchRule }

func NewRuleDivOpt(group string) *RuleDivOpt {
	r := &RuleDivOpt{}
	r.batchRule = newBatchRule(group, "divopt", []OpCode{CPUI_SUBPIECE, CPUI_INT_RIGHT, CPUI_INT_SRIGHT}, r.apply, func(g string) Rule {
		return NewRuleDivOpt(g)
	})
	return r
}

type divOptForm struct {
	base   *Varnode
	n      uint64
	coeff  uint64
	xsize  int
	extopc OpCode
}

func (r *RuleDivOpt) apply(op *PcodeOp, data *Funcdata) int {
	form, ok := findDivOptForm(op)
	if !ok || form.base == nil || form.base.IsFree() {
		return 0
	}
	if checkDivOptOverlap(op) {
		return 0
	}
	xsize := form.xsize
	if form.extopc == CPUI_INT_SEXT {
		xsize--
	}
	divisor := calcMagicDivisor(form.n, form.coeff, xsize)
	if divisor == 0 {
		return 0
	}
	size := form.base.Size()
	if size <= 0 {
		return 0
	}
	if form.extopc == CPUI_INT_SEXT {
		divop := newAuxBinaryOp(data, op.Addr(), CPUI_INT_SDIV, size, form.base, data.NewConstant(size, divisor))
		signop := newAuxBinaryOp(data, op.Addr(), CPUI_INT_SRIGHT, size, form.base, data.NewConstant(size, uint64(size*8-1)))
		rewriteOp(data, op, CPUI_INT_ADD, divop.Output(), signop.Output())
		return 1
	}
	rewriteOp(data, op, CPUI_INT_DIV, form.base, data.NewConstant(size, divisor))
	return 1
}

type RuleSignDiv2 struct{ batchRule }

func NewRuleSignDiv2(group string) *RuleSignDiv2 {
	r := &RuleSignDiv2{}
	r.batchRule = newBatchRule(group, "signdiv2", []OpCode{CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleSignDiv2(g) })
	return r
}

func (r *RuleSignDiv2) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 || !isConstantValue(op.Input(1), 1) {
		return 0
	}
	addop := definedBy(op.Input(0), CPUI_INT_ADD)
	if addop == nil {
		return 0
	}
	var base *Varnode
	for slot := 0; slot < 2; slot++ {
		multop := definedBy(addop.Input(slot), CPUI_INT_MULT)
		if multop == nil || !isAllOnesConst(multop.Input(1)) {
			continue
		}
		shiftop := definedBy(multop.Input(0), CPUI_INT_SRIGHT)
		if shiftop == nil || shiftop.NumInput() != 2 {
			continue
		}
		other := addop.Input(1 - slot)
		if shiftop.Input(0) != other {
			continue
		}
		if !isConstantValue(shiftop.Input(1), uint64(other.Size()*8-1)) || other.IsFree() {
			continue
		}
		base = other
		break
	}
	if base == nil {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_SDIV, base, data.NewConstant(base.Size(), 2))
	return 1
}

type RuleDivChain struct{ batchRule }

func NewRuleDivChain(group string) *RuleDivChain {
	r := &RuleDivChain{}
	r.batchRule = newBatchRule(group, "divchain", []OpCode{CPUI_INT_DIV, CPUI_INT_SDIV}, r.apply, func(g string) Rule { return NewRuleDivChain(g) })
	return r
}

func (r *RuleDivChain) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	const2, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	inVn := op.Input(0)
	if !inVn.IsWritten() || inVn.LoneDescend() == nil {
		return 0
	}
	divOp := inVn.Def()
	if divOp == nil {
		return 0
	}
	opc2 := op.Code()
	opc1 := divOp.Code()
	if opc1 != opc2 && !(opc2 == CPUI_INT_DIV && opc1 == CPUI_INT_RIGHT) {
		return 0
	}
	const1, ok := constantValue(divOp.Input(1))
	if !ok {
		return 0
	}
	val1 := const1
	if opc1 == CPUI_INT_RIGHT {
		if const1 >= 64 {
			return 0
		}
		val1 = uint64(1) << const1
	}
	base := divOp.Input(0)
	if base.IsFree() {
		return 0
	}
	size := outputOrInputSize(op)
	resval := truncateToSize(val1*const2, size)
	if resval == 0 {
		return 0
	}
	abs1 := absoluteConstForSize(val1, size)
	abs2 := absoluteConstForSize(const2, size)
	bitcount := bits.Len64(abs1) + bits.Len64(abs2) + 2
	if opc2 == CPUI_INT_DIV && bitcount > int(size)*8 {
		return 0
	}
	if opc2 == CPUI_INT_SDIV && bitcount > int(size)*8-2 {
		return 0
	}
	data.OpSetInput(op, base, 0)
	data.OpSetInput(op, data.NewConstant(size, resval), 1)
	return 1
}

type RuleSignForm struct{ batchRule }

func NewRuleSignForm(group string) *RuleSignForm {
	r := &RuleSignForm{}
	r.batchRule = newBatchRule(group, "signform", []OpCode{CPUI_SUBPIECE}, r.apply, func(g string) Rule { return NewRuleSignForm(g) })
	return r
}

func (r *RuleSignForm) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	sextop := definedBy(op.Input(0), CPUI_INT_SEXT)
	if sextop == nil {
		return 0
	}
	base := sextop.Input(0)
	c, ok := constantValue(op.Input(1))
	if !ok || c < uint64(base.Size()) || base.IsFree() {
		return 0
	}
	rewriteOp(data, op, CPUI_INT_SRIGHT, base, data.NewConstant(4, uint64(base.Size()*8-1)))
	return 1
}

type RuleSignForm2 struct{ batchRule }

func NewRuleSignForm2(group string) *RuleSignForm2 {
	r := &RuleSignForm2{}
	r.batchRule = newBatchRule(group, "signform2", []OpCode{CPUI_INT_SRIGHT}, r.apply, func(g string) Rule { return NewRuleSignForm2(g) })
	return r
}

func (r *RuleSignForm2) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	shift, ok := constantValue(op.Input(1))
	if !ok || int32(shift) != op.Input(0).Size()*8-1 {
		return 0
	}
	subOp := definedBy(op.Input(0), CPUI_SUBPIECE)
	if subOp == nil {
		return 0
	}
	c, ok := constantValue(subOp.Input(1))
	if !ok {
		return 0
	}
	multOut := subOp.Input(0)
	if int32(c)+op.Input(0).Size() != multOut.Size() {
		return 0
	}
	multOp := definedBy(multOut, CPUI_INT_MULT)
	if multOp == nil {
		return 0
	}
	var sextOp *PcodeOp
	slot := -1
	for i := 0; i < 2; i++ {
		if candidate := definedBy(multOp.Input(i), CPUI_INT_SEXT); candidate != nil {
			sextOp = candidate
			slot = i
			break
		}
	}
	if sextOp == nil {
		return 0
	}
	base := sextOp.Input(0)
	if base.IsFree() || base.Size() != op.Input(0).Size() {
		return 0
	}
	other := multOp.Input(1 - slot)
	if val, ok := constantValue(other); ok {
		if val > maskForSize(op.Input(0).Size()) || 2*op.Input(0).Size() > multOut.Size() {
			return 0
		}
	} else {
		zextOp := definedBy(other, CPUI_INT_ZEXT)
		if zextOp == nil || zextOp.Input(0).Size()+op.Input(0).Size() > multOut.Size() {
			return 0
		}
	}
	data.OpSetInput(op, base, 0)
	return 1
}

type RuleModOpt struct{ batchRule }

func NewRuleModOpt(group string) *RuleModOpt {
	r := &RuleModOpt{}
	r.batchRule = newBatchRule(group, "modopt", []OpCode{CPUI_INT_DIV, CPUI_INT_SDIV}, r.apply, func(g string) Rule { return NewRuleModOpt(g) })
	return r
}

func (r *RuleModOpt) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 || op.Output() == nil {
		return 0
	}
	divisor, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	base := op.Input(0)
	if base.IsFree() {
		return 0
	}
	remOp := CPUI_INT_REM
	if op.Code() == CPUI_INT_SDIV {
		remOp = CPUI_INT_SREM
	}
	for _, desc := range op.Output().DescendIter() {
		multConst, multOut := quotientScaleUse(desc, op.Output())
		if multOut == nil {
			continue
		}
		for _, root := range multOut.DescendIter() {
			switch root.Code() {
			case CPUI_INT_SUB:
				if root.Input(0) == base && root.Input(1) == multOut && multConst == divisor {
					rewriteOp(data, root, remOp, base, data.NewConstant(base.Size(), divisor))
					return 1
				}
			case CPUI_INT_ADD:
				if multConst == negateConstForSize(divisor, multOut.Size()) && (root.Input(0) == base || root.Input(1) == base) {
					rewriteOp(data, root, remOp, base, data.NewConstant(base.Size(), divisor))
					return 1
				}
			}
		}
	}
	return 0
}

type RuleSignMod2nOpt struct{ batchRule }

func NewRuleSignMod2nOpt(group string) *RuleSignMod2nOpt {
	r := &RuleSignMod2nOpt{}
	r.batchRule = newBatchRule(group, "signmod2nopt", []OpCode{CPUI_INT_RIGHT}, r.apply, func(g string) Rule { return NewRuleSignMod2nOpt(g) })
	return r
}

func (r *RuleSignMod2nOpt) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 {
		return 0
	}
	shiftAmt, ok := constantValue(op.Input(1))
	if !ok {
		return 0
	}
	base := checkSignExtraction(op.Input(0))
	if base == nil || base.IsFree() {
		return 0
	}
	n := uint64(base.Size()*8) - shiftAmt
	if n == 0 || n >= 64 {
		return 0
	}
	mask := lowMask(n)
	for _, multop := range op.Output().DescendIter() {
		if multop.Code() != CPUI_INT_MULT || !isAllOnesConst(multop.Input(1)) {
			continue
		}
		baseOp := multop.Output().LoneDescend()
		if baseOp == nil || baseOp.Code() != CPUI_INT_ADD {
			continue
		}
		slot := 1 - baseOp.GetSlot(multop.Output())
		andOp := definedBy(baseOp.Input(slot), CPUI_INT_AND)
		truncSize := int32(-1)
		if andOp == nil {
			zextOp := definedBy(baseOp.Input(slot), CPUI_INT_ZEXT)
			if zextOp == nil {
				continue
			}
			andOp = definedBy(zextOp.Input(0), CPUI_INT_AND)
			if andOp == nil {
				continue
			}
			truncSize = zextOp.Input(0).Size()
		}
		if !isConstantValue(andOp.Input(1), mask) {
			continue
		}
		addOp := definedBy(andOp.Input(0), CPUI_INT_ADD)
		if addOp == nil {
			continue
		}
		aSlot := -1
		for i := 0; i < 2; i++ {
			vn := addOp.Input(i)
			if truncSize >= 0 {
				subOp := definedBy(vn, CPUI_SUBPIECE)
				if subOp == nil || !isZeroConst(subOp.Input(1)) {
					continue
				}
				vn = subOp.Input(0)
			}
			if vn == base {
				aSlot = i
				break
			}
		}
		if aSlot < 0 {
			continue
		}
		shiftOp := definedBy(addOp.Input(1-aSlot), CPUI_INT_RIGHT)
		if shiftOp == nil {
			continue
		}
		shiftVal, ok := constantValue(shiftOp.Input(1))
		if !ok {
			continue
		}
		if truncSize >= 0 {
			shiftVal += uint64(base.Size()-truncSize) * 8
		}
		if shiftVal != shiftAmt {
			continue
		}
		extVn := checkSignExtraction(shiftOp.Input(0))
		if extVn == nil {
			continue
		}
		if truncSize >= 0 {
			subOp := definedBy(extVn, CPUI_SUBPIECE)
			if subOp == nil {
				continue
			}
			off, ok := constantValue(subOp.Input(1))
			if !ok || int32(off) != truncSize {
				continue
			}
			extVn = subOp.Input(0)
		}
		if extVn != base {
			continue
		}
		rewriteOp(data, baseOp, CPUI_INT_SREM, base, data.NewConstant(base.Size(), mask+1))
		return 1
	}
	return 0
}

type RuleSignMod2Opt struct{ batchRule }

func NewRuleSignMod2Opt(group string) *RuleSignMod2Opt {
	r := &RuleSignMod2Opt{}
	r.batchRule = newBatchRule(group, "signmod2opt", []OpCode{CPUI_INT_AND}, r.apply, func(g string) Rule { return NewRuleSignMod2Opt(g) })
	return r
}

func (r *RuleSignMod2Opt) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 || !isOneConst(op.Input(1)) {
		return 0
	}
	addOp := definedBy(op.Input(0), CPUI_INT_ADD)
	if addOp == nil {
		return 0
	}
	multSlot := -1
	var multOp *PcodeOp
	for i := 0; i < 2; i++ {
		multOp = definedBy(addOp.Input(i), CPUI_INT_MULT)
		if multOp != nil && isAllOnesConst(multOp.Input(1)) {
			multSlot = i
			break
		}
	}
	if multSlot < 0 {
		return 0
	}
	base := checkSignExtraction(multOp.Input(0))
	if base == nil {
		return 0
	}
	otherBase := addOp.Input(1 - multSlot)
	trunc := false
	if otherBase != base {
		subA := definedBy(multOp.Input(0), CPUI_SUBPIECE)
		subB := definedBy(otherBase, CPUI_SUBPIECE)
		if subA == nil || subB == nil || !isZeroConst(subB.Input(1)) {
			return 0
		}
		truncAmt, ok := constantValue(subA.Input(1))
		if !ok || int32(truncAmt)+subA.Output().Size() != subA.Input(0).Size() {
			return 0
		}
		base = subA.Input(0)
		otherBase = subB.Input(0)
		if otherBase != base {
			return 0
		}
		trunc = true
	}
	if base.IsFree() {
		return 0
	}
	andOut := op.Output()
	if trunc {
		zextOp := andOut.LoneDescend()
		if zextOp == nil || zextOp.Code() != CPUI_INT_ZEXT {
			return 0
		}
		andOut = zextOp.Output()
	}
	for _, root := range andOut.DescendIter() {
		if root.Code() != CPUI_INT_ADD {
			continue
		}
		slot := root.GetSlot(andOut)
		if slot < 0 {
			continue
		}
		if checkSignExtraction(root.Input(1-slot)) != base {
			continue
		}
		rewriteOp(data, root, CPUI_INT_SREM, base, data.NewConstant(base.Size(), 2))
		return 1
	}
	return 0
}

type RuleSignMod2nOpt2 struct{ batchRule }

func NewRuleSignMod2nOpt2(group string) *RuleSignMod2nOpt2 {
	r := &RuleSignMod2nOpt2{}
	r.batchRule = newBatchRule(group, "signmod2nopt2", []OpCode{CPUI_INT_MULT}, r.apply, func(g string) Rule { return NewRuleSignMod2nOpt2(g) })
	return r
}

func (r *RuleSignMod2nOpt2) apply(op *PcodeOp, data *Funcdata) int {
	if op.NumInput() != 2 || !isAllOnesConst(op.Input(1)) {
		return 0
	}
	andOp := definedBy(op.Input(0), CPUI_INT_AND)
	if andOp == nil {
		return 0
	}
	maskVn := andOp.Input(1)
	mask, ok := constantValue(maskVn)
	if !ok {
		return 0
	}
	npow := truncateToSize(^mask+1, maskVn.Size())
	if bits.OnesCount64(npow) != 1 || npow == 1 {
		return 0
	}
	base := checkSignExtForm(definedBy(andOp.Input(0), CPUI_INT_ADD))
	if base == nil || base.IsFree() {
		return 0
	}
	for _, root := range op.Output().DescendIter() {
		if root.Code() != CPUI_INT_ADD {
			continue
		}
		slot := root.GetSlot(op.Output())
		if slot < 0 || root.Input(1-slot) != base {
			continue
		}
		if slot == 0 {
			data.OpSetInput(root, base, 0)
		}
		data.OpSetInput(root, data.NewConstant(base.Size(), npow), 1)
		data.OpSetOpcode(root, CPUI_INT_SREM)
		return 1
	}
	return 0
}

func findDivOptForm(op *PcodeOp) (*divOptForm, bool) {
	if op == nil || op.NumInput() < 2 {
		return nil, false
	}
	cur := op
	shiftopc := cur.Code()
	n := uint64(0)
	switch shiftopc {
	case CPUI_INT_RIGHT, CPUI_INT_SRIGHT:
		shiftAmt, ok := constantValue(cur.Input(1))
		if !ok || !cur.Input(0).IsWritten() {
			return nil, false
		}
		n = shiftAmt
		cur = cur.Input(0).Def()
	case CPUI_SUBPIECE:
		shiftopc = CPUI_MAX
	default:
		return nil, false
	}
	if cur.Code() == CPUI_SUBPIECE {
		off, ok := constantValue(cur.Input(1))
		if !ok || !cur.Input(0).IsWritten() {
			return nil, false
		}
		if cur.Output().Size()+int32(off) != cur.Input(0).Size() {
			return nil, false
		}
		n += off * 8
		cur = cur.Input(0).Def()
	}
	if cur == nil || cur.Code() != CPUI_INT_MULT {
		return nil, false
	}
	var inVn *Varnode
	coeff, ok := constantValue(cur.Input(0))
	if ok {
		inVn = cur.Input(1)
		if !inVn.IsWritten() {
			return nil, false
		}
	} else {
		coeff, ok = constantValue(cur.Input(1))
		if !ok {
			return nil, false
		}
		inVn = cur.Input(0)
		if !inVn.IsWritten() {
			return nil, false
		}
	}
	extOp := inVn.Def()
	extopc := CPUI_INT_ZEXT
	base := inVn
	xsize := 0
	switch extOp.Code() {
	case CPUI_INT_ZEXT:
		base = extOp.Input(0)
		if base.IsFree() {
			return nil, false
		}
		xsize = bits.Len64(base.NZMask())
		if xsize == 0 || xsize > int(inVn.Size())*4 {
			return nil, false
		}
		extopc = CPUI_INT_ZEXT
	case CPUI_INT_SEXT:
		base = extOp.Input(0)
		if base.IsFree() {
			return nil, false
		}
		xsize = int(base.Size() * 8)
		extopc = CPUI_INT_SEXT
	default:
		if inVn.IsFree() {
			return nil, false
		}
		xsize = bits.Len64(inVn.NZMask())
		if xsize == 0 || xsize > int(inVn.Size())*4 {
			return nil, false
		}
		base = inVn
		extopc = CPUI_INT_ZEXT
	}
	if (extopc == CPUI_INT_ZEXT && shiftopc == CPUI_INT_SRIGHT) || (extopc == CPUI_INT_SEXT && shiftopc == CPUI_INT_RIGHT) {
		if int(op.Output().Size()*8)-int(n) != xsize {
			return nil, false
		}
	}
	return &divOptForm{base: base, n: n, coeff: coeff, xsize: xsize, extopc: extopc}, true
}

func calcMagicDivisor(n uint64, coeff uint64, xsize int) uint64 {
	if n > 127 || xsize <= 0 || xsize > 64 || coeff <= 1 {
		return 0
	}
	y := new(big.Int).SetUint64(coeff)
	y.Sub(y, big.NewInt(1))
	if y.Sign() <= 0 {
		return 0
	}
	power := new(big.Int).Lsh(big.NewInt(1), uint(n))
	q := new(big.Int)
	rem := new(big.Int)
	q.QuoRem(power, y, rem)
	if q.BitLen() > 64 {
		return 0
	}
	if y.Cmp(q) < 0 {
		return 0
	}
	diff := new(big.Int)
	if rem.Cmp(q) >= 0 {
		q.Add(q, big.NewInt(1))
		rem.Sub(rem, y)
		rem.Add(rem, q)
		if rem.Cmp(q) >= 0 {
			return 0
		}
		diff.Set(q)
	}
	denom := new(big.Int).Sub(q, rem)
	denom.Add(denom, diff)
	if denom.Sign() <= 0 {
		return 0
	}
	tmp := new(big.Int).Quo(power, denom)
	maxx := new(big.Int)
	if xsize == 64 {
		maxx.SetUint64(^uint64(0))
	} else {
		maxx.Lsh(big.NewInt(1), uint(xsize))
		maxx.Sub(maxx, big.NewInt(1))
	}
	if tmp.Cmp(maxx) <= 0 {
		return 0
	}
	return q.Uint64()
}

func checkDivOptOverlap(op *PcodeOp) bool {
	if op == nil || op.Code() != CPUI_SUBPIECE || op.Output() == nil {
		return false
	}
	for _, desc := range op.Output().DescendIter() {
		if desc.Code() != CPUI_INT_RIGHT && desc.Code() != CPUI_INT_SRIGHT {
			continue
		}
		if _, ok := findDivOptForm(desc); ok {
			return true
		}
	}
	return false
}

func quotientScaleUse(op *PcodeOp, quotient *Varnode) (uint64, *Varnode) {
	if op == nil || op.Code() != CPUI_INT_MULT || op.Output() == nil {
		return 0, nil
	}
	for slot := 0; slot < 2; slot++ {
		if op.Input(slot) != quotient {
			continue
		}
		if c, ok := constantValue(op.Input(1 - slot)); ok {
			return c, op.Output()
		}
	}
	return 0, nil
}

func checkSignExtraction(outVn *Varnode) *Varnode {
	signOp := definedBy(outVn, CPUI_INT_SRIGHT)
	if signOp == nil || signOp.NumInput() != 2 {
		return nil
	}
	val, ok := constantValue(signOp.Input(1))
	res := signOp.Input(0)
	if !ok || val != uint64(res.Size()*8-1) {
		return nil
	}
	return res
}

func checkSignExtForm(op *PcodeOp) *Varnode {
	if op == nil || op.Code() != CPUI_INT_ADD {
		return nil
	}
	for slot := 0; slot < 2; slot++ {
		multOp := definedBy(op.Input(slot), CPUI_INT_MULT)
		if multOp == nil || !isAllOnesConst(multOp.Input(1)) {
			continue
		}
		base := op.Input(1 - slot)
		shiftOp := definedBy(multOp.Input(0), CPUI_INT_SRIGHT)
		if shiftOp == nil || shiftOp.Input(0) != base {
			continue
		}
		if !isConstantValue(shiftOp.Input(1), uint64(base.Size()*8-1)) {
			continue
		}
		return base
	}
	return nil
}

func absoluteConstForSize(val uint64, size int32) uint64 {
	if val&signBitForSize(size) != 0 {
		return negateConstForSize(val, size)
	}
	return val
}

func newAuxBinaryOp(data *Funcdata, addr address.Address, opcode OpCode, outSize int32, in0 *Varnode, in1 *Varnode) *PcodeOp {
	op := data.NewOp(2, addr)
	data.OpSetOpcode(op, opcode)
	data.NewUniqueOut(outSize, op)
	data.OpSetInput(op, in0, 0)
	data.OpSetInput(op, in1, 1)
	data.OpMarkAlive(op)
	return op
}

type batchCDivModRuleFactory func(string) Rule

var batchCDivModRuleFactories = []batchCDivModRuleFactory{
	func(group string) Rule { return NewRulePositiveDiv(group) },
	func(group string) Rule { return NewRuleDivOpt(group) },
	func(group string) Rule { return NewRuleSignDiv2(group) },
	func(group string) Rule { return NewRuleDivChain(group) },
	func(group string) Rule { return NewRuleSignForm(group) },
	func(group string) Rule { return NewRuleSignForm2(group) },
	func(group string) Rule { return NewRuleModOpt(group) },
	func(group string) Rule { return NewRuleSignMod2nOpt(group) },
	func(group string) Rule { return NewRuleSignMod2Opt(group) },
	func(group string) Rule { return NewRuleSignMod2nOpt2(group) },
}

func BatchCDivModRules(group string) []Rule {
	rules := make([]Rule, 0, len(batchCDivModRuleFactories))
	for _, factory := range batchCDivModRuleFactories {
		rules = append(rules, factory(group))
	}
	return rules
}

func AddBatchCDivModRules(pool *ActionPool, group string) int {
	if pool == nil {
		return 0
	}
	rules := BatchCDivModRules(group)
	for _, rule := range rules {
		pool.AddRule(rule)
	}
	return len(rules)
}
