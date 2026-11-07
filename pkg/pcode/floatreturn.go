package pcode

// isFloatReturn reports that the function returns a 4-byte float in an
// 8-byte float output slot (x64: XMM0_Qa), so only the low 4 bytes of the
// return value matter (Extensions.NarrowFloatReturns, beyond Ghidra).
//
// Ghidra's core sizes the return by the bytes the returned values may hold
// (ActionDeadCode::gatherConsumedReturn) and trims a concatenation with
// unrelated upper bytes only in the integer patterns RulePiecePathology
// knows. A path that returns a float parameter register unchanged (movaps
// xmm0, xmm1) keeps all 8 bytes alive, so the function prints as returning
// ulonglong, every float result goes through (ulonglong)(uint) and the
// parameter becomes an integer too.
//
// The low 4 bytes of every returned value are classified, following
// MULTIEQUAL, COPY, INDIRECT, PIECE, SUBPIECE and zero extension:
//   - evidence: the output of a 4-byte float operation;
//   - compatible: a 4-byte value (a load, a bit copy), a constant, a call's
//     output, or a parameter of the function in a float input slot;
//   - anything else (an 8-byte float operation, i.e. double; integer
//     arithmetic over the 8 bytes) rules the narrowing out.
//
// It narrows only when nothing rules it out and at least one path is
// evidence: a double return is never cut to a float.
func isFloatReturn(data *Funcdata) bool {
	fp := data.GetFuncProto()
	if fp == nil || fp.Model() == nil || fp.Model().OutputParams == nil || fp.Model().InputParams == nil {
		return false
	}
	c := floatLaneCheck{data: data, fp: fp, seen: map[*PcodeOp]bool{}}
	found := false
	for _, op := range data.GetPcodeOpBank().AliveOps() {
		if op.Code() != CPUI_RETURN || op.NumInput() < 2 {
			continue
		}
		vn := op.Input(1)
		if vn == nil || vn.Size() != 8 {
			return false
		}
		pe := fp.Model().OutputParams.findEntry(vn.Addr(), vn.Size(), true)
		if pe == nil || pe.getType() != typeclassFloat {
			return false
		}
		found = true
		if !c.low4(vn, 0, 0) {
			return false
		}
	}
	return found && c.evidence
}

// floatLaneMaxDepth bounds the def-chain walk of one returned value.
const floatLaneMaxDepth = 64

type floatLaneCheck struct {
	data     *Funcdata
	fp       *FuncProto
	seen     map[*PcodeOp]bool
	evidence bool
}

// low4 reports whether the 4 bytes at byte offset off of vn are compatible
// with a float, recording float evidence on the way.
func (c *floatLaneCheck) low4(vn *Varnode, off int32, depth int) bool {
	if depth > floatLaneMaxDepth {
		return false
	}
	if off < 0 || off+4 > vn.Size() {
		return false
	}
	if vn.IsConstant() {
		return true
	}
	if !vn.IsWritten() {
		if !vn.IsInput() {
			return false
		}
		// A parameter of this function in a float input slot.
		pe := c.fp.Model().InputParams.findEntry(vn.Addr(), vn.Size(), true)
		return pe != nil && pe.getType() == typeclassFloat
	}
	op := vn.Def()
	switch op.Code() {
	case CPUI_MULTIEQUAL:
		if c.seen[op] {
			return true // a loop back edge adds nothing new
		}
		c.seen[op] = true
		for i := 0; i < op.NumInput(); i++ {
			if !c.low4(op.Input(i), off, depth+1) {
				return false
			}
		}
		return true
	case CPUI_COPY:
		return c.low4(op.Input(0), off, depth+1)
	case CPUI_INDIRECT:
		if op.IsIndirectCreation() {
			return false
		}
		return c.low4(op.Input(0), off, depth+1)
	case CPUI_SUBPIECE:
		return c.low4(op.Input(0), off+int32(op.Input(1).Offset()), depth+1)
	case CPUI_PIECE:
		lo := op.Input(1)
		if off < lo.Size() {
			return c.low4(lo, off, depth+1)
		}
		return c.low4(op.Input(0), off-lo.Size(), depth+1)
	case CPUI_INT_ZEXT:
		return c.low4(op.Input(0), off, depth+1)
	case CPUI_CALL, CPUI_CALLIND:
		return off == 0
	}
	if off != 0 {
		return false
	}
	if isFloatArith(op.Code()) {
		if vn.Size() == 4 {
			c.evidence = true
			return true
		}
		return false // a double
	}
	return vn.Size() == 4
}

// isFloatArith reports an op computing a floating-point value.
func isFloatArith(opc OpCode) bool {
	switch opc {
	case CPUI_FLOAT_ADD, CPUI_FLOAT_SUB, CPUI_FLOAT_MULT, CPUI_FLOAT_DIV, CPUI_FLOAT_NEG,
		CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT, CPUI_FLOAT_INT2FLOAT, CPUI_FLOAT_FLOAT2FLOAT,
		CPUI_FLOAT_CEIL, CPUI_FLOAT_FLOOR, CPUI_FLOAT_ROUND:
		return true
	}
	return false
}

// usedAsFloat reports that vn is read as a float: by a float operation, or
// as a call argument passed in a float parameter slot of the callee's model
// (x64: XMM0-3_Qa). Copies are followed.
func usedAsFloat(data *Funcdata, vn *Varnode) bool {
	work := []*Varnode{vn}
	for n := 0; len(work) > 0 && n < 32; n++ {
		v := work[len(work)-1]
		work = work[:len(work)-1]
		for _, op := range v.DescendIter() {
			switch c := op.Code(); {
			case c == CPUI_COPY:
				work = append(work, op.Output())
			case isFloatArith(c), c == CPUI_FLOAT_LESS, c == CPUI_FLOAT_LESSEQUAL,
				c == CPUI_FLOAT_EQUAL, c == CPUI_FLOAT_NOTEQUAL, c == CPUI_FLOAT_NAN,
				c == CPUI_FLOAT_TRUNC:
				return true
			case c == CPUI_CALL || c == CPUI_CALLIND:
				if fc := data.callSpecsForOp(op); fc != nil && fc.floatArgSlot(op.GetSlot(v)) {
					return true
				}
			}
		}
	}
	return false
}

// floatArgSlot reports that CALL input slot k (1 = first argument) holds an
// argument in a float parameter entry. The call's inputs follow its used
// trials in order (buildInputFromTrials), which keep their storage.
func (fc *FuncCallSpecs) floatArgSlot(k int) bool {
	active := fc.GetActiveInput()
	m := fc.Model()
	if k < 1 || active == nil || m == nil || m.InputParams == nil {
		return false
	}
	n := 0
	for i := 0; i < active.NumTrials(); i++ {
		t := active.Trial(i)
		if !t.IsUsed() {
			continue
		}
		if n++; n == k {
			pe := m.InputParams.findEntry(t.GetAddress(), t.GetSize(), true)
			return pe != nil && pe.getType() == typeclassFloat
		}
	}
	return false
}
