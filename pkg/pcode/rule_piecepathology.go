package pcode

// piecePathologyApply recognizes a concatenation whose most significant part
// is junk -- the untouched high bytes of a register around a freshly written
// low part (sete al; ret) -- and records, at the RETURN or CALL it flows to,
// that only the low bytes matter. Dead code and subvariable flow then drop
// the junk. Returns the number of hints that changed.
// C++ parity: ruleaction.cc RulePiecePathology::applyOp.
func piecePathologyApply(op *PcodeOp, data *Funcdata) int {
	vn := op.Input(0)
	if !vn.IsWritten() {
		return 0
	}
	subOp := vn.Def()
	switch subOp.Code() {
	case CPUI_SUBPIECE:
		if subOp.Input(1).Offset() == 0 {
			return 0
		}
		if !isPiecePathology(subOp.Input(0), data) {
			return 0
		}
	case CPUI_INDIRECT:
		if !subOp.IsIndirectCreation() {
			return 0
		}
		lsbVn := op.Input(1)
		if !lsbVn.IsWritten() {
			return 0
		}
		lsbOp := lsbVn.Def()
		if lsbOp.flags&(PcodeOpBinary|PcodeOpUnary) == 0 {
			if !lsbOp.IsCall() {
				return 0
			}
			fc := lsbOp.callSpec
			if fc == nil || !fc.IsOutputLocked() {
				return 0
			}
		}
		addr := lsbVn.Addr()
		if addr.Space != nil && addr.Space.BigEndian {
			addr.Offset -= uint64(vn.Size())
		} else {
			addr.Offset += uint64(lsbVn.Size())
		}
		if addr != vn.Addr() {
			return 0
		}
	default:
		return 0
	}
	return tracePathologyForward(op, data)
}

// isPiecePathology reports whether vn is (through COPYs and MULTIEQUALs) an
// incoming value or the result of a call whose output is not being recovered:
// bytes nobody in this function produced.
// C++ parity: RulePiecePathology::isPathology.
func isPiecePathology(vn *Varnode, data *Funcdata) bool {
	var worklist []*PcodeOp
	marked := map[*PcodeOp]bool{}
	pos, slot := 0, 0
	res := false
	for {
		if vn.IsInput() && !vn.IsPersist() {
			res = true
			break
		}
		op := vn.Def()
		for !res && op != nil {
			switch op.Code() {
			case CPUI_COPY:
				vn = op.Input(0)
				op = vn.Def()
			case CPUI_MULTIEQUAL:
				if !marked[op] {
					marked[op] = true
					worklist = append(worklist, op)
				}
				op = nil
			case CPUI_INDIRECT:
				if callOp := op.Input(1).GetIndirectCause(); callOp != nil && callOp.IsCall() {
					if fc := callOp.callSpec; fc != nil && !fc.IsOutputActive() {
						res = true
					}
				}
				op = nil
			case CPUI_CALL, CPUI_CALLIND:
				if fc := op.callSpec; fc != nil && !fc.IsOutputActive() {
					res = true
				}
				op = nil
			default:
				op = nil
			}
		}
		if res || pos >= len(worklist) {
			break
		}
		cur := worklist[pos]
		if slot < cur.NumInput() {
			vn = cur.Input(slot)
			slot++
		} else {
			pos++
			if pos >= len(worklist) {
				break
			}
			vn = worklist[pos].Input(0)
			slot = 1
		}
	}
	return res
}

// tracePathologyForward follows the concatenation forward through COPY,
// INDIRECT and MULTIEQUAL to the RETURNs and calls it reaches and records how
// many bytes of it they really need.
// C++ parity: RulePiecePathology::tracePathologyForward.
func tracePathologyForward(op *PcodeOp, data *Funcdata) int {
	count := 0
	marked := map[*PcodeOp]bool{op: true}
	worklist := []*PcodeOp{op}
	bytesConsumed := op.Input(1).Size()
	for pos := 0; pos < len(worklist); pos++ {
		outVn := worklist[pos].Output()
		if outVn == nil {
			continue
		}
		for _, cur := range outVn.DescendIter() {
			switch cur.Code() {
			case CPUI_COPY, CPUI_INDIRECT, CPUI_MULTIEQUAL:
				if !marked[cur] {
					marked[cur] = true
					worklist = append(worklist, cur)
				}
			case CPUI_RETURN:
				if fp := data.GetFuncProto(); fp != nil && !fp.IsOutputLocked() {
					if fp.SetReturnBytesConsumed(bytesConsumed) {
						count++
					}
				}
			}
			// TODO known mismatch: the CALL branch (FuncCallSpecs::
			// setInputBytesConsumed) is not ported.
		}
	}
	return count
}
