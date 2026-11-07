package analysis

import (
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// returnScanLimit bounds the instructions followed from a callee's entry to
// its return.
const returnScanLimit = 256

// CalleeFloatReturn implements pcode.HostCalleeReturn: 4 when the function
// at entry returns a float in XMM0, 8 for a double, 0 when unknown.
//
// The scan follows the entry path to the first return (fall-through at a
// conditional branch, the target of a direct jump; a call is stepped over
// and clobbers XMM0 and RAX) and looks at the last writes before it. A float
// return is reported only when the low lane of XMM0 was last written with a
// 4- or 8-byte value (a float operation or a scalar load such as movss /
// movsd) and RAX was not written after it. An integer return written to
// EAX/RAX later (cvttss2si eax, xmm0), a whole-register copy (movaps xmm0,
// xmm1), an indirect jump, or no return within the limit gives no answer.
func (c *CalleeReads) CalleeFloatReturn(entry address.Address) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.returns[entry.Offset]; ok {
		return r
	}
	if !c.ensureEngine(entry.Offset) || !c.retRegsOK {
		return 0
	}
	r := c.scanReturn(address.Address{Space: c.code, Offset: entry.Offset})
	c.returns[entry.Offset] = r
	return r
}

func (c *CalleeReads) scanReturn(at address.Address) int32 {
	const unset = -1
	seq := 0
	xmmSeq, xmmSize := unset, int32(0) // last write to XMM0's low lane
	raxSeq := unset
	seen := map[uint64]bool{}
	for n := 0; n < returnScanLimit && !seen[at.Offset]; n++ {
		seen[at.Offset] = true
		tr, err := c.engine.TranslateInstructionAt(at)
		if err != nil {
			return 0
		}
		next := tr.Next
	ops:
		for _, op := range tr.Ops {
			seq++
			if out := op.Output; out != nil && isRegister(*out) {
				if overlaps(*out, c.rax, 8) {
					raxSeq = seq
				}
				if overlaps(*out, c.xmm0, 4) {
					xmmSeq = seq
					xmmSize = 0
					if out.Offset == c.xmm0 && (out.Size == 4 || out.Size == 8) && op.OpCode != pcode.CPUI_INT_XOR {
						xmmSize = int32(out.Size)
					}
				}
			}
			switch op.OpCode {
			case pcode.CPUI_BRANCH:
				if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
					next = address.Address{Space: t.Space, Offset: t.Offset}
					break ops
				}
			case pcode.CPUI_CALL, pcode.CPUI_CALLIND:
				// The callee may overwrite both return registers.
				xmmSeq, xmmSize, raxSeq = seq, 0, seq
			case pcode.CPUI_BRANCHIND:
				return 0
			case pcode.CPUI_RETURN:
				if xmmSeq == unset || xmmSize == 0 || raxSeq > xmmSeq {
					return 0
				}
				return xmmSize
			}
		}
		at = next
	}
	return 0
}

// overlaps reports whether vn covers any of the size bytes at off.
func overlaps(vn pcode.VarnodeData, off uint64, size uint64) bool {
	return vn.Offset < off+size && off < vn.Offset+uint64(vn.Size)
}
