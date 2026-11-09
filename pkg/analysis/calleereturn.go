package analysis

import (
	"fmt"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// returnScanLimit bounds the instructions visited from a callee's entry over
// all of its paths.
const returnScanLimit = 2048

// returnCallDepth bounds how far "call g; ret" is followed into g.
const returnCallDepth = 3

// Lane tags for the low lane of an XMM register.
const (
	laneUnknown int32 = 0  // not written on the path, or by something we cannot size
	laneZero    int32 = -1 // xorps x, x: 0.0 of either size
)

// CalleeFloatReturn implements pcode.HostCalleeReturn: 4 when the function
// at entry returns a float in XMM0, 8 for a double, 0 when unknown.
//
// Every path from the entry to a return is followed (both sides of a
// conditional branch, the target of a direct jump, so a tail jump continues
// into the function it jumps to), within returnScanLimit instructions. For
// each XMM register the size of the value last written to its low lane is
// tracked: a scalar float operation or load (movss, movsd, cvtdq2ps) sets
// 4 or 8, a whole-register copy (movaps xmm0, xmm6) passes the source's size
// on, xorps x, x gives 0.0 of either size, a direct call sets XMM0 to the
// callee's own float return (followed returnCallDepth deep) and any other
// write makes it unknown.
//
// A return path gives a size when XMM0's lane is sized, was not read again
// after that write (a void function's float scratch in XMM0 feeds a later
// operation; a result is written last) and RAX was not written after it; a path where RAX was written after XMM0 (cvttss2si eax,
// xmm0; an integer result) makes the whole answer 0. The result is the one
// size the sized paths agree on; 0.0-only paths agree with any size, and no
// sized path, two sizes, an indirect jump on every path or no return within
// the limit give 0.
func (c *CalleeReads) CalleeFloatReturn(entry address.Address) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ensureEngine(entry.Offset) || !c.retRegsOK {
		return 0
	}
	return c.floatReturn(entry.Offset, 0)
}

// floatReturn is CalleeFloatReturn under c.mu. A function being scanned is
// cached as 0 first, so recursion through a cycle answers unknown.
func (c *CalleeReads) floatReturn(entry uint64, depth int) int32 {
	if r, ok := c.returns[entry]; ok {
		return r
	}
	if !c.prog.IsExec(entry) { // an import slot: its bytes are a pointer
		return 0
	}
	c.returns[entry] = 0
	r := c.scanReturn(address.Address{Space: c.code, Offset: entry}, depth)
	c.returns[entry] = r
	return r
}

// returnPath is the register state along one path of scanReturn.
type returnPath struct {
	at      address.Address
	lane    [16]int32 // low-lane tag per XMM register
	xmmSeq  int       // sequence number of the last write to XMM0's low lane
	raxSeq  int       // sequence number of the last write to RAX
	xmmRead bool      // XMM0's low lane was read after its last write
}

// returnState identifies a path state at an instruction: reaching the same
// instruction with the same state again cannot give a new answer, while a
// different state (another register written on the way) is followed again.
type returnState struct {
	at       uint64
	lane     [16]int32
	raxAfter bool
	xmmRead  bool
}

func (c *CalleeReads) scanReturn(at address.Address, depth int) int32 {
	const unset = -1
	seq, budget := 0, returnScanLimit
	size := int32(0)
	seen := map[returnState]bool{}
	work := []returnPath{{at: at, xmmSeq: unset, raxSeq: unset}}
	for len(work) > 0 {
		p := work[len(work)-1]
		work = work[:len(work)-1]
	path:
		for budget > 0 {
			st := returnState{p.at.Offset, p.lane, p.raxSeq > p.xmmSeq, p.xmmRead}
			if seen[st] {
				break
			}
			seen[st] = true
			budget--
			tr, err := c.engine.TranslateInstructionAt(p.at)
			if err != nil {
				break
			}
			next := tr.Next
			for _, op := range tr.Ops {
				seq++
				if !selfCombine(op) {
					for _, in := range op.Inputs {
						if isRegister(in) && overlaps(in, c.xmmBase[0], 4) {
							p.xmmRead = true
						}
					}
				}
				if out := op.Output; out != nil && isRegister(*out) {
					if overlaps(*out, c.rax, 8) {
						p.raxSeq = seq
					}
					if k, ok := c.xmmIndex(*out); ok {
						p.lane[k] = c.laneTag(op, p.lane)
						if k == 0 {
							p.xmmSeq, p.xmmRead = seq, false
						}
					}
				}
				switch op.OpCode {
				case pcode.CPUI_BRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						next = address.Address{Space: t.Space, Offset: t.Offset}
						break
					}
					continue
				case pcode.CPUI_CBRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						q := p
						q.at = address.Address{Space: t.Space, Offset: t.Offset}
						work = append(work, q)
					}
					continue
				case pcode.CPUI_CALL, pcode.CPUI_CALLIND:
					// The callee may overwrite both return registers; a direct
					// callee known to return a float leaves it in XMM0.
					p.raxSeq, p.xmmSeq, p.xmmRead = seq, seq, false
					p.lane[0] = laneUnknown
					if t := op.Inputs[0]; op.OpCode == pcode.CPUI_CALL && depth < returnCallDepth &&
						t.Space != nil && !t.Space.IsConstant() {
						p.lane[0] = c.floatReturn(t.Offset, depth+1)
					}
					continue
				case pcode.CPUI_BRANCHIND:
					break path
				case pcode.CPUI_RETURN:
					if p.raxSeq > p.xmmSeq {
						return 0 // an integer result on this path
					}
					if l := p.lane[0]; l > 0 && !p.xmmRead {
						if size != 0 && size != l {
							return 0
						}
						size = l
					}
					break path
				default:
					continue
				}
				break // a direct jump: the rest of the instruction is not reached
			}
			p.at = next
		}
	}
	return size
}

// xmmIndex is the XMM register whose low lane out writes, if any.
func (c *CalleeReads) xmmIndex(out pcode.VarnodeData) (int, bool) {
	for k, base := range c.xmmBase {
		if overlaps(out, base, 4) {
			return k, true
		}
	}
	return 0, false
}

// laneTag is the low-lane tag an op writing an XMM low lane leaves.
func (c *CalleeReads) laneTag(op pcode.RawOp, lane [16]int32) int32 {
	out := *op.Output
	if selfCombine(op) {
		return laneZero // xorps x, x
	}
	if op.OpCode == pcode.CPUI_COPY && len(op.Inputs) == 1 && isRegister(op.Inputs[0]) &&
		op.Inputs[0].Size == out.Size && c.laneOffset(out.Offset) == 0 {
		for k, base := range c.xmmBase {
			if op.Inputs[0].Offset == base {
				return lane[k] // movaps xmm0, xmm6: the source's low lane
			}
		}
	}
	if op.OpCode != pcode.CPUI_INT_XOR && c.laneOffset(out.Offset) == 0 && (out.Size == 4 || out.Size == 8) {
		return int32(out.Size)
	}
	return laneUnknown
}

// laneOffset is out's byte offset inside the XMM register holding it.
func (c *CalleeReads) laneOffset(off uint64) uint64 {
	for _, base := range c.xmmBase {
		if off >= base && off < base+16 {
			return off - base
		}
	}
	return 0
}

// findXMM fills c.xmmBase; false when a register is missing (not x86-64).
func (c *CalleeReads) findXMM() bool {
	for k := range c.xmmBase {
		off, ok := registerOffset(c.engine, fmt.Sprintf("XMM%d", k))
		if !ok {
			return false
		}
		c.xmmBase[k] = off
	}
	return true
}

// overlaps reports whether vn covers any of the size bytes at off.
func overlaps(vn pcode.VarnodeData, off uint64, size uint64) bool {
	return vn.Offset < off+size && off < vn.Offset+uint64(vn.Size)
}
