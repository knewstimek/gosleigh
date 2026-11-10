package analysis

import (
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// notInputScanLimit bounds the instructions visited over all paths.
const notInputScanLimit = 1024

// paramRegNames are the x64 register parameter slots checked by
// CalleeNotInputs.
var paramRegNames = []string{"RCX", "RDX", "R8", "R9", "XMM0", "XMM1", "XMM2", "XMM3"}

// paramReg is one register checked by CalleeNotInputs: the whole register
// (8 bytes, 16 for XMM) is a read target, its low 4 bytes must be covered for
// a write to replace the caller's value.
type paramReg struct {
	off, size uint64
}

// CalleeNotInputs implements pcode.HostCalleeNotInputs: the parameter
// registers the function at entry provably does not take from its caller.
//
// Every path from the entry is followed (both sides of a conditional branch,
// direct jumps, so a tail jump continues into its target). A register is not
// an input when no path reads it before writing it, and every path either
// writes it before reading it or reaches a return without touching it. A path
// ending anywhere else -- at a call (the callee may read it), an indirect
// jump, an undecodable instruction or the instruction limit -- with the
// register untouched leaves it undecided, so the answer is never a guess.
//
// Unlike CalleeReadsBeforeWrite a register stored to the home area counts as
// a read: the function may load it back later.
//
// The home stores also tell a slot's kind: x64 passes each of the first four
// parameters in either the integer or the XMM register of its slot, and MSVC
// homes the one used (mov [rsp+8], rcx or movss [rsp+8], xmm0). The other
// register of a homed slot is not an input.
func (c *CalleeReads) CalleeNotInputs(entry address.Address) []pcode.HostStorage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.notInputs[entry.Offset]; ok {
		return r
	}
	if !c.prog.IsExec(entry.Offset) || !c.ensureEngine(entry.Offset) || len(c.params) == 0 {
		return nil
	}
	r := c.scanNotInputs(address.Address{Space: c.code, Offset: entry.Offset})
	c.reads(entry.Offset)
	r = c.addOtherSlotRegs(r, c.homes[entry.Offset])
	// Stack slots past the last one any path reads are not inputs (needs the
	// full-path scan of CalleeInputs; not for a possible varargs function).
	if in := c.inputsOf(entry.Offset); in.complete && !in.mayBeVarargs {
		from := uint64(stackParamBase + 8*(in.lastStack+1))
		r = append(r, pcode.HostStorage{Space: "stack", Offset: from, Size: int32(stackParamBase + 8*stackSlots - int(from))})
	}
	c.notInputs[entry.Offset] = r
	return r
}

// addOtherSlotRegs adds, for each homed parameter slot, the slot's register
// that was not homed (c.params: four integer then four XMM registers).
func (c *CalleeReads) addOtherSlotRegs(r []pcode.HostStorage, homes []homeStore) []pcode.HostStorage {
	const slots = 4
	var homed [2 * slots]bool
	for _, h := range homes {
		s := int(h.disp/8) - 1
		if h.disp%8 != 0 || s < 0 || s >= slots {
			continue
		}
		for _, k := range []int{s, s + slots} {
			if c.params[k].off == h.reg {
				homed[k] = true
			}
		}
	}
	for s := 0; s < slots; s++ {
		for _, pair := range [][2]int{{s, s + slots}, {s + slots, s}} {
			if k, other := pair[0], pair[1]; homed[k] && !homed[other] {
				p := c.params[other]
				r = appendStorage(r, pcode.HostStorage{Space: "register", Offset: p.off, Size: int32(p.size)})
			}
		}
	}
	return r
}

func appendStorage(r []pcode.HostStorage, s pcode.HostStorage) []pcode.HostStorage {
	for _, x := range r {
		if x == s {
			return r
		}
	}
	return append(r, s)
}

func (c *CalleeReads) scanNotInputs(at address.Address) []pcode.HostStorage {
	type state struct {
		at      uint64
		written uint32 // bit k: c.params[k] written on this path
	}
	var read, open uint32 // read on some path; untouched where a path stopped early
	all := uint32(1)<<len(c.params) - 1

	budget := notInputScanLimit
	seen := map[state]bool{}
	work := []state{{at: at.Offset}}
	for len(work) > 0 {
		p := work[len(work)-1]
		work = work[:len(work)-1]
		done := false // the path reached a return
	path:
		for {
			if seen[p] {
				done = true // already followed from here with this state
				break path
			}
			if budget == 0 {
				break
			}
			seen[p] = true
			budget--
			tr, err := c.translate(address.Address{Space: c.code, Offset: p.at})
			if err != nil {
				break
			}
			next := tr.Next.Offset
			for i, op := range tr.Ops {
				if !noRead(tr.Ops, i) {
					for _, in := range op.Inputs {
						if isRegister(in) {
							read |= c.paramMask(in, false) &^ p.written
						}
					}
				}
				if out := op.Output; out != nil && isRegister(*out) {
					p.written |= c.paramMask(*out, true)
				}
				switch op.OpCode {
				case pcode.CPUI_BRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						next = t.Offset
						break
					}
					continue
				case pcode.CPUI_CBRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						work = append(work, state{at: t.Offset, written: p.written})
					}
					continue
				case pcode.CPUI_RETURN:
					done = true
					break path
				case pcode.CPUI_CALL, pcode.CPUI_CALLIND, pcode.CPUI_BRANCHIND:
					break path
				default:
					continue
				}
				break // a direct jump: the rest of the instruction is not reached
			}
			p.at = next
		}
		if !done {
			open |= all &^ p.written
		}
	}
	var out []pcode.HostStorage
	for k, r := range c.params {
		if (read|open)&(1<<k) == 0 {
			out = append(out, pcode.HostStorage{Space: "register", Offset: r.off, Size: int32(r.size)})
		}
	}
	return out
}

// paramMask is the set of parameter registers vn reads (any overlap) or,
// with write set, replaces (covers the low 4 bytes).
func (c *CalleeReads) paramMask(vn pcode.VarnodeData, write bool) uint32 {
	var m uint32
	for k, r := range c.params {
		if write {
			if vn.Offset <= r.off && vn.Offset+uint64(vn.Size) >= r.off+4 {
				m |= 1 << k
			}
		} else if overlaps(vn, r.off, r.size) {
			m |= 1 << k
		}
	}
	return m
}

// findParams fills c.params from paramRegNames; empty when any is missing.
func (c *CalleeReads) findParams() {
	var ps []paramReg
	for _, n := range paramRegNames {
		off, ok := c.registerOffset(n)
		if !ok {
			return
		}
		size := uint64(8)
		if n[0] == 'X' {
			size = 16
		}
		ps = append(ps, paramReg{off, size})
	}
	c.params = ps
}
