package analysis

import (
	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/pcode"
)

// inputScanLimit bounds the instructions visited over all paths of one
// function by CalleeInputs.
const inputScanLimit = 4096

// Stack parameters live at entry RSP + 0x28 + 8*k on x64 (return address,
// then the 0x20-byte home area); stackSlots of them are tracked.
const (
	stackParamBase = 0x28
	stackSlots     = 24
)

// slotRead is what a function reads of one parameter location before writing
// it: the widest read, whether it was used as a float, and for an XMM
// register the widest scalar (4- or 8-byte) read. A whole-register read
// (roundsd as a user op, a 16-byte store) shows the parameter exists but not
// its size.
type slotRead struct {
	size   int32
	float  bool
	scalar int32
}

// inferredInputs is the CalleeInputs answer for one entry.
type inferredInputs struct {
	params []pcode.HostParam
	ok     bool
	// reg are the register reads (c.params order) for a caller passing them on.
	reg [8]slotRead
}

// inputPath is the state along one path of scanInputs.
type inputPath struct {
	at       uint64
	written  uint8    // c.params written (or clobbered by a call)
	stackW   uint32   // stack parameter slots written
	sp, rbp  int64    // entry-relative values; valid when the bit is set in spOK
	r11      int64    //
	spOK     uint8    // bit 0 RSP, 1 RBP, 2 R11
	xmmParam [16]int8 // XMM register -> index into c.params it still holds (-1 none)
}

func (p *inputPath) key() inputPath { return *p }

// CalleeInputs implements pcode.HostCalleePrototype: the full input list of
// the function at entry (x64), when it can be inferred with certainty.
//
// Every path is followed (both sides of a conditional branch; a direct jump,
// so a tail jump continues into its target) with the stack pointer tracked
// relative to the entry. A parameter register read before it is written is an
// input, sized by the widest read (an XMM register copied whole, movaps xmm6,
// xmm3, is sized by the scalar use of the copy); a stack location at entry
// RSP + 0x28 + 8k loaded before it is stored is an input, a float when loaded
// into an XMM register. A call clobbers the parameter registers, but one not
// touched before it may be passed on: it is an input when the callee reads it
// before writing (CalleeReadsBeforeWrite), as Ghidra's core rescued by that
// hint would take it, and not otherwise. After a dynamic allocation (sub rsp,
// rax) RSP is no longer followed, but stack accesses through a frame register
// set before it (RBP, R11) still are.
//
// Only a function with stack parameters is answered, and not one homing R9
// (maybe varargs); see buildInputs. The answer is given only when every path
// was followed to its end within
// inputScanLimit, no indirect jump was met, no call to an unknown target met
// an untouched parameter register, and each of the four register
// slots is used as an integer or as a float but not both. The list is the
// four register slots up to the last one used (an unused slot before it is
// an 8-byte integer placeholder; all four when stack parameters follow) and
// then every stack slot up to the last one read.
func (c *CalleeReads) CalleeInputs(entry address.Address) ([]pcode.HostParam, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.prog.IsExec(entry.Offset) || !c.ensureEngine(entry.Offset) || len(c.params) != 8 || !c.spOK {
		return nil, false
	}
	r := c.inputsOf(entry.Offset)
	return r.params, r.ok
}

// inputsOf is CalleeInputs under c.mu, cached per entry.
func (c *CalleeReads) inputsOf(entry uint64) *inferredInputs {
	if r, ok := c.inputs[entry]; ok {
		return r
	}
	r := c.scanInputs(entry)
	c.inputs[entry] = r
	return r
}

func (c *CalleeReads) scanInputs(entry uint64) *inferredInputs {
	fail := &inferredInputs{}
	var reg [8]slotRead
	var stack [stackSlots]slotRead
	budget := inputScanLimit
	seen := map[inputPath]bool{}
	start := inputPath{at: entry, spOK: 1}
	for k := range start.xmmParam {
		start.xmmParam[k] = -1
		for j := 4; j < 8; j++ {
			if c.xmmBase[k] == c.params[j].off {
				start.xmmParam[k] = int8(j) // XMM0..3 hold their own slot's value
			}
		}
	}
	work := []inputPath{start}
	for len(work) > 0 {
		p := work[len(work)-1]
		work = work[:len(work)-1]
		for {
			if seen[p.key()] {
				break
			}
			seen[p.key()] = true
			if budget == 0 {
				return fail
			}
			budget--
			tr, err := c.engine.TranslateInstructionAt(address.Address{Space: c.code, Offset: p.at})
			if err != nil {
				return fail
			}
			next, end := tr.Next.Offset, false
			uniq := map[uint64]int64{} // unique temp -> entry-relative stack address
			loaded := map[uint64]int{} // unique temp -> stack slot it was loaded from
		ops:
			for i, op := range tr.Ops {
				if !noRead(tr.Ops, i) {
					for _, in := range op.Inputs {
						if isRegister(in) {
							c.noteParamRead(&p, in, op, &reg)
						}
					}
				}
				switch op.OpCode {
				case pcode.CPUI_LOAD:
					if d, ok := c.stackAddr(&p, uniq, op.Inputs[1]); ok {
						if s, in := stackSlot(d, int32(op.Output.Size)); in && p.stackW&(1<<s) == 0 {
							_, isXMM := c.xmmIndex(*op.Output)
							widen(&stack[s], int32(d-stackParamBase-int64(s)*8)+int32(op.Output.Size), isXMM && isRegister(*op.Output))
							if op.Output.Space != nil && op.Output.Space.Name == "unique" {
								loaded[op.Output.Offset] = s
							}
						}
					}
				case pcode.CPUI_STORE:
					if d, ok := c.stackAddr(&p, uniq, op.Inputs[1]); ok {
						if s, in := stackSlot(d, int32(op.Inputs[2].Size)); in {
							p.stackW |= 1 << s
						}
					}
				case pcode.CPUI_CALL, pcode.CPUI_CALLIND:
					if !c.passOn(&p, op, &reg) {
						return fail
					}
					p.sp += 8 // the callee's ret pops the pushed return address
				case pcode.CPUI_BRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						next = t.Offset
						break ops
					}
				case pcode.CPUI_CBRANCH:
					if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
						q := p
						q.at = t.Offset
						work = append(work, q)
					}
				case pcode.CPUI_BRANCHIND:
					// With RSP back at its entry value this is a tail jump
					// (virtual dispatch: jmp [vtable+n]) and ends the path,
					// provided no parameter register is left undecided for the
					// unknown target. Otherwise a switch or computed jump whose
					// paths are not followed.
					if p.spOK&1 == 0 || p.sp != 0 || !c.passOn(&p, op, &reg) {
						return fail
					}
					end = true
					break ops
				case pcode.CPUI_RETURN:
					end = true
					break ops
				}
				if op.Output != nil {
					// movss xmm0, [rsp+x]: the load goes through a temporary.
					if op.OpCode == pcode.CPUI_COPY && isRegister(*op.Output) && op.Inputs[0].Space != nil && op.Inputs[0].Space.Name == "unique" {
						if s, ok := loaded[op.Inputs[0].Offset]; ok {
							if _, isXMM := c.xmmIndex(*op.Output); isXMM {
								stack[s].float = true
							}
						}
					}
					c.trackWrite(&p, uniq, op)
				}
			}
			if end {
				break
			}
			p.at = next
		}
	}
	return c.buildInputs(reg, stack, c.homesR9(entry))
}

// noteParamRead records a read of a parameter register (or of an XMM register
// still holding one) before the path wrote it.
func (c *CalleeReads) noteParamRead(p *inputPath, in pcode.VarnodeData, op pcode.RawOp, reg *[8]slotRead) {
	for k, r := range c.params {
		if !overlaps(in, r.off, r.size) || p.written&(1<<k) != 0 {
			continue
		}
		if k >= 4 && in.Offset == r.off && in.Size == 16 && op.OpCode == pcode.CPUI_COPY {
			continue // a whole-register copy: sized by the copy's use (trackWrite)
		}
		widen(&reg[k], int32(in.Size), k >= 4)
	}
	// A copy of an XMM parameter used as a scalar sizes the parameter.
	if x, ok := c.xmmIndex(in); ok && in.Offset == c.xmmBase[x] && in.Size < 16 {
		if k := p.xmmParam[x]; k >= 0 && p.written&(1<<k) == 0 && c.xmmBase[x] != c.params[k].off {
			widen(&reg[k], int32(in.Size), true)
		}
	}
}

// trackWrite updates the path for an op's output: parameter registers
// written, XMM copies of parameters, and the stack pointer and its copies.
func (c *CalleeReads) trackWrite(p *inputPath, uniq map[uint64]int64, op pcode.RawOp) {
	out := *op.Output
	if out.Space != nil && out.Space.Name == "unique" {
		if d, ok := c.spValue(p, uniq, op); ok {
			uniq[out.Offset] = d
		} else {
			delete(uniq, out.Offset)
		}
		return
	}
	if !isRegister(out) {
		return
	}
	// XMM: a whole copy of a register holding a parameter keeps it; any other
	// write of the low lane ends it.
	if x, ok := c.xmmIndex(out); ok {
		p.xmmParam[x] = -1
		if op.OpCode == pcode.CPUI_COPY && out.Offset == c.xmmBase[x] && out.Size == 16 && isRegister(op.Inputs[0]) {
			if y, ok := c.xmmIndex(op.Inputs[0]); ok && op.Inputs[0].Offset == c.xmmBase[y] {
				if k := p.xmmParam[y]; k >= 0 && p.written&(1<<k) == 0 {
					p.xmmParam[x] = k
				}
			}
		}
	}
	for k, r := range c.params {
		if out.Offset <= r.off && out.Offset+uint64(out.Size) >= r.off+4 {
			p.written |= 1 << k
		}
	}
	for i, reg := range []uint64{c.sp, c.rbp, c.r11} {
		if out.Offset != reg || out.Size != 8 {
			continue
		}
		d, ok := c.spValue(p, uniq, op)
		switch {
		case ok:
			p.setSP(i, d)
		default:
			p.spOK &^= 1 << i // e.g. RSP after sub rsp, rax
		}
	}
}

func (p *inputPath) setSP(i int, d int64) {
	p.spOK |= 1 << i
	switch i {
	case 0:
		p.sp = d
	case 1:
		p.rbp = d
	default:
		p.r11 = d
	}
}

// spValue is the entry-relative stack address op computes, if any: a copy of,
// or a constant added to or subtracted from, a value holding one.
func (c *CalleeReads) spValue(p *inputPath, uniq map[uint64]int64, op pcode.RawOp) (int64, bool) {
	isConst := func(v pcode.VarnodeData) bool { return v.Space != nil && v.Space.IsConstant() }
	switch op.OpCode {
	case pcode.CPUI_COPY:
		return c.stackAddr(p, uniq, op.Inputs[0])
	case pcode.CPUI_INT_ADD:
		if d, ok := c.stackAddr(p, uniq, op.Inputs[0]); ok && isConst(op.Inputs[1]) {
			return d + int64(op.Inputs[1].Offset), true
		}
		if d, ok := c.stackAddr(p, uniq, op.Inputs[1]); ok && isConst(op.Inputs[0]) {
			return d + int64(op.Inputs[0].Offset), true
		}
	case pcode.CPUI_INT_SUB:
		if d, ok := c.stackAddr(p, uniq, op.Inputs[0]); ok && isConst(op.Inputs[1]) {
			return d - int64(op.Inputs[1].Offset), true
		}
	}
	return 0, false
}

// stackAddr is the entry-relative stack address v holds, if known.
func (c *CalleeReads) stackAddr(p *inputPath, uniq map[uint64]int64, v pcode.VarnodeData) (int64, bool) {
	if v.Space != nil && v.Space.Name == "unique" {
		d, ok := uniq[v.Offset]
		return d, ok
	}
	if !isRegister(v) || v.Size != 8 {
		return 0, false
	}
	switch {
	case v.Offset == c.sp && p.spOK&1 != 0:
		return p.sp, true
	case v.Offset == c.rbp && p.spOK&2 != 0:
		return p.rbp, true
	case v.Offset == c.r11 && p.spOK&4 != 0:
		return p.r11, true
	}
	return 0, false
}

// passOn handles a call on the path: parameter registers not touched before
// it are inputs when the callee reads them (passed on unchanged), and then
// all are clobbered. False when such a register meets a callee whose inputs
// are unknown.
func (c *CalleeReads) passOn(p *inputPath, op pcode.RawOp, reg *[8]slotRead) bool {
	untouched := ^p.written
	for k := range c.params {
		// Already known to be an input, or its slot is (one slot is passed in
		// its integer or its XMM register, never both).
		if untouched&(1<<k) != 0 && (reg[k].size != 0 || reg[k^4].size != 0) {
			untouched &^= 1 << k
		}
	}
	if untouched != 0 {
		t := op.Inputs[0]
		if op.OpCode != pcode.CPUI_CALL || t.Space == nil || t.Space.IsConstant() || !c.prog.IsExec(t.Offset) {
			return false // the target, and so what it takes, is unknown
		}
		// Ghidra's core does not take a register passed on unchanged as an
		// input of the function passing it (AncestorRealistic); it is one
		// when the callee reads it before writing (as CalleeReadsBeforeWrite
		// rescues it at the call), else it is not.
		inner := c.reads(t.Offset)
		for k, r := range c.params {
			if untouched&(1<<k) == 0 {
				continue
			}
			for _, s := range inner {
				if s.Offset <= r.off && r.off < s.Offset+uint64(s.Size) {
					n := int32(s.Offset + uint64(s.Size) - r.off)
					if n > int32(r.size) {
						n = int32(r.size)
					}
					if k >= 4 && n > 8 {
						n = 0 // a whole XMM register: no scalar size, decided below
					}
					widen(&reg[k], n, k >= 4)
					if n == 0 {
						reg[k].size = 16
					}
				}
			}
		}
	}
	p.written = 0xff
	for x := range p.xmmParam {
		p.xmmParam[x] = -1
	}
	return true
}

// stackSlot is the stack parameter slot an access of size bytes at the
// entry-relative address d falls in.
func stackSlot(d int64, size int32) (int, bool) {
	if d < stackParamBase {
		return 0, false
	}
	s := (d - stackParamBase) / 8
	if s >= stackSlots || (d-stackParamBase)%8+int64(size) > 8 {
		return 0, false
	}
	return int(s), true
}

func widen(r *slotRead, size int32, float bool) {
	if size > r.size {
		r.size = size
	}
	if float && (size == 4 || size == 8) && size > r.scalar {
		r.scalar = size
	}
	r.float = r.float || float
}

// buildInputs turns the reads into the input list, or not ok.
func (c *CalleeReads) buildInputs(reg [8]slotRead, stack [stackSlots]slotRead, mayBeVarargs bool) *inferredInputs {
	res := &inferredInputs{reg: reg}
	lastStack := -1
	for s := range stack {
		if stack[s].size != 0 {
			lastStack = s
		}
	}
	// Locked: a function with stack parameters, or one whose parameters are
	// all floats. Other register-only functions are already served by the
	// read and not-input hints, which leave each argument's size to the caller
	// (an integer lock sized by a 64-bit register copy prints casts); a float
	// size comes from a scalar operation and is exact, and the lock fixes a
	// double argument the caller's heritage split to 4 bytes (SUB84(d, 0)).
	// A function homing R9 may be varargs: its parameter count is not knowable.
	floatsOnly := false
	for s := 0; s < 4; s++ {
		if reg[s].size != 0 {
			floatsOnly = false
			break
		}
		floatsOnly = floatsOnly || reg[s+4].size != 0
	}
	if (lastStack < 0 && !floatsOnly) || mayBeVarargs {
		return res
	}
	lastReg := -1
	for s := 0; s < 4; s++ {
		if reg[s].size != 0 && reg[s+4].size != 0 {
			return res // integer and float use of one slot
		}
		if reg[s].size != 0 || reg[s+4].size != 0 {
			lastReg = s
		}
		if reg[s+4].size != 0 && reg[s+4].scalar == 0 {
			return res // an XMM parameter never used as a scalar
		}
	}
	if lastStack >= 0 {
		lastReg = 3
	}
	var params []pcode.HostParam
	for s := 0; s <= lastReg; s++ {
		k, r := s, reg[s]
		if reg[s+4].size != 0 {
			k, r = s+4, reg[s+4]
			r.size = r.scalar
		} else if r.size == 0 {
			r.size = 8 // unused slot before a used one
		}
		params = append(params, hostParam("register", c.params[k].off, r))
	}
	for s := 0; s <= lastStack; s++ {
		r := stack[s]
		if r.size == 0 {
			r.size = 8
		}
		params = append(params, hostParam("stack", uint64(stackParamBase+8*s), r))
	}
	res.params, res.ok = params, true
	return res
}

// homesR9 reports that the function's entry path stores R9 to its home slot.
func (c *CalleeReads) homesR9(entry uint64) bool {
	c.reads(entry)
	for _, h := range c.homes[entry] {
		if h.disp == 0x20 && h.reg == c.params[3].off {
			return true
		}
	}
	return false
}

func hostParam(space string, off uint64, r slotRead) pcode.HostParam {
	desc := &pcode.HostTypeDesc{Name: undefinedName(r.size), Meta: "unknown", Size: r.size}
	if r.float && (r.size == 4 || r.size == 8) {
		desc = &pcode.HostTypeDesc{Name: "float", Meta: "float", Size: r.size}
		if r.size == 8 {
			desc.Name = "double"
		}
	}
	return pcode.HostParam{Space: space, Offset: off, Size: r.size, Type: pcode.ResolveHostType(desc)}
}

func undefinedName(size int32) string {
	switch size {
	case 1:
		return "undefined1"
	case 2:
		return "undefined2"
	case 4:
		return "undefined4"
	}
	return "undefined8"
}
