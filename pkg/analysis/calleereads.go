// Package analysis holds whole-program analyses that Ghidra runs on its Java
// side, outside the decompiler core, and hands to the core as facts about
// other functions (Ghidra: analyzers such as Decompiler Parameter ID writing
// prototypes to the program database). Nothing here is a port of Ghidra's
// C++ core; every analysis is opt-in and listed in DIFFERENCES.md.
package analysis

import (
	"fmt"
	"sort"
	"sync"

	"github.com/knewstimek/gosleigh/pkg/address"
	"github.com/knewstimek/gosleigh/pkg/decomp"
	"github.com/knewstimek/gosleigh/pkg/pcode"
	"github.com/knewstimek/gosleigh/pkg/sla"
)

// calleeScanLimit bounds the instructions followed from a callee's entry.
// Parameters are read near the entry; a short scan keeps a decompile with
// many callees cheap and stops before unrelated code.
const calleeScanLimit = 64

// CalleeReads finds, for a function entry, the registers the function reads
// before writing them along its entry path. Set it as
// decomp.Function.CalleeReads; it implements pcode.HostCalleeReads. Results
// are cached per entry and it is safe for concurrent use.
//
// The scan follows one path from the entry: fall-through at a conditional
// branch, the target of a direct jump, and it stops at a call, an indirect
// jump, a return, an undecodable instruction or after calleeScanLimit
// instructions. A read on that path before any write is evidence the
// register carries a value in; a write first, or no read before the stop,
// gives no evidence (never a claim that the register is unused). An
// instruction combining a register with itself into a value that does not
// depend on it (xor ecx, ecx; sub eax, eax) is not a read, and neither is
// storing a register to the caller's home area ([rsp+8]..[rsp+0x20] before
// the stack pointer moves): a varargs function homes every parameter
// register whether or not it was passed one.
//
// The core applies the hint only to an argument candidate Ghidra already
// has and left inactive. A candidate exists only for a register the caller
// touches somewhere (MSVC homes its register parameters, so they usually
// are); a caller that never touches it gets no candidate and no argument,
// as in Ghidra.
type CalleeReads struct {
	prog *decomp.Program

	mu     sync.Mutex
	engine *sla.Engine
	code   *address.Space
	sp     uint64 // stack pointer register offset; spOK when it was found
	spOK   bool

	// rax, xmm0 are the return registers' offsets (retRegsOK when found);
	// returns caches CalleeFloatReturn.
	rax, xmm0 uint64
	xmmBase   [16]uint64 // XMM0..XMM15 offsets, for CalleeFloatReturn
	retRegsOK bool
	returns   map[uint64]int32
	cache     map[uint64][]pcode.HostStorage
	// params are the register parameter slots and notInputs caches
	// CalleeNotInputs.
	params    []paramReg
	notInputs map[uint64][]pcode.HostStorage
	homes     map[uint64][]homeStore // home-area stores of the entry path, per entry
}

// NewCalleeReads returns a CalleeReads over prog's image.
func NewCalleeReads(prog *decomp.Program) *CalleeReads {
	return &CalleeReads{prog: prog, cache: map[uint64][]pcode.HostStorage{}, returns: map[uint64]int32{},
		notInputs: map[uint64][]pcode.HostStorage{}, homes: map[uint64][]homeStore{}}
}

// CalleeReadsBeforeWrite implements pcode.HostCalleeReads.
func (c *CalleeReads) CalleeReadsBeforeWrite(entry address.Address) []pcode.HostStorage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.cache[entry.Offset]; ok {
		return r
	}
	if !c.prog.IsExec(entry.Offset) || !c.ensureEngine(entry.Offset) {
		return nil
	}
	return c.reads(entry.Offset)
}

// reads is CalleeReadsBeforeWrite under c.mu, caching the home-area stores
// of the same scan for CalleeNotInputs.
func (c *CalleeReads) reads(entry uint64) []pcode.HostStorage {
	if r, ok := c.cache[entry]; ok {
		return r
	}
	r, homes := c.scanReads(address.Address{Space: c.code, Offset: entry})
	r = c.addHomedRegs(r, homes)
	c.cache[entry], c.homes[entry] = r, homes
	return r
}

// addHomedRegs counts homed parameter registers as read. A homed XMM register
// always counts (movsd [rsp+8], xmm0: a double parameter). A homed integer
// register counts only when R9 is not homed: a varargs function homes the
// variadic slots up to the last one (R9) whatever it was passed, so there
// homing is no evidence (counting it gave junk arguments to varargs calls),
// and a fixed-parameter function homing all four is left without it.
func (c *CalleeReads) addHomedRegs(r []pcode.HostStorage, homes []homeStore) []pcode.HostStorage {
	const slots = 4
	if len(c.params) < 2*slots {
		return r
	}
	var homed [2 * slots]bool // c.params order: four integer, four XMM
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
	for k, ok := range homed {
		if ok && (k >= slots || !homed[slots-1]) {
			r = appendStorage(r, pcode.HostStorage{Space: "register", Offset: c.params[k].off, Size: int32(c.params[k].size)})
		}
	}
	return r
}

// ensureEngine builds the shared engine on first use. Callers hold c.mu.
func (c *CalleeReads) ensureEngine(entry uint64) bool {
	if c.engine != nil {
		return true
	}
	engine, at, err := c.prog.NewEngine(entry)
	if err != nil {
		return false
	}
	c.engine, c.code = engine, at.Space
	c.sp, c.spOK = registerOffset(engine, "RSP")
	rax, okA := registerOffset(engine, "RAX")
	xmm0, okX := registerOffset(engine, "XMM0")
	c.rax, c.xmm0 = rax, xmm0
	c.retRegsOK = okA && okX && c.findXMM()
	c.findParams()
	return true
}

// homeStore is a register stored to the caller's home area at disp (8..0x20)
// on the entry path before the function wrote it: MSVC homes a parameter
// register into its own slot, the integer or the XMM register the slot is
// passed in.
type homeStore struct {
	disp uint64
	reg  uint64
}

// scanReads walks the entry path and returns the register bytes read before
// written, merged into ranges, and the parameter registers it homes.
func (c *CalleeReads) scanReads(at address.Address) ([]pcode.HostStorage, []homeStore) {
	var homes []homeStore
	written := map[uint64]bool{}
	read := map[uint64]bool{}
	seen := map[uint64]bool{}
	// spCopies are registers holding the entry stack pointer (mov r11, rsp),
	// through which a prologue may home the parameter registers.
	spCopies := map[uint64]bool{}
	for n := 0; n < calleeScanLimit && !seen[at.Offset]; n++ {
		seen[at.Offset] = true
		tr, err := c.engine.TranslateInstructionAt(at)
		if err != nil {
			break
		}
		next, stop := tr.Next, false
		homed, h := c.homingCopies(tr.Ops, written, spCopies)
		homes = append(homes, h...)
	ops:
		for i, op := range tr.Ops {
			if homed[i] {
				continue
			}
			if !selfCombine(op) {
				for _, in := range op.Inputs {
					if isRegister(in) {
						for b := in.Offset; b < in.Offset+uint64(in.Size); b++ {
							if !written[b] {
								read[b] = true
							}
						}
					}
				}
			}
			if out := op.Output; out != nil && isRegister(*out) {
				c.noteSPCopy(op, written, spCopies)
				for b := out.Offset; b < out.Offset+uint64(out.Size); b++ {
					written[b] = true
				}
			}
			switch op.OpCode {
			case pcode.CPUI_BRANCH:
				// A p-code relative branch (constant space) stays inside the
				// instruction; a direct jump moves the path to its target.
				if t := op.Inputs[0]; t.Space != nil && !t.Space.IsConstant() {
					next = address.Address{Space: t.Space, Offset: t.Offset}
					break ops
				}
			case pcode.CPUI_BRANCHIND, pcode.CPUI_CALL, pcode.CPUI_CALLIND, pcode.CPUI_RETURN:
				stop = true
				break ops
			}
		}
		if stop {
			break
		}
		at = next
	}
	if c.spOK { // the stack pointer is never an argument
		for b := c.sp; b < c.sp+8; b++ {
			delete(read, b)
		}
	}
	return mergeBytes(read), homes
}

// homingCopies marks the ops of one instruction that store a register to
// the caller's home area, [entry rsp + 8 .. + 0x20], addressed through RSP
// before it moves or through a register holding the entry RSP: the STORE and
// the COPY of the register into the temporary it stores (Sleigh: tmp = 8 +
// RSP; val = RCX; *tmp = val).
func (c *CalleeReads) homingCopies(ops []pcode.RawOp, written, spCopies map[uint64]bool) (map[int]bool, []homeStore) {
	if !c.spOK || (written[c.sp] && len(spCopies) == 0) {
		return nil, nil
	}
	var homes []homeStore
	// RSP itself counts while it has its entry value; a copy keeps that value
	// after RSP moves (mov r11, rsp ... sub rsp, n ... mov [r11+0x18], r8).
	isSP := func(v pcode.VarnodeData) bool {
		return isRegister(v) && ((v.Offset == c.sp && !written[c.sp]) || spCopies[v.Offset])
	}
	isConst := func(v pcode.VarnodeData) bool { return v.Space != nil && v.Space.IsConstant() }
	isUnique := func(v *pcode.VarnodeData) bool { return v != nil && v.Space != nil && v.Space.Name == "unique" }
	spDisp := map[uint64]uint64{} // temporary -> k where it holds rsp+k
	regCopy := map[uint64]int{}   // temporary -> index of the COPY from a register
	var out map[int]bool
	for i, op := range ops {
		switch {
		case op.OpCode == pcode.CPUI_INT_ADD && isUnique(op.Output) && len(op.Inputs) == 2:
			if isSP(op.Inputs[0]) && isConst(op.Inputs[1]) {
				spDisp[op.Output.Offset] = op.Inputs[1].Offset
			} else if isConst(op.Inputs[0]) && isSP(op.Inputs[1]) {
				spDisp[op.Output.Offset] = op.Inputs[0].Offset
			}
		case op.OpCode == pcode.CPUI_COPY && isUnique(op.Output) && len(op.Inputs) == 1 && isRegister(op.Inputs[0]):
			regCopy[op.Output.Offset] = i
		case op.OpCode == pcode.CPUI_STORE && len(op.Inputs) == 3:
			ptr, val := op.Inputs[1], op.Inputs[2]
			k, ok := spDisp[ptr.Offset]
			if !ok || !isUnique(&ptr) || k < 8 || k > 0x20 {
				continue
			}
			cp, isCopy := regCopy[val.Offset]
			if !isCopy && !isRegister(val) {
				continue
			}
			if out == nil {
				out = map[int]bool{}
			}
			out[i] = true
			src := val
			if isCopy {
				out[cp] = true
				src = ops[cp].Inputs[0]
			}
			if !written[src.Offset] {
				homes = append(homes, homeStore{k, src.Offset})
			}
		}
	}
	return out, homes
}

// noteSPCopy keeps spCopies current for an op writing a register: a copy of
// the entry stack pointer (or of a register holding it) joins, any other
// write leaves.
func (c *CalleeReads) noteSPCopy(op pcode.RawOp, written, spCopies map[uint64]bool) {
	out := op.Output.Offset
	if c.spOK && op.OpCode == pcode.CPUI_COPY && len(op.Inputs) == 1 &&
		isRegister(op.Inputs[0]) && op.Inputs[0].Size == 8 && op.Output.Size == 8 &&
		((op.Inputs[0].Offset == c.sp && !written[c.sp]) || spCopies[op.Inputs[0].Offset]) {
		spCopies[out] = true
		return
	}
	delete(spCopies, out)
}

// registerOffset finds a register's offset in the register space by name.
func registerOffset(engine *sla.Engine, name string) (uint64, bool) {
	for key, n := range engine.RegisterNamesByLocation() {
		if n != name {
			continue
		}
		var space, off, size uint64
		if _, err := fmt.Sscanf(key, "%d:%d:%d", &space, &off, &size); err == nil {
			return off, true
		}
	}
	return 0, false
}

// selfCombine reports an op whose result does not depend on its inputs
// because both are the same storage: xor/sub of a register with itself.
func selfCombine(op pcode.RawOp) bool {
	switch op.OpCode {
	case pcode.CPUI_INT_XOR, pcode.CPUI_INT_SUB, pcode.CPUI_BOOL_XOR:
		return len(op.Inputs) == 2 && op.Inputs[0] == op.Inputs[1]
	}
	return false
}

func isRegister(vn pcode.VarnodeData) bool {
	return vn.Space != nil && vn.Space.Name == "register"
}

// mergeBytes turns a byte set into ascending contiguous ranges.
func mergeBytes(bytes map[uint64]bool) []pcode.HostStorage {
	if len(bytes) == 0 {
		return nil
	}
	offs := make([]uint64, 0, len(bytes))
	for b := range bytes {
		offs = append(offs, b)
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	var out []pcode.HostStorage
	for _, b := range offs {
		if k := len(out) - 1; k >= 0 && out[k].Offset+uint64(out[k].Size) == b {
			out[k].Size++
			continue
		}
		out = append(out, pcode.HostStorage{Space: "register", Offset: b, Size: 1})
	}
	return out
}
