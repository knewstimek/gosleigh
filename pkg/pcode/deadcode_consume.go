package pcode

import "math/bits"

// consumeAnalysis computes the per-Varnode "consumed" bit mask via backward
// propagation from sinks (RETURN/BRANCH/STORE, call parameters, auto-live
// Varnodes), mirroring the consume half of C++ ActionDeadCode::apply
// (coreaction.cc 3936-4034) plus its helpers pushConsumed / propagateConsumed /
// gatherConsumedReturn / markConsumedParameters.
//
// This is the foundation of a faithful consume-based dead-code pass and the H7
// return-recovery chain. It is intentionally DORMANT: the live ActionDeadCode
// (action_deadcode.go) is still descendant-count based, and nothing yet deletes
// ops from these consume values. computeConsumed only populates Varnode.Consumed()
// so the next H7 step (consume-based deadcode + return preservation) can build on
// a verified propagation core.
//
// Documented divergences from C++ (Gosleigh gaps, tracked in docs/STATUS.md H7):
//   - Pre-live registers (coreaction.cc 3960): C++ marks every Varnode in a
//     not-yet-heritaged deadcode space fully consumed. Gosleigh has no per-space
//     heritage-pass tracking (no numHeritagePasses / deadRemovalAllowed), so this
//     seeding is omitted. Return-register preservation instead relies on
//     gatherConsumedReturn (ActiveOutput / output-lock).
//   - NZMask is conservative: CalcNZMask is a stub and non-constant Varnodes
//     default to ~0, so the comparison and minimalmask consume masks are
//     over-approximated (never under-consumed -- safe, just less precise).
//   - markConsumedParameters uses the conservative "all call inputs fully
//     consumed" path; Gosleigh's call-spec input-consumed modeling is incomplete.
//   - The >8-byte precision corrections in SUBPIECE/PIECE/INT_LEFT (where a
//     Varnode exceeds the 64-bit consume field) are omitted; supported Varnodes
//     are <= 8 bytes.
type consumeAnalysis struct {
	worklist []*Varnode
	vacuous  map[*Varnode]bool // C++ Varnode::isConsumeVacuous
	inList   map[*Varnode]bool // C++ Varnode::isConsumeList
}

func newConsumeAnalysis() *consumeAnalysis {
	return &consumeAnalysis{
		vacuous: make(map[*Varnode]bool),
		inList:  make(map[*Varnode]bool),
	}
}

// coveringMask smears the highest set bit of val down to bit 0.
// C++ parity: coveringmask (address.cc 1056).
func coveringMask(val uint64) uint64 {
	res := val
	for sz := uint(1); sz < 64; sz <<= 1 {
		res |= res >> sz
	}
	return res
}

// minimalMask returns the smallest of the byte/uint2/uint4/uint8 masks that
// covers val. C++ parity: minimalmask (address.hh 568).
func minimalMask(val uint64) uint64 {
	if val > 0xffffffff {
		return ^uint64(0)
	}
	if val > 0xffff {
		return 0xffffffff
	}
	if val > 0xff {
		return 0xffff
	}
	return 0xff
}

// leastSigBitSet returns the index of the lowest set bit, or -1 if val is 0.
// C++ parity: leastsigbit_set (address.cc 970).
func leastSigBitSet(val uint64) int {
	if val == 0 {
		return -1
	}
	return bits.TrailingZeros64(val)
}

// push records a new consume contribution to vn and queues it for propagation.
// C++ parity: ActionDeadCode::pushConsumed (coreaction.cc 3563).
func (c *consumeAnalysis) push(val uint64, vn *Varnode) {
	if vn == nil {
		return
	}
	newval := (val | vn.Consumed()) & maskForSize(vn.Size())
	if newval == vn.Consumed() && c.vacuous[vn] {
		return
	}
	c.vacuous[vn] = true
	if !c.inList[vn] {
		c.inList[vn] = true
		if vn.IsWritten() {
			c.worklist = append(c.worklist, vn)
		}
	}
	vn.SetConsumed(newval)
}

// propagate pops one written Varnode and pushes its consume value backward to the
// inputs of its defining op. C++ parity: ActionDeadCode::propagateConsumed
// (coreaction.cc 3583).
func (c *consumeAnalysis) propagate() {
	vn := c.worklist[len(c.worklist)-1]
	c.worklist = c.worklist[:len(c.worklist)-1]
	outc := vn.Consumed()
	c.inList[vn] = false

	op := vn.Def()
	if op == nil {
		return
	}

	all := func(x uint64) uint64 { // (x == 0) ? 0 : ~0
		if x == 0 {
			return 0
		}
		return ^uint64(0)
	}
	var a, b uint64
	switch op.Code() {
	case CPUI_INT_MULT:
		b = coveringMask(outc)
		if op.Input(1).IsConstant() {
			if leastSet := leastSigBitSet(op.Input(1).Offset()); leastSet >= 0 {
				a = (maskForSize(vn.Size()) >> uint(leastSet)) & b
			}
		} else {
			a = b
		}
		c.push(a, op.Input(0))
		c.push(b, op.Input(1))
	case CPUI_INT_ADD, CPUI_INT_SUB:
		a = coveringMask(outc) // Make sure value is filled out as a contiguous mask
		c.push(a, op.Input(0))
		c.push(a, op.Input(1))
	case CPUI_SUBPIECE:
		sz := int(op.Input(1).Offset())
		if sz < 8 { // Truncating beyond the consume field tells nothing
			a = outc << uint(sz*8)
		}
		if a == 0 && outc != 0 && op.Input(0).Size() > 8 {
			// Upper bits beyond the consume field are consumed: set the
			// highest bit possible to indicate some consumption.
			a = ^uint64(0)
			a ^= a >> 1
		}
		c.push(a, op.Input(0))
		c.push(all(outc), op.Input(1))
	case CPUI_PIECE:
		sz := int(op.Input(1).Size())
		if vn.Size() > 8 { // Concatenation beyond the consume precision
			if sz >= 8 {
				a = ^uint64(0) // Bits not in the consume field are assumed consumed
				b = outc
			} else {
				a = (outc >> uint(sz*8)) ^ (^uint64(0) << uint(8*(8-sz)))
				b = outc ^ (a << uint(sz*8))
			}
		} else {
			a = outc >> uint(sz*8)
			b = outc ^ (a << uint(sz*8))
		}
		c.push(a, op.Input(0))
		c.push(b, op.Input(1))
	case CPUI_INDIRECT:
		c.push(outc, op.Input(0))
		if indop := op.Input(1).GetIndirectCause(); indop != nil && !indop.IsDead() {
			if indop.Code() == CPUI_COPY {
				if indop.Output().CharacterizeOverlap(op.Output()) > 0 {
					c.push(^uint64(0), indop.Output()) // Mark the copy as consumed
					indop.SetFlag(PcodeOpIndirectSource)
				}
			} else {
				indop.SetFlag(PcodeOpIndirectSource)
			}
		}
	case CPUI_COPY, CPUI_INT_NEGATE:
		c.push(outc, op.Input(0))
	case CPUI_INT_XOR, CPUI_INT_OR:
		c.push(outc, op.Input(0))
		c.push(outc, op.Input(1))
	case CPUI_INT_AND:
		if op.Input(1).IsConstant() {
			c.push(outc&op.Input(1).Offset(), op.Input(0))
		} else {
			c.push(outc, op.Input(0))
		}
		c.push(outc, op.Input(1))
	case CPUI_MULTIEQUAL:
		for i := 0; i < op.NumInput(); i++ {
			c.push(outc, op.Input(i))
		}
	case CPUI_INT_ZEXT:
		c.push(outc, op.Input(0))
	case CPUI_INT_SEXT:
		b = maskForSize(op.Input(0).Size())
		a = outc & b
		if outc > b {
			a |= b ^ (b >> 1) // Make sure signbit is marked used
		}
		c.push(a, op.Input(0))
	case CPUI_INT_LEFT:
		if op.Input(1).IsConstant() {
			sz := int(vn.Size())
			sa := int(op.Input(1).Offset())
			if sz > 8 { // Bits exist beyond the precision of the consume field
				switch {
				case sa >= 64:
					a = ^uint64(0) // Assume one bits where unrepresented bits shift in
				case sa == 0:
					a = outc
				default:
					a = (outc >> uint(sa)) ^ (^uint64(0) << uint(64-sa))
				}
				if rem := 8*sz - sa; rem < 64 {
					a &^= ^uint64(0) << uint(rem) // High bits shifted out are not consumed
				}
			} else if sa < 64 {
				a = outc >> uint(sa)
			}
			c.push(a, op.Input(0))
			c.push(all(outc), op.Input(1))
		} else {
			a = all(outc)
			c.push(a, op.Input(0))
			c.push(a, op.Input(1))
		}
	case CPUI_INT_RIGHT:
		if op.Input(1).IsConstant() {
			if sa := op.Input(1).Offset(); sa < 64 { // Beyond the consume field: nothing known
				a = outc << uint(sa)
			}
			c.push(a, op.Input(0))
			c.push(all(outc), op.Input(1))
		} else {
			a = all(outc)
			c.push(a, op.Input(0))
			c.push(a, op.Input(1))
		}
	case CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
		if outc != 0 { // Anywhere known to be zero is not consumed
			a = op.Input(0).NZMask() | op.Input(1).NZMask()
		}
		c.push(a, op.Input(0))
		c.push(a, op.Input(1))
	case CPUI_INSERT:
		a = (uint64(1) << uint(op.Input(3).Offset())) - 1 // Insert mask
		c.push(a, op.Input(1))
		a <<= uint(op.Input(2).Offset())
		c.push(outc&^a, op.Input(0))
		c.push(all(outc), op.Input(2))
		c.push(all(outc), op.Input(3))
	case CPUI_ZPULL, CPUI_SPULL:
		a = (uint64(1) << uint(op.Input(2).Offset())) - 1 // Pull mask
		a &= outc                                        // Consumed bits of mask
		a <<= uint(op.Input(1).Offset())
		c.push(a, op.Input(0))
		c.push(all(outc), op.Input(1))
		c.push(all(outc), op.Input(2))
	case CPUI_POPCOUNT, CPUI_LZCOUNT:
		a = uint64(16*op.Input(0).Size()-1) & outc // Consumed bits among those that could be set
		c.push(all(a), op.Input(0))
	case CPUI_CALL, CPUI_CALLIND:
		// Call output doesn't indicate consumption of inputs
	case CPUI_FLOAT_INT2FLOAT:
		if outc != 0 {
			a = coveringMask(op.Input(0).NZMask())
		}
		c.push(a, op.Input(0))
	default:
		a = all(outc) // all or nothing
		for i := 0; i < op.NumInput(); i++ {
			c.push(a, op.Input(i))
		}
	}
}

// computeConsumed clears and recomputes the consume mask of every Varnode by
// seeding sinks and propagating backward to fixpoint. C++ parity: the consume
// portion of ActionDeadCode::apply (coreaction.cc 3936-4034).
func (c *consumeAnalysis) computeConsumed(data *Funcdata) {
	// Clear consume on all Varnodes (C++ 3949-3957). The vacuous/list bookkeeping
	// lives in this analysis (Go maps) rather than on the Varnode.
	// addrforce survives only on direct writes. C++ parity: ActionDeadCode::apply.
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		vn.SetConsumed(0)
		if vn.IsAddrForce() && !vn.IsDirectWrite() {
			vn.ClearFlags(VarnodeAddrForce)
		}
	}

	// Pre-live: every Varnode in a space whose heritage has not run yet is
	// treated as consumed, so nothing written there (a global store before
	// ram is heritaged) is lost before data-flow can see its readers.
	// C++ parity: ActionDeadCode::apply "Set pre-live registers" loop.
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		if sp := vn.Space(); sp != nil && !data.deadRemovalAllowed(sp) {
			c.push(^uint64(0), vn)
		}
	}

	returnConsume := gatherConsumedReturn(data)

	for _, op := range data.GetPcodeOpBank().AliveOps() {
		if op.IsCall() {
			// Inputs handled by markConsumedParameters; holdOutput seeding omitted.
			continue
		}
		if !op.IsAssignment() {
			switch op.Code() {
			case CPUI_RETURN:
				c.push(^uint64(0), op.Input(0))
				for i := 1; i < op.NumInput(); i++ {
					c.push(returnConsume, op.Input(i))
				}
			case CPUI_BRANCHIND:
				c.push(^uint64(0), op.Input(0))
			default:
				for i := 0; i < op.NumInput(); i++ {
					c.push(^uint64(0), op.Input(i))
				}
			}
			continue
		}
		// Assignment op: only auto-live Varnodes are seeded here; the rest receive
		// their consume value through back-propagation from their readers.
		for i := 0; i < op.NumInput(); i++ {
			if vn := op.Input(i); vn != nil && vn.IsAutoLive() {
				c.push(^uint64(0), vn)
			}
		}
		if out := op.Output(); out != nil && out.IsAutoLive() {
			c.push(^uint64(0), out)
		}
	}

	// Mark consumption of call parameters.
	// C++ parity: ActionDeadCode::markConsumedParameters (coreaction.cc 3851).
	for _, op := range data.GetPcodeOpBank().AliveOps() {
		if !op.IsCall() {
			continue
		}
		fc := data.callSpecsForOp(op)
		if fc == nil {
			// A call without a specification consumes all of its inputs.
			for j := 0; j < op.NumInput(); j++ {
				c.push(^uint64(0), op.Input(j))
			}
			continue
		}
		c.push(^uint64(0), op.Input(0)) // the call target is fully consumed
		if fc.IsInputLocked() || fc.IsInputActive() {
			for j := 1; j < op.NumInput(); j++ {
				c.push(^uint64(0), op.Input(j))
			}
			continue
		}
		// An open prototype consumes only the bits a parameter can hold.
		// TODO known mismatch: FuncCallSpecs::getInputBytesConsumed hints are
		// not recorded (always 0 = no restriction).
		for j := 1; j < op.NumInput(); j++ {
			vn := op.Input(j)
			consumeVal := ^uint64(0)
			if !vn.IsAutoLive() {
				consumeVal = minimalMask(vn.NZMask())
			}
			c.push(consumeVal, vn)
		}
	}

	for len(c.worklist) > 0 {
		c.propagate()
	}
}

// gatherConsumedReturn returns the consume mask applied to every CPUI_RETURN
// value input. Once the output is locked or active-return recovery has begun,
// the return value is treated as fully consumed, which is the mechanism that
// keeps the return-register computation alive once the recovery chain is wired.
// C++ parity: ActionDeadCode::gatherConsumedReturn (coreaction.cc 3882).
func gatherConsumedReturn(data *Funcdata) uint64 {
	fp := data.GetFuncProto()
	if fp != nil && (fp.IsOutputLocked() || fp.GetActiveOutput() != nil) {
		return ^uint64(0)
	}
	var consumeVal uint64
	for _, op := range data.GetPcodeOpBank().AliveOps() {
		if op.Code() != CPUI_RETURN {
			continue
		}
		if op.NumInput() > 1 {
			if vn := op.Input(1); vn != nil {
				consumeVal |= minimalMask(vn.NZMask())
			}
		}
	}
	if fp := data.GetFuncProto(); fp != nil {
		if val := fp.ReturnBytesConsumed(); val != 0 {
			consumeVal &= maskForSize(val)
		}
	}
	return consumeVal
}
