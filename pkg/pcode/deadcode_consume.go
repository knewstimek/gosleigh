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

	switch op.Code() {
	case CPUI_INT_MULT:
		b := coveringMask(outc)
		var a uint64
		if op.Input(1).IsConstant() {
			leastSet := leastSigBitSet(op.Input(1).Offset())
			if leastSet >= 0 {
				a = (maskForSize(vn.Size()) >> uint(leastSet)) & b
			} else {
				a = 0
			}
		} else {
			a = b
		}
		c.push(a, op.Input(0))
		c.push(b, op.Input(1))
	case CPUI_INT_ADD, CPUI_INT_SUB:
		a := coveringMask(outc)
		c.push(a, op.Input(0))
		c.push(a, op.Input(1))
	case CPUI_SUBPIECE:
		sz := int(op.Input(1).Offset())
		var a uint64
		if sz >= 8 {
			a = 0
		} else {
			a = outc << uint(sz*8)
		}
		var b uint64
		if outc != 0 {
			b = ^uint64(0)
		}
		c.push(a, op.Input(0))
		c.push(b, op.Input(1))
	case CPUI_PIECE:
		sz := int(op.Input(1).Size())
		a := outc >> uint(sz*8)
		b := outc ^ (a << uint(sz*8))
		c.push(a, op.Input(0))
		c.push(b, op.Input(1))
	case CPUI_INDIRECT:
		// The iop-source COPY marking (RuleIndirectCollapse interplay) is omitted;
		// it only affects INDIRECT collapse, not consume preservation.
		c.push(outc, op.Input(0))
	case CPUI_COPY, CPUI_INT_NEGATE:
		c.push(outc, op.Input(0))
	case CPUI_INT_XOR, CPUI_INT_OR:
		c.push(outc, op.Input(0))
		c.push(outc, op.Input(1))
	case CPUI_INT_AND:
		if op.Input(1).IsConstant() {
			val := op.Input(1).Offset()
			c.push(outc&val, op.Input(0))
			c.push(outc, op.Input(1))
		} else {
			c.push(outc, op.Input(0))
			c.push(outc, op.Input(1))
		}
	case CPUI_MULTIEQUAL:
		for i := 0; i < op.NumInput(); i++ {
			c.push(outc, op.Input(i))
		}
	case CPUI_INT_ZEXT:
		c.push(outc, op.Input(0))
	case CPUI_INT_SEXT:
		b := maskForSize(op.Input(0).Size())
		a := outc & b
		if outc > b {
			a |= b ^ (b >> 1) // mark sign bit used
		}
		c.push(a, op.Input(0))
	case CPUI_INT_LEFT:
		if op.Input(1).IsConstant() {
			sa := int(op.Input(1).Offset())
			a := outc >> uint(sa) // <= 8-byte Varnode path
			var b uint64
			if outc != 0 {
				b = ^uint64(0)
			}
			c.push(a, op.Input(0))
			c.push(b, op.Input(1))
		} else {
			var a uint64
			if outc != 0 {
				a = ^uint64(0)
			}
			c.push(a, op.Input(0))
			c.push(a, op.Input(1))
		}
	case CPUI_INT_RIGHT:
		if op.Input(1).IsConstant() {
			sa := int(op.Input(1).Offset())
			var a uint64
			if sa < 64 {
				a = outc << uint(sa)
			}
			var b uint64
			if outc != 0 {
				b = ^uint64(0)
			}
			c.push(a, op.Input(0))
			c.push(b, op.Input(1))
		} else {
			var a uint64
			if outc != 0 {
				a = ^uint64(0)
			}
			c.push(a, op.Input(0))
			c.push(a, op.Input(1))
		}
	case CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL:
		var a uint64
		if outc != 0 {
			a = op.Input(0).NZMask() | op.Input(1).NZMask()
		}
		c.push(a, op.Input(0))
		c.push(a, op.Input(1))
	case CPUI_CALL, CPUI_CALLIND:
		// Call output does not indicate consumption of inputs.
	default:
		var a uint64
		if outc != 0 {
			a = ^uint64(0)
		}
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
	for _, vn := range data.GetVarnodeBank().AllVarnodes() {
		vn.SetConsumed(0)
	}

	// Pre-live registers (C++ 3960) omitted: no per-space heritage-pass tracking.

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

	// Mark consumption of call parameters (conservative: fully consumed).
	// C++ parity: ActionDeadCode::markConsumedParameters (coreaction.cc 3851).
	for i := 0; i < data.NumCalls(); i++ {
		fc := data.GetCallSpecs(i)
		if fc == nil || fc.op == nil {
			continue
		}
		for j := 0; j < fc.op.NumInput(); j++ {
			c.push(^uint64(0), fc.op.Input(j))
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
	// FuncProto::getReturnBytesConsumed narrowing is not modeled.
	return consumeVal
}
