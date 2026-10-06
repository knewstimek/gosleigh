// Copyright 2026 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package pcode

import "math/bits"

// This file completes circleRange with the push-forward, widening and
// containment operations the value set solver needs.
// C++ parity: rangeutil.cc CircleRange.

// newCircleRangeEmpty is the default range, which holds nothing.
// C++ parity: CircleRange::CircleRange(void).
func newCircleRangeEmpty() circleRange { return circleRange{isempty: true} }

// setRangeSingle makes the range hold the single value val, step 1.
// C++ parity: CircleRange::setRange(uintb,int4).
func (r *circleRange) setRangeSingle(val uint64, size int32) {
	r.mask = maskForSize(size)
	r.step = 1
	r.left = val
	r.right = (val + 1) & r.mask
	r.isempty = false
}

// setFull makes the range hold every value of a size-byte domain.
// C++ parity: CircleRange::setFull.
func (r *circleRange) setFull(size int32) {
	r.mask = maskForSize(size)
	r.step = 1
	r.left = 0
	r.right = 0
	r.isempty = false
}

// isFull reports whether every value is in the range.
// C++ parity: CircleRange::isFull.
func (r *circleRange) isFull() bool { return !r.isempty && r.step == 1 && r.left == r.right }

// equals compares two ranges. C++ parity: CircleRange::operator==.
func (r *circleRange) equals(op2 *circleRange) bool {
	if r.isempty != op2.isempty {
		return false
	}
	if r.isempty {
		return true
	}
	return r.left == op2.left && r.right == op2.right && r.mask == op2.mask && r.step == op2.step
}

// getMaxInfo is the index (+1) of the most significant bit any value in the
// range needs. C++ parity: CircleRange::getMaxInfo.
func (r *circleRange) getMaxInfo() int {
	halfPoint := r.mask ^ (r.mask >> 1)
	if r.contains(halfPoint) {
		return 64 - bits.LeadingZeros64(halfPoint)
	}
	var sizeLeft, sizeRight int
	if halfPoint&r.left == 0 {
		sizeLeft = bits.LeadingZeros64(r.left)
	} else {
		sizeLeft = bits.LeadingZeros64(^r.left & r.mask)
	}
	if halfPoint&r.right == 0 {
		sizeRight = bits.LeadingZeros64(r.right)
	} else {
		sizeRight = bits.LeadingZeros64(^r.right & r.mask)
	}
	if sizeRight < sizeLeft {
		return 64 - sizeRight
	}
	return 64 - sizeLeft
}

// containsRange reports whether op2 lies inside r.
// C++ parity: CircleRange::contains(const CircleRange &).
func (r *circleRange) containsRange(op2 *circleRange) bool {
	if r.isempty {
		return op2.isempty
	}
	if op2.isempty {
		return true
	}
	if r.step > op2.step && !op2.isSingle() {
		return false
	}
	if r.left == r.right {
		return true
	}
	if op2.left == op2.right {
		return false
	}
	if r.left%uint64(r.step) != op2.left%uint64(r.step) {
		return false // Wrong phase
	}
	if r.left == op2.left && r.right == op2.right {
		return true
	}
	switch circleArrange[circleEncodeRangeOverlaps(r.left, r.right, op2.left, op2.right)] {
	case 'c':
		return true
	case 'b':
		return r.right == op2.right
	}
	return false
}

// minimalContainer sets r to the smallest range holding r and op2,
// reporting whether the result covers everything.
// C++ parity: CircleRange::minimalContainer.
func (r *circleRange) minimalContainer(op2 *circleRange, maxStep int) bool {
	if r.isSingle() && op2.isSingle() {
		var lo, hi uint64
		if r.getMin() < op2.getMin() {
			lo, hi = r.getMin(), op2.getMin()
		} else {
			lo, hi = op2.getMin(), r.getMin()
		}
		diff := hi - lo
		if diff > 0 && diff <= uint64(maxStep) && leastSigBitSet(diff) == mostSigBitSet(diff) {
			r.step = int(diff)
			r.left = lo
			r.right = (hi + uint64(r.step)) & r.mask
			return false
		}
	}
	aRight := r.right - uint64(r.step) + 1 // Treat original ranges as having step=1
	bRight := op2.right - uint64(op2.step) + 1
	r.step = 1
	r.mask |= op2.mask
	switch circleArrange[circleEncodeRangeOverlaps(r.left, aRight, op2.left, bRight)] {
	case 'a': // order (l r op2.l op2.r)
		vacantSize1 := r.left + (r.mask - bRight) + 1
		vacantSize2 := op2.left - aRight
		if vacantSize1 < vacantSize2 {
			r.left = op2.left
			r.right = aRight
		} else {
			r.right = bRight
		}
	case 'f': // order (op2.l op2.r l r)
		vacantSize1 := op2.left + (r.mask - aRight) + 1
		vacantSize2 := r.left - bRight
		if vacantSize1 < vacantSize2 {
			r.right = bRight
		} else {
			r.left = op2.left
			r.right = aRight
		}
	case 'b': // order (l op2.l r op2.r)
		r.right = bRight
	case 'c': // order (l op2.l op2.r r)
		r.right = aRight
	case 'd': // order (op2.l l r op2.r)
		r.left = op2.left
		r.right = bRight
	case 'e': // order (op2.l l op2.r r)
		r.left = op2.left
		r.right = aRight
	case 'g': // order (l op2.r op2.l r): entire circle is covered
		r.left = 0
		r.right = 0
	}
	r.normalize()
	return r.left == r.right
}

// invert turns r into its complement with step 1, returning the old step.
// C++ parity: CircleRange::invert.
func (r *circleRange) invert() int {
	res := r.step
	r.step = 1
	r.complement()
	return res
}

// circleSignExtendBit sign-extends val from bit position bitPos.
// C++ parity: sign_extend(intb,int4).
func circleSignExtendBit(val uint64, bitPos int) int64 {
	sa := uint(63 - bitPos)
	return int64(val<<sa) >> sa
}

// pushForwardUnary sets r to the values in1 takes through a unary op,
// reporting whether they form a range.
// C++ parity: CircleRange::pushForwardUnary.
func (r *circleRange) pushForwardUnary(opc OpCode, in1 *circleRange, inSize, outSize int32) bool {
	if in1.isempty {
		r.isempty = true
		return true
	}
	switch opc {
	case CPUI_CAST, CPUI_COPY:
		*r = *in1
	case CPUI_INT_ZEXT:
		r.isempty = false
		r.step = in1.step
		r.mask = maskForSize(outSize)
		if in1.left == in1.right {
			r.left = in1.left % uint64(r.step)
			r.right = in1.mask + 1 + r.left
		} else {
			r.left = in1.left
			r.right = (in1.right - uint64(in1.step)) & in1.mask
			if r.right < r.left {
				return false // Extending causes 2 pieces
			}
			r.right += uint64(r.step) // Impossible for it to wrap with bigger mask
		}
	case CPUI_INT_SEXT:
		r.isempty = false
		r.step = in1.step
		r.mask = maskForSize(outSize)
		if in1.left == in1.right {
			rem := in1.left % uint64(r.step)
			r.right = maskForSize(inSize) >> 1
			r.left = (maskForSize(outSize) ^ r.right) + rem
			r.right = r.right + 1 + rem
		} else {
			r.left = circleSignExtend(in1.left, inSize, outSize)
			r.right = circleSignExtend((in1.right-uint64(in1.step))&in1.mask, inSize, outSize)
			if int64(r.right) < int64(r.left) {
				return false // Extending causes 2 pieces
			}
			r.right = (r.right + uint64(r.step)) & r.mask
		}
	case CPUI_INT_2COMP:
		r.isempty = false
		r.step = in1.step
		r.mask = in1.mask
		r.right = (^in1.left + 1 + uint64(r.step)) & r.mask
		r.left = (^in1.right + 1 + uint64(r.step)) & r.mask
		r.normalize()
	case CPUI_INT_NEGATE:
		r.isempty = false
		r.step = in1.step
		r.mask = in1.mask
		r.left = (^in1.right + uint64(r.step)) & r.mask
		r.right = (^in1.left + uint64(r.step)) & r.mask
		r.normalize()
	case CPUI_BOOL_NEGATE, CPUI_FLOAT_NAN:
		r.isempty = false
		r.mask = 0xff
		r.step = 1
		r.left = 0
		r.right = 2
	default:
		return false
	}
	return true
}

// pushForwardBinary sets r to the values a binary op yields from in1 and
// in2, reporting whether they form a range. maxStep caps step growth.
// C++ parity: CircleRange::pushForwardBinary.
func (r *circleRange) pushForwardBinary(opc OpCode, in1, in2 *circleRange, inSize, outSize int32, maxStep int) bool {
	if in1.isempty || in2.isempty {
		r.isempty = true
		return true
	}
	switch opc {
	case CPUI_PTRSUB, CPUI_INT_ADD:
		r.isempty = false
		r.mask = in1.mask | in2.mask
		switch {
		case in1.left == in1.right || in2.left == in2.right:
			r.step = min(in1.step, in2.step) // Smaller step
			r.left = (in1.left + in2.left) % uint64(r.step)
			r.right = r.left
		case in2.isSingle():
			r.step = in1.step
			r.left = (in1.left + in2.left) & r.mask
			r.right = (in1.right + in2.left) & r.mask
		case in1.isSingle():
			r.step = in2.step
			r.left = (in2.left + in1.left) & r.mask
			r.right = (in2.right + in1.left) & r.mask
		default:
			r.step = min(in1.step, in2.step) // Smaller step
			var size1 uint64
			if in1.left < in1.right {
				size1 = in1.right - in1.left
			} else {
				size1 = in1.mask - (in1.left - in1.right) + uint64(in1.step)
			}
			r.left = (in1.left + in2.left) & r.mask
			r.right = (in1.right - uint64(in1.step) + in2.right - uint64(in2.step) + uint64(r.step)) & r.mask
			var sizenew uint64
			if r.left < r.right {
				sizenew = r.right - r.left
			} else {
				sizenew = r.mask - (r.left - r.right) + uint64(r.step)
			}
			if sizenew < size1 {
				r.right = r.left // Over-flow, we covered everything
			}
			r.normalize()
		}
	case CPUI_INT_MULT:
		r.isempty = false
		r.mask = in1.mask | in2.mask
		var constVal uint64
		switch {
		case in1.isSingle():
			constVal = in1.getMin()
			r.step = in2.step
		case in2.isSingle():
			constVal = in2.getMin()
			r.step = in1.step
		default:
			return false
		}
		tmp := uint32(constVal)
		for r.step < maxStep {
			if tmp&1 != 0 {
				break
			}
			r.step <<= 1
			tmp >>= 1
		}
		wholeSize := 64 - bits.LeadingZeros64(r.mask)
		if in1.getMaxInfo()+in2.getMaxInfo() > wholeSize {
			r.left = (in1.left * in2.left) % uint64(r.step)
			r.right = r.left // Covered everything
			r.normalize()
			return true
		}
		if constVal&(r.mask^(r.mask>>1)) != 0 { // Multiplying by negative number
			r.left = ((in1.right - uint64(in1.step)) * (in2.right - uint64(in2.step))) & r.mask
			r.right = (in1.left*in2.left + uint64(r.step)) & r.mask
		} else {
			r.left = (in1.left * in2.left) & r.mask
			r.right = ((in1.right-uint64(in1.step))*(in2.right-uint64(in2.step)) + uint64(r.step)) & r.mask
		}
	case CPUI_INT_LEFT:
		if !in2.isSingle() {
			return false
		}
		r.isempty = false
		r.mask = in1.mask
		r.step = in1.step
		sa := uint32(in2.getMin())
		for tmp := sa; r.step < maxStep && tmp > 0; tmp-- {
			r.step <<= 1
		}
		r.left = (in1.left << sa) & r.mask
		r.right = (in1.right << sa) & r.mask
		wholeSize := 64 - bits.LeadingZeros64(r.mask)
		if in1.getMaxInfo()+int(sa) > wholeSize {
			r.right = r.left // Covered everything
			r.normalize()
			return true
		}
	case CPUI_SUBPIECE:
		if !in2.isSingle() {
			return false
		}
		r.isempty = false
		sa := uint(in2.left) * 8
		r.mask = maskForSize(outSize)
		r.step = 1
		if sa == 0 {
			r.step = in1.step
		}
		var span uint64
		if in1.left < in1.right {
			span = in1.right - in1.left
		} else {
			span = in1.left - in1.right
		}
		if span == 0 || (span>>sa) > r.mask {
			r.left, r.right = 0, 0 // We cover everything
		} else {
			r.left = (in1.left >> sa) & r.mask
			r.right = (((in1.right - uint64(in1.step)) >> sa) + uint64(r.step)) & r.mask
			r.normalize()
		}
	case CPUI_INT_RIGHT:
		if !in2.isSingle() {
			return false
		}
		r.isempty = false
		sa := uint(in2.left)
		r.mask = maskForSize(outSize)
		r.step = 1 // Lose any step
		if in1.left < in1.right {
			r.left = in1.left >> sa
			r.right = ((in1.right - uint64(in1.step)) >> sa) + 1
		} else {
			r.left = 0
			r.right = in1.mask >> sa
		}
		if r.left == r.right { // Don't truncate accidentally to everything
			r.right = (r.left + 1) & r.mask
		}
	case CPUI_INT_SRIGHT:
		if !in2.isSingle() {
			return false
		}
		r.isempty = false
		sa := uint(in2.left)
		r.mask = maskForSize(outSize)
		r.step = 1 // Lose any step
		bitPos := int(8*inSize - 1)
		valLeft := circleSignExtendBit(in1.left, bitPos)
		valRight := circleSignExtendBit(in1.right, bitPos)
		if valLeft >= valRight {
			valRight = int64(r.mask >> 1) // Max positive
			valLeft = circleSignExtendBit(uint64(valRight+1), bitPos)
		}
		r.left = uint64(valLeft>>sa) & r.mask
		r.right = uint64(((valRight-int64(in1.step))>>sa)+1) & r.mask
		if r.left == r.right { // Don't truncate accidentally to everything
			r.right = (r.left + 1) & r.mask
		}
	case CPUI_INT_EQUAL, CPUI_INT_NOTEQUAL, CPUI_INT_SLESS, CPUI_INT_SLESSEQUAL,
		CPUI_INT_LESS, CPUI_INT_LESSEQUAL, CPUI_INT_CARRY, CPUI_INT_SCARRY, CPUI_INT_SBORROW,
		CPUI_BOOL_XOR, CPUI_BOOL_AND, CPUI_BOOL_OR,
		CPUI_FLOAT_EQUAL, CPUI_FLOAT_NOTEQUAL, CPUI_FLOAT_LESS, CPUI_FLOAT_LESSEQUAL:
		// Ops with boolean outcome: both true and false are possible
		r.isempty = false
		r.mask = 0xff
		r.step = 1
		r.left = 0
		r.right = 2
	default:
		return false
	}
	return true
}

// pushForwardTrinary handles PTRADD as in1 + in2*in3.
// C++ parity: CircleRange::pushForwardTrinary.
func (r *circleRange) pushForwardTrinary(opc OpCode, in1, in2, in3 *circleRange, inSize, outSize int32, maxStep int) bool {
	if opc != CPUI_PTRADD {
		return false
	}
	tmpRange := newCircleRangeEmpty()
	if !tmpRange.pushForwardBinary(CPUI_INT_MULT, in2, in3, inSize, inSize, maxStep) {
		return false
	}
	return r.pushForwardBinary(CPUI_INT_ADD, in1, &tmpRange, inSize, outSize, maxStep)
}

// widen moves one boundary of r out to the matching boundary of op2, which
// contains r: the right one when the left boundary is stable.
// C++ parity: CircleRange::widen.
func (r *circleRange) widen(op2 *circleRange, leftIsStable bool) {
	if leftIsStable {
		lmod := r.left % uint64(r.step)
		mod := op2.right % uint64(r.step)
		if mod <= lmod {
			r.right = op2.right + (lmod - mod)
		} else {
			r.right = op2.right - (mod - lmod)
		}
		r.right &= r.mask
	} else {
		r.left = op2.left & r.mask
	}
	r.normalize()
}
