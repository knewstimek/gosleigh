// Copyright 2024 The Gosleigh Authors
// Licensed under the Apache License, Version 2.0.

package pcode

// circleRange is a faithful port of the subset of Ghidra's CircleRange
// (rangeutil.hh / rangeutil.cc) needed by RuleRangeMeld. A CircleRange models a
// set of integers as a half-open interval [left,right) on a modular ring of size
// (mask+1), with an explicit stride. Only the pull-back / intersect / union /
// translate path exercised by RuleRangeMeld with usenzmask==false is ported here;
// push-forward, widening, NZMask seeding and the value-set solver are not.
//
// C++ parity: CircleRange (rangeutil.hh:50, rangeutil.cc).
type circleRange struct {
	left    uint64 // Left boundary of the open range [left,right)
	right   uint64 // Right boundary of the open range [left,right)
	mask    uint64 // Bit mask defining the size (modulus) of the ring
	isempty bool   // true if the set is empty
	step    int    // Explicit step size
}

// arrange maps a raw boundary-comparison code (0..63) to a normalized overlap
// category character. Copied verbatim from CircleRange::arrange.
// C++ parity: rangeutil.cc:21.
const circleArrange = "gcgbegdagggggggeggggcgbggggggggcdfgggggggegdggggbgggfggggcgbegda"

// newCircleRangeBoolean builds a single-value boolean range (0 or 1).
// C++ parity: CircleRange::CircleRange(bool val).
func newCircleRangeBoolean(val bool) circleRange {
	r := circleRange{mask: 0xff, step: 1, isempty: false}
	if val {
		r.left = 1
		r.right = 2
	} else {
		r.left = 0
		r.right = 1
	}
	return r
}

// circleSignExtend sign-extends a sizein-byte value to a sizeout-byte value.
// C++ parity: uintb sign_extend(uintb in,int4 sizein,int4 sizeout).
func circleSignExtend(in uint64, sizein, sizeout int32) uint64 {
	res := in & maskForSize(sizein)
	signbit := uint64(1) << (uint(sizein)*8 - 1)
	if res&signbit != 0 {
		res |= maskForSize(sizeout) &^ maskForSize(sizein)
	}
	return res
}

// normalize collapses all left==right representations to the canonical "full" form.
// C++ parity: CircleRange::normalize.
func (r *circleRange) normalize() {
	if r.left == r.right {
		if r.step != 1 {
			r.left = r.left % uint64(r.step)
		} else {
			r.left = 0
		}
		r.right = r.left
	}
}

// complement sets this to its complement. Only valid when step is 1.
// C++ parity: CircleRange::complement.
func (r *circleRange) complement() {
	if r.isempty {
		r.left = 0
		r.right = 0
		r.isempty = false
		return
	}
	if r.left == r.right {
		r.isempty = true
		return
	}
	r.left, r.right = r.right, r.left
}

// convertToBoolean restricts this to the boolean sub-range and reports whether
// it contained both 0 and 1.
// C++ parity: CircleRange::convertToBoolean.
func (r *circleRange) convertToBoolean() bool {
	if r.isempty {
		return false
	}
	containsZero := r.contains(0)
	containsOne := r.contains(1)
	r.mask = 0xff
	r.step = 1
	if containsZero && containsOne {
		r.left = 0
		r.right = 2
		r.isempty = false
		return true
	} else if containsZero {
		r.left = 0
		r.right = 1
		r.isempty = false
	} else if containsOne {
		r.left = 1
		r.right = 2
		r.isempty = false
	} else {
		r.isempty = true
	}
	return false
}

// isSingle reports whether the range holds exactly one value.
// C++ parity: CircleRange::isSingle.
func (r *circleRange) isSingle() bool {
	return !r.isempty && r.right == ((r.left+uint64(r.step))&r.mask)
}

// contains reports membership of a specific integer.
// C++ parity: CircleRange::contains(uintb).
func (r *circleRange) contains(val uint64) bool {
	if r.isempty {
		return false
	}
	if r.step != 1 {
		if (r.left % uint64(r.step)) != (val % uint64(r.step)) {
			return false // Phase is wrong
		}
	}
	if r.left < r.right {
		if val < r.left {
			return false
		}
		if r.right <= val {
			return false
		}
	} else if r.right < r.left {
		if val < r.right {
			return true
		}
		if val >= r.left {
			return true
		}
		return false
	}
	return true
}

// encodeRangeOverlaps computes the normalized overlap category for two ranges.
// C++ parity: CircleRange::encodeRangeOverlaps (rangeutil.hh:358).
func circleEncodeRangeOverlaps(op1left, op1right, op2left, op2right uint64) byte {
	val := 0
	if op1left <= op1right {
		val |= 0x20
	}
	if op1left <= op2left {
		val |= 0x10
	}
	if op1left <= op2right {
		val |= 0x8
	}
	if op1right <= op2left {
		val |= 0x4
	}
	if op1right <= op2right {
		val |= 0x2
	}
	if op2left <= op2right {
		val |= 0x1
	}
	return circleArrange[val]
}

// newStride restricts a range to a coarser stride, matching the given remainder.
// Returns true if the result is empty.
// C++ parity: CircleRange::newStride.
func circleNewStride(mask uint64, step, oldStep int, rem uint64, myleft, myright *uint64) bool {
	if oldStep != 1 {
		oldRem := *myleft % uint64(oldStep)
		if oldRem != (rem % uint64(oldStep)) {
			return true // Step is completely off
		}
	}
	origOrder := *myleft < *myright
	leftRem := *myleft % uint64(step)
	rightRem := *myright % uint64(step)
	if leftRem > rem {
		*myleft += rem + uint64(step) - leftRem
	} else {
		*myleft += rem - leftRem
	}
	if rightRem > rem {
		*myright += rem + uint64(step) - rightRem
	} else {
		*myright += rem - rightRem
	}
	*myleft &= mask
	*myright &= mask
	newOrder := *myleft < *myright
	return origOrder != newOrder
}

// newDomain truncates a range to fit a smaller domain mask.
// Returns true if the truncated range is empty.
// C++ parity: CircleRange::newDomain.
func circleNewDomain(newMask uint64, newStep int, myleft, myright *uint64) bool {
	var rem uint64
	if newStep != 1 {
		rem = *myleft % uint64(newStep)
	} else {
		rem = 0
	}
	if *myleft > newMask {
		if *myright > newMask { // Both bounds out of range of newMask
			if *myleft < *myright {
				return true // Old range completely out of bounds of new mask
			}
			*myleft = rem
			*myright = rem // Old range contained everything in newMask
			return false
		}
		*myleft = rem // Take everything up to left edge of new range
	}
	if *myright > newMask {
		*myright = rem // Take everything up to right edge of new range
	}
	if *myleft == *myright {
		*myleft = rem // Normalize the everything
		*myright = rem
	}
	return false
}

// circleUnion sets this to the single-interval union of this and op2.
// Returns 0 if valid, 2 if the union would be two pieces (this unmodified).
// C++ parity: CircleRange::circleUnion.
func (r *circleRange) circleUnion(op2 circleRange) int {
	if op2.isempty {
		return 0
	}
	if r.isempty {
		*r = op2
		return 0
	}
	if r.mask != op2.mask {
		return 2 // Cannot do proper union with different domains
	}
	aRight := r.right
	bRight := op2.right
	newStep := r.step
	if r.step < op2.step {
		if r.isSingle() {
			newStep = op2.step
			aRight = (r.left + uint64(newStep)) & r.mask
		} else {
			return 2
		}
	} else if op2.step < r.step {
		if op2.isSingle() {
			newStep = r.step
			bRight = (op2.left + uint64(newStep)) & r.mask
		} else {
			return 2
		}
	}
	var rem uint64
	if newStep != 1 {
		rem = r.left % uint64(newStep)
		if rem != (op2.left % uint64(newStep)) {
			return 2
		}
	} else {
		rem = 0
	}
	if r.left == aRight || op2.left == bRight {
		r.left = rem
		r.right = rem
		r.step = newStep
		return 0
	}
	overlapCode := circleEncodeRangeOverlaps(r.left, aRight, op2.left, bRight)
	switch overlapCode {
	case 'a', 'f': // order (l r op2.l op2.r) or (op2.l op2.r l r)
		if aRight == op2.left {
			r.right = bRight
			r.step = newStep
			return 0
		}
		if r.left == bRight {
			r.left = op2.left
			r.right = aRight
			r.step = newStep
			return 0
		}
		return 2 // 2 pieces
	case 'b': // order (l op2.l r op2.r)
		r.right = bRight
		r.step = newStep
		return 0
	case 'c': // order (l op2.l op2.r r)
		r.right = aRight
		r.step = newStep
		return 0
	case 'd': // order (op2.l l r op2.r)
		r.left = op2.left
		r.right = bRight
		r.step = newStep
		return 0
	case 'e': // order (op2.l l op2.r r)
		r.left = op2.left
		r.right = aRight
		r.step = newStep
		return 0
	case 'g': // either impossible or covers whole circle
		r.left = rem
		r.right = rem
		r.step = newStep
		return 0 // entire circle is covered
	}
	return -1 // Never reached
}

// intersect sets this to the single-interval intersection of this and op2.
// Returns 0 if valid (possibly empty), 2 if the intersection would be two pieces.
// C++ parity: CircleRange::intersect.
func (r *circleRange) intersect(op2 circleRange) int {
	var retval, newStep int
	var newMask, myleft, myright, op2left, op2right uint64

	if r.isempty {
		return 0 // Intersection with empty is empty
	}
	if op2.isempty {
		r.isempty = true
		return 0
	}
	myleft = r.left
	myright = r.right
	op2left = op2.left
	op2right = op2.right
	if r.step < op2.step {
		newStep = op2.step
		rem := op2left % uint64(newStep)
		if circleNewStride(r.mask, newStep, r.step, rem, &myleft, &myright) { // Increase the smaller stride
			r.isempty = true
			return 0
		}
	} else if op2.step < r.step {
		newStep = r.step
		rem := myleft % uint64(newStep)
		if circleNewStride(op2.mask, newStep, op2.step, rem, &op2left, &op2right) {
			r.isempty = true
			return 0
		}
	} else {
		newStep = r.step
	}
	newMask = r.mask & op2.mask
	if r.mask != newMask {
		if circleNewDomain(newMask, newStep, &myleft, &myright) {
			r.isempty = true
			return 0
		}
	} else if op2.mask != newMask {
		if circleNewDomain(newMask, newStep, &op2left, &op2right) {
			r.isempty = true
			return 0
		}
	}
	if myleft == myright { // Intersect with this everything
		r.left = op2left
		r.right = op2right
		retval = 0
	} else if op2left == op2right { // Intersect with op2 everything
		r.left = myleft
		r.right = myright
		retval = 0
	} else {
		overlapCode := circleEncodeRangeOverlaps(myleft, myright, op2left, op2right)
		switch overlapCode {
		case 'a', 'f': // order (l r op2.l op2.r) or (op2.l op2.r l r)
			r.isempty = true
			retval = 0 // empty set
		case 'b': // order (l op2.l r op2.r)
			r.left = op2left
			r.right = myright
			if r.left == r.right {
				r.isempty = true
			}
			retval = 0
		case 'c': // order (l op2.l op2.r r)
			r.left = op2left
			r.right = op2right
			retval = 0
		case 'd': // order (op2.l l r op2.r)
			r.left = myleft
			r.right = myright
			retval = 0
		case 'e': // order (op2.l l op2.r r)
			r.left = myleft
			r.right = op2right
			if r.left == r.right {
				r.isempty = true
			}
			retval = 0
		case 'g': // order (l op2.r op2.l r)
			if myleft == op2right {
				r.left = op2left
				r.right = myright
				if r.left == r.right {
					r.isempty = true
				}
				retval = 0
			} else if op2left == myright {
				r.left = myleft
				r.right = op2right
				if r.left == r.right {
					r.isempty = true
				}
				retval = 0
			} else {
				retval = 2 // 2 pieces
			}
		default:
			retval = 2 // Never reached
		}
	}
	if retval != 0 {
		return retval
	}
	r.mask = newMask
	r.step = newStep
	return 0
}

// pullBackUnary pulls this range back through a unary operator.
// Returns true if a valid range is formed.
// C++ parity: CircleRange::pullBackUnary.
func (r *circleRange) pullBackUnary(opc OpCode, inSize, outSize int32) bool {
	// If there is nothing in the output set, no input maps to it.
	if r.isempty {
		return true
	}
	switch opc {
	case CPUI_BOOL_NEGATE:
		if r.convertToBoolean() {
			break // Both outputs possible => both inputs possible
		}
		r.left = r.left ^ 1 // Flip the boolean range
		r.right = r.left + 1
	case CPUI_COPY:
		// Identity transform on range.
	case CPUI_INT_2COMP:
		val := (^r.left + 1 + uint64(r.step)) & r.mask
		r.left = (^r.right + 1 + uint64(r.step)) & r.mask
		r.right = val
	case CPUI_INT_NEGATE:
		val := (^r.left + uint64(r.step)) & r.mask
		r.left = (^r.right + uint64(r.step)) & r.mask
		r.right = val
	case CPUI_INT_ZEXT:
		val := maskForSize(inSize) // (smaller) input mask
		rem := r.left % uint64(r.step)
		var zextrange circleRange
		zextrange.left = rem
		zextrange.right = val + 1 + rem // Biggest possible range of ZEXT
		zextrange.mask = r.mask
		zextrange.step = r.step // Keep the same stride
		zextrange.isempty = false
		if 0 != r.intersect(zextrange) {
			return false
		}
		r.left &= val
		r.right &= val
		r.mask &= val // Preserve the stride
	case CPUI_INT_SEXT:
		val := maskForSize(inSize) // (smaller) input mask
		rem := r.left & uint64(r.step)
		var sextrange circleRange
		sextrange.left = val ^ (val >> 1) // High order bit for (small) input space
		sextrange.left += rem
		sextrange.right = circleSignExtend(sextrange.left, inSize, outSize)
		sextrange.mask = r.mask
		sextrange.step = r.step // Keep the same stride
		sextrange.isempty = false
		if sextrange.intersect(*r) != 0 {
			return false
		}
		if !sextrange.isempty {
			return false
		}
		r.left &= val
		r.right &= val
		r.mask &= val // Preserve the stride
	default:
		return false
	}
	return true
}

// pullBackBinary pulls this range back through a binary operator, where the
// other input is the constant val on the side opposite slot.
// Returns true if a valid range is formed.
// C++ parity: CircleRange::pullBackBinary.
func (r *circleRange) pullBackBinary(opc OpCode, val uint64, slot int, inSize, outSize int32) bool {
	// If there is nothing in the output set, no input maps to it.
	if r.isempty {
		return true
	}
	switch opc {
	case CPUI_INT_EQUAL:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break // All possible outs => all possible ins
		}
		yescomplement := r.left == 0
		r.left = val
		r.right = (val + 1) & r.mask
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_NOTEQUAL:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		r.left = (val + 1) & r.mask
		r.right = val
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_LESS:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		if slot == 0 {
			if val == 0 {
				r.isempty = true // X < 0 is always false
			} else {
				r.left = 0
				r.right = val
			}
		} else {
			if val == r.mask {
				r.isempty = true // 0xffff < X is always false
			} else {
				r.left = (val + 1) & r.mask
				r.right = 0
			}
		}
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_LESSEQUAL:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		if slot == 0 {
			r.left = 0
			r.right = (val + 1) & r.mask
		} else {
			r.left = val
			r.right = 0
		}
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_SLESS:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		if slot == 0 {
			if val == (r.mask>>1)+1 {
				r.isempty = true // X < -infinity is always false
			} else {
				r.left = (r.mask >> 1) + 1 // -infinity
				r.right = val
			}
		} else {
			if val == (r.mask >> 1) {
				r.isempty = true // infinity < X is always false
			} else {
				r.left = (val + 1) & r.mask
				r.right = (r.mask >> 1) + 1 // -infinity
			}
		}
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_SLESSEQUAL:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		if slot == 0 {
			r.left = (r.mask >> 1) + 1 // -infinity
			r.right = (val + 1) & r.mask
		} else {
			r.left = val
			r.right = (r.mask >> 1) + 1 // -infinity
		}
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_CARRY:
		bothTrueFalse := r.convertToBoolean()
		r.mask = maskForSize(inSize)
		if bothTrueFalse {
			break
		}
		yescomplement := r.left == 0
		if val == 0 {
			r.isempty = true // Nothing carries adding zero
		} else {
			r.left = ((r.mask - val) + 1) & r.mask
			r.right = 0
		}
		if yescomplement {
			r.complement()
		}
	case CPUI_INT_ADD:
		r.left = (r.left - val) & r.mask
		r.right = (r.right - val) & r.mask
	case CPUI_INT_SUB:
		if slot == 0 {
			r.left = (r.left + val) & r.mask
			r.right = (r.right + val) & r.mask
		} else {
			r.left = (val - r.left) & r.mask
			r.right = (val - r.right) & r.mask
		}
	case CPUI_INT_RIGHT:
		if r.step == 1 {
			rightBound := (maskForSize(inSize) >> val) + 1 // The maximal right bound
			if ((r.left >= rightBound) && (r.right >= rightBound) && (r.left >= r.right)) ||
				((r.left == 0) && (r.right >= rightBound)) || (r.left == r.right) {
				r.left = 0 // covers everything in range of shift
				r.right = 0
			} else {
				if r.left > rightBound {
					r.left = rightBound
				}
				if r.right > rightBound {
					r.right = 0
				}
				r.left = (r.left << val) & r.mask
				r.right = (r.right << val) & r.mask
				if r.left == r.right {
					r.isempty = true
				}
			}
		} else {
			return false
		}
	case CPUI_INT_SRIGHT:
		if r.step == 1 {
			rightb := maskForSize(inSize)
			leftb := rightb >> (val + 1)
			rightb = leftb ^ rightb // Smallest negative possible
			leftb += 1              // Biggest positive (+1) possible
			if ((r.left >= leftb) && (r.left <= rightb) && (r.right >= leftb) &&
				(r.right <= rightb) && (r.left >= r.right)) || (r.left == r.right) {
				r.left = 0 // covers everything in range of shift
				r.right = 0
			} else {
				if (r.left > leftb) && (r.left < rightb) {
					r.left = leftb
				}
				if (r.right > leftb) && (r.right < rightb) {
					r.right = rightb
				}
				r.left = (r.left << val) & r.mask
				r.right = (r.right << val) & r.mask
				if r.left == r.right {
					r.isempty = true
				}
			}
		} else {
			return false
		}
	default:
		return false
	}
	return true
}

// pullBack pulls this range back through the given PcodeOp, returning the single
// unknown input Varnode (or nil). Symbol markup propagation (copySymbolIfValid)
// and the usenzmask NZMASK intersection are intentionally not ported: Gosleigh
// has no per-Varnode constant-symbol markup, and RuleRangeMeld always calls with
// usenzmask==false. constMarkup is accepted to mirror the C++ signature.
// C++ parity: CircleRange::pullBack.
func (r *circleRange) pullBack(op *PcodeOp, constMarkup **Varnode, usenzmask bool) *Varnode {
	var res *Varnode

	if op.NumInput() == 1 {
		res = op.Input(0)
		if res.IsConstant() {
			return nil
		}
		if !r.pullBackUnary(op.Code(), res.Size(), op.Output().Size()) {
			return nil
		}
	} else if op.NumInput() == 2 {
		// Find non-constant varnode input and slot; the other input must be constant.
		slot := 0
		res = op.Input(slot)
		constvn := op.Input(1 - slot)
		if res.IsConstant() {
			slot = 1
			constvn = res
			res = op.Input(slot)
			if res.IsConstant() {
				return nil
			}
		} else if !constvn.IsConstant() {
			return nil
		}
		val := constvn.Offset()
		if !r.pullBackBinary(op.Code(), val, slot, res.Size(), op.Output().Size()) {
			return nil
		}
		// usenzmask SUBPIECE widening branch not ported (always false here).
	} else { // Neither unary nor binary
		return nil
	}
	// usenzmask NZMASK intersection not ported (always false here).
	return res
}

// translate2Op recovers comparison-op parameters such that the comparison
// returns true exactly for inputs in this range.
// Returns restype: 0 success, 1 always true, 2 not possible, 3 always false.
// C++ parity: CircleRange::translate2Op.
func (r *circleRange) translate2Op() (opc OpCode, c uint64, cslot int, restype int) {
	if r.isempty {
		return CPUI_MAX, 0, 0, 3
	}
	if r.step != 1 {
		return CPUI_MAX, 0, 0, 2 // Not possible with a stride
	}
	if r.right == ((r.left + 1) & r.mask) { // Single value
		return CPUI_INT_EQUAL, r.left, 0, 0
	}
	if r.left == ((r.right + 1) & r.mask) { // All but one value
		return CPUI_INT_NOTEQUAL, r.right, 0, 0
	}
	if r.left == r.right { // All outputs are possible
		return CPUI_MAX, 0, 0, 1
	}
	if r.left == 0 {
		return CPUI_INT_LESS, r.right, 1, 0
	}
	if r.right == 0 {
		return CPUI_INT_LESS, (r.left - 1) & r.mask, 0, 0
	}
	if r.left == (r.mask>>1)+1 {
		return CPUI_INT_SLESS, r.right, 1, 0
	}
	if r.right == (r.mask>>1)+1 {
		return CPUI_INT_SLESS, (r.left - 1) & r.mask, 0, 0
	}
	return CPUI_MAX, 0, 0, 2 // Cannot represent
}

// -----------------------------------------------------------------------
// Range accessors / constructors used by JumpValuesRange enumeration.
// These port the small CircleRange surface (rangeutil.hh:64-82) that the
// jump-table value iterator needs on top of the RuleRangeMeld subset above:
// a boundary constructor, setRange, and the getMin/getMax/getEnd/getStep/
// getMask/getSize/getNext accessors driving the do/while iteration idiom.
// -----------------------------------------------------------------------

// newCircleRangeBounds builds a range from explicit boundaries.
// C++ parity: CircleRange::CircleRange(uintb lft,uintb rgt,int4 size,int4 stp)
// (rangeutil.cc:179).
func newCircleRangeBounds(lft, rgt uint64, size, stp int32) circleRange {
	return circleRange{
		left:    lft,
		right:   rgt,
		mask:    maskForSize(size),
		step:    int(stp),
		isempty: false,
	}
}

// newCircleRangeSingle builds a range holding the single value val over a
// size-byte domain with step 1.
// C++ parity: CircleRange::CircleRange(uintb val,int4 size) (rangeutil.cc:205).
func newCircleRangeSingle(val uint64, size int32) circleRange {
	m := maskForSize(size)
	return circleRange{left: val, right: (val + 1) & m, mask: m, step: 1, isempty: false}
}

// isEmpty reports whether the range holds no values.
// C++ parity: CircleRange::isEmpty (rangeutil.hh:71).
func (r *circleRange) isEmpty() bool { return r.isempty }

// setRange assigns explicit boundaries in place.
// C++ parity: CircleRange::setRange(uintb,uintb,int4,int4) (rangeutil.cc:219).
func (r *circleRange) setRange(lft, rgt uint64, size, stp int32) {
	r.mask = maskForSize(size)
	r.left = lft
	r.right = rgt
	r.step = int(stp)
	r.isempty = false
}

// getMin returns the left boundary of the range.
// C++ parity: CircleRange::getMin (rangeutil.hh:74).
func (r *circleRange) getMin() uint64 { return r.left }

// getMax returns the right-most integer contained in the range.
// C++ parity: CircleRange::getMax (rangeutil.hh:75).
func (r *circleRange) getMax() uint64 { return (r.right - uint64(r.step)) & r.mask }

// getEnd returns the right (open) boundary of the range.
// C++ parity: CircleRange::getEnd (rangeutil.hh:76).
func (r *circleRange) getEnd() uint64 { return r.right }

// getMask returns the domain mask.
// C++ parity: CircleRange::getMask (rangeutil.hh:77).
func (r *circleRange) getMask() uint64 { return r.mask }

// getStep returns the explicit step.
// C++ parity: CircleRange::getStep (rangeutil.hh:79).
func (r *circleRange) getStep() int { return r.step }

// getSize returns the number of integers contained in the range.
// The step==0 guard is a Go addition: a zero-value circleRange (Go composite
// literal default) has step 0, which the C++ default constructor never
// produces because it sets isempty. Guarding avoids a divide-by-zero if such
// a value ever reaches getSize.
// C++ parity: CircleRange::getSize (rangeutil.cc:256).
func (r *circleRange) getSize() uint64 {
	if r.isempty || r.step == 0 {
		return 0
	}
	var val uint64
	if r.left < r.right {
		val = (r.right - r.left) / uint64(r.step)
	} else {
		val = (r.mask - (r.left - r.right) + uint64(r.step)) / uint64(r.step)
		if val == 0 { // Overflow: all uintb values are in the range
			val = r.mask
			if r.step > 1 {
				val = val / uint64(r.step)
				val += 1
			}
		}
	}
	return val
}

// getNext advances an integer within the range, returning the next value and
// whether iteration should continue (i.e. the new value is not the end).
// C++ parity: CircleRange::getNext (rangeutil.hh:82).
func (r *circleRange) getNext(val uint64) (uint64, bool) {
	next := (val + uint64(r.step)) & r.mask
	return next, next != r.right
}
