// Copyright 2026 The Gosleigh Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcode

import "math/bits"

// BitRange is a range of bits within a byte container: the container is
// ByteSize bytes at ByteOffset, the range NumBits bits from LeastSigBit.
// C++ parity: class BitRange (address.hh / address.cc).
type BitRange struct {
	ByteOffset  int32
	ByteSize    int32
	LeastSigBit int32
	NumBits     int32
	IsBigEndian bool
}

// undefinedBitRange is BitRange(void): every field -1.
func undefinedBitRange() BitRange {
	return BitRange{ByteOffset: -1, ByteSize: -1, LeastSigBit: -1, NumBits: -1}
}

// byteBitRange is BitRange(bOff,bSize,bigEndian): the whole byte range.
func byteBitRange(bOff, bSize int32, bigEndian bool) BitRange {
	return BitRange{ByteOffset: bOff, ByteSize: bSize, NumBits: bSize * 8, IsBigEndian: bigEndian}
}

// newBitRangeIn copies op2's bits into a new container.
// C++ parity: BitRange::BitRange(const BitRange &op2,int4 off,int4 sz).
func newBitRangeIn(op2 BitRange, off, sz int32) BitRange {
	b := BitRange{ByteOffset: off, ByteSize: sz, NumBits: op2.NumBits, IsBigEndian: op2.IsBigEndian}
	b.LeastSigBit = b.translateLSB(op2)
	return b
}

// Empty reports a range of zero bits. C++ parity: BitRange::empty.
func (b BitRange) Empty() bool { return b.NumBits <= 0 }

// compare orders the ranges as containers, then bits.
// C++ parity: BitRange::compare.
func (b BitRange) compare(op2 BitRange) int {
	cmp := func(x, y int32) int {
		if x < y {
			return -1
		}
		return 1
	}
	if b.ByteOffset != op2.ByteOffset {
		return cmp(b.ByteOffset, op2.ByteOffset)
	}
	if b.ByteSize != op2.ByteSize {
		return cmp(b.ByteSize, op2.ByteSize)
	}
	if b.LeastSigBit != op2.LeastSigBit {
		return cmp(b.LeastSigBit, op2.LeastSigBit)
	}
	if b.NumBits != op2.NumBits {
		return cmp(b.NumBits, op2.NumBits)
	}
	return 0
}

// translateLSB is op2's least significant bit in this range's frame.
// C++ parity: BitRange::translateLSB.
func (b BitRange) translateLSB(op2 BitRange) int32 {
	op2Sig := op2.LeastSigBit
	if b.IsBigEndian {
		thisPos := b.ByteOffset + b.ByteSize
		op2Pos := op2.ByteOffset + op2.ByteSize
		op2Sig += 8 * (thisPos - op2Pos)
	} else {
		op2Sig += 8 * (op2.ByteOffset - b.ByteOffset)
	}
	return op2Sig
}

// overlapTest characterizes the overlap: -1 this comes before, 1 after (no
// intersection), 0 the same range, 2 this contained in op2, 3 op2
// contained in this, 4 partial overlap.
// C++ parity: BitRange::overlapTest.
func (b BitRange) overlapTest(op2 BitRange) int {
	op2Sig := b.translateLSB(op2)
	thisMost := b.LeastSigBit + b.NumBits
	op2Most := op2Sig + op2.NumBits
	if b.IsBigEndian {
		if b.LeastSigBit >= op2Most {
			return -1
		}
		if op2Sig >= thisMost {
			return 1
		}
	} else {
		if thisMost <= op2Sig {
			return -1
		}
		if op2Most <= b.LeastSigBit {
			return 1
		}
	}
	if b.LeastSigBit == op2Sig && thisMost == op2Most {
		return 0
	}
	if op2Sig <= b.LeastSigBit && op2Most >= thisMost {
		return 2
	}
	if b.LeastSigBit <= op2Sig && thisMost >= op2Most {
		return 3
	}
	return 4
}

// intersection keeps the container and narrows the bits to those also in
// op2 (none: NumBits 0). C++ parity: BitRange::intersection.
func (b *BitRange) intersection(op2 BitRange) {
	op2Sig := b.translateLSB(op2)
	op2Most := op2Sig + op2.NumBits
	thisMost := b.LeastSigBit + b.NumBits
	if op2Sig > b.LeastSigBit {
		b.NumBits -= op2Sig - b.LeastSigBit
		b.LeastSigBit = op2Sig
	}
	if op2Most < thisMost {
		b.NumBits -= thisMost - op2Most
	}
	if b.NumBits < 0 {
		b.LeastSigBit = 0
		b.NumBits = 0
	}
}

// IntersectMask narrows the range to the minimal cover of its bits that
// are set in mask. C++ parity: BitRange::intersectMask.
func (b *BitRange) IntersectMask(mask uint64) {
	mask &= b.Mask()
	if mask == 0 {
		b.LeastSigBit = 0
		b.NumBits = 0
		return
	}
	newLeastSig := int32(bits.TrailingZeros64(mask))
	newMostSig := int32(bits.Len64(mask))
	thisMost := b.LeastSigBit + b.NumBits
	if newLeastSig > b.LeastSigBit {
		b.NumBits -= newLeastSig - b.LeastSigBit
		b.LeastSigBit = newLeastSig
	}
	if newMostSig < thisMost {
		b.NumBits -= thisMost - newMostSig
	}
}

// Shift moves the range left (negative: right) within its container.
// C++ parity: BitRange::shift.
func (b *BitRange) Shift(leftShiftAmount int32) {
	b.LeastSigBit += leftShiftAmount
	most := b.LeastSigBit + b.NumBits
	if b.LeastSigBit < 0 {
		b.NumBits += b.LeastSigBit
		b.LeastSigBit = 0
	} else if most > b.ByteSize*8 {
		b.NumBits -= most - b.ByteSize*8
	}
	if b.NumBits < 0 {
		b.LeastSigBit = 0
		b.NumBits = 0
	}
}

// TruncateMostSigBytes drops num most significant container bytes.
// C++ parity: BitRange::truncateMostSigBytes.
func (b *BitRange) TruncateMostSigBytes(num int32) {
	if b.IsBigEndian {
		b.ByteOffset += num
	}
	b.ByteSize -= num
	if maxOffset := b.LeastSigBit + b.NumBits; maxOffset > b.ByteSize*8 {
		b.NumBits -= maxOffset - b.ByteSize*8
	}
	if b.NumBits < 0 {
		b.NumBits = 0
	}
}

// TruncateLeastSigBytes drops num least significant container bytes.
// C++ parity: BitRange::truncateLeastSigBytes.
func (b *BitRange) TruncateLeastSigBytes(num int32) {
	if !b.IsBigEndian {
		b.ByteOffset += num
	}
	b.ByteSize -= num
	b.LeastSigBit -= num * 8
	if b.LeastSigBit < 0 {
		b.NumBits += b.LeastSigBit
		b.LeastSigBit = 0
		if b.NumBits < 0 {
			b.NumBits = 0
		}
	}
}

// ExtendBytes adds num most significant container bytes.
// C++ parity: BitRange::extendBytes.
func (b *BitRange) ExtendBytes(num int32) {
	if b.IsBigEndian {
		b.ByteOffset -= num
	}
	b.ByteSize += num
}

// Mask is the range as a mask aligned with the container.
// C++ parity: BitRange::getMask.
func (b BitRange) Mask() uint64 {
	var res uint64
	if b.NumBits < 64 {
		res = uint64(1) << uint(b.NumBits)
	}
	res--
	if b.LeastSigBit >= 64 {
		return 0
	}
	return res << uint(b.LeastSigBit)
}

// isByteRange reports a range starting and ending on byte boundaries.
// C++ parity: BitRange::isByteRange.
func (b BitRange) isByteRange() bool {
	return b.NumBits&7 == 0 && b.LeastSigBit&7 == 0
}

// IsMostSignificant reports a range ending at the container's top bit.
// C++ parity: BitRange::isMostSignificant.
func (b BitRange) IsMostSignificant() bool {
	return 8*b.ByteSize == b.LeastSigBit+b.NumBits
}

// minimizeContainer shrinks the container to the bytes the range touches.
// C++ parity: BitRange::minimizeContainer.
func (b *BitRange) minimizeContainer() {
	trunc := b.LeastSigBit / 8
	if b.IsBigEndian {
		b.ByteSize -= trunc
	} else {
		b.ByteOffset += trunc
	}
	b.LeastSigBit &= 7
	if num := b.ByteSize - (b.LeastSigBit+b.NumBits+7)/8; num > 0 {
		if b.IsBigEndian {
			b.ByteOffset += num
		}
		b.ByteSize -= num
	}
}

// ExpandToMost grows the range to the container's top bit.
// C++ parity: BitRange::expandToMost.
func (b *BitRange) ExpandToMost() {
	b.NumBits = 8*b.ByteSize - b.LeastSigBit
}

// extendSignBit sign-extends the low numbits of val to a value of size
// bytes. C++ parity: extend_signbit (address.cc).
func extendSignBit(val uint64, numbits, size int32) uint64 {
	if numbits < size*8 {
		sa := uint(64 - numbits)
		val = uint64(int64(val<<sa) >> sa)
		val &= bitfieldSizeMask(size)
	}
	return val
}

// bitfieldSizeMask is the all-ones mask of sz bytes (0 for none).
// C++ parity: calc_mask.
func bitfieldSizeMask(sz int32) uint64 {
	if sz <= 0 {
		return 0
	}
	if sz >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(sz*8)) - 1
}
