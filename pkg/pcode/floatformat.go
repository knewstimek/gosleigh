// Copyright 2026 The Gosleigh Authors.
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

import (
	"math"
	"math/bits"
)

// floatClass classifies a decoded floating-point value.
// C++ parity: FloatFormat::floatclass.
type floatClass int

const (
	floatNormalized floatClass = iota
	floatInfinity
	floatZero
	floatNaN
	floatDenormalized
)

// FloatFormat encodes and decodes one target floating-point format and
// emulates float p-code ops through the host's double arithmetic.
// C++ parity: FloatFormat (float.cc).
type FloatFormat struct {
	size        int32
	signbitPos  int32
	fracPos     int32
	fracSize    int32
	expPos      int32
	expSize     int32
	bias        int32
	maxexponent int32
	jbitimplied bool
}

// newFloatFormat builds the IEEE 754 format of the given byte size.
// C++ parity: FloatFormat::FloatFormat(int4).
func newFloatFormat(sz int32) *FloatFormat {
	f := &FloatFormat{size: sz}
	switch sz {
	case 4:
		f.signbitPos, f.expPos, f.expSize, f.fracPos, f.fracSize, f.bias, f.jbitimplied = 31, 23, 8, 0, 23, 127, true
	case 8:
		f.signbitPos, f.expPos, f.expSize, f.fracPos, f.fracSize, f.bias, f.jbitimplied = 63, 52, 11, 0, 52, 1023, true
	}
	f.maxexponent = 1<<f.expSize - 1
	return f
}

// defaultFloatFormats are the formats every Translate carries when the
// processor spec names none. C++ parity: Translate::setDefaultFloatFormats.
var defaultFloatFormats = []*FloatFormat{newFloatFormat(4), newFloatFormat(8)}

// getFloatFormat returns the format of the given size, or nil.
// C++ parity: Translate::getFloatFormat.
func getFloatFormat(size int32) *FloatFormat {
	for _, f := range defaultFloatFormats {
		if f.size == size {
			return f
		}
	}
	return nil
}

// createFloat builds a host double from a sign, a top-aligned significand
// and an exponent. C++ parity: FloatFormat::createFloat.
func floatCreate(sign bool, signif uint64, exp int32) float64 {
	signif >>= 1 // Keep the high bit 0
	res := math.Ldexp(float64(signif), int(exp-63+1))
	if sign {
		res = res * -1.0
	}
	return res
}

// floatExtractExpSig splits a host double. C++ parity: FloatFormat::extractExpSig.
func floatExtractExpSig(x float64) (cls floatClass, sgn bool, signif uint64, exp int32) {
	sgn = math.Signbit(x)
	if x == 0.0 {
		return floatZero, sgn, 0, 0
	}
	if math.IsInf(x, 0) {
		return floatInfinity, sgn, 0, 0
	}
	if math.IsNaN(x) {
		return floatNaN, sgn, 0, 0
	}
	if sgn {
		x = -x
	}
	norm, e := math.Frexp(x) // norm is between 1/2 and 1
	norm = math.Ldexp(norm, 63)
	signif = uint64(norm) << 1
	return floatNormalized, sgn, signif, int32(e - 1)
}

func (f *FloatFormat) extractFractionalCode(x uint64) uint64 {
	x >>= uint(f.fracPos)
	return x << uint(64-f.fracSize)
}

func (f *FloatFormat) extractSign(x uint64) bool {
	return (x>>uint(f.signbitPos))&1 != 0
}

func (f *FloatFormat) extractExponentCode(x uint64) int32 {
	x >>= uint(f.expPos)
	return int32(x & (uint64(1)<<uint(f.expSize) - 1))
}

func (f *FloatFormat) setFractionalCode(x, code uint64) uint64 {
	code >>= uint(64 - f.fracSize)
	code <<= uint(f.fracPos)
	return x | code
}

func (f *FloatFormat) setSign(x uint64, sign bool) uint64 {
	if !sign {
		return x
	}
	return x | uint64(1)<<uint(f.signbitPos)
}

func (f *FloatFormat) setExponentCode(x, code uint64) uint64 {
	return x | code<<uint(f.expPos)
}

func (f *FloatFormat) getZeroEncoding(sgn bool) uint64 {
	return f.setSign(f.setExponentCode(f.setFractionalCode(0, 0), 0), sgn)
}

func (f *FloatFormat) getInfinityEncoding(sgn bool) uint64 {
	return f.setSign(f.setExponentCode(f.setFractionalCode(0, 0), uint64(f.maxexponent)), sgn)
}

func (f *FloatFormat) getNaNEncoding(sgn bool) uint64 {
	res := f.setFractionalCode(0, uint64(1)<<63) // quiet NaN
	return f.setSign(f.setExponentCode(res, uint64(f.maxexponent)), sgn)
}

// getHostFloat decodes an encoding to a host double.
// C++ parity: FloatFormat::getHostFloat.
func (f *FloatFormat) getHostFloat(encoding uint64) (float64, floatClass) {
	sgn := f.extractSign(encoding)
	frac := f.extractFractionalCode(encoding)
	exp := f.extractExponentCode(encoding)
	normal := true
	var cls floatClass
	switch {
	case exp == 0:
		if frac == 0 {
			if sgn {
				return math.Copysign(0, -1), floatZero
			}
			return 0, floatZero
		}
		cls = floatDenormalized
		normal = false
	case exp == f.maxexponent:
		if frac == 0 {
			if sgn {
				return math.Inf(-1), floatInfinity
			}
			return math.Inf(1), floatInfinity
		}
		nan := math.NaN()
		if sgn {
			nan = math.Copysign(nan, -1)
		}
		return nan, floatNaN
	default:
		cls = floatNormalized
	}
	exp -= f.bias
	if normal && f.jbitimplied {
		frac >>= 1
		frac |= uint64(1) << 63
	}
	return floatCreate(sgn, frac, exp), cls
}

// roundToNearestEven rounds signif at lowbitpos.
// C++ parity: FloatFormat::roundToNearestEven.
func floatRoundToNearestEven(signif *uint64, lowbitpos int32) bool {
	var lowbitmask uint64
	if lowbitpos < 64 {
		lowbitmask = uint64(1) << uint(lowbitpos)
	}
	midbitmask := uint64(1) << uint(lowbitpos-1)
	epsmask := midbitmask - 1
	odd := *signif&lowbitmask != 0
	if *signif&midbitmask != 0 && (*signif&epsmask != 0 || odd) {
		*signif += midbitmask
		return true
	}
	return false
}

// encodeParts rounds and packs a normalized significand and unbiased
// exponent. Shared tail of getEncoding and convertEncoding.
func (f *FloatFormat) encodeParts(sgn bool, signif uint64, exp int32) uint64 {
	exp += f.bias
	if exp < -f.fracSize { // Exponent is too small to represent
		return f.getZeroEncoding(sgn)
	}
	if exp < 1 { // Must be denormalized
		if floatRoundToNearestEven(&signif, 64-f.fracSize-exp) {
			if signif>>63 == 0 {
				signif = uint64(1) << 63
				exp++
			}
		}
		return f.setFractionalCode(f.getZeroEncoding(sgn), signif>>uint(-exp))
	}
	if floatRoundToNearestEven(&signif, 64-f.fracSize-1) {
		if signif>>63 == 0 { // the add overflowed
			signif = uint64(1) << 63
			exp++
		}
	}
	if exp >= f.maxexponent { // Exponent is too big to represent
		return f.getInfinityEncoding(sgn)
	}
	if f.jbitimplied && exp != 0 {
		signif <<= 1 // Cut off top bit (which should be 1)
	}
	res := f.setFractionalCode(0, signif)
	res = f.setExponentCode(res, uint64(exp))
	return f.setSign(res, sgn)
}

// getEncoding encodes a host double. C++ parity: FloatFormat::getEncoding.
func (f *FloatFormat) getEncoding(host float64) uint64 {
	cls, sgn, signif, exp := floatExtractExpSig(host)
	switch cls {
	case floatZero:
		return f.getZeroEncoding(sgn)
	case floatInfinity:
		return f.getInfinityEncoding(sgn)
	case floatNaN:
		return f.getNaNEncoding(sgn)
	}
	return f.encodeParts(sgn, signif, exp)
}

// convertEncoding re-encodes a value of format formin.
// C++ parity: FloatFormat::convertEncoding.
func (f *FloatFormat) convertEncoding(encoding uint64, formin *FloatFormat) uint64 {
	sgn := formin.extractSign(encoding)
	signif := formin.extractFractionalCode(encoding)
	exp := formin.extractExponentCode(encoding)
	if exp == formin.maxexponent { // NaN or INFINITY encoding
		if signif != 0 {
			return f.getNaNEncoding(sgn)
		}
		return f.getInfinityEncoding(sgn)
	}
	if exp == 0 { // incoming is subnormal
		if signif == 0 {
			return f.getZeroEncoding(sgn)
		}
		lz := int32(bits.LeadingZeros64(signif))
		signif <<= uint(lz)
		exp = -formin.bias - lz
	} else {
		exp -= formin.bias
		if f.jbitimplied {
			signif = uint64(1)<<63 | signif>>1
		}
	}
	return f.encodeParts(sgn, signif, exp)
}

func (f *FloatFormat) host(a uint64) float64 {
	v, _ := f.getHostFloat(a)
	return v
}

// The op* methods emulate float p-code through the host double.
// C++ parity: FloatFormat::opEqual .. opRound.

func (f *FloatFormat) opEqual(a, b uint64) uint64    { return boolToUint64(f.host(a) == f.host(b)) }
func (f *FloatFormat) opNotEqual(a, b uint64) uint64 { return boolToUint64(f.host(a) != f.host(b)) }
func (f *FloatFormat) opLess(a, b uint64) uint64     { return boolToUint64(f.host(a) < f.host(b)) }
func (f *FloatFormat) opLessEqual(a, b uint64) uint64 {
	return boolToUint64(f.host(a) <= f.host(b))
}

func (f *FloatFormat) opNan(a uint64) uint64 {
	_, cls := f.getHostFloat(a)
	return boolToUint64(cls == floatNaN)
}

func (f *FloatFormat) opAdd(a, b uint64) uint64  { return f.getEncoding(f.host(a) + f.host(b)) }
func (f *FloatFormat) opDiv(a, b uint64) uint64  { return f.getEncoding(f.host(a) / f.host(b)) }
func (f *FloatFormat) opMult(a, b uint64) uint64 { return f.getEncoding(f.host(a) * f.host(b)) }
func (f *FloatFormat) opSub(a, b uint64) uint64  { return f.getEncoding(f.host(a) - f.host(b)) }
func (f *FloatFormat) opNeg(a uint64) uint64     { return f.getEncoding(-f.host(a)) }
func (f *FloatFormat) opAbs(a uint64) uint64     { return f.getEncoding(math.Abs(f.host(a))) }
func (f *FloatFormat) opSqrt(a uint64) uint64    { return f.getEncoding(math.Sqrt(f.host(a))) }
func (f *FloatFormat) opCeil(a uint64) uint64    { return f.getEncoding(math.Ceil(f.host(a))) }
func (f *FloatFormat) opFloor(a uint64) uint64   { return f.getEncoding(math.Floor(f.host(a))) }

// opRound rounds half away from zero, as std::round.
func (f *FloatFormat) opRound(a uint64) uint64 { return f.getEncoding(math.Round(f.host(a))) }

func (f *FloatFormat) opInt2Float(a uint64, sizein int32) uint64 {
	return f.getEncoding(float64(signedVal(a, sizein)))
}

func (f *FloatFormat) opFloat2Float(a uint64, outformat *FloatFormat) uint64 {
	return outformat.convertEncoding(a, f)
}

// opTrunc converts toward zero as the C cast (intb)double does on the host.
func (f *FloatFormat) opTrunc(a uint64, sizeout int32) uint64 {
	return uint64(floatToIntb(f.host(a))) & maskForSize(sizeout)
}

// floatToIntb is the x86-64 cvttsd2si result the C++ (intb) cast produces:
// out-of-range and NaN inputs give the "integer indefinite" 0x8000000000000000.
func floatToIntb(v float64) int64 {
	if math.IsNaN(v) || v >= 9223372036854775808.0 || v < -9223372036854775808.0 {
		return math.MinInt64
	}
	return int64(v)
}
