package pcode

import (
	"strings"
	"unicode/utf8"

	"gosleigh/pkg/address"
)

// maxStringChars bounds how far a string is searched for its terminator.
// C++ parity: StringManager maximumChars (Architecture: max_implied... 2048).
const maxStringChars = 2048

// stringData returns the UTF-8 bytes of the NUL-terminated 1-byte-character
// string at addr. C++ parity: StringManager::getStringData (char size 1).
func (fd *Funcdata) stringData(addr address.Address) ([]byte, bool) {
	b, _, ok := fd.stringDataSized(addr, 1)
	return b, ok
}

// stringDataSized decodes the NUL-terminated string of charsize-byte code
// units at addr into UTF-8, reporting whether it was cut at the size limit.
// The image is read 32 bytes at a time until a chunk holds a terminator.
// C++ parity: StringManagerUnicode::getStringData + checkCharacters +
// assignStringData.
func (fd *Funcdata) stringDataSized(addr address.Address, charsize int) ([]byte, bool, bool) {
	read := fd.ImageReader()
	if read == nil || (charsize != 1 && charsize != 2 && charsize != 4) {
		return nil, false, false
	}
	bigend := addr.Space != nil && addr.Space.BigEndian
	var buf []byte
	for {
		amount := 32 // Grab 32 bytes of image at a time
		if len(buf)+amount > maxStringChars {
			amount = maxStringChars - len(buf)
			if amount == 0 {
				return nil, false, false // Could not find a terminator
			}
		}
		chunk := make([]byte, amount)
		for k := 0; k < amount; k++ {
			v, err := read(address.Address{Space: addr.Space, Offset: addr.Offset + uint64(len(buf)+k)}, 1)
			if err != nil {
				return nil, false, false // Data unavailable
			}
			chunk[k] = byte(v)
		}
		buf = append(buf, chunk...)
		if hasCharTerminator(chunk, charsize) {
			break
		}
	}
	numChars := checkCharacters(buf, charsize, bigend)
	if numChars < 0 {
		return nil, false, false // Invalid encoding
	}
	return assignStringData(buf, charsize, bigend, numChars)
}

// assignStringData converts the code units to UTF-8 up to the terminator.
// C++ parity: StringManagerUnicode::assignStringData.
func assignStringData(buf []byte, charsize int, bigend bool, numChars int) ([]byte, bool, bool) {
	var out []byte
	for i := 0; i < len(buf); {
		cp, skip := getCodepoint(buf[i:], charsize, bigend)
		if cp <= 0 {
			break
		}
		out = utf8.AppendRune(out, rune(cp))
		i += skip
	}
	if out == nil {
		// An empty string is still a string: C++ keeps its terminator, so
		// StringManager::isString holds and it prints as "".
		out = []byte{}
	}
	return out, numChars >= maxStringChars, true
}

// stringLiteral renders UTF-8 string data as a C literal, with an L prefix
// for wide characters and a marker when it was cut.
// C++ parity: PrintC::printCharacterConstant (after getStringData).
func stringLiteral(data []byte, trunc bool, charType Datatype) string {
	lit := quoteCString(data)
	if charType.Size() > 1 {
		lit = "L" + lit // Wide character
	}
	if trunc {
		lit = lit[:len(lit)-1] + "...\" /* TRUNCATED STRING LITERAL */"
	}
	return lit
}

// internalStringLiteral prints the internal string a BUILTIN_STRINGDATA
// CALLOTHER names by its hash.
// C++ parity: StringManager::registerInternalStringData + getStringData of
// the constant address.
func (fd *Funcdata) internalStringLiteral(hash uint64, charType Datatype) (string, bool) {
	data, _, ok := fd.InternalStringData(hash)
	if !ok || charType == nil {
		return "", false
	}
	charsize := int(charType.Size())
	numChars := checkCharacters(data, charsize, false)
	if numChars < 0 {
		return "", false
	}
	out, trunc, ok := assignStringData(data, charsize, false, numChars)
	if !ok {
		return "", false
	}
	return stringLiteral(out, trunc, charType), true
}

// hasCharTerminator reports whether a buffer holds an all-zero code unit.
// C++ parity: StringManager::hasCharTerminator.
func hasCharTerminator(buf []byte, charsize int) bool {
	for i := 0; i+charsize <= len(buf); i += charsize {
		zero := true
		for j := 0; j < charsize; j++ {
			if buf[i+j] != 0 {
				zero = false
				break
			}
		}
		if zero {
			return true
		}
	}
	return false
}

// checkCharacters counts the characters before the terminator, or -1 for an
// invalid encoding. C++ parity: StringManager::checkCharacters.
func checkCharacters(buf []byte, charsize int, bigend bool) int {
	count := 0
	for i := 0; i < len(buf); {
		cp, skip := getCodepoint(buf[i:], charsize, bigend)
		if cp < 0 {
			return -1
		}
		if cp == 0 {
			break
		}
		count++
		i += skip
	}
	return count
}

// getCodepoint decodes one UTF-8/16/32 character, returning -1 for an
// invalid encoding. C++ parity: StringManager::getCodepoint.
func getCodepoint(buf []byte, charsize int, bigend bool) (int, int) {
	at := func(i int) int {
		if i < len(buf) {
			return int(buf[i])
		}
		return 0
	}
	utf16 := func(i int) int {
		if bigend {
			return at(i)<<8 | at(i+1)
		}
		return at(i+1)<<8 | at(i)
	}
	var cp, sk int
	switch charsize {
	case 2:
		cp, sk = utf16(0), 2
		if cp >= 0xD800 && cp <= 0xDBFF { // High surrogate
			trail := utf16(2)
			sk += 2
			if trail < 0xDC00 || trail > 0xDFFF {
				return -1, 0
			}
			cp = (cp << 10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00)
		} else if cp >= 0xDC00 && cp <= 0xDFFF {
			return -1, 0 // Trail before high
		}
	case 1:
		val := at(0)
		switch {
		case val&0x80 == 0:
			cp, sk = val, 1
		case val&0xe0 == 0xc0:
			if at(1)&0xc0 != 0x80 {
				return -1, 0
			}
			cp, sk = (val&0x1f)<<6|at(1)&0x3f, 2
		case val&0xf0 == 0xe0:
			if at(1)&0xc0 != 0x80 || at(2)&0xc0 != 0x80 {
				return -1, 0
			}
			cp, sk = (val&0xf)<<12|(at(1)&0x3f)<<6|at(2)&0x3f, 3
		case val&0xf8 == 0xf0:
			if at(1)&0xc0 != 0x80 || at(2)&0xc0 != 0x80 || at(3)&0xc0 != 0x80 {
				return -1, 0
			}
			cp, sk = (val&7)<<18|(at(1)&0x3f)<<12|(at(2)&0x3f)<<6|at(3)&0x3f, 4
		default:
			return -1, 0
		}
	case 4:
		sk = 4
		if bigend {
			cp = at(0)<<24 | at(1)<<16 | at(2)<<8 | at(3)
		} else {
			cp = at(3)<<24 | at(2)<<16 | at(1)<<8 | at(0)
		}
	default:
		return -1, 0
	}
	if cp >= 0xd800 && (cp > 0x10ffff || cp <= 0xdfff) {
		return -1, 0 // Out of range or a surrogate
	}
	return cp, sk
}

// isReadOnlyGlobal reports whether the global scope marks addr read-only.
// C++ parity: Scope::isReadOnly on the global scope.
func (fd *Funcdata) isReadOnlyGlobal(addr address.Address) bool {
	e := fd.resolveGlobalSymbol(addr)
	return e != nil && e.Symbol() != nil && e.Symbol().Flags()&VarnodeReadOnly != 0
}

// quoteCString renders string bytes as a C string literal.
// C++ parity: PrintC::printCharacterConstant + escapeCharacterData/printUnicode.
func quoteCString(b []byte) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		b = b[n:]
		sb.WriteString(escapeCharForC(int(r)))
	}
	sb.WriteByte('"')
	return sb.String()
}

// stringLiteral renders a constant pointer to a read-only string as the
// string itself.
// C++ parity: PrintC::pushPtrCharConstant.
func (fd *Funcdata) stringLiteral(vn *Varnode, dt Datatype) (string, bool) {
	ptr, ok := dt.(*Pointer)
	if !ok || vn.Offset() == 0 || !isCharPrintLike(ptr.Pointee()) {
		return "", false
	}
	addr := address.Address{Space: fd.baseAddr.Space, Offset: vn.Offset()}
	if addr.Space == nil || !fd.isReadOnlyGlobal(addr) {
		return "", false
	}
	return fd.printCharacterConstant(addr, ptr.Pointee())
}

// printCharacterConstant renders the string at addr as a C literal, with an
// L prefix for wide characters and a marker when it was cut.
// C++ parity: PrintC::printCharacterConstant.
func (fd *Funcdata) printCharacterConstant(addr address.Address, charType Datatype) (string, bool) {
	data, trunc, ok := fd.stringDataSized(addr, int(charType.Size()))
	if !ok {
		return "", false
	}
	return stringLiteral(data, trunc, charType), true
}
