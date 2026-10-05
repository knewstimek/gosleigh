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
// string at addr in the load image, or false when there is no image, no
// terminator within the limit, or an invalid encoding.
// TODO known mismatch: only 1-byte (UTF-8) strings; UTF-16/32 not decoded.
// C++ parity: StringManagerUnicode::getStringData + checkCharacters.
func (fd *Funcdata) stringData(addr address.Address) ([]byte, bool) {
	read := fd.ImageReader()
	if read == nil {
		return nil, false
	}
	var buf []byte
	for i := 0; i < maxStringChars; i++ {
		v, err := read(address.Address{Space: addr.Space, Offset: addr.Offset + uint64(i)}, 1)
		if err != nil {
			return nil, false
		}
		if byte(v) == 0 {
			if !utf8.Valid(buf) {
				return nil, false
			}
			return buf, true
		}
		buf = append(buf, byte(v))
	}
	return nil, false
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
	if !ok || vn.Offset() == 0 || !isCharPrintLike(ptr.Pointee()) || ptr.Pointee().Size() != 1 {
		return "", false
	}
	addr := address.Address{Space: fd.baseAddr.Space, Offset: vn.Offset()}
	if addr.Space == nil || !fd.isReadOnlyGlobal(addr) {
		return "", false
	}
	data, ok := fd.stringData(addr)
	if !ok {
		return "", false
	}
	return quoteCString(data), true
}
