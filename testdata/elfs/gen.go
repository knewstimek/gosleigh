//go:build ignore

// gen.go writes a minimal valid ELF32 x86 binary to testdata/elfs/simple_add.elf.
// The .text section contains 11 bytes encoding a simple add function:
//   push ebp; mov ebp,esp; mov eax,[ebp+8]; add eax,[ebp+0xC]; pop ebp; ret
//
// Run with: go run testdata/elfs/gen.go  (from the repo root)
package main

import (
	"bytes"
	"encoding/binary"
	"os"
)

// ELF32 constants (from elf.h / debug/elf).
const (
	etExec      = 2  // ET_EXEC
	emI386      = 3  // EM_386
	shtProgbits = 1  // SHT_PROGBITS
	shtStrtab   = 3  // SHT_STRTAB
	shfAlloc    = 2  // SHF_ALLOC
	shfExecinst = 4  // SHF_EXECINSTR
)

// text is the .text section payload:
//   55           push ebp
//   89 EC        mov  ebp,esp
//   8B 45 08     mov  eax,[ebp+0x8]
//   03 45 0C     add  eax,[ebp+0xC]
//   5D           pop  ebp
//   C3           ret
var text = []byte{0x55, 0x89, 0xEC, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3}

// shstrtab is the section name string table.
//   [0]  null terminator (required by ELF spec)
//   [1]  ".text\0"
//   [7]  ".shstrtab\0"
var shstrtab = []byte("\x00.text\x00.shstrtab\x00") // 17 bytes

// File layout (little-endian, ELF32):
//   offset   0 ..  51 : ELF32 header         (52 bytes)
//   offset  52 ..  62 : .text section data   (11 bytes)
//   offset  63 ..  79 : .shstrtab data       (17 bytes)
//   offset  80 .. 199 : section header table (3 * 40 = 120 bytes)

const (
	textOffset    = 52
	shstrtabOff   = 63
	shTableOffset = 80

	textVMA = 0x08048034 // virtual load address of .text
)

func pu16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

func pu32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeELFHeader(buf *bytes.Buffer) {
	// e_ident (16 bytes)
	buf.WriteString("\x7fELF") // magic
	buf.WriteByte(1)            // ELFCLASS32
	buf.WriteByte(1)            // ELFDATA2LSB (little-endian)
	buf.WriteByte(1)            // EV_CURRENT
	buf.WriteByte(0)            // ELFOSABI_NONE
	buf.Write(make([]byte, 8))  // padding

	pu16(buf, etExec)      // e_type
	pu16(buf, emI386)      // e_machine
	pu32(buf, 1)           // e_version
	pu32(buf, textVMA)     // e_entry
	pu32(buf, 0)           // e_phoff (no program headers)
	pu32(buf, shTableOffset) // e_shoff
	pu32(buf, 0)           // e_flags
	pu16(buf, 52)          // e_ehsize
	pu16(buf, 32)          // e_phentsize
	pu16(buf, 0)           // e_phnum
	pu16(buf, 40)          // e_shentsize
	pu16(buf, 3)           // e_shnum: null + .text + .shstrtab
	pu16(buf, 2)           // e_shstrndx: .shstrtab is section 2
}

// writeSectionHeader writes a 40-byte ELF32 section header entry.
func writeSectionHeader(buf *bytes.Buffer, name, typ, flags, addr, offset, size, link, info, align, entsize uint32) {
	pu32(buf, name)
	pu32(buf, typ)
	pu32(buf, flags)
	pu32(buf, addr)
	pu32(buf, offset)
	pu32(buf, size)
	pu32(buf, link)
	pu32(buf, info)
	pu32(buf, align)
	pu32(buf, entsize)
}

func main() {
	buf := new(bytes.Buffer)

	writeELFHeader(buf)
	if buf.Len() != 52 {
		panic("ELF header size mismatch")
	}

	// .text section data at file offset 52
	buf.Write(text)
	if buf.Len() != 63 {
		panic(".text offset mismatch")
	}

	// .shstrtab data at file offset 63
	buf.Write(shstrtab)
	if buf.Len() != 80 {
		panic(".shstrtab end offset mismatch")
	}

	// Section header table at file offset 80.
	// Section 0: null (all zeros, required by ELF spec).
	writeSectionHeader(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	// Section 1: .text
	//   name offset 1 in shstrtab, SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR
	writeSectionHeader(buf,
		1,                         // sh_name -> "\x00[.text]\x00..."
		shtProgbits,               // sh_type
		shfAlloc|shfExecinst,      // sh_flags
		textVMA,                   // sh_addr
		textOffset,                // sh_offset (file offset)
		uint32(len(text)),         // sh_size
		0, 0, 1, 0,
	)

	// Section 2: .shstrtab
	//   name offset 7 in shstrtab ("\x00.text\x00" = 7 bytes)
	writeSectionHeader(buf,
		7,                         // sh_name -> ".shstrtab"
		shtStrtab,                 // sh_type
		0,                         // sh_flags
		0,                         // sh_addr
		shstrtabOff,               // sh_offset (file offset)
		uint32(len(shstrtab)),     // sh_size
		0, 0, 1, 0,
	)

	if err := os.WriteFile("testdata/elfs/simple_add.elf", buf.Bytes(), 0644); err != nil {
		panic(err)
	}
}
