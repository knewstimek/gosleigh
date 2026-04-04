//go:build ignore

// gen_sym_elf.go writes a minimal valid ELF32 x86 binary with a .symtab
// section to testdata/elfs/simple_add_sym.elf.
//
// The .text section contains the same 11-byte add function as simple_add.elf.
// The .symtab section contains one STT_FUNC symbol "simple_add" pointing to
// the start of .text.
//
// Run with: go run testdata/elfs/gen_sym_elf.go  (from the repo root)
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
)

// ELF32 constants.
const (
	etExec      = 2 // ET_EXEC
	emI386      = 3 // EM_386
	shtProgbits = 1 // SHT_PROGBITS
	shtSymtab   = 2 // SHT_SYMTAB
	shtStrtab   = 3 // SHT_STRTAB
	shfAlloc    = 2 // SHF_ALLOC
	shfExecinst = 4 // SHF_EXECINSTR
	stbGlobal   = 1 // STB_GLOBAL
	sttFunc     = 2 // STT_FUNC
)

// text is the .text section payload (same as simple_add.elf):
//
//	55           push ebp
//	89 EC        mov  ebp,esp
//	8B 45 08     mov  eax,[ebp+0x8]
//	03 45 0C     add  eax,[ebp+0xC]
//	5D           pop  ebp
//	C3           ret
var text = []byte{0x55, 0x89, 0xEC, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3}

const textVMA = uint32(0x08048034)

// File layout:
//
//	offset   0 ..  51 : ELF32 header            (52 bytes)
//	offset  52 ..  62 : .text data              (11 bytes)
//	offset  63 ..  63 : 1-byte pad to 64
//	offset  64 ..  79 : .shstrtab               (16 bytes)
//	offset  80 ..  95 : .strtab                 (16 bytes)
//	offset  96 .. 127 : .symtab (2 entries * 16 bytes)
//	offset 128 .. 287 : section header table (5 * 40 bytes)

const (
	textOffset    = 52
	shstrtabOff   = 64
	strtabOff     = 80
	symtabOff     = 96
	shTableOffset = 128
)

// shstrtab contains section names.
// Offsets: 0=NUL, 1=".text", 7=".shstrtab", 17=".strtab", 25=".symtab" (33 bytes, padded to 16)
// We keep it compact: null + names.
var shstrtab = []byte("\x00.text\x00.shstrtab\x00.strtab\x00.symtab\x00") // 33 bytes -- but we need it to fit in 16

// Recalculate -- use tighter layout:
// shstrtab (33 bytes), strtab (16 bytes), symtab (32 bytes), shdr table (5*40=200).
// Adjust offsets:
//
//	52 ..  62 : .text (11)
//	63        : pad (1)
//	64 ..  96 : .shstrtab (33)   -- starts at 64
//	97 .. 112 : .strtab (16)     -- starts at 97
//	113.. 144 : .symtab (32)     -- starts at 113
//	145.. 344 : shdr table (5*40=200) -- starts at 145

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

// writeELF32Sym writes one ELF32 Sym32 entry (16 bytes).
func writeELF32Sym(buf *bytes.Buffer, name, value, size uint32, info, other uint8, shndx uint16) {
	pu32(buf, name)
	pu32(buf, value)
	pu32(buf, size)
	buf.WriteByte(info)
	buf.WriteByte(other)
	pu16(buf, shndx)
}

func main() {
	// Section string table: null + ".text\0" + ".shstrtab\0" + ".strtab\0" + ".symtab\0"
	shstrData := []byte("\x00.text\x00.shstrtab\x00.strtab\x00.symtab\x00")
	// offsets: 0=NUL, 1=.text, 7=.shstrtab, 17=.strtab, 25=.symtab

	// Symbol string table: null + "simple_add\0"
	strtabData := []byte("\x00simple_add\x00")
	// offsets: 0=NUL, 1=simple_add

	// symtab: entry 0 = null symbol, entry 1 = simple_add
	var symBuf bytes.Buffer
	// entry 0: all zeros (required null symbol)
	writeELF32Sym(&symBuf, 0, 0, 0, 0, 0, 0)
	// entry 1: simple_add at textVMA, size=len(text), STB_GLOBAL|STT_FUNC, shndx=1 (.text)
	symInfo := uint8(stbGlobal<<4 | sttFunc)
	writeELF32Sym(&symBuf, 1, textVMA, uint32(len(text)), symInfo, 0, 1)
	symtabData := symBuf.Bytes() // 32 bytes

	// Calculate offsets in the final file.
	// 0..51: ELF header (52 bytes)
	// 52..62: .text (11 bytes)
	// 63: pad byte
	elfTextOff := uint32(52)
	shstrOff := uint32(64)
	strOff := shstrOff + uint32(len(shstrData))
	symOff := strOff + uint32(len(strtabData))
	// align symOff to 4
	if symOff%4 != 0 {
		symOff += 4 - (symOff % 4)
	}
	shdrOff := symOff + uint32(len(symtabData))

	// Build file buffer.
	buf := new(bytes.Buffer)

	// ELF header (52 bytes).
	buf.WriteString("\x7fELF") // magic
	buf.WriteByte(1)           // ELFCLASS32
	buf.WriteByte(1)           // ELFDATA2LSB
	buf.WriteByte(1)           // EV_CURRENT
	buf.WriteByte(0)           // ELFOSABI_NONE
	buf.Write(make([]byte, 8)) // padding
	pu16(buf, etExec)
	pu16(buf, emI386)
	pu32(buf, 1)       // e_version
	pu32(buf, textVMA) // e_entry
	pu32(buf, 0)       // e_phoff
	pu32(buf, shdrOff) // e_shoff
	pu32(buf, 0)       // e_flags
	pu16(buf, 52)      // e_ehsize
	pu16(buf, 32)      // e_phentsize
	pu16(buf, 0)       // e_phnum
	pu16(buf, 40)      // e_shentsize
	pu16(buf, 5)       // e_shnum: null + .text + .shstrtab + .strtab + .symtab
	pu16(buf, 2)       // e_shstrndx: .shstrtab is section 2

	if buf.Len() != 52 {
		panic("ELF header size mismatch")
	}

	// .text at file offset 52.
	buf.Write(text)
	// pad to shstrOff
	for buf.Len() < int(shstrOff) {
		buf.WriteByte(0)
	}

	// .shstrtab
	buf.Write(shstrData)

	// .strtab
	buf.Write(strtabData)

	// pad to symOff
	for buf.Len() < int(symOff) {
		buf.WriteByte(0)
	}

	// .symtab
	buf.Write(symtabData)

	// pad to shdrOff
	for buf.Len() < int(shdrOff) {
		buf.WriteByte(0)
	}

	// Section header table (5 entries * 40 bytes each).
	// Section 0: null
	writeSectionHeader(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

	// Section 1: .text (name offset 1 in shstrtab)
	writeSectionHeader(buf,
		1,                    // sh_name -> ".text"
		shtProgbits,          // sh_type
		shfAlloc|shfExecinst, // sh_flags
		textVMA,              // sh_addr
		elfTextOff,           // sh_offset
		uint32(len(text)),    // sh_size
		0, 0, 1, 0,
	)

	// Section 2: .shstrtab (name offset 7)
	writeSectionHeader(buf,
		7,                     // sh_name -> ".shstrtab"
		shtStrtab,             // sh_type
		0,                     // sh_flags
		0,                     // sh_addr
		shstrOff,              // sh_offset
		uint32(len(shstrData)), // sh_size
		0, 0, 1, 0,
	)

	// Section 3: .strtab (name offset 17)
	writeSectionHeader(buf,
		17,                     // sh_name -> ".strtab"
		shtStrtab,              // sh_type
		0,                      // sh_flags
		0,                      // sh_addr
		strOff,                 // sh_offset
		uint32(len(strtabData)), // sh_size
		0, 0, 1, 0,
	)

	// Section 4: .symtab (name offset 25)
	// link=3 (.strtab section index), info=1 (one local symbol before globals)
	writeSectionHeader(buf,
		25,                     // sh_name -> ".symtab"
		shtSymtab,              // sh_type
		0,                      // sh_flags
		0,                      // sh_addr
		symOff,                 // sh_offset
		uint32(len(symtabData)), // sh_size
		3,                      // sh_link -> .strtab
		1,                      // sh_info -> index of first global
		4,                      // sh_addralign
		16,                     // sh_entsize (ELF32_Sym size)
	)

	outPath := "testdata/elfs/simple_add_sym.elf"
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		panic(err)
	}

	// Self-verify: open with debug/elf and check symbol.
	f, err := elf.Open(outPath)
	if err != nil {
		panic("verify: elf.Open: " + err.Error())
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		panic("verify: f.Symbols: " + err.Error())
	}
	found := false
	for _, s := range syms {
		if s.Name == "simple_add" {
			found = true
		}
	}
	if !found {
		panic("verify: symbol 'simple_add' not found in generated ELF")
	}
}
