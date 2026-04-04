//go:build ignore

// gen_pe.go generates a minimal valid PE32 binary for testing.
// Run with: go run testdata/elfs/gen_pe.go
package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

func main() {
	const outPath = "testdata/elfs/simple_add.exe"

	buf := make([]byte, 0x400)

	// DOS stub: e_magic = MZ, e_lfanew = 0x40
	buf[0] = 0x4D
	buf[1] = 0x5A
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x00000040)

	// PE signature at 0x40
	buf[0x40] = 0x50
	buf[0x41] = 0x45
	buf[0x42] = 0x00
	buf[0x43] = 0x00

	// COFF header at 0x44 (20 bytes)
	binary.LittleEndian.PutUint16(buf[0x44:], 0x014C) // Machine = I386
	binary.LittleEndian.PutUint16(buf[0x46:], 1)      // NumberOfSections = 1
	binary.LittleEndian.PutUint32(buf[0x48:], 0)      // TimeDateStamp
	binary.LittleEndian.PutUint32(buf[0x4C:], 0)      // PointerToSymbolTable
	binary.LittleEndian.PutUint32(buf[0x50:], 0)      // NumberOfSymbols
	binary.LittleEndian.PutUint16(buf[0x54:], 0x00E0) // SizeOfOptionalHeader = 224
	binary.LittleEndian.PutUint16(buf[0x56:], 0x0102) // Characteristics

	// OptionalHeader32 at 0x58 (224 bytes, magic=0x010B)
	o := 0x58
	binary.LittleEndian.PutUint16(buf[o:], 0x010B) // Magic
	o += 2
	buf[o] = 0 // MajorLinkerVersion
	o++
	buf[o] = 0 // MinorLinkerVersion
	o++
	binary.LittleEndian.PutUint32(buf[o:], 0x200) // SizeOfCode
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0) // SizeOfInitializedData
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0) // SizeOfUninitializedData
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x1000) // AddressOfEntryPoint
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x1000) // BaseOfCode
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x2000) // BaseOfData
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x00400000) // ImageBase
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x1000) // SectionAlignment
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x200) // FileAlignment
	o += 4
	binary.LittleEndian.PutUint16(buf[o:], 4) // MajorOSVersion
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 0) // MinorOSVersion
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 0) // MajorImageVersion
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 0) // MinorImageVersion
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 4) // MajorSubsystemVersion
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 0) // MinorSubsystemVersion
	o += 2
	binary.LittleEndian.PutUint32(buf[o:], 0) // Win32VersionValue
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x2000) // SizeOfImage
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x200) // SizeOfHeaders
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0) // CheckSum
	o += 4
	binary.LittleEndian.PutUint16(buf[o:], 3) // Subsystem = CUI
	o += 2
	binary.LittleEndian.PutUint16(buf[o:], 0) // DllCharacteristics
	o += 2
	binary.LittleEndian.PutUint32(buf[o:], 0x100000) // SizeOfStackReserve
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x1000) // SizeOfStackCommit
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x100000) // SizeOfHeapReserve
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0x1000) // SizeOfHeapCommit
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 0) // LoaderFlags
	o += 4
	binary.LittleEndian.PutUint32(buf[o:], 16) // NumberOfRvaAndSizes
	o += 4
	// DataDirectory: 16 * 8 = 128 bytes of zeros (already zeroed)
	o += 128

	// o should now be 0x138
	if o != 0x138 {
		log.Fatalf("section header offset mismatch: got 0x%X, want 0x138", o)
	}

	// Section header at 0x138 (40 bytes)
	copy(buf[0x138:], []byte{'.', 't', 'e', 'x', 't', 0, 0, 0}) // Name
	binary.LittleEndian.PutUint32(buf[0x140:], 13)               // VirtualSize
	binary.LittleEndian.PutUint32(buf[0x144:], 0x1000)           // VirtualAddress
	binary.LittleEndian.PutUint32(buf[0x148:], 0x200)            // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[0x14C:], 0x200)            // PointerToRawData
	binary.LittleEndian.PutUint32(buf[0x150:], 0)                // PointerToRelocations
	binary.LittleEndian.PutUint32(buf[0x154:], 0)                // PointerToLinenumbers
	binary.LittleEndian.PutUint16(buf[0x158:], 0)                // NumberOfRelocations
	binary.LittleEndian.PutUint16(buf[0x15A:], 0)                // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(buf[0x15C:], 0x60000020)       // Characteristics

	// .text section data at 0x200: x86 add() function (13 bytes)
	code := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3, 0x00, 0x00}
	copy(buf[0x200:], code)

	if err := os.WriteFile(outPath, buf, 0644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outPath, len(buf))

	// Self-verification: parse the file we just wrote.
	f, err := pe.Open(outPath)
	if err != nil {
		log.Fatalf("verification: pe.Open failed: %v", err)
	}
	defer f.Close()

	if _, ok := f.OptionalHeader.(*pe.OptionalHeader32); !ok {
		log.Fatalf("verification: OptionalHeader is not *pe.OptionalHeader32")
	}

	var found bool
	for _, sec := range f.Sections {
		if sec.Name == ".text" {
			if sec.VirtualAddress != 0x1000 {
				log.Fatalf("verification: .text VirtualAddress = 0x%X, want 0x1000", sec.VirtualAddress)
			}
			found = true
			break
		}
	}
	if !found {
		log.Fatalf("verification: .text section not found")
	}

	fmt.Println("verification OK")
}
