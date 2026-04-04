//go:build ignore

// gen_import_pe.go generates a minimal valid PE32 binary with an import table
// and writes it to testdata/elfs/simple_add_sym.exe.
//
// The binary imports one function "TestImportFunc" from "testlib.dll".
// The import directory, IAT, and hint/name table are embedded directly in
// the .idata section so that LoadPE32Imports can parse them.
//
// Run with: go run testdata/elfs/gen_import_pe.go  (from the repo root)
package main

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

// pe32DataDirectory is one entry in the optional header data directory array.
type pe32DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

func u16(buf []byte, off int, v uint16) { binary.LittleEndian.PutUint16(buf[off:], v) }
func u32(buf []byte, off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }

func main() {
	const outPath = "testdata/elfs/simple_add_sym.exe"

	// File layout:
	//   0x000 ..  0x03F : DOS stub (e_magic=MZ, e_lfanew=0x40)
	//   0x040 ..  0x043 : PE signature
	//   0x044 ..  0x057 : COFF header (20 bytes)
	//   0x058 ..  0x137 : OptionalHeader32 (224 bytes)
	//   0x138 ..  0x15F : .text section header (40 bytes)
	//   0x160 ..  0x187 : .idata section header (40 bytes)
	//   0x200 ..  0x20C : .text data (13 bytes)
	//   0x400 ..        : .idata data (contains import table)
	//
	// .idata virtual layout (RVA 0x2000):
	//   RVA 0x2000 : Import Directory Table (20 bytes per entry + 20-byte null)
	//   RVA 0x2028 : ILT (2 entries: thunk + null terminator)  -- 8 bytes
	//   RVA 0x2030 : IAT (2 entries: same as ILT)              -- 8 bytes
	//   RVA 0x2038 : Hint/Name "TestImportFunc" (2+14+1 = 17 bytes)
	//   RVA 0x2050 : DLL name "testlib.dll\0"                  -- 12 bytes
	// Total .idata virtual size: 0x5C bytes

	const (
		imageBase   = uint32(0x00400000)
		textRVA     = uint32(0x1000)
		idataRVA    = uint32(0x2000)
		textFileOff = uint32(0x200)
		idataFileOff = uint32(0x400)
	)

	// .idata content (all relative to idataRVA):
	// IDT entry 0: ImportLookupTableRVA=0x2028, TimeDateStamp=0, ForwarderChain=0,
	//              NameRVA=0x2050, ImportAddressTableRVA=0x2030
	// IDT entry 1: all zeros (terminator)
	// ILT (at 0x2028): [0x00002038, 0x00000000]  -- RVA to hint/name, null term
	// IAT (at 0x2030): [0x00002038, 0x00000000]  -- same as ILT pre-binding
	// Hint/Name (at 0x2038): uint16 hint=0, "TestImportFunc\0"
	// DLL name (at 0x2050): "testlib.dll\0"

	idata := make([]byte, 0x80)

	// IDT entry 0 at offset 0x00
	u32(idata, 0x00, idataRVA+0x28) // ImportLookupTableRVA
	u32(idata, 0x04, 0)             // TimeDateStamp
	u32(idata, 0x08, 0)             // ForwarderChain
	u32(idata, 0x0C, idataRVA+0x50) // NameRVA (DLL name)
	u32(idata, 0x10, idataRVA+0x30) // ImportAddressTableRVA

	// IDT terminator at offset 0x14 (already zero)

	// ILT at offset 0x28
	u32(idata, 0x28, idataRVA+0x38) // thunk -> hint/name RVA
	u32(idata, 0x2C, 0)             // null terminator

	// IAT at offset 0x30
	u32(idata, 0x30, idataRVA+0x38) // same as ILT
	u32(idata, 0x34, 0)             // null terminator

	// Hint/Name at offset 0x38: uint16 hint=0, then "TestImportFunc\0"
	u16(idata, 0x38, 0) // hint
	copy(idata[0x3A:], []byte("TestImportFunc\x00"))

	// DLL name at offset 0x50
	copy(idata[0x50:], []byte("testlib.dll\x00"))

	// Build the PE file buffer.
	buf := make([]byte, 0x600)

	// DOS stub.
	buf[0] = 0x4D
	buf[1] = 0x5A
	u32(buf, 0x3C, 0x00000040) // e_lfanew

	// PE signature.
	buf[0x40] = 0x50
	buf[0x41] = 0x45

	// COFF header at 0x44.
	u16(buf, 0x44, 0x014C) // Machine = I386
	u16(buf, 0x46, 2)      // NumberOfSections = 2 (.text + .idata)
	u32(buf, 0x48, 0)      // TimeDateStamp
	u32(buf, 0x4C, 0)      // PointerToSymbolTable
	u32(buf, 0x50, 0)      // NumberOfSymbols
	u16(buf, 0x54, 0x00E0) // SizeOfOptionalHeader = 224
	u16(buf, 0x56, 0x0102) // Characteristics

	// OptionalHeader32 at 0x58.
	o := 0x58
	u16(buf, o, 0x010B)           // Magic PE32
	o += 2
	buf[o] = 0; o++               // MajorLinkerVersion
	buf[o] = 0; o++               // MinorLinkerVersion
	u32(buf, o, 0x200); o += 4    // SizeOfCode
	u32(buf, o, 0x200); o += 4    // SizeOfInitializedData
	u32(buf, o, 0); o += 4        // SizeOfUninitializedData
	u32(buf, o, 0x1000); o += 4   // AddressOfEntryPoint
	u32(buf, o, 0x1000); o += 4   // BaseOfCode
	u32(buf, o, 0x2000); o += 4   // BaseOfData
	u32(buf, o, imageBase); o += 4 // ImageBase
	u32(buf, o, 0x1000); o += 4   // SectionAlignment
	u32(buf, o, 0x200); o += 4    // FileAlignment
	u16(buf, o, 4); o += 2        // MajorOSVersion
	u16(buf, o, 0); o += 2        // MinorOSVersion
	u16(buf, o, 0); o += 2        // MajorImageVersion
	u16(buf, o, 0); o += 2        // MinorImageVersion
	u16(buf, o, 4); o += 2        // MajorSubsystemVersion
	u16(buf, o, 0); o += 2        // MinorSubsystemVersion
	u32(buf, o, 0); o += 4        // Win32VersionValue
	u32(buf, o, 0x4000); o += 4   // SizeOfImage
	u32(buf, o, 0x200); o += 4    // SizeOfHeaders
	u32(buf, o, 0); o += 4        // CheckSum
	u16(buf, o, 3); o += 2        // Subsystem = CUI
	u16(buf, o, 0); o += 2        // DllCharacteristics
	u32(buf, o, 0x100000); o += 4 // SizeOfStackReserve
	u32(buf, o, 0x1000); o += 4   // SizeOfStackCommit
	u32(buf, o, 0x100000); o += 4 // SizeOfHeapReserve
	u32(buf, o, 0x1000); o += 4   // SizeOfHeapCommit
	u32(buf, o, 0); o += 4        // LoaderFlags
	u32(buf, o, 16); o += 4       // NumberOfRvaAndSizes

	// DataDirectory (16 entries * 8 bytes = 128 bytes).
	// Entry 0 = Export  (none)
	// Entry 1 = Import  (.idata)
	u32(buf, o+8, idataRVA)    // Import directory RVA
	u32(buf, o+12, 0x28)       // Import directory size (2 entries * 20 bytes = 40 bytes = 0x28)
	o += 128

	if o != 0x138 {
		log.Fatalf("optional header end mismatch: got 0x%X, want 0x138", o)
	}

	// .text section header at 0x138.
	copy(buf[0x138:], []byte{'.', 't', 'e', 'x', 't', 0, 0, 0})
	u32(buf, 0x140, 13)          // VirtualSize
	u32(buf, 0x144, textRVA)     // VirtualAddress
	u32(buf, 0x148, 0x200)       // SizeOfRawData
	u32(buf, 0x14C, textFileOff) // PointerToRawData
	u32(buf, 0x150, 0)           // PointerToRelocations
	u32(buf, 0x154, 0)           // PointerToLinenumbers
	u16(buf, 0x158, 0)           // NumberOfRelocations
	u16(buf, 0x15A, 0)           // NumberOfLinenumbers
	u32(buf, 0x15C, 0x60000020)  // Characteristics

	// .idata section header at 0x160.
	copy(buf[0x160:], []byte{'.', 'i', 'd', 'a', 't', 'a', 0, 0})
	u32(buf, 0x168, uint32(len(idata))) // VirtualSize
	u32(buf, 0x16C, idataRVA)           // VirtualAddress
	u32(buf, 0x170, 0x200)              // SizeOfRawData
	u32(buf, 0x174, idataFileOff)       // PointerToRawData
	u32(buf, 0x178, 0)                  // PointerToRelocations
	u32(buf, 0x17C, 0)                  // PointerToLinenumbers
	u16(buf, 0x180, 0)                  // NumberOfRelocations
	u16(buf, 0x182, 0)                  // NumberOfLinenumbers
	u32(buf, 0x184, 0xC0000040)         // Characteristics (read+write+init data)

	// .text data at 0x200.
	code := []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3, 0x00, 0x00}
	copy(buf[textFileOff:], code)

	// .idata data at 0x400.
	copy(buf[idataFileOff:], idata)

	if err := os.WriteFile(outPath, buf, 0644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outPath, len(buf))

	// Self-verification: parse with debug/pe.
	f, err := pe.Open(outPath)
	if err != nil {
		log.Fatalf("verify: pe.Open: %v", err)
	}
	defer f.Close()

	if _, ok := f.OptionalHeader.(*pe.OptionalHeader32); !ok {
		log.Fatalf("verify: not PE32")
	}

	found := false
	for _, sec := range f.Sections {
		if sec.Name == ".idata" {
			found = true
		}
	}
	if !found {
		log.Fatalf("verify: .idata section not found")
	}
	fmt.Println("verification OK")
}
