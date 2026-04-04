// Copyright 2026 The Gosleigh Authors. Apache 2.0.
// Corresponds to Ghidra's PeLoader / ImageSectionHeader handling.

package loader

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// LoadPE32TextSection opens a PE32 (32-bit Windows executable) file and returns
// the raw bytes of the .text section along with the section's virtual memory address.
// Returns an error if the file is not PE32 (e.g. PE32+/64-bit), or has no .text section.
func LoadPE32TextSection(path string) ([]byte, uint64, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("pe.Open %s: %w", path, err)
	}
	defer f.Close()

	hdr32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, 0, fmt.Errorf("%s: not a PE32 file (PE32+ or unknown optional header)", path)
	}

	for _, sec := range f.Sections {
		if sec.Name == ".text" {
			data, err := sec.Data()
			if err != nil {
				return nil, 0, fmt.Errorf("reading .text section from %s: %w", path, err)
			}
			// Trim to VirtualSize if smaller than raw data to match actual code size.
			if vs := int(sec.VirtualSize); vs > 0 && vs < len(data) {
				data = data[:vs]
			}
			vma := uint64(sec.VirtualAddress) + uint64(hdr32.ImageBase)
			return data, vma, nil
		}
	}

	return nil, 0, fmt.Errorf("%s: no .text section found", path)
}

// Ensure the file handle is closed even on early returns (used via defer above).
var _ = os.ErrClosed

// LoadPE32Exports reads the COFF symbol table from a PE32 file and returns a
// SymbolTable containing all externally-visible (IMAGE_SYM_CLASS_EXTERNAL)
// symbols that belong to a valid section.
//
// Using the COFF symbol table (f.Symbols) rather than the PE export directory
// is preferred: COFF symbols are present in non-stripped executables and object
// files, while the export directory only exists in DLLs with explicit exports.
//
// Returns an empty table (not an error) when the file has no COFF symbol table.
func LoadPE32Exports(path string) (*SymbolTable, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	oh32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("not a PE32 file")
	}

	st := NewSymbolTable()

	// f.Symbols is populated by pe.Open from the COFF symbol table;
	// nil means the file has no COFF symbol table (stripped binary or DLL-only export).
	symbols := f.Symbols
	if symbols == nil {
		return st, nil
	}

	for _, sym := range symbols {
		// IMAGE_SYM_CLASS_EXTERNAL (2): symbol is visible outside the translation unit.
		if sym.StorageClass != 2 {
			continue
		}
		// SectionNumber is 1-based; skip absolute/undefined (<=0) symbols.
		if sym.SectionNumber < 1 || int(sym.SectionNumber) > len(f.Sections) {
			continue
		}
		sect := f.Sections[sym.SectionNumber-1]
		// addr = ImageBase + section VirtualAddress + symbol offset within section.
		addr := uint64(oh32.ImageBase) + uint64(sect.VirtualAddress) + uint64(sym.Value)
		st.Add(Symbol{
			Name:    sym.Name,
			Address: addr,
		})
	}

	return st, nil
}

// LoadPE32Imports reads the PE import directory and returns a SymbolTable
// mapping each imported function's hint-name to a synthetic address derived
// from its import address table entry RVA + ImageBase.
// Returns an empty table (not an error) when there is no import directory.
func LoadPE32Imports(path string) (*SymbolTable, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("LoadPE32Imports: open %s: %w", path, err)
	}
	defer f.Close()

	hdr32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("LoadPE32Imports: %s is not PE32", path)
	}
	imageBase := uint64(hdr32.ImageBase)

	st := NewSymbolTable()

	// DataDirectory[1] = import directory.
	if len(hdr32.DataDirectory) < 2 {
		return st, nil
	}
	impDir := hdr32.DataDirectory[1]
	if impDir.VirtualAddress == 0 || impDir.Size == 0 {
		return st, nil
	}

	raw, secBase, err := readRVASection(f, impDir.VirtualAddress)
	if err != nil {
		return st, nil
	}

	// Import Directory Table: each entry is 20 bytes.
	//   +0   ImportLookupTableRVA  (4)
	//   +4   TimeDateStamp         (4)
	//   +8   ForwarderChain        (4)
	//   +12  NameRVA               (4)
	//   +16  ImportAddressTableRVA (4)
	// The table ends with an all-zero 20-byte entry.
	off := int(impDir.VirtualAddress) - int(secBase)
	for off+20 <= len(raw) {
		iltRVA := binary.LittleEndian.Uint32(raw[off:])
		iatRVA := binary.LittleEndian.Uint32(raw[off+16:])
		if iltRVA == 0 && iatRVA == 0 {
			break // null terminator entry
		}
		// Use ILT to find hint/name entries; walk alongside IAT for addresses.
		parseImportThunks(raw, secBase, imageBase, iltRVA, iatRVA, st)
		off += 20
	}
	return st, nil
}

// parseImportThunks walks the Import Lookup Table (ILT) for one import
// descriptor, extracting hint/name pairs and pairing them with their
// Import Address Table (IAT) virtual addresses.
func parseImportThunks(raw []byte, secBase uint32, imageBase uint64, iltRVA, iatRVA uint32, st *SymbolTable) {
	iltOff := int(iltRVA) - int(secBase)
	iatOff := int(iatRVA) - int(secBase)
	if iltOff < 0 || iatOff < 0 {
		return
	}
	for {
		if iltOff+4 > len(raw) || iatOff+4 > len(raw) {
			break
		}
		thunk := binary.LittleEndian.Uint32(raw[iltOff:])
		if thunk == 0 {
			break
		}
		// Bit 31 set => ordinal import (no name).
		if thunk&0x80000000 != 0 {
			iltOff += 4
			iatOff += 4
			continue
		}
		// Bits 30:0 are RVA to hint/name: uint16 hint + null-terminated name.
		hnOff := int(thunk&0x7FFFFFFF) - int(secBase) + 2 // skip 2-byte hint
		if hnOff < 0 || hnOff >= len(raw) {
			iltOff += 4
			iatOff += 4
			continue
		}
		end := strings.IndexByte(string(raw[hnOff:]), 0)
		if end < 0 {
			iltOff += 4
			iatOff += 4
			continue
		}
		name := string(raw[hnOff : hnOff+end])
		// IAT slot VA = imageBase + iatRVA + index*4
		// where index is the slot's position relative to the start of this IAT.
		idx := (iatOff - (int(iatRVA) - int(secBase))) / 4
		slotVA := imageBase + uint64(iatRVA) + uint64(idx)*4
		if name != "" {
			st.Add(Symbol{Name: name, Address: slotVA})
		}
		iltOff += 4
		iatOff += 4
	}
}

// readRVASection returns the raw bytes of the section that contains rva,
// along with that section's VirtualAddress (used as the base for offset math).
func readRVASection(f *pe.File, rva uint32) ([]byte, uint32, error) {
	for _, sec := range f.Sections {
		start := sec.VirtualAddress
		end := start + sec.VirtualSize
		if end == 0 {
			end = start + sec.Size
		}
		if rva >= start && rva < end {
			data, err := sec.Data()
			if err != nil {
				return nil, 0, err
			}
			return data, start, nil
		}
	}
	return nil, 0, fmt.Errorf("no section contains RVA 0x%x", rva)
}
