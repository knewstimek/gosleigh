// Copyright 2026 The Gosleigh Authors. Apache 2.0.

package loader_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gosleigh/pkg/loader"
)

// TestSymbolTableBasic verifies Add, Lookup, All, and Len.
func TestSymbolTableBasic(t *testing.T) {
	st := loader.NewSymbolTable()
	if st.Len() != 0 {
		t.Fatalf("expected empty table, got len=%d", st.Len())
	}

	st.Add(loader.Symbol{Name: "main", Address: 0x1000, Size: 64})
	st.Add(loader.Symbol{Name: "helper", Address: 0x800, Size: 32})
	st.Add(loader.Symbol{Name: "exit", Address: 0x2000, Size: 16})

	if st.Len() != 3 {
		t.Fatalf("expected 3 symbols, got %d", st.Len())
	}

	sym, ok := st.Lookup(0x1000)
	if !ok {
		t.Fatal("Lookup(0x1000) returned false")
	}
	if sym.Name != "main" {
		t.Fatalf("expected name 'main', got %q", sym.Name)
	}

	_, ok = st.Lookup(0x9999)
	if ok {
		t.Fatal("Lookup of missing address should return false")
	}

	all := st.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d symbols, want 3", len(all))
	}
	// All() must be sorted by address ascending.
	if all[0].Address > all[1].Address || all[1].Address > all[2].Address {
		t.Fatalf("All() not sorted: %v", all)
	}
}

// TestSymbolTableOverwrite verifies that Add overwrites an existing symbol.
func TestSymbolTableOverwrite(t *testing.T) {
	st := loader.NewSymbolTable()
	st.Add(loader.Symbol{Name: "old", Address: 0x100})
	st.Add(loader.Symbol{Name: "new", Address: 0x100})
	sym, ok := st.Lookup(0x100)
	if !ok {
		t.Fatal("Lookup after overwrite returned false")
	}
	if sym.Name != "new" {
		t.Fatalf("expected 'new', got %q", sym.Name)
	}
	if st.Len() != 1 {
		t.Fatalf("expected 1 symbol after overwrite, got %d", st.Len())
	}
}

// TestLoadELFSymbols verifies that LoadELFSymbols returns a non-error result
// on the simple_add_sym.elf fixture (which has a .symtab).
func TestLoadELFSymbols(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	elfPath := filepath.Join(dir, "../../testdata/elfs/simple_add_sym.elf")

	st, err := loader.LoadELFSymbols(elfPath)
	if err != nil {
		t.Fatalf("LoadELFSymbols: %v", err)
	}
	if st == nil {
		t.Fatal("LoadELFSymbols returned nil table")
	}
	t.Logf("LoadELFSymbols: %d symbols", st.Len())
	if st.Len() == 0 {
		t.Fatal("expected at least one symbol in simple_add_sym.elf")
	}

	// The fixture must have a symbol named "simple_add".
	found := false
	for _, sym := range st.All() {
		t.Logf("  0x%x  %s (size=%d)", sym.Address, sym.Name, sym.Size)
		if sym.Name == "simple_add" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected symbol 'simple_add' in symbol table")
	}
}

// TestLoadDWARFFunctionsNoData verifies that LoadDWARFFunctions on a plain ELF
// with no DWARF returns an empty table without error.
func TestLoadDWARFFunctionsNoData(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	// simple_add.elf has no DWARF -- should return empty, not error.
	elfPath := filepath.Join(dir, "../../testdata/elfs/simple_add.elf")

	st, err := loader.LoadDWARFFunctions(elfPath)
	if err != nil {
		t.Fatalf("LoadDWARFFunctions: %v", err)
	}
	if st == nil {
		t.Fatal("LoadDWARFFunctions returned nil table")
	}
	t.Logf("LoadDWARFFunctions (no DWARF): %d symbols", st.Len())
}

// buildCOFFPE32 constructs a minimal valid PE32 binary in memory with one
// COFF external symbol "simple_add" in the .text section. The binary is
// written to a temp file and the path is returned.
//
// Layout:
//
//	0x000-0x03F  DOS stub (e_lfanew=0x40)
//	0x040-0x043  PE signature
//	0x044-0x057  COFF header (PointerToSymbolTable=0x400, NumberOfSymbols=1)
//	0x058-0x137  OptionalHeader32 (224 bytes, no data directories)
//	0x138-0x15F  .text section header (VirtualAddress=0x1000, raw at 0x200)
//	0x200-0x3FF  .text raw data (sector-padded)
//	0x400-0x411  COFF symbol table (1 entry, 18 bytes)
//	0x412-0x41F  String table ("simple_add\0")
func buildCOFFPE32(t *testing.T) string {
	t.Helper()

	buf := make([]byte, 0x500)
	pu16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(buf[off:], v) }
	pu32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }

	const (
		imageBase   = uint32(0x00400000)
		textRVA     = uint32(0x1000)
		textFileOff = uint32(0x200)
		symTabOff   = uint32(0x400)
		numSymbols  = uint32(1)
	)

	// DOS stub: MZ magic + e_lfanew at 0x3C.
	buf[0x00] = 0x4D // 'M'
	buf[0x01] = 0x5A // 'Z'
	pu32(0x3C, 0x40) // e_lfanew

	// PE signature at 0x40.
	buf[0x40] = 'P'
	buf[0x41] = 'E'

	// COFF header at 0x44.
	pu16(0x44, 0x014C) // Machine = i386
	pu16(0x46, 1)      // NumberOfSections = 1
	pu32(0x48, 0)      // TimeDateStamp
	pu32(0x4C, symTabOff)   // PointerToSymbolTable
	pu32(0x50, numSymbols)  // NumberOfSymbols
	pu16(0x54, 0x00E0) // SizeOfOptionalHeader = 224
	pu16(0x56, 0x0102) // Characteristics

	// OptionalHeader32 at 0x58 (224 bytes total, ends at 0x138).
	o := 0x58
	pu16(o, 0x010B); o += 2      // Magic = PE32
	buf[o] = 0; o++              // MajorLinkerVersion
	buf[o] = 0; o++              // MinorLinkerVersion
	pu32(o, 0x200); o += 4       // SizeOfCode
	pu32(o, 0); o += 4           // SizeOfInitializedData
	pu32(o, 0); o += 4           // SizeOfUninitializedData
	pu32(o, textRVA); o += 4     // AddressOfEntryPoint
	pu32(o, textRVA); o += 4     // BaseOfCode
	pu32(o, 0); o += 4           // BaseOfData
	pu32(o, imageBase); o += 4   // ImageBase
	pu32(o, 0x1000); o += 4      // SectionAlignment
	pu32(o, 0x200); o += 4       // FileAlignment
	pu16(o, 4); o += 2           // MajorOperatingSystemVersion
	pu16(o, 0); o += 2           // MinorOperatingSystemVersion
	pu16(o, 0); o += 2           // MajorImageVersion
	pu16(o, 0); o += 2           // MinorImageVersion
	pu16(o, 4); o += 2           // MajorSubsystemVersion
	pu16(o, 0); o += 2           // MinorSubsystemVersion
	pu32(o, 0); o += 4           // Win32VersionValue
	pu32(o, 0x2000); o += 4      // SizeOfImage
	pu32(o, 0x200); o += 4       // SizeOfHeaders
	pu32(o, 0); o += 4           // CheckSum
	pu16(o, 3); o += 2           // Subsystem = CUI
	pu16(o, 0); o += 2           // DllCharacteristics
	pu32(o, 0x100000); o += 4    // SizeOfStackReserve
	pu32(o, 0x1000); o += 4      // SizeOfStackCommit
	pu32(o, 0x100000); o += 4    // SizeOfHeapReserve
	pu32(o, 0x1000); o += 4      // SizeOfHeapCommit
	pu32(o, 0); o += 4           // LoaderFlags
	pu32(o, 16); o += 4          // NumberOfRvaAndSizes = 16 (all entries present but zero)
	o += 128                     // DataDirectory[16] -- all zeros, no actual directories

	if o != 0x138 {
		t.Fatalf("optional header end at 0x%X, want 0x138", o)
	}

	// .text section header at 0x138.
	copy(buf[0x138:], ".text\x00\x00\x00")
	pu32(0x140, 13)           // VirtualSize
	pu32(0x144, textRVA)      // VirtualAddress
	pu32(0x148, 0x200)        // SizeOfRawData
	pu32(0x14C, textFileOff)  // PointerToRawData
	pu32(0x150, 0)            // PointerToRelocations
	pu32(0x154, 0)            // PointerToLinenumbers
	pu16(0x158, 0)            // NumberOfRelocations
	pu16(0x15A, 0)            // NumberOfLinenumbers
	pu32(0x15C, 0x60000020)   // Characteristics: code, execute, read

	// .text code (simple add function).
	copy(buf[textFileOff:], []byte{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x03, 0x45, 0x0C, 0x5D, 0xC3})

	// COFF symbol table at 0x400.
	// Each entry is 18 bytes (COFFSymbol: Name[8] + Value(4) + SectionNumber(2) + Type(2) + StorageClass(1) + NumAux(1)).
	// "simple_add" is 10 chars -- too long for inline; use long-name form:
	//   Name[0:4] = 0x00000000 (signals long name)
	//   Name[4:8] = offset into string table (4, past the 4-byte size field)
	binary.LittleEndian.PutUint32(buf[0x400:], 0)          // long-name indicator
	binary.LittleEndian.PutUint32(buf[0x404:], 4)          // offset 4 in string table
	binary.LittleEndian.PutUint32(buf[0x408:], 0)          // Value = 0 (offset within section)
	binary.LittleEndian.PutUint16(buf[0x40C:], 1)          // SectionNumber = 1 (.text)
	binary.LittleEndian.PutUint16(buf[0x40E:], 0x0020)     // Type = function
	buf[0x410] = 2                                          // StorageClass = IMAGE_SYM_CLASS_EXTERNAL
	buf[0x411] = 0                                          // NumberOfAuxSymbols

	// String table at 0x412 (symTabOff + numSymbols*18 = 0x400 + 18 = 0x412).
	// Layout: 4-byte total size, then null-terminated strings.
	const symName = "simple_add"
	strTableSize := uint32(4 + len(symName) + 1) // 4-byte size field + string + null
	binary.LittleEndian.PutUint32(buf[0x412:], strTableSize)
	copy(buf[0x416:], symName+"\x00")

	tmp := filepath.Join(t.TempDir(), "coff_sym.exe")
	if err := os.WriteFile(tmp, buf, 0644); err != nil {
		t.Fatalf("write COFF PE: %v", err)
	}
	return tmp
}

// TestLoadPE32Exports verifies that LoadPE32Exports recovers the "simple_add"
// symbol from a PE32 binary that has a COFF symbol table.
func TestLoadPE32Exports(t *testing.T) {
	fixturePath := buildCOFFPE32(t)
	st, err := loader.LoadPE32Exports(fixturePath)
	if err != nil {
		t.Fatalf("LoadPE32Exports: %v", err)
	}
	if st.Len() == 0 {
		t.Fatal("expected at least one COFF symbol")
	}
	found := false
	for _, sym := range st.All() {
		t.Logf("  0x%x  %s", sym.Address, sym.Name)
		if sym.Name == "simple_add" {
			found = true
		}
	}
	if !found {
		t.Errorf("COFF symbol 'simple_add' not found in PE exports, got: %v", st.All())
	}
}

// TestLoadPE32Exports_NoCOFF verifies that LoadPE32Exports returns an empty
// table (not an error) when the PE has no COFF symbol table.
func TestLoadPE32Exports_NoCOFF(t *testing.T) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.exe")
	st, err := loader.LoadPE32Exports(fixturePath)
	if err != nil {
		t.Fatalf("LoadPE32Exports: %v", err)
	}
	if st == nil {
		t.Fatal("LoadPE32Exports returned nil table")
	}
	t.Logf("LoadPE32Exports (no COFF): %d symbols", st.Len())
}

// TestLoadPE32Exports_InvalidFile verifies that LoadPE32Exports returns an
// error for garbage input.
func TestLoadPE32Exports_InvalidFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "garbage.exe")
	os.WriteFile(tmp, []byte("not a pe file"), 0644)
	_, err := loader.LoadPE32Exports(tmp)
	if err == nil {
		t.Error("expected error for invalid PE file")
	}
}

// TestLoadPE32Exports_Nonexistent verifies that LoadPE32Exports returns an
// error for a nonexistent path.
func TestLoadPE32Exports_Nonexistent(t *testing.T) {
	_, err := loader.LoadPE32Exports("/nonexistent/path.exe")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestLoadELFSymbols_InvalidFile verifies that LoadELFSymbols returns an
// error for garbage input.
func TestLoadELFSymbols_InvalidFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "garbage.elf")
	os.WriteFile(tmp, []byte("not an elf file"), 0644)
	_, err := loader.LoadELFSymbols(tmp)
	if err == nil {
		t.Error("expected error for invalid ELF file")
	}
}

// TestLoadELFSymbols_Nonexistent verifies that LoadELFSymbols returns an
// error for a nonexistent path.
func TestLoadELFSymbols_Nonexistent(t *testing.T) {
	_, err := loader.LoadELFSymbols("/nonexistent/path.elf")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestLoadELFSymbols_TruncatedFile verifies that LoadELFSymbols returns an
// error when the ELF file is truncated (only the first 20 bytes retained).
func TestLoadELFSymbols_TruncatedFile(t *testing.T) {
	_, curFile, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.elf")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "truncated.elf")
	os.WriteFile(tmp, data[:20], 0644)
	_, err = loader.LoadELFSymbols(tmp)
	if err == nil {
		t.Error("expected error for truncated ELF file")
	}
}

// TestLoadPE32Imports_InvalidFile verifies that LoadPE32Imports returns an
// error for garbage input.
func TestLoadPE32Imports_InvalidFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "garbage.exe")
	os.WriteFile(tmp, []byte("not a pe file"), 0644)
	_, err := loader.LoadPE32Imports(tmp)
	if err == nil {
		t.Error("expected error for invalid PE file")
	}
}

// TestLoadDWARFFunctions_InvalidFile verifies that LoadDWARFFunctions returns
// an error for garbage input (neither valid ELF nor PE).
func TestLoadDWARFFunctions_InvalidFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "garbage.bin")
	os.WriteFile(tmp, []byte("not a valid binary"), 0644)
	_, err := loader.LoadDWARFFunctions(tmp)
	if err == nil {
		t.Error("expected error for invalid file")
	}
}

// TestLoadDWARFFunctions_PENoDebug verifies that LoadDWARFFunctions returns an
// empty table (not an error) on a PE without DWARF debug information.
func TestLoadDWARFFunctions_PENoDebug(t *testing.T) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.exe")
	st, err := loader.LoadDWARFFunctions(fixturePath)
	if err != nil {
		t.Fatalf("LoadDWARFFunctions on PE: %v", err)
	}
	// simple_add_sym.exe has no DWARF info, should return empty table.
	if st.Len() != 0 {
		t.Errorf("expected empty symbol table for PE without DWARF, got %d symbols", st.Len())
	}
}

// TestLoadPE32ImportsNoImports verifies that LoadPE32Imports on a PE with no
// import directory returns an empty table without error.
func TestLoadPE32ImportsNoImports(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	pePath := filepath.Join(dir, "../../testdata/elfs/simple_add.exe")

	st, err := loader.LoadPE32Imports(pePath)
	if err != nil {
		t.Fatalf("LoadPE32Imports: %v", err)
	}
	if st == nil {
		t.Fatal("LoadPE32Imports returned nil table")
	}
	t.Logf("LoadPE32Imports (no imports): %d symbols", st.Len())
}

// TestLoadPE32ImportsSymExe verifies that LoadPE32Imports on the fixture PE
// that has an import table returns at least one import symbol.
func TestLoadPE32ImportsSymExe(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(file)
	pePath := filepath.Join(dir, "../../testdata/elfs/simple_add_sym.exe")

	st, err := loader.LoadPE32Imports(pePath)
	if err != nil {
		t.Fatalf("LoadPE32Imports: %v", err)
	}
	if st == nil {
		t.Fatal("LoadPE32Imports returned nil table")
	}
	t.Logf("LoadPE32Imports: %d symbols", st.Len())
	for _, sym := range st.All() {
		t.Logf("  0x%x  %s", sym.Address, sym.Name)
	}
	if st.Len() == 0 {
		t.Fatal("expected at least one import symbol in simple_add_sym.exe")
	}
}

// -- Fuzz tests ---------------------------------------------------------------
// Each fuzz target writes the corpus bytes to a temp file and calls the loader.
// The invariant is: no panic on any input, regardless of content.

func FuzzLoadELFSymbols(f *testing.F) {
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("not elf"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.elf")
		os.WriteFile(tmp, data, 0644)
		loader.LoadELFSymbols(tmp) // must not panic
	})
}

func FuzzLoadPE32Exports(f *testing.F) {
	f.Add([]byte("MZ"))
	f.Add([]byte("not pe"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.exe")
		os.WriteFile(tmp, data, 0644)
		loader.LoadPE32Exports(tmp) // must not panic
	})
}

func FuzzLoadPE32Imports(f *testing.F) {
	f.Add([]byte("MZ"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.exe")
		os.WriteFile(tmp, data, 0644)
		loader.LoadPE32Imports(tmp) // must not panic
	})
}

func FuzzLoadDWARFFunctions(f *testing.F) {
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("MZ"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := filepath.Join(t.TempDir(), "fuzz.bin")
		os.WriteFile(tmp, data, 0644)
		loader.LoadDWARFFunctions(tmp) // must not panic
	})
}

// -- Benchmarks ---------------------------------------------------------------
// Each benchmark runs against the on-disk fixture to measure real I/O + parse time.

func BenchmarkLoadELFSymbols(b *testing.B) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.elf")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loader.LoadELFSymbols(fixturePath)
	}
}

func BenchmarkLoadPE32Exports(b *testing.B) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.exe")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loader.LoadPE32Exports(fixturePath)
	}
}

func BenchmarkLoadPE32Imports(b *testing.B) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.exe")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loader.LoadPE32Imports(fixturePath)
	}
}

func BenchmarkLoadDWARFFunctions(b *testing.B) {
	_, curFile, _, _ := runtime.Caller(0)
	fixturePath := filepath.Join(filepath.Dir(curFile), "..", "..", "testdata", "elfs", "simple_add_sym.elf")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		loader.LoadDWARFFunctions(fixturePath)
	}
}
