# E6: Symbol Recovery (PE Import / ELF Symbol / DWARF Function Names)

## Objective

Load function names from binary formats and propagate them into the decompiler output.
PrintC already uses `fd.DisplayName()` when non-empty (printc.go line 326-327).
The missing pieces are: (1) symbol loaders, (2) `Funcdata.SetDisplayName`, (3) bridge wiring.

Target: when decompiling a PE or ELF binary with known symbol names, PrintC output uses
the actual function name instead of the generic "bridge_func" or user-supplied name.

## What is already implemented (DO NOT re-implement):

- `pkg/loader/pe.go`: `LoadPE32TextSection(path) ([]byte, uint64, error)`
- `pkg/loader/elf.go`: `LoadELF32TextSection(path) ([]byte, uint64, error)`
- `pkg/pcode/funcdata.go`: `DisplayName() string` getter (field already exists)
- `pkg/bridge/bridge.go`: `BuildConfig.Name string`, `Build()` returns `*Result`
- PrintC: `fd.DisplayName()` used for function name if non-empty (printc.go:326-327)
- `testdata/elfs/simple_add.elf`, `testdata/elfs/simple_add.exe`: existing test fixtures (no symbols)

## Part 1: SymbolTable type

### pkg/loader/symbols.go (new file)

```go
// Symbol is a named address in a binary.
type Symbol struct {
    Name    string
    Address uint64 // virtual address (VMA)
    Size    uint64 // 0 if unknown
}

// SymbolTable maps virtual addresses to symbol names.
// Used to associate function names from PE import/export tables,
// ELF .symtab/.dynsym sections, or DWARF debug info with code addresses.
type SymbolTable struct {
    byAddr map[uint64]Symbol
}

func NewSymbolTable() *SymbolTable
func (st *SymbolTable) Add(s Symbol)
// Lookup returns the symbol at addr, or (Symbol{}, false) if not found.
func (st *SymbolTable) Lookup(addr uint64) (Symbol, bool)
// All returns all symbols sorted by address.
func (st *SymbolTable) All() []Symbol
// Len returns the number of symbols.
func (st *SymbolTable) Len() int
```

## Part 2: Symbol loaders

### pkg/loader/pe.go additions

```go
// LoadPE32Exports returns a SymbolTable of exported functions from a PE32 binary.
// Each symbol's Address is ImageBase + VirtualAddress of the export.
// Returns an empty SymbolTable (not nil) when there are no exports or the
// export directory is absent. Returns error only on file open/parse failure.
//
// Uses debug/pe standard library: f.Symbols() and f.Section(".edata") or
// iterates the export directory via OptionalHeader DataDirectory[0].
// Simpler alternative: use pe.File.Symbols() which returns COFF symbol table entries.
// For PE32 export table parsing use the DataDirectory export approach OR just use
// pe.File.Symbols() which covers COFF debug symbols.
//
// Implementation note: Go stdlib debug/pe has no Export() method.
// Use COFF symbol table via f.Symbols() for named functions.
// f.Symbols() returns []pe.Symbol where Symbol.Name is the function name and
// Symbol.Value is the RVA (relative to section VirtualAddress).
// For the address: Symbol.SectionNumber -> f.Sections[n-1].VirtualAddress + ImageBase + Symbol.Value
func LoadPE32Exports(path string) (*SymbolTable, error)

// LoadPE32Imports returns a SymbolTable of imported functions from a PE32 binary.
// Uses pe.File.ImportedSymbols() (Go stdlib) which returns strings like "KERNEL32.dll:ExitProcess".
// Address is set to 0 for imported symbols since IAT addresses require runtime linking;
// the Name field is set to "DLL!FuncName" format.
// Returns an empty SymbolTable (not nil) when there are no imports.
func LoadPE32Imports(path string) (*SymbolTable, error)
```

Implementation note for LoadPE32Exports with COFF symbols:
```go
f, err := pe.Open(path)
// ...
hdr32, ok := f.OptionalHeader.(*pe.OptionalHeader32)
syms, _ := f.Symbols() // nil when no COFF symbol table
for _, s := range syms {
    if int(s.SectionNumber) < 1 || int(s.SectionNumber) > len(f.Sections) { continue }
    if s.StorageClass != pe.IMAGE_SYM_CLASS_EXTERNAL { continue } // exported functions
    sec := f.Sections[s.SectionNumber-1]
    addr := uint64(hdr32.ImageBase) + uint64(sec.VirtualAddress) + uint64(s.Value)
    st.Add(Symbol{Name: s.Name, Address: addr})
}
```

For LoadPE32Imports, use `f.ImportedSymbols()` which returns `[]string` like "KERNEL32.DLL:ExitProcess".
Convert each to Symbol with Address=0 and Name="DLL!Func" by replacing ":" with "!".

### pkg/loader/elf.go additions

```go
// LoadELFSymbols returns a SymbolTable from an ELF file's .symtab and/or .dynsym.
// Tries Symbols() first (static .symtab), then DynamicSymbols() (.dynsym).
// Only includes symbols with non-empty names and STT_FUNC type (or any type when
// STT_FUNC filtering would return zero symbols).
// Returns an empty SymbolTable (not nil) on success with no symbols found.
func LoadELFSymbols(path string) (*SymbolTable, error)
```

Implementation note:
```go
f, err := elf.Open(path)
syms, err1 := f.Symbols()      // static .symtab -- often absent in stripped binaries
dsyms, err2 := f.DynamicSymbols() // .dynsym -- present in shared libs / dynamic execs
// Merge both, prefer STT_FUNC entries, skip empty names
for _, s := range append(syms, dsyms...) {
    if s.Name == "" { continue }
    st.Add(Symbol{Name: s.Name, Address: s.Value, Size: s.Size})
}
```

### pkg/loader/dwarf.go (new file)

```go
// LoadDWARFFunctions returns a SymbolTable of function names from DWARF debug info.
// Reads DW_TAG_subprogram entries with DW_AT_low_pc and DW_AT_name attributes.
// Only includes entries that have both a name and a non-zero low_pc address.
// Returns an empty SymbolTable when the file has no DWARF info (not an error).
// Uses Go stdlib debug/dwarf (no new dependencies).
func LoadDWARFFunctions(path string) (*SymbolTable, error)
```

Implementation pattern:
```go
// Open as ELF or PE (try ELF first, then PE).
// Get DWARF data via f.DWARF().
// Walk the DWARF reader with r.Next() to get *dwarf.Entry.
// For each Entry with Tag == dwarf.TagSubprogram:
//   name, ok := entry.Val(dwarf.AttrName).(string)
//   lowpc, ok2 := entry.Val(dwarf.AttrLowpc).(uint64)
//   if name != "" && lowpc != 0 { st.Add(...) }
```

For opening both ELF and PE:
```go
// Try ELF
ef, err := elf.Open(path)
if err == nil {
    dw, err2 := ef.DWARF()
    if err2 == nil { /* walk DWARF */ }
    ef.Close()
    return st, nil
}
// Try PE
pf, err := pe.Open(path)
if err == nil {
    dw, err2 := pf.DWARF()
    if err2 == nil { /* walk DWARF */ }
    pf.Close()
    return st, nil
}
return nil, fmt.Errorf("LoadDWARFFunctions: not an ELF or PE file: %s", path)
```

## Part 3: Funcdata.SetDisplayName

### pkg/pcode/funcdata.go additions

```go
// SetDisplayName sets the human-readable display name for this function.
// When non-empty, PrintC uses this instead of Name() for the function header.
func (fd *Funcdata) SetDisplayName(name string) {
    if fd == nil { return }
    fd.displayName = name
}
```

## Part 4: Bridge wiring

### pkg/bridge/bridge.go: add SymbolName to BuildConfig

```go
type BuildConfig struct {
    Name            string
    Entry           address.Address
    End             address.Address
    MaxInstructions int
    CspecPath       string
    // SymbolName overrides the display name in PrintC output.
    // When non-empty, fd.SetDisplayName(SymbolName) is called after creating Funcdata.
    SymbolName string
}
```

In `Build()`, after creating `fd`:
```go
if cfg.SymbolName != "" {
    fd.SetDisplayName(cfg.SymbolName)
}
```

## Part 5: Test fixtures and tests

### testdata/elfs/gen_sym_elf.go (new, //go:build ignore)

Create an ELF32 generator that produces a binary with a .symtab section.
The symbol table should have a FUNC entry for "simple_add" at the .text VMA.

ELF32 .symtab entry is 16 bytes:
- st_name: uint32 (index into .strtab)
- st_value: uint32 (VMA)
- st_size: uint32
- st_info: uint8 (type+binding: STB_GLOBAL<<4 | STT_FUNC = 0x12)
- st_other: uint8 (0)
- st_shndx: uint16 (section index of .text = 1)

.strtab: null + "simple_add\0"

The existing gen.go creates a stripped ELF. gen_sym_elf.go should create a similar binary
but with .symtab and .strtab sections added.

Output path: `testdata/elfs/simple_add_sym.elf`

### testdata/elfs/gen_import_pe.go (new, //go:build ignore)

Create a PE32 binary with a COFF symbol table entry for the .text function.
COFF symbols are written at PointerToSymbolTable with NumberOfSymbols.

COFF symbol entry is 18 bytes:
- Name: 8 bytes (null-padded short name or zeros+offset into string table)
- Value: uint32 (offset from section start)
- SectionNumber: int16 (1-based section index)
- Type: uint16 (0x20 = function type)
- StorageClass: uint8 (2 = IMAGE_SYM_CLASS_EXTERNAL)
- NumberOfAuxSymbols: uint8 (0)

Add a single COFF symbol "simple_add" for the .text section, offset 0.

Output path: `testdata/elfs/simple_add_sym.exe`

### pkg/loader/symbols_test.go (new)

Unit tests:
1. `TestSymbolTableAddLookup`: Create SymbolTable, Add symbols, verify Lookup returns correct entry.
2. `TestLoadELFSymbols`: Load `testdata/elfs/simple_add_sym.elf` (generated by gen_sym_elf.go),
   verify returned SymbolTable contains "simple_add" at the expected VMA.
   Skip (t.Skip) if file not present (so tests pass before generator is run).
   Better: check in generator output in testdata so it IS present.
3. `TestLoadPE32Exports`: Load `testdata/elfs/simple_add_sym.exe`, verify "simple_add" symbol present.
4. `TestLoadDWARFFunctions_NoDebug`: Load `testdata/elfs/simple_add.elf` (no DWARF), verify
   returns empty SymbolTable without error.
5. `TestLoadPE32Imports_NoImports`: Load `testdata/elfs/simple_add.exe` (no imports), verify
   returns empty SymbolTable without error.

### pkg/loader/loader_test.go addition: TestE6SymbolNameInOutput

```go
// TestE6SymbolNameInOutput verifies that a symbol name supplied via BuildConfig.SymbolName
// appears in the PrintC output as the function name.
func TestE6SymbolNameInOutput(t *testing.T) {
    // Build a simple function with SymbolName set.
    // Reuse the classify2 binary bytes (or any existing test binary).
    // Assert that output contains the supplied name.
    result, err := bridge.Build(engine, bridge.BuildConfig{
        Name:            "func_0x401000",
        SymbolName:      "my_special_func",
        Entry:           base,
        MaxInstructions: 20,
    })
    // ... Heritage, PrintC
    // Assert: strings.Contains(output, "my_special_func")
}
```

## Part 6: Generate test fixtures

The goal file executor MUST run the generators to create the fixture files before tests run:

```bash
cd /path/to/repo
go run testdata/elfs/gen_sym_elf.go
go run testdata/elfs/gen_import_pe.go
```

Both generators should be written to be runnable from the repo root without arguments.

## Part 7: Docs

### docs/STATUS.md
Add E6 entry:
```
- [x] E6: symbol recovery -- PE COFF exports, ELF symbols, DWARF function names, bridge SymbolName (2026-04-05)
```

### docs/E_PHASE_ROADMAP.md
Mark E6 as done: add `[DONE 2026-04-05]` to the E6 header line.

## In-scope

1. `pkg/loader/symbols.go` (new): Symbol, SymbolTable types
2. `pkg/loader/pe.go`: LoadPE32Exports, LoadPE32Imports
3. `pkg/loader/elf.go`: LoadELFSymbols
4. `pkg/loader/dwarf.go` (new): LoadDWARFFunctions
5. `pkg/loader/symbols_test.go` (new): unit tests
6. `pkg/pcode/funcdata.go`: SetDisplayName
7. `pkg/bridge/bridge.go`: BuildConfig.SymbolName + wiring
8. `pkg/loader/loader_test.go`: TestE6SymbolNameInOutput
9. `testdata/elfs/gen_sym_elf.go` (new, build:ignore): ELF32 with .symtab generator
10. `testdata/elfs/gen_import_pe.go` (new, build:ignore): PE32 with COFF symbols generator
11. Run generators to produce `testdata/elfs/simple_add_sym.elf` and `testdata/elfs/simple_add_sym.exe`
12. `docs/STATUS.md`, `docs/E_PHASE_ROADMAP.md`

## Out-of-scope

- ARM/MIPS ELF support (x86 only)
- PE64/PE32+ support
- DWARF variable types (only function names)
- dwarf.AttrHighpc range symbols
- Automatic symbol injection into HighVariable names (only function display name)
- Relocations, dynamic linking simulation

## Invariants

- All existing tests pass (go test ./... green)
- No new external dependencies (debug/dwarf, debug/elf, debug/pe are stdlib)
- ASCII-only in code, tabs for indentation
- ghidra-ref/ must not be modified
- Existing LoadPE32TextSection and LoadELF32TextSection behavior unchanged

## Done when

- go test ./... green
- LoadELFSymbols returns symbols from simple_add_sym.elf
- LoadPE32Exports returns symbols from simple_add_sym.exe
- LoadDWARFFunctions returns empty table on no-DWARF binary without error
- LoadPE32Imports returns empty table on no-imports binary without error
- TestE6SymbolNameInOutput passes: PrintC output contains "my_special_func"
- docs/STATUS.md has E6 entry
- docs/E_PHASE_ROADMAP.md marks E6 done
