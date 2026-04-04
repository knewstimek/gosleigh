# D7: PE/COFF loader (Windows EXE/DLL .text section extraction)

## Objective

Implement a PE32 (Portable Executable) loader in pkg/loader/ that extracts the .text
section bytes and VMA from a Windows EXE or DLL file. Then create a real PE32 ELF test
binary (similar to testdata/elfs/simple_add.elf) and run the full decompilation pipeline
on it.

## Why

Phase D3 added ELF32 loader. The next major binary format is PE32 (Windows executables).
Without PE support, Gosleigh cannot process any Windows binary. PE32 is the dominant format
for x86 Windows targets -- games, desktop apps, malware analysis, etc.

The PE format is documented in the Microsoft PE/COFF spec. Go's debug/pe stdlib package
handles PE32 parsing, similar to how debug/elf was used for ELF32 in pkg/loader/elf.go.

## Part 1: PE32 loader

Implement LoadPE32TextSection in pkg/loader/pe.go:

```go
// LoadPE32TextSection opens a PE32 Windows executable and returns the raw bytes
// of the .text section together with the section's virtual address (VMA).
// Only PE32 (32-bit) is supported; PE32+ (64-bit) returns an error.
func LoadPE32TextSection(path string) ([]byte, uint64, error)
```

Use Go's debug/pe stdlib package (no external dependencies):
- pe.Open(path)
- Find section named ".text" (or ".TEXT")
- Return section.Data(), uint64(section.VirtualAddress) + uint64(file.OptionalHeader.(*pe.OptionalHeader32).ImageBase)
- If OptionalHeader is not *pe.OptionalHeader32, return an error ("not a PE32 file")

Edge cases to handle:
- File not found -> wrapped error
- No .text section -> error "PE32: no .text section"
- PE32+ (64-bit) -> error "not a PE32 file, got PE32+"

## Part 2: Test PE32 binary

Create testdata/elfs/simple_add.exe -- a minimal PE32 binary containing only the add() function.

Create testdata/elfs/gen_pe.go with build tag //go:build ignore that generates the binary.
The binary must be a valid PE32 with:
- MZ header (0x4D 0x5A)
- PE signature (0x50 0x45 0x00 0x00)
- COFF header with Machine=0x014c (IMAGE_FILE_MACHINE_I386)
- Optional header (PE32, not PE32+)
- .text section containing the same add() function as in simple_add.elf:
  55 89 E5 8B 45 08 8B 55 0C 01 D0 5D C3 (13 bytes)
- ImageBase = 0x400000 (typical PE32 default)
- VirtualAddress of .text = 0x1000 (typical first section offset)

The generator can write the binary directly (hard-code all PE header fields) without using
any PE assembly library. The minimal PE structure is well-known:
- DOS stub: MZ header + "This program cannot be run in DOS mode" (enough bytes to reach PE offset)
- PE header at offset 0x80 or wherever the DOS stub puts it
- One .text section with the add() function bytes

If generating a valid PE32 is too complex, use raw bytes hard-coded into gen_pe.go.
The test binary does NOT need to be executable -- it just needs to be parseable by debug/pe.

Alternatively: create simple_add.exe directly as a []byte literal in a go:generate script
and commit the binary to testdata/elfs/. A minimal valid PE32 is about 512 bytes.

## Part 3: Test

Add pkg/loader/pe_test.go with:

### TestPELoader
Load testdata/elfs/simple_add.exe and verify:
- err == nil
- len(data) == 13 (same add() function)
- data[0] == 0x55 (PUSH EBP)
- base == expected VMA (0x400000 + 0x1000 = 0x401000)

### TestX86PEDecompile
Run the full pipeline on the PE file:
a. LoadPE32TextSection(path)
b. EngineBuilder{SLAPath, PspecPath, Bytes: data, BaseAddr: base}
c. bridge.Build -> Heritage -> BatchAActionPool -> ActionBlockStructure -> ActionFinalStructure
d. PrintC.Emit -> non-empty C output
e. t.Logf("PE decompile output:\n%s", output)

## Part 4: CLI integration

Add --pe flag to cmd/gosleigh/main.go (similar to --elf) that calls LoadPE32TextSection.
The flag must be mutually exclusive with --binary and --elf.

Verify manually:
  go run ./cmd/gosleigh/ translate --sla pkg/sla/testdata/x86-packed.sla --pspec testdata/sla/x86.pspec --pe testdata/elfs/simple_add.exe

## Part 5: docs

- docs/STATUS.md: add Phase D7 completion entry
- docs/X86_ROADMAP.md: update Phase C10 (ELF/PE section extraction) to note PE32 done

## In-scope

1. pkg/loader/pe.go: LoadPE32TextSection (debug/pe stdlib, no external deps)
2. pkg/loader/pe_test.go: TestPELoader + TestX86PEDecompile
3. testdata/elfs/simple_add.exe: minimal PE32 binary (hard-coded or generated)
4. testdata/elfs/gen_pe.go: PE binary generator (build tag ignore)
5. cmd/gosleigh/main.go: --pe flag
6. docs updates

## Out-of-scope

- PE32+ (64-bit PE) -- future
- PE import table / relocation table parsing -- future
- DWARF/PDB debug info -- future
- ARM PE -- future
- Modifying existing ELF loader or tests

## Invariants

- All existing tests (go test ./...) must pass
- TestPELoader and TestX86PEDecompile must NOT skip
- No new external Go dependencies
- ASCII-only, tabs for indentation, English comments
- Must use debug/pe from stdlib (same approach as debug/elf for ELF)

## Done when

- go build ./... passes
- go test ./pkg/loader/... -run TestPELoader passes (data[0]==0x55, len==13)
- go test ./pkg/loader/... -run TestX86PEDecompile passes with non-empty C output
- go test ./... passes with all tests green
- --pe flag works in CLI on testdata/elfs/simple_add.exe
