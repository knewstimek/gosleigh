# E4: x86-64 Support

## Objective

Add x86-64 (AMD64) decompiler support. After this phase:
- x86-64 instructions decode to p-code via x86-64.sla (already present in testdata/sla/)
- System V AMD64 ABI: RDI/RSI/RDX/RCX/R8/R9 register parameters
- Windows x64 ABI: RCX/RDX/R8/R9 register parameters (x86-64-win.cspec)
- ProtoModel extended to support register-passed parameters
- ScopeLocal extended to classify register varnodes as params
- Golden fixtures for common x86-64 opcodes
- E2E test: simple x86-64 function decompiles with named params

## SLA files available (already in testdata/sla/)

- testdata/sla/x86-64.sla        -- x86-64 Sleigh translation
- testdata/sla/x86-64.pspec      -- processor spec
- testdata/sla/x86-64-gcc.cspec  -- System V AMD64 ABI (Linux/macOS)
- testdata/sla/x86-64-win.cspec  -- Windows x64 ABI
- testdata/sla/x86-64-golang.cspec -- Go ABI (optional)

## C++ reference files

- ghidra-ref/.../cpp/fspec.hh + fspec.cc: PrototypeModel register params (ParamEntry with register addr)
- ghidra-ref/.../cpp/varmap.hh + varmap.cc: ScopeLocal register param handling

## Part 1: ProtoModel register parameter support

### Modify pkg/pcode/protomodel.go

Add register parameter list to ProtoModel:

```go
// RegParams is the ordered list of register names used for integer parameters
// in register-based ABIs (System V AMD64: RDI/RSI/RDX/RCX/R8/R9).
// Empty for stack-only ABIs (x86-32 cdecl).
RegParams []string

// ReturnReg is the primary return value register (e.g. "RAX" for x86-64, "EAX" for x86-32).
ReturnReg string

// PointerSize is the size of a pointer in bytes (4 for x86-32, 8 for x86-64).
PointerSize int
```

Modify NewProtoModelFromCspec to extract register params from the cspec:
- Parse `<default_proto>` -> `<input>` -> `<pentry>` elements
- For each pentry that has `<register name="RDI"/>` (not `<addr space="stack">`),
  append the register name to RegParams
- Order matters: pentry elements appear in call-order (first pentry = first param)
- Set PointerSize from `<data_organization><pointer_size value="8"/>` or default 4

System V AMD64 pentry order in x86-64-gcc.cspec: RDI, RSI, RDX, RCX, R8, R9 (integer regs)
Note: XMM0_Qa..XMM7_Qa are for float params -- include them too if present.

### Modify pkg/pcode/cspec.go

CspecParamEntry already has `Register *CspecRegister`. Verify the field is populated
when parsing `<pentry><register name="RDI"/></pentry>`.

Add a method to CspecData to extract ordered register params:
```go
func (cs *CspecData) IntegerRegParams() []string  // returns ["RDI","RSI","RDX","RCX","R8","R9"] for gcc
func (cs *CspecData) FloatRegParams() []string    // returns ["XMM0_Qa",...] for gcc
func (cs *CspecData) PointerSize() int            // from <pointer_size> element
func (cs *CspecData) StackShift() int64           // extrapop from default_proto (8 for x86-64)
```

## Part 2: ScopeLocal register param classification

### Modify pkg/pcode/scopelocal.go

BuildFromVarnodes currently only classifies stack-space varnodes. Add register param handling:

For each varnode in register space (SpaceKindRegister or space.Name=="register"):
- Check if the varnode's register name matches one of ProtoModel.RegParams (in order)
- If it's a MULTIEQUAL/PHI input at function entry, or a direct def at entry, classify as param
- Create HighVariable for it, naming by position: param_0 (RDI), param_1 (RSI), etc.

The register name lookup: a Varnode in register space has Addr().Offset() equal to
the register's byte offset in the register file. To map offset->name, use the
Engine's AddressSpaceManager (or the SLA's symbol table).

Simpler approach: scan the FuncProto's parameter detection differently for register ABIs.
Instead of scanning by stack offset, scan by register offset:
- Before BuildFromVarnodes, call a new method ProtoModel.RegParamOffsets() that returns
  a map[uint64]int (register offset -> param index) built by looking up each RegParam
  name in the Engine's space manager.
- Then in BuildFromVarnodes, varnodes in register space with matching offsets become params.

This requires Engine/address space access. Add to BuildConfig or pass to ScopeLocal.

Alternative simpler approach for E4 (recommended):
- Add `RegParamOffsets map[uint64]int` to ProtoModel (byte offset in register space -> param index)
- Populate this map in NewProtoModelFromCspec by calling a lookup function
  `lookupRegOffset(spaceMgr AddrSpaceMgr, regName string) (uint64, bool)`
- Pass the address space manager (or Engine) to NewProtoModelFromCspec

Add to ProtoModel:
```go
// RegParamOffsets maps register space byte offsets to parameter indices (0-based).
// Used for register-based ABIs like AMD64 System V.
RegParamOffsets map[uint64]int
```

Modify ScopeLocal.BuildFromVarnodes to also collect register-space varnodes that
have matching RegParamOffsets:
```go
for _, vn := range varnodes {
    if vn.Space().Kind() == address.SpaceKindRegister {
        if idx, ok := sl.model.RegParamOffsets[vn.Offset()]; ok {
            // This varnode is a register parameter
            // Create HighParam with name "param_N" where N=idx
        }
    }
}
```

## Part 3: Golden fixtures for x86-64

### pkg/sla/x86_64_golden_test.go (new file)

New test file for x86-64 golden fixtures. Similar structure to x86_golden_test.go.

Golden engine builder for x86-64:
```go
func goldenEngineX8664(t testing.TB) *sla.Engine {
    t.Helper()
    slaPath := filepath.Join(testdataDir(), "x86-64.sla")
    pspecPath := filepath.Join(testdataDir(), "x86-64.pspec")
    eng, _, err := (&loader.EngineBuilder{SLAPath: slaPath, PspecPath: pspecPath}).Build()
    ...
}
```

Add golden fixtures for common x86-64 opcodes. Use GOSLEIGH_UPDATE_GOLDEN=1 to generate.
The fixture names use x86_64_ prefix to distinguish from x86-32.

Required fixtures (at minimum 6):
```go
{"x86_64_MOV_RAX_imm64", []byte{0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
// MOV RAX, 1 (REX.W prefix 0x48 + B8+rd imm64)

{"x86_64_ADD_RAX_RBX", []byte{0x48, 0x01, 0xD8}},
// ADD RAX, RBX (REX.W 0x48, ADD r/m64,r64 opcode 0x01, ModRM 0xD8=11 011 000)

{"x86_64_PUSH_RBP", []byte{0x55}},
// PUSH RBP (no REX needed -- same opcode as x86-32 PUSH EBP, but 64-bit mode uses 64-bit regs)

{"x86_64_MOV_RBP_RSP", []byte{0x48, 0x89, 0xE5}},
// MOV RBP, RSP (REX.W + MOV r/m64,r64)

{"x86_64_RET", []byte{0xC3}},
// RET (near return)

{"x86_64_MOV_EAX_EDI_load", []byte{0x89, 0xF8}},
// MOV EAX, EDI (zero-extends to RAX; no REX needed)
```

Each fixture must decode without error to at least 1 p-code op.

### testdata/golden/ fixture files

Run with GOSLEIGH_UPDATE_GOLDEN=1 to generate. The golden JSON files live at:
testdata/golden/x86_64_MOV_RAX_imm64.json etc.

## Part 4: E2E test for x86-64 function

### TestX8664SimpleFunction (pkg/loader/loader_test.go)

A minimal x86-64 function that accepts two int64 params (RDI, RSI) and returns their sum.
System V AMD64 ABI: first arg in RDI, second in RSI, return in RAX.

```
// add64(int64 a, int64 b) int64 { return a + b; }
// Assembly:
//   48 89 F8       MOV RAX, RDI      ; copy first arg to RAX
//   48 01 F0       ADD RAX, RSI      ; add second arg
//   C3             RET               ; return RAX
```

Binary: `{0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3}`

Assertions:
- bridge.Build + Heritage + PrintC pipeline succeeds without error
- PrintC output is non-empty
- Output contains "param" (register params named param_0, param_1)
- OR output contains RAX/RDI/RSI (acceptable if param naming not yet fully working)
- t.Logf the output

### TestX8664CallingConvention (pkg/loader/loader_test.go)

Slightly more complex: a function with local variable and conditional branch.

```
// classify64(int64 x) int64 { if (x > 0) return 1; return 0; }
// 48 85 FF           TEST RDI, RDI     ; test x (first param in RDI)
// 7E 05              JLE +5            ; jump if <= 0
// B8 01 00 00 00     MOV EAX, 1        ; return 1
// C3                 RET
// 31 C0              XOR EAX, EAX      ; return 0
// C3                 RET
```

Binary: `{0x48, 0x85, 0xFF, 0x7E, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0x31, 0xC0, 0xC3}`

Assertions:
- Pipeline succeeds without error
- result.Instructions >= 4
- result.Graph.GetSize() >= 2 (multiple blocks from conditional)
- PrintC output non-empty

## Part 5: Loader support for x86-64 address size

### Check EngineBuilder / loader.go

The current EngineBuilder uses x86-packed.sla implicitly for golden tests. For x86-64:
- x86-64.sla uses 64-bit addresses (pointer size 8)
- The address computation in bridge.go must not assume 32-bit offsets

Check: does bridge.Build() work with a 64-bit address space? Key areas:
1. Entry address: passed as `address.Address{Space: ram, Offset: base}` -- fine if uint64
2. CALL target computation: rel32 sign-extension must produce 64-bit result
3. Stack pointer manipulation: ESP -> RSP, 4-byte -> 8-byte stack cell

If bridge.go has hardcoded 32-bit assumptions (e.g., masking to 0xFFFFFFFF), fix them.
If sla engine loading has pointer-size assumptions, fix them.

Add a check: after EngineBuilder.Build(), verify that the default address space
has the correct size (8 bytes for x86-64 vs 4 for x86-32). Add PointerSize() method
to Engine or expose AddressSize from Engine for use in ProtoModel.

## Part 6: Windows x64 ABI support

### testdata/sla/x86-64-win.cspec is already present

The Windows x64 ABI uses RCX/RDX/R8/R9 as integer param registers (4 params max,
rest on stack). Since x86-64-win.cspec exists, just verify that:
1. ParseCspec correctly parses it
2. CspecData.IntegerRegParams() returns ["RCX","RDX","R8","R9"] for win.cspec

Add a test: TestCspecX8664Win (pkg/pcode/cspec_test.go):
```go
func TestCspecX8664Win(t *testing.T) {
    cs := ParseCspec("testdata/sla/x86-64-win.cspec")  // adjust path
    regs := cs.IntegerRegParams()
    // should contain RCX, RDX, R8, R9
    if len(regs) < 4 { t.Errorf(...) }
}
```

## Part 7: Docs

Update docs/STATUS.md: add E4 entry.
Update docs/E_PHASE_ROADMAP.md: mark E4 complete.

## In-scope

1. pkg/pcode/protomodel.go: add RegParams, ReturnReg, PointerSize, RegParamOffsets
2. pkg/pcode/cspec.go: add IntegerRegParams(), FloatRegParams(), PointerSize(), StackShift()
3. pkg/pcode/scopelocal.go: classify register-space varnodes as params
4. pkg/sla/x86_64_golden_test.go (new): golden test for x86-64
5. testdata/golden/: generate x86-64 golden JSON fixtures (6+ entries)
6. pkg/loader/loader_test.go: TestX8664SimpleFunction, TestX8664CallingConvention
7. pkg/pcode/cspec_test.go: TestCspecX8664Win
8. pkg/pcode/protomodel_test.go: tests for register param classification
9. docs/STATUS.md, docs/E_PHASE_ROADMAP.md

## Out-of-scope

- XMM/YMM/ZMM (SSE/AVX) float register parameters -- stub ok
- Full Windows x64 shadow space (32-byte spill area) -- not needed for basic support
- x86-64 DWARF CFI / stack unwinding
- Go calling convention (goroutines, g register)
- RIP-relative addressing decode (may already work via x86-64.sla)
- 64-bit struct passing (by-value struct in regs)

## Invariants

- All existing tests pass (113 golden subtests, 23+ E2E tests)
- go test ./... passes green
- No new external dependencies
- ASCII-only, tabs for indentation
- x86-32 tests must not regress (ProtoModel defaults must still work for cdecl)
- PointerSize defaults to 4 when cspec does not specify (backward compat for x86-32)

## Done when

- go test ./... passes green
- TestX8664SimpleFunction passes: x86-64 function decompiles without error
- TestX8664CallingConvention passes: multi-block x86-64 function has correct CFG
- x86-64 golden fixtures: >= 6 subtests passing
- CspecData.IntegerRegParams() returns correct register list for gcc + win cspec
- docs/STATUS.md has E4 entry
