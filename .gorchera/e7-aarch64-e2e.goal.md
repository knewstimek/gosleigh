# E7: AARCH64 E2E Pipeline (ARM64 decompile support)

## Objective

Add AARCH64 (ARM64 little-endian) full-pipeline support: load AARCH64.sla, apply context
defaults from pspec, translate ARM64 instructions to p-code, run Heritage + BatchA +
BlockStructure + FinalStructure, emit PrintC C output. Validate with golden fixtures and
an E2E test.

The AARCH64.sla is already present at `testdata/sla/AARCH64.sla`. The engine already loads
it and translates ADD + RET correctly (confirmed by prior probe). The missing pieces are:
1. `testdata/sla/AARCH64.pspec` -- context defaults (ShowPAC=0, PAC_clobber=0, ShowBTI=0, ShowMemTag=0)
2. `pkg/sla/aarch64_golden_test.go` -- golden fixtures for 4+ ARM64 instructions
3. `testdata/golden/aarch64_*.json` -- golden fixture files
4. `pkg/loader/loader_test.go` addition: `TestAARCH64SimpleFunction`
5. docs updates

## What is already implemented (DO NOT re-implement):

- `testdata/sla/AARCH64.sla`: ARM64 LE SLA file, loadable by EngineBuilder
- All E1-E6 infrastructure: Heritage, BatchA, BlockStructure, FinalStructure, PrintC
- `pkg/loader/loader.go`: EngineBuilder with SLAPath + PspecPath support
- `pkg/sla/pspec.go`: ParsePspec for context_set defaults
- `testdata/sla/x86.pspec`, `x86-64.pspec`: reference pspec format
- `pkg/sla/golden_test.go`: goldenFixturePath, opsToGolden, compareGolden harness
- `pkg/sla/x86_64_golden_test.go`: reference golden test (goldenEngineX8664 pattern)
- Prior probe confirmed: `add x0, x0, x1` (0x00, 0x00, 0x01, 0x8B) + `ret` (0xC0, 0x03, 0x5F, 0xD6) translate correctly without pspec

## Part 1: AARCH64.pspec

### testdata/sla/AARCH64.pspec (new file)

Create a minimal pspec that sets AARCH64 context defaults. Copy the context_set entries
from Ghidra's AARCH64.pspec. Only context_set (NOT tracked_set) entries are needed.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <context_data>
    <context_set space="ram">
      <set name="ShowPAC" val="0" description="1 to show PAC operations in decompiler"/>
      <set name="PAC_clobber" val="0" description="1 to let PAC operations overwrite their operands in decompiler"/>
      <set name="ShowBTI" val="0" description="1 to show BTI effects in decompiler"/>
      <set name="ShowMemTag" val="0" description="1 to show memory tag checks in decompiler"/>
    </context_set>
  </context_data>
</processor_spec>
```

Note: `ParsePspec()` reads only context_set entries. The extra attributes
(description) are ignored by xml.Unmarshal. The val="0" for all entries means
"use simplified decoding without PAC/BTI/MTE side-effects" -- this is the correct
default for decompiling standard ARM64 binaries.

## Part 2: AARCH64 golden test

### pkg/sla/aarch64_golden_test.go (new file)

Pattern: identical to `pkg/sla/x86_64_golden_test.go` but for AARCH64.

```go
package sla_test

// goldenEngineAARCH64 builds a *sla.Engine from testdata/sla/AARCH64.sla
// with pspec context defaults applied (ShowPAC=0, PAC_clobber=0, ShowBTI=0, ShowMemTag=0).
// Note: AARCH64.sla lives in the root testdata/sla/, reached via ../../testdata/sla/
// from pkg/sla/.
func goldenEngineAARCH64(program []byte) (*sla.Engine, address.Address, error) {
    // Load from testdata/sla/AARCH64.sla (root-relative path from pkg/sla/)
    slaPath := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "AARCH64.sla")
    pspecPath := filepath.Join(filepath.Dir(file), "..", "..", "testdata", "sla", "AARCH64.pspec")
    // ... (same pattern as goldenEngineX8664 but without packed format assumption)
    // Note: AARCH64.sla uses the same sla.Read() + sla.DecodeBoundariesPayload() path.
    // The SLA may be in XML or packed format -- sla.Read() handles both.
}
```

ARM64 is little-endian (LE). The engine default space is "ram".

#### Test cases for TestGoldenAARCH64

Minimum 4 instruction golden tests. All instructions are 4-byte fixed-width, little-endian.

| Name | Bytes (LE) | ARM64 mnemonic | Expected ops |
|------|-----------|----------------|--------------|
| `aarch64_ADD_X0_X0_X1` | 0x00, 0x00, 0x01, 0x8B | ADD X0, X0, X1 | >= 1 op including INT_ADD |
| `aarch64_RET` | 0xC0, 0x03, 0x5F, 0xD6 | RET | COPY + RETURN (2 ops) |
| `aarch64_MOV_X0_X1` | 0xE0, 0x03, 0x01, 0xAA | MOV X0, X1 (ORR X0, XZR, X1) | >= 1 COPY op |
| `aarch64_NOP` | 0x1F, 0x20, 0x03, 0xD5 | NOP | 0 ops (Ghidra PCODE_NOP) |

Additional useful fixtures (add if engine supports them):
- `aarch64_LDR_X0_X1` (0x20, 0x00, 0x40, 0xF9): LDR X0, [X1] -> LOAD
- `aarch64_STR_X0_X1` (0x20, 0x00, 0x00, 0xF9): STR X0, [X1] -> STORE

For NOP: Ghidra's AARCH64.sla emits 0 ops for NOP (PCODE_NOP). The golden fixture
should have an empty ops array []. The test must NOT fail when 0 ops are returned for
NOP -- instead it verifies the golden fixture matches.

Implementation note for goldenEngineAARCH64:
- AARCH64.sla may not be in packed format. Use sla.Read() which handles both
  XML and packed. Then call sla.DecodeBoundariesPayload(container.Payload).
- AARCH64 has context variables: ShowPAC, PAC_clobber, ShowBTI, ShowMemTag.
  Use pspecData to set all four to 0 via backend.SetVariableDefault().
- If SetVariableDefault() returns an error for a context variable that is not
  registered in the SLA boundaries, skip it gracefully (not all SLA files register
  all pspec context vars).

The backend.RegisterContextVariable step must come BEFORE SetVariableDefault.
Only register context fields that exist in xrefs.ContextFields.

### testdata/golden/aarch64_*.json (new files)

Run with GOSLEIGH_UPDATE_GOLDEN=1 to generate:
```
GOSLEIGH_UPDATE_GOLDEN=1 go test ./pkg/sla/ -run TestGoldenAARCH64 -v
```

All golden files must be committed as checked-in fixtures.

## Part 3: E2E test

### pkg/loader/loader_test.go addition: TestAARCH64SimpleFunction

Pattern: same as TestX8664SimpleFunction (no calling convention, just pipeline correctness).

```go
// TestAARCH64SimpleFunction exercises the full AARCH64 pipeline:
//   EngineBuilder.Build -> bridge.Build -> Heritage -> BatchA ->
//   BlockStructure -> FinalStructure -> PrintC
//
// Bytes: ADD X0,X0,X1 (0x00,0x00,0x01,0x8B) + RET (0xC0,0x03,0x5F,0xD6).
// Verifies that AARCH64 instructions decode and produce non-empty PrintC output
// end-to-end with no panics, no translation errors, and at least 1 instruction.
func TestAARCH64SimpleFunction(t *testing.T) {
    dir := ...  // filepath.Dir(file) from runtime.Caller(0)
    slaPath := filepath.Join(dir, "../../testdata/sla/AARCH64.sla")
    pspecPath := filepath.Join(dir, "../../testdata/sla/AARCH64.pspec")

    // ADD X0, X0, X1; RET (little-endian 4-byte ARM64 instructions)
    prog := []byte{
        0x00, 0x00, 0x01, 0x8B, // ADD X0, X0, X1
        0xC0, 0x03, 0x5F, 0xD6, // RET
    }

    engine, entryAddr, err := (&loader.EngineBuilder{
        SLAPath:   slaPath,
        PspecPath: pspecPath,
        Bytes:     prog,
    }).Build()
    // ... assert no error

    result, err := bridge.Build(engine, bridge.BuildConfig{
        Name:            "aarch64_add",
        Entry:           entryAddr,
        MaxInstructions: 10,
    })
    // ... assert no error, len(result.Instructions) >= 2

    pcode.NewHeritage(result.Funcdata, result.HeritageSpaces).Heritage(result.Graph)
    pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
    pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
    pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)

    output, err := pcode.NewPrintC().Emit(result.Funcdata)
    // ... assert no error
    // ... assert strings.TrimSpace(output) != ""
    // t.Logf("AARCH64 simple function C output:\n%s", output)
}
```

Important: the EngineBuilder path already handles pspec loading. Just pass PspecPath.

## Part 4: Documentation

### docs/STATUS.md

Add entry under the E-phase section:
```
- [x] E7: AARCH64 E2E pipeline -- AARCH64.pspec, 4+ golden fixtures, TestAARCH64SimpleFunction E2E (2026-04-05)
```

### docs/E_PHASE_ROADMAP.md

Add E7 entry after E6:
```
## E7: AARCH64 (ARM64) E2E Support [DONE 2026-04-05]

**핵심 deliverable**: ARM64 코드 디컴파일 (AARCH64.sla E2E).
- AARCH64.pspec: ShowPAC=0, PAC_clobber=0, ShowBTI=0, ShowMemTag=0 context defaults
- aarch64_golden_test.go: goldenEngineAARCH64 + TestGoldenAARCH64 (4+ instructions)
- testdata/golden/aarch64_*.json: golden fixture files (ADD, RET, MOV, NOP)
- loader_test.go: TestAARCH64SimpleFunction E2E (ADD X0,X0,X1 + RET)
```

## In-scope

1. `testdata/sla/AARCH64.pspec` (new): ShowPAC=0, PAC_clobber=0, ShowBTI=0, ShowMemTag=0
2. `pkg/sla/aarch64_golden_test.go` (new): goldenEngineAARCH64 + TestGoldenAARCH64
3. `testdata/golden/aarch64_*.json` (new, generated): 4+ golden fixture files
4. `pkg/loader/loader_test.go`: TestAARCH64SimpleFunction E2E
5. `docs/STATUS.md`: E7 entry
6. `docs/E_PHASE_ROADMAP.md`: E7 section

## Out-of-scope

- AARCH64 calling convention (cspec + AAPCS64 register param wiring) -- E8 material
- AARCH64BE (big-endian) support
- Apple Silicon / AARCH64_AppleSilicon.sla
- ARM32 (ARM7/ARM8 etc.) support
- AARCH64 SIMD/SVE/NEON instructions
- DWARF ARM64 function recovery

## Invariants

- All existing tests pass (go test ./... green)
- ghidra-ref/ must not be modified
- ASCII-only in code
- Tabs for indentation
- AARCH64.pspec must parse without error via ParsePspec()
- SetVariableDefault() errors for unregistered context vars must be handled gracefully

## Done when

- go test ./... green
- TestGoldenAARCH64 passes with >= 4 instruction subtests (no 0-op failure for non-NOP)
- TestAARCH64SimpleFunction passes: >= 2 instructions, non-empty PrintC output
- testdata/golden/aarch64_ADD_X0_X0_X1.json, aarch64_RET.json, aarch64_MOV_X0_X1.json committed
- docs/STATUS.md has E7 entry
- docs/E_PHASE_ROADMAP.md has E7 section
