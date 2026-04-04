# D15: REP string ops + ENTER + switch E2E golden fixtures

## Objective

Add golden fixture coverage for REP string ops and ENTER, plus a switch-like E2E:
1. REP MOVSB (F3 A4) -- byte-level memory copy (memcpy inner loop)
2. REP MOVSD (F3 A5) -- dword-level memory copy (most common memcpy form)
3. REP STOSD (F3 AB) -- dword-level memory fill (memset)
4. REPNE SCASB (F2 AE) -- byte scan until match (strlen pattern)
5. ENTER imm16, 0 (C8 08 00 00) -- function prologue (ENTER 8, 0 -- allocate 8 bytes)
6. SCASB (AE) -- single-step byte scan (without REP prefix, for fixture baseline)

Plus a switch-pattern E2E using computed jump (3-case dispatch).

## Why

After D14 (76 golden subtests), the remaining practical gaps for real compiled x86:
- REP MOVS/STOS: Every C memcpy/memset in O0 builds uses these. Any code that copies
  structs or initializes arrays will have REP string ops. Without them, memory-heavy
  functions cannot be decompiled.
- REPNE SCAS: strlen() is the most common string function in all C programs. The standard
  O0 implementation is REPNE SCASB. Without this, string length calculations are opaque.
- ENTER: Pair to LEAVE (added D12). Some compilers still emit ENTER for alloca-heavy
  functions. Needed for complete prologue coverage.
- Switch E2E: JMP indirect (FF E0) golden was added in D14 but no switch-body E2E exists.
  A 3-case switch exercises the JMP indirect -> multiple-target CFG path.

## Part 1: Golden fixtures

### REP MOVSB
  {"x86_REP_MOVSB", []byte{0xF3, 0xA4}},  // REP MOVSB (copy ECX bytes from ESI to EDI)

Expected: COPY ops setting up ECX/ESI/EDI as loop variables, then a BRANCHIND or
CPOOLREF sequence. Ghidra models REP as an inline loop construct. Accept whatever
the SLA emits -- may be complex (5-15 ops). Require op count >= 2.

### REP MOVSD
  {"x86_REP_MOVSD", []byte{0xF3, 0xA5}},  // REP MOVSD (copy ECX dwords from ESI to EDI)

Same as REP MOVSB but moves 4 bytes per iteration. Require op count >= 2.

### REP STOSD
  {"x86_REP_STOSD", []byte{0xF3, 0xAB}},  // REP STOSD (fill ECX dwords at EDI with EAX)

Expected: loop decrement ECX + store EAX -> [EDI] + advance EDI. Require op count >= 2.

### REPNE SCASB
  {"x86_REPNE_SCASB", []byte{0xF2, 0xAE}},  // REPNE SCASB (scan until AL matches [EDI])

Expected: loop comparing AL with [EDI], decrementing ECX, advancing EDI until match or
ECX=0. Used in strlen. Require op count >= 2.

### SCASB (no prefix)
  {"x86_SCASB", []byte{0xAE}},  // SCASB (compare AL with [EDI], advance EDI)

Expected: LOAD([EDI]) -> tmp, compare with AL, set flags, INT_ADD(EDI, 1). ~3-5 ops.

### ENTER
  {"x86_ENTER_8", []byte{0xC8, 0x08, 0x00, 0x00}},  // ENTER 8, 0

ENTER imm16=8, level=0: same effect as PUSH EBP + MOV EBP,ESP + SUB ESP,8.
Expected: COPY/STORE/INT_SUB sequence. ~4-6 ops. (level=0 means no display chain)

Total golden subtests after D15: >= 82 (76 + 6 = 82)

## Part 2: E2E switch-pattern function

Add TestX86SwitchFunction to pkg/loader/loader_test.go.

A 3-case switch using if-else chain (O0 compiler output for small switch):

int classify(int x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return -1;
    }
}

Assembly (CMP+JE chain, O0 style):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (x)
  0x06: 83 F8 00        CMP EAX, 0
  0x09: 75 07           JNE +7              (not 0)
  0x0B: B8 0A 00 00 00  MOV EAX, 10
  0x10: EB 1A           JMP +26             (epilogue)
  0x12: 83 F8 01        CMP EAX, 1
  0x15: 75 07           JNE +7              (not 1)
  0x17: B8 14 00 00 00  MOV EAX, 20
  0x1C: EB 10           JMP +16             (epilogue)
  0x1E: 83 F8 02        CMP EAX, 2
  0x21: 75 07           JNE +7              (not 2)
  0x23: B8 1E 00 00 00  MOV EAX, 30
  0x28: EB 06           JMP +6              (epilogue)
  0x2A: B8 FF FF FF FF  MOV EAX, -1
  0x2F: 5D              POP EBP
  0x30: C3              RET
  Total: 49 bytes

Bytes:
{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08,
 0x83, 0xF8, 0x00, 0x75, 0x07,
 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xEB, 0x1A,
 0x83, 0xF8, 0x01, 0x75, 0x07,
 0xB8, 0x14, 0x00, 0x00, 0x00, 0xEB, 0x10,
 0x83, 0xF8, 0x02, 0x75, 0x07,
 0xB8, 0x1E, 0x00, 0x00, 0x00, 0xEB, 0x06,
 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 10
- result.Graph.GetSize() >= 5 (4-way dispatch + join = at least 5 basic blocks)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("classify C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add REP_MOVSB, REP_MOVSD, REP_STOSD, REPNE_SCASB, SCASB, ENTER_8
2. testdata/golden/: 6 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. pkg/loader/loader_test.go: TestX86SwitchFunction
4. Fix any decode gaps for REP-prefix ops, SCASB, ENTER if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- REP MOVSW (16-bit) -- dword form covers the common case
- REPNE MOVSD (rare combination)
- ENTER with level > 0 (display chain -- almost never used)
- Computed jump table switch (JMP [table+EAX*4] with embedded data)
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass (76 golden subtests, 17 E2E tests... confirm exact counts)
- New golden fixtures >= 1 op each (REP ops may have many)
- TestX86SwitchFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 82 subtests
- go test ./pkg/loader/... -run TestX86SwitchFunction passes with non-empty PrintC
- go test ./... passes green
