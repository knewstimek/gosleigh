# D8: LEA/MOVZX/MOVSX/OR/AND/INC golden fixtures + TestX86ComplexFunction E2E

## Objective

Add 7 more x86 opcode golden fixtures that are essential for real-world decompilation:
LEA, MOVZX, MOVSX, OR, AND, INC, CMP. Then add a "complex function" E2E test that
exercises several of these ops together.

## Why

After D5-D7, the following common x86 opcodes are still missing from the golden fixture set:
- LEA (Load Effective Address): used for pointer arithmetic, address computation
- MOVZX (Move with Zero Extension): extremely common in compiled C (bool/byte -> int)
- MOVSX (Move with Sign Extension): common for signed byte/short -> int
- OR / AND: bitwise ops, very common in flags tests and masks
- INC (Increment): loop counters, pointer bumps
- CMP: comparison before conditional branches (Jcc)

CMP is especially critical: virtually every if/else or loop uses CMP+Jcc. Without CMP golden
fixtures, we cannot test the decompiler on any function with comparisons (only TEST was added in D4).

## Part 1: New golden fixtures

Add to TestGoldenX86 in pkg/sla/x86_golden_test.go:

### OR and AND
  {"x86_OR_EAX_EBX",   []byte{0x09, 0xD8}},  // OR EAX, EBX (ModRM 0xD8 = EAX,EBX)
  {"x86_AND_EAX_EBX",  []byte{0x21, 0xD8}},  // AND EAX, EBX (ModRM 0xD8)

Expected: INT_OR/INT_AND + flag ops (SF, ZF, CF=0, OF=0, PF, AF=?). ~5-7 ops each.

### INC
  {"x86_INC_EAX",      []byte{0x40}},         // INC EAX (short form opcode)

Expected: INT_ADD(EAX, const:1:4) + flag ops. ~5-6 ops.

### CMP
  {"x86_CMP_EAX_EBX",  []byte{0x39, 0xD8}},  // CMP EAX, EBX (compares EAX - EBX, sets flags)

Expected: INT_SUB (for flags) + flag ops (ZF, SF, CF, OF, AF, PF), no output varnode for result. ~6-7 ops.
CMP does NOT write EAX -- the result is discarded, only flags are updated.

### MOVZX
  {"x86_MOVZX_EAX_AL", []byte{0x0F, 0xB6, 0xC0}},  // MOVZX EAX, AL (zero-extend AL into EAX)

ModRM 0xC0 = mod=11, reg=0 (EAX), rm=0 (AL/EAX low byte)
Expected: INT_ZEXT(AL -> EAX). 1-2 ops.

### MOVSX
  {"x86_MOVSX_EAX_AL", []byte{0x0F, 0xBE, 0xC0}},  // MOVSX EAX, AL (sign-extend AL into EAX)

Expected: INT_SEXT(AL -> EAX). 1-2 ops.

### LEA
  {"x86_LEA_EAX_EBX_ECX", []byte{0x8D, 0x04, 0x0B}},  // LEA EAX, [EBX+ECX] (SIB: base=EBX, index=ECX, scale=1)

ModRM 0x04 = mod=00, reg=0 (EAX), rm=4 (SIB follows)
SIB 0x0B = scale=00, index=1 (ECX), base=3 (EBX)
Expected: INT_ADD(EBX, ECX) -> EAX. 1-2 ops. (No LOAD -- LEA computes address without dereferencing)

If SIB is not yet supported, use simpler LEA:
  {"x86_LEA_EAX_disp8", []byte{0x8D, 0x45, 0x08}},  // LEA EAX, [EBP+8]
Expected: INT_ADD(EBP, const:8) -> EAX. 1-2 ops.

Generate golden fixtures for all 7 cases. Total after D8: >= 32 subtests.

## Part 2: Complex function E2E test

Add TestX86ComplexFunction to pkg/loader/loader_test.go.

The test function uses CMP + conditional branch + LEA or MOVZX:

A "max" function (int max(int a, int b) { return a >= b ? a : b; }):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (a)
  0x06: 8B 55 0C        MOV EDX, [EBP+12]   (b)
  0x09: 39 D0           CMP EAX, EDX        (compare a, b)
  0x0B: 7D 02           JGE +2              (jump if a >= b -> return a)
  0x0D: 89 D0           MOV EAX, EDX        (else: EAX = b)
  0x0F: 5D              POP EBP
  0x10: C3              RET
  Total: 17 bytes

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x55, 0x0C, 0x39, 0xD0, 0x7D, 0x02, 0x89, 0xD0, 0x5D, 0xC3}

Note: JGE rel8 (0x7D) -- Jump if Greater or Equal (SF == OF). This adds another Jcc golden fixture.
Add {"x86_JGE_fwd", []byte{0x7D, 0x02}} to TestGoldenX86 as well (total 33 subtests).

TestX86ComplexFunction assertions:
- len(result.Instructions) >= 5
- result.Graph.GetSize() >= 2 (CMP+JGE creates at least 2 basic blocks)
- Heritage + BatchAActionPool + ActionBlockStructure + ActionFinalStructure
- PrintC output non-empty
- t.Logf("Complex C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add OR, AND, INC, CMP, MOVZX, MOVSX, LEA (+ JGE_fwd) -- total >= 32-33
2. testdata/golden/: generate new JSON fixtures (7-8 files)
3. pkg/loader/loader_test.go: TestX86ComplexFunction (CMP+JGE max() function)
4. Fix any decode gaps for CMP, MOVZX, MOVSX, LEA, JGE if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- Floating point ops
- 64-bit x86
- SSE/MMX instructions
- Do not modify existing golden fixtures

## Invariants

- All existing tests (go test ./...) must pass
- New golden fixtures >= 1 op each (CMP, OR, AND, INC required; MOVZX/MOVSX/LEA required)
- TestX86ComplexFunction must NOT skip
- ASCII-only, tabs for indentation, English comments
- No new external dependencies

## Done when

- go build ./... passes
- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 32 subtests
- go test ./pkg/loader/... -run TestX86ComplexFunction passes and logs non-empty C output
- go test ./... passes with all tests green
