# D14: immediate arithmetic + JMP indirect + IMUL 3-operand golden fixtures + E2E

## Objective

Add golden fixture coverage for:
1. OR EAX, imm8 (83 C8 05) -- OR with sign-extended immediate
2. AND EAX, imm8 (83 E0 0F) -- AND with sign-extended immediate
3. XOR EAX, imm8 (83 F0 0F) -- XOR with sign-extended immediate
4. CMP EAX, imm8 (83 F8 05) -- CMP with sign-extended immediate
5. IMUL 3-operand: IMUL EAX, EBX, imm8 (6B C3 05) -- EAX = EBX * 5
6. JMP_EAX (FF E0) -- indirect jump via register (for switch table dispatch)
7. JMP_mem_EAX (FF 20) -- indirect jump via memory [EAX]

Plus a "classify_sign" E2E function that uses immediate arithmetic (OR imm + CMP imm).

## Why

After D13 (69 golden subtests), the remaining practical gaps:
- OR/AND/XOR/CMP with immediate (83-prefix): These are extremely common in all
  real compiled code. The existing OR/AND/CMP golden fixtures use register-to-register
  forms only. The immediate forms have different ModRM encoding and should be verified.
- IMUL 3-operand (6B): Very common in loop optimizations -- GCC/Clang use this to
  multiply a loop variable by a constant without a separate MOV.
- JMP indirect (FF /4): Required for any switch statement decompilation.
  Without JMP indirect, switch() bodies cannot be traced through.

## Part 1: Golden fixtures to add

### OR/AND/XOR with immediate (83 group)

Encoding: 83 ModRM imm8 where ModRM = 11 xxx 000 (mod=11, reg=xxx, rm=0=EAX)
- OR: reg=1: ModRM = 11 001 000 = 0xC8
- AND: reg=4: ModRM = 11 100 000 = 0xE0
- XOR: reg=6: ModRM = 11 110 000 = 0xF0
- CMP: reg=7: ModRM = 11 111 000 = 0xF8

  {"x86_OR_EAX_imm8",  []byte{0x83, 0xC8, 0x05}},  // OR EAX, 5
  {"x86_AND_EAX_imm8", []byte{0x83, 0xE0, 0x0F}},  // AND EAX, 15
  {"x86_XOR_EAX_imm8", []byte{0x83, 0xF0, 0x0F}},  // XOR EAX, 15
  {"x86_CMP_EAX_imm8", []byte{0x83, 0xF8, 0x05}},  // CMP EAX, 5

Expected: same p-code as register forms (INT_OR, INT_AND, INT_XOR, INT_SUB for flags)
but with immediate operand instead of register. Accept whatever SLA emits.

### IMUL 3-operand
  {"x86_IMUL_EAX_EBX_imm8", []byte{0x6B, 0xC3, 0x05}},  // IMUL EAX, EBX, 5

ModRM 0xC3 = mod=11, reg=0 (EAX=dest), rm=3 (EBX=src1); imm8=5.
Expected: INT_SEXT(EBX:4 -> 8) * INT_SEXT(5:4 -> 8) -> EAX (with overflow flags).
Or simpler: EAX = EBX * 5 with INT_MULT. Accept whatever SLA emits.

### JMP indirect
  {"x86_JMP_EAX", []byte{0xFF, 0xE0}},  // JMP EAX (ModRM 0xE0 = mod=11,reg=4,rm=0)

Expected: BRANCHIND(EAX) -- indirect branch. 1 op.

  {"x86_JMP_mem_EAX", []byte{0xFF, 0x20}},  // JMP [EAX] (ModRM 0x20 = mod=00,reg=4,rm=0)

Expected: LOAD([EAX]) -> tmp + BRANCHIND(tmp). Or direct BRANCHIND with [EAX] addr. 1-2 ops.

Total golden subtests after D14: >= 76 (69 + 4 imm + 1 IMUL + 2 JMP = 76)

## Part 2: E2E classify_sign function

Add TestX86ClassifySignFunction to pkg/loader/loader_test.go.

A function that checks sign of an integer:
int classify_sign(int x) {
    if (x == 0) return 0;
    if (x > 0) return 1;
    return -1;
}

Assembly using CMP+imm8:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (x)
  0x06: 83 F8 00        CMP EAX, 0          (x == 0?)
  0x09: 75 05           JNE +5              (not zero)
  0x0B: B8 00 00 00 00  MOV EAX, 0          (return 0)
  0x10: EB 0A           JMP +10             (to epilogue)
  0x12: 83 F8 00        CMP EAX, 0          (x > 0?)
  0x15: 7E 05           JLE +5              (not positive)
  0x17: B8 01 00 00 00  MOV EAX, 1          (return 1)
  0x1C: EB 03           JMP +3              (to epilogue)
  0x1E: B8 FF FF FF FF  MOV EAX, -1         (return -1)
  0x23: 5D              POP EBP
  0x24: C3              RET
  Total: 37 bytes

Bytes:
{0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08,
 0x83, 0xF8, 0x00, 0x75, 0x05,
 0xB8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0A,
 0x83, 0xF8, 0x00, 0x7E, 0x05,
 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x03,
 0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 8
- result.Graph.GetSize() >= 4 (3-way dispatch: zero/positive/negative paths)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("classify_sign C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add OR_EAX_imm8, AND_EAX_imm8, XOR_EAX_imm8, CMP_EAX_imm8, IMUL_EAX_EBX_imm8, JMP_EAX, JMP_mem_EAX
2. testdata/golden/: 7 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. pkg/loader/loader_test.go: TestX86ClassifySignFunction
4. Fix any decode gaps for 83-group immediate, IMUL 3-op, JMP indirect
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- ADD/SUB/ADC/SBB with immediate 32-bit (0x05, 0x0D etc.) -- use 83 forms
- JMP far (EA)
- REP string ops
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass (69 golden subtests, 16 E2E tests)
- New golden fixtures >= 1 op each
- TestX86ClassifySignFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 76 subtests
- go test ./pkg/loader/... -run TestX86ClassifySignFunction passes with non-empty PrintC
- go test ./... passes green
