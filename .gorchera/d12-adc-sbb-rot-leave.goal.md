# D12: ADC/SBB + ROR/ROL + LEAVE golden fixtures + 3-branch E2E

## Objective

Add golden fixture coverage for six more x86 opcodes:
1. ADC EAX, EBX (0x11 0xD8) -- Add with Carry (multi-precision arithmetic)
2. SBB EAX, EBX (0x19 0xD8) -- Subtract with Borrow (multi-precision arithmetic)
3. ROR EAX, imm8 (0xC1 0xC8 0x03) -- Rotate Right by immediate
4. ROL EAX, imm8 (0xC1 0xC0 0x03) -- Rotate Left by immediate
5. LEAVE (0xC9) -- epilogue shorthand: MOV ESP,EBP + POP EBP
6. CWDE (0x98) -- sign-extend AX into EAX (INT_SEXT(AX->EAX))

Plus an E2E test for a function with 3 branches (clamp / range-check pattern).

## Why

After D11, common missing opcodes for real decompilation:
- ADC/SBB: multi-precision (64-bit on 32-bit) math and crypto routines use these.
  Without them, any 64-bit integer operation in 32-bit code is misrendered.
- ROR/ROL: appear in hash functions, encryption (RC4, AES key schedule), and
  bit-manipulation routines. Without them, crypto code cannot be decompiled.
- LEAVE: used by most compilers as the epilogue instruction. Without a golden fixture,
  we do not know whether the decompiler handles it correctly.
- CWDE: common after byte/short arithmetic before sign-dependent ops.

A 3-branch E2E (clamp function: if x < lo return lo; if x > hi return hi; return x)
exercises a diamond-with-join CFG pattern and validates block structuring for real code.

## Part 1: Golden fixtures to add

### ADC
  {"x86_ADC_EAX_EBX", []byte{0x11, 0xD8}},  // ADC EAX, EBX (ModRM 0xD8)

Expected: INT_ADD(EAX, EBX) + INT_ADD(result, CF) + flag ops. ~6-8 ops.

### SBB
  {"x86_SBB_EAX_EBX", []byte{0x19, 0xD8}},  // SBB EAX, EBX (ModRM 0xD8)

Expected: INT_SUB(EAX, EBX) - INT_ZEXT(CF) + flag ops. ~6-8 ops.

### ROR
  {"x86_ROR_EAX_imm8", []byte{0xC1, 0xC8, 0x03}},  // ROR EAX, 3 (ModRM 0xC8)

Expected: INT_RIGHT(EAX, 3) | INT_LEFT(EAX, 29) -> EAX, plus OF/CF. ~3-5 ops.

### ROL
  {"x86_ROL_EAX_imm8", []byte{0xC1, 0xC0, 0x03}},  // ROL EAX, 3 (ModRM 0xC0)

Expected: INT_LEFT(EAX, 3) | INT_RIGHT(EAX, 29) -> EAX, plus OF/CF. ~3-5 ops.

### LEAVE
  {"x86_LEAVE", []byte{0xC9}},  // LEAVE (single byte)

Expected: COPY(EBP -> ESP) + LOAD([EBP]) -> EBP + INT_ADD(EBP, 4). ~3 ops.
Same effect as MOV ESP,EBP + POP EBP. Ghidra may model this as 2-3 ops.

### CWDE
  {"x86_CWDE", []byte{0x98}},  // CWDE (sign-extend AX to EAX)

Expected: INT_SEXT(AX -> EAX). 1-2 ops.
(CWDE is the 32-bit mode interpretation of CBW/CWDE depending on operand size prefix)

Total golden subtests after D12: >= 63 (57 + 6 = 63)

## Part 2: E2E clamp function (3-branch CFG)

Add TestX86ClampFunction to pkg/loader/loader_test.go.

A clamp function: int clamp(int x, int lo, int hi):
  if (x < lo) return lo;
  if (x > hi) return hi;
  return x;

Assembly (3-way branch using CMP+JGE and CMP+JLE):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (x)
  0x06: 8B 55 0C        MOV EDX, [EBP+12]   (lo)
  0x09: 39 D0           CMP EAX, EDX        (x vs lo)
  0x0B: 7D 03           JGE +3              (skip if x >= lo)
  0x0D: 89 D0           MOV EAX, EDX        (x = lo)
  0x0F: EB 08           JMP +8              (jump to epilogue)
  0x11: 8B 55 10        MOV EDX, [EBP+16]   (hi)
  0x14: 39 D0           CMP EAX, EDX        (x vs hi)
  0x16: 7E 02           JLE +2              (skip if x <= hi)
  0x18: 89 D0           MOV EAX, EDX        (x = hi)
  0x1A: 5D              POP EBP
  0x1B: C3              RET
  Total: 28 bytes

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x8B, 0x55, 0x0C, 0x39, 0xD0, 0x7D, 0x03,
        0x89, 0xD0, 0xEB, 0x08, 0x8B, 0x55, 0x10, 0x39, 0xD0, 0x7E, 0x02, 0x89, 0xD0,
        0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 8
- result.Graph.GetSize() >= 3 (3-way branch creates at least 3 basic blocks)
- Heritage + BatchAActionPool + ActionBlockStructure + ActionFinalStructure
- PrintC output non-empty
- t.Logf("clamp C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add ADC_EAX_EBX, SBB_EAX_EBX, ROR_EAX_imm8, ROL_EAX_imm8, LEAVE, CWDE
2. testdata/golden/: 6 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. pkg/loader/loader_test.go: TestX86ClampFunction (3-branch clamp E2E)
4. Fix any decode gaps for ADC, SBB, ROR, ROL, LEAVE, CWDE if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- ADC/SBB with immediate (only register form needed)
- ROR/ROL by CL (register-count form)
- RCR/RCL (rotate through carry -- rare)
- REP string ops
- FPU/SSE/MMX
- 64-bit mode

## Invariants

- All existing tests pass (57 golden subtests, 13 E2E tests)
- New golden fixtures >= 1 op each
- TestX86ClampFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 63 subtests
- go test ./pkg/loader/... -run TestX86ClampFunction passes, logs >= 3 CFG blocks
- go test ./... passes green
