# D9: PUSH/POP general regs + more Jcc variants + DEC + XCHG golden fixtures + nested loop E2E

## Objective

Add common x86 opcodes not yet covered:
1. PUSH/POP for general registers (EBX, ECX, EDX, ESI, EDI) -- short form opcodes
2. More Jcc variants (JL, JLE, JG, JGE_via_CMP, JA, JB) used in signed/unsigned comparisons
3. DEC (decrement register) -- complement to INC
4. XCHG EAX, ECX -- exchange registers
5. A nested-loop or multi-branch function E2E test

## Why

D8 added CMP+JGE. Real compiled C uses many Jcc variants depending on signed vs unsigned
comparison. Without JL/JLE/JG/JA/JB, the decompiler cannot reconstruct correct comparison
semantics. PUSH/POP for non-EBP registers appear in every non-trivial function prologue/epilogue.
DEC is the counterpart to INC (already done).

## Part 1: Golden fixtures to add

### PUSH/POP short form (1-byte opcodes 0x50-0x5F)
  {"x86_PUSH_EBX", []byte{0x53}},  // PUSH EBX (opcode 0x53)
  {"x86_PUSH_ECX", []byte{0x51}},  // PUSH ECX (opcode 0x51)
  {"x86_POP_EBX",  []byte{0x5B}},  // POP EBX (opcode 0x5B)

Expected: same pattern as PUSH_EBP / POP_EBP -- COPY + INT_SUB + STORE / LOAD + INT_ADD + COPY

### DEC
  {"x86_DEC_EAX", []byte{0x48}},  // DEC EAX (short form)

Expected: INT_SUB(EAX, 1) + flag ops (~5-6 ops). Note: CF not affected by DEC (unlike SUB).

### XCHG
  {"x86_XCHG_EAX_ECX", []byte{0x91}},  // XCHG EAX, ECX (short form, opcode 0x91)

Expected: COPY(EAX->tmp) + COPY(ECX->EAX) + COPY(tmp->ECX). ~3 ops.

### Jcc variants
  {"x86_JL_fwd",  []byte{0x7C, 0x02}},  // JL +2 (jump if less, SF != OF)
  {"x86_JLE_fwd", []byte{0x7E, 0x02}},  // JLE +2 (jump if less or equal, ZF=1 or SF!=OF)
  {"x86_JG_fwd",  []byte{0x7F, 0x02}},  // JG +2 (jump if greater, ZF=0 and SF=OF)
  {"x86_JB_fwd",  []byte{0x72, 0x02}},  // JB +2 (jump if below/CF=1, unsigned less than)
  {"x86_JA_fwd",  []byte{0x77, 0x02}},  // JA +2 (jump if above, CF=0 and ZF=0)

Expected: each produces BOOL_NEGATE/INT_EQUAL/INT_AND of flag varnodes + CBRANCH. 2-4 ops each.

Total golden subtests after D9: >= 41 (33 + 3 PUSH/POP + 1 DEC + 1 XCHG + 5 Jcc = 43)

## Part 2: Nested-loop or FibFunction E2E test

Add TestX86FibFunction to pkg/loader/loader_test.go.

A simple iterative Fibonacci function that exercises PUSH/POP general regs + loop:

int fib(int n) {
  // iterative Fibonacci: fib(0)=0, fib(1)=1, fib(n)=fib(n-1)+fib(n-2)
  // Uses EBX for prev, ECX for curr, loop counter in EDX
}

Assembly (simple loop with PUSH/POP EBX, ECX):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 53              PUSH EBX          (save EBX)
  0x04: 51              PUSH ECX          (save ECX)
  0x05: 8B 4D 08        MOV ECX, [EBP+8]  (n)
  0x08: 31 DB           XOR EBX, EBX      (prev = 0)
  0x0A: B8 01 00 00 00  MOV EAX, 1        (curr = 1)
  0x0F: 85 C9           TEST ECX, ECX     (n == 0?)
  0x11: 74 0B           JE +11            (if n==0, return 0)
  0x13: 48              DEC EAX           (curr = 0 initially... actually let's keep it simple)

Actually this gets complex. Use a simpler function that exercises PUSH EBX + PUSH ECX + POP ECX + POP EBX:

int add3(int a, int b, int c) {
  // Uses EBX to save a callee-saved register
  PUSH EBP; MOV EBP,ESP; PUSH EBX
  MOV EBX, [EBP+8]    (a)
  ADD EBX, [EBP+12]   (a+b)
  ADD EBX, [EBP+16]   (a+b+c)
  MOV EAX, EBX
  POP EBX
  POP EBP
  RET
}

Bytes:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 53              PUSH EBX
  0x04: 8B 5D 08        MOV EBX, [EBP+8]
  0x07: 03 5D 0C        ADD EBX, [EBP+12]
  0x0A: 03 5D 10        ADD EBX, [EBP+16]
  0x0D: 89 D8           MOV EAX, EBX
  0x0F: 5B              POP EBX
  0x10: 5D              POP EBP
  0x11: C3              RET
  Total: 18 bytes

Byte array: {0x55, 0x89, 0xE5, 0x53, 0x8B, 0x5D, 0x08, 0x03, 0x5D, 0x0C, 0x03, 0x5D, 0x10, 0x89, 0xD8, 0x5B, 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 6
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("add3 C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add PUSH_EBX, PUSH_ECX, POP_EBX, DEC_EAX, XCHG_EAX_ECX, JL_fwd, JLE_fwd, JG_fwd, JB_fwd, JA_fwd
2. testdata/golden/: 10 new JSON fixture files
3. pkg/loader/loader_test.go: TestX86Add3Function (3-arg add using PUSH/POP EBX)
4. Fix any decode gaps for PUSH general regs, POP, XCHG, Jcc variants
5. docs updates

## Out-of-scope

- CALL indirect (FF /2)
- String ops (REP MOVS etc.)
- FPU/SSE
- 64-bit

## Invariants

- All existing tests pass
- New golden fixtures >= 1 op each
- TestX86Add3Function must NOT skip
- No new external dependencies
- ASCII-only, tabs, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 43 subtests
- go test ./pkg/loader/... -run TestX86Add3Function passes with non-empty PrintC
- go test ./... passes green
