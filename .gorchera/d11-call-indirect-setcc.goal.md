# D11: CALL indirect + SETCC golden fixtures + indirect-call E2E

## Objective

Add two categories of opcodes not yet covered:
1. CALL indirect: FF D0 (CALL EAX) and FF 10 (CALL [EAX]) -- function pointer dispatch
2. SETCC: 0F 94 (SETE AL), 0F 95 (SETNE AL), 0F 9C (SETL AL), 0F 9D (SETGE AL)
   -- boolean expressions compiled to byte results in C
3. A MOVZX from 16-bit: 0F B7 C0 (MOVZX EAX, AX) -- already have 8-bit variant, add 16-bit
4. An E2E function that uses an indirect call (function pointer)

## Why

After D10, the golden fixture set covers most arithmetic, bitwise, compare, branch, push/pop,
stack frame, and load/store ops. The remaining gaps for real C function decompilation:

- CALL indirect is essential for any code with function pointers or virtual dispatch.
  Without it, callback-based code cannot be decompiled.
- SETCC is produced by C boolean expressions assigned to variables (e.g., `int x = (a > b);`).
  Without SETE/SETNE/SETL/SETGE, the decompiler cannot reconstruct boolean-valued expressions.
- MOVZX from 16-bit (0F B7) is the counterpart to 0F B6 (from 8-bit, already done).

## Part 1: Golden fixtures to add

### CALL indirect (register)
  {"x86_CALL_EAX", []byte{0xFF, 0xD0}},  // CALL EAX (ModRM 0xD0 = mod=11,reg=2,rm=0)

Expected: CALL with EAX as target varnode. Typically: COPY(ESP-4)+STORE(retaddr)+CALL(EAX).
May also see INT_SUB(ESP,4)+STORE+CALL pattern similar to CALL rel32.
Accept whatever the SLA emits.

### CALL indirect (memory)
  {"x86_CALL_mem_EAX", []byte{0xFF, 0x10}},  // CALL [EAX] (ModRM 0x10 = mod=00,reg=2,rm=0)

Expected: LOAD([EAX]) -> tmp, then CALL(tmp). Or CALL with [EAX] address varnode directly.
Verify op count >= 2.

### SETCC
  {"x86_SETE_AL",  []byte{0x0F, 0x94, 0xC0}},  // SETE AL (ModRM 0xC0 = mod=11,rm=0=AL)
  {"x86_SETNE_AL", []byte{0x0F, 0x95, 0xC0}},  // SETNE AL
  {"x86_SETL_AL",  []byte{0x0F, 0x9C, 0xC0}},  // SETL AL (signed less than)
  {"x86_SETGE_AL", []byte{0x0F, 0x9D, 0xC0}},  // SETGE AL (signed greater or equal)

Expected for SETE: COPY(ZF) -> AL or INT_ZEXT(ZF) -> AL. 1-2 ops.
Expected for SETNE: INT_NEGATE(ZF) -> AL or BOOL_NEGATE(ZF). 1-2 ops.
Expected for SETL: BOOL_XOR(SF, OF) -> AL or similar. 2-4 ops.
Expected for SETGE: INT_EQUAL(SF, OF) -> AL. 1-2 ops.
Accept whatever the SLA emits -- record golden verbatim.

### MOVZX from 16-bit
  {"x86_MOVZX_EAX_AX", []byte{0x0F, 0xB7, 0xC0}},  // MOVZX EAX, AX (ModRM 0xC0 = mod=11,reg=0,rm=0)

Expected: INT_ZEXT(AX -> EAX). 1-2 ops. (Zero-extend 16-bit AX into 32-bit EAX)

Total golden subtests after D11: >= 57 (50 + 2 CALL + 4 SETCC + 1 MOVZX = 57)

## Part 2: E2E with indirect call (function pointer)

Add TestX86IndirectCallFunction to pkg/loader/loader_test.go.

A function that calls through a function pointer passed in as argument:

int apply(int (*fn)(int), int x) {
    return fn(x);  // indirect call via register
}

Assembly -- simplified: fn in EBP+8, x in EBP+12:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 0C        MOV EAX, [EBP+12]   (x)
  0x06: 50              PUSH EAX             (arg)
  0x07: 8B 55 08        MOV EDX, [EBP+8]     (fn pointer)
  0x0A: FF D2           CALL EDX             (call fn via register)
  0x0C: 83 C4 04        ADD ESP, 4           (clean up arg)
  0x0F: 5D              POP EBP
  0x10: C3              RET
  Total: 17 bytes

Bytes: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x0C, 0x50, 0x8B, 0x55, 0x08, 0xFF, 0xD2, 0x83, 0xC4, 0x04, 0x5D, 0xC3}

Note: 0x50 = PUSH EAX (already covered). 0xFF 0xD2 = CALL EDX (ModRM 0xD2 = mod=11,reg=2,rm=2=EDX).
0x83 0xC4 0x04 = ADD ESP, imm8(4) -- similar to SUB ESP,imm8 (already in D10). Should decode fine.

Assertions:
- len(result.Instructions) >= 5
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("apply C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add CALL_EAX, CALL_mem_EAX, SETE_AL, SETNE_AL, SETL_AL, SETGE_AL, MOVZX_EAX_AX
2. testdata/golden/: 7 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. pkg/loader/loader_test.go: TestX86IndirectCallFunction
4. Fix any decode gaps for CALL indirect, SETCC, MOVZX 16-bit if needed
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- CALL far (inter-segment)
- SETCC to memory (only register form needed)
- CMOVcc (conditional move)
- BOUND instruction
- FPU/SSE/MMX

## Invariants

- All existing tests pass (50 golden subtests, 12 E2E tests)
- New golden fixtures >= 1 op each
- TestX86IndirectCallFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 57 subtests
- go test ./pkg/loader/... -run TestX86IndirectCallFunction passes with non-empty PrintC
- go test ./... passes green
