# D10: PUSH imm + NOT/NEG + stack locals golden fixtures + E2E with local vars

## Objective

Add remaining common x86 opcodes not yet covered:
1. PUSH immediate: 0x6A (imm8 sign-extended) and 0x68 (imm32) -- used in C calling conventions
2. NOT EAX (0xF7 0xD0) -- bitwise NOT
3. NEG EAX (0xF7 0xD8) -- two's-complement negation
4. MOV [EBP-N], reg -- stack local variable write (used in every non-trivial function)
5. An E2E test for a function with stack-allocated local variables

## Why

After D9, the golden fixture set covers most arithmetic, bitwise, compare, branch, push/pop, and
calling ops. But three gaps remain before we can decompile realistic C functions:

- PUSH imm is ubiquitous: every function call with literal args uses PUSH 0x6A/0x68.
- NOT/NEG are single-instruction unary ops used heavily in bit-manipulation and arithmetic.
- Stack locals (MOV [EBP-4], reg; MOV reg, [EBP-4]) are required to decompile any function
  that allocates a local variable -- present in virtually every non-trivial C function.

Without stack write golden fixtures, the decompiler will silently mishandle local variable
allocation in E2E tests.

## Part 1: Golden fixtures to add

### PUSH immediate
  {"x86_PUSH_imm8",  []byte{0x6A, 0x05}},         // PUSH byte 5 (sign-extended to 32-bit)
  {"x86_PUSH_imm32", []byte{0x68, 0x78, 0x56, 0x34, 0x12}}, // PUSH dword 0x12345678

Expected for PUSH imm: same ops as PUSH_EBP -- COPY(imm)+INT_SUB(ESP,4)+STORE(imm->[ESP]).
Verify op count >= 2 (INT_SUB + STORE minimum; COPY may be implicit).

### NOT
  {"x86_NOT_EAX", []byte{0xF7, 0xD0}},  // NOT EAX (ModRM 0xD0 = mod=11,reg=2,rm=0)

Expected: INT_NEGATE or INT_NOT depending on Ghidra semantics.
Note: x86 NOT is bitwise complement (XOR with -1), so Ghidra likely uses INT_NEGATE or
INT_XOR(EAX, const:0xFFFFFFFF:4). Accept whichever the SLA emits -- record golden verbatim.

### NEG
  {"x86_NEG_EAX", []byte{0xF7, 0xD8}},  // NEG EAX (ModRM 0xD8 = mod=11,reg=3,rm=0)

Expected: INT_2COMP (two's complement negation) + flag ops (CF, OF, SF, ZF, AF, PF).
CF is SET if src != 0; OF set if result == 0x80000000.

### Stack local write
  {"x86_MOV_EBP_minus4_EAX", []byte{0x89, 0x45, 0xFC}},  // MOV [EBP-4], EAX (disp8 -4 = 0xFC)

ModRM 0x45 = mod=01 (disp8), reg=0 (EAX), rm=5 (EBP).
Expected: STORE(EAX -> [EBP+(-4)]). 1 op (STORE with INT_ADD(EBP, -4) implicit in address).
This verifies that disp8 with negative offset is handled correctly.

### Stack local read back
  {"x86_MOV_EAX_EBP_minus4", []byte{0x8B, 0x45, 0xFC}},  // MOV EAX, [EBP-4]

ModRM 0x45 = mod=01 (disp8), reg=0 (EAX), rm=5 (EBP), disp = -4 (0xFC sign-extended).
Expected: LOAD([EBP+(-4)]) -> EAX. 1 op.

Total golden subtests after D10: >= 48 (43 + 2 PUSH_imm + 1 NOT + 1 NEG + 2 stack mov = 49)

## Part 2: E2E test with stack-allocated local variable

Add TestX86LocalVarFunction to pkg/loader/loader_test.go.

A function that uses a stack local variable:

int double_it(int x) {
    int local = x * 2;
    return local;
}

Assembly:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 83 EC 04        SUB ESP, 4        (allocate 4 bytes for local)
  0x06: 8B 45 08        MOV EAX, [EBP+8] (x)
  0x09: D1 E0           SHL EAX, 1        (x * 2 via shift)
  0x0B: 89 45 FC        MOV [EBP-4], EAX  (store into local)
  0x0E: 8B 45 FC        MOV EAX, [EBP-4]  (load local into EAX)
  0x11: 89 EC           MOV ESP, EBP      (epilogue)
  0x13: 5D              POP EBP
  0x14: C3              RET
  Total: 21 bytes

Bytes: {0x55, 0x89, 0xE5, 0x83, 0xEC, 0x04, 0x8B, 0x45, 0x08, 0xD1, 0xE0, 0x89, 0x45, 0xFC, 0x8B, 0x45, 0xFC, 0x89, 0xEC, 0x5D, 0xC3}

Note: 0x83 0xEC 0x04 = SUB ESP, imm8(4) -- this may be a new opcode. If SUB ESP,imm8 is
not yet handled, add golden fixture x86_SUB_ESP_imm8 first and fix any gap.
SUB r/m32, imm8: opcode 0x83, ModRM 0xEC = mod=11,reg=5(SUB),rm=4(ESP), imm8=0x04.

Assertions:
- len(result.Instructions) >= 6
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("double_it C output:\n%s", output)

## In-scope

1. pkg/sla/x86_golden_test.go: add PUSH_imm8, PUSH_imm32, NOT_EAX, NEG_EAX, MOV_EBP_minus4_EAX, MOV_EAX_EBP_minus4
2. testdata/golden/: 6 new JSON fixture files (generated with GOSLEIGH_UPDATE_GOLDEN=1)
3. If SUB ESP,imm8 (0x83 0xEC) decode fails: add x86_SUB_ESP_imm8 golden fixture and fix gap
4. pkg/loader/loader_test.go: TestX86LocalVarFunction
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- PUSH/POP segment registers (CS/DS/ES/SS)
- REP string ops (MOVS, STOS, SCAS)
- FPU/SSE/MMX
- 64-bit mode
- ENTER/LEAVE instructions (rare in modern compilers)

## Invariants

- All existing tests pass
- New golden fixtures >= 1 op each
- TestX86LocalVarFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 49 subtests
- go test ./pkg/loader/... -run TestX86LocalVarFunction passes with non-empty PrintC
- go test ./... passes green
