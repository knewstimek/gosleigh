# D18: misc opcode gaps + complex multi-arg function E2E

## Objective

Fill remaining practical opcode gaps and add a complex multi-argument E2E:
1. MOVSX EAX, AX   (0F BF C0) -- sign-extend 16-bit reg to 32-bit (complement to MOVZX 16-bit)
2. MOVSX EAX, [EAX] (0F BE 00) -- sign-extend byte from memory
3. TEST EAX, imm32  (A9 FF FF FF FF) -- TEST with immediate (flags only, no result)
4. AND EAX, EBX    (21 D8)     -- register AND (complement to AND_EAX_imm8 from D14)
5. OR EAX, EBX     (09 D8)     -- register OR
6. MOV AX, [EBP+8] (66 8B 45 08) -- 16-bit MOV with operand-size prefix (OS prefix 66h)
7. MOVZX EAX, [EAX] (0F B6 00) -- zero-extend byte from memory

Plus a complex E2E: a function with 3 arguments, a local variable, struct pointer access,
and conditional return -- exercises the full pipeline together.

## Why

After D17 (97 golden subtests), remaining gaps for production-quality x86 coverage:
- MOVSX from memory/16-bit: Ubiquitous in code that handles signed chars/shorts.
  Without MOVSX from memory, any function reading a signed byte/word from a struct fails.
- TEST imm32: Used in flag-testing patterns like `if (flags & MASK)`. Without it,
  bitfield tests produce wrong output.
- Register AND/OR: D14 covered imm8 forms (83-group). The register forms (21/09) have
  different ModRM and are very common in bit manipulation.
- 66h OS prefix: Used whenever 16-bit values are loaded (short int, WORD). Every
  function handling wchar_t, UTF-16, or Windows WORD types needs this.
- MOVZX from memory: Ubiquitous for unsigned char/byte access (e.g., `(unsigned)buf[i]`).

The complex E2E validates that all pipeline stages (Heritage, block structuring, PrintC)
correctly handle a function that combines multiple previously-tested patterns.

## Part 1: Golden fixtures

### MOVSX EAX, AX (16-bit sign extend)
  {"x86_MOVSX_EAX_AX", []byte{0x0F, 0xBF, 0xC0}},

ModRM 0xC0 = mod=11, reg=0 (EAX=dst), rm=0 (AX=src, 16-bit).
Expected: INT_SEXT(AX:2 -> EAX:4). 1 op.

### MOVSX EAX, [EAX] (byte from memory, sign extend)
  {"x86_MOVSX_EAX_mem", []byte{0x0F, 0xBE, 0x00}},

ModRM 0x00 = mod=00, reg=0 (EAX=dst), rm=0 (EAX=base addr).
Opcode 0F BE: MOVSX r32, r/m8. Reads 1 byte from [EAX] and sign-extends to 32-bit.
Expected: LOAD([EAX]:1) -> tmp:1, INT_SEXT(tmp:1 -> EAX:4). 1-2 ops.

### MOVZX EAX, [EAX] (byte from memory, zero extend)
  {"x86_MOVZX_EAX_mem", []byte{0x0F, 0xB6, 0x00}},

ModRM 0x00 = mod=00, reg=0 (EAX=dst), rm=0 (EAX=base addr).
Opcode 0F B6: MOVZX r32, r/m8. Reads 1 byte from [EAX] and zero-extends.
Expected: LOAD([EAX]:1) -> tmp:1, INT_ZEXT(tmp:1 -> EAX:4). 1-2 ops.

### TEST EAX, imm32
  {"x86_TEST_EAX_imm32", []byte{0xA9, 0xFF, 0xFF, 0xFF, 0xFF}},

Opcode A9: TEST EAX, imm32 (short form). imm=0xFFFFFFFF.
Expected: INT_AND(EAX, -1) -> tmp, ZF/SF/PF flags. ~3-5 ops (flags only, no result stored).

### AND EAX, EBX (register form)
  {"x86_AND_EAX_EBX", []byte{0x21, 0xD8}},

Opcode 21: AND r/m32, r32. ModRM 0xD8 = mod=11, reg=3(EBX=src), rm=0(EAX=dst).
Expected: INT_AND(EAX, EBX) -> EAX + flag ops. ~4-5 ops.

### OR EAX, EBX (register form)
  {"x86_OR_EAX_EBX", []byte{0x09, 0xD8}},

Opcode 09: OR r/m32, r32. ModRM 0xD8 = mod=11, reg=3(EBX), rm=0(EAX).
Expected: INT_OR(EAX, EBX) -> EAX + flag ops. ~4-5 ops.

### MOV AX, [EBP+8] (16-bit load with 66h prefix)
  {"x86_MOV_AX_EBP_disp8", []byte{0x66, 0x8B, 0x45, 0x08}},

Prefix 66h (operand size override) + 8B (MOV r16, r/m16) + ModRM 0x45 (disp8, EAX=dst, EBP=base).
Reads 2 bytes from [EBP+8] into AX (not EAX).
Expected: LOAD([EBP+8]:2) -> AX:2. 1 op.

Total golden subtests after D18: >= 104 (97 + 7 = 104)

## Part 2: Complex multi-arg E2E function

Add TestX86ComplexMultiArgFunction to pkg/loader/loader_test.go.

A function combining multiple patterns:

int process(int *arr, int len, int threshold) {
    int sum = 0;
    int i;
    for (i = 0; i < len; i++) {
        if (arr[i] > threshold) {
            sum += arr[i];
        }
    }
    return sum;
}

Assembly (arr=EBP+8, len=EBP+12, threshold=EBP+16):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 56              PUSH ESI          (callee save)
  0x04: 31 F6           XOR ESI, ESI      (sum = 0)
  0x06: 31 C0           XOR EAX, EAX      (i = 0)
  0x08: 3B 45 0C        CMP EAX, [EBP+12] (i < len?)
  0x0B: 7D 14           JGE +20           (exit)
  0x0D: 8B 55 08        MOV EDX, [EBP+8]  (arr)
  0x10: 8B 14 82        MOV EDX, [EDX+EAX*4] (arr[i])
  0x13: 3B 55 10        CMP EDX, [EBP+16] (arr[i] > threshold?)
  0x16: 7E 02           JLE +2            (skip add)
  0x18: 01 D6           ADD ESI, EDX      (sum += arr[i])
  0x1A: 40              INC EAX           (i++)
  0x1B: EB EB           JMP -21           (loop back to CMP at 0x08)
  0x1D: 89 F0           MOV EAX, ESI      (return sum)
  0x1F: 5E              POP ESI           (callee restore)
  0x20: 5D              POP EBP
  0x21: C3              RET
  Total: 34 bytes

Note: 0x8B 0x14 0x82 = MOV EDX, [EDX+EAX*4]. ModRM 0x14 = mod=00, reg=2(EDX), rm=4(SIB).
SIB 0x82 = scale=10(4), index=000(EAX), base=010(EDX). This exercises SIB from D16.

JGE at 0x0B: target=0x1F, next=0x0D, offset=0x1F-0x0D=0x12 -> JGE +0x12 = 0x7D 0x12
JLE at 0x16: target=0x1A, next=0x18, offset=0x1A-0x18=0x02 -> 0x7E 0x02
JMP at 0x1B: target=0x08, next=0x1D, offset=0x08-0x1D=-0x15=0xEB -> 0xEB 0xEB

Bytes:
{0x55, 0x89, 0xE5, 0x56, 0x31, 0xF6, 0x31, 0xC0,
 0x3B, 0x45, 0x0C, 0x7D, 0x12,
 0x8B, 0x55, 0x08, 0x8B, 0x14, 0x82,
 0x3B, 0x55, 0x10, 0x7E, 0x02,
 0x01, 0xD6, 0x40, 0xEB, 0xEB,
 0x89, 0xF0, 0x5E, 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 10
- result.Graph.GetSize() >= 4 (entry + loop body + conditional + exit)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("process C output:\n%s", output)

Note on JMP offset: At 0x1B (EB EB), next_ip = 0x1D. Target = 0x08.
Offset = 0x08 - 0x1D = -0x15 = 0xEB as signed byte. CORRECT.

## In-scope

1. pkg/sla/x86_golden_test.go: add 7 fixtures above
2. testdata/golden/: 7 new JSON files
3. pkg/loader/loader_test.go: TestX86ComplexMultiArgFunction
4. Fix any decode gaps for 66h prefix, 0F BE/B6 from memory
5. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- 66h prefix with SIB (complex; rare in O0 code)
- REP prefix with 66h override
- REPZ/REPNZ other than string ops
- FPU/SSE/MMX
- 64-bit

## Invariants

- All existing tests pass (97 golden subtests, 16 E2E tests)
- New golden fixtures >= 1 op each
- TestX86ComplexMultiArgFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 104 subtests
- go test ./pkg/loader/... -run TestX86ComplexMultiArgFunction passes
- go test ./... passes green
