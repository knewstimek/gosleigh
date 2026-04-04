# D6: IDIV/DIV golden fixtures + bitshift ops + TestX86DivideFunction E2E

## Objective

1. Add IDIV and DIV golden fixtures to close the integer division gap.
2. Add SHL/SHR/SAR bitshift golden fixtures (extremely common in compiled C).
3. Add a divide function E2E test (int div(int a, int b) { return a/b; }).
4. Update docs.

## Why

Phase D5 verified IMUL/MUL. The remaining common x86 integer arithmetic ops needed for
real-world decompilation are integer division (IDIV/DIV) and bitshifts (SHL/SHR/SAR).
IDIV and SAR appear in almost every non-trivial function (division, modulo, sign-extending
shifts). Without them the decompiler cannot handle most real compiled C.

## New opcodes needed

### Division opcodes (Part 1 -- required)

x86 IDIV r/m32 (0xF7 /7): signed divide EDX:EAX by r/m32, quotient->EAX, remainder->EDX
  {"x86_IDIV_ECX", []byte{0xF7, 0xF9}}  // IDIV ECX (ModRM 0xF9 = mod=11 reg=7 rm=1)

Expected p-code: INT_SDIV + INT_SREM + flag ops. Probably 4-8 ops.

x86 DIV r/m32 (0xF7 /6): unsigned divide EDX:EAX by r/m32, quotient->EAX, remainder->EDX
  {"x86_DIV_ECX", []byte{0xF7, 0xF1}}   // DIV ECX (ModRM 0xF1 = mod=11 reg=6 rm=1)

Expected p-code: INT_DIV + INT_REM. Probably 3-5 ops.

### CDQ (Part 1 -- required for divide function)

CDQ (0x99): sign-extend EAX into EDX:EAX (used before IDIV)
  {"x86_CDQ", []byte{0x99}}

Expected p-code: INT_SRIGHT (shift EAX right 31) -> EDX, or similar sign-extension. 1-2 ops.

### Bitshift opcodes (Part 2 -- required)

  {"x86_SHL_EAX_imm8", []byte{0xC1, 0xE0, 0x02}}  // SHL EAX, 2
  {"x86_SHR_EAX_imm8", []byte{0xC1, 0xE8, 0x02}}  // SHR EAX, 2
  {"x86_SAR_EAX_imm8", []byte{0xC1, 0xF8, 0x02}}  // SAR EAX, 2

ModRM for EAX: 0xE0 (/4 SHL), 0xE8 (/5 SHR), 0xF8 (/7 SAR)
Expected p-code: INT_LEFT / INT_RIGHT / INT_SRIGHT + flag ops. 3-6 ops each.

## Divide function E2E test (Part 3)

Add TestX86DivideFunction to pkg/loader/loader_test.go.

The divide function (int div(int a, int b) { return a / b; }) bytes:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (arg a)
  0x06: 99              CDQ                 (sign-extend EAX -> EDX:EAX)
  0x07: F7 7D 0C        IDIV [EBP+0xC]      (EAX = EDX:EAX / [EBP+12])
  0x0A: 5D              POP EBP
  0x0B: C3              RET
  Total: 12 bytes

Byte slice: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x99, 0xF7, 0x7D, 0x0C, 0x5D, 0xC3}

Note: IDIV [EBP+0xC] uses memory operand with disp8. ModRM 0x7D = mod=01 reg=7 rm=5 (EBP+disp8).

TestX86DivideFunction:
  a. EngineBuilder{SLAPath, PspecPath, Bytes: prog}
  b. bridge.Build(engine, bridge.BuildConfig{Name:"divide", Entry:base, MaxInstructions:20})
  c. Assert len(result.Instructions) >= 4
  d. Heritage + BatchAActionPool + BlockStructure + FinalStructure
  e. PrintC output non-empty
  f. t.Logf("Divide C output:\n%s", output)

## Bitshift function E2E test (Part 4 -- optional but preferred)

Add TestX86BitshiftFunction to pkg/loader/loader_test.go.

A simple shift function (int shl2(int a) { return a << 2; }):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]
  0x06: C1 E0 02        SHL EAX, 2
  0x09: 5D              POP EBP
  0x0A: C3              RET
  Total: 11 bytes

Byte slice: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0xC1, 0xE0, 0x02, 0x5D, 0xC3}

Assertions same as TestX86DivideFunction pattern.

## In-scope

1. pkg/sla/x86_golden_test.go: add IDIV_ECX, DIV_ECX, CDQ, SHL_EAX_imm8, SHR_EAX_imm8, SAR_EAX_imm8
2. testdata/golden/: generate 6 new JSON fixtures
3. pkg/loader/loader_test.go: add TestX86DivideFunction (required) + TestX86BitshiftFunction (preferred)
4. Fix any decode/translate gaps for IDIV, DIV, CDQ, SHL, SHR, SAR
5. docs/STATUS.md: add Phase D6 completion entry
6. docs/X86_ROADMAP.md: update D6 status

## Out-of-scope

- FLOAT ops (future)
- 64-bit x86 (future)
- switch/jump table (future)
- Do not modify existing golden fixtures

## Invariants

- All existing tests (go test ./...) must pass
- New golden fixtures >= 1 op each (IDIV and CDQ required)
- TestX86DivideFunction must NOT skip
- TestX86BitshiftFunction must NOT skip
- ASCII-only, tabs for indentation, English comments
- No new external dependencies

## Done when

- go build ./... passes
- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 25 subtests (19 + IDIV + DIV + CDQ + SHL + SHR + SAR)
- go test ./pkg/loader/... -run TestX86DivideFunction passes and logs non-empty C output
- go test ./... passes with all tests green
