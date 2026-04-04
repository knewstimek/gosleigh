# B8: x86 additional opcode coverage and gap fixes

## Objective

Extend TestGoldenX86 with 7 new x86 32-bit opcodes and fix any translation gaps
encountered. Each new opcode must produce at least 1 p-code op (or be documented
as a genuine PCODE_NOP variant with 0 ops). Generate golden fixture JSON files
for all passing opcodes.

## Why

Phase B6+B7 confirmed that RET (0xC3) and PUSH EBP (0x55) work with 3 ops each.
But only 2 opcodes is not enough to trust the x86 translation path. B8 adds
common opcodes (MOV, ADD, SUB, XOR, POP, JMP) which cover register addressing,
immediate values, ALU ops, and branch targets -- the building blocks of real
x86 function code. Gaps found here must be fixed before Phase C E2E can proceed.

## New opcodes to add and test

Add these entries to the `cases` slice in `pkg/sla/x86_golden_test.go`:

| Subtest name       | Bytes                          | Mnemonic          |
|--------------------|--------------------------------|-------------------|
| x86_MOV_EBX_EAX   | {0x89, 0xC3}                   | MOV EBX, EAX     |
| x86_MOV_EAX_imm32 | {0xB8, 0x01, 0x00, 0x00, 0x00} | MOV EAX, 1       |
| x86_ADD_EAX_EBX   | {0x01, 0xD8}                   | ADD EAX, EBX     |
| x86_SUB_EAX_EBX   | {0x29, 0xD8}                   | SUB EAX, EBX     |
| x86_XOR_EAX_EAX   | {0x31, 0xC0}                   | XOR EAX, EAX     |
| x86_POP_EBP       | {0x5D}                         | POP EBP          |
| x86_JMP_short     | {0xEB, 0x00}                   | JMP +0 (rel8)    |

ModRM explanation for reference (all register-to-register):
- 0xC3 = mod=11, reg=EAX(000), r/m=EBX(011) -- direct register addressing
- 0xD8 = mod=11, reg=EBX(011), r/m=EAX(000) -- direct register addressing
- 0xC0 = mod=11, reg=EAX(000), r/m=EAX(000) -- direct register addressing

## In-scope

1. `pkg/sla/x86_golden_test.go` -- extend only (do NOT recreate from scratch):
   - Add the 7 new entries to the existing `cases` slice in TestGoldenX86.
   - Change the 0-ops handling: for `x86_NOP` keep the current t.Logf warning.
     For all NEW opcodes (not x86_NOP), add a hard t.Fatalf if 0 ops are returned
     even in update mode -- 0 ops for a real instruction is always a failure.
   - Differentiate: check `tc.name == "x86_NOP"` to apply the soft vs hard rule.

2. `pkg/sla/translate.go` (or other runtime files) -- fix translation gaps:
   - If an opcode returns 0 ops or an error, trace the failure:
     - Check TranslateInstructionAt error message
     - Look for "unimplemented" or "unable to resolve constructor" patterns
     - Cross-reference Ghidra C++ in ghidra-ref/ for the failing code path
   - Fix the specific gap. Common expected issues:
     - OperandSymbol / VarnodeList variants not yet handled
     - ContextOp resolution gaps for flag-setting ALU ops
     - Dynamic varnode paths for memory-indirect forms (not present in these opcodes,
       but may appear in adjacent Sleigh constructors)
   - Do NOT modify: integration_test.go, golden_test.go, pspec.go, pspec_test.go,
     or any existing 6502 golden fixture JSON files.

3. `testdata/golden/` -- generate golden fixtures for all 7 new opcodes:
   - Run: GOSLEIGH_UPDATE_GOLDEN=1 go test ./pkg/sla/... -run TestGoldenX86
   - Each new fixture must contain at least 1 op entry (not an empty array).
   - Exception: if a genuine PCODE_NOP definition is found in x86.sla for one of
     these opcodes, document it in the test and allow 0 ops only for that subtest.

## Out-of-scope

- No memory-indirect addressing (e.g., MOV [EAX], EBX). Register-only opcodes only.
- No 64-bit (REX prefix, x86-64).
- No floating point or SSE/MMX.
- No CALL instruction (stack + ret-addr push is complex; save for B9).
- No conditional branches beyond JMP short.
- Do not modify integration_test.go or golden_test.go (6502 must be untouched).
- Do not add MOV segment-register forms, LEA, or string ops.

## Invariants

- Existing golden tests (BRK.json, NOP_EA.json, LDA_imm.json) must pass unchanged.
- Existing x86 golden tests (x86_NOP.json, x86_RET.json, x86_PUSH_EBP.json) must pass.
- `go build ./...` must pass.
- `go test ./pkg/sla/...` must pass with all tests green.
- All 7 new subtests must produce at least 1 op and have a golden fixture.
- ASCII-only in all code and test output. Tabs for indentation.
- Comments in English.

## Constraints

- Do NOT recreate x86_golden_test.go. Extend the existing file only.
- Do NOT recreate pspec.go or pspec_test.go.
- The goldenEngineX86 helper function is already correct. Do not change its signature.
- The 16-byte zero-padded instruction buffer is sufficient for all opcodes listed
  (longest is 5 bytes: MOV EAX, imm32).
- If a gap requires touching lower.go, resolve_handles.go, builder.go, or discache.go:
  check C++ ghidra-ref for the correct parity behavior first. Document the C++ ref
  in the fix comment.
- testdata/x86-packed.sla and testdata/sla/x86.pspec are read-only reference files.

## Expected p-code output (for reference, not binding)

Ghidra 32-bit x86 p-code expectations:

x86_MOV_EBX_EAX (89 C3):  COPY(EAX -> EBX)                           -- 1 op
x86_MOV_EAX_imm32 (B8...): COPY(const:1 -> EAX)                      -- 1 op
x86_ADD_EAX_EBX (01 D8):  INT_ADD(EAX, EBX -> EAX), flag ops (CF/ZF/SF/OF/AF) -- 5-6 ops
x86_SUB_EAX_EBX (29 D8):  INT_SUB(EAX, EBX -> EAX), flag ops         -- 5-6 ops
x86_XOR_EAX_EAX (31 C0):  INT_XOR(EAX, EAX -> EAX), flag ops (ZF/SF/CF/OF) -- 4-5 ops
x86_POP_EBP (5D):         LOAD(ram[ESP] -> EBP), INT_ADD(ESP, 4 -> ESP) -- 2 ops
x86_JMP_short (EB 00):    BRANCH(ram:inst_next)                       -- 1 op

Flag ops (CF, ZF, SF, OF, AF) are in carry/zero/sign/overflow/auxcarry registers.
The exact count depends on which flag constructors the Sleigh pattern selects.

## Done when

- `go build ./...` passes.
- `go test ./pkg/sla/... -run TestGoldenX86` passes with all 10 subtests green
  (3 existing + 7 new).
- Each new fixture file exists and contains at least 1 op entry.
- `go test ./pkg/sla/... -run TestGolden6502` still passes (6502 parity unchanged).
- `go test ./pkg/sla/... -run TestParsePspec` still passes.
