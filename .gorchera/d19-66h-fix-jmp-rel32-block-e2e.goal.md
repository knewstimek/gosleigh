# D19: 66h prefix fix + JMP rel32 + PUSH/POP gaps + block structuring E2E

## Objective

Fix the 66h operand-size prefix decode gap and add remaining critical golden fixtures:
1. Fix 66h prefix: `66 8B 45 08` (MOV AX,[EBP+8]) must produce 2-byte LOAD/COPY, not 4-byte.
   Regenerate testdata/golden/x86_MOV_AX_EBP_disp8.json to capture correct output.
2. JMP rel32 (E9 xx xx xx xx) -- near jump with 32-bit offset (complement to JMP short EB)
3. PUSH EAX (50) / POP EAX (58) -- EAX is commonly pushed in cdecl argument passing
4. PUSH EDX (52) / POP EDX (5A) -- EDX pushed in some ABI-passing patterns
5. JO/JNO (70/71) -- overflow conditional jumps (arithmetic overflow check pattern)
6. XCHG [mem], EAX (87 00) -- memory XCHG (lock-free swap pattern)

Plus a block structuring E2E: a function with nested if-else that exercises advanced
block structuring (multi-level nesting, shared exit block).

## Why

After D18 (102 golden subtests, 19 E2E tests):

### 66h prefix fix (DEFECT from D18)
The D18 evaluator flagged: `66 8B 45 08` produces 4-byte p-code output (EAX, size=4)
instead of 2-byte (AX, size=2). The golden test passes only because it compares
against the buggy fixture. Real code with `short`, `wchar_t`, or Windows `WORD`
types will decompile incorrectly. This must be fixed before declaring x86 complete.

Root cause to investigate: Gosleigh's p-code translation layer (lower.go / engine.go)
may strip operand-size information encoded by Ghidra x86.sla in the 66h prefix path.
The fix must preserve all existing behavior (97+5 golden tests).

### JMP rel32 (E9)
JMP short (EB) is covered. But most compiler-generated long jumps use E9. Any function
with a loop body exceeding +127/-128 bytes uses E9 instead of EB. Real O0 code for
medium-size functions almost always has E9 jumps. Without it, the engine cannot decode
these instructions.

### PUSH/POP EAX, EDX
PUSH_EBP, PUSH_EBX, PUSH_ECX, PUSH_ESI, PUSH_EDI are covered. But PUSH EAX (50)
and PUSH EDX (52) are not. cdecl argument passing pushes arguments in reverse; for
functions calling printf or similar, EAX or EDX may be pushed. Without these, many
call sites fail to decode.

### JO/JNO
Used in signed arithmetic overflow checks. Any function that checks for integer
overflow uses JO/JNO. Without these, overflow-guard code fails to decode.

### Block structuring E2E
Roadmap item 14: E2E test that validates the full block structuring pipeline
(Heritage -> ActionBlockStructure -> ActionFinalStructure -> PrintC) on a function
with multi-level nesting. This validates that the decompiler produces valid C output
for non-trivial control flow.

## Part 1: Fix 66h prefix decode gap

### Investigation
Determine why `66 8B 45 08` produces 4-byte output.
- Run GOSLEIGH_UPDATE_GOLDEN=1 on the fixture and observe what the engine actually emits.
- Check if x86.sla's operand-size override path produces different VarnodeData sizes.
- Trace through lowerVarnodeTpl in lower.go for the 66h-prefixed instruction.

### Expected fix location
Most likely in pkg/sla/lower.go or pkg/sla/engine.go where Varnode output size is
determined. The 66h prefix should cause the destination Varnode to have size=2 (AX)
rather than size=4 (EAX). If x86.sla already emits size=2 and some layer promotes it
to size=4, that promotion is the bug.

### After fix
- Delete testdata/golden/x86_MOV_AX_EBP_disp8.json
- Regenerate with GOSLEIGH_UPDATE_GOLDEN=1
- Verify the new fixture has: LOAD output size=2, COPY destination size=2
- Run all 102 golden subtests -- all must pass

## Part 2: Golden fixtures

### JMP rel32
  {"x86_JMP_rel32", []byte{0xE9, 0x00, 0x01, 0x00, 0x00}},

Opcode E9: JMP rel32. Offset = 0x100. Target = 0x105 (next_ip=5, +0x100=0x105).
Expected: BRANCH to const:0x105. 1 op.

### PUSH EAX
  {"x86_PUSH_EAX", []byte{0x50}},  // PUSH EAX

Expected: same pattern as PUSH EBP/EBX/ECX. ~2-3 ops (STORE EAX -> [ESP-4], SUB ESP,4).

### POP EAX
  {"x86_POP_EAX", []byte{0x58}},   // POP EAX

Expected: ~2-3 ops (LOAD [ESP] -> EAX, ADD ESP,4).

### PUSH EDX
  {"x86_PUSH_EDX", []byte{0x52}},  // PUSH EDX

Expected: same as PUSH EAX. ~2-3 ops.

### POP EDX
  {"x86_POP_EDX", []byte{0x5A}},   // POP EDX

Expected: ~2-3 ops.

### JO (Jump if Overflow)
  {"x86_JO_fwd", []byte{0x70, 0x08}},  // JO +8

Expected: CBRANCH based on OF (overflow flag). 1 op.

Total golden subtests after D19: >= 109 (102 + 1 fix-regen + 6 new = 108, rounded up)
Note: x86_MOV_AX_EBP_disp8 fixture is regenerated in-place (same slot, better content).
New count = 102 + 6 = 108 unique slots (the fix replaces, not adds, one fixture).

Actually: 102 existing + 6 new = 108 total golden subtests after D19.

## Part 3: Block structuring E2E

Add TestX86NestedIfFunction to pkg/loader/loader_test.go.

A function with nested if-else:

int classify2(int x, int y) {
    if (x > 0) {
        if (y > x) {
            return 2;    // x>0, y>x
        } else {
            return 1;    // x>0, y<=x
        }
    } else {
        return 0;        // x<=0
    }
}

Assembly (x=EBP+8, y=EBP+12):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (x)
  0x06: 85 C0           TEST EAX, EAX       (x <= 0?)
  0x08: 7E 10           JLE +16             (-> else: return 0)
  0x0A: 8B 4D 0C        MOV ECX, [EBP+12]   (y)
  0x0D: 3B C8           CMP ECX, EAX        (y > x?)
  0x0F: 7E 06           JLE +6              (-> return 1)
  0x11: B8 02 00 00 00  MOV EAX, 2
  0x16: EB 06           JMP +6              (-> epilogue)
  0x18: B8 01 00 00 00  MOV EAX, 1
  0x1D: EB 01           JMP +1              (-> epilogue)
  0x1F: 31 C0           XOR EAX, EAX        (return 0)
  0x21: 5D              POP EBP
  0x22: C3              RET
  Total: 35 bytes

JLE at 0x08: target=0x1A...
Wait, recalculate:
- JLE at 0x08, next_ip=0x0A, target=0x1F (XOR EAX,EAX). offset = 0x1F - 0x0A = 0x15. -> 7E 15
- JLE at 0x0F, next_ip=0x11, target=0x18 (MOV EAX,1). offset = 0x18 - 0x11 = 0x07. -> 7E 07
- JMP at 0x16, next_ip=0x18, target=0x21 (POP EBP). offset = 0x21 - 0x18 = 0x09. -> EB 09
- JMP at 0x1D, next_ip=0x1F, target=0x21. offset = 0x21 - 0x1F = 0x02. -> EB 02

Corrected assembly:
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]    (x)
  0x06: 85 C0           TEST EAX, EAX
  0x08: 7E 15           JLE +21             (-> 0x1F: XOR EAX,EAX)
  0x0A: 8B 4D 0C        MOV ECX, [EBP+12]   (y)
  0x0D: 3B C8           CMP ECX, EAX        (y vs x)
  0x0F: 7E 07           JLE +7              (-> 0x18: MOV EAX,1)
  0x11: B8 02 00 00 00  MOV EAX, 2
  0x16: EB 09           JMP +9              (-> 0x21: POP EBP)
  0x18: B8 01 00 00 00  MOV EAX, 1
  0x1D: EB 02           JMP +2              (-> 0x21: POP EBP)
  0x1F: 31 C0           XOR EAX, EAX
  0x21: 5D              POP EBP
  0x22: C3              RET
  Total: 35 bytes

Verify 0x21 = epilogue start:
0x00:55, 0x01:89, 0x02:E5, 0x03:8B, 0x04:45, 0x05:08,
0x06:85, 0x07:C0, 0x08:7E, 0x09:15,
0x0A:8B, 0x0B:4D, 0x0C:0C, 0x0D:3B, 0x0E:C8,
0x0F:7E, 0x10:07,
0x11:B8, 0x12:02, 0x13:00, 0x14:00, 0x15:00,
0x16:EB, 0x17:09,
0x18:B8, 0x19:01, 0x1A:00, 0x1B:00, 0x1C:00,
0x1D:EB, 0x1E:02,
0x1F:31, 0x20:C0,
0x21:5D, 0x22:C3
Total: 35 bytes (0x00..0x22). Correct.

Check JLE at 0x08: next_ip=0x0A, target=0x1F. offset=0x1F-0x0A=0x15. JLE 0x15. Correct.
Check JLE at 0x0F: next_ip=0x11, target=0x18. offset=0x18-0x11=0x07. JLE 0x07. Correct.
Check JMP at 0x16: next_ip=0x18, target=0x21. offset=0x21-0x18=0x09. JMP 0x09. Correct.
Check JMP at 0x1D: next_ip=0x1F, target=0x21. offset=0x21-0x1F=0x02. JMP 0x02. Correct.

Bytes:
{0x55, 0x89, 0xE5,
 0x8B, 0x45, 0x08, 0x85, 0xC0, 0x7E, 0x15,
 0x8B, 0x4D, 0x0C, 0x3B, 0xC8, 0x7E, 0x07,
 0xB8, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x09,
 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x02,
 0x31, 0xC0,
 0x5D, 0xC3}

Assertions:
- len(result.Instructions) >= 10
- result.Graph.GetSize() >= 4 (entry + 2 branches + exit = at least 4 blocks)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("classify2 C output:\n%s", output)

## In-scope

1. pkg/sla/lower.go or engine.go: fix 66h prefix producing 4-byte instead of 2-byte output
2. testdata/golden/x86_MOV_AX_EBP_disp8.json: delete and regenerate with correct 16-bit p-code
3. pkg/sla/x86_golden_test.go: add 6 new entries (JMP_rel32, PUSH_EAX, POP_EAX, PUSH_EDX, POP_EDX, JO_fwd)
4. testdata/golden/: 6 new JSON fixture files
5. pkg/loader/loader_test.go: TestX86NestedIfFunction
6. docs/STATUS.md + docs/X86_ROADMAP.md updates

## Out-of-scope

- Floating-point instructions (FLD, FST, FMUL etc.) -- separate effort
- DWARF/symtab integration
- Assembly printer
- 64-bit mode
- Segment override prefixes (FS:, GS:)
- REP with 66h combined (REPZ MOVSW etc.)

## Invariants

- All existing tests pass (102 golden subtests -- including the REGENERATED x86_MOV_AX_EBP_disp8)
- After fix: x86_MOV_AX_EBP_disp8.json must contain LOAD with size=2 and COPY with size=2
- New golden fixtures >= 1 op each
- TestX86NestedIfFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 108 subtests
- testdata/golden/x86_MOV_AX_EBP_disp8.json contains "size":2 in LOAD/COPY ops
- go test ./pkg/loader/... -run TestX86NestedIfFunction passes with non-empty PrintC
- go test ./... passes green
