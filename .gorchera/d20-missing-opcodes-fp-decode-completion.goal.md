# D20: Missing opcodes + FP basic decode + x86 completion declaration

## Objective

Complete the x86 coverage and declare x86 done:
1. XCHG EAX, [EAX] (87 00) -- memory exchange (lock-free swap pattern)
2. JNO rel8 (71 xx) -- jump if no overflow (complement to JO from D19)
3. FP basic decode: FLD_st0_const (D9 E8 = FLD1, loads 1.0 onto FP stack), FMUL_st0_st1 (DE C9), FSTPS (D9 1C 24 = FSTP [ESP]) -- verify x86.sla decodes FP ops to p-code
4. Multi-function call chain E2E: a caller that calls a helper, exercises CALL rel32 + return value propagation through EAX
5. x86 completion declaration: update docs/STATUS.md and docs/X86_ROADMAP.md with final status

## Why

After D19 (108 golden subtests, 20 E2E tests):

### XCHG EAX, [EAX]
Was in D19 scope but deferred. XCHG is used in lock-free compare-exchange patterns and as
a no-op in some older code (XCHG EAX, EAX = NOP variant). Without it, any lock-free code
fails to decode.

### JNO
Complement to JO (D19). Overflow-check patterns always have both branches. A function that
checks for NO overflow (success path) uses JNO. Without it, the positive path of overflow
checks is missing.

### FP basic decode
x86.sla already defines FLD/FADD/FMUL/FSTP p-code semantics. The golden fixture test only
checks that x86.sla successfully decodes these opcodes to p-code -- it does NOT require the
full Heritage/PrintC float type inference layer (that is a future separate phase). This
establishes that the Sleigh translation layer is FP-capable.

FP golden fixtures produce p-code FLOAT_* ops (FLOAT_ADD, FLOAT_MULT, FLOAT_NAN etc.) and
ST0/ST7 register varnodes. If x86.sla cannot decode these, the golden test will show the
decode gap; if it can, we confirm the foundation is correct.

### Multi-function call chain E2E
All prior E2E tests use single functions. A caller+callee chain exercises:
- CALL rel32 encoding (E8) between two functions in the same byte slice
- Return value convention (callee result in EAX used by caller)
- The bridge.Build() MaxInstructions limit across function boundaries

### x86 completion declaration
D1-D20 cover: all common integer ops, all Jcc variants, PUSH/POP all general regs,
MOV/LOAD/STORE with all addressing modes (disp8/disp32/SIB/abs32/reg), CALL/RET,
REP string ops, ENTER/LEAVE, MOVSX/MOVZX, CMOVcc, BSWAP, IMUL/IDIV/MUL/DIV,
bitshift/rotate, SETcc, indirect CALL/JMP, 66h prefix, REP prefix, basic FP decode.
This constitutes a production-quality x86 Sleigh translation layer.

## Part 1: Missing integer opcode golden fixtures

### XCHG EAX, [EAX]
  {"x86_XCHG_EAX_mem", []byte{0x87, 0x00}},  // XCHG EAX, [EAX]

ModRM 0x00 = mod=00, reg=0 (EAX), rm=0 (EAX = base address).
Opcode 87: XCHG r/m32, r32 (or r32, r/m32 -- symmetric).
Expected: reads [EAX] to tmp, writes EAX to [EAX], writes tmp to EAX. ~3-4 ops.

### JNO rel8
  {"x86_JNO_fwd", []byte{0x71, 0x08}},  // JNO +8

Complement to JO (0x70). CBRANCH based on NOT OF (overflow flag).
Expected: CBRANCH on !OF to offset 10. 1 op.

Total golden subtests after D20: >= 110 (108 + 2 = 110)

## Part 2: FP basic decode golden fixtures

Add to x86_golden_test.go. These verify that x86.sla translates FP opcodes to p-code.
If the decode fails (unknown opcode), the test will fail and reveal the gap.
The fixture content is generated with GOSLEIGH_UPDATE_GOLDEN=1; we do NOT pre-specify
exact p-code because FP p-code is architecture-spec-defined and may vary.

### FLD1 (D9 E8) -- load constant 1.0 onto FP stack
  {"x86_FLD1", []byte{0xD9, 0xE8}},

Opcode D9 E8: FLD1 -- push 1.0 onto ST(0). No memory access.
Expected: at least 1 p-code op. Accept any FLOAT_* or COPY/INT_* ops.
Must decode without error (no UnimplError).

### FLDZ (D9 EE) -- load constant 0.0 onto FP stack
  {"x86_FLDZ", []byte{0xD9, 0xEE}},

Opcode D9 EE: FLDZ -- push 0.0 onto ST(0).
Expected: at least 1 op. Accept any output.

### FSTPS [ESP] (D9 1C 24) -- store and pop ST(0) to [ESP]
  {"x86_FSTPS_mem", []byte{0xD9, 0x1C, 0x24}},

ModRM 0x1C = mod=00, reg=3 (FSTP opcode group), rm=4 (SIB follows).
SIB 0x24 = scale=00, index=4(none), base=4(ESP). Address = [ESP] (no disp).
Opcode D9 /3: FSTP m32fp -- pops ST(0) to float32 at address.
Expected: STORE op writing ST0 to [ESP]. 1-3 ops.

Total FP golden fixtures: 3. Total after D20: >= 113.

Note: If any FP opcode produces UnimplError, do NOT fail -- instead add a skip note
in the test (t.Skipf("FP decode not yet implemented: %v", err)) and file a TODO comment.
The goal is to PROBE the decode, not to require success.

Actually: require that at least FLD1 and FLDZ decode without error (they are constant-load
instructions with no memory access, most likely to work). FSTPS may or may not work.

## Part 3: Multi-function call chain E2E

Add TestX86CallChainFunction to pkg/loader/loader_test.go.

A caller function that calls a helper:

int double_it(int x) { return x + x; }
int compute(int a) { return double_it(a) + 1; }

The binary encodes both functions consecutively. bridge.Build() decodes only compute()
(starting at its entry point), but the CALL target lands within double_it().

Assembly for double_it (at offset 0x00):
  0x00: 55              PUSH EBP
  0x01: 89 E5           MOV EBP, ESP
  0x03: 8B 45 08        MOV EAX, [EBP+8]   (x)
  0x06: 01 C0           ADD EAX, EAX        (x + x)
  0x08: 5D              POP EBP
  0x09: C3              RET
  Total: 10 bytes (0x00..0x09)

Assembly for compute (at offset 0x0A):
  0x0A: 55              PUSH EBP
  0x0B: 89 E5           MOV EBP, ESP
  0x0D: FF 75 08        PUSH [EBP+8]       (push a as argument)
  0x10: E8 EB FF FF FF  CALL -21           (call double_it at 0x00; offset = 0x00 - 0x15 = -21 = 0xFFFFEB)
  0x15: 83 C4 04        ADD ESP, 4         (clean up argument)
  0x18: 40              INC EAX            (result + 1)
  0x19: 5D              POP EBP
  0x1A: C3              RET
  Total: 17 bytes

Verify CALL offset: at 0x10, next_ip = 0x15, target = 0x00. offset = 0x00 - 0x15 = -0x15.
As int32: -21 = 0xFFFFFFEB. Bytes (LE): EB FF FF FF. Opcode E8 -> E8 EB FF FF FF. Correct.

Combined bytes:
{
  // double_it (0x00..0x09)
  0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x01, 0xC0, 0x5D, 0xC3,
  // compute (0x0A..0x1A)
  0x55, 0x89, 0xE5,
  0xFF, 0x75, 0x08,
  0xE8, 0xEB, 0xFF, 0xFF, 0xFF,
  0x83, 0xC4, 0x04,
  0x40,
  0x5D, 0xC3,
}

bridge.Build() entry = base + 0x0A (compute). MaxInstructions = 20.
When the bridge hits CALL, it records the CALL p-code op and the called address.
The bridge should NOT follow into double_it (it is a separate function). CALL is terminal
for the current function's CFG (it returns to the instruction after CALL).

Assertions:
- len(result.Instructions) >= 5 (compute has ~8 instructions)
- result.Graph.GetSize() >= 1 (at minimum entry block)
- Heritage + pipeline runs without error
- PrintC output non-empty
- t.Logf("compute C output:\n%s", output)

## Part 4: x86 completion declaration

Update docs/STATUS.md: add D20 entry (same format as D19).

Update docs/X86_ROADMAP.md:
- Mark Phase D as COMPLETE
- Add a "x86 Completion Summary" section listing:
  - Final golden subtest count (>= 113)
  - Final E2E test count (>= 21)
  - Coverage summary: integer ops, Jcc variants, addressing modes, FP decode foundation
  - Remaining non-blocking gaps: FP Heritage/PrintC layer (future), DWARF/symtab (optional), 64-bit (out of scope)

## In-scope

1. pkg/sla/x86_golden_test.go: add XCHG_EAX_mem, JNO_fwd, FLD1, FLDZ, FSTPS_mem (5 entries)
2. testdata/golden/: 5 new JSON fixture files
3. pkg/loader/loader_test.go: TestX86CallChainFunction
4. docs/STATUS.md: D20 entry
5. docs/X86_ROADMAP.md: Phase D complete + completion summary

## Out-of-scope

- FP Heritage/PrintC type inference layer (future phase)
- LOCK prefix (atomic ops)
- SSE/MMX/AVX
- 64-bit mode
- DWARF/symtab integration
- Segment override (FS:/GS:)

## Invariants

- All existing tests pass (108 golden subtests, 20 E2E tests)
- New golden fixtures >= 1 op each (except FP which may skip if UnimplError)
- TestX86CallChainFunction must NOT skip
- No new external dependencies
- ASCII-only, tabs for indentation, English comments

## Done when

- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 110 subtests (integer) + FP probed
- go test ./pkg/loader/... -run TestX86CallChainFunction passes with non-empty PrintC
- go test ./... passes green
- docs/X86_ROADMAP.md contains "x86 Completion" section
