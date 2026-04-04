# D2: CALL instruction support + caller function E2E

## Objective

Add x86 CALL instruction (rel32 form) support to Gosleigh and verify that a
function containing a CALL can be decompiled end-to-end through Heritage + PrintC.
This is the first step toward handling real x86 binaries that call other functions.

## Why

Phase D1 verified loop CFG (back edges, CBRANCH, do-while structure in PrintC).
CALL is the next critical p-code op for real code: virtually every non-trivial
x86 function contains at least one CALL. Without CALL support verified, we
cannot trust the decompiler on real binaries.

Ghidra Sleigh emits `CALL ram[target]` for x86 direct CALL rel32. The bridge
must NOT treat CALL as a hard terminator (execution falls through after return),
and Heritage/PrintC must handle the CALL p-code op in the output.

## New opcode to add to TestGoldenX86

Add this entry to the cases slice in pkg/sla/x86_golden_test.go:

  {"x86_CALL_near", []byte{0xE8, 0x00, 0x00, 0x00, 0x00}},  // CALL rel32=0, target=next instr

Notes:
- 0xE8 cb: CALL near relative. rel32=0 means target = current+5+0 = 5 (next instruction).
- Expected p-code: 1 CALL op (possibly preceded by stack ops for return address push).
  In Ghidra x86.sla, CALL near emits: CALL ram[target] -- check actual output.
- Must produce >= 1 op (t.Fatalf if 0 ops).
- Generate golden fixture via GOSLEIGH_UPDATE_GOLDEN=1.

## Caller function E2E test

Add TestX86CallerFunction to pkg/loader/loader_test.go (package loader_test).

The caller function bytes (12 bytes):
  0x00: 55              // PUSH EBP          (1 byte)
  0x01: 89 E5           // MOV EBP, ESP      (2 bytes)
  0x03: E8 00 00 00 00  // CALL +5 (next)    (5 bytes)
  0x08: 5D              // POP EBP           (1 byte)
  0x09: C3              // RET               (1 byte)

As a byte slice: {0x55, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3}

This is a minimal caller: prologue (PUSH EBP / MOV EBP,ESP), CALL to next instruction
(a self-contained call that immediately returns), epilogue (POP EBP / RET).

TestX86CallerFunction implementation:
  a. Use loader.EngineBuilder{SLAPath, PspecPath, Bytes: prog} to build engine
     (same path resolution as TestX86SimpleFunction)
  b. bridge.Build(engine, bridge.BuildConfig{Name:"caller", Entry:base, MaxInstructions:20})
  c. Assert len(result.Instructions) >= 4 (PUSH + MOV + CALL + POP + RET = at least 4)
  d. Assert result.Graph != nil
  e. Find that at least one instruction has a CALL p-code op:
     found := false
     for _, instr := range result.Instructions {
         for _, op := range instr.Ops {
             if op.Opcode == pcode.CALL { found = true }
         }
     }
     if !found { t.Fatalf("no CALL op found in instructions") }
  f. Heritage:
     heritage := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
     heritage.Heritage(result.Graph)
  g. Run analysis actions:
     pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
     pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
     pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
  h. PrintC:
     output, err := pcode.NewPrintC().Emit(result.Funcdata)
     t.Fatal if err != nil
     t.Logf("Caller C output:\n%s", output)
     if strings.TrimSpace(output) == "" { t.Fatalf("PrintC returned empty output for caller") }

If CALL p-code opcode constant is not exported from pcode package, check pcode/opcodes.go
or similar and use the correct exported name (e.g. pcode.OpCALL, pcode.CALL, etc.).

## Expected p-code for CALL near rel32 (0xE8 00 00 00 00)

Ghidra x86.sla for CALL near: emits CALL p-code op targeting ram space.
Exact form may be: CALL ram[5] (target address = base+5 for rel32=0 at base=0).
Check actual output -- the golden fixture records whatever Sleigh produces.

The CALL op itself does NOT push a return address onto the stack in Ghidra p-code
(the RET handling takes care of that). Verify in the actual fixture output.

## Bridge.go CALL handling

Verify that bridge.go does NOT treat CALL as a hard terminator. The function
collectInstructions should continue past a CALL instruction to the next sequential
instruction. Currently RETURN and BRANCHIND are hard terminators (added in D1).
CALL should NOT be in the hard-terminator set.

If any CALL-related gap is found (e.g., bridge panics on CALL op, or CFG
construction fails due to CALL target being treated as a branch target):
- Read the exact error
- Cross-reference ghidra-ref/ bridge.cc / flow.cc as needed
- Fix the specific gap

## In-scope

1. pkg/sla/x86_golden_test.go: extend cases slice with CALL_near
2. testdata/golden/x86_CALL_near.json: generate fixture
3. pkg/loader/loader_test.go: add TestX86CallerFunction
4. Fix gaps in: bridge.go (if CALL causes panic or wrong CFG), heritage.go, printc.go
   if they fail on CALL p-code. Cross-reference C++ before fixing.
5. Verify pcode.CALL constant is correctly defined and exported.

## Out-of-scope

- Do not add inter-procedural analysis (callee body analysis).
- Do not add CALL indirect (0xFF /2 ModRM) support.
- Do not add 64-bit x86 support.
- Do not add ELF/PE binary loading.
- Do not modify pspec.go, pspec_test.go, golden_test.go, integration_test.go.
- Do not modify existing golden fixture files (x86_NOP, x86_RET, etc.).

## Invariants

- All existing tests (go test ./...) must pass.
- 1 new golden fixture must have >= 1 op entry.
- TestX86CallerFunction must NOT skip. t.Fatal if any step fails.
- ASCII-only, tabs for indentation, English comments.
- No new external dependencies.

## Done when

- go build ./... passes.
- go test ./pkg/sla/... -run TestGoldenX86 passes with 13 subtests (12 existing + 1 new).
- go test ./pkg/loader/... -run TestX86CallerFunction passes and logs non-empty C output.
- go test ./... passes with all tests green.
- testdata/golden/x86_CALL_near.json exists with >= 1 op.
