# D1: Heritage SSA on real loop CFG + PrintC loop output

## Objective

Verify that the full x86 decompilation pipeline handles a real loop CFG correctly.
Extend TestGoldenX86 with DEC ECX and JNE opcodes, then add a loop E2E test that
verifies Heritage produces a correct CFG with a back edge, and PrintC emits
recognizable loop/condition structure.

## Why

Phase C4 verified the pipeline on a trivial 2-instruction function (ADD+RET =
single basic block, no CFG complexity). Phase D1 is the first real stress test:
a counted loop requires:
- CBRANCH p-code (conditional branch with fallthrough + target)
- Heritage building a CFG with a back edge (loop back to block start)
- Dominator tree correctly computed (loop header dominates loop body)
- PrintC emitting something other than a straight-line C function

Without this verification, we cannot trust the decompiler for any real code.

## New opcodes to add to TestGoldenX86

Add these entries to the cases slice in x86_golden_test.go:

  {"x86_DEC_ECX",  []byte{0x49}},         // DEC ECX -- 1 op (INT_SUB ECX-1)
  {"x86_JNE_back", []byte{0x75, 0xFE}},   // JNE -2 (self loop, rel8=-2)

Notes:
- DEC ECX: opcode 0x49 in 32-bit mode (0x48=DEC EAX, 0x49=DEC ECX, ...)
- JNE rel8: 0x75 cb. For JNE -2 (EB FE), rel8=0xFE (-2 signed), target = current+2+(-2) = current. Self-loop for the golden fixture (just tests CBRANCH emission).
- Both must produce >= 1 op (t.Fatalf if 0 ops, matching the existing guard).
- Generate golden fixtures for both via GOSLEIGH_UPDATE_GOLDEN=1.

## Loop E2E test

Add TestX86CountedLoop to pkg/loader/loader_test.go (package loader_test).

The loop function bytes (9 bytes total):
  0x00: B9 03 00 00 00  // MOV ECX, 3      (5 bytes)
  0x05: 49              // DEC ECX          (1 byte)
  0x06: 75 FD           // JNE -3 (to 0x05) (2 bytes, FD=-3 signed)
  0x08: C3              // RET              (1 byte)

As a byte slice: {0xB9, 0x03, 0x00, 0x00, 0x00, 0x49, 0x75, 0xFD, 0xC3}

This is a counted loop: ECX starts at 3, decrements each iteration,
loops back while ECX != 0 (3 iterations total), then returns.

TestX86CountedLoop implementation:
  a. Write the 9 bytes to a temp file (os.CreateTemp)
  b. Use loader.EngineBuilder{SLAPath, PspecPath, Bytes: prog} to build engine
     (same path resolution as TestX86SimpleFunction)
  c. bridge.Build(engine, bridge.BuildConfig{Name:"loop", Entry:base, MaxInstructions:20})
  d. Assert len(result.Instructions) >= 3 (MOV + DEC + JNE + RET = at least 3)
  e. Assert result.Graph != nil and result.Graph.GetSize() >= 2
     (must have at least 2 basic blocks: loop-entry block and exit block)
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
     t.Logf("Loop C output:\n%s", output)
     if strings.TrimSpace(output) == "" { t.Fatalf("PrintC returned empty output for loop") }

If any step fails (e.g., bridge.Build returns error, Heritage panics, PrintC returns empty):
  - Read the exact error
  - Cross-reference ghidra-ref/ C++ (heritage.cc, print_c.cc, block.cc as needed)
  - Fix the specific gap
  - Re-run the test

## In-scope

1. pkg/sla/x86_golden_test.go: extend cases slice with DEC_ECX and JNE_back
2. testdata/golden/x86_DEC_ECX.json and x86_JNE_back.json: generate fixtures
3. pkg/loader/loader_test.go: add TestX86CountedLoop
4. Fix gaps in: bridge.go (if CBRANCH resolveTarget fails), heritage.go, printc.go,
   or block_actions.go if they fail on loop CFG. Cross-reference C++ before fixing.

## Out-of-scope

- Do not add CALL instruction support yet.
- Do not add 64-bit x86 support.
- Do not add memory-indirect addressing.
- Do not modify pspec.go, pspec_test.go, golden_test.go, integration_test.go.
- Do not modify the existing x86 golden fixture files.

## Invariants

- All existing tests (go test ./...) must pass.
- 2 new golden fixtures must have >= 1 op entry each.
- TestX86CountedLoop must NOT skip. t.Fatal if any step fails.
- ASCII-only, tabs for indentation, English comments.
- No new external dependencies.

## Expected p-code for DEC ECX (0x49)
Ghidra p-code for DEC r32 (no-operand form):
  INT_SUB(ECX, const:1 -> ECX)  -- 1 main op + flag ops (OF, SF, ZF, AF, PF)
  Total: ~6 ops.

## Expected p-code for JNE rel8 (0x75 FE)
Ghidra p-code for JNE (short form):
  CBRANCH(ZF == 0, target)  -- 1 op with conditional branch
  Note: ZF is the zero flag register.

## Done when

- go build ./... passes.
- go test ./pkg/sla/... -run TestGoldenX86 passes with 12 subtests (10 existing + 2 new).
- go test ./pkg/loader/... -run TestX86CountedLoop passes and logs non-empty C output.
- go test ./... passes with all tests green.
- x86_DEC_ECX.json and x86_JNE_back.json exist with >= 1 op each.
