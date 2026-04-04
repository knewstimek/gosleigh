# D4: if-else CFG + block structuring E2E validation

## Objective

Verify that the full decompilation pipeline (Heritage + block structuring + PrintC)
correctly handles functions with if-else control flow. The current pipeline has
been verified on: straight-line code, simple do-while loops, and function calls.
The missing piece is diamond/if-else CFG: a function that has a conditional branch
leading to two paths that merge at a join point.

## Why

Block structuring (ActionBlockStructure + ActionFinalStructure) must recognize
an if-else pattern in the CFG and emit corresponding C output. Without this
verified, the decompiler cannot handle any real function that has conditionals.

Ghidra's block structuring converts:
  if (cond) { ... } else { ... } join
into a C if-else statement. The CFG is a "diamond":
  entry -> true-branch, entry -> false-branch, true-branch -> join, false-branch -> join

## New opcode: x86 JE rel8

Add to TestGoldenX86 in pkg/sla/x86_golden_test.go:
  {"x86_JE_fwd", []byte{0x74, 0x02}},   // JE +2 (jump forward 2 bytes past next 2 bytes)

JE rel8 opcode: 0x74 cb. For JE +2 at base=0, target = 0+2+2 = 4.
Expected p-code: BOOL_NEGATE(ZF) + CBRANCH -- 2 ops (same as JNE).
Generate golden fixture: testdata/golden/x86_JE_fwd.json.

## if-else E2E test function

Add TestX86IfElse to pkg/loader/loader_test.go.

The test function bytes (a simple abs() -- absolute value):
  0x00: 55              // PUSH EBP           1 byte
  0x01: 89 E5           // MOV EBP, ESP       2 bytes
  0x03: 8B 45 08        // MOV EAX, [EBP+8]  3 bytes  (arg = EAX)
  0x06: 85 C0           // TEST EAX, EAX      2 bytes  (sets ZF/SF/OF)
  0x08: 79 04           // JNS +4 (jmp to 0x0E if SF==0 i.e. EAX >= 0)  2 bytes
  0x0A: F7 D8           // NEG EAX            2 bytes  (if negative: negate)
  0x0C: EB 00           // JMP +0 (fallthrough to 0x0E)  2 bytes
  0x0E: 5D              // POP EBP            1 byte
  0x0F: C3              // RET                1 byte
  Total: 16 bytes

As byte slice: {0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08, 0x85, 0xC0, 0x79, 0x04, 0xF7, 0xD8, 0xEB, 0x00, 0x5D, 0xC3}

This is an if-else: if (EAX < 0) EAX = -EAX; return EAX;
CFG: entry(PUSH+MOV+MOV+TEST+JNS) -> true-path(falls through to NEG+JMP) + false-path(JNS target) -> join(POP+RET)

TestX86IfElse implementation:
  a. EngineBuilder{SLAPath, PspecPath, Bytes: prog} -- same as other E2E tests
  b. bridge.Build(engine, bridge.BuildConfig{Name:"ifelse", Entry:base, MaxInstructions:20})
  c. Assert len(result.Instructions) >= 6 (PUSH+MOV+MOV+TEST+JNS+NEG+JMP+POP+RET)
  d. Assert result.Graph.GetSize() >= 2 (at least 2 basic blocks)
  e. Heritage:
     heritage := pcode.NewHeritage(result.Funcdata, result.HeritageSpaces)
     heritage.Heritage(result.Graph)
  f. Run analysis:
     pcode.NewBatchAActionPool("batch-a", "analysis").Perform(result.Funcdata)
     pcode.NewActionBlockStructure("analysis").Apply(result.Funcdata)
     pcode.NewActionFinalStructure("analysis").Apply(result.Funcdata)
  g. PrintC:
     output, err := pcode.NewPrintC().Emit(result.Funcdata)
     t.Fatal if err != nil
     t.Logf("IfElse C output:\n%s", output)
     if strings.TrimSpace(output) == "" { t.Fatalf("PrintC returned empty for if-else") }

New opcodes in this test not yet in golden fixtures:
- TEST EAX,EAX (0x85 0xC0): similar to AND with EFLAGS. May need golden fixture if executor wants to add it.
- JNS rel8 (0x79 cb): Jump if not sign. Add golden fixture if needed.
- NEG EAX (0xF7 0xD8): Two's complement negate. Add golden fixture if needed.

For each new opcode encountered that produces 0 ops (unexpected), add to TestGoldenX86 and generate fixture.

## Expected behavior

The bridge must:
- Correctly identify the conditional branch (JNS) as splitting the CFG into two paths
- Both paths should merge at the join block (POP EBP / RET)
- The resulting CFG should have >= 3 basic blocks (entry, true-path, join; or with separate false-path: 3-4 blocks)

Block structuring must:
- Recognize the diamond pattern and produce an if structure in the BlockGraph
- PrintC must emit recognizable C with conditional logic (not just straight-line code)

If bridge, heritage, or block structuring fails on the diamond CFG:
- Read the exact error
- Cross-reference ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/block.cc,
  heritage.cc, or actionsanalysis.cc as needed
- Fix the specific gap

## In-scope

1. pkg/sla/x86_golden_test.go: add x86_JE_fwd subtest (and TEST/JNS/NEG if needed)
2. testdata/golden/x86_JE_fwd.json: generate fixture
3. pkg/loader/loader_test.go: add TestX86IfElse
4. Fix gaps in bridge.go (JNS target resolution), heritage.go, block_actions.go
   if diamond CFG causes panic or wrong output
5. docs/STATUS.md: add Phase D4 completion entry
6. docs/X86_ROADMAP.md: update D4 status

## Out-of-scope

- Do not add switch/case support (that requires jump tables -- Phase D5+).
- Do not add nested if-else.
- Do not add 64-bit x86.
- Do not modify existing golden fixtures or pspec.go.

## Invariants

- All existing tests (go test ./...) must pass.
- TestX86IfElse must NOT skip. t.Fatal if any step fails.
- New golden fixtures must have >= 1 op each (except NOP-like cases).
- ASCII-only, tabs for indentation, English comments.
- No new external dependencies.

## JNS opcode note

JNS rel8: opcode 0x79. Jump if Not Sign (SF == 0). p-code:
  BOOL_NEGATE(SF) + CBRANCH -- same pattern as JNE/JE.
Target = base+2+4 = base+6 (for JNS +4 at offset 0x08 in the function: 0x08+2+4 = 0x0E = join block start).

## NEG opcode note

NEG EAX: opcode 0xF7 /3. Two's complement negate.
p-code: INT_NEGATE(EAX) -> EAX + flag ops (CF, OF, SF, ZF, AF, PF) -- ~7 ops total.

## TEST opcode note

TEST EAX,EAX: opcode 0x85 /r. Logical AND setting flags, result discarded.
p-code: INT_AND(EAX, EAX) discarded + flag ops (SF, ZF, AF, PF, CF=0, OF=0) -- ~6 ops.

## Done when

- go build ./... passes.
- go test ./pkg/sla/... -run TestGoldenX86 passes with >= 14 subtests.
- go test ./pkg/loader/... -run TestX86IfElse passes and logs non-empty C output.
- go test ./... passes with all tests green.
- testdata/golden/x86_JE_fwd.json exists with >= 1 op.
