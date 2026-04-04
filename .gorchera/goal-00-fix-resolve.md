# Goal 00: Fix sla.Engine Constructor Resolution

## Problem

`sla.Engine.TranslateInstructionAt()` fails with "unable to resolve constructor" for all 6502 instructions except BRK (0x00). This blocks the entire E2E decompiler pipeline.

Tested instructions that fail:
- NOP (0xEA), RTS (0x60), JMP abs (4C 34 12), JSR abs (20 34 12)
- BNE rel (D0 02), LDA #imm (A9 42), STA zp (85 00), INX (E8)
- LDX #imm (A2 10), STA abs (8D 00 02)

Only BRK (0x00) succeeds -- likely because all-zero bits match a default/fallback in the decision tree.

## Root Cause Investigation

The error "unable to resolve constructor" comes from the decision tree resolution path. Likely causes:

1. **LoadFill not feeding instruction bytes**: ParserContext buffer might be all zeros, so only BRK (0x00) matches
2. **Decision tree bit extraction broken**: GetByte/GetBits might not read from the loaded buffer correctly
3. **Decision tree decoding incomplete**: The decision tree from 6502.sla might not be fully decoded

## Files to investigate

- `pkg/sla/decision_resolve.go` -- DecisionNode.resolve() / SubtableSymbol resolve
- `pkg/sla/resolve.go` -- Resolve() entry, how ParserContext is prepared
- `pkg/sla/obtain_context.go` -- ObtainContext / ObtainPcodeContext
- `pkg/sla/walker.go` -- ParserContext buffer, GetByte, GetBits
- `pkg/sla/backend.go` -- Backend LoadFill implementation
- `pkg/sla/integration_test.go` -- current test setup (reference for how Engine is configured)
- `pkg/sla/load_context.go` -- LoadContext path

## C++ reference

- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleigh.cc` -- Sleigh::resolve(), Sleigh::oneInstruction()
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/context.cc` -- ParserContext, getInstructionBytes/getBits
- `ghidra-ref/Ghidra/Features/Decompiler/src/decompile/cpp/sleighbase.cc` -- DecisionNode::resolve()

## Strategy

1. Add debug logging or a test that dumps: (a) the instruction bytes loaded into ParserContext buffer, (b) the decision tree path taken during resolve, (c) the bit values extracted at each decision node
2. Compare with what Ghidra's C++ would do for the same 6502.sla and the same instruction byte
3. Find the divergence point and fix it
4. Verify by translating at least 5 different 6502 instructions successfully

## Success criteria

- `Engine.TranslateInstructionAt()` succeeds for NOP, RTS, LDA #imm, STA zp, JMP abs, JSR abs, BNE rel, INX, LDX #imm, STA abs
- Each returns non-empty `[]pcode.RawOp`
- `go test ./pkg/sla/...` passes (existing + new tests)
- `go test ./...` passes

## Constraints

- Tabs for indentation
- English comments
- No non-ASCII in code
- Check C++ reference before making assumptions about how resolution should work
