# Goal 01: sla -> pcode Bridge + 6502 E2E Pipe-through

## Objective

Create a bridge that connects `pkg/sla.Engine` output (raw p-code per instruction) to `pkg/pcode.Funcdata` input, then run the full pipeline (Heritage -> Actions -> PrintC) on a real 6502 binary to produce C output.

## Context

### sla Engine output (pkg/sla/engine.go)
```go
type InstructionTranslation struct {
    Address address.Address
    Next    address.Address
    Length  int
    Ops     []pcode.RawOp  // raw p-code ops for one instruction
}
// Engine.TranslateInstructionAt(addr) -> InstructionTranslation
```

### pcode Funcdata input (pkg/pcode/funcdata.go)
```go
fd := pcode.NewFuncdata(name, entryAddr, uniqSpace, uniqBase, constSpace)
// Per raw op:
op := fd.NewOp(numInputs, addr)
fd.OpSetOpcode(op, opcode)
// output: fd.NewVarnodeOut(size, loc, op) or fd.NewVarnode(size, loc)
// inputs: fd.NewVarnode(size, loc) or fd.NewConstant(size, val)
fd.OpSetOutput(op, vn)
fd.OpSetInput(op, vn, slot)
fd.OpMarkAlive(op)
// After all ops:
fd.SetBasicBlocks(graph)  // BlockGraph with BlockBasic nodes
// Then: Heritage -> Actions -> PrintC
```

### What needs to be built

1. **`pkg/bridge/bridge.go`** (new package): Function-level translator
   - Input: sla.Engine + function entry address + function end address (or instruction count)
   - Iterates instructions from entry to end using Engine.TranslateInstructionAt()
   - Converts each RawOp into Funcdata ops/varnodes
   - Builds BasicBlocks by splitting at branch targets (BRANCH, CBRANCH, BRANCHIND, CALL, RETURN)
   - Constructs BlockGraph with proper edges
   - Returns populated Funcdata ready for Heritage

2. **`pkg/bridge/bridge_test.go`**: Integration test
   - Load testdata/6502.sla (XML) or testdata/6502-packed.sla
   - Set up sla.Engine with a small hand-crafted 6502 program (e.g. LDA #$42; STA $00; RTS -- 5 bytes)
   - Run bridge to get Funcdata
   - Run Heritage
   - Run Actions (at minimum a basic set)
   - Run PrintC
   - Verify non-empty C output

3. **BasicBlock construction rules** (mirror Ghidra's `FlowInfo`):
   - Start new block at: function entry, branch targets, instruction after conditional branch
   - End block at: BRANCH, CBRANCH, BRANCHIND, CALL (if noreturn), RETURN
   - CBRANCH creates two edges: fallthrough + target
   - BRANCH creates one edge to target
   - RETURN creates no outgoing edges
   - CALL creates fallthrough edge (unless noreturn)

## Files to read before starting
- `pkg/sla/engine.go` -- Engine interface
- `pkg/sla/backend.go` -- Backend (LoadImage, context)
- `pkg/sla/integration_test.go` -- how Engine is set up with real .sla
- `pkg/pcode/funcdata.go` -- Funcdata constructor and op/varnode creation
- `pkg/pcode/block.go` or similar -- BlockBasic, BlockGraph
- `pkg/pcode/heritage.go` -- Heritage entry point
- `pkg/pcode/action.go` -- Action pipeline
- `pkg/pcode/printc.go` -- PrintC.Emit()
- `pkg/pcode/rawop.go` -- RawOp, OpCode constants
- `pkg/address/space.go` -- Space types

## Success criteria
- `go test ./pkg/bridge/...` passes
- The test loads a real .sla, translates real 6502 instructions, and produces non-empty C output via PrintC
- No placeholder/stub functions -- every function either works or returns a clear error

## Constraints
- Use tabs for indentation (Go standard)
- Comments in English
- No non-ASCII characters in code/output
- Keep pkg/sla and pkg/pcode unchanged -- bridge is a new package that imports both
